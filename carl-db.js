/* CARL Field PWA — offline data + submission queue (foreground / window context).
 *
 * Exposes window.CARL with:
 *   Drafts:   saveDraft, listDrafts, getDraft, deleteDraft
 *   Outbox:   enqueue, listOutbox, pendingCount, sendItem, flushQueued, recoverStuck,
 *             updateOutbox, deleteOutbox
 *   Plumbing: registerSync, onChange, uid
 *
 * Shared IndexedDB contract with sw.js: DB "carl-field" v1, stores "drafts" and "outbox"
 * (both keyPath "id"). Outbox item:
 *   { id, status: 'queued'|'sending'|'sent'|'done'|'error', payload, idempotencyKey,
 *     createdAt, completedAt?, result?, error? }
 *   'sent' = dispatched but the response was lost (page killed / timeout) — the server may
 *   have finished; recoverStuck() tries to fetch the result from the daily report.
 */
(function () {
  'use strict';

  var WEBHOOK_URL = 'https://n8n.carlcompliance.com/webhook/carl-verify';
  // NOTE: corrected from the dead n8n.gjbishop.com host so recovery + daily report work.
  var DAILY_REPORT_URL = 'https://n8n.carlcompliance.com/webhook/carl-daily-report';
  var SUBMIT_TIMEOUT_MS = 180000; // matches the ~3 min synchronous pipeline

  var listeners = [];
  function emitChange() { listeners.forEach(function (cb) { try { cb(); } catch (e) {} }); }

  function uid() {
    return (self.crypto && crypto.randomUUID)
      ? crypto.randomUUID()
      : 'id-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  }

  /* ---------------- IndexedDB ---------------- */
  function openDB() {
    return new Promise(function (resolve, reject) {
      var r = indexedDB.open('carl-field', 1);
      r.onupgradeneeded = function () {
        var db = r.result;
        if (!db.objectStoreNames.contains('drafts')) db.createObjectStore('drafts', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('outbox')) db.createObjectStore('outbox', { keyPath: 'id' });
      };
      r.onsuccess = function () { resolve(r.result); };
      r.onerror = function () { reject(r.error); };
    });
  }
  function tx(store, mode, fn) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var t = db.transaction(store, mode);
        var os = t.objectStore(store);
        var out = fn(os);
        t.oncomplete = function () { resolve(out && out.result !== undefined ? out.result : out); };
        t.onerror = function () { reject(t.error); };
        t.onabort = function () { reject(t.error); };
      });
    });
  }
  function getAll(store) { return tx(store, 'readonly', function (os) { return os.getAll(); }); }
  function put(store, val) { return tx(store, 'readwrite', function (os) { os.put(val); return val; }); }
  function del(store, id) { return tx(store, 'readwrite', function (os) { os.delete(id); }); }
  function get(store, id) { return tx(store, 'readonly', function (os) { return os.get(id); }); }

  /* ---------------- Drafts ---------------- */
  function saveDraft(draft) {
    var d = Object.assign({}, draft);
    if (!d.id) d.id = uid();
    d.updatedAt = Date.now();
    return put('drafts', d).then(function (v) { emitChange(); return v; });
  }
  function listDrafts() {
    return getAll('drafts').then(function (rows) {
      return (rows || []).sort(function (a, b) { return (b.updatedAt || 0) - (a.updatedAt || 0); });
    });
  }
  function getDraft(id) { return get('drafts', id); }
  function deleteDraft(id) { return del('drafts', id).then(function () { emitChange(); }); }

  /* ---------------- Outbox ---------------- */
  function enqueue(payload) {
    var item = {
      id: uid(),
      status: 'queued',
      payload: payload,
      idempotencyKey: uid(),
      createdAt: Date.now()
    };
    return put('outbox', item).then(function () { emitChange(); return item; });
  }
  function listOutbox() {
    return getAll('outbox').then(function (rows) {
      return (rows || []).sort(function (a, b) { return (a.createdAt || 0) - (b.createdAt || 0); });
    });
  }
  function updateOutbox(item) { return put('outbox', item).then(function (v) { emitChange(); return v; }); }
  function deleteOutbox(id) { return del('outbox', id).then(function () { emitChange(); }); }
  function pendingCount() {
    return listOutbox().then(function (rows) {
      return rows.filter(function (i) { return i.status === 'queued' || i.status === 'sending' || i.status === 'sent'; }).length;
    });
  }

  /* Send a single outbox item and await the result (interactive path).
   * Resolves { ok:true, result } or { ok:false, reason, item }. Updates status + storage. */
  function sendItem(item, opts) {
    opts = opts || {};
    item.status = 'sending';
    return updateOutbox(item).then(function () {
      var controller = new AbortController();
      var timedOut = false;
      var timer = setTimeout(function () { timedOut = true; controller.abort(); }, opts.timeout || SUBMIT_TIMEOUT_MS);
      if (opts.signal) opts.signal.addEventListener('abort', function () { controller.abort(); });
      return fetch(WEBHOOK_URL, {
        method: 'POST',
        mode: 'cors',
        headers: { 'Content-Type': 'application/json', 'X-CARL-Idempotency': item.idempotencyKey },
        body: JSON.stringify(item.payload),
        signal: controller.signal
      }).then(function (resp) {
        clearTimeout(timer);
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        return resp.json();
      }).then(function (data) {
        if (data && data.error && !data.discipline) throw new Error(data.error);
        item.status = 'done'; item.result = data; item.completedAt = Date.now();
        return updateOutbox(item).then(function () { return { ok: true, result: data, item: item }; });
      }).catch(function (err) {
        clearTimeout(timer);
        // Network failure or timeout: the server may still be processing. Mark 'sent' so it
        // becomes a recovery candidate rather than a hard error (don't auto-resend a possibly
        // in-flight 3-min job). A genuine connectivity failure stays 'queued' for retry.
        var lostMidFlight = timedOut || err.name === 'AbortError';
        var noNetwork = !navigator.onLine || /Failed to fetch|NetworkError/.test(err.message || '');
        item.status = lostMidFlight ? 'sent' : (noNetwork ? 'queued' : 'error');
        item.error = err.message;
        return updateOutbox(item).then(function () {
          return { ok: false, reason: item.status, error: err.message, item: item };
        });
      });
    });
  }

  /* Flush all 'queued' items (e.g. on reconnect). Sequential to avoid hammering. */
  function flushQueued(opts) {
    return listOutbox().then(function (rows) {
      var queued = rows.filter(function (i) { return i.status === 'queued'; });
      return queued.reduce(function (p, item) {
        return p.then(function () { return sendItem(item, opts); });
      }, Promise.resolve());
    });
  }

  /* Recovery: for items dispatched but missing a result ('sent', or stale 'sending'),
   * ask the daily report for that day and match by building_number + observation + time
   * window. Attaches the recovered result and marks 'done'. Returns recovered items. */
  function recoverStuck(opts) {
    opts = opts || {};
    var graceMs = opts.graceMs || 30000;
    return listOutbox().then(function (rows) {
      var candidates = rows.filter(function (i) {
        if (i.result) return false;
        if (i.status === 'sent') return true;
        if (i.status === 'sending' && (Date.now() - i.createdAt) > (SUBMIT_TIMEOUT_MS + graceMs)) return true;
        return false;
      });
      if (!candidates.length) return [];
      // Group by entry_date (Guam) of createdAt so we query each relevant day once.
      var dates = {};
      candidates.forEach(function (i) {
        var d = new Date(i.createdAt).toLocaleDateString('en-CA', { timeZone: 'Pacific/Guam' });
        (dates[d] = dates[d] || []).push(i);
      });
      var recovered = [];
      var days = Object.keys(dates);
      return days.reduce(function (p, date) {
        return p.then(function () {
          return fetch(DAILY_REPORT_URL, {
            method: 'POST', mode: 'cors',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ date: date })
          }).then(function (r) { return r.ok ? r.json() : { entries: [] }; })
            .then(function (report) {
              var entries = (report && report.entries) || [];
              dates[date].forEach(function (item) {
                var obs = (item.payload.observation || '').trim();
                var bld = (item.payload.building_number || '').trim();
                var match = entries.find(function (e) {
                  var eo = (e.observation_text || e.observation || '').trim();
                  var eb = (e.building_number || '').trim();
                  return eb === bld && eo && obs && (eo === obs || eo.indexOf(obs) === 0 || obs.indexOf(eo) === 0);
                });
                if (match) {
                  item.status = 'done'; item.result = match; item.completedAt = Date.now(); item.recovered = true;
                  recovered.push(item);
                }
              });
            }).catch(function () { /* offline / endpoint down — leave candidates as-is */ });
        });
      }, Promise.resolve()).then(function () {
        return Promise.all(recovered.map(function (i) { return updateOutbox(i); })).then(function () { return recovered; });
      });
    });
  }

  /* Register Android/Chromium Background Sync (no-op on iOS). */
  function registerSync() {
    if (!('serviceWorker' in navigator)) return Promise.resolve(false);
    return navigator.serviceWorker.ready.then(function (reg) {
      if (reg.sync && reg.sync.register) {
        return reg.sync.register('carl-outbox-sync').then(function () { return true; }).catch(function () { return false; });
      }
      return false;
    }).catch(function () { return false; });
  }

  function onChange(cb) { listeners.push(cb); return function () { listeners = listeners.filter(function (x) { return x !== cb; }); }; }

  window.CARL = {
    WEBHOOK_URL: WEBHOOK_URL,
    DAILY_REPORT_URL: DAILY_REPORT_URL,
    saveDraft: saveDraft, listDrafts: listDrafts, getDraft: getDraft, deleteDraft: deleteDraft,
    enqueue: enqueue, listOutbox: listOutbox, pendingCount: pendingCount,
    sendItem: sendItem, flushQueued: flushQueued, recoverStuck: recoverStuck,
    updateOutbox: updateOutbox, deleteOutbox: deleteOutbox,
    registerSync: registerSync, onChange: onChange, uid: uid
  };

  // Reflect SW background-flush updates into the foreground UI.
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', function (e) {
      if (e.data && e.data.type === 'outbox-updated') emitChange();
    });
  }
})();
