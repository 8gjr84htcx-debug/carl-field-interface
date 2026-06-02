/* CARL Field PWA — offline authentication (device-bound, encrypted-at-rest).
 *
 * Lets a verified device keep working through low-signal stretches (hangars, tunnels,
 * marine sites) instead of being locked out the moment a session expires offline.
 *
 * Policy enforced:
 *   - 7-day sliding grace window: any successful online check resets it to now+7d, no
 *     password. Effective offline allowance = min(grace_expires, hard_expires).
 *   - 30-day hard re-auth: a checkpoint that only a real password login resets. Online
 *     refresh never extends it.
 *   - Device binding: a non-extractable P-256 ECDSA keypair is generated on first login;
 *     the private key never leaves the device. Reconnect proves possession by signing a
 *     server nonce. Credentials cannot transfer to another device.
 *   - Server-side revocation takes effect on the next online connection.
 *   - Fail closed: if the device cannot persist a non-extractable key, offline-auth is
 *     disabled (online required); at-rest encryption is never weakened.
 *
 * Cached (AES-GCM encrypted in IndexedDB "secure"): username, display_name, title,
 * deviceId, fingerprint, graceToken (server-signed, carries gexp/hexp), lastAuthAt,
 * highWater. NEVER cached: password, password hash, transferable session cookie.
 *
 * Storage is owned by carl-db.js (window.CARL.secure*). This module owns the crypto and
 * the auth state machine, exposed as window.CARLAuth.
 */
(function () {
  'use strict';

  var AUTH_URL = 'https://auth.carlcompliance.com';
  var GRACE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;   // informational; server is authoritative
  var HARD_LIMIT_MS   = 30 * 24 * 60 * 60 * 1000;  // informational; server is authoritative
  var CLOCK_SKEW_MS   = 60 * 60 * 1000;            // tolerance for the rollback guard (1h)

  // secure-store keys
  var K_PRIV  = 'devicePriv';
  var K_PUB   = 'devicePub';
  var K_AES   = 'cacheKey';
  var K_CACHE = 'credCache';

  var STATES = {
    UNAUTHENTICATED:     'UNAUTHENTICATED',     // no cache -> login screen
    ONLINE_AUTHED:       'ONLINE_AUTHED',       // online, within policy
    OFFLINE_GRACE:       'OFFLINE_GRACE',       // offline, within min(gexp,hexp)
    GRACE_EXPIRED:       'GRACE_EXPIRED',       // offline, past window -> block new actions
    HARD_REAUTH:         'HARD_REAUTH',         // online, 30-day checkpoint -> force password
    REVOKED_OR_TAMPERED: 'REVOKED_OR_TAMPERED', // cache cleared -> force fresh login
    OFFLINE:             'OFFLINE'              // could not reach server this attempt
  };

  // current-status mirror, surfaced to carl-db.js's audit provider
  var _fp = null, _mode = 'online', _online = true;

  var sec = {
    get: function (k) { return window.CARL.secureGet(k); },
    put: function (k, v) { return window.CARL.securePut(k, v); },
    clearAll: function () { return window.CARL.secureClear(); }
  };

  /* ---------------- encoding helpers ---------------- */
  function bufToB64(buf) {
    var bytes = new Uint8Array(buf), s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function b64ToBuf(b64) {
    var s = atob(b64), bytes = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes.buffer;
  }
  function b64urlToStr(b64url) {
    var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return atob(b64);
  }
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  /* ---------------- grace-token claims (read-only; HMAC is server-verified) ---------------- */
  function parseClaims(graceToken) {
    try {
      var parts = String(graceToken).split('.');
      if (parts.length !== 2) return null;
      return JSON.parse(b64urlToStr(parts[0]));
    } catch (e) { return null; }
  }

  /* ---------------- device label ---------------- */
  function deviceLabel() {
    var ua = navigator.userAgent || '';
    var plat = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad'
             : /Android/.test(ua) ? 'Android' : 'Device';
    var br = /CriOS/.test(ua) ? 'Chrome' : /FxiOS/.test(ua) ? 'Firefox'
           : (/Safari/.test(ua) && !/Chrome|CriOS/.test(ua)) ? 'Safari'
           : /Chrome/.test(ua) ? 'Chrome' : '';
    return plat + (br ? ' (' + br + ')' : '');
  }

  /* ---------------- crypto primitives ---------------- */
  function subtleOk() { return !!(window.crypto && window.crypto.subtle); }

  function genCacheKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  // ECDSA P-256. extractable=false applies to the PRIVATE key; the public key is always
  // extractable (we must export it to register with the server).
  function genDeviceKeypair() {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  }
  function exportPubSpkiB64(pub) {
    return crypto.subtle.exportKey('spki', pub).then(bufToB64);
  }
  function fingerprintOfSpki(spkiB64) {
    return crypto.subtle.digest('SHA-256', b64ToBuf(spkiB64)).then(function (d) {
      var b = new Uint8Array(d), hex = '';
      for (var i = 0; i < b.length; i++) hex += ('0' + b[i].toString(16)).slice(-2);
      return hex;
    });
  }
  function signNonce(priv, nonce) {
    return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, enc.encode(nonce)).then(bufToB64);
  }

  function encryptCache(aesKey, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, enc.encode(JSON.stringify(obj)))
      .then(function (ct) { return { iv: bufToB64(iv.buffer), ct: bufToB64(ct) }; });
  }
  function decryptCache(aesKey, blob) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(blob.iv)) }, aesKey, b64ToBuf(blob.ct))
      .then(function (pt) { return JSON.parse(dec.decode(pt)); });
  }

  /* ---------------- capability probe (fail-closed) ---------------- */
  var _capable = null;
  function ensureSecureCapable() {
    if (_capable !== null) return Promise.resolve(_capable);
    if (!subtleOk() || !window.indexedDB || !window.CARL || !window.CARL.securePut) {
      _capable = false; return Promise.resolve(false);
    }
    // Generate -> persist -> read back -> round-trip a non-extractable AES-GCM key.
    return genCacheKey().then(function (k) {
      return sec.put('__captest', k).then(function () { return sec.get('__captest'); });
    }).then(function (k) {
      if (!k) throw new Error('key did not persist');
      var iv = crypto.getRandomValues(new Uint8Array(12));
      return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, enc.encode('probe'))
        .then(function (ct) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, k, ct); });
    }).then(function (pt) {
      _capable = (dec.decode(pt) === 'probe');
      return window.CARL.secureDel('__captest').catch(function () {}).then(function () { return _capable; });
    }).catch(function () {
      _capable = false;
      return window.CARL.secureDel('__captest').catch(function () {}).then(function () { return false; });
    });
  }

  /* ---------------- cache read/write ---------------- */
  function loadCache() {
    return Promise.all([sec.get(K_AES), sec.get(K_CACHE)]).then(function (r) {
      var aesKey = r[0], blob = r[1];
      if (!aesKey || !blob) return null;
      return decryptCache(aesKey, blob).then(function (cache) {
        _fp = cache.fingerprint || null;
        // Advance the monotonic high-water mark during legitimate use so a later clock
        // rollback below it is detectable.
        var now = Date.now();
        if (now > (cache.highWater || 0)) { cache.highWater = now; return saveCache(cache).then(function () { return cache; }); }
        return cache;
      }).catch(function () { return null; }); // undecryptable -> treat as no cache (tamper / key loss)
    });
  }
  function saveCache(cache) {
    return sec.get(K_AES).then(function (aesKey) {
      if (!aesKey) throw new Error('no cache key');
      return encryptCache(aesKey, cache).then(function (blob) { return sec.put(K_CACHE, blob); });
    });
  }

  /* ---------------- provisioning (first login + every password login) ---------------- */
  // Called right after a successful password /login, with the live session token.
  // Reuses the existing device keypair if present (stable device identity); generates one
  // on first login. Registers with the server, which resets the 30-day clock and returns a
  // fresh grace token.
  function firstTimeProvision(sessionToken, user) {
    return ensureSecureCapable().then(function (ok) {
      if (!ok) throw new Error('secure-storage-unavailable');
      return Promise.all([sec.get(K_PRIV), sec.get(K_PUB)]);
    }).then(function (kp) {
      if (kp[0] && kp[1]) return { privateKey: kp[0], publicKey: kp[1] };
      return genDeviceKeypair().then(function (pair) {
        return sec.put(K_PRIV, pair.privateKey)
          .then(function () { return sec.put(K_PUB, pair.publicKey); })
          .then(function () { return pair; });
      });
    }).then(function (pair) {
      return sec.get(K_AES).then(function (aes) { return aes ? pair : genCacheKey().then(function (k) { return sec.put(K_AES, k).then(function () { return pair; }); }); });
    }).then(function (pair) {
      return exportPubSpkiB64(pair.publicKey).then(function (spki) {
        return fingerprintOfSpki(spki).then(function (fp) {
          return fetch(AUTH_URL + '/device/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + sessionToken },
            body: JSON.stringify({ public_key: spki, fingerprint: fp, label: deviceLabel() })
          }).then(function (resp) {
            if (!resp.ok) throw new Error('register-failed-' + resp.status);
            return resp.json();
          }).then(function (data) {
            var now = Date.now();
            var cache = {
              username: user.username,
              display_name: user.display_name || '',
              title: user.title || '',
              deviceId: data.device_id,
              fingerprint: fp,
              graceToken: data.grace_token,
              lastAuthAt: now,
              highWater: now
            };
            _fp = fp;
            return saveCache(cache).then(function () { return cache; });
          });
        });
      });
    });
  }

  /* ---------------- online refresh (slides the 7-day window; catches revoke/tamper/hard) ----------------
   * /grace/challenge -> sign nonce with the device private key -> /grace/refresh.
   * Returns { status, cache? }. Network failure -> { status: OFFLINE } so the caller falls
   * back to the offline state machine without disturbing the cache. */
  function refreshOnline() {
    return loadCache().then(function (cache) {
      if (!cache) return { status: STATES.UNAUTHENTICATED };
      return sec.get(K_PRIV).then(function (priv) {
        if (!priv) return wipe(STATES.REVOKED_OR_TAMPERED); // keys lost -> can't prove device
        return fetch(AUTH_URL + '/grace/challenge', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: cache.graceToken })
        }).then(function (resp) {
          return resp.json().catch(function () { return {}; }).then(function (body) {
            if (!resp.ok) return rejectByReason(resp.status, body);
            return signNonce(priv, body.nonce).then(function (sig) {
              return fetch(AUTH_URL + '/grace/refresh', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: cache.graceToken, nonce: body.nonce, signature: sig })
              }).then(function (r2) {
                return r2.json().catch(function () { return {}; }).then(function (b2) {
                  if (!r2.ok) return rejectByReason(r2.status, b2);
                  var now = Date.now();
                  cache.graceToken = b2.grace_token;
                  cache.lastAuthAt = now;
                  cache.highWater = now;
                  if (b2.display_name) cache.display_name = b2.display_name;
                  if (b2.title) cache.title = b2.title;
                  return saveCache(cache).then(function () { return { status: STATES.ONLINE_AUTHED, cache: cache }; });
                });
              });
            });
          });
        }).catch(function () { return { status: STATES.OFFLINE }; }); // genuine network failure
      });
    });
  }

  // Map a non-OK server response to an outcome. Revocation/tamper wipe the cache; the
  // 30-day hard checkpoint keeps the device keypair so the next password login reuses it.
  function rejectByReason(httpStatus, body) {
    var reason = body && body.reason;
    if (reason === 'hard_reauth' || httpStatus === 426) return { status: STATES.HARD_REAUTH };
    if (reason === 'revoked') return wipe(STATES.REVOKED_OR_TAMPERED);
    // invalid token, bad signature, fp/did mismatch, unknown device -> tamper/migration
    return wipe(STATES.REVOKED_OR_TAMPERED);
  }

  function wipe(status) { return clearCache().then(function () { return { status: status }; }); }

  /* ---------------- local (offline) state machine ---------------- */
  function computeState(cache, online) {
    if (!cache) return STATES.UNAUTHENTICATED;
    var now = Date.now();
    // Clock-rollback guard: device clock moved meaningfully behind the high-water mark.
    if (now < (cache.highWater || 0) - CLOCK_SKEW_MS) return STATES.GRACE_EXPIRED;
    var claims = parseClaims(cache.graceToken) || {};
    var graceExpired = claims.gexp != null && now >= claims.gexp;
    var hardExpired  = claims.hexp != null && now >= claims.hexp;
    if (!online) return (graceExpired || hardExpired) ? STATES.GRACE_EXPIRED : STATES.OFFLINE_GRACE;
    return hardExpired ? STATES.HARD_REAUTH : STATES.ONLINE_AUTHED;
  }

  /* ---------------- wipe ---------------- */
  function clearCache() {
    _fp = null;
    return sec.clearAll().catch(function () {});
  }

  /* ---------------- status mirror for the audit provider ---------------- */
  function setStatus(s) {
    if (s && typeof s.mode === 'string') _mode = s.mode;
    if (s && typeof s.online === 'boolean') _online = s.online;
  }
  function auditInfo() { return { device_fingerprint: _fp, auth_mode: _mode, online: _online }; }

  // Register the audit provider with the storage layer so drafts/outbox get stamped.
  if (window.CARL && window.CARL.setAuditProvider) window.CARL.setAuditProvider(auditInfo);

  window.CARLAuth = {
    STATES: STATES,
    AUTH_URL: AUTH_URL,
    ensureSecureCapable: ensureSecureCapable,
    firstTimeProvision: firstTimeProvision,
    loadCache: loadCache,
    refreshOnline: refreshOnline,
    computeState: computeState,
    clearCache: clearCache,
    parseClaims: parseClaims,
    setStatus: setStatus,
    auditInfo: auditInfo,
    deviceLabel: deviceLabel
  };
})();
