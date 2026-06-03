/* CARL Field PWA service worker.
 * Responsibilities:
 *   - Precache the app shell so the app loads offline.
 *   - Network-first for navigations (always prefer fresh app.html), cache fallback.
 *   - Stale-while-revalidate for same-origin static assets (icons, manifest, carl-db.js).
 *   - NEVER intercept the cross-origin webhook POST or any non-GET request — those
 *     pass straight through to the network so CORS and the 3-minute pipeline are untouched.
 *   - Best-effort Background Sync (Android/Chromium only) to flush the outbox after the
 *     page has closed. iOS has no Background Sync; the page handles retry/recovery there.
 *
 * Shared IndexedDB contract with carl-db.js: DB "carl-field" v2, stores "outbox"
 * (keyPath "id"), items { id, status, payload, idempotencyKey, createdAt, result }, plus
 * "drafts" and "secure" (offline-auth material, owned by carl-offline-auth.js).
 * Bump SHELL_CACHE when shell assets change to force an update.
 */
const SHELL_CACHE = 'carl-shell-v7';
const WEBHOOK_URL = 'https://n8n.carlcompliance.com/webhook/carl-verify';

const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/carl-db.js',
  '/carl-offline-auth.js',
  '/offline.html',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-192.png',
  '/icons/icon-maskable-512.png',
  '/icons/apple-touch-icon-180.png',
  '/icons/favicon-32.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      // addAll is atomic; use individual puts so one missing asset can't abort install.
      .then((cache) => Promise.all(SHELL_ASSETS.map((url) =>
        cache.add(url).catch((err) => console.warn('[sw] precache skip', url, err))
      )))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Let non-GET (webhook POST, daily-report POST, etc.) and cross-origin requests pass through untouched.
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Navigations: network-first, fall back to cached app shell, then offline page.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((resp) => {
          const copy = resp.clone();
          caches.open(SHELL_CACHE).then((c) => c.put(req, copy)).catch(() => {});
          return resp;
        })
        .catch(() => caches.match(req)
          .then((hit) => hit || caches.match('/index.html'))
          .then((hit) => hit || caches.match('/'))
          .then((hit) => hit || caches.match('/offline.html')))
    );
    return;
  }

  // Same-origin static assets: stale-while-revalidate.
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req).then((resp) => {
        if (resp && resp.status === 200) {
          const copy = resp.clone();
          caches.open(SHELL_CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return resp;
      }).catch(() => cached);
      return cached || network;
    })
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'skip-waiting') self.skipWaiting();
});

/* ---- Background Sync: best-effort outbox flush (Android/Chromium) ---- */
self.addEventListener('sync', (event) => {
  if (event.tag === 'carl-outbox-sync') {
    event.waitUntil(flushOutboxFromSW());
  }
});

function idbOpen() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open('carl-field', 2);
    r.onupgradeneeded = () => {
      const db = r.result;
      if (!db.objectStoreNames.contains('drafts')) db.createObjectStore('drafts', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('outbox')) db.createObjectStore('outbox', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('secure')) db.createObjectStore('secure', { keyPath: 'k' });
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

function idbAll(db, store) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db, store, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function flushOutboxFromSW() {
  let db;
  try { db = await idbOpen(); } catch (e) { return; }
  const items = (await idbAll(db, 'outbox')).filter((i) => i.status === 'queued');
  for (const item of items) {
    try {
      item.status = 'sending';
      await idbPut(db, 'outbox', item);
      const resp = await fetch(WEBHOOK_URL, {
        method: 'POST',
        mode: 'cors',
        headers: { 'Content-Type': 'application/json', 'X-CARL-Idempotency': item.idempotencyKey || '' },
        body: JSON.stringify(item.payload)
      });
      if (resp.ok) {
        item.result = await resp.json();
        item.status = 'done';
        item.completedAt = Date.now();
      } else {
        // Reached the server but it errored — leave for foreground recovery (may have processed).
        item.status = 'sent';
      }
    } catch (e) {
      // Send did not complete in the background; mark 'sent' so the page can recover via daily report.
      item.status = (item.status === 'sending') ? 'sent' : 'queued';
    }
    try { await idbPut(db, 'outbox', item); } catch (e) {}
    // Tell any open client to refresh its queue view.
    const clients = await self.clients.matchAll();
    clients.forEach((c) => c.postMessage({ type: 'outbox-updated', id: item.id, status: item.status }));
  }
}
