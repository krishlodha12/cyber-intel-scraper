// Network first (always fresh when online); falls back to the last copy when offline.
const CACHE = 'tl-v1';
self.addEventListener('install', e => e.waitUntil(
  caches.open(CACHE).then(c => c.addAll(['./', 'icon-192.png'])).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(fetch(e.request).then(r => {
    const copy = r.clone();
    caches.open(CACHE).then(c => c.put(e.request, copy));
    return r;
  }).catch(() => caches.match(e.request).then(m => m || caches.match('./'))));
});
