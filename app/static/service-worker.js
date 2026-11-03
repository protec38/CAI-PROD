/* Only the public shell and local assets are cached. Never cache sessions,
   authenticated HTML, API responses, mutations, exports or shared links. */
// Bump the cache version whenever a shell asset changes.
const CACHE = 'cai-shell-v5';
const ASSETS = ['/hors-ligne', '/hors-ligne/fiche', '/hors-ligne/fiche/detail', '/static/offline.css', '/static/offline-store.js', '/static/offline.js', '/static/responsive.css', '/static/accessibility.js'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key =>
    key.startsWith('cai-shell-') && key !== CACHE).map(key => caches.delete(key))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (ASSETS.includes(url.pathname)) {
    event.respondWith(caches.open(CACHE).then(async cache => {
      const cached = await cache.match(url.pathname);
      return cached || fetch(event.request);
    }));
  } else if (event.request.mode === 'navigate' &&
    (/^\/evenement\/\d+\/dashboard$/.test(url.pathname) || /^\/fiche\/(?:\d+|local-[a-f0-9-]+)$/.test(url.pathname) ||
      ['/', '/evenement/new', '/fiche/new'].includes(url.pathname))) {
    const fallback = url.pathname === '/fiche/new' ? '/hors-ligne/fiche' :
      /^\/fiche\/(?:\d+|local-[a-f0-9-]+)$/.test(url.pathname) ? '/hors-ligne/fiche/detail' : '/hors-ligne';
    if (/^\/fiche\/local-/.test(url.pathname)) {
      event.respondWith(caches.match(fallback)); return;
    }
    event.respondWith(fetch(event.request, {signal: AbortSignal.timeout(6000)}).then(async response => {
      if (response.status >= 500) return (await caches.match(fallback)) || response;
      return response;
    }).catch(() => caches.match(fallback)));
  }
});
