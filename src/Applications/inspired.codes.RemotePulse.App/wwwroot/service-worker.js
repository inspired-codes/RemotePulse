// Bump this whenever this file changes. `activate` deletes every cache that isn't the current
// name, which is also how stale _framework/ entries from old deployments get cleared - so give
// it a nudge after a few app deploys even if this file's logic didn't change.
const CACHE_NAME = 'remotepulse-cache-v13';

// Precached on install so the app shell paints with no network at all. The framework itself
// (_framework/*) is NOT listed here - its filenames are content hashes that change every build,
// so it's cached on demand instead (see the fetch handler). One online launch pulls the whole
// runtime; every launch after that works offline.
const STATIC_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icon.png',
  './icons/icon-192x192.png',
  './icons/icon-512x512.png',
  './icons/icon-master.svg'
];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.filter(c => c !== CACHE_NAME).map(c => caches.delete(c))
      );
    }).then(() => self.clients.claim())
  );
});

// ignoreVary: framework assets can come back with `Vary: Accept-Encoding` (compression at the
// proxy), and without this a cached hit is rejected whenever that header differs.
const MATCH_OPTS = { ignoreVary: true };

// stale-safe network-first: try the network, cache what comes back, fall back to cache offline.
function networkFirst(request, fallback) {
  return fetch(request)
    .then((res) => {
      const clone = res.clone();
      caches.open(CACHE_NAME).then(c => c.put(request, clone));
      return res;
    })
    .catch(() => caches.match(request, MATCH_OPTS).then((cached) => cached || (fallback ? caches.match(fallback, MATCH_OPTS) : undefined)));
}

// cache-first: serve from cache, otherwise fetch once and keep it. Correct forever for
// content-addressed files, since a given URL's bytes never change.
function cacheFirst(request) {
  return caches.match(request, MATCH_OPTS).then((cached) => {
    return cached || fetch(request).then((res) => {
      const clone = res.clone();
      caches.open(CACHE_NAME).then(c => c.put(request, clone));
      return res;
    });
  });
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // API calls and writes always go straight to the network, never cached.
  if (url.pathname.startsWith('/api/') || e.request.method !== 'GET') {
    e.respondWith(fetch(e.request));
    return;
  }

  // Distribution downloads, landing portal, and bootstrap scripts always stream directly from the network
  if (url.pathname === '/' || url.pathname === '/portal.html' || url.pathname.startsWith('/downloads/') || url.pathname.endsWith('.zip') || url.pathname.endsWith('.ps1')) {
    e.respondWith(fetch(e.request));
    return;
  }

  // Blazor runtime + RCL static assets. Every filename here is a content hash (dotnet.js has
  // no boot.json in .NET 10 - the runtime resolves the fingerprinted list itself), so a cached
  // entry is immutable and cache-first is always right. A new build ships new filenames, which
  // simply miss the cache and get fetched fresh. This is what lets the app boot with no network.
  // Exception: a fixed-name manifest (*.json) under _framework/ must stay network-first so a
  // redeploy is picked up - there are none today, but guard against a future one.
  if (url.pathname.startsWith('/_framework/') || url.pathname.startsWith('/_content/')) {
    e.respondWith(url.pathname.endsWith('.json') ? networkFirst(e.request) : cacheFirst(e.request));
    return;
  }

  // The HTML shell names every fingerprinted file via its importmap, so it must never go stale
  // cache-first - a rebuild that shifts those hashes would otherwise strand installed clients on
  // filenames the server no longer has. Network-first, cached copy only when genuinely offline.
  if (e.request.mode === 'navigate' || url.pathname === '/app' || url.pathname.startsWith('/app/') || url.pathname.endsWith('/index.html')) {
    e.respondWith(networkFirst(e.request, './index.html'));
    return;
  }

  // App JS/CSS (qrScannerInterop.js, app.css): network-first so edits propagate on next online load.
  if (url.pathname.endsWith('.js') || url.pathname.endsWith('.css')) {
    e.respondWith(networkFirst(e.request));
    return;
  }

  // Everything else (images, manifest): cache-first.
  e.respondWith(cacheFirst(e.request));
});
