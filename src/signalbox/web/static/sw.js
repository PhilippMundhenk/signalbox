// Service worker for Web Push (#372). It is registered only after a person pressed "Subscribe
// this browser" in Settings. It shows the digest text of a push message and opens the link; it
// caches nothing and handles no other request.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (err) {
    data = {};
  }
  const title = typeof data.title === 'string' && data.title ? data.title : 'Signalbox';
  const body = typeof data.body === 'string' ? data.body : '';
  const url = typeof data.url === 'string' ? data.url : './#/';
  event.waitUntil(self.registration.showNotification(title, { body, data: { url }, icon: 'icon-192.png', tag: 'signalbox' }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = new URL((event.notification.data && event.notification.data.url) || './#/', self.registration.scope).href;
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const client of list) {
        if (client.url.split('#')[0] === target.split('#')[0] && 'focus' in client) {
          if ('navigate' in client) client.navigate(target);
          return client.focus();
        }
      }
      return self.clients.openWindow(target);
    }),
  );
});
