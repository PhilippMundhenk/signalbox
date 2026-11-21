// Entry point: session handling, shell and hash router.
import { get, onUnauthorized, post } from './api.js';
import { append, clear, h } from './util.js';
import { showError } from './ui.js';
import { renderFindings } from './views/findings.js';
import { renderDevices, renderDeviceForm } from './views/devices.js';
import { renderDevice } from './views/device.js';
import { renderSegments } from './views/segments.js';
import { renderWireless } from './views/wireless.js';
import { renderServices } from './views/services.js';
import { renderClients } from './views/clients.js';
import { renderTopology } from './views/topology.js';
import { renderSettings } from './views/settings.js';

const root = document.getElementById('app');
const state = { session: null, cleanups: [], renderId: 0 };
const runCleanups = () => {
  for (const fn of state.cleanups.splice(0)) fn();
};

export const ctx = {
  navigate(hash) {
    if (location.hash === hash) render();
    else location.hash = hash;
  },
  onCleanup(fn) {
    state.cleanups.push(fn); // polls and timers of a page stop when it is left
  },
  refresh() {
    render();
  },
  // True while the page that asked is still the one shown (async work may outlive it).
  alive(id) {
    return id === state.renderId;
  },
  get renderId() {
    return state.renderId;
  },
};

const LOGO = () => h('img', { src: 'favicon.svg', alt: '', width: '28', height: '28', class: 'logo' });
const DISCLAIMER =
  'Signalbox is an independent open-source project, not affiliated with, endorsed or supported by any of the vendors whose devices it works with. Product names are used only to say what it works with.';

export function applyTheme(choice) {
  if (choice === 'light' || choice === 'dark') document.documentElement.dataset.theme = choice;
  else delete document.documentElement.dataset.theme;
}

function savedTheme() {
  try {
    return localStorage.getItem('theme') || 'auto';
  } catch (err) {
    return 'auto';
  }
}

function themeToggle() {
  const order = ['auto', 'light', 'dark'];
  const btn = h('button', { class: 'btn small ghost', type: 'button', 'data-testid': 'theme', 'aria-label': 'Change theme' }, `Theme: ${savedTheme()}`);
  btn.addEventListener('click', () => {
    const next = order[(order.indexOf(savedTheme()) + 1) % order.length];
    try {
      localStorage.setItem('theme', next);
    } catch (err) {
      /* private mode: only for this page */
    }
    applyTheme(next);
    btn.textContent = `Theme: ${next}`;
  });
  return btn;
}

const NAV = [
  ['findings', '#/', 'Findings'],
  ['devices', '#/devices', 'Devices'],
  ['topology', '#/topology', 'Topology'],
  ['segments', '#/segments', 'Segments'],
  ['wireless', '#/wireless', 'Wireless'],
  ['services', '#/dhcp-dns', 'DHCP & DNS'],
  ['clients', '#/clients', 'Clients'],
  ['settings', '#/settings', 'Settings'],
];

export function routeInfo() {
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  const [first, second, third] = parts;
  if (first === 'devices' && second === 'new') return { name: 'device-new', nav: 'devices' };
  if (first === 'devices') return { name: 'devices', nav: 'devices' };
  if (first === 'device' && second) return { name: 'device', nav: 'devices', id: second, tab: third || 'overview' };
  if (first === 'dhcp-dns') return { name: 'services', nav: 'services' };
  const simple = ['segments', 'wireless', 'clients', 'settings', 'topology'];
  if (simple.includes(first)) return { name: first, nav: first };
  return { name: 'findings', nav: 'findings' };
}

function footer(session) {
  return h('footer', {}, h('p', { 'data-testid': 'disclaimer' }, DISCLAIMER), h('p', { 'data-testid': 'version' }, `Signalbox ${session.version}`));
}

function renderLogin(message) {
  runCleanups();
  clear(root);
  const pw = h('input', { type: 'password', id: 'pw', autocomplete: 'current-password', required: true, 'data-testid': 'login-password' });
  const err = h('p', { class: 'error', role: 'alert', 'data-testid': 'login-error' }, message || '');
  const submit = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'login-submit' }, 'Sign in');
  const form = h(
    'form',
    {
      class: 'card login',
      onsubmit: async (e) => {
        e.preventDefault();
        submit.disabled = true;
        try {
          await post('/login', { password: pw.value });
          await boot();
        } catch (ex) {
          err.textContent = ex.message;
          submit.disabled = false;
          pw.select();
        }
      },
    },
    h('div', { class: 'brand' }, LOGO(), 'Signalbox'),
    h('p', { class: 'muted' }, 'Sign in to see and check your network.'),
    h('label', { for: 'pw' }, 'Password'),
    pw,
    err,
    h('p', {}, submit),
    h('p', { class: 'muted small' }, 'First start without a configured password? The generated one is printed in the server log.'),
  );
  root.append(h('main', { id: 'main' }, form), footer(state.session));
  pw.focus();
}

async function render() {
  runCleanups();
  state.renderId += 1;
  const route = routeInfo();
  const session = state.session;
  clear(root);
  const nav = h(
    'nav',
    { class: 'nav', 'aria-label': 'Main' },
    NAV.map(([key, href, text]) => h('a', { href, 'aria-current': route.nav === key ? 'page' : null, 'data-testid': `nav-${key}` }, text)),
  );
  const actions = h(
    'div',
    { class: 'topbar-actions' },
    themeToggle(),
    h(
      'button',
      {
        class: 'btn small',
        type: 'button',
        'data-testid': 'logout',
        onclick: async () => {
          await post('/logout').catch(() => null);
          await boot();
        },
      },
      'Log out',
    ),
  );
  append(root, [h('header', { class: 'topbar' }, h('a', { class: 'brand', href: '#/' }, LOGO(), 'Signalbox'), nav, actions)]);
  const main = h('main', { id: 'main', tabindex: '-1' });
  root.append(main, footer(session));
  try {
    if (route.name === 'findings') await renderFindings(main, ctx);
    else if (route.name === 'devices') await renderDevices(main, ctx);
    else if (route.name === 'device-new') await renderDeviceForm(main, ctx, null);
    else if (route.name === 'device') await renderDevice(main, ctx, route);
    else if (route.name === 'segments') await renderSegments(main, ctx);
    else if (route.name === 'wireless') await renderWireless(main, ctx);
    else if (route.name === 'services') await renderServices(main, ctx);
    else if (route.name === 'clients') await renderClients(main, ctx);
    else if (route.name === 'topology') await renderTopology(main, ctx);
    else await renderSettings(main, ctx, session);
  } catch (err) {
    showError(err);
  }
}

async function boot() {
  const session = await get('/session').catch(() => null);
  if (!session) {
    clear(root);
    root.append(h('main', {}, h('p', { class: 'error', 'data-testid': 'offline' }, 'Cannot reach the Signalbox server.')));
    return;
  }
  state.session = session;
  if (!session.authenticated) {
    renderLogin();
    return;
  }
  await render();
}

window.addEventListener('hashchange', () => {
  if (state.session && state.session.authenticated) render();
});
onUnauthorized(() => {
  if (state.session && state.session.authenticated) {
    state.session.authenticated = false;
    renderLogin('Your session ended. Please sign in again.');
  }
});

applyTheme(savedTheme());
boot();
