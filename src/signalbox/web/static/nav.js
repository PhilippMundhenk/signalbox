// Navigation shell: a side bar on wide screens, a compact top bar plus the same side bar as a drawer
// on narrow ones. Icons are built with setAttribute, never from markup strings.
import { h, s } from './util.js';
import { t } from './i18n.js';

export const WIDE = window.matchMedia('(min-width: 1100px)');

// 24x24 stroke icons, one path string per shape.
const ICONS = {
  findings: ['M12 3 2.5 20h19L12 3z', 'M12 10v4', 'M12 17.2v.1'],
  devices: ['M3 5h18v6H3z', 'M3 13h18v6H3z', 'M7 8h.01', 'M7 16h.01'],
  topology: ['M12 4a2 2 0 1 0 0 .01', 'M5 19a2 2 0 1 0 0 .01', 'M19 19a2 2 0 1 0 0 .01', 'M12 6v5l-6 6', 'M12 11l6 6'],
  segments: ['M4 7h16', 'M4 12h16', 'M4 17h16', 'M8 5v14', 'M16 5v14'],
  wireless: ['M2.5 9a14 14 0 0 1 19 0', 'M5.5 12.5a9.5 9.5 0 0 1 13 0', 'M8.8 16a5 5 0 0 1 6.4 0', 'M12 19.5v.01'],
  services: ['M4 6h16v5H4z', 'M4 13h16v5H4z', 'M8 8.5h.01', 'M8 15.5h.01'],
  clients: ['M3 5h14v10H3z', 'M8 19h4', 'M10 15v4', 'M19 9h2v10h-2z'],
  desired: ['M5 4h14v16H5z', 'M8.5 9l2 2 4-4', 'M8.5 15h7'],
  changes: ['M4 8h13l-3-3', 'M20 16H7l3 3'],
  settings: ['M4 7h10', 'M18 7h2', 'M4 17h2', 'M10 17h10', 'M16 5v4', 'M8 15v4'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  close: ['M6 6l12 12', 'M18 6L6 18'],
};

export function icon(name) {
  return s(
    'svg',
    { class: 'icon', viewBox: '0 0 24 24', width: '20', height: '20', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false' },
    ICONS[name].map((d) => s('path', { d })),
  );
}

const FOCUSABLE = 'a[href], button:not([disabled])';
let closeCurrent = null;

// Close the drawer when the screen becomes wide while it is open.
WIDE.addEventListener('change', () => {
  if (WIDE.matches && closeCurrent) closeCurrent(false);
});

/**
 * items: [[key, href, label]]; current: key of the active section; brand(): a logo node;
 * actions: node with theme and log out. Returns {shell, content}; the caller fills content.
 */
export function buildShell({ items, current, brand, actions }) {
  const currentLabel = (items.find(([key]) => key === current) || [])[2] || '';
  const menuBtn = h(
    'button',
    { class: 'btn menu-btn', type: 'button', 'aria-label': t('nav.menu'), 'aria-expanded': 'false', 'aria-controls': 'sidebar', 'data-testid': 'nav-menu' },
    icon('menu'),
  );
  const topbar = h(
    'header',
    { class: 'topbar' },
    menuBtn,
    h('a', { class: 'brand', href: '#/', 'aria-label': 'Signalbox' }, brand(), h('span', { class: 'brand-text' }, 'Signalbox')),
    h('span', { class: 'current-section', 'data-testid': 'nav-current' }, currentLabel),
  );
  const nav = h(
    'nav',
    { class: 'nav', 'aria-label': t('nav.main') },
    items.map(([key, href, text]) =>
      h('a', { href, 'aria-current': current === key ? 'page' : null, 'data-testid': `nav-${key}` }, icon(key), h('span', { class: 'nav-label' }, text)),
    ),
  );
  const closeBtn = h('button', { class: 'btn ghost close-btn', type: 'button', 'aria-label': t('nav.closeMenu'), 'data-testid': 'nav-close' }, icon('close'));
  const sidebar = h(
    'div',
    { class: 'sidebar', id: 'sidebar' },
    h('div', { class: 'sidebar-head' }, h('a', { class: 'brand', href: '#/', 'aria-label': t('nav.startPage') }, brand(), 'Signalbox'), closeBtn),
    nav,
    actions,
  );
  const scrim = h('div', { class: 'scrim', 'data-testid': 'nav-scrim' });
  const content = h('div', { class: 'content' });
  const shell = h('div', { class: 'shell' }, topbar, sidebar, scrim, content);

  const setOpen = (open, restoreFocus = true) => {
    shell.classList.toggle('drawer-open', open);
    menuBtn.setAttribute('aria-expanded', String(open));
    for (const el of [topbar, content]) el.toggleAttribute('inert', open);
    if (open) {
      closeCurrent = () => setOpen(false, false);
      (nav.querySelector('[aria-current="page"]') || nav.querySelector('a')).focus();
    } else {
      closeCurrent = null;
      if (restoreFocus && sidebar.contains(document.activeElement)) menuBtn.focus();
    }
  };
  menuBtn.addEventListener('click', () => setOpen(!shell.classList.contains('drawer-open')));
  closeBtn.addEventListener('click', () => setOpen(false));
  scrim.addEventListener('click', () => setOpen(false));
  // A link to the page already shown does not change the hash, so close explicitly.
  nav.addEventListener('click', (e) => {
    if (e.target.closest('a')) setOpen(false, false);
  });
  sidebar.addEventListener('keydown', (e) => {
    if (!shell.classList.contains('drawer-open')) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      setOpen(false);
    } else if (e.key === 'Tab') {
      const stops = [...sidebar.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null);
      const first = stops[0];
      const last = stops[stops.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });
  return { shell, content };
}
