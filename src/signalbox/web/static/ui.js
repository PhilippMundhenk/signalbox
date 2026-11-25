// Shared UI pieces: toasts, dialogs, form fields, tables, badges.
import { ApiError } from './api.js';
import { clear, h } from './util.js';
import { has, t } from './i18n.js';

// A toast confirms something that worked and goes away by itself. Problems are never toasts:
// they are notices (below), so they stay until resolved.
export function toast(message, kind = 'ok') {
  const root = document.getElementById('toasts');
  const el = h('div', { class: `toast ${kind}`, role: 'status', 'data-testid': 'toast' }, message);
  root.append(el);
  setTimeout(() => el.remove(), 3500);
  return el;
}

// One notice for every page (#300, #311): kind "info" (default), "warn" or "error"; an error is an
// alert for screen readers, the others a polite status.
export function notice(kind, testid, ...children) {
  return h('div', { class: `notice ${kind}`, role: kind === 'error' ? 'alert' : 'status', 'data-testid': testid }, ...children);
}

// The one rule for notices (#311): every context (the page, a form, a dialog, a panel) has ONE
// slot. A newer result replaces what is there (setNotice), a success or a new attempt clears it
// (clearNotice), and a notice that is only information can be dismissed.
export function slot(testid) {
  return h('div', { class: 'notice-slot', 'data-slot': testid || null });
}

export function clearNotice(box) {
  if (box) clear(box);
  return box;
}

// kind, testid, content (text or nodes). opts.dismiss adds a close button.
export function setNotice(box, kind, testid, content, opts = {}) {
  if (!box) return null;
  const el = notice(kind, testid, content);
  if (opts.dismiss) el.prepend(h('button', { class: 'notice-close', type: 'button', 'aria-label': t('common.dismiss'), title: t('common.dismiss'), 'data-testid': 'notice-dismiss', onclick: () => el.remove() }, '×'));
  clear(box);
  box.append(el);
  return el;
}

// A running state: spinner and text (the text says what is going on).
export function busy(testid, ...children) {
  return h('div', { class: 'busy', role: 'status', 'aria-live': 'polite', 'data-testid': testid }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), h('div', { class: 'busy-text' }, ...children));
}

// The page's own slot, above the content; errors without a closer context land here.
let pageBox = null;
export function setPageSlot(box) {
  pageBox = box;
}
export function pageSlot() {
  return pageBox;
}

// Show an error in `box` (default: the page slot). A refused login is the login page's job.
export function showError(err, box) {
  if (err instanceof ApiError && err.code === 'login_required') return;
  const target = box || pageBox;
  const text = err && err.message ? err.message : String(err);
  if (target) setNotice(target, 'error', target === pageBox ? 'page-error' : 'error', text, { dismiss: target === pageBox });
  else toast(text, 'error');
}

export function modal({ title, body, actions, onClose }) {
  const root = document.getElementById('modal-root');
  const previous = document.activeElement;
  const close = () => {
    overlay.remove();
    document.documentElement.classList.remove('modal-open');
    if (previous && previous.focus) previous.focus();
    if (onClose) onClose();
  };
  const box = h(
    'div',
    { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title, 'data-testid': 'modal' },
    h('h2', {}, title),
    h('div', { class: 'modal-body', 'data-testid': 'modal-body' }, body),
    h('div', { class: 'modal-actions' }, actions(close)),
  );
  const overlay = h('div', { class: 'overlay' }, box);
  overlay.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
  });
  clear(root).append(overlay);
  document.documentElement.classList.add('modal-open'); // the page behind does not scroll (#524)
  const first = box.querySelector('input, select, button');
  if (first) first.focus();
  return close;
}

export function confirmDialog({ title, message, confirmLabel = t('common.confirm'), danger = false }) {
  return new Promise((resolve) => {
    let answered = false;
    const done = (value, close) => {
      answered = true;
      close();
      resolve(value);
    };
    modal({
      title,
      body: h('p', {}, message),
      onClose: () => {
        if (!answered) resolve(false);
      },
      actions: (close) => [
        h('button', { class: 'btn', 'data-testid': 'confirm-cancel', onclick: () => done(false, close) }, t('common.cancel')),
        h('button', { class: danger ? 'btn danger' : 'btn primary', 'data-testid': 'confirm-ok', onclick: () => done(true, close) }, confirmLabel),
      ],
    });
  });
}

let fieldCounter = 0;
export function field(label, control, hint) {
  if (!control.id) {
    fieldCounter += 1;
    control.id = `f${fieldCounter}`;
  }
  const help = hint ? h('small', { class: 'muted', id: `${control.id}-help` }, hint) : null;
  if (help) control.setAttribute('aria-describedby', help.id);
  return h('div', { class: 'field' }, h('label', { for: control.id }, label), control, help);
}

export function checkField(label, control, hint) {
  return h('div', { class: 'field' }, h('label', { class: 'check' }, control, ' ', label), hint ? h('small', { class: 'muted' }, hint) : null);
}

export function select(options, value, attrs = {}) {
  const el = h('select', attrs);
  for (const [val, text] of options) el.append(h('option', { value: val, selected: String(val) === String(value) }, text));
  return el;
}

// Runs an action with its button disabled. A failure is shown in `box` (default: the page slot),
// replacing an older one; a success clears it.
export async function run(button, fn, box) {
  if (button) button.disabled = true;
  try {
    const result = await fn();
    clearNotice(box || pageBox);
    return result;
  } catch (err) {
    showError(err, box);
    return undefined;
  } finally {
    if (button) button.disabled = false;
  }
}

export function pageHead(title, ...actions) {
  return h('div', { class: 'page-head' }, h('h1', {}, title), ...actions);
}

// Link to a device's own web interface (#214); null when none is known. The URL comes from the
// backend (scheme, host and port only) and is set as an attribute, never as HTML.
export function manageLink(device, label, testid, cls) {
  if (!/^https?:\/\//.test(device.manage_url || '')) return null;
  return h('a', { class: cls || null, href: device.manage_url, target: '_blank', rel: 'noopener noreferrer', title: t('ui.openWeb', { name: device.name }), 'aria-label': t('ui.openWebAria', { name: device.name }), 'data-testid': testid }, label);
}

export function card(title, ...children) {
  return h('section', { class: 'card' }, title ? h('h2', {}, title) : null, ...children);
}

export function empty(testid, title, ...children) {
  return h('div', { class: 'card empty', 'data-testid': testid }, h('h2', {}, title), ...children);
}

// A table that becomes stacked cards on a phone. columns: [label, (row) => node|text, className?]
export function table(columns, rows, { testid, rowTestid, rowAttrs, compact } = {}) {
  const thead = h('thead', {}, h('tr', {}, columns.map(([label, , cls]) => h('th', { scope: 'col', class: cls || null }, label))));
  const tbody = h('tbody', {});
  for (const row of rows) {
    const extra = rowAttrs ? rowAttrs(row) : {};
    tbody.append(
      h(
        'tr',
        { 'data-testid': rowTestid || null, ...extra },
        columns.map(([label, fn, cls]) => {
          const value = fn(row);
          return h('td', { 'data-label': label, class: cls || null }, value === null || value === undefined || value === '' ? '–' : value);
        }),
      ),
    );
  }
  return h('div', { class: 'table-wrap' }, h('table', { class: compact ? 'stack compact' : 'stack', 'data-testid': testid || null }, thead, tbody));
}

const STATUS_TEXT = {
  ok: 'ui.status.ok',
  partial: 'ui.status.partial',
  unreachable: 'ui.status.unreachable',
  'auth-failed': 'ui.status.authFailed',
  'untrusted-certificate': 'ui.status.untrusted',
};

export function statusBadge(status) {
  const key = status || 'unknown';
  return h('span', { class: `badge status-${key}`, 'data-testid': 'status', 'data-status': key }, t(STATUS_TEXT[key] || 'ui.status.unknown'));
}

export function severityBadge(severity) {
  return h('span', { class: `badge sev-${severity}`, 'data-testid': 'severity' }, t({ error: 'ui.severity.error', warning: 'ui.severity.warning', info: 'ui.severity.info' }[severity] || 'ui.severity.info'));
}

export function tag(text, cls = '') {
  return h('span', { class: `tag ${cls}`.trim() }, text);
}

const SOURCE = { reported: 'ui.source.reported', declared: 'ui.source.declared', heuristic: 'ui.source.heuristic' };
const PURPOSE = { main: 'ui.purpose.main', guest: 'ui.purpose.guest', iot: 'ui.purpose.iot', management: 'ui.purpose.management', servers: 'ui.purpose.servers', lab: 'ui.purpose.lab', voice: 'ui.purpose.voice', cameras: 'ui.purpose.cameras', transit: 'ui.purpose.transit', other: 'ui.purpose.other' };
const purposeName = (p) => (PURPOSE[p] && has(PURPOSE[p]) ? t(PURPOSE[p]) : p);
const UNTRUSTED = new Set(['guest', 'iot', 'cameras']);

// Purpose of a segment or SSID ("guest", "iot", ...) with where it comes from; a guess gets a "?".
export function purposeTag(obj) {
  if (!obj || !obj.purpose) return null;
  const guessed = obj.purpose_source === 'heuristic';
  const cls = ['purpose', UNTRUSTED.has(obj.purpose) ? 'untrusted' : '', guessed ? 'guess' : ''].join(' ');
  const el = h('span', { class: `tag ${cls}`.trim(), 'data-testid': 'purpose', 'data-source': obj.purpose_source || '', title: SOURCE[obj.purpose_source] ? t(SOURCE[obj.purpose_source]) : '' }, guessed ? `${purposeName(obj.purpose)}?` : purposeName(obj.purpose));
  if (obj.reported_purpose) el.title += ` (${t('ui.deviceReports', { purpose: obj.reported_purpose })})`;
  return el;
}

export function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    dl.append(h('dt', {}, k), h('dd', {}, v === null || v === '' ? '–' : v));
  }
  return dl;
}

export function tabs(items, current, testPrefix = 'tab') {
  return h(
    'nav',
    { class: 'tabs', 'aria-label': t('ui.sections') },
    items.map(([key, text, href]) => h('a', { href, 'aria-current': key === current ? 'page' : null, 'data-testid': `${testPrefix}-${key}` }, text)),
  );
}

export function filterBar(...controls) {
  return h('div', { class: 'filters' }, ...controls);
}
