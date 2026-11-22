// Shared UI pieces: toasts, dialogs, form fields, tables, badges.
import { ApiError } from './api.js';
import { clear, h } from './util.js';

export function toast(message, kind = 'ok') {
  const root = document.getElementById('toasts');
  const el = h('div', { class: `toast ${kind}`, role: kind === 'error' ? 'alert' : 'status', 'data-testid': 'toast' }, message);
  root.append(el);
  setTimeout(() => el.remove(), kind === 'error' ? 8000 : 3500);
  return el;
}

export function showError(err) {
  if (err instanceof ApiError && err.code === 'login_required') return;
  toast(err && err.message ? err.message : String(err), 'error');
}

export function modal({ title, body, actions, onClose }) {
  const root = document.getElementById('modal-root');
  const previous = document.activeElement;
  const close = () => {
    overlay.remove();
    if (previous && previous.focus) previous.focus();
    if (onClose) onClose();
  };
  const box = h(
    'div',
    { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title, 'data-testid': 'modal' },
    h('h2', {}, title),
    body,
    h('div', { class: 'modal-actions' }, actions(close)),
  );
  const overlay = h('div', { class: 'overlay' }, box);
  overlay.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
  });
  clear(root).append(overlay);
  const first = box.querySelector('input, select, button');
  if (first) first.focus();
  return close;
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false }) {
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
        h('button', { class: 'btn', 'data-testid': 'confirm-cancel', onclick: () => done(false, close) }, 'Cancel'),
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

export async function run(button, fn) {
  if (button) button.disabled = true;
  try {
    return await fn();
  } catch (err) {
    showError(err);
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
  return h('a', { class: cls || null, href: device.manage_url, target: '_blank', rel: 'noopener noreferrer', title: `Open the web interface of ${device.name}`, 'aria-label': `Open web interface of ${device.name}`, 'data-testid': testid }, label);
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
  ok: 'OK',
  partial: 'Partly read',
  unreachable: 'Unreachable',
  'auth-failed': 'Login failed',
  'untrusted-certificate': 'Untrusted certificate',
};

export function statusBadge(status) {
  const key = status || 'unknown';
  return h('span', { class: `badge status-${key}`, 'data-testid': 'status', 'data-status': key }, STATUS_TEXT[key] || 'Not read yet');
}

export function severityBadge(severity) {
  return h('span', { class: `badge sev-${severity}`, 'data-testid': 'severity' }, { error: 'Error', warning: 'Warning', info: 'Info' }[severity] || severity);
}

export function tag(text, cls = '') {
  return h('span', { class: `tag ${cls}`.trim() }, text);
}

const SOURCE = { reported: 'reported by the device', declared: 'declared in the desired state', heuristic: 'guessed from the name' };
const UNTRUSTED = new Set(['guest', 'iot', 'cameras']);

// Purpose of a segment or SSID ("guest", "iot", ...) with where it comes from; a guess gets a "?".
export function purposeTag(obj) {
  if (!obj || !obj.purpose) return null;
  const guessed = obj.purpose_source === 'heuristic';
  const cls = ['purpose', UNTRUSTED.has(obj.purpose) ? 'untrusted' : '', guessed ? 'guess' : ''].join(' ');
  const el = h('span', { class: `tag ${cls}`.trim(), 'data-testid': 'purpose', 'data-source': obj.purpose_source || '', title: SOURCE[obj.purpose_source] || '' }, guessed ? `${obj.purpose}?` : obj.purpose);
  if (obj.reported_purpose) el.title += ` (device reports ${obj.reported_purpose})`;
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
    { class: 'tabs', 'aria-label': 'Sections' },
    items.map(([key, text, href]) => h('a', { href, 'aria-current': key === current ? 'page' : null, 'data-testid': `${testPrefix}-${key}` }, text)),
  );
}

export function filterBar(...controls) {
  return h('div', { class: 'filters' }, ...controls);
}
