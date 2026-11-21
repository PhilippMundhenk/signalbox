// Small helpers: DOM builder, formatting. No dependencies.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  append(el, children);
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

// SVG elements (topology); attributes are set with setAttribute, never as markup.
export function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  setAttrs(el, attrs);
  append(el, children);
  return el;
}

function setAttrs(el, attrs) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.setAttribute('class', value);
    else if (key.startsWith('on')) el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'value') el.value = value;
    else if (key === 'checked' || key === 'disabled' || key === 'selected') el[key] = Boolean(value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

// Appends children, skipping null/undefined/false and flattening arrays (unlike Element.append).
export function place(el, ...children) {
  return append(el, children);
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function fmtTime(iso) {
  if (!iso) return '–';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function fmtAgo(iso, now = Date.now()) {
  if (!iso) return 'never';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return String(iso);
  const d = Math.max(0, Math.round((now - t) / 1000));
  if (d < 10) return 'just now';
  if (d < 60) return `${d} s ago`;
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} d ago`;
}

// SHA-256 hex as the devices show it: upper-case byte pairs, colon-separated.
export function groupHex(hex) {
  return String(hex || '').toUpperCase().match(/.{1,2}/g)?.join(':') || '';
}

export function yesNo(value) {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return '–';
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function by(key) {
  return (a, b) => String(key(a)).localeCompare(String(key(b)), undefined, { numeric: true });
}
