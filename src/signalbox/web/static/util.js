// Small helpers: DOM builder, formatting. No dependencies.
import { compare, fmtDate, fmtNumber, t } from './i18n.js';

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

// A technical value (address, MAC, id) that stays left-to-right inside right-to-left text (#204).
export function ltr(text, tag = 'bdi') {
  return h(tag, { dir: 'ltr', class: 'ltr' }, text);
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
  return fmtDate(d);
}

export function fmtAgo(iso, now = Date.now()) {
  if (!iso) return t('util.never');
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return String(iso);
  const d = Math.max(0, Math.round((now - ts) / 1000));
  if (d < 10) return t('util.justNow');
  if (d < 60) return t('util.secondsAgo', { n: fmtNumber(d) });
  if (d < 3600) return t('util.minutesAgo', { n: fmtNumber(Math.floor(d / 60)) });
  if (d < 86400) return t('util.hoursAgo', { n: fmtNumber(Math.floor(d / 3600)) });
  return t('util.daysAgo', { n: fmtNumber(Math.floor(d / 86400)) });
}

// SHA-256 hex as the devices show it: upper-case byte pairs, colon-separated.
export function groupHex(hex) {
  return String(hex || '').toUpperCase().match(/.{1,2}/g)?.join(':') || '';
}

export function yesNo(value) {
  if (value === true) return t('common.yes');
  if (value === false) return t('common.no');
  return '–';
}

export function fmtSpeed(mbps) {
  return mbps >= 1000 ? t('util.gbit', { n: fmtNumber(mbps / 1000) }) : t('util.mbit', { n: fmtNumber(mbps) });
}

// Link speed, with the port's maximum where it is faster ("1 Gbit/s of 2.5 Gbit/s").
export function portSpeed(p) {
  const top = p.max_speed_mbps;
  if (!p.speed_mbps) return top ? t('util.speedMax', { speed: fmtSpeed(top) }) : null;
  return top && top > p.speed_mbps ? t('util.speedOf', { speed: fmtSpeed(p.speed_mbps), top: fmtSpeed(top) }) : fmtSpeed(p.speed_mbps);
}

// Port configuration details (#156), only those the device reports.
export function portDetails(p) {
  return [
    p.admin_up === false ? t('util.disabled') : null,
    p.pvid ? t('util.pvid', { id: p.pvid }) : null,
    p.mtu ? t('util.mtu', { n: p.mtu }) : p.jumbo === true ? t('util.jumbo') : null,
    p.profile ? t('util.profile', { name: p.profile }) : null,
  ].filter(Boolean);
}

// Where a port sits in its device (#252, Port.role).
export const PORT_ROLE = {
  get jack() {
    return t('util.role.jack');
  },
  get cpu() {
    return t('util.role.cpu');
  },
  get 'switch-port'() {
    return t('util.role.switchPort');
  },
  get bridge() {
    return t('util.role.bridge');
  },
  get vlan() {
    return t('util.role.vlan');
  },
  get wireless() {
    return t('util.role.wireless');
  },
  get lag() {
    return t('util.role.lag');
  },
  get tunnel() {
    return t('util.role.tunnel');
  },
  get virtual() {
    return t('util.role.virtual');
  },
};

// How a link aggregation works (#157, Port.lag_mode).
export const LAG_MODE = {
  get static() {
    return t('util.lagMode.static');
  },
  get 'lacp-active'() {
    return t('util.lagMode.lacpActive');
  },
  get 'lacp-passive'() {
    return t('util.lagMode.lacpPassive');
  },
  get 'active-backup'() {
    return t('util.lagMode.activeBackup');
  },
  get 'balance-rr'() {
    return t('util.lagMode.balanceRr');
  },
  get 'balance-xor'() {
    return t('util.lagMode.balanceXor');
  },
  get broadcast() {
    return t('util.lagMode.broadcast');
  },
  get 'balance-tlb'() {
    return t('util.lagMode.balanceTlb');
  },
  get 'balance-alb'() {
    return t('util.lagMode.balanceAlb');
  },
  get other() {
    return t('util.lagMode.other');
  },
};

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function by(key) {
  return (a, b) => compare(key(a), key(b));
}

export function fmtBytes(n) {
  if (n === null || n === undefined) return '–';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = v < 10 ? 1 : 0;
  return `${i ? fmtNumber(v, { minimumFractionDigits: digits, maximumFractionDigits: digits }) : v} ${units[i]}`;
}

export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return '–';
  const s = Math.max(0, Math.round(Number(seconds)));
  const d = Math.floor(s / 86400);
  const hrs = Math.floor((s % 86400) / 3600);
  const min = Math.floor((s % 3600) / 60);
  if (d) return t('util.durDays', { d, h: hrs });
  if (hrs) return t('util.durHours', { h: hrs, m: min });
  if (min) return t('util.durMinutes', { m: min });
  return t('util.durSeconds', { s });
}
