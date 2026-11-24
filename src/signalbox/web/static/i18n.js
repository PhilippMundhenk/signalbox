// Translations (#204): message catalogues under i18n/<lang>.json, a tiny t() helper.
// English is the source and the fallback for every missing key; a missing key everywhere shows
// the key itself, so a gap is visible rather than blank. No dependencies, no build step.

const FALLBACK = 'en';
const STORAGE_KEY = 'lang';

let catalog = {};
let fallback = {};
let current = FALLBACK;
let languages = [{ code: 'en', name: 'English', dir: 'ltr' }];
let plural = new Intl.PluralRules('en');

function stored() {
  try {
    return localStorage.getItem(STORAGE_KEY) || '';
  } catch (err) {
    return '';
  }
}

// 'de-AT' -> 'de' when only 'de' is offered; null when nothing matches.
function match(wanted, codes) {
  const lower = String(wanted).toLowerCase();
  return codes.find((c) => c.toLowerCase() === lower) || codes.find((c) => c.toLowerCase() === lower.split('-')[0]) || null;
}

// The language to use: the stored choice, else the browser's preference, else English.
export function pickLanguage(codes, preferred = navigator.languages || [navigator.language], saved = stored()) {
  if (saved && saved !== 'auto') {
    const chosen = match(saved, codes);
    if (chosen) return chosen;
  }
  for (const wanted of preferred || []) {
    const found = match(wanted, codes);
    if (found) return found;
  }
  return FALLBACK;
}

async function fetchJson(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return res.json();
}

export async function initI18n() {
  try {
    const index = await fetchJson('i18n/index.json');
    if (Array.isArray(index) && index.length) languages = index;
  } catch (err) {
    /* only English */
  }
  const code = pickLanguage(languages.map((l) => l.code));
  try {
    fallback = await fetchJson(`i18n/${FALLBACK}.json`);
  } catch (err) {
    fallback = {};
  }
  catalog = fallback;
  if (code !== FALLBACK) {
    try {
      catalog = await fetchJson(`i18n/${code}.json`);
    } catch (err) {
      catalog = fallback;
    }
  }
  current = code;
  plural = new Intl.PluralRules(code);
  const info = languages.find((l) => l.code === code) || {};
  document.documentElement.lang = code;
  document.documentElement.dir = info.dir || 'ltr';
  document.title = t('app.title');
}

export const language = () => current;
export const availableLanguages = () => languages;

export function setLanguage(code) {
  try {
    if (code && code !== 'auto') localStorage.setItem(STORAGE_KEY, code);
    else localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    /* private mode: only for this page */
  }
}

export const savedLanguage = () => stored() || 'auto';

// In right-to-left text every parameter (an address, a name, a number) is wrapped in a first-strong
// isolate, so Latin values keep their own order and do not reorder the words around them (#204).
const FSI = '\u2068';
const PDI = '\u2069';

function fill(text, params) {
  const rtl = document.documentElement.dir === 'rtl';
  return text.replace(/\{(\w+)\}/g, (whole, name) => {
    if (!params || !(name in params) || params[name] === null || params[name] === undefined) return whole;
    const value = String(params[name]);
    return rtl && value ? `${FSI}${value}${PDI}` : value;
  });
}

function lookup(key, params) {
  // Plural forms: key.one / key.other (any CLDR category) chosen by params.count.
  if (params && typeof params.count === 'number') {
    for (const dict of [catalog, fallback]) {
      const form = dict[`${key}.${plural.select(params.count)}`] ?? dict[`${key}.other`];
      if (form !== undefined) return form;
    }
  }
  return catalog[key] ?? fallback[key];
}

// Translate a key; `params` fill {placeholders}. Missing everywhere: the key.
export function t(key, params) {
  const text = lookup(key, params);
  return text === undefined ? key : fill(text, params);
}

// True when a catalogue (this language or English) has the key.
export function has(key) {
  return catalog[key] !== undefined || fallback[key] !== undefined || catalog[`${key}.other`] !== undefined || fallback[`${key}.other`] !== undefined;
}

// A server text with a stable id and parameters (#204): translated when the catalogue has the id,
// otherwise the English text the server sent.
export function tServer(id, params, english) {
  return id && has(id) ? t(id, params) : english;
}

export function fmtNumber(n, options) {
  return new Intl.NumberFormat(current, options).format(n);
}

export function fmtDate(value, options = { dateStyle: 'medium', timeStyle: 'short' }) {
  return new Intl.DateTimeFormat(current, options).format(new Date(value));
}

export function compare(a, b) {
  return String(a).localeCompare(String(b), current, { numeric: true });
}
