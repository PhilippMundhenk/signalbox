// Rule parameters and scopes (#454): a form generated from the JSON Schema GET /api/rules sends.
// Every value shows where it comes from (default, file, set here). Values from signalbox.yaml or the
// environment are read-only; scopes of the file are listed, the page's own scopes are editable.
// Names, ids and values from the server are untrusted: text nodes and value properties only.
import { del, enc, get, put } from '../api.js';
import { append, h } from '../util.js';
import { t } from '../i18n.js';
import { run, select, setNotice, slot, tag, toast } from '../ui.js';

const SELECTORS = [
  ['site', 'settings.sel.site'],
  ['device', 'settings.sel.device'],
  ['device_role', 'settings.sel.device_role'],
  ['segment', 'settings.sel.segment'],
  ['segment_purpose', 'settings.sel.segment_purpose'],
  ['tag', 'settings.sel.tag'],
];
const SOURCE = { default: 'settings.srcDefault', file: 'settings.srcFile', ui: 'settings.srcUi' };

// One control for one parameter, from its JSON Schema property. Returns {el, read()}.
function control(name, prop, value, disabled) {
  const attrs = { 'data-testid': 'param-input', 'data-name': name, disabled, 'aria-label': name };
  if (prop.type === 'boolean') {
    const el = h('input', { ...attrs, type: 'checkbox', checked: Boolean(value) });
    return { el, read: () => el.checked };
  }
  if (Array.isArray(prop.enum)) {
    const el = select(prop.enum.map((v) => [v, String(v)]), value, attrs);
    return { el, read: () => el.value };
  }
  if (prop.type === 'integer' || prop.type === 'number') {
    const el = h('input', {
      ...attrs,
      type: 'number',
      step: prop.type === 'integer' ? '1' : 'any',
      min: prop.minimum !== undefined ? String(prop.minimum) : null,
      max: prop.maximum !== undefined ? String(prop.maximum) : null,
      value: String(value),
    });
    return { el, read: () => (el.value === '' ? null : Number(el.value)) };
  }
  const el = h('input', { ...attrs, type: 'text', maxlength: '200', value: String(value ?? '') });
  return { el, read: () => el.value };
}

function matchText(match) {
  return Object.entries(match)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
}

// The editor of one rule; `reload` redraws the rules after a save.
export function ruleParams(r, reload) {
  const p = r.parameters;
  const props = (p && p.schema && p.schema.properties) || {};
  const names = Object.keys(props);
  const fileScopes = (p ? p.scopes : []).filter((s) => s.source === 'file');
  const uiScopes = (p ? p.scopes : []).filter((s) => s.source === 'ui');
  const unit = (n) => (props[n] && props[n].unit && props[n].type !== 'boolean' ? ` ${props[n].unit}` : '');
  const box = slot('rule-params-error');
  const inputs = {};

  const paramRows = names.map((n) => {
    const source = p.sources[n];
    const fixed = source === 'file';
    const c = control(n, props[n], p.values[n], fixed);
    inputs[n] = c;
    const reset = h('button', { class: 'btn small', type: 'button', 'data-testid': 'param-reset', hidden: source !== 'ui' }, t('settings.paramReset'));
    reset.addEventListener('click', () =>
      run(reset, async () => {
        const rest = { ...uiParams() };
        delete rest[n];
        await save(rest, collectScopes());
      }, box),
    );
    return h(
      'li',
      { 'data-testid': 'rule-param', 'data-name': n, 'data-source': source },
      h('code', {}, n),
      ' ',
      c.el,
      unit(n),
      ' ',
      tag(t(SOURCE[source])),
      ' ',
      h('span', { class: 'muted small' }, `(${t('settings.paramDefault', { value: p.defaults[n] })}) ${props[n].description || ''}`),
      fixed ? h('small', { class: 'muted' }, ` ${t('settings.paramFixed')}`) : null,
      ' ',
      reset,
    );
  });

  // Values of the parameters this page sets: those it set before, and those changed from the default.
  function uiParams() {
    const out = {};
    for (const n of names) {
      if (p.sources[n] === 'file') continue;
      const v = inputs[n].read();
      if (v === null) continue;
      if (p.sources[n] === 'ui' || v !== p.defaults[n]) out[n] = v;
    }
    return out;
  }

  // Scopes of the file: read only.
  const fileRows = fileScopes.map((s) => {
    const set = names.filter((n) => n in s.params).map((n) => `${n} = ${s.values[n]}${unit(n)}`);
    if (s.enabled !== null) set.push(`enabled = ${s.enabled}`);
    if (s.severity) set.push(`severity = ${s.severity}`);
    return h('li', { 'data-testid': 'rule-scope', 'data-source': 'file' }, h('strong', {}, t('settings.paramScope', { match: matchText(s.match) })), ` ${set.join(', ')} `, tag(t('settings.scopeFile')));
  });

  // Scopes of this page: editable.
  const scopeList = h('ul', { 'data-testid': 'ui-scopes' });
  const scopeEditors = [];
  let optionsLoaded = null;
  const loadOptions = () => (optionsLoaded = optionsLoaded || get('/rules/scope-options'));

  async function addScope(s) {
    const options = await loadOptions();
    const picks = {};
    const matchBox = h('span', {});
    for (const [k, label] of SELECTORS) {
      const list = options[k] || [];
      const current = s && s.match[k] !== undefined ? s.match[k] : '';
      const known = list.some((o) => o.value === current);
      const opts = [['', t('settings.scopeAny')], ...(current && !known ? [[current, current]] : []), ...list.map((o) => [o.value, o.label])];
      const el = select(opts, current, { 'data-testid': 'scope-select', 'data-kind': k, 'aria-label': t(label) });
      picks[k] = el;
      append(matchBox, [h('label', { class: 'small' }, `${t(label)} `, el), ' ']);
    }
    const enabled = select(
      [['', t('settings.scopeKeep')], ['true', t('settings.scopeOn')], ['false', t('settings.scopeOff')]],
      s && s.enabled !== null && s.enabled !== undefined ? String(s.enabled) : '',
      { 'data-testid': 'scope-enabled', 'aria-label': t('settings.scopeEnabled') },
    );
    const sparams = {};
    const rows = names.map((n) => {
      const on = Boolean(s && n in s.params);
      const c = control(n, props[n], on ? s.params[n] : p.values[n], !on);
      c.el.setAttribute('data-testid', 'scope-param-input');
      const tick = h('input', { type: 'checkbox', checked: on, 'data-testid': 'scope-param-set', 'data-name': n, 'aria-label': t('settings.scopeSet', { name: n }) });
      tick.addEventListener('change', () => {
        c.el.disabled = !tick.checked;
      });
      sparams[n] = { tick, c };
      return h('span', { class: 'small' }, tick, ' ', h('code', {}, n), ' ', c.el, unit(n), ' ');
    });
    const remove = h('button', { class: 'btn small', type: 'button', 'data-testid': 'scope-remove' }, t('settings.scopeRemove'));
    const li = h('li', { 'data-testid': 'ui-scope' }, h('div', {}, matchBox), h('div', {}, h('label', { class: 'small' }, `${t('settings.scopeEnabled')} `, enabled)), h('div', {}, rows), remove);
    const editor = {
      li,
      read() {
        const match = {};
        for (const [k] of SELECTORS) if (picks[k].value) match[k] = picks[k].value;
        const params = {};
        for (const n of names) if (sparams[n].tick.checked) params[n] = sparams[n].c.read();
        const out = { match, params };
        if (enabled.value) out.enabled = enabled.value === 'true';
        return out;
      },
    };
    remove.addEventListener('click', () => {
      li.remove();
      scopeEditors.splice(scopeEditors.indexOf(editor), 1);
    });
    scopeEditors.push(editor);
    scopeList.append(li);
  }
  function collectScopes() {
    return scopeEditors.map((e) => e.read());
  }
  for (const s of uiScopes) addScope(s);

  async function save(params, scopes) {
    await put(`/rules/${enc(r.id)}/settings`, { params, scopes });
    toast(t('settings.paramsSaved'));
    await reload();
  }

  const add = h('button', { class: 'btn small', type: 'button', 'data-testid': 'scope-add' }, t('settings.scopeAdd'));
  add.addEventListener('click', () => run(add, () => addScope(null), box));
  const saveBtn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'params-save' }, t('settings.paramsSave'));
  saveBtn.addEventListener('click', () => run(saveBtn, () => save(uiParams(), collectScopes()), box));
  const resetAll = h('button', { class: 'btn small', type: 'button', 'data-testid': 'params-reset-all', hidden: !(Object.values(p.sources || {}).includes('ui') || uiScopes.length) }, t('settings.resetAll'));
  resetAll.addEventListener('click', () =>
    run(resetAll, async () => {
      await del(`/rules/${enc(r.id)}/settings`);
      toast(t('settings.paramsSaved'));
      await reload();
    }, box),
  );

  return h(
    'div',
    { class: 'rule-params', 'data-testid': 'rule-params' },
    h('h4', {}, t('settings.params')),
    names.length ? h('ul', {}, paramRows) : null,
    h('h4', {}, t('settings.scopes')),
    h('ul', {}, fileRows),
    scopeList,
    add,
    ' ',
    saveBtn,
    ' ',
    resetAll,
    box,
    h('p', { class: 'muted small' }, t('settings.paramsFile')),
  );
}
