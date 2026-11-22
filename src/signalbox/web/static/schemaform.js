// A form generated from an adapter's settings (JSON Schema from pydantic).
// Supports string, integer, number, boolean, enum, defaults, descriptions and secrets.
import { h } from './util.js';
import { checkField, field } from './ui.js';

function resolve(schema, root) {
  let s = schema || {};
  for (let i = 0; i < 5 && s.$ref; i += 1) {
    const name = s.$ref.split('/').pop();
    const target = (root.$defs || root.definitions || {})[name] || {};
    const { $ref, ...rest } = s;
    s = { ...target, ...rest };
  }
  if (Array.isArray(s.allOf) && s.allOf.length === 1) {
    const { allOf, ...rest } = s;
    s = { ...resolve(allOf[0], root), ...rest };
  }
  let nullable = false;
  if (Array.isArray(s.anyOf)) {
    const options = s.anyOf.map((x) => resolve(x, root));
    nullable = options.some((x) => x.type === 'null');
    const main = options.find((x) => x.type !== 'null') || {};
    const { anyOf, ...rest } = s;
    s = { ...main, ...rest };
  }
  if (Array.isArray(s.type)) {
    nullable = nullable || s.type.includes('null');
    s = { ...s, type: s.type.find((t) => t !== 'null') };
  }
  if (s.enum && !s.type) s = { ...s, type: typeof s.enum[0] === 'number' ? 'number' : 'string' };
  return { ...s, nullable };
}

function titleOf(name, s) {
  if (s.title) return s.title;
  return name.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
}

/**
 * schema: config_schema; secrets: names of secret fields; values: stored non-secret config;
 * secretsSet: names of secrets that are stored (edit). Returns {element, collect()}.
 */
export function schemaForm(schema, { secrets = [], values = {}, secretsSet = null, idPrefix = 'cfg' } = {}) {
  const required = new Set(schema.required || []);
  const fields = [];
  const element = h('div', { class: 'schema-form', 'data-testid': 'config-form' });
  // settings marked "advanced" (simulators, tests) go into a closed section
  const advanced = h('details', { class: 'advanced', 'data-testid': 'advanced-settings' }, h('summary', {}, 'Advanced'));
  for (const [name, raw] of Object.entries(schema.properties || {})) {
    const s = resolve(raw, schema);
    const box = s.advanced ? advanced : element;
    const isSecret = secrets.includes(name) || s.format === 'password' || s.writeOnly;
    const label = titleOf(name, s) + (required.has(name) && !s.nullable ? '' : ' (optional)');
    const current = name in values ? values[name] : s.default;
    const id = `${idPrefix}-${name}`;
    const testid = `cfg-${name}`;
    let control;
    let read;
    if (isSecret) {
      const stored = secretsSet && secretsSet.includes(name);
      control = h('input', { type: 'password', id, autocomplete: 'new-password', 'data-testid': testid, placeholder: stored ? 'stored — leave empty to keep' : '' });
      read = () => (control.value === '' ? undefined : control.value);
      const hint = [s.description, stored ? 'A value is stored. Leave the field empty to keep it.' : null].filter(Boolean).join(' ');
      box.append(field(label, control, hint || null));
      let remove = null;
      if (stored && s.nullable) {
        // an optional secret can be removed again (e.g. a switch read without password)
        remove = h('input', { type: 'checkbox', 'data-testid': `${testid}-clear` });
        remove.addEventListener('change', () => {
          control.disabled = remove.checked;
          if (remove.checked) control.value = '';
        });
        box.append(checkField(`Remove the stored ${label.replace(' (optional)', '').toLowerCase()}`, remove, null));
      }
      fields.push({ name, s, read, control, secret: true, stored, remove, required: required.has(name) && !s.nullable });
      continue;
    }
    if (s.type === 'boolean') {
      control = h('input', { type: 'checkbox', id, checked: Boolean(current), 'data-testid': testid });
      read = () => control.checked;
      box.append(checkField(label.replace(' (optional)', ''), control, s.description));
    } else if (s.enum) {
      control = h('select', { id, 'data-testid': testid });
      if (s.nullable || (!required.has(name) && s.default === undefined)) control.append(h('option', { value: '' }, '–'));
      for (const opt of s.enum) control.append(h('option', { value: String(opt), selected: String(opt) === String(current) }, String(opt)));
      read = () => {
        if (control.value === '') return s.nullable ? null : undefined;
        const opt = s.enum.find((x) => String(x) === control.value);
        return opt;
      };
      box.append(field(label, control, s.description));
    } else if (s.type === 'integer' || s.type === 'number') {
      control = h('input', { type: 'number', id, inputmode: s.type === 'integer' ? 'numeric' : 'decimal', step: s.type === 'integer' ? '1' : 'any', 'data-testid': testid, value: current === undefined || current === null ? '' : String(current) });
      if (s.minimum !== undefined) control.min = String(s.minimum);
      if (s.maximum !== undefined) control.max = String(s.maximum);
      read = () => {
        if (control.value.trim() === '') return s.nullable ? null : undefined;
        const n = Number(control.value);
        return s.type === 'integer' ? Math.trunc(n) : n;
      };
      box.append(field(label, control, s.description));
    } else {
      control = h('input', { type: 'text', id, autocomplete: 'off', spellcheck: 'false', 'data-testid': testid, placeholder: s.examples ? String(s.examples[0]) : '', value: current === undefined || current === null ? '' : String(current) });
      if (s.maxLength) control.maxLength = s.maxLength;
      read = () => {
        if (control.value === '') {
          if (s.nullable) return null;
          // cleared on purpose: keep it empty instead of falling back to the default
          return typeof s.default === 'string' && s.default !== '' ? '' : undefined;
        }
        return control.value;
      };
      box.append(field(label, control, s.description));
    }
    fields.push({ name, s, read, control, required: required.has(name) && !s.nullable });
  }

  if (advanced.children.length > 1) element.append(advanced);

  function collect() {
    const config = {};
    const errors = [];
    const clear = [];
    for (const f of fields) {
      f.control.removeAttribute('aria-invalid');
      if (f.remove && f.remove.checked) {
        clear.push(f.name);
        continue;
      }
      const value = f.read();
      const label = titleOf(f.name, f.s);
      if (value === undefined) {
        if (f.required && !(f.secret && f.stored) && f.s.default === undefined) {
          errors.push(`${label} is required.`);
          f.control.setAttribute('aria-invalid', 'true');
        }
        continue;
      }
      if (typeof value === 'number') {
        if (Number.isNaN(value) || (f.s.minimum !== undefined && value < f.s.minimum) || (f.s.maximum !== undefined && value > f.s.maximum)) {
          errors.push(`${label} must be a number${f.s.minimum !== undefined ? ` from ${f.s.minimum}` : ''}${f.s.maximum !== undefined ? ` to ${f.s.maximum}` : ''}.`);
          f.control.setAttribute('aria-invalid', 'true');
          continue;
        }
      }
      config[f.name] = value;
    }
    return { config, errors, clear };
  }

  return { element, collect };
}
