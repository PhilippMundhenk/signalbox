// Devices: list, add and edit (settings form generated from the adapter's schema).
import { enc, get, post, put } from '../api.js';
import { compare, t } from '../i18n.js';
import { schemaForm } from '../schemaform.js';
import { clear, fmtAgo, fmtTime, h, place } from '../util.js';
import { checkField, empty, field, manageLink, pageHead, run, select, statusBadge, table, toast } from '../ui.js';
import { linked, testResult, trustPanel } from './devicetest.js';
import { discoveryPanel, findButton, takePrefill } from './discovery.js';
import { autoSetup } from './devicesetup.js';

// What to prepare on the device before adding it (steps, commands to paste, setup guide).
function setupGuide(a, open) {
  if (!a.setup_steps.length && !a.setup_commands) return null;
  const parts = [h('summary', {}, t('devices.setup.summary', { name: a.name }))];
  if (a.setup_steps.length) parts.push(h('ol', { 'data-testid': 'setup-steps' }, a.setup_steps.map((s) => h('li', {}, ...linked(s)))));
  if (a.setup_commands) {
    const code = h('pre', { class: 'commands', 'data-testid': 'setup-commands', tabindex: '0' }, a.setup_commands);
    const copy = h('button', { class: 'btn small', type: 'button', 'data-testid': 'copy-commands' }, t('devices.setup.copy'));
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(a.setup_commands);
        toast(t('devices.setup.copied'));
      } catch {
        window.getSelection().selectAllChildren(code); // no clipboard (plain http): select them
        toast(t('devices.setup.selected'), 'warn');
      }
    });
    parts.push(h('div', { class: 'row' }, copy), code);
  }
  if (a.setup_url) parts.push(h('p', { class: 'muted small' }, h('a', { href: a.setup_url, target: '_blank', rel: 'noopener noreferrer', 'data-testid': 'setup-guide' }, t('devices.setup.guide'))));
  return h('details', { class: 'setup-guide notice', open, 'data-testid': 'setup' }, ...parts);
}

// Role names, looked up when rendered (getters: ROLE_TEXT[role] stays usable, and follows the language).
export const ROLE_TEXT = {
  get gateway() { return t('devices.role.gateway'); },
  get switch() { return t('devices.role.switch'); },
  get ap() { return t('devices.role.ap'); },
  get other() { return t('devices.role.other'); },
};
// the order roles are offered in; a router with Wi-Fi is a router, so that comes first
const ROLE_ORDER = ['gateway', 'ap', 'switch', 'other'];
// Devices whose connection is tested as soon as their page opens (right after adding).
export const testOnOpen = new Set();

export async function renderDevices(main, ctx) {
  const id = ctx.renderId;
  const [devices, sites, adapters, found] = await Promise.all([get('/devices'), get('/sites'), get('/adapters'), get('/discovery')]);
  if (!ctx.alive(id)) return;
  // Find devices (#203): the panel stays hidden until asked for, or shows the last search
  const panel = discoveryPanel(ctx, found, false);
  const find = () => (found.enabled ? findButton(panel) : null);
  const siteName = (sid) => (sites.find((x) => x.id === sid) || {}).name || sid;
  const adapterName = (aid) => (adapters.find((x) => x.id === aid) || {}).name || aid;
  place(main, pageHead(t('devices.title'), find(), h('a', { class: 'btn primary', href: '#/devices/new', 'data-testid': 'add-device' }, t('devices.add'))));
  place(main, panel);
  if (!devices.length) {
    place(main, 
      empty(
        'empty',
        t('devices.empty.title'),
        h('p', { class: 'muted' }, t('devices.empty.text')),
        h('p', { class: 'row' }, h('a', { class: 'btn primary', href: '#/devices/new' }, t('devices.empty.first')), find()),
      ),
    );
    return;
  }
  devices.sort((a, b) => compare(a.name, b.name));
  place(main, 
    table(
      [
        [t('devices.col.name'), (d) => [h('a', { href: `#/device/${enc(d.id)}`, 'data-testid': 'device-link' }, d.name), ' ', manageLink(d, '↗', 'device-manage-link', 'manage-link')]],
        [t('devices.col.status'), (d) => [statusBadge(d.status), d.enabled ? null : h('span', { class: 'tag' }, t('devices.disabled'))]],
        [t('devices.col.adapter'), (d) => adapterName(d.adapter)],
        [t('devices.col.role'), (d) => ROLE_TEXT[d.role] || d.role],
        [t('devices.col.site'), (d) => siteName(d.site_id)],
        [t('devices.col.firstSeen'), (d) => ago(d.first_seen, 'device-first-seen')],
        [t('devices.col.lastRead'), (d) => ago(d.last_ok, 'device-last-ok')],
      ],
      devices,
      { testid: 'devices', rowTestid: 'device-row', rowAttrs: (d) => ({ 'data-id': d.id }) },
    ),
  );
  const net = await get('/network');
  if (!ctx.alive(id)) return;
  const managed = net.devices.filter((d) => d.managed_by);
  if (managed.length) {
    const controller = (cid) => (devices.find((x) => x.id === cid) || {}).name || cid;
    place(main,
      h('section', { class: 'card' },
        h('h2', {}, t('devices.managed.title')),
        h('p', { class: 'muted' }, t('devices.managed.text')),
        table(
          [
            [t('devices.col.name'), (d) => d.name],
            [t('devices.col.status'), (d) => statusBadge(net.statuses[d.id])],
            [t('devices.col.role'), (d) => ROLE_TEXT[d.role] || d.role],
            [t('devices.col.model'), (d) => d.model || ''],
            [t('devices.col.controller'), (d) => h('a', { href: `#/device/${enc(d.managed_by)}` }, controller(d.managed_by))],
          ],
          managed,
          { testid: 'managed-devices', rowTestid: 'managed-row' },
        ),
      ),
    );
  }
}

// A time as "3 h ago" with the exact time on hover; nothing for an unknown time.
function ago(iso, testid) {
  return iso ? h('span', { title: fmtTime(iso), 'data-testid': testid }, fmtAgo(iso)) : null;
}

// The first site, created inline: a device needs one and a fresh install has none.
function firstSite(onCreated) {
  const name = h('input', { type: 'text', value: t('devices.firstSite.defaultName'), 'data-testid': 'first-site-name', maxlength: '100' });
  const btn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'first-site-create' }, t('devices.firstSite.create'));
  btn.addEventListener('click', () =>
    run(btn, async () => {
      const site = await post('/sites', { name: name.value.trim() || t('devices.firstSite.defaultName') });
      toast(t('devices.firstSite.created', { name: site.name }));
      onCreated(site);
    }),
  );
  return h(
    'div',
    { class: 'notice', 'data-testid': 'first-site' },
    h('p', {}, h('strong', {}, t('devices.firstSite.heading')), t('devices.firstSite.text')),
    field(t('devices.firstSite.name'), name),
    btn,
  );
}

// device: null to add, else the stored device record (edit).
export async function renderDeviceForm(main, ctx, device) {
  const id = ctx.renderId;
  let [sites, adapters] = await Promise.all([get('/sites'), get('/adapters')]);
  if (!ctx.alive(id)) return;
  const editing = Boolean(device);
  // a device found by Find devices: adapter, role, address and name are suggestions
  const found = editing ? null : takePrefill();
  const prefill = found && adapters.some((a) => a.id === found.adapter) ? found : null;
  if (!editing) place(main, h('p', { class: 'back' }, h('a', { href: '#/devices' }, t('devices.back'))), pageHead(t('devices.add')));
  if (!adapters.length) {
    place(main, empty('no-adapters', t('devices.noAdapters.title'), h('p', { class: 'muted' }, t('devices.noAdapters.text'))));
    return;
  }
  const form = h('form', { class: 'card device-form', 'data-testid': 'device-form', novalidate: true });
  const name = h('input', { type: 'text', maxlength: '100', required: true, 'data-testid': 'device-name', value: device ? device.name : prefill ? prefill.name : '' });
  const adapter = select(adapters.map((a) => [a.id, `${a.name} (${a.vendor})`]), device ? device.adapter : prefill ? prefill.adapter : adapters[0].id, { 'data-testid': 'device-adapter' });
  const adapterHelp = h('p', { class: 'muted small', 'data-testid': 'adapter-description' });
  const setupBox = h('div', {});
  const autoBox = h('div', {}); // the automatic setup comes after the connection fields it needs
  const role = h('select', { 'data-testid': 'device-role' });
  const siteBox = h('div', {});
  const site = h('select', { 'data-testid': 'device-site' });
  const enabled = h('input', { type: 'checkbox', checked: device ? device.enabled : true, 'data-testid': 'device-enabled' });
  const allowWrites = h('input', { type: 'checkbox', checked: device ? device.allow_writes : false, 'data-testid': 'device-allow-writes' });
  const configBox = h('div', {});
  const errors = h('div', { class: 'error', role: 'alert', 'data-testid': 'form-errors' });
  const testBox = h('div', { 'data-testid': 'form-test', 'aria-live': 'polite' });
  let cfg = null;
  // a certificate trusted while testing: pinned when the device is saved
  let trusted = null;

  const fillSites = () => {
    clear(site);
    for (const x of sites) place(site, h('option', { value: x.id, selected: device && device.site_id === x.id }, x.name));
    clear(siteBox);
    if (!sites.length) {
      place(siteBox, 
        firstSite((created) => {
          sites = [created];
          fillSites();
        }),
      );
    } else {
      place(siteBox, field(t('devices.field.site'), site, sites.length > 1 ? null : t('devices.field.siteHelp')));
    }
    save.disabled = !sites.length;
  };

  const fillAdapter = () => {
    const a = adapters.find((x) => x.id === adapter.value);
    adapterHelp.textContent = a.description || '';
    clear(setupBox);
    clear(autoBox);
    place(setupBox, setupGuide(a, !editing && !a.admin_login));
    if (a.admin_login) {
      const userInput = () => configBox.querySelector('[data-testid="cfg-username"]');
      const own = { get: () => (userInput() ? userInput().value.trim() : ''), set: (v) => { if (userInput()) userInput().value = v; } };
      place(
        autoBox,
        autoSetup(a, () => collect(true, true), (saved) => {
          testOnOpen.add(saved.id);
          ctx.navigate(`#/device/${enc(saved.id)}`);
        }, own),
      );
    }
    const wanted = role.value || (device && device.role) || (prefill && prefill.role);
    clear(role);
    const roles = [...a.roles].sort((x, y) => ROLE_ORDER.indexOf(x) - ROLE_ORDER.indexOf(y));
    for (const r of roles) place(role, h('option', { value: r, selected: r === wanted }, ROLE_TEXT[r] || r));
    clear(configBox);
    const same = device && device.adapter === a.id;
    const suggested = prefill && prefill.adapter === a.id ? prefill.config : {};
    cfg = schemaForm(a.config_schema, {
      secrets: a.secret_fields,
      values: same ? device.config : suggested,
      secretsSet: same ? device.secrets_set : null,
    });
    place(configBox, h('h3', {}, t('devices.connection', { name: a.name })), cfg.element);
    clear(testBox);
    trusted = null;
  };

  // The form's values, or null after showing what is missing.
  // forSetup: the automatic setup fills in the secret settings itself
  const collect = (forTest, forSetup = false) => {
    clear(errors);
    const problems = [];
    if (!name.value.trim() && !forTest) problems.push(t('devices.error.name'));
    if (!site.value) problems.push(t('devices.error.site'));
    const { config, errors: cfgErrors, clear: cleared } = cfg.collect({ noSecrets: forSetup });
    problems.push(...cfgErrors);
    if (problems.length) {
      place(errors, h('ul', {}, problems.map((p) => h('li', {}, p))));
      return null;
    }
    const body = { name: name.value.trim() || t('devices.defaultName'), site_id: site.value, role: role.value, adapter: adapter.value, enabled: enabled.checked, allow_writes: allowWrites.checked, config };
    if (cleared.length) body.clear_secrets = cleared;
    if (trusted) body.trust_fingerprint = trusted;
    if (forSetup && editing) body.device_id = device.id;
    return body;
  };

  const testBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'form-test-button' }, t('devices.test'));
  async function test() {
    const body = collect(true);
    if (!body) return;
    if (editing) body.device_id = device.id;
    place(clear(testBox), h('p', { class: 'muted', 'data-testid': 'testing' }, t('devices.testing')));
    try {
      const res = await post('/devices/test', body);
      if (!ctx.alive(id)) return;
      place(clear(testBox), testResult(res));
      if (res.pending_fingerprint && res.status === 'untrusted-certificate') {
        place(
          testBox,
          trustPanel(
            res.pending_fingerprint,
            async (fp) => {
              trusted = fp;
              await test();
            },
            editing ? t('devices.trustOnSave') : t('devices.trustOnAdd'),
          ),
        );
      }
    } catch (err) {
      clear(testBox);
      errors.textContent = err.message;
    }
  }
  testBtn.addEventListener('click', () => run(testBtn, test));

  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'device-save' }, editing ? t('devices.saveChanges') : t('devices.add'));
  adapter.addEventListener('change', fillAdapter);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const body = collect(false);
    if (!body) return;
    run(save, async () => {
      try {
        const saved = editing ? await put(`/devices/${enc(device.id)}`, body) : await post('/devices', body);
        toast(editing ? t('devices.saved') : t('devices.added', { name: saved.name }));
        if (!editing) testOnOpen.add(saved.id);
        ctx.navigate(`#/device/${enc(saved.id)}`);
      } catch (err) {
        errors.textContent = err.message;
      }
    });
  });

  place(form, 
    prefill
      ? h(
          'div',
          { class: 'notice', 'data-testid': 'prefill-notice' },
          h('p', {}, h('strong', {}, t('devices.prefill.heading')), t('devices.prefill.text')),
          prefill.note ? h('p', { 'data-testid': 'prefill-note' }, prefill.note) : null,
        )
      : null,
    field(t('devices.field.name'), name, t('devices.field.nameHelp')),
    field(t('devices.field.adapter'), adapter),
    adapterHelp,
    setupBox,
    field(t('devices.field.role'), role, t('devices.field.roleHelp')),
    siteBox,
    editing ? checkField(t('devices.field.read'), enabled, t('devices.field.readHelp')) : null,
    checkField(t('devices.field.allowChanges'), allowWrites, t('devices.field.allowChangesHelp')),
    configBox,
    autoBox,
    h('p', { class: 'muted small' }, t('devices.testHelp')),
    testBox,
    errors,
    h('div', { class: 'row' }, save, testBtn, h('a', { class: 'btn', href: editing ? `#/device/${enc(device.id)}` : '#/devices' }, t('common.cancel'))),
  );
  place(main, form);
  fillAdapter();
  fillSites();
  if (!editing) name.focus();
}
