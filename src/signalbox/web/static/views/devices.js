// Devices: list, add and edit (settings form generated from the adapter's schema).
import { enc, get, post, put } from '../api.js';
import { schemaForm } from '../schemaform.js';
import { clear, fmtAgo, fmtTime, h, place } from '../util.js';
import { checkField, empty, field, pageHead, run, select, statusBadge, table, toast } from '../ui.js';
import { linked, testResult, trustPanel } from './devicetest.js';

// What to prepare on the device before adding it (steps, commands to paste, setup guide).
function setupGuide(a, open) {
  if (!a.setup_steps.length && !a.setup_commands) return null;
  const parts = [h('summary', {}, `Before you add it: prepare the ${a.name}`)];
  if (a.setup_steps.length) parts.push(h('ol', { 'data-testid': 'setup-steps' }, a.setup_steps.map((s) => h('li', {}, ...linked(s)))));
  if (a.setup_commands) {
    const code = h('pre', { class: 'commands', 'data-testid': 'setup-commands', tabindex: '0' }, a.setup_commands);
    const copy = h('button', { class: 'btn small', type: 'button', 'data-testid': 'copy-commands' }, 'Copy commands');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(a.setup_commands);
        toast('Commands copied.');
      } catch {
        window.getSelection().selectAllChildren(code); // no clipboard (plain http): select them
        toast('Commands selected: copy them with Ctrl+C.', 'warn');
      }
    });
    parts.push(h('div', { class: 'row' }, copy), code);
  }
  if (a.setup_url) parts.push(h('p', { class: 'muted small' }, h('a', { href: a.setup_url, target: '_blank', rel: 'noopener noreferrer', 'data-testid': 'setup-guide' }, 'Full setup guide')));
  return h('details', { class: 'setup-guide notice', open, 'data-testid': 'setup' }, ...parts);
}

export const ROLE_TEXT = { gateway: 'Router / gateway (with or without Wi-Fi)', switch: 'Switch', ap: 'Access point (Wi-Fi only, no routing)', other: 'Other (controller, …)' };
// the order roles are offered in; a router with Wi-Fi is a router, so that comes first
const ROLE_ORDER = ['gateway', 'ap', 'switch', 'other'];
// Devices whose connection is tested as soon as their page opens (right after adding).
export const testOnOpen = new Set();

export async function renderDevices(main, ctx) {
  const id = ctx.renderId;
  const [devices, sites, adapters] = await Promise.all([get('/devices'), get('/sites'), get('/adapters')]);
  if (!ctx.alive(id)) return;
  const siteName = (sid) => (sites.find((x) => x.id === sid) || {}).name || sid;
  const adapterName = (aid) => (adapters.find((x) => x.id === aid) || {}).name || aid;
  place(main, pageHead('Devices', h('a', { class: 'btn primary', href: '#/devices/new', 'data-testid': 'add-device' }, 'Add device')));
  if (!devices.length) {
    place(main, 
      empty(
        'empty',
        'No devices yet',
        h('p', { class: 'muted' }, 'Add your router, switches and access points. Signalbox reads them with an adapter and only reads: it changes nothing on the device.'),
        h('p', {}, h('a', { class: 'btn primary', href: '#/devices/new' }, 'Add your first device')),
      ),
    );
    return;
  }
  devices.sort((a, b) => a.name.localeCompare(b.name));
  place(main, 
    table(
      [
        ['Name', (d) => h('a', { href: `#/device/${enc(d.id)}`, 'data-testid': 'device-link' }, d.name)],
        ['Status', (d) => [statusBadge(d.status), d.enabled ? null : h('span', { class: 'tag' }, 'disabled')]],
        ['Adapter', (d) => adapterName(d.adapter)],
        ['Role', (d) => ROLE_TEXT[d.role] || d.role],
        ['Site', (d) => siteName(d.site_id)],
        ['First seen', (d) => ago(d.first_seen, 'device-first-seen')],
        ['Last read', (d) => ago(d.last_ok, 'device-last-ok')],
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
        h('h2', {}, 'Managed through a controller'),
        h('p', { class: 'muted' }, 'Reported by a controller you added (for example an Omada controller). They need no settings of their own.'),
        table(
          [
            ['Name', (d) => d.name],
            ['Status', (d) => statusBadge(net.statuses[d.id])],
            ['Role', (d) => ROLE_TEXT[d.role] || d.role],
            ['Model', (d) => d.model || ''],
            ['Controller', (d) => h('a', { href: `#/device/${enc(d.managed_by)}` }, controller(d.managed_by))],
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
  const name = h('input', { type: 'text', value: 'Home', 'data-testid': 'first-site-name', maxlength: '100' });
  const btn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'first-site-create' }, 'Create site');
  btn.addEventListener('click', () =>
    run(btn, async () => {
      const site = await post('/sites', { name: name.value.trim() || 'Home' });
      toast(`Site ${site.name} created.`);
      onCreated(site);
    }),
  );
  return h(
    'div',
    { class: 'notice', 'data-testid': 'first-site' },
    h('p', {}, h('strong', {}, 'First, create a site. '), 'A site is one place with its own network, such as your home or an office. Most people need just one.'),
    field('Site name', name),
    btn,
  );
}

// device: null to add, else the stored device record (edit).
export async function renderDeviceForm(main, ctx, device) {
  const id = ctx.renderId;
  let [sites, adapters] = await Promise.all([get('/sites'), get('/adapters')]);
  if (!ctx.alive(id)) return;
  const editing = Boolean(device);
  if (!editing) place(main, h('p', { class: 'back' }, h('a', { href: '#/devices' }, '← Devices')), pageHead('Add device'));
  if (!adapters.length) {
    place(main, empty('no-adapters', 'No adapters installed', h('p', { class: 'muted' }, 'Signalbox talks to devices through adapters. Install one (see docs/ADAPTERS.md) and restart Signalbox.')));
    return;
  }
  const form = h('form', { class: 'card device-form', 'data-testid': 'device-form', novalidate: true });
  const name = h('input', { type: 'text', maxlength: '100', required: true, 'data-testid': 'device-name', value: device ? device.name : '' });
  const adapter = select(adapters.map((a) => [a.id, `${a.name} (${a.vendor})`]), device ? device.adapter : adapters[0].id, { 'data-testid': 'device-adapter' });
  const adapterHelp = h('p', { class: 'muted small', 'data-testid': 'adapter-description' });
  const setupBox = h('div', {});
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
      place(siteBox, field('Site', site, sites.length > 1 ? null : 'Add more sites under Settings.'));
    }
    save.disabled = !sites.length;
  };

  const fillAdapter = () => {
    const a = adapters.find((x) => x.id === adapter.value);
    adapterHelp.textContent = a.description || '';
    clear(setupBox);
    place(setupBox, setupGuide(a, !editing));
    const wanted = role.value || (device && device.role);
    clear(role);
    const roles = [...a.roles].sort((x, y) => ROLE_ORDER.indexOf(x) - ROLE_ORDER.indexOf(y));
    for (const r of roles) place(role, h('option', { value: r, selected: r === wanted }, ROLE_TEXT[r] || r));
    clear(configBox);
    const same = device && device.adapter === a.id;
    cfg = schemaForm(a.config_schema, {
      secrets: a.secret_fields,
      values: same ? device.config : {},
      secretsSet: same ? device.secrets_set : null,
    });
    place(configBox, h('h3', {}, `${a.name} connection`), cfg.element);
    clear(testBox);
    trusted = null;
  };

  // The form's values, or null after showing what is missing.
  const collect = (forTest) => {
    clear(errors);
    const problems = [];
    if (!name.value.trim() && !forTest) problems.push('Give the device a name.');
    if (!site.value) problems.push('Create a site first.');
    const { config, errors: cfgErrors } = cfg.collect();
    problems.push(...cfgErrors);
    if (problems.length) {
      place(errors, h('ul', {}, problems.map((p) => h('li', {}, p))));
      return null;
    }
    const body = { name: name.value.trim() || 'new device', site_id: site.value, role: role.value, adapter: adapter.value, enabled: enabled.checked, allow_writes: allowWrites.checked, config };
    if (trusted) body.trust_fingerprint = trusted;
    return body;
  };

  const testBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'form-test-button' }, 'Test connection');
  async function test() {
    const body = collect(true);
    if (!body) return;
    if (editing) body.device_id = device.id;
    place(clear(testBox), h('p', { class: 'muted', 'data-testid': 'testing' }, 'Reading the device…'));
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
            editing ? 'Trusted when you save the changes.' : 'Trusted when you add the device.',
          ),
        );
      }
    } catch (err) {
      clear(testBox);
      errors.textContent = err.message;
    }
  }
  testBtn.addEventListener('click', () => run(testBtn, test));

  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'device-save' }, editing ? 'Save changes' : 'Add device');
  adapter.addEventListener('change', fillAdapter);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const body = collect(false);
    if (!body) return;
    run(save, async () => {
      try {
        const saved = editing ? await put(`/devices/${enc(device.id)}`, body) : await post('/devices', body);
        toast(editing ? 'Saved.' : `${saved.name} added.`);
        if (!editing) testOnOpen.add(saved.id);
        ctx.navigate(`#/device/${enc(saved.id)}`);
      } catch (err) {
        errors.textContent = err.message;
      }
    });
  });

  place(form, 
    field('Name', name, 'How Signalbox shows this device, for example “Office switch”.'),
    field('Adapter', adapter),
    adapterHelp,
    setupBox,
    field('Role', role, 'What the device mainly does. A router that also has Wi-Fi (like most Fritz!Boxes) is a router: its Wi-Fi is read either way.'),
    siteBox,
    editing ? checkField('Read this device', enabled, 'Disabled devices are kept but not read and not checked.') : null,
    checkField('Allow changes', allowWrites, 'Approved changes may be deployed to this device. Off: Signalbox only reads it. Deploying must also be enabled in the configuration.'),
    configBox,
    h('p', { class: 'muted small' }, 'Test connection reads the device with these settings without saving them. Nothing is changed on the device.'),
    testBox,
    errors,
    h('div', { class: 'row' }, save, testBtn, h('a', { class: 'btn', href: editing ? `#/device/${enc(device.id)}` : '#/devices' }, 'Cancel')),
  );
  place(main, form);
  fillAdapter();
  fillSites();
  if (!editing) name.focus();
}
