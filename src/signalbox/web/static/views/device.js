// One device: overview with connection test and certificate trust, settings, advanced (raw data).
import { del, enc, get, post } from '../api.js';
import { loadNetwork } from '../net.js';
import { clear, fmtAgo, fmtTime, groupHex, h, place, yesNo } from '../util.js';
import { card, confirmDialog, empty, kv, pageHead, run, statusBadge, table, tabs, toast } from '../ui.js';
import { ROLE_TEXT, renderDeviceForm, testOnOpen } from './devices.js';

const COUNT_TEXT = { ports: 'ports', segments: 'segments', subnets: 'subnets', wlans: 'SSIDs', clients: 'clients' };

function trustPanel(device, fingerprint, onTrusted) {
  const btn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'trust' }, 'Trust this certificate');
  btn.addEventListener('click', () =>
    run(btn, async () => {
      await post(`/devices/${enc(device.id)}/trust`, { fingerprint });
      toast('Certificate trusted.');
      await onTrusted();
    }),
  );
  return h(
    'div',
    { class: 'notice', 'data-testid': 'untrusted' },
    h('h3', {}, 'The device presented a certificate Signalbox does not trust yet'),
    h('p', {}, 'Before you trust it, compare this SHA-256 fingerprint with the one the device shows in its own web interface or console. If they differ, someone may be in between: do not trust it.'),
    h('p', { class: 'fingerprint mono', 'data-testid': 'fingerprint' }, groupHex(fingerprint)),
    btn,
  );
}

function testResult(res) {
  return h(
    'div',
    { class: `test-result status-${res.status}`, 'data-testid': 'test-result' },
    h('p', {}, 'Result: ', statusBadge(res.status)),
    res.errors.length ? h('ul', { class: 'error', 'data-testid': 'test-errors' }, res.errors.map((e) => h('li', {}, `${e.capability}: ${e.message}`))) : null,
    res.status === 'ok' || res.status === 'partial'
      ? h('p', { 'data-testid': 'test-counts' }, 'Found ', Object.entries(res.counts).map(([k, v], i) => `${i ? ', ' : ''}${v} ${COUNT_TEXT[k] || k}`), '.')
      : null,
  );
}

async function overview(main, ctx, device, adapters, sites) {
  const id = ctx.renderId;
  const ix = await loadNetwork();
  if (!ctx.alive(id)) return;
  const observed = ix.net.devices.find((d) => d.id === device.id);
  const adapter = adapters.find((a) => a.id === device.adapter);
  const errors = ix.net.errors.filter((e) => e.device_id === device.id);
  const result = h('div', {});
  const trustBox = h('div', {});
  const statusBox = h('span', {}, statusBadge(device.status));

  const showTrust = (fingerprint, status) => {
    clear(trustBox);
    if (fingerprint && status === 'untrusted-certificate') place(trustBox, trustPanel(device, fingerprint, test));
  };

  const testBtn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'test' }, 'Test connection');
  async function test() {
    place(clear(result), h('p', { class: 'muted', 'data-testid': 'testing' }, 'Reading the device…'));
    const res = await post(`/devices/${enc(device.id)}/test`);
    if (!ctx.alive(id)) return;
    place(clear(result), testResult(res));
    place(clear(statusBox), statusBadge(res.status));
    showTrust(res.pending_fingerprint, res.status);
  }
  testBtn.addEventListener('click', () => run(testBtn, test));

  const remove = h('button', { class: 'btn danger', type: 'button', 'data-testid': 'delete-device' }, 'Remove device');
  remove.addEventListener('click', () =>
    run(remove, async () => {
      const ok = await confirmDialog({ title: `Remove ${device.name}?`, message: 'Signalbox forgets this device, its stored settings and its last reading. The device itself is not changed.', confirmLabel: 'Remove', danger: true });
      if (!ok) return;
      await del(`/devices/${enc(device.id)}`);
      toast(`${device.name} removed.`);
      ctx.navigate('#/devices');
    }),
  );

  const fw = observed && observed.firmware;
  place(main, 
    card(
      null,
      kv([
        ['Status', statusBox],
        ['Adapter', adapter ? `${adapter.name} (${adapter.vendor})` : `${device.adapter} (not installed)`],
        ['Role', ROLE_TEXT[device.role] || device.role],
        ['Site', (sites.find((x) => x.id === device.site_id) || {}).name || device.site_id],
        ['Vendor', observed ? observed.vendor : null],
        ['Model', observed ? observed.model : null],
        ['Firmware', fw ? [fw.current || '–', fw.available ? ` (update available: ${fw.available})` : '', fw.end_of_life ? ' – end of life' : ''].join('') : null],
        ['Management address', observed ? observed.management_address : null],
        ['Last read', observed && observed.observed_at ? h('span', { title: fmtTime(observed.observed_at) }, fmtAgo(observed.observed_at)) : 'not yet'],
        ['Enabled', yesNo(device.enabled)],
      ]),
      errors.length ? h('ul', { class: 'error', 'data-testid': 'device-errors' }, errors.map((e) => h('li', {}, `${e.capability}: ${e.message}`))) : null,
    ),
    trustBox,
    card('Connection', h('p', { class: 'muted' }, 'Reads the device now with the stored settings and shows what was found. Nothing is changed on the device.'), h('div', { class: 'row' }, testBtn), result),
    h('div', { class: 'row end' }, remove),
  );
  showTrust(device.pending_fingerprint, device.status);
  if (testOnOpen.delete(device.id)) run(testBtn, test);
}

function rawObjects(net, deviceId) {
  const mine = (o) => o.device_id === deviceId || (o.source && o.source.device_id === deviceId);
  return {
    ports: net.ports.filter(mine),
    segments: net.segments.filter((x) => x.source && x.source.device_id === deviceId),
    subnets: net.subnets.filter(mine),
    dhcp_servers: net.dhcp_servers.filter(mine),
    dns_services: net.dns_services.filter(mine),
    radios: net.radios.filter(mine),
    wlans: net.wlans.filter(mine),
    clients: net.clients.filter(mine),
    neighbours: net.neighbours.filter((n) => (n.source && n.source.device_id === deviceId) || n.local_port_id.startsWith(`${deviceId}/`)),
  };
}

async function advanced(main, ctx, device) {
  const id = ctx.renderId;
  const net = await get('/network');
  if (!ctx.alive(id)) return;
  const raw = rawObjects(net, device.id);
  const total = Object.values(raw).reduce((n, list) => n + list.length, 0);
  place(main, h('p', { class: 'muted' }, 'Everything this device reported, as Signalbox stores it. Vendor fields that the common model does not cover are listed under “vendor_extra”; they are shown here only and never used by the checks.'));
  if (!total) {
    place(main, empty('empty', 'Nothing read yet', h('p', { class: 'muted' }, 'Test the connection on the overview tab or wait for the next reading.')));
    return;
  }
  if (raw.ports.length) {
    place(main, 
      card(
        `Ports (${raw.ports.length})`,
        table(
          [
            ['Port', (p) => p.name],
            ['Kind', (p) => p.kind],
            ['Up', (p) => yesNo(p.up)],
            ['Speed', (p) => (p.speed_mbps ? `${p.speed_mbps} Mbit/s` : null)],
            ['MAC', (p) => (p.mac ? h('span', { class: 'mono' }, p.mac) : null)],
            ['Vendor fields', (p) => (Object.keys(p.vendor_extra || {}).length ? h('code', { class: 'extra' }, JSON.stringify(p.vendor_extra)) : null)],
          ],
          raw.ports,
          { testid: 'raw-port-table', rowTestid: 'raw-port' },
        ),
      ),
    );
  }
  for (const [kind, list] of Object.entries(raw)) {
    if (!list.length) continue;
    place(main, 
      h(
        'details',
        { class: 'card raw', 'data-testid': `raw-${kind}` },
        h('summary', {}, `${kind.replace('_', ' ')} (${list.length}) – raw`),
        h('pre', { class: 'json' }, JSON.stringify(list, null, 2)),
      ),
    );
  }
}

export async function renderDevice(main, ctx, route) {
  const id = ctx.renderId;
  const [device, adapters, sites] = await Promise.all([get(`/devices/${enc(route.id)}`).catch(() => null), get('/adapters'), get('/sites')]);
  if (!ctx.alive(id)) return;
  place(main, h('p', { class: 'back' }, h('a', { href: '#/devices' }, '← Devices')));
  if (!device) {
    place(main, empty('not-found', 'No such device', h('p', {}, h('a', { href: '#/devices' }, 'Back to the devices'))));
    return;
  }
  const base = `#/device/${enc(device.id)}`;
  place(main, 
    pageHead(device.name),
    tabs(
      [
        ['overview', 'Overview', base],
        ['settings', 'Settings', `${base}/settings`],
        ['advanced', 'Advanced', `${base}/advanced`],
      ],
      route.tab,
    ),
  );
  main.querySelector('h1').setAttribute('data-testid', 'device-title');
  if (route.tab === 'settings') await renderDeviceForm(main, ctx, device);
  else if (route.tab === 'advanced') await advanced(main, ctx, device);
  else await overview(main, ctx, device, adapters, sites);
}
