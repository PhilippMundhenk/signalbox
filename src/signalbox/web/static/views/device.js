// One device: overview with connection test and certificate trust, settings, advanced (raw data).
import { del, enc, get, post } from '../api.js';
import { loadNetwork } from '../net.js';
import { clear, fmtAgo, fmtBytes, fmtDuration, fmtTime, groupHex, h, place, portDetails, portSpeed, yesNo } from '../util.js';
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

const given = (v) => v !== null && v !== undefined;
// kv() skips undefined: a row only for what the device reports.
const opt = (v, fn = (x) => x) => (given(v) ? fn(v) : undefined);
const pct = (v) => `${Math.round(v * 10) / 10} %`;
const usage = (used, total) => (given(used) && total ? `${fmtBytes(used)} of ${fmtBytes(total)} (${Math.round((100 * used) / total)} %)` : undefined);
const okText = (ok) => (ok === true ? 'OK' : ok === false ? 'failed' : 'state unknown');

// Health as reported (#178): only the values the device has.
function healthCard(health) {
  if (!health) return null;
  const ups = (u) => [u.on_battery ? 'on battery' : u.on_battery === false ? 'on mains' : 'state unknown', opt(u.charge_pct, (v) => `charge ${pct(v)}`), opt(u.runtime_seconds, (v) => `runtime ${fmtDuration(v)}`)].filter(Boolean).join(', ');
  const rows = [
    ['Uptime', opt(health.uptime_seconds, fmtDuration)],
    ['Started', opt(health.boot_time, fmtTime)],
    ['Last restart', opt(health.last_reboot_reason)],
    ['CPU load', opt(health.cpu_load_pct, (v) => `${pct(v)}${health.cpu_count ? ` (${health.cpu_count} cores)` : ''}`)],
    ['Load average', opt(health.load_average, (l) => l.map((x) => x.toFixed(2)).join(' / '))],
    ['Memory used', usage(health.memory_used_bytes, health.memory_total_bytes)],
    ...health.storage.map((st) => [`Storage ${st.name}`, `${usage(st.used_bytes, st.total_bytes) || '–'}${given(st.wear_pct) ? `, wear ${pct(st.wear_pct)}` : ''}`]),
    ...health.temperatures.map((t) => [`Temperature ${t.name}`, `${t.value_c} °C${given(t.limit_c) ? ` (limit ${t.limit_c} °C)` : ''}`]),
    ...health.fans.map((f) => [`Fan ${f.name}`, `${given(f.rpm) ? `${f.rpm} rpm, ` : ''}${okText(f.ok)}`]),
    ...health.power_supplies.map((p) => [`Power supply ${p.name}`, `${okText(p.ok)}${given(p.watts) ? `, ${p.watts} W` : ''}`]),
    ...health.ups.map((u) => [`UPS ${u.name}`, ups(u)]),
  ];
  return h('section', { class: 'card', 'data-testid': 'device-health' }, h('h2', {}, 'Health'), kv(rows));
}

// Clock, time zone and NTP (#179).
function timeCard(time) {
  if (!time) return null;
  let offset;
  if (time.clock && time.read_at) {
    const sec = (new Date(time.clock).getTime() - new Date(time.read_at).getTime()) / 1000;
    offset = Math.abs(sec) < 2 ? 'in step with Signalbox' : `${fmtDuration(Math.abs(sec))} ${sec > 0 ? 'ahead' : 'behind'}`;
  }
  const c = time.ntp_client;
  const s = time.ntp_server;
  const sync = c && c.synchronised === true ? ', synchronised' : c && c.synchronised === false ? ', not synchronised' : '';
  const rows = [
    ['Clock', offset],
    ['Time zone', opt(time.timezone)],
    ['NTP client', c ? (c.enabled ? `${c.servers.join(', ') || 'no servers'}${sync}` : 'off') : undefined],
    ['Last synchronised', c ? opt(c.last_sync, fmtTime) : undefined],
    ['NTP server', s ? (s.enabled ? 'serves time to the network' : 'off') : undefined],
  ];
  return h('section', { class: 'card', 'data-testid': 'device-time' }, h('h2', {}, 'Time'), kv(rows));
}

const UPLINK_KIND = { dhcp: 'DHCP', static: 'static address', pppoe: 'PPPoE', dslite: 'DS-Lite', 'map-e': 'MAP-E', lte: 'mobile', bridge: 'bridge (modem only)', other: null };
const NAT_TEXT = {
  public: 'public IPv4',
  cgnat: 'IPv4 behind the provider’s NAT (CGNAT)',
  private: 'private IPv4: another router is in front (double NAT)',
  none: 'no IPv4 of its own',
};
const kbps = (v) => (v >= 1000 ? `${Math.round(v / 100) / 10} Mbit/s` : `${v} kbit/s`);

// One uplink (#148): summary first, addresses only on request (they identify the household).
function uplinkValue(ix, u) {
  const since = u.up && u.since ? `up for ${fmtDuration((Date.now() - new Date(u.since).getTime()) / 1000)}` : null;
  const v6 = u.addresses.some((a) => a.includes(':') && !a.toLowerCase().startsWith('fe80'));
  const pd = u.delegated_prefixes.length ? `IPv6 /${u.delegated_prefixes[0].split('/')[1]} delegated` : v6 ? 'IPv6' : null;
  const summary = [
    UPLINK_KIND[u.kind],
    u.up === false ? 'down' : since || (u.up ? 'up' : null),
    // in the LAN of another known router: that one is in front, whatever the address looks like
    u.upstream_device ? `behind ${ix.deviceName(u.upstream_device)} (double NAT)` : NAT_TEXT[u.nat_class],
    pd,
    u.downstream_kbps && u.upstream_kbps ? `${kbps(u.downstream_kbps)} down / ${kbps(u.upstream_kbps)} up` : null,
  ].filter(Boolean);
  const details = [
    ...u.addresses,
    ...u.delegated_prefixes.map((p) => `${p} (delegated)`),
    u.public_ipv4 ? `${u.public_ipv4} (public)` : null,
    u.upstream_gateway ? `gateway ${u.upstream_gateway}` : null,
    u.dns_servers.length ? `DNS ${u.dns_servers.join(', ')}` : null,
  ].filter(Boolean);
  return h(
    'div',
    { 'data-testid': 'uplink' },
    h('span', { 'data-testid': 'uplink-summary' }, summary.join(' · ') || 'no details reported'),
    details.length
      ? h('details', { class: 'addresses', 'data-testid': 'uplink-addresses' }, h('summary', {}, 'Show addresses'), h('ul', { class: 'mono' }, details.map((a) => h('li', {}, a))))
      : null,
  );
}

function internetCard(ix, deviceId) {
  const uplinks = ix.net.uplinks.filter((u) => u.device_id === deviceId);
  if (!uplinks.length) return null;
  const rows = uplinks.map((u) => [u.name || u.id.split('/uplink/').pop(), uplinkValue(ix, u)]);
  return h('section', { class: 'card', 'data-testid': 'device-internet' }, h('h2', {}, 'Internet'), kv(rows));
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
        ['Changes allowed', yesNo(device.allow_writes)],
      ]),
      errors.length ? h('ul', { class: 'error', 'data-testid': 'device-errors' }, errors.map((e) => h('li', {}, `${e.capability}: ${e.message}`))) : null,
    ),
    internetCard(ix, device.id),
    observed ? healthCard(observed.health) : null,
    observed ? timeCard(observed.time) : null,
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
    uplinks: net.uplinks.filter(mine),
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
            ['Description', (p) => p.description],
            ['Kind', (p) => p.kind],
            ['Up', (p) => yesNo(p.up)],
            ['Speed', (p) => portSpeed(p)],
            ['Settings', (p) => portDetails(p).join(' · ') || null],
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
