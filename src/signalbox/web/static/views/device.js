// One device: overview with connection test and certificate trust, settings, advanced (raw data).
import { del, enc, get, post } from '../api.js';
import { loadNetwork } from '../net.js';
import { clear, fmtAgo, fmtBytes, fmtDuration, fmtTime, h, place, portDetails, portSpeed, yesNo } from '../util.js';
import { card, confirmDialog, empty, kv, pageHead, run, statusBadge, table, tabs, toast } from '../ui.js';
import { ROLE_TEXT, renderDeviceForm, testOnOpen } from './devices.js';
import { readErrors, testResult, trustPanel } from './devicetest.js';
import { notesCard } from '../annotations.js';

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

const SERVICE_LABEL = {
  ssh: 'SSH', telnet: 'Telnet', http: 'HTTP', https: 'HTTPS', api: 'API', 'api-ssl': 'API (TLS)', snmp: 'SNMP', ftp: 'FTP', tftp: 'TFTP',
  winbox: 'Winbox', 'mac-telnet': 'MAC telnet', 'mac-winbox': 'MAC Winbox', romon: 'RoMON', 'tr-064': 'TR-064', upnp: 'UPnP', vendor: 'configuration protocol', other: 'service',
};

function serviceLabel(s) {
  const text = SERVICE_LABEL[s.kind] || s.kind;
  return s.name && ![s.kind, text.toLowerCase()].includes(s.name.toLowerCase()) ? `${text} (${s.name})` : text;
}

// Root may log in with a password: the same rule as ManagementService.allows_root_password().
function rootPassword(s) {
  if (s.root_login === false || s.password_login === false) return false;
  if (s.root_password_login !== null) return s.root_password_login;
  return s.root_login && s.password_login ? true : null;
}

// One management service (#173): where it listens and who can reach it, as the device says.
function serviceValue(ix, s, hasUplink) {
  if (!s.enabled) return h('span', { class: 'muted', 'data-testid': 'service-summary' }, 'off');
  const redirect = s.kind === 'http' && s.redirects_to_https;
  const plain = s.encrypted === false && !redirect;
  const where = [
    ...s.listen.filter((a) => a !== '0.0.0.0' && a !== '::'),
    ...s.interfaces.map((p) => ix.portName(p)),
    ...s.segments.map((x) => ix.segmentName(x)),
  ];
  const root = s.kind === 'ssh' ? rootPassword(s) : null;
  const summary = [
    s.transport === 'layer2' ? 'layer 2 (MAC address)' : s.port ? `port ${s.port}` : null,
    redirect ? 'redirects to HTTPS' : s.encrypted === true ? 'encrypted' : null,
    where.length ? `on ${where.join(', ')}` : 'on every address',
    s.allowed_from.length ? `only from ${s.allowed_from.join(', ')}` : null,
    s.reach_segments.length ? `reachable from ${s.reach_segments.map((x) => ix.segmentName(x)).join(', ')}` : null,
    s.internet === null && hasUplink ? 'internet: the firewall decides' : null,
    s.kind === 'ssh' && s.password_login === false ? 'keys only' : null,
    s.snmp && s.snmp.versions.length ? `v${s.snmp.versions.join('/v')}` : null,
  ].filter(Boolean);
  return h(
    'div',
    { class: 'service', 'data-testid': 'service' },
    h('span', { 'data-testid': 'service-summary' }, summary.join(' · ')),
    plain ? h('span', { class: 'tag danger', 'data-testid': 'service-plaintext' }, 'unencrypted') : null,
    s.internet === true ? h('span', { class: 'tag danger', 'data-testid': 'service-internet' }, 'reachable from the internet') : null,
    root ? h('span', { class: 'tag danger', 'data-testid': 'service-root-password' }, 'root with password') : null,
    s.snmp && s.snmp.default_community ? h('span', { class: 'tag danger' }, 'default community') : null,
  );
}

function managementCard(ix, observed) {
  const services = ix.net.services.filter((s) => s.device_id === observed.id);
  const rows = [];
  if (observed.transport_encrypted !== null)
    rows.push([
      'Signalbox reads it',
      observed.transport_encrypted
        ? 'encrypted'
        : h('span', { 'data-testid': 'transport-plaintext' }, 'unencrypted: the password travels in clear text in this network'),
    ]);
  const hasUplink = ix.net.uplinks.some((u) => u.device_id === observed.id);
  const order = [...services].sort((a, b) => Number(b.enabled) - Number(a.enabled) || serviceLabel(a).localeCompare(serviceLabel(b)));
  rows.push(...order.map((s) => [serviceLabel(s), serviceValue(ix, s, hasUplink)]));
  if (!rows.length) return null;
  return h('section', { class: 'card', 'data-testid': 'device-management' }, h('h2', {}, 'Management'), kv(rows));
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
    if (fingerprint && status === 'untrusted-certificate')
      place(
        trustBox,
        trustPanel(fingerprint, async (fp) => {
          await post(`/devices/${enc(device.id)}/trust`, { fingerprint: fp });
          toast('Certificate trusted.');
          await test();
        }),
      );
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
      readErrors(errors, 'device-errors'),
    ),
    notesCard(ix, device.id, 'device', `Notes on ${device.name}`, () => ctx.refresh()),
    internetCard(ix, device.id),
    observed ? managementCard(ix, observed) : null,
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
    services: net.services.filter(mine),
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
