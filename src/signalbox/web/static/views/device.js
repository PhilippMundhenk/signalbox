// One device: overview with connection test and certificate trust, settings, advanced (raw data).
import { del, enc, get, post } from '../api.js';
import { compare, fmtDate, fmtNumber, t } from '../i18n.js';
import { fdbText, loadNetwork } from '../net.js';
import { LAG_MODE, PORT_ROLE, clear, fmtAgo, fmtBytes, fmtDuration, fmtTime, h, ltr, place, portDetails, portSpeed, yesNo } from '../util.js';
import { busy, card, confirmDialog, empty, kv, manageLink, pageHead, run, statusBadge, table, tabs, toast } from '../ui.js';
import { ROLE_TEXT, renderDeviceForm, testOnOpen } from './devices.js';
import { fixPanel, remedyOf } from './devicefix.js';
import { readErrors, testResult, trustPanel } from './devicetest.js';
import { notesCard } from '../annotations.js';
import { sparkline } from '../sparkline.js';

const given = (v) => v !== null && v !== undefined;
// kv() skips undefined: a row only for what the device reports.
const opt = (v, fn = (x) => x) => (given(v) ? fn(v) : undefined);
const pct = (v) => `${fmtNumber(Math.round(v * 10) / 10)} %`;
const usage = (used, total) => (given(used) && total ? t('device.usage', { used: fmtBytes(used), total: fmtBytes(total), percent: fmtNumber(Math.round((100 * used) / total)) }) : undefined);
const okText = (ok) => (ok === true ? t('device.ok.ok') : ok === false ? t('device.ok.failed') : t('device.state.unknown'));

// Health as reported (#178): only the values the device has.
function healthCard(health) {
  if (!health) return null;
  const ups = (u) => [u.on_battery ? t('device.ups.battery') : u.on_battery === false ? t('device.ups.mains') : t('device.state.unknown'), opt(u.charge_pct, (v) => t('device.ups.charge', { value: pct(v) })), opt(u.runtime_seconds, (v) => t('device.ups.runtime', { duration: fmtDuration(v) }))].filter(Boolean).join(', ');
  const rows = [
    [t('device.health.uptime'), opt(health.uptime_seconds, fmtDuration)],
    [t('device.health.started'), opt(health.boot_time, fmtTime)],
    [t('device.health.lastRestart'), opt(health.last_reboot_reason)],
    [t('device.health.cpuLoad'), opt(health.cpu_load_pct, (v) => `${pct(v)}${health.cpu_count ? ` (${t('device.health.cores', { count: health.cpu_count })})` : ''}`)],
    [t('device.health.loadAverage'), opt(health.load_average, (l) => l.map((x) => x.toFixed(2)).join(' / '))],
    [t('device.health.memoryUsed'), usage(health.memory_used_bytes, health.memory_total_bytes)],
    ...health.storage.map((st) => [t('device.health.storage', { name: st.name }), `${usage(st.used_bytes, st.total_bytes) || '–'}${given(st.wear_pct) ? `, ${t('device.health.wear', { value: pct(st.wear_pct) })}` : ''}`]),
    ...health.temperatures.map((tmp) => [t('device.health.temperature', { name: tmp.name }), `${tmp.value_c} °C${given(tmp.limit_c) ? ` (${t('device.health.limit', { value: tmp.limit_c })})` : ''}`]),
    ...health.fans.map((f) => [t('device.health.fan', { name: f.name }), `${given(f.rpm) ? `${f.rpm} rpm, ` : ''}${okText(f.ok)}`]),
    ...health.power_supplies.map((p) => [t('device.health.powerSupply', { name: p.name }), `${okText(p.ok)}${given(p.watts) ? `, ${p.watts} W` : ''}`]),
    ...health.ups.map((u) => [t('device.health.ups', { name: u.name }), ups(u)]),
  ];
  return h('section', { class: 'card', 'data-testid': 'device-health' }, h('h2', {}, t('device.health.title')), kv(rows));
}

// Clock, time zone and NTP (#179).
function timeCard(time) {
  if (!time) return null;
  let offset;
  if (time.clock && time.read_at) {
    const sec = (new Date(time.clock).getTime() - new Date(time.read_at).getTime()) / 1000;
    offset = Math.abs(sec) < 2 ? t('device.time.inStep') : t(sec > 0 ? 'device.time.ahead' : 'device.time.behind', { duration: fmtDuration(Math.abs(sec)) });
  }
  const c = time.ntp_client;
  const s = time.ntp_server;
  const sync = c && c.synchronised === true ? `, ${t('device.time.synchronised')}` : c && c.synchronised === false ? `, ${t('device.time.notSynchronised')}` : '';
  const rows = [
    [t('device.time.clock'), offset],
    [t('device.time.timezone'), opt(time.timezone)],
    [t('device.time.ntpClient'), c ? (c.enabled ? `${c.servers.join(', ') || t('device.time.noServers')}${sync}` : t('device.off')) : undefined],
    [t('device.time.lastSync'), c ? opt(c.last_sync, fmtTime) : undefined],
    [t('device.time.ntpServer'), s ? (s.enabled ? t('device.time.serves') : t('device.off')) : undefined],
  ];
  return h('section', { class: 'card', 'data-testid': 'device-time' }, h('h2', {}, t('device.time.title')), kv(rows));
}

const UPLINK_KIND = { dhcp: 'device.uplink.dhcp', static: 'device.uplink.static', pppoe: 'device.uplink.pppoe', dslite: 'device.uplink.dslite', 'map-e': 'device.uplink.mapE', lte: 'device.uplink.lte', bridge: 'device.uplink.bridge' };
const NAT_TEXT = {
  public: 'device.nat.public',
  cgnat: 'device.nat.cgnat',
  private: 'device.nat.private',
  none: 'device.nat.none',
};
const kbps = (v) => (v >= 1000 ? `${Math.round(v / 100) / 10} Mbit/s` : `${v} kbit/s`);

// One uplink (#148): summary first, addresses only on request (they identify the household).
function uplinkValue(ix, u) {
  const since = u.up && u.since ? t('device.uplink.upFor', { duration: fmtDuration((Date.now() - new Date(u.since).getTime()) / 1000) }) : null;
  const v6 = u.addresses.some((a) => a.includes(':') && !a.toLowerCase().startsWith('fe80'));
  const pd = u.delegated_prefixes.length ? t('device.uplink.delegatedPrefix', { length: u.delegated_prefixes[0].split('/')[1] }) : v6 ? 'IPv6' : null;
  const summary = [
    UPLINK_KIND[u.kind] ? t(UPLINK_KIND[u.kind]) : null,
    u.up === false ? t('device.state.down') : since || (u.up ? t('device.state.up') : null),
    // in the LAN of another known router: that one is in front, whatever the address looks like
    u.upstream_device ? t('device.uplink.behind', { name: ix.deviceName(u.upstream_device) }) : NAT_TEXT[u.nat_class] ? t(NAT_TEXT[u.nat_class]) : undefined,
    pd,
    u.downstream_kbps && u.upstream_kbps ? t('device.uplink.speed', { down: kbps(u.downstream_kbps), up: kbps(u.upstream_kbps) }) : null,
    u.health && u.health.state === 'degraded' ? t('device.multiwan.state.degraded') : null,
    u.health && given(u.health.latency_ms) ? t('device.multiwan.latency', { value: Math.round(u.health.latency_ms * 10) / 10 }) : null,
    u.health && given(u.health.loss_pct) ? t('device.multiwan.loss', { value: Math.round(u.health.loss_pct * 10) / 10 }) : null,
  ].filter(Boolean);
  const details = [
    ...u.addresses,
    ...u.delegated_prefixes.map((p) => t('device.uplink.delegated', { prefix: p })),
    u.public_ipv4 ? t('device.uplink.public', { address: u.public_ipv4 }) : null,
    u.upstream_gateway ? t('device.uplink.gateway', { address: u.upstream_gateway }) : null,
    u.dns_servers.length ? t('device.uplink.dns', { servers: u.dns_servers.join(', ') }) : null,
  ].filter(Boolean);
  return h(
    'div',
    { 'data-testid': 'uplink' },
    h('span', { 'data-testid': 'uplink-summary' }, summary.join(' · ') || t('device.uplink.none')),
    details.length
      ? h('details', { class: 'addresses', 'data-testid': 'uplink-addresses' }, h('summary', {}, t('device.uplink.showAddresses')), h('ul', { class: 'mono' }, details.map((a) => h('li', {}, a))))
      : null,
  );
}

// Multi-WAN (#150): one row per gateway group with its lines (tier, state, latency, loss, the
// one that carries the traffic) and how often the active line changed in the retained history.
const HEALTH_STATE = { online: 'device.multiwan.state.online', degraded: 'device.multiwan.state.degraded', down: 'device.multiwan.state.down', standby: 'device.multiwan.state.standby' };
function multiwanMember(g, m) {
  const parts = [
    g.mode === 'failover' ? (m.tier > 1 ? t('device.multiwan.tier.backup', { tier: m.tier }) : t('device.multiwan.tier.first')) : null,
    HEALTH_STATE[m.state] ? t(HEALTH_STATE[m.state]) : null,
    g.active === m.name ? t('device.multiwan.active') : null,
    given(m.latency_ms) ? t('device.multiwan.latency', { value: Math.round(m.latency_ms * 10) / 10 }) : null,
    given(m.loss_pct) ? t('device.multiwan.loss', { value: Math.round(m.loss_pct * 10) / 10 }) : null,
    given(m.weight) && g.mode === 'balance' ? t('device.multiwan.weight', { value: m.weight }) : null,
    m.monitor_targets.length ? t('device.multiwan.monitor', { targets: m.monitor_targets.join(', ') }) : null,
  ].filter(Boolean);
  return h('li', { 'data-testid': 'multiwan-member' }, h('strong', {}, m.name), parts.length ? ` · ${parts.join(' · ')}` : '');
}

function multiwanCard(ix, deviceId) {
  const groups = (ix.net.gateway_groups || []).filter((g) => g.device_id === deviceId);
  if (!groups.length) return null;
  const rows = groups.map((g) => [
    g.name,
    h(
      'div',
      { 'data-testid': 'multiwan-group' },
      h('span', {}, g.mode === 'balance' ? t('device.multiwan.balance') : t('device.multiwan.failover')),
      h('ul', {}, g.members.map((m) => multiwanMember(g, m))),
      given(g.failovers) ? h('span', { class: 'muted small', 'data-testid': 'multiwan-failovers' }, t('device.multiwan.failovers', { count: g.failovers, days: g.failover_days })) : null,
    ),
  ]);
  return h('section', { class: 'card', 'data-testid': 'device-multiwan' }, h('h2', {}, t('device.multiwan.title')), kv(rows));
}

// Neighbours learned by LLDP, CDP or MNDP (#163, #448): what each announces on its port. Text
// only; a fact the neighbour did not announce is left out.
const WATTS = (v) => fmtNumber(Math.round(v * 10) / 10);
function lldpDetails(n) {
  return [
    opt(n.port_vlan, (v) => t('device.lldp.portVlan', { id: v })),
    n.vlans && n.vlans.length ? t('device.lldp.vlans', { list: n.vlans.join(', ') }) : null,
    opt(n.max_frame_size, (v) => t('device.lldp.frameSize', { bytes: fmtNumber(v) })),
    opt(n.poe_requested_w, (v) => t('device.lldp.poeRequested', { value: WATTS(v) })),
    opt(n.poe_allocated_w, (v) => t('device.lldp.poeAllocated', { value: WATTS(v) })),
    opt(n.poe_class, (v) => t('device.lldp.poeClass', { value: v })),
    n.med_device_class ? t('device.lldp.med', { class: n.med_device_class }) : null,
    n.last_seen ? t('device.lldp.lastSeen', { ago: fmtAgo(n.last_seen) }) : opt(n.age_seconds, (v) => t('device.lldp.age', { duration: fmtDuration(v) })),
  ].filter(Boolean);
}

function lldpCard(ix, deviceId) {
  const rows = ix.net.neighbours.filter((n) => (n.source && n.source.device_id === deviceId) || n.local_port_id.startsWith(`${deviceId}/`));
  if (!rows.length) return null;
  rows.sort((a, b) => compare(ix.portName(a.local_port_id), ix.portName(b.local_port_id)));
  const remote = (n) => [n.remote_port, n.port_description && n.port_description !== n.remote_port ? `(${n.port_description})` : null].filter(Boolean).join(' ');
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-lldp' },
    h('h2', {}, t('device.lldp.title')),
    h('p', { class: 'muted' }, t('device.lldp.intro', { count: rows.length })),
    table(
      [
        [t('device.lldp.port'), (n) => ix.portName(n.local_port_id)],
        [t('device.lldp.neighbour'), (n) => n.system_name || n.chassis_id],
        [t('device.lldp.remotePort'), remote],
        [t('device.lldp.protocol'), (n) => (n.protocol || '').toUpperCase()],
        [t('device.lldp.details'), (n) => h('span', { 'data-testid': 'lldp-details' }, lldpDetails(n).join(' · '))],
      ],
      rows,
      { testid: 'lldp-table', rowTestid: 'lldp-row', compact: true },
    ),
  );
}

// DNS resolvers on the device (#182, #456): the settings that decide how names are answered,
// and the upstream resolvers with the way they are reached. A service whose settings could not
// be read says so instead of showing empty lists.
const TRANSPORT = { udp: 'device.dns.transport.udp', tls: 'device.dns.transport.tls', https: 'device.dns.transport.https', quic: 'device.dns.transport.quic' };
function dnsSettings(s) {
  const onOff = (v, on, off) => (v === true ? t(on) : v === false ? t(off) : null);
  return [
    onOff(s.recursive, 'device.dns.recursive.yes', 'device.dns.recursive.no'),
    onOff(s.dnssec, 'device.dns.dnssec.on', 'device.dns.dnssec.off'),
    onOff(s.rebind_protection, 'device.dns.rebind.on', 'device.dns.rebind.off'),
    s.rebind_allowed_domains.length ? t('device.dns.rebindAllowed', { domains: s.rebind_allowed_domains.join(', ') }) : null,
    opt(s.cache_size, (v) => t('device.dns.cache', { size: fmtNumber(v) })),
    s.local_domain ? t('device.dns.localDomain', { domain: s.local_domain }) : null,
    onOff(s.register_dhcp, 'device.dns.dhcp.on', 'device.dns.dhcp.off'),
  ].filter(Boolean);
}

function dnsUpstream(f) {
  const where = f.port === 53 ? f.address : f.address.includes(':') ? `[${f.address}]:${f.port}` : `${f.address}:${f.port}`;
  return h(
    'li',
    { 'data-testid': 'dns-upstream' },
    h('span', { class: 'mono' }, where),
    ` · ${t(TRANSPORT[f.transport] || TRANSPORT.udp)}`,
    f.domain ? ` · ${t('device.dns.forDomain', { domain: f.domain })}` : '',
  );
}

function dnsCard(ix, deviceId) {
  const services = ix.net.dns_services.filter((s) => s.device_id === deviceId);
  if (!services.length) return null;
  const rows = services.map((s) => [
    s.name || t('device.dns.service'),
    h(
      'div',
      { 'data-testid': 'dns-service' },
      s.port !== 53 ? h('span', { class: 'muted small' }, t('device.dns.port', { port: s.port })) : null,
      s.config_read
        ? h('ul', { 'data-testid': 'dns-settings' }, dnsSettings(s).map((x) => h('li', {}, x)))
        : h('p', { class: 'muted', 'data-testid': 'dns-unread' }, t('device.dns.unread')),
      s.config_read && s.forwarders.length
        ? h('div', {}, h('strong', {}, t('device.dns.upstreams')), h('ul', {}, s.forwarders.map(dnsUpstream)))
        : null,
    ),
  ]);
  return h('section', { class: 'card', 'data-testid': 'device-dns' }, h('h2', {}, t('device.dns.title')), kv(rows));
}

function internetCard(ix, deviceId) {
  const uplinks = ix.net.uplinks.filter((u) => u.device_id === deviceId);
  if (!uplinks.length) return null;
  const rows = uplinks.map((u) => [u.name || u.id.split('/uplink/').pop(), uplinkValue(ix, u)]);
  return h('section', { class: 'card', 'data-testid': 'device-internet' }, h('h2', {}, t('device.internet.title')), kv(rows));
}

// Cables drawn from partial data (#378): each with the observations that support it.
const EVIDENCE = { fdb: 'topology.evidence.fdb', arp: 'topology.evidence.arp', address: 'topology.evidence.address' };
function inferredCard(ix, deviceId) {
  const ours = (id) => (ix.ports.get(id) || {}).device_id === deviceId || id.startsWith(`${deviceId}/port/`);
  const links = ix.net.links.filter((l) => l.inferred && (ours(l.a) || ours(l.b)));
  if (!links.length) return null;
  const rows = links.map((l) => {
    const [mine, other] = ours(l.a) ? [l.a, l.b] : [l.b, l.a];
    const seen = l.evidence.map((e) => `${ix.portName(e.port_id)} (${EVIDENCE[e.source] ? t(EVIDENCE[e.source]) : e.source})`);
    return [ix.portName(mine), h('span', {}, `↔ ${ix.portName(other)}`, h('br'), h('span', { class: 'muted small', 'data-testid': 'inferred-evidence' }, t('topology.evidence', { sources: seen.join(', ') || '–' })))];
  });
  return h('section', { class: 'card', 'data-testid': 'device-inferred-links' }, h('h2', {}, t('device.inferredLinks')), kv(rows));
}

// WireGuard tunnels (#239): the interface, then one row per peer. Endpoints are the other
// site's public address: shown on request, like uplink addresses.
function handshakeText(p) {
  if (!p.latest_handshake) return t('device.peer.noHandshake');
  const age = given(p.handshake_age) ? p.handshake_age : (Date.now() - new Date(p.latest_handshake).getTime()) / 1000;
  return t('device.peer.handshake', { duration: fmtDuration(Math.max(0, age)) });
}

function peerTable(ix, tun) {
  if (!tun.peers.length) return h('p', { class: 'muted' }, t('device.peer.none'));
  const tunnelOf = (id) => ix.net.tunnels.find((x) => x.id === id);
  return table(
    [
      [t('device.peer.peer'), (p) => p.name || h('span', { class: 'mono' }, `${p.public_key.slice(0, 10)}…`)],
      [
        t('device.peer.otherEnd'),
        (p) => {
          const other = p.other_end && tunnelOf(p.other_end);
          if (other) return h('a', { href: `#/device/${enc(other.device_id)}`, 'data-testid': 'peer-other-end' }, `${ix.deviceName(other.device_id)} · ${other.name}`);
          return p.networks.length ? t('device.peer.remoteSite') : t('device.peer.client');
        },
      ],
      [t('device.peer.routes'), (p) => (p.networks.length ? h('span', { class: 'mono' }, p.networks.join(', ')) : null)],
      [t('device.peer.status'), (p) => h('span', { 'data-testid': 'peer-handshake' }, handshakeText(p))],
      [t('device.peer.traffic'), (p) => (given(p.rx_bytes) ? t('device.peer.trafficValue', { rx: fmtBytes(p.rx_bytes), tx: fmtBytes(p.tx_bytes || 0) }) : null)],
      [t('device.peer.keepalive'), (p) => (p.keepalive_seconds ? `${p.keepalive_seconds} s` : p.keepalive_seconds === 0 ? t('device.off') : null)],
      [
        t('device.peer.endpoint'),
        (p) =>
          p.endpoint_host
            ? h('details', { class: 'addresses', 'data-testid': 'peer-endpoint' }, h('summary', {}, t('device.peer.show')), h('span', { class: 'mono' }, p.endpoint_port ? `${p.endpoint_host}:${p.endpoint_port}` : p.endpoint_host))
            : null,
      ],
    ],
    tun.peers,
    { rowTestid: 'tunnel-peer', compact: true },
  );
}

function tunnelsCard(ix, deviceId) {
  const tunnels = (ix.net.tunnels || []).filter((t) => t.device_id === deviceId);
  if (!tunnels.length) return null;
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-tunnels' },
    h('h2', {}, t('device.tunnel.title')),
    tunnels.map((tun) =>
      h(
        'div',
        { 'data-testid': 'tunnel', 'data-id': tun.id },
        h('h3', {}, `${tun.name}${tun.description ? ` (${tun.description})` : ''}`),
        kv([
          [t('device.tunnel.kind'), tun.kind === 'wireguard' ? 'WireGuard' : tun.kind],
          [t('device.tunnel.state'), tun.up === true ? t('device.state.up') : tun.up === false ? t('device.state.down') : t('device.state.unknown')],
          [t('device.tunnel.listensOn'), opt(tun.listen_port, (v) => `UDP ${v}`)],
          [t('device.tunnel.addresses'), tun.addresses.length ? tun.addresses.join(', ') : undefined],
          [t('device.tunnel.publicKey'), opt(tun.public_key, (v) => h('span', { class: 'mono' }, v))],
        ]),
        peerTable(ix, tun),
      ),
    ),
  );
}

// Dynamic DNS clients (#154, #440): the state first; the name identifies the household, so it
// and the announced address are shown on request, like uplink addresses.
function ddnsState(d) {
  return [
    d.enabled ? null : t('device.off'),
    d.last_result === 'ok' ? t('device.ddns.ok') : d.last_result === 'error' ? t('device.ddns.error') : null,
    d.last_update ? t('device.ddns.updated', { duration: fmtDuration(Math.max(0, (Date.now() - new Date(d.last_update).getTime()) / 1000)) }) : null,
    d.tls === true ? t('device.ddns.encrypted') : d.tls === false ? t('device.ddns.plain') : null,
  ].filter(Boolean);
}

function ddnsCard(ix, deviceId) {
  const clients = (ix.net.ddns || []).filter((d) => d.device_id === deviceId);
  if (!clients.length) return null;
  const rows = clients.map((d) => [
    d.provider,
    h(
      'div',
      { 'data-testid': 'ddns' },
      h('span', { 'data-testid': 'ddns-state' }, ddnsState(d).join(' · ') || t('device.state.unknown')),
      h(
        'details',
        { class: 'addresses', 'data-testid': 'ddns-name' },
        h('summary', {}, t('device.peer.show')),
        h('ul', { class: 'mono' }, [h('li', {}, d.hostname), d.published_address ? h('li', {}, t('device.ddns.announces', { address: d.published_address })) : null].filter(Boolean)),
      ),
    ),
  ]);
  return h('section', { class: 'card', 'data-testid': 'device-ddns' }, h('h2', {}, t('device.ddns.title')), kv(rows));
}

// Firewall (#135): zones and what is in them, the default action per zone pair, port forwards.
function zoneMembers(ix, z) {
  const tail = (id, key) => id.split(`/${key}/`).pop();
  return [
    ...z.segments.map((id) => ix.segmentName(id)),
    ...z.uplinks.map((id) => t('device.fw.internet', { name: tail(id, 'uplink') })),
    ...z.tunnels.map((id) => t('device.fw.tunnel', { name: tail(id, 'tunnel') })),
    ...z.ports.map((id) => tail(id, 'port')),
  ].join(', ');
}

function policyMatrix(fw) {
  const names = fw.zones.map((z) => z.name);
  const cell = (a) => h('td', { class: a === 'accept' ? 'ok-text' : a ? 'warn-text' : 'muted', 'data-testid': 'fw-policy', title: a ? null : t('device.fw.notRead') }, a || '–');
  return h(
    'table',
    { class: 'fw-matrix', 'data-testid': 'fw-matrix' },
    h('thead', {}, h('tr', {}, h('th', {}, t('device.fw.fromTo')), h('th', {}, t('device.fw.device')), names.map((n) => h('th', {}, n)))),
    h('tbody', {}, names.map((src, i) => h('tr', {}, h('th', {}, src), (fw.matrix[i] || []).map(cell)))),
  );
}

function firewallCard(ix, deviceId) {
  const fw = (ix.net.firewalls || []).find((f) => f.device_id === deviceId);
  if (!fw) return null;
  const forwards = fw.port_forwards.map((p) => [
    `${p.protocols.length ? p.protocols.join('/').toUpperCase() : t('device.fw.allProtocols')} ${p.external_ports.length ? p.external_ports.map((r) => (r.end && r.end !== r.start ? `${r.start}-${r.end}` : `${r.start}`)).join(', ') : t('device.fw.allPorts')}`,
    [h('span', { class: 'mirror', 'aria-hidden': 'true' }, '→'), ' ', ltr(`${p.target_address}${p.target_port ? `:${p.target_port}` : ''}`), `${p.name ? ` (${p.name})` : ''}${p.enabled ? '' : `, ${t('device.off')}`}`],
  ]);
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-firewall' },
    h('h2', {}, t('device.fw.title')),
    fw.enabled ? null : h('p', { class: 'muted' }, t('device.fw.filteringOff')),
    fw.rules_complete ? null : h('p', { class: 'muted', 'data-testid': 'fw-incomplete' }, t('device.fw.incomplete')),
    kv(fw.zones.map((z) => [z.name, zoneMembers(ix, z) || '–'])),
    fw.zones.length ? policyMatrix(fw) : null,
    h('p', { class: 'muted' }, t('device.fw.rules', { count: fw.rules.filter((r) => r.enabled).length })),
    forwards.length ? h('div', { 'data-testid': 'fw-forwards' }, h('h3', {}, t('device.fw.forwards')), kv(forwards)) : null,
  );
}

const SERVICE_LABEL = {
  ssh: 'SSH', telnet: 'Telnet', http: 'HTTP', https: 'HTTPS', api: 'API', 'api-ssl': 'API (TLS)', snmp: 'SNMP', ftp: 'FTP', tftp: 'TFTP',
  winbox: 'Winbox', 'mac-telnet': 'MAC telnet', 'mac-winbox': 'MAC Winbox', romon: 'RoMON', 'tr-064': 'TR-064', upnp: 'UPnP',
};
const SERVICE_KEY = { vendor: 'device.service.vendor', other: 'device.service.other' };

function serviceLabel(s) {
  const text = SERVICE_KEY[s.kind] ? t(SERVICE_KEY[s.kind]) : SERVICE_LABEL[s.kind] || s.kind;
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
  if (!s.enabled) return h('span', { class: 'muted', 'data-testid': 'service-summary' }, t('device.off'));
  const redirect = s.kind === 'http' && s.redirects_to_https;
  const plain = s.encrypted === false && !redirect;
  const where = [
    ...s.listen.filter((a) => a !== '0.0.0.0' && a !== '::'),
    ...s.interfaces.map((p) => ix.portName(p)),
    ...s.segments.map((x) => ix.segmentName(x)),
  ];
  const root = s.kind === 'ssh' ? rootPassword(s) : null;
  const summary = [
    s.transport === 'layer2' ? t('device.service.layer2') : s.port ? t('device.service.port', { port: s.port }) : null,
    redirect ? t('device.service.redirects') : s.encrypted === true ? t('device.service.encrypted') : null,
    where.length ? t('device.service.on', { where: where.join(', ') }) : t('device.service.everyAddress'),
    s.allowed_from.length ? t('device.service.onlyFrom', { from: s.allowed_from.join(', ') }) : null,
    s.reach_segments.length ? t('device.service.reachableFrom', { from: s.reach_segments.map((x) => ix.segmentName(x)).join(', ') }) : null,
    s.internet === null && hasUplink ? t('device.service.firewallDecides') : null,
    s.kind === 'ssh' && s.password_login === false ? t('device.service.keysOnly') : null,
    s.snmp && s.snmp.versions.length ? `v${s.snmp.versions.join('/v')}` : null,
  ].filter(Boolean);
  return h(
    'div',
    { class: 'service', 'data-testid': 'service' },
    h('span', { 'data-testid': 'service-summary' }, summary.join(' · ')),
    plain ? h('span', { class: 'tag danger', 'data-testid': 'service-plaintext' }, t('device.service.unencrypted')) : null,
    s.internet === true ? h('span', { class: 'tag danger', 'data-testid': 'service-internet' }, t('device.service.internet')) : null,
    root ? h('span', { class: 'tag danger', 'data-testid': 'service-root-password' }, t('device.service.rootPassword')) : null,
    s.snmp && s.snmp.default_community ? h('span', { class: 'tag danger' }, t('device.service.defaultCommunity')) : null,
  );
}

function managementCard(ix, observed) {
  const services = ix.net.services.filter((s) => s.device_id === observed.id);
  const rows = [];
  if (observed.transport_encrypted !== null)
    rows.push([
      t('device.mgmt.readsIt'),
      observed.transport_encrypted
        ? t('device.service.encrypted')
        : h('span', { 'data-testid': 'transport-plaintext' }, t('device.mgmt.plaintext')),
    ]);
  const hasUplink = ix.net.uplinks.some((u) => u.device_id === observed.id);
  const order = [...services].sort((a, b) => Number(b.enabled) - Number(a.enabled) || compare(serviceLabel(a), serviceLabel(b)));
  rows.push(...order.map((s) => [serviceLabel(s), serviceValue(ix, s, hasUplink)]));
  if (!rows.length) return null;
  return h('section', { class: 'card', 'data-testid': 'device-management' }, h('h2', {}, t('device.mgmt.title')), kv(rows));
}

const LOG_KIND = {
  syslog: 'device.logs.syslog',
  netflow: 'device.logs.netflow',
  ipfix: 'device.logs.ipfix',
  sflow: 'device.logs.sflow',
  'snmp-trap': 'device.logs.snmpTrap',
  metrics: 'device.logs.metrics',
  other: 'device.logs.other',
};

// Where the device sends logs, flow records, traps and metrics (#180); null: not read.
function loggingCard(observed) {
  const targets = observed.log_targets;
  if (!Array.isArray(targets)) return null;
  const rows = targets.map((x) => {
    const ip6 = x.address.includes(':');
    const host = x.port ? `${ip6 ? `[${x.address}]` : x.address}:${x.port}` : x.address;
    const facts = [host, x.transport ? x.transport.toUpperCase() : null, x.topics.length ? x.topics.join(', ') : null];
    const label = x.name ? `${t(LOG_KIND[x.kind] || LOG_KIND.other)} (${x.name})` : t(LOG_KIND[x.kind] || LOG_KIND.other);
    return [
      label,
      h(
        'span',
        { class: x.enabled ? '' : 'muted', 'data-testid': 'log-target' },
        x.enabled ? facts.filter(Boolean).join(' · ') : `${facts[0]} · ${t('device.off')}`,
      ),
    ];
  });
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-logging' },
    h('h2', {}, t('device.logs.title')),
    rows.length ? kv(rows) : h('p', { class: 'muted' }, t('device.logs.none')),
  );
}

const PRIVILEGE = {
  admin: 'device.accounts.privilege.admin',
  write: 'device.accounts.privilege.write',
  read: 'device.accounts.privilege.read',
  other: 'device.accounts.privilege.other',
};

// Local accounts, the factory-password state and the rights of Signalbox's own login (#175);
// null when the integration reports none of them. Account names are shown here only.
function accountsCard(observed) {
  const accounts = Array.isArray(observed.accounts) ? observed.accounts : null;
  const factory = observed.default_credentials;
  const have = observed.signalbox_account_privilege;
  if (!accounts && factory == null && !have) return null;
  const day = (iso) => fmtDate(new Date(iso), { dateStyle: 'medium' });
  const rows = [];
  if (factory != null)
    rows.push([
      t('device.accounts.factory'),
      h('span', { class: factory ? 'bad-text' : '', 'data-testid': 'account-factory' }, t(factory ? 'device.accounts.factoryYes' : 'device.accounts.factoryNo')),
    ]);
  if (have) {
    const need = observed.signalbox_account_needed;
    const more = need && ['other', 'read', 'write', 'admin'].indexOf(have) > ['other', 'read', 'write', 'admin'].indexOf(need);
    const text = more ? t('device.accounts.rightsMore', { have: t(PRIVILEGE[have]), need: t(PRIVILEGE[need]) }) : t(PRIVILEGE[have]);
    rows.push([t('device.accounts.signalbox'), h('span', { class: more ? 'warn-text' : '', 'data-testid': 'account-signalbox' }, text)]);
  }
  for (const a of accounts || []) {
    const facts = [a.privilege ? t(PRIVILEGE[a.privilege]) : t('device.accounts.privilege.unknown')];
    if (!a.enabled) facts.push(t('device.accounts.disabled'));
    if (a.password_set === false && a.key_auth !== true) facts.push(t('device.accounts.noPassword'));
    if (a.key_auth) facts.push(t('device.accounts.key'));
    if (a.last_login) facts.push(t('device.accounts.lastLogin', { date: day(a.last_login) }));
    else if (a.logins_tracked) facts.push(t('device.accounts.neverLoggedIn'));
    if (a.allowed_from.length) facts.push(t('device.accounts.from', { networks: a.allowed_from.join(', ') }));
    if (a.is_signalbox) facts.push(t('device.accounts.ours'));
    const bad = a.enabled && a.password_set === false && a.key_auth !== true;
    rows.push([a.name, h('span', { class: bad ? 'bad-text' : a.enabled ? '' : 'muted', 'data-testid': 'account' }, facts.join(' · '))]);
  }
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-accounts' },
    h('h2', {}, t('device.accounts.title')),
    rows.length ? kv(rows) : h('p', { class: 'muted' }, t('device.accounts.none')),
  );
}

// The certificate the device presents for HTTPS (#174); null: no HTTPS read.
function certificateCard(observed) {
  const c = observed.certificate;
  if (!c || typeof c !== 'object') return null;
  const day = (iso) => fmtDate(new Date(iso), { dateStyle: 'medium' });
  const expired = new Date(c.not_after).getTime() <= Date.now();
  const key = c.key_type === 'other' ? c.key_type : `${c.key_type.toUpperCase()} ${c.key_bits}`;
  const rows = [
    [t('device.cert.validityLabel'), h('span', { class: expired ? 'bad' : '', 'data-testid': 'cert-validity' }, t('device.cert.validity', { from: day(c.not_before), to: day(c.not_after) }))],
    [t('device.cert.issuer'), c.self_signed ? t('device.cert.selfSigned') : c.issuer],
    [t('device.cert.key'), `${key} · ${c.signature_algorithm}`],
  ];
  const covers = c.matches_management_address === true ? t('device.cert.covers') : c.matches_management_address === false ? t('device.cert.coversNot') : null;
  const names = [c.san.length ? c.san.join(', ') : null, covers].filter(Boolean).join(' · ');
  if (names) rows.push([t('device.cert.names'), names]);
  if (c.pinned_since) rows.push([t('device.cert.pinnedSince'), day(c.pinned_since)]);
  rows.push([t('device.cert.fingerprint'), h('code', {}, c.fingerprint_sha256)]);
  if (!c.trusted) rows.push([t('device.cert.untrusted'), '']);
  return h('section', { class: 'card', 'data-testid': 'device-certificate' }, h('h2', {}, t('device.cert.title')), kv(rows));
}

// Certificates stored on the device (#330): VPN, RADIUS, web interface, authorities. Public
// data only; an empty list means the device does not list them.
const CERT_USE = {
  management: 'device.certs.use.management',
  vpn: 'device.certs.use.vpn',
  radius: 'device.certs.use.radius',
  other: 'device.certs.use.other',
};

function storedCertificatesCard(ix, deviceId) {
  const certs = (ix.net.certificates || []).filter((c) => c.device_id === deviceId);
  if (!certs.length) return null;
  const day = (iso) => fmtDate(new Date(iso), { dateStyle: 'medium' });
  const rows = certs.map((c) => {
    const expired = new Date(c.not_after).getTime() <= Date.now();
    const key = c.key_type === 'other' ? null : `${c.key_type.toUpperCase()} ${c.key_bits}`;
    const facts = [
      c.ca ? t('device.certs.ca') : null,
      ...c.uses.map((u) => t(CERT_USE[u] || CERT_USE.other)),
      key,
      c.self_signed ? t('device.cert.selfSigned') : c.issuer ? t('device.certs.issuedBy', { issuer: c.issuer }) : null,
      c.trusted_on_device ? t('device.certs.trustedOnDevice') : null,
      c.has_private_key ? t('device.certs.hasKey') : null,
      c.used_by.length ? t('device.certs.usedBy', { names: c.used_by.map((id) => id.split('/service/').pop()).join(', ') }) : null,
    ].filter(Boolean);
    return [
      c.name,
      h(
        'span',
        { 'data-testid': 'stored-certificate', 'data-id': c.id },
        h('span', { class: expired ? 'bad' : '' }, expired ? t('device.certs.expired', { date: day(c.not_after) }) : t('device.certs.until', { date: day(c.not_after) })),
        facts.length ? ` · ${facts.join(' · ')}` : '',
      ),
    ];
  });
  return h('section', { class: 'card', 'data-testid': 'device-certificates' }, h('h2', {}, t('device.certs.title')), kv(rows));
}

// The network of an interface address ("192.0.2.1/24" -> "192.0.2.0/24"); IPv6 shortened.
function networkOf(iface) {
  const [addr, lenText] = iface.split('/');
  const len = Number(lenText);
  if (!addr.includes(':')) {
    const v = addr.split('.').reduce((acc, part) => (acc << 8n) | BigInt(part), 0n);
    const mask = len === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - len)) - 1n);
    const n = v & mask;
    return `${[24n, 16n, 8n, 0n].map((sh) => String((n >> sh) & 255n)).join('.')}/${len}`;
  }
  const [head, tail = ''] = addr.split('::');
  const left = head ? head.split(':') : [];
  const right = addr.includes('::') && tail ? tail.split(':') : [];
  const groups = addr.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  const v = groups.reduce((acc, g) => (acc << 16n) | BigInt(`0x${g || '0'}`), 0n);
  const mask = len === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - len)) - 1n);
  const n = v & mask;
  const out = Array.from({ length: 8 }, (_, i) => ((n >> BigInt(112 - 16 * i)) & 0xffffn).toString(16));
  let best = [0, 0];
  for (let i = 0; i < 8; i += 1) {
    let j = i;
    while (j < 8 && out[j] === '0') j += 1;
    if (j - i > best[1] - best[0]) best = [i, j];
  }
  const text = best[1] - best[0] > 1 ? `${out.slice(0, best[0]).join(':')}::${out.slice(best[1]).join(':')}` : out.join(':');
  return `${text}/${len}`;
}

const ROUTE_ORIGIN = {
  connected: 'device.routes.origin.connected',
  static: 'device.routes.origin.static',
  dhcp: 'device.routes.origin.dhcp',
  ra: 'device.routes.origin.ra',
  vpn: 'device.routes.origin.vpn',
  dynamic: 'device.routes.origin.dynamic',
  other: 'device.routes.origin.other',
};
const ROUTE_KIND = {
  blackhole: 'device.routes.kind.blackhole',
  unreachable: 'device.routes.kind.unreachable',
  prohibit: 'device.routes.kind.prohibit',
};

// Routing table and policy rules (#149): the networks the device is attached to (derived from
// its subnets), then the routes it reports; null when nothing is known.
function routesCard(ix, deviceId) {
  const routes = (ix.net.routes || []).filter((r) => r.device_id === deviceId);
  const rules = (ix.net.routing_rules || []).filter((r) => r.device_id === deviceId);
  if (!routes.length && !rules.length) return null;
  const connected = ix.net.subnets
    .filter((x) => x.device_id === deviceId && !x.interface.startsWith('fe80:'))
    .map((x) => ({ destination: x.interface, origin: 'connected', connected: true, segment: x.segment_id }));
  const rows = [...connected, ...routes.map((r) => ({ ...r, route: true }))];
  const destination = (r) => {
    if (r.connected) return ltr(networkOf(r.destination));
    const net = r.destination === '0.0.0.0/0' || r.destination === '::/0' ? t('device.routes.default') : r.destination;
    return ltr(`${net}${r.table && r.table !== 'main' ? ` · ${t('device.routes.table', { table: r.table })}` : ''}`);
  };
  const via = (r) => {
    if (r.connected) return ix.segmentName(r.segment);
    if (r.kind && r.kind !== 'unicast') return t(ROUTE_KIND[r.kind]);
    return r.gateway ? ltr(r.gateway) : null;
  };
  const state = (r) => (r.connected ? null : !r.enabled ? t('device.off') : r.active === false ? t('device.routes.notInstalled') : null);
  const ruleAction = (r) => (r.action === 'lookup' ? t('device.routes.table', { table: r.table }) : t(ROUTE_KIND[r.action]));
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-routes' },
    h('h2', {}, t('device.routes.title')),
    table(
      [
        [t('device.routes.destination'), destination],
        [t('device.routes.via'), via],
        [t('device.routes.interface'), (r) => (r.interface ? r.interface.split('/port/').pop() : null)],
        [t('device.routes.metric'), (r) => (given(r.metric) ? String(r.metric) : null)],
        [t('device.routes.origin'), (r) => t(ROUTE_ORIGIN[r.origin] || ROUTE_ORIGIN.other)],
        [t('device.routes.state'), state],
      ],
      rows,
      { rowTestid: 'route', compact: true },
    ),
    rules.length
      ? [
          h('h3', {}, t('device.routes.rules')),
          table(
            [
              [t('device.routes.rulePriority'), (r) => (given(r.priority) ? String(r.priority) : null)],
              [t('device.routes.ruleFrom'), (r) => (r.src ? ltr(r.src) : t('device.routes.any'))],
              [t('device.routes.ruleTo'), (r) => (r.dst ? ltr(r.dst) : t('device.routes.any'))],
              [t('device.routes.ruleIn'), (r) => (r.segment_id ? ix.segmentName(r.segment_id) : t('device.routes.any'))],
              [t('device.routes.ruleAction'), ruleAction],
              [t('device.routes.state'), (r) => (r.enabled ? null : t('device.off'))],
            ],
            [...rules].sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0)),
            { rowTestid: 'routing-rule', compact: true },
          ),
        ]
      : null,
  );
}

const BAND = { 2.4: '2.4 GHz', 5: '5 GHz', 6: '6 GHz' };

const DFS_STATE = { available: 'device.radios.dfs.available', cac: 'device.radios.dfs.cac', 'radar-detected': 'device.radios.dfs.radar' };

// "36-64, 100-140": runs of neighbouring channels (4 apart on 5 and 6 GHz).
function channelRuns(channels, band) {
  const step = band === '2.4' ? 1 : 4;
  const runs = [];
  for (const c of [...new Set(channels)].sort((a, b) => a - b)) {
    const last = runs[runs.length - 1];
    if (last && c - last[1] === step) last[1] = c;
    else runs.push([c, c]);
  }
  return runs.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(', ');
}

// The radios with what they support and their state at the last read (#172); only the values
// the device reports. Null when the device has no radios.
function radiosCard(ix, deviceId) {
  const radios = ix.net.radios.filter((r) => r.device_id === deviceId).sort((a, b) => compare(a.name, b.name));
  if (!radios.length) return null;
  const std = (s) => `802.11${s}`;
  const rows = radios.map((r) => {
    const now = [
      BAND[r.band],
      r.enabled === false ? t('device.off') : null,
      opt(r.standard, std),
      r.channel ? t('device.port.channel', { channel: r.channel }) : null,
      r.channel_auto ? t('device.radios.auto') : null,
      opt(r.width_mhz, (w) => `${w} MHz`),
      opt(r.tx_power_dbm, (v) => `${v} dBm`),
      opt(r.client_count, (n) => t('device.radios.clients', { count: n })),
      opt(r.channel_utilisation_pct, (v) => t('device.radios.busy', { value: pct(v) })),
      opt(r.interference_pct, (v) => t('device.radios.interference', { value: pct(v) })),
      opt(r.noise_dbm, (v) => t('device.radios.noise', { value: v })),
      opt(r.dfs_state, (v) => t(DFS_STATE[v])),
      opt(r.last_radar, (v) => t('device.radios.lastRadar', { time: fmtTime(v) })),
      opt(r.neighbour_count, (n) => t('device.radios.neighbours', { count: n })),
      opt(r.strongest_foreign_dbm, (v) => t('device.radios.strongest', { value: v })),
    ].filter(Boolean);
    const can = [
      r.standards && r.standards.length ? r.standards.map(std).join(', ') : null,
      r.supported_channels && r.supported_channels.length ? t('device.radios.channels', { channels: channelRuns(r.supported_channels, r.band) }) : null,
      r.supported_widths_mhz && r.supported_widths_mhz.length ? `${r.supported_widths_mhz.join('/')} MHz` : null,
      opt(r.max_tx_power_dbm, (v) => t('device.radios.maxPower', { value: v })),
      opt(r.antennas, (v) => t('device.radios.antennas', { value: v })),
      r.dfs_capable ? t('device.radios.dfsCapable') : null,
      r.mlo ? t('device.radios.mlo') : null,
    ].filter(Boolean);
    return [
      r.name,
      h(
        'span',
        { 'data-testid': 'radio', 'data-id': r.id },
        h('span', { class: r.enabled === false ? 'muted' : '' }, now.join(' · ')),
        can.length ? h('span', { class: 'muted small radio-caps' }, t('device.radios.supports', { list: can.join(' · ') })) : null,
      ),
    ];
  });
  return h('section', { class: 'card', 'data-testid': 'device-radios' }, h('h2', {}, t('device.radios.title')), kv(rows));
}

// Link aggregation (#157): a LAG's mode, hash and LACP settings; a member's LAG and LACP state.
function lagFacts(ix, p) {
  const out = [];
  if (p.lag_mode) out.push(LAG_MODE[p.lag_mode] || p.lag_mode);
  if (p.hash_policy) out.push(t('device.lag.hash', { hash: p.hash_policy }));
  if (p.lacp_rate) out.push(t(p.lacp_rate === 'fast' ? 'device.lag.rateFast' : 'device.lag.rateSlow'));
  if (p.min_links) out.push(t('device.lag.minLinks', { n: p.min_links }));
  const upper = [...ix.ports.values()].find((q) => q.role === 'lag' && q.device_id === p.device_id && (q.lower || []).includes(p.id));
  if (upper || (p.lag && p.kind !== 'lag')) out.push(t('device.lag.member', { lag: upper ? upper.name : p.lag }));
  const st = p.lag_member_state;
  if (st) {
    if (st.collecting_distributing === false) out.push(t('device.lag.notAggregating'));
    else if (st.selected === false) out.push(t('device.lag.standby'));
    else if (st.collecting_distributing === true || st.selected === true) out.push(t('device.lag.aggregating'));
    if (st.partner_system_id) out.push(st.partner_port != null ? t('device.lag.partnerPort', { mac: st.partner_system_id, port: st.partner_port }) : t('device.lag.partner', { mac: st.partner_system_id }));
  }
  return out;
}

// Spanning tree (#155): protocols, port roles and states as the device reports them.
const STP_PROTOCOL = { stp: 'STP', rstp: 'RSTP', mstp: 'MSTP', 'loop-detect': 'device.stp.loopDetect', none: 'device.stp.off' };
const STP_ROLE = { root: 'device.stp.role.root', designated: 'device.stp.role.designated', alternate: 'device.stp.role.alternate', backup: 'device.stp.role.backup', disabled: 'device.stp.role.disabled' };
const STP_STATE = { forwarding: 'device.stp.state.forwarding', blocking: 'device.stp.state.blocking', discarding: 'device.stp.state.discarding', learning: 'device.stp.state.learning', listening: 'device.stp.state.listening', disabled: 'device.stp.state.disabled' };
const stpProtocol = (p) => (p.startsWith('device.') ? t(p) : p);

// The spanning tree facts of one bridge port, for its entry in the port tree.
function stpFacts(stp) {
  if (!stp) return [];
  return [
    stp.role ? t(STP_ROLE[stp.role]) : null,
    stp.state ? t(STP_STATE[stp.state]) : null,
    stp.edge ? t('device.stp.edge') : null,
    stp.bpdu_guard ? t('device.stp.bpduGuard') : null,
    stp.root_guard ? t('device.stp.rootGuard') : null,
    stp.loop_protect ? t('device.stp.loopProtect') : null,
    opt(stp.path_cost, (v) => t('device.stp.cost', { cost: v })),
  ].filter(Boolean);
}

// The device's bridges with their spanning tree (#155): protocol, priority, the root bridge.
function stpCard(ix, observed) {
  const bridges = observed.stp_bridges || [];
  if (!bridges.length) return null;
  const roots = new Set((ix.net.devices || []).flatMap((d) => (d.stp_bridges || []).map((b) => b.root_bridge_id).filter(Boolean)));
  const rows = bridges.map((b) => {
    const isRoot = b.bridge_id && (b.root_bridge_id === b.bridge_id || (!b.root_bridge_id && roots.has(b.bridge_id)));
    const root = b.root_bridge_id && b.root_bridge_id !== b.bridge_id ? b.root_bridge_id : null;
    const facts = [
      stpProtocol(STP_PROTOCOL[b.protocol] || b.protocol),
      opt(b.priority, (v) => t('device.stp.priority', { priority: v })),
      b.bridge_id ? h('span', { class: 'mono' }, b.bridge_id) : null,
      isRoot ? h('span', { class: 'tag', 'data-testid': 'stp-root' }, t('device.stp.isRoot')) : null,
      root ? t('device.stp.root', { root }) : null,
      b.root_port_id ? t('device.stp.rootPort', { port: ix.portName(b.root_port_id) }) : null,
      opt(b.root_path_cost, (v) => t('device.stp.cost', { cost: v })),
    ].filter(Boolean);
    const parts = [];
    facts.forEach((f, i) => parts.push(...(i ? [' · ', f] : [f])));
    return [b.name, h('span', { 'data-testid': 'stp-bridge', 'data-name': b.name }, ...parts)];
  });
  return h('section', { class: 'card', 'data-testid': 'device-stp' }, h('h2', {}, t('device.stp.title')), kv(rows));
}

// What a port's counters did between the last two reads (#158): the error and drop deltas, never
// the lifetime totals; nothing when the device reports no counters or has not been read twice.
function counterFact(d) {
  if (!d) return null;
  if (d.reset) return t('device.port.countersReset');
  const minutes = Math.max(1, Math.round(d.seconds / 60));
  const errors = d.errors === null || d.errors === undefined ? '–' : d.errors;
  const drops = d.drops === null || d.drops === undefined ? '–' : d.drops;
  return t('device.port.deltas', { errors, drops, minutes });
}

// PoE (#159): the budget of the switch with a bar, and the state and power of each port.
const POE_STATUS = { delivering: 'device.poe.status.delivering', searching: 'device.poe.status.searching', disabled: 'device.poe.status.disabled', fault: 'device.poe.status.fault', overload: 'device.poe.status.overload' };
const watts = (v) => fmtNumber(Math.round(v * 10) / 10);

function poeFacts(poe) {
  return [
    poe.status ? (POE_STATUS[poe.status] ? t(POE_STATUS[poe.status]) : poe.status) : poe.enabled === true ? t('device.poe.on') : poe.enabled === false ? t('device.poe.off') : null,
    opt(poe.power_w, (v) => t('device.poe.power', { power: watts(v) })),
    opt(poe.max_w, (v) => t('device.poe.max', { max: watts(v) })),
    opt(poe.power_class, (v) => t('device.poe.class', { class: v })),
    opt(poe.mode, (v) => t('device.poe.mode', { mode: v })),
    opt(poe.priority, (v) => t('device.poe.priority', { priority: v })),
  ].filter(Boolean);
}

function poeCard(ix, observed, deviceId) {
  const supply = observed && observed.poe;
  const ports = [...ix.ports.values()].filter((p) => p.device_id === deviceId && p.poe);
  if (!supply && !ports.length) return null;
  const rows = [];
  if (supply && given(supply.budget_w)) {
    const used = given(supply.used_w) ? supply.used_w : null;
    rows.push([
      t('device.poe.budget'),
      h('span', { 'data-testid': 'poe-budget' },
        used !== null ? t('device.poe.budgetUsed', { used: watts(used), budget: watts(supply.budget_w) }) : t('device.poe.budgetOnly', { budget: watts(supply.budget_w) }),
        used !== null ? [' ', h('progress', { max: String(supply.budget_w), value: String(Math.min(used, supply.budget_w)), 'data-testid': 'poe-bar' })] : null),
    ]);
    if (given(supply.reserved_w)) rows.push([t('device.poe.reservedLabel'), t('device.poe.reserved', { reserved: watts(supply.reserved_w) })]);
  }
  if (supply && supply.standard) rows.push([t('device.poe.standard'), supply.standard]);
  for (const p of ports) rows.push([p.name, h('span', { 'data-testid': 'poe-port', 'data-id': p.id }, poeFacts(p.poe).join(' · '))]);
  return h('section', { class: 'card', 'data-testid': 'device-poe' }, h('h2', {}, t('device.poe.title')), kv(rows));
}

// One entry of the port tree (#252): the port (or radio), what it is, and what runs on it.
function portNode(ix, node, deltas = {}, series = {}) {
  const name = (pid) => (ix.ports.get(pid) || {}).name || pid.split('/port/').pop();
  const ssids = node.wlans.map((w) => ix.wlans.get(w)).filter(Boolean);
  let label;
  let facts;
  if (node.node === 'radio') {
    const r = ix.radios.get(node.id) || { name: node.id.split('/').pop() };
    label = t('device.port.radio', { name: r.name });
    facts = [BAND[r.band], r.channel ? t('device.port.channel', { channel: r.channel }) : null, r.enabled === false ? t('device.off') : null];
  } else {
    const p = ix.ports.get(node.id) || { name: name(node.id) };
    label = p.description && p.description !== p.name ? `${p.name} (${p.description})` : p.name;
    facts = [
      p.role ? PORT_ROLE[p.role] || p.role : null,
      p.up === true ? t('device.state.up') : p.up === false ? t('device.state.down') : null,
      p.up !== false ? portSpeed(p) : null,
      ...portDetails(p),
      ...lagFacts(ix, p),
      ...stpFacts(p.stp),
      counterFact(deltas[node.id]),
      node.members.length ? t('device.port.over', { members: node.members.map(name).join(', ') }) : null,
    ];
  }
  return h(
    'li',
    { 'data-testid': 'port-node', 'data-id': node.id, 'data-role': node.node === 'radio' ? 'radio' : (ix.ports.get(node.id) || {}).role || '' },
    h('span', { class: 'name' }, label),
    ' ',
    h('span', { class: 'muted small' }, facts.filter(Boolean).join(' · ')),
    series[node.id] ? [' ', sparkline(series[node.id])] : null,
    ssids.length ? h('span', { class: 'ssids', 'data-testid': 'port-ssids' }, ssids.map((w) => h('span', { class: 'tag' }, t('device.port.ssid', { ssid: w.ssid })))) : null,
    node.children.length ? h('ul', {}, node.children.map((c) => portNode(ix, c, deltas, series))) : null,
  );
}

// The internal structure of the device's ports (#252); nothing when it has none.
function portsCard(ix, tree, deltas, series = {}) {
  if (!tree.length) return null;
  const known = tree.some(function roled(n) {
    return (ix.ports.get(n.id) || {}).role || n.node === 'radio' || n.children.some(roled);
  });
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-ports' },
    h('h2', {}, t('device.port.title')),
    known ? null : h('p', { class: 'muted' }, t('device.port.unknownRoles')),
    h('ul', { class: 'port-tree' }, tree.map((n) => portNode(ix, n, deltas, series))),
  );
}

// The access points the device's radios heard (#169), per radio and collapsed: a controller's
// rogue AP list or a scan the user turned on. Other people's networks: shown here only.
function neighboursCard(ix, rows) {
  if (!rows.length) return null;
  const radios = new Map(ix.net.radios.map((r) => [r.id, r]));
  const groups = new Map();
  for (const r of rows) {
    const key = r.radio_id || r.device_id;
    groups.set(key, [...(groups.get(key) || []), r]);
  }
  const label = (key) => {
    const radio = radios.get(key);
    if (radio) return `${radio.name} (${BAND[radio.band]})`;
    const dev = ix.net.devices.find((d) => d.id === key);
    return dev ? dev.name : key;
  };
  const name = (r) => {
    const text = r.ssid === null ? h('span', { class: 'muted' }, t('device.neighbours.hidden')) : r.ssid;
    const mark = r.own
      ? h('span', { class: 'muted small' }, ` · ${t('device.neighbours.own')}`)
      : r.own_ssid
        ? h('span', { class: 'bad small', 'data-testid': 'neighbour-twin' }, ` · ${t('device.neighbours.twin')}`)
        : null;
    return h('span', {}, text, mark);
  };
  const channel = (r) =>
    [r.channel ? t('device.port.channel', { channel: r.channel }) : null, opt(r.width_mhz, (w) => `${w} MHz`)].filter(Boolean).join(' · ');
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-neighbours' },
    h('h2', {}, t('device.neighbours.title')),
    h('p', { class: 'muted' }, t('device.neighbours.intro', { count: rows.length })),
    [...groups.keys()]
      .sort((a, b) => compare(label(a), label(b)))
      .map((key) =>
        h(
          'details',
          { class: 'fdb-port', 'data-testid': 'neighbour-radio', 'data-radio': key },
          h('summary', {}, t('device.neighbours.radio', { radio: label(key), count: groups.get(key).length })),
          table(
            [
              [t('device.neighbours.ssid'), name],
              [t('device.neighbours.bssid'), (r) => h('span', { class: 'mono' }, r.bssid)],
              [t('device.neighbours.channel'), channel],
              [t('device.neighbours.signal'), (r) => opt(r.signal_dbm, (v) => `${v} dBm`)],
              [t('device.neighbours.security'), (r) => r.security],
              [t('device.neighbours.seen'), (r) => opt(r.last_seen, fmtTime)],
            ],
            groups.get(key),
            { testid: 'neighbour-table', rowTestid: 'neighbour-row', compact: true },
          ),
        ),
      ),
  );
}

// The device's MAC address table (#160), per port and collapsed: a table can be long. A
// controller's page shows the tables of the switches it manages too.
function learnedCard(ix, entries) {
  if (!entries.length) return null;
  const byPort = new Map();
  for (const e of entries) byPort.set(e.port_id, [...(byPort.get(e.port_id) || []), e]);
  const ports = [...byPort.keys()].sort((a, b) => compare(ix.portName(a), ix.portName(b)));
  const clients = new Map(ix.net.clients.map((c) => [c.mac, c]));
  const who = (e) => {
    const c = clients.get(e.mac);
    const label = ix.net.annotations && (ix.net.annotations.find((a) => a.target === `client/${e.mac}`) || {}).label;
    return label || (c && c.hostname) || null;
  };
  return h(
    'section',
    { class: 'card', 'data-testid': 'device-fdb' },
    h('h2', {}, t('device.fdb.title')),
    h('p', { class: 'muted' }, t('device.fdb.intro', { count: entries.length })),
    ports.map((pid) => {
      const list = byPort.get(pid).sort((a, b) => (a.mac < b.mac ? -1 : 1));
      return h(
        'details',
        { class: 'fdb-port', 'data-testid': 'fdb-port', 'data-port': pid },
        h('summary', {}, t('device.fdb.port', { port: ix.portName(pid), count: list.length })),
        table(
          [
            [t('device.fdb.mac'), (e) => h('span', { class: 'mono' }, e.mac)],
            [t('device.fdb.client'), who],
            [t('device.fdb.entry'), (e) => fdbText(e, fmtDuration)],
          ],
          list,
          { testid: 'fdb-table', rowTestid: 'fdb-row', compact: true },
        ),
      );
    }),
  );
}

async function overview(main, ctx, device, adapters, sites) {
  const id = ctx.renderId;
  const [ix, tree, deltas, series, fdb, heard] = await Promise.all([
    loadNetwork(),
    get(`/devices/${enc(device.id)}/port-tree`),
    get(`/devices/${enc(device.id)}/port-counters`).catch(() => ({})),
    get(`/devices/${enc(device.id)}/port-series`).catch(() => ({})),
    get('/fdb').catch(() => []),
    get(`/wifi-scan?device=${enc(device.id)}`).catch(() => []),
  ]);
  if (!ctx.alive(id)) return;
  const learned = fdb.filter((e) => e.device_id === device.id || e.device_id.startsWith(`${device.id}/`));
  const observed = ix.net.devices.find((d) => d.id === device.id);
  const adapter = adapters.find((a) => a.id === device.adapter);
  // a service on another device (#387): where it runs, and what runs here
  const host = observed && observed.hosted_on ? ix.net.devices.find((d) => d.id === observed.hosted_on) : null;
  const guests = ix.net.devices.filter((d) => d.hosted_on === device.id).sort((a, b) => a.name.localeCompare(b.name));
  // a refused path trace (#253) is shown like a read problem, with its Fix it where there is one
  const traceErrors = (ix.net.traces || []).filter((tr) => tr.source === device.id && tr.error).map((tr) => ({ device_id: device.id, capability: t('device.traceTo', { target: tr.target }), message: tr.error, fix: tr.fix, remedy: tr.remedy, message_id: tr.message_id, fix_id: tr.fix_id, params: tr.params }));
  const errors = [...ix.net.errors.filter((e) => e.device_id === device.id), ...traceErrors];
  const result = h('div', {});
  const trustBox = h('div', {});
  const statusBox = h('span', {}, statusBadge(device.status));
  // The device's current read state in one place (#300): status, last read time and the
  // problems/gaps of that read. A connection test or a Fix it replaces all of it, so an old
  // problem never stays next to a newer, good result.
  const lastReadBox = h('span', { 'data-testid': 'last-read' }, observed && observed.observed_at ? h('span', { title: fmtTime(observed.observed_at) }, fmtAgo(observed.observed_at)) : t('device.overview.notYet'));
  const stateBox = h('div', { 'data-testid': 'device-read-state' });
  const showErrors = (list, note) => place(clear(stateBox), readErrors(list, 'device-errors', fixFor), note || null);
  const applyReading = (reading) => {
    if (!reading) return;
    const now = new Date().toISOString();
    place(clear(statusBox), statusBadge(reading.status));
    place(clear(lastReadBox), h('span', { title: fmtTime(now) }, fmtAgo(now)));
    showErrors(reading.errors, h('p', { class: 'muted small', 'data-testid': 'read-state-note' }, reading.errors.some((e) => !e.optional) ? t('device.state.fromRead', { time: fmtTime(now) }) : t('device.state.noProblems', { time: fmtTime(now) })));
  };

  const showTrust = (fingerprint, status) => {
    clear(trustBox);
    if (fingerprint && status === 'untrusted-certificate')
      place(
        trustBox,
        trustPanel(fingerprint, async (fp) => {
          await post(`/devices/${enc(device.id)}/trust`, { fingerprint: fp });
          toast(t('device.trusted'));
          await test();
        }),
      );
  };

  const testBtn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'test' }, t('device.test'));
  async function test() {
    place(clear(result), busy('testing', t('device.testing')));
    let res;
    try {
      res = await post(`/devices/${enc(device.id)}/test`);
    } catch (err) {
      clear(result); // the spinner ends; the error is the page's one notice
      throw err;
    }
    if (!ctx.alive(id)) return;
    place(clear(result), testResult(res, { errors: false }));
    applyReading(res);
    showTrust(res.pending_fingerprint, res.status);
  }
  testBtn.addEventListener('click', () => run(testBtn, test));

  const remove = h('button', { class: 'btn danger', type: 'button', 'data-testid': 'delete-device' }, t('device.remove'));
  remove.addEventListener('click', () =>
    run(remove, async () => {
      const ok = await confirmDialog({ title: t('device.removeTitle', { name: device.name }), message: t('device.removeMessage'), confirmLabel: t('common.remove'), danger: true });
      if (!ok) return;
      await del(`/devices/${enc(device.id)}`);
      toast(t('device.removed', { name: device.name }));
      ctx.navigate('#/devices');
    }),
  );

  // Fix it (#215): next to a read error the integration can repair; only on request
  const fixBox = h('div', { 'data-testid': 'fix-box' });
  const fixFor = (e) => {
    const remedy = remedyOf(adapter, e.remedy);
    if (!remedy) return null;
    if (!device.allow_writes && !remedy.read_side) return h('p', { class: 'muted small', 'data-testid': 'fix-needs-writes' }, t('device.fixNeedsWrites', { title: remedy.title }));
    const btn = h('button', { class: 'btn small', type: 'button', 'data-testid': 'fix-it', 'data-remedy': remedy.id }, t('device.fixIt'));
    btn.addEventListener('click', () => {
      place(clear(fixBox), fixPanel(device, adapter, remedy, applyReading));
      fixBox.scrollIntoView({ block: 'nearest' });
    });
    return h('p', {}, btn);
  };

  const fw = observed && observed.firmware;
  place(main, 
    card(
      null,
      kv([
        [t('device.overview.status'), statusBox],
        [t('device.overview.adapter'), adapter ? `${adapter.name} (${adapter.vendor})` : t('device.overview.notInstalled', { adapter: device.adapter })],
        [t('device.overview.role'), ROLE_TEXT[device.role] || device.role],
        [t('device.overview.site'), (sites.find((x) => x.id === device.site_id) || {}).name || device.site_id],
        [t('device.overview.vendor'), observed ? observed.vendor : null],
        [t('device.overview.model'), observed ? observed.model : null],
        [t('device.overview.firmware'), fw ? [fw.current || '–', fw.available ? ` (${t('device.overview.updateAvailable', { version: fw.available })})` : '', fw.end_of_life ? ` – ${t('device.overview.endOfLife')}` : ''].join('') : null],
        // Update and configuration state (#181): only what the device says (null is not shown)
        ...firmwareRows(fw),
        ...configRows(observed),
        [t('device.overview.managementAddress'), observed ? observed.management_address : null],
        // Identity (#177): shown where the device says it. The serial number is private data.
        ...[
          [t('device.overview.hostname'), observed && observed.hostname],
          [t('device.overview.serial'), observed && observed.serial],
          [t('device.overview.baseMac'), observed && observed.mac],
          [t('device.overview.hardwareRevision'), observed && observed.hardware_revision],
          [t('device.overview.board'), observed && observed.board],
          [t('device.overview.architecture'), observed && observed.architecture],
          [t('device.overview.bootloader'), observed && observed.bootloader],
          [t('device.overview.bootloaderAvailable'), observed && observed.bootloader_available && observed.bootloader_available !== observed.bootloader ? observed.bootloader_available : null],
          [t('device.overview.location'), observed && observed.location],
          [t('device.overview.contact'), observed && observed.contact],
          [t('device.overview.os'), observed && [observed.os, observed.os_version].filter(Boolean).join(' ')],
        ].filter(([, v]) => v),
        [t('device.overview.runsOn'), host ? h('a', { href: `#/device/${enc(host.id)}`, 'data-testid': 'runs-on' }, host.name) : undefined],
        [t('device.overview.alsoRunsHere'), guests.length ? h('span', { 'data-testid': 'also-runs-here' }, guests.map((g, i) => [i ? ', ' : '', h('a', { href: `#/device/${enc(g.id)}`, 'data-testid': 'hosted-link' }, g.name)])) : undefined],
        [t('device.overview.lastRead'), lastReadBox],
        [t('device.overview.enabled'), yesNo(device.enabled)],
        [t('device.overview.changesAllowed'), yesNo(device.allow_writes)],
      ]),
      stateBox,
      fixBox,
    ),
    notesCard(ix, device.id, 'device', t('device.notes', { name: device.name }), () => ctx.refresh()),
    internetCard(ix, device.id),
    multiwanCard(ix, device.id),
    dnsCard(ix, device.id),
    ddnsCard(ix, device.id),
    inferredCard(ix, device.id),
    portsCard(ix, tree, deltas, series),
    observed ? stpCard(ix, observed) : null,
    poeCard(ix, observed, device.id),
    radiosCard(ix, device.id),
    lldpCard(ix, device.id),
    neighboursCard(ix, heard),
    learnedCard(ix, learned),
    tunnelsCard(ix, device.id),
    firewallCard(ix, device.id),
    routesCard(ix, device.id),
    observed ? managementCard(ix, observed) : null,
    observed ? loggingCard(observed) : null,
    observed ? certificateCard(observed) : null,
    observed ? accountsCard(observed) : null,
    storedCertificatesCard(ix, device.id),
    observed ? healthCard(observed.health) : null,
    observed ? timeCard(observed.time) : null,
    trustBox,
    card(t('device.connection.title'), h('p', { class: 'muted' }, t('device.connection.text')), h('div', { class: 'row' }, testBtn), result),
    h('div', { class: 'row end' }, remove),
  );
  showTrust(device.pending_fingerprint, device.status);
  showErrors(errors);
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
    certificates: (net.certificates || []).filter(mine),
    dhcp_servers: net.dhcp_servers.filter(mine),
    dns_services: net.dns_services.filter(mine),
    radios: net.radios.filter(mine),
    wlans: net.wlans.filter(mine),
    clients: net.clients.filter(mine),
    neighbours: net.neighbours.filter((n) => (n.source && n.source.device_id === deviceId) || n.local_port_id.startsWith(`${deviceId}/`)),
    tunnels: (net.tunnels || []).filter(mine),
    firewalls: (net.firewalls || []).filter(mine),
  };
}

async function advanced(main, ctx, device) {
  const id = ctx.renderId;
  const net = await get('/network');
  if (!ctx.alive(id)) return;
  const raw = rawObjects(net, device.id);
  const total = Object.values(raw).reduce((n, list) => n + list.length, 0);
  place(main, h('p', { class: 'muted' }, t('device.adv.intro')));
  if (!total) {
    place(main, empty('empty', t('device.adv.empty'), h('p', { class: 'muted' }, t('device.adv.emptyHint'))));
    return;
  }
  if (raw.ports.length) {
    place(main, 
      card(
        t('device.adv.ports', { count: raw.ports.length }),
        table(
          [
            [t('device.adv.port'), (p) => p.name],
            [t('device.adv.description'), (p) => p.description],
            [t('device.adv.kind'), (p) => p.kind],
            [t('device.adv.role'), (p) => (p.role ? PORT_ROLE[p.role] || p.role : null)],
            [t('device.adv.up'), (p) => yesNo(p.up)],
            [t('device.adv.speed'), (p) => portSpeed(p)],
            [t('device.adv.settings'), (p) => portDetails(p).join(' · ') || null],
            [t('device.adv.mac'), (p) => (p.mac ? h('span', { class: 'mono' }, p.mac) : null)],
            [t('device.adv.vendorFields'), (p) => (Object.keys(p.vendor_extra || {}).length ? h('code', { class: 'extra' }, JSON.stringify(p.vendor_extra)) : null)],
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
        h('summary', {}, t('device.adv.raw', { kind: kind.replace('_', ' '), count: list.length })),
        h('pre', { class: 'json' }, JSON.stringify(list, null, 2)),
      ),
    );
  }
}


// Rows of the firmware state beyond the version (#181); a field the device does not say is left out.
function firmwareRows(fw) {
  if (!fw) return [];
  const known = (v) => v !== null && v !== undefined;
  return [
    [t('device.overview.channel'), fw.channel],
    [t('device.overview.autoUpdate'), known(fw.auto_update) ? yesNo(fw.auto_update) : null],
    [t('device.overview.lastChecked'), fw.last_checked ? fmtTime(fw.last_checked) : null],
    [t('device.overview.lastUpdated'), fw.last_updated ? fmtTime(fw.last_updated) : null],
    [t('device.overview.pendingUpdates'), known(fw.pending_updates) ? t('device.overview.pendingUpdatesValue', { count: fw.pending_updates, security: known(fw.pending_security_updates) ? fw.pending_security_updates : '?' }) : null],
    [t('device.overview.rebootPending'), known(fw.reboot_pending) ? yesNo(fw.reboot_pending) : null],
  ].filter(([, v]) => v);
}

// Configuration state and the backups the device keeps (#181). The user the device logged for the
// last change is a name from the device: it goes into a text node only (kv() never parses markup).
function configRows(observed) {
  if (!observed) return [];
  const cs = observed.config_state;
  const lb = observed.local_backups;
  const known = (v) => v !== null && v !== undefined;
  const rows = [];
  if (cs) {
    if (known(cs.unsaved)) rows.push([t('device.overview.configSaved'), yesNo(!cs.unsaved)]);
    if (known(cs.pending)) rows.push([t('device.overview.configStaged'), yesNo(cs.pending)]);
    if (cs.last_changed) {
      rows.push([t('device.overview.configChanged'), cs.changed_by ? t('device.overview.configChangedBy', { when: fmtTime(cs.last_changed), user: cs.changed_by }) : fmtTime(cs.last_changed)]);
    }
  }
  if (lb && known(lb.count)) {
    rows.push([t('device.overview.backups'), lb.newest ? t('device.overview.backupsNewest', { count: lb.count, when: fmtTime(lb.newest) }) : String(lb.count)]);
  }
  return rows;
}

export async function renderDevice(main, ctx, route) {
  const id = ctx.renderId;
  const [device, adapters, sites] = await Promise.all([get(`/devices/${enc(route.id)}`).catch(() => null), get('/adapters'), get('/sites')]);
  if (!ctx.alive(id)) return;
  place(main, h('p', { class: 'back' }, h('a', { href: '#/devices' }, t('device.back'))));
  if (!device) {
    place(main, empty('not-found', t('device.notFound'), h('p', {}, h('a', { href: '#/devices' }, t('device.backToDevices')))));
    return;
  }
  const base = `#/device/${enc(device.id)}`;
  place(main, 
    pageHead(device.name, manageLink(device, t('device.openWeb'), 'manage-link', 'btn')),
    tabs(
      [
        ['overview', t('device.tab.overview'), base],
        ['settings', t('device.tab.settings'), `${base}/settings`],
        ['advanced', t('device.tab.advanced'), `${base}/advanced`],
      ],
      route.tab,
    ),
  );
  main.querySelector('h1').setAttribute('data-testid', 'device-title');
  if (route.tab === 'settings') await renderDeviceForm(main, ctx, device);
  else if (route.tab === 'advanced') await advanced(main, ctx, device);
  else await overview(main, ctx, device, adapters, sites);
}
