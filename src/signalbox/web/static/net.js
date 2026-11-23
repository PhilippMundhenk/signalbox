// The merged network from /api/network with lookups and human names for object ids.
import { get } from './api.js';
import { h, place } from './util.js';

export async function loadNetwork() {
  const [net, devices, sites] = await Promise.all([get('/network'), get('/devices'), get('/sites')]);
  return indexNetwork(net, devices, sites);
}

export function indexNetwork(net, devices = [], sites = []) {
  const ix = {
    net,
    sites: sites.length ? sites : net.sites,
    deviceList: devices,
    devices: new Map(),
    ports: new Map(net.ports.map((p) => [p.id, p])),
    segments: new Map(net.segments.map((x) => [x.id, x])),
    radios: new Map(net.radios.map((r) => [r.id, r])),
    wlans: new Map(net.wlans.map((w) => [w.id, w])),
    links: new Map(net.links.map((l) => [l.id, l])),
  };
  for (const d of devices) ix.devices.set(d.id, { id: d.id, name: d.name, site_id: d.site_id, role: d.role, adapter: d.adapter });
  for (const d of net.devices) ix.devices.set(d.id, { ...ix.devices.get(d.id), ...d });
  ix.siteName = (id) => (ix.sites.find((x) => x.id === id) || {}).name || id;
  ix.deviceName = (id) => (ix.devices.get(id) || {}).name || id;
  ix.segmentName = (id) => segmentLabel(ix.segments.get(id), id);
  ix.portName = (id) => {
    const p = ix.ports.get(id);
    if (p) return `${ix.deviceName(p.device_id)} · ${p.name}`;
    const m = /^(.+?)\/port\/(.+)$/.exec(id || '');
    return m ? `${ix.deviceName(m[1])} · ${m[2]}` : id;
  };
  ix.label = (id) => objectLabel(ix, id);
  // Where a client is (#160): "port 5 of Switch" for a port, the usual label otherwise.
  ix.placeName = (id) => {
    const p = ix.ports.get(id);
    return p ? `port ${p.name} of ${ix.deviceName(p.device_id)}` : objectLabel(ix, id);
  };
  ix.siteOf = (id) => siteOf(ix, id);
  return ix;
}

export function segmentLabel(seg, id) {
  if (!seg) {
    const m = /\/segment\/(.+)$/.exec(id || '');
    if (!m) return id || '–';
    return /^native(-|$)/.test(m[1]) ? 'Untagged network' : `VLAN ${m[1]}`;
  }
  const base = seg.vlan ? `VLAN ${seg.vlan}` : 'Untagged network';
  return seg.name ? `${base} (${seg.name})` : base;
}

function objectLabel(ix, id) {
  if (!id) return '–';
  if (ix.devices.has(id)) return ix.deviceName(id);
  if (ix.ports.has(id) || /\/port\//.test(id)) return ix.portName(id);
  if (/\/segment\//.test(id)) return `${ix.siteName(id.split('/')[0])}: ${ix.segmentName(id)}`;
  const wlan = ix.wlans.get(id);
  if (wlan) return `${ix.deviceName(wlan.device_id)} · SSID ${wlan.ssid}`;
  const radio = ix.radios.get(id);
  if (radio) return `${ix.deviceName(radio.device_id)} · radio ${radio.name}`;
  const link = ix.links.get(id);
  if (link) return `Link ${ix.portName(link.a)} ↔ ${ix.portName(link.b)}`;
  const first = id.split('/')[0];
  if (ix.devices.has(first)) return `${ix.deviceName(first)} · ${id.slice(first.length + 1).replace('/', ' ')}`;
  return id;
}

function siteOf(ix, id) {
  if (!id) return null;
  const first = id.split('/')[0];
  const dev = ix.devices.get(first);
  if (dev) return dev.site_id;
  if (ix.sites.some((x) => x.id === first)) return first;
  const link = ix.links.get(id);
  if (link) return siteOf(ix, link.a);
  return null;
}

// A link to a device's page for device ids, plain text for everything else.
export function objectRef(ix, id) {
  const first = (id || '').split('/')[0];
  const label = ix.label(id);
  if (ix.devices.has(first)) return h('a', { href: `#/device/${encodeURIComponent(first)}`, 'data-testid': 'object-ref' }, label);
  return h('span', { 'data-testid': 'object-ref' }, label);
}

export function siteFilter(ix, value, onchange) {
  if (ix.sites.length < 2) return null;
  const sel = h('select', { 'aria-label': 'Site', 'data-testid': 'filter-site', onchange: () => onchange(sel.value) });
  place(sel, h('option', { value: '' }, 'All sites'));
  for (const site of ix.sites) place(sel, h('option', { value: site.id, selected: site.id === value }, site.name));
  return sel;
}

export function noData(what) {
  return h(
    'div',
    { class: 'card empty', 'data-testid': 'empty' },
    h('h2', {}, `No ${what} known yet`),
    h('p', { class: 'muted' }, `Signalbox shows ${what} once a device that reports them has been read.`),
    h('p', {}, h('a', { href: '#/devices', class: 'btn' }, 'Devices')),
  );
}

// A MAC address table entry (#160) in words: "dynamic, VLAN 20, 30 s old".
export function fdbText(e, fmtDuration) {
  const kind = { dynamic: 'learned', static: 'static', self: 'own address' }[e.kind] || e.kind;
  return [kind, e.vlan ? `VLAN ${e.vlan}` : null, e.age_seconds !== null && e.age_seconds !== undefined ? `${fmtDuration(e.age_seconds)} old` : null].filter(Boolean).join(', ');
}
