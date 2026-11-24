// Topology: devices with their ports, links between ports, VLAN overlay, entered cables,
// VPN tunnels between sites and unmanaged sites behind a tunnel (#239), routed paths (#253).
import { del, enc, get, post } from '../api.js';
import { PORT_ROLE, by, clear, h, place, portDetails, portSpeed, s } from '../util.js';
import { card, confirmDialog, field, pageHead, run, select, statusBadge, table, tag, toast } from '../ui.js';
import { routedPathsCard } from './traces.js';
import { t } from '../i18n.js';

const LAYER = { gateway: 0, remote: 0, switch: 1, ap: 2, other: 3 };
const ORIGIN = { lldp: 'topology.origin.lldp', mac: 'topology.origin.mac', manual: 'topology.origin.manual', tunnel: 'topology.origin.tunnel' };
const ROLE = { gateway: 'topology.role.gateway', remote: 'topology.role.remote', switch: 'topology.role.switch', ap: 'topology.role.ap', other: 'topology.role.other' };
const MODE = { tagged: 'topology.mode.tagged', untagged: 'topology.mode.untagged' };
const KIND = { cable: 'topology.linkKind.cable', wireless: 'topology.linkKind.wireless', vpn: 'topology.linkKind.vpn' };
const originLabel = (o) => (ORIGIN[o] ? t(ORIGIN[o]) : o);
const modeLabel = (m) => (MODE[m] ? t(MODE[m]) : m);

const PORT = 18;
const PORT_GAP = 5;
const MAX_PORTS = 24;
const ROW = 150;
const TOP = 30; // room for VPN arcs above the first row
const BOX_H = 74;
const GAP = 36;
const state = { segment: '', site: '', internal: false };

// Jacks and ports of unknown role; internal ports (CPU port, bridges, VLAN and Wi-Fi interfaces,
// #252) only on request. A link to a hidden port ends at the device box.
function shownPorts(node) {
  return state.internal ? node.ports : node.ports.filter((p) => p.external !== false);
}

function visiblePorts(node, linked) {
  const ports = shownPorts(node);
  if (ports.length <= MAX_PORTS) return ports;
  return ports.filter((p) => linked.has(p.id)).slice(0, MAX_PORTS);
}

function layout(nodes, linked) {
  const rows = [[], [], [], []];
  for (const n of [...nodes].sort(by((x) => x.name))) rows[LAYER[n.role] ?? 3].push(n);
  const boxes = new Map();
  const used = rows.filter((r) => r.length);
  let width = 0;
  used.forEach((row, i) => {
    let x = GAP / 2;
    for (const n of row) {
      const ports = visiblePorts(n, linked);
      const w = Math.max(150, ports.length * (PORT + PORT_GAP) + 20);
      boxes.set(n.id, { node: n, x, y: TOP + i * ROW, w, ports });
      x += w + GAP;
    }
    width = Math.max(width, x);
  });
  // centre each row
  used.forEach((row) => {
    const last = boxes.get(row[row.length - 1].id);
    const shift = (width - (last.x + last.w + GAP / 2)) / 2;
    for (const n of row) boxes.get(n.id).x += shift;
  });
  return { boxes, width: Math.max(width, 320), height: used.length * ROW + TOP - 10 };
}

function portCenter(boxes, end) {
  const b = boxes.get(end.device_id);
  if (!b) return null;
  const i = b.ports.findIndex((p) => p.id === end.port_id);
  if (i < 0) return { x: b.x + b.w / 2, y: b.y + BOX_H, top: b.y };
  return { x: b.x + 10 + i * (PORT + PORT_GAP) + PORT / 2, y: b.y + BOX_H - 14 - PORT / 2, top: b.y };
}

function edgeSegment(edge, seg) {
  return edge.segments.find((x) => x.segment_id === seg);
}

function drawGraph(data, nodes, onPort) {
  const linked = new Set(data.edges.flatMap((e) => [e.a.port_id, e.b.port_id]));
  const { boxes, width, height } = layout(nodes, linked);
  const svg = s('svg', { viewBox: `0 0 ${width} ${height}`, width: String(width), height: String(height), class: 'topo', role: 'img', 'aria-label': t('topology.graphLabel'), 'data-testid': 'topology-graph' });
  const edgeLayer = s('g', { class: 'edges' });
  const nodeLayer = s('g', { class: 'nodes' });
  const markLayer = s('g', { class: 'marks' });
  place(svg, edgeLayer, nodeLayer, markLayer);
  for (const e of data.edges) {
    if (e.kind === 'vpn') {
      // a tunnel joins two boxes, not ports: an arc above them, dashed
      const ba = boxes.get(e.a.device_id);
      const bb = boxes.get(e.b.device_id);
      if (!ba || !bb) continue;
      const ax = ba.x + ba.w / 2;
      const bx = bb.x + bb.w / 2;
      const top = Math.max(2, Math.min(ba.y, bb.y) - TOP + 4);
      const path = s('path', { d: `M${ax},${ba.y} C${ax},${top} ${bx},${top} ${bx},${bb.y}`, class: `edge vpn ${state.segment ? 'dim' : ''}`.trim(), 'data-testid': 'topo-edge', 'data-id': e.id, 'data-kind': 'vpn', 'data-state': state.segment ? 'dim' : 'none' });
      place(path, s('title', {}, t('topology.vpnTitle', { a: e.a.port, b: e.b.port }) + (vpnText(e) ? t('topology.vpnDetail', { text: vpnText(e) }) : '')));
      place(edgeLayer, path);
      continue;
    }
    const a = portCenter(boxes, e.a);
    const b = portCenter(boxes, e.b);
    if (!a || !b) continue;
    // a line leaves the upper device at its port and enters the lower one from the top,
    // above the port; devices in the same row are joined by a curve below them
    let from = { x: a.x, y: a.y };
    let to = { x: b.x, y: b.y };
    let c1;
    let c2;
    if (a.top === b.top) {
      const below = a.top + BOX_H + 40;
      c1 = `${from.x},${below}`;
      c2 = `${to.x},${below}`;
    } else {
      if (a.top < b.top) to = { x: b.x, y: b.top };
      else from = { x: a.x, y: a.top };
      const mid = (from.y + to.y) / 2;
      c1 = `${from.x},${mid}`;
      c2 = `${to.x},${mid}`;
    }
    const seg = state.segment ? edgeSegment(e, state.segment) : null;
    const cls = ['edge', e.kind, e.origin];
    if (state.segment) cls.push(seg ? (seg.consistent ? 'carry' : 'inconsistent') : 'dim');
    const path = s('path', { d: `M${from.x},${from.y} C${c1} ${c2} ${to.x},${to.y}`, class: cls.join(' '), 'data-testid': 'topo-edge', 'data-id': e.id, 'data-state': state.segment ? (seg ? (seg.consistent ? 'carry' : 'inconsistent') : 'dim') : 'none' });
    place(path, s('title', {}, t('topology.edgeTitle', { a: e.a.port, b: e.b.port, origin: originLabel(e.origin) })));
    place(edgeLayer, path);
    if (seg && !seg.consistent) {
      // the end that lacks the VLAN; both ends when they disagree on tagged / untagged
      const oneMissing = !seg.a !== !seg.b;
      for (const [end, pos, mode] of [[e.a, a, seg.a], [e.b, b, seg.b]]) {
        if (oneMissing && mode) continue;
        const mark = s('circle', { cx: String(pos.x), cy: String(pos.y), r: '13', class: 'bad-end', 'data-testid': 'bad-end' });
        place(mark, s('title', {}, t('topology.endTitle', { port: end.port, mode: mode ? modeLabel(mode) : t('topology.notMember') })));
        place(markLayer, mark);
      }
    }
  }
  for (const { node, x, y, w, ports } of boxes.values()) {
    const g = s('g', { class: `node role-${node.role} status-${node.status}`, 'data-testid': 'topo-node', 'data-id': node.id });
    place(g, s('rect', { x: String(x), y: String(y), width: String(w), height: String(BOX_H), rx: '10', class: 'box' }));
    place(g, s('text', { x: String(x + 10), y: String(y + 20), class: 'name' }, node.name));
    const roleName = ROLE[node.role] ? t(ROLE[node.role]) : node.role;
    const roleText = node.role === 'remote' ? t('topology.remoteSite', { networks: node.networks.join(', ') || t('topology.noNetworks') }) : `${roleName}${shownPorts(node).length > ports.length ? t('topology.morePorts', { count: shownPorts(node).length - ports.length }) : ''}`;
    place(g, s('text', { x: String(x + 10), y: String(y + 36), class: 'role' }, roleText));
    ports.forEach((p, i) => {
      const px = x + 10 + i * (PORT + PORT_GAP);
      const py = y + BOX_H - 14 - PORT;
      const member = state.segment && (p.untagged.includes(state.segment) ? 'untagged' : p.tagged.includes(state.segment) ? 'tagged' : null);
      const clients = (data.clients[p.id] || []).length;
      const cls = ['port', p.up === false ? 'down' : 'up', linked.has(p.id) ? 'linked' : '', member ? `m-${member}` : '', clients ? 'has-clients' : '', p.external === false ? 'internal' : ''];
      const rect = s('rect', { x: String(px), y: String(py), width: String(PORT), height: String(PORT), rx: '3', class: cls.join(' ').trim(), tabindex: '0', role: 'button', 'aria-label': `${t('topology.portAria', { device: node.name, port: p.name })}${p.description ? t('topology.paren', { description: p.description }) : ''}${clients ? t('topology.portClientsAria', { count: clients }) : ''}`, 'data-testid': 'topo-port', 'data-id': p.id });
      place(rect, s('title', {}, `${p.name}${p.description ? t('topology.paren', { description: p.description }) : ''}${p.role && p.role !== 'jack' ? `, ${PORT_ROLE[p.role] || p.role}` : ''}${member ? t('topology.paren', { description: modeLabel(member) }) : ''}${clients ? t('topology.portClientsTitle', { count: clients }) : ''}`));
      rect.addEventListener('click', () => onPort(node, p));
      rect.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          onPort(node, p);
        }
      });
      place(g, rect);
    });
    place(nodeLayer, g);
  }
  return svg;
}

// Speed, PVID, MTU, admin state, profile: a line only when the device reports any of them.
function portFacts(port, segments) {
  const parts = [portSpeed(port), ...portDetails(port)];
  // PVID and untagged membership disagree (ProSAFE, Easy Smart allow it): say where frames go.
  if (port.pvid_segment && port.untagged.length && !port.untagged.includes(port.pvid_segment)) {
    parts.push(t('topology.untaggedFramesIn', { segment: segments[port.pvid_segment] || port.pvid_segment }));
  }
  const text = parts.filter(Boolean).join(' · ');
  return text ? h('p', { class: 'muted', 'data-testid': 'port-facts' }, text) : null;
}

function portPanel(data, segments, node, port) {
  const clients = data.clients[port.id] || [];
  return h(
    'div',
    { class: 'card port-panel', 'data-testid': 'port-panel' },
    h('h3', {}, t('topology.portHeading', { device: node.name, port: port.name })),
    port.description ? h('p', { 'data-testid': 'port-description' }, port.description) : null,
    port.role ? h('p', { class: 'muted', 'data-testid': 'port-role' }, PORT_ROLE[port.role] || port.role) : null,
    h('p', { class: 'muted' }, [port.untagged.length ? t('topology.untaggedList', { list: port.untagged.map((x) => segments[x] || x).join(', ') }) : null, port.tagged.length ? t('topology.taggedList', { list: port.tagged.map((x) => segments[x] || x).join(', ') }) : null].filter(Boolean).join(' · ') || t('topology.noMembership')),
    portFacts(port, segments),
    clients.length
      ? table(
          [
            [t('topology.col.name'), (c) => c.hostname],
            [t('topology.col.mac'), (c) => h('span', { class: 'mono' }, c.mac)],
            [t('topology.col.segment'), (c) => (c.segment_id ? segments[c.segment_id] || c.segment_id : null)],
          ],
          clients,
          { rowTestid: 'port-client', compact: true },
        )
      : h('p', { class: 'muted', 'data-testid': 'no-port-clients' }, t('topology.noPortClients')),
  );
}

// What a VPN link carries: the networks each end routes into the tunnel, the handshake.
function vpnText(e) {
  const v = e.vpn || {};
  const nets = [...((v.a && v.a.networks) || []), ...((v.b && v.b.networks) || [])];
  const ages = [v.a, v.b].filter((x) => x && x.handshake_age !== null && x.handshake_age !== undefined).map((x) => x.handshake_age);
  const shake = ages.length ? t('topology.handshake', { seconds: Math.round(Math.min(...ages)) }) : [v.a, v.b].some(Boolean) ? t('topology.noHandshake') : '';
  return [nets.join(', '), shake].filter(Boolean).join(' · ');
}

function linkList(ctx, data, nodes) {
  const names = new Map(nodes.map((n) => [n.id, n.name]));
  const endText = (end) => `${names.get(end.device_id) || end.device_id} · ${end.port}`;
  const edges = [...data.edges].sort(by((e) => `${endText(e.a)} ${endText(e.b)}`));
  if (!edges.length) return h('p', { class: 'muted', 'data-testid': 'no-links' }, t('topology.noLinks'));
  return table(
    [
      [t('topology.col.from'), (e) => endText(e.a)],
      [t('topology.col.to'), (e) => endText(e.b)],
      [t('topology.col.kind'), (e) => (KIND[e.kind] ? t(KIND[e.kind]) : e.kind)],
      [t('topology.col.foundBy'), (e) => tag(originLabel(e.origin), `origin-${e.origin}`)],
      [
        t('topology.col.vlans'),
        (e) =>
          e.kind === 'vpn'
            ? h('span', { 'data-testid': 'vpn-detail' }, vpnText(e) || null)
            : e.segments.length
            ? e.segments.map((x, i) => [i ? ', ' : '', h('span', { class: x.consistent ? '' : 'error', title: x.consistent ? t('topology.bothEnds', { mode: modeLabel(x.a) }) : t('topology.endsDiffer', { a: x.a ? modeLabel(x.a) : t('topology.notMember'), b: x.b ? modeLabel(x.b) : t('topology.notMember') }) }, `${x.name}${x.consistent ? '' : ' (!)'}`)])
            : null,
      ],
      [
        '',
        (e) => {
          if (e.origin !== 'manual') return null;
          const btn = h('button', { class: 'btn small', type: 'button', 'data-testid': 'link-delete', 'aria-label': t('topology.deleteLinkAria', { a: endText(e.a), b: endText(e.b) }) }, t('common.delete'));
          btn.addEventListener('click', () =>
            run(btn, async () => {
              if (!(await confirmDialog({ title: t('topology.deleteCable.title'), message: t('topology.deleteCable.message', { a: endText(e.a), b: endText(e.b) }), confirmLabel: t('common.delete'), danger: true }))) return;
              await del(`/links/${enc(e.id)}`);
              toast(t('topology.linkDeleted'));
              ctx.refresh();
            }),
          );
          return btn;
        },
        'actions',
      ],
    ],
    edges,
    { testid: 'links', rowTestid: 'link-row', rowAttrs: (e) => ({ 'data-origin': e.origin }) },
  );
}

function addLinkForm(ctx, nodes) {
  const sorted = [...nodes].sort(by((n) => n.name));
  const pick = (side) => {
    const dev = select([['', t('topology.chooseDevice')], ...sorted.map((n) => [n.id, n.name])], '', { 'data-testid': `link-${side}-device` });
    const port = h('select', { 'data-testid': `link-${side}-port`, disabled: true });
    dev.addEventListener('change', () => {
      clear(port);
      const node = nodes.find((n) => n.id === dev.value);
      port.disabled = !node;
      if (node) for (const p of [...node.ports].sort(by((x) => x.name))) place(port, h('option', { value: p.id }, p.name));
    });
    return { dev, port };
  };
  const a = pick('a');
  const b = pick('b');
  const kind = select([['cable', t('topology.kind.cable')], ['wireless', t('topology.kind.wireless')]], 'cable', { 'data-testid': 'link-kind' });
  const msg = h('p', { class: 'error', role: 'alert', 'data-testid': 'link-error' });
  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'link-add' }, t('topology.addCable'));
  const form = h('form', {
    class: 'link-form',
    onsubmit: (e) => {
      e.preventDefault();
      msg.textContent = '';
      if (!a.port.value || !b.port.value) {
        msg.textContent = t('topology.err.chooseBoth');
        return;
      }
      if (a.port.value === b.port.value) {
        msg.textContent = t('topology.err.samePort');
        return;
      }
      run(save, async () => {
        await post('/links', { a: a.port.value, b: b.port.value, kind: kind.value });
        toast(t('topology.cableAdded'));
        ctx.refresh();
      });
    },
  });
  place(form, 
    h('div', { class: 'link-ends' }, h('fieldset', {}, h('legend', {}, t('topology.oneEnd')), field(t('topology.device'), a.dev), field(t('topology.port'), a.port)), h('fieldset', {}, h('legend', {}, t('topology.otherEnd')), field(t('topology.device'), b.dev), field(t('topology.port'), b.port))),
    field(t('topology.col.kind'), kind),
    msg,
    save,
  );
  return card(t('topology.enterCable'), h('p', { class: 'muted' }, t('topology.enterCableNote')), form);
}

export async function renderTopology(main, ctx) {
  const id = ctx.renderId;
  const [data, sites] = await Promise.all([get('/topology'), get('/sites')]);
  if (!ctx.alive(id)) return;
  place(main, pageHead(t('topology.title')));
  if (!data.nodes.length) {
    place(main, h('div', { class: 'card empty', 'data-testid': 'empty' }, h('h2', {}, t('topology.empty.title')), h('p', { class: 'muted' }, t('topology.empty.text')), h('p', {}, h('a', { class: 'btn', href: '#/devices' }, t('topology.empty.devices')))));
    return;
  }
  if (state.site && !sites.some((x) => x.id === state.site)) state.site = '';
  // unmanaged sites behind a tunnel are boxes of their own, next to the gateways
  for (const r of data.remotes || []) data.nodes.push({ ...r, role: 'remote', status: 'ok', ports: [] });
  const graphBox = h('div', { class: 'topo-wrap' });
  const panel = h('div', {});
  const legend = h('p', { class: 'legend muted small', 'data-testid': 'topo-legend' });
  const nodesOf = () => data.nodes.filter((n) => !state.site || n.site_id === state.site);
  const draw = () => {
    const nodes = nodesOf();
    const ids = new Set(nodes.map((n) => n.id));
    const view = { ...data, edges: data.edges.filter((e) => ids.has(e.a.device_id) || ids.has(e.b.device_id)) };
    place(clear(graphBox), drawGraph(view, nodes, (node, port) => place(clear(panel), portPanel(data, data.segments, node, port))));
    place(clear(legend), 
      state.segment
        ? [h('span', { class: 'key carry' }), t('topology.legend.carries'), h('span', { class: 'key inconsistent' }), t('topology.legend.disagree'), h('span', { class: 'key dim' }), t('topology.legend.dim')]
        : [t('topology.legend.hint'), data.edges.some((e) => e.kind === 'vpn') ? t('topology.legend.vpn') : ''],
    );
  };
  const segSelect = select([['', t('topology.noOverlay')], ...Object.entries(data.segments).sort(by(([, n]) => n)).map(([sid, n]) => [sid, `${n}${sites.length > 1 ? ` – ${(sites.find((x) => sid.startsWith(`${x.id}/`)) || {}).name || ''}` : ''}`])], state.segment, { 'aria-label': t('topology.highlightVlan'), 'data-testid': 'topo-segment' });
  segSelect.addEventListener('change', () => {
    state.segment = segSelect.value;
    draw();
  });
  let siteSelect = null;
  if (sites.length > 1) {
    siteSelect = select([['', t('topology.allSites')], ...sites.map((x) => [x.id, x.name])], state.site, { 'aria-label': t('topology.site'), 'data-testid': 'filter-site' });
    siteSelect.addEventListener('change', () => {
      state.site = siteSelect.value;
      draw();
    });
  }
  const internalBox = h('input', { type: 'checkbox', 'data-testid': 'topo-internal' });
  internalBox.checked = state.internal;
  internalBox.addEventListener('change', () => {
    state.internal = internalBox.checked;
    draw();
  });
  const hasInternal = data.nodes.some((n) => n.ports.some((p) => p.external === false));
  const problems = data.nodes.filter((n) => n.status !== 'ok');
  place(main, 
    h('div', { class: 'filters' }, siteSelect, segSelect, hasInternal ? h('label', { class: 'check', title: t('topology.internalTitle') }, internalBox, t('topology.showInternal')) : null),
    problems.length ? h('p', { class: 'notice small' }, t('topology.notRead'), problems.map((n, i) => [i ? ', ' : '', n.name, ' ', statusBadge(n.status)])) : null,
    h('div', { class: 'card topo-card' }, legend, graphBox, h('p', { class: 'phone-only muted small' }, t('topology.phoneNote'))),
    panel,
    card(t('topology.links'), linkList(ctx, data, data.nodes)),
    routedPathsCard(ctx, data.nodes),
    addLinkForm(ctx, data.nodes.filter((n) => n.role !== 'remote')),
  );
  draw();
}
