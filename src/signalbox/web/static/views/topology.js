// Topology: devices with their ports, links between ports, VLAN overlay, entered cables,
// VPN tunnels between sites and unmanaged sites behind a tunnel (#239), routed paths (#253).
// The drawing is layered (topolayout.js), wires end at the port squares (#303).
import { del, enc, get, post } from '../api.js';
import { PORT_ROLE, by, clear, h, place, portDetails, portSpeed, s } from '../util.js';
import { card, clearNotice, confirmDialog, field, notice, pageHead, run, select, setNotice, slot, statusBadge, table, tag, toast } from '../ui.js';
import { routedPathsCard } from './traces.js';
import { layoutTopology } from '../topolayout.js';
import { attachZoom } from '../topozoom.js';
import { t } from '../i18n.js';

const ORIGIN = { lldp: 'topology.origin.lldp', mac: 'topology.origin.mac', manual: 'topology.origin.manual', tunnel: 'topology.origin.tunnel' };
const ROLE = { gateway: 'topology.role.gateway', remote: 'topology.role.remote', switch: 'topology.role.switch', ap: 'topology.role.ap', other: 'topology.role.other' };
const MODE = { tagged: 'topology.mode.tagged', untagged: 'topology.mode.untagged' };
const KIND = { cable: 'topology.linkKind.cable', wireless: 'topology.linkKind.wireless', vpn: 'topology.linkKind.vpn' };
const originLabel = (o) => (ORIGIN[o] ? t(ORIGIN[o]) : o);
const modeLabel = (m) => (MODE[m] ? t(MODE[m]) : m);

const PORT = 18;
const PORT_GAP = 5;
const MAX_PORTS = 24;
const BOX_H = 88;
const STRIP = 6; // distance of the port squares from the box edge
const state = { segment: '', site: '', internal: false, expanded: new Set() };

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

function edgeSegment(edge, seg) {
  return edge.segments.find((x) => x.segment_id === seg);
}

// Wire through points top to bottom, leaving and entering vertically.
function smooth(points) {
  let d = `M${points[0].x},${points[0].y}`;
  for (let i = 1; i < points.length; i++) {
    const p = points[i - 1];
    const q = points[i];
    const my = (p.y + q.y) / 2;
    d += ` C${p.x},${my} ${q.x},${my} ${q.x},${q.y}`;
  }
  return d;
}

// Overlay state of one cable: which VLAN, carried by both ends, or not.
function cableState(e) {
  if (!state.segment) return 'none';
  const seg = edgeSegment(e, state.segment);
  return seg ? (seg.consistent ? 'carry' : 'inconsistent') : 'dim';
}

function drawGraph(data, nodes, onPort, siteNames) {
  const linked = new Set(data.edges.flatMap((e) => [e.a.port_id, e.b.port_id]));
  const ports = new Map(nodes.map((n) => [n.id, visiblePorts(n, linked)]));
  const present = new Set(nodes.map((n) => n.id));
  const cables = data.edges.filter((e) => e.kind !== 'vpn' && present.has(e.a.device_id) && present.has(e.b.device_id));
  const tunnels = data.edges.filter((e) => e.kind === 'vpn' && present.has(e.a.device_id) && present.has(e.b.device_id));
  const sized = nodes.map((n) => ({ id: n.id, name: n.name, role: n.role, site: n.site_id || '', w: Math.max(150, ports.get(n.id).length * (PORT + PORT_GAP) + 16, n.name.length * 8 + 24), h: BOX_H }));
  const lay = layoutTopology({
    nodes: sized,
    siteNames,
    edges: [...cables, ...tunnels].map((e) => ({ id: e.id, a: e.a.device_id, b: e.b.device_id, kind: e.kind, up: e.a.uplink && !e.b.uplink ? 'a' : e.b.uplink && !e.a.uplink ? 'b' : null })),
  });
  const rankOf = (id) => lay.nodes[id].rank;
  // a port faces up when its cable goes to a device in a higher layer
  const faceUp = new Set();
  for (const e of cables) {
    if (rankOf(e.b.device_id) < rankOf(e.a.device_id)) faceUp.add(e.a.port_id);
    if (rankOf(e.a.device_id) < rankOf(e.b.device_id)) faceUp.add(e.b.port_id);
  }
  // position of every shown port: the top strip holds the ports of cables going up
  const spots = new Map();
  for (const n of nodes) {
    const box = lay.nodes[n.id];
    let iu = 0;
    let id = 0;
    for (const p of ports.get(n.id)) {
      const up = faceUp.has(p.id);
      const i = up ? iu++ : id++;
      spots.set(p.id, { x: box.x + 8 + i * (PORT + PORT_GAP), y: up ? box.y + STRIP : box.y + BOX_H - STRIP - PORT, up });
    }
  }
  // end of a wire: at the port square, or at the box when the port is not shown
  const endAt = (end, up) => {
    const spot = spots.get(end.port_id);
    if (spot) return { x: spot.x + PORT / 2, y: up ? spot.y : spot.y + PORT };
    const b = lay.nodes[end.device_id];
    return { x: b.x + b.w / 2, y: up ? b.y : b.y + BOX_H };
  };
  const svg = s('svg', { class: 'topo', role: 'img', 'aria-label': t('topology.graphLabel'), 'data-testid': 'topology-graph' });
  const vp = s('g', { class: 'viewport' });
  const frameLayer = s('g', { class: 'frames' });
  const edgeLayer = s('g', { class: 'edges' });
  const nodeLayer = s('g', { class: 'nodes' });
  const markLayer = s('g', { class: 'marks' });
  place(svg, vp);
  place(vp, frameLayer, edgeLayer, nodeLayer, markLayer);
  if (lay.sites.length > 1) {
    for (const site of lay.sites) {
      place(frameLayer, s('rect', { x: String(site.x), y: String(lay.frameY), width: String(site.w), height: String(lay.height - lay.frameY - 6), rx: '14', class: 'site-frame', 'data-testid': 'topo-site' }), s('text', { x: String(site.x + 12), y: String(lay.titleY), class: 'site-name' }, siteNames[site.id] || site.id));
    }
  }
  // the devices no cable reaches sit in a labelled strip at the bottom of their site
  for (const site of lay.sites) {
    if (site.strip) {
      place(frameLayer, s('text', { x: String(site.x + 12), y: String(site.strip.y + 16), class: 'strip-name', 'data-testid': 'topo-uncabled' }, t('topology.notCabled')));
    }
  }
  const links = new Map(nodes.map((n) => [n.id, { edges: [], near: new Set() }]));
  const track = (path, a, b) => {
    links.get(a).edges.push(path);
    links.get(b).edges.push(path);
    links.get(a).near.add(b);
    links.get(b).near.add(a);
  };
  const vpnArc = new Map(lay.vpns.map((v) => [v.id, v]));
  // tunnels: an arc over the boxes, or a wire down from an unmanaged site
  for (const e of tunnels) {
    const ba = lay.nodes[e.a.device_id];
    const bb = lay.nodes[e.b.device_id];
    const dim = state.segment ? 'dim' : '';
    let d;
    if (rankOf(e.a.device_id) !== rankOf(e.b.device_id)) {
      const [hi, lo] = rankOf(e.a.device_id) < rankOf(e.b.device_id) ? [ba, bb] : [bb, ba];
      const key = [e.a.device_id, e.b.device_id].sort().join('|');
      d = smooth([{ x: hi.x + hi.w / 2, y: hi.y + BOX_H }, ...(lay.routes[key] || []), { x: lo.x + lo.w / 2, y: lo.y }]);
    } else if (vpnArc.has(e.id)) {
      const v = vpnArc.get(e.id);
      const r = 8;
      const dir = v.bx > v.ax ? 1 : -1;
      d = `M${v.ax},${v.ay} V${v.y + r} Q${v.ax},${v.y} ${v.ax + dir * r},${v.y} H${v.bx - dir * r} Q${v.bx},${v.y} ${v.bx},${v.y + r} V${v.by}`;
    } else {
      const ax = ba.x + ba.w / 2;
      const bx = bb.x + bb.w / 2;
      const top = Math.max(2, Math.min(ba.y, bb.y) - 30);
      d = `M${ax},${ba.y} C${ax},${top} ${bx},${top} ${bx},${bb.y}`;
    }
    const path = s('path', { d, class: `edge vpn ${dim}`.trim(), 'data-testid': 'topo-edge', 'data-id': e.id, 'data-kind': 'vpn', 'data-state': state.segment ? 'dim' : 'none' });
    place(path, s('title', {}, t('topology.vpnTitle', { a: e.a.port, b: e.b.port }) + (vpnText(e) ? t('topology.vpnDetail', { text: vpnText(e) }) : '')));
    place(edgeLayer, path);
    track(path, e.a.device_id, e.b.device_id);
  }
  // cables, parallel ones of two devices bundled
  const arcs = new Map(); // layer -> same-layer wires drawn so far
  for (const pair of lay.pairs) {
    const all = pair.edges.map((id) => cables.find((e) => e.id === id)).filter(Boolean);
    if (!all.length) continue;
    const bundled = all.length > 1 && !state.expanded.has(pair.key);
    const states = all.map(cableState);
    const rep = bundled ? all[Math.max(0, states.includes('inconsistent') ? states.indexOf('inconsistent') : states.includes('carry') ? states.indexOf('carry') : 0)] : null;
    for (const e of bundled ? [rep] : all) {
      const upper = rankOf(e.a.device_id) <= rankOf(e.b.device_id) ? [e.a, e.b] : [e.b, e.a];
      const same = rankOf(e.a.device_id) === rankOf(e.b.device_id);
      const from = endAt(upper[0], false);
      const to = endAt(upper[1], !same);
      let d;
      if (same) {
        const r = rankOf(e.a.device_id);
        const n = arcs.get(r) || 0;
        arcs.set(r, n + 1);
        const below = Math.max(from.y, to.y) + 26 + Math.min(70, Math.abs(from.x - to.x) / 8) + n * 10;
        d = `M${from.x},${from.y} C${from.x},${below} ${to.x},${below} ${to.x},${to.y}`;
      } else {
        d = smooth([from, ...(lay.routes[pair.key] || []), to]);
      }
      const st = bundled ? (states.includes('inconsistent') ? 'inconsistent' : states.includes('carry') ? 'carry' : state.segment ? 'dim' : 'none') : cableState(e);
      const cls = ['edge', e.kind, e.origin];
      if (st !== 'none') cls.push(st);
      if (bundled) cls.push('bundle');
      const path = s('path', { d, class: cls.join(' '), 'data-testid': 'topo-edge', 'data-id': e.id, 'data-state': st, 'data-a': e.a.port_id, 'data-b': e.b.port_id, 'data-count': bundled ? String(all.length) : null });
      place(path, s('title', {}, t('topology.edgeTitle', { a: e.a.port, b: e.b.port, origin: originLabel(e.origin) })));
      place(edgeLayer, path);
      track(path, e.a.device_id, e.b.device_id);
      if (all.length > 1 && (bundled || e === all[0])) {
        const nameOf = (id) => (nodes.find((n) => n.id === id) || {}).name || id;
        const text = t(bundled ? 'topology.bundle.expand' : 'topology.bundle.collapse', { count: all.length, a: nameOf(pair.a), b: nameOf(pair.b) });
        const mid = bundled && !same ? { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 } : { x: from.x, y: from.y + 22 };
        const badge = s('g', { class: `badge ${bundled ? '' : 'open'}`.trim(), tabindex: '0', role: 'button', 'aria-label': text, 'aria-expanded': String(!bundled), 'data-testid': 'topo-bundle', 'data-count': String(all.length) });
        place(badge, s('title', {}, text), s('circle', { cx: String(mid.x), cy: String(mid.y), r: '11' }), s('text', { x: String(mid.x), y: String(mid.y + 4), 'text-anchor': 'middle' }, bundled ? String(all.length) : '−'));
        const toggle = () => {
          if (bundled) state.expanded.add(pair.key);
          else state.expanded.delete(pair.key);
          svg.dispatchEvent(new CustomEvent('redraw'));
        };
        badge.addEventListener('click', toggle);
        badge.addEventListener('keydown', (ev) => {
          if (ev.key === 'Enter' || ev.key === ' ') {
            ev.preventDefault();
            toggle();
          }
        });
        place(markLayer, badge);
      }
      if (st === 'inconsistent') {
        // the end that lacks the VLAN; both ends when they disagree on tagged / untagged
        const seg = edgeSegment(e, state.segment);
        const oneMissing = !seg.a !== !seg.b;
        for (const [end, pos, mode] of [[e.a, endAt(e.a, faceUp.has(e.a.port_id)), seg.a], [e.b, endAt(e.b, faceUp.has(e.b.port_id)), seg.b]]) {
          if (oneMissing && mode) continue;
          const cy = pos.y + (faceUp.has(end.port_id) ? PORT / 2 : -PORT / 2);
          const mark = s('circle', { cx: String(pos.x), cy: String(cy), r: '13', class: 'bad-end', 'data-testid': 'bad-end' });
          place(mark, s('title', {}, t('topology.endTitle', { port: end.port, mode: mode ? modeLabel(mode) : t('topology.notMember') })));
          place(markLayer, mark);
        }
      }
    }
  }
  const els = new Map();
  for (const n of nodes) {
    const { x, y, w } = lay.nodes[n.id];
    const g = s('g', { class: `node role-${n.role} status-${n.status}`, 'data-testid': 'topo-node', 'data-id': n.id });
    els.set(n.id, g);
    place(g, s('rect', { x: String(x), y: String(y), width: String(w), height: String(BOX_H), rx: '10', class: 'box' }));
    const label = s('text', { x: String(x + 10), y: String(y + 40), class: 'name' }, n.name);
    if (n.role === 'remote') place(g, label);
    else place(g, s('a', { href: `#/device/${enc(n.id)}`, class: 'name-link', 'data-testid': 'topo-device-link', 'aria-label': t('topology.openDevice', { device: n.name }) }, label));
    const roleName = ROLE[n.role] ? t(ROLE[n.role]) : n.role;
    const hidden = shownPorts(n).length - ports.get(n.id).length;
    const roleText = n.role === 'remote' ? t('topology.remoteSite', { networks: n.networks.join(', ') || t('topology.noNetworks') }) : `${roleName}${hidden > 0 ? t('topology.morePorts', { count: hidden }) : ''}`;
    place(g, s('text', { x: String(x + 10), y: String(y + 55), class: 'role' }, roleText));
    for (const p of ports.get(n.id)) {
      const spot = spots.get(p.id);
      const member = state.segment && (p.untagged.includes(state.segment) ? 'untagged' : p.tagged.includes(state.segment) ? 'tagged' : null);
      const clients = (data.clients[p.id] || []).length;
      const cls = ['port', p.up === false ? 'down' : 'up', linked.has(p.id) ? 'linked' : '', member ? `m-${member}` : '', clients ? 'has-clients' : '', p.external === false ? 'internal' : ''];
      const rect = s('rect', { x: String(spot.x), y: String(spot.y), width: String(PORT), height: String(PORT), rx: '3', class: cls.join(' ').trim(), tabindex: '0', role: 'button', 'aria-label': `${t('topology.portAria', { device: n.name, port: p.name })}${p.description ? t('topology.paren', { description: p.description }) : ''}${clients ? t('topology.portClientsAria', { count: clients }) : ''}`, 'data-testid': 'topo-port', 'data-id': p.id });
      place(rect, s('title', {}, `${p.name}${p.description ? t('topology.paren', { description: p.description }) : ''}${p.role && p.role !== 'jack' ? `, ${PORT_ROLE[p.role] || p.role}` : ''}${member ? t('topology.paren', { description: modeLabel(member) }) : ''}${clients ? t('topology.portClientsTitle', { count: clients }) : ''}`));
      rect.addEventListener('click', () => onPort(n, p));
      rect.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          onPort(n, p);
        }
      });
      place(g, rect);
    }
    // hovering a device lifts its wires and neighbours, the rest steps back
    const mine = links.get(n.id);
    g.addEventListener('mouseenter', () => {
      svg.classList.add('hovering');
      g.classList.add('hot');
      for (const p of mine.edges) p.classList.add('hot');
      for (const id of mine.near) els.get(id).classList.add('near');
    });
    g.addEventListener('mouseleave', () => {
      svg.classList.remove('hovering');
      g.classList.remove('hot');
      for (const p of mine.edges) p.classList.remove('hot');
      for (const id of mine.near) els.get(id).classList.remove('near');
    });
    place(nodeLayer, g);
  }
  svg.zoomable = { width: lay.width, height: lay.height, vp };
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
  const msg = slot(); // the form's one place for problems
  const problem = (text) => setNotice(msg, 'error', 'link-error', text);
  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'link-add' }, t('topology.addCable'));
  const form = h('form', {
    class: 'link-form',
    onsubmit: (e) => {
      e.preventDefault();
      clearNotice(msg);
      if (!a.port.value || !b.port.value) {
        problem(t('topology.err.chooseBoth'));
        return;
      }
      if (a.port.value === b.port.value) {
        problem(t('topology.err.samePort'));
        return;
      }
      run(save, async () => {
        await post('/links', { a: a.port.value, b: b.port.value, kind: kind.value });
        toast(t('topology.cableAdded'));
        ctx.refresh();
      }, msg);
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

// Legend of lines, boxes and ports; collapsible, always on the page (#303).
function legendBlock() {
  const swatch = (kids, w = 40) => s('svg', { class: 'topo key-svg', width: String(w), height: '16', viewBox: `0 0 ${w} 16`, 'aria-hidden': 'true' }, kids);
  const line = (cls) => swatch(s('path', { d: 'M2,8 L38,8', class: `edge ${cls}` }));
  const box = (cls) => swatch(s('g', { class: `node ${cls}` }, s('rect', { x: '3', y: '2', width: '34', height: '12', rx: '4', class: 'box' })));
  const port = (cls) => swatch(s('rect', { x: '12', y: '0', width: '16', height: '16', rx: '3', class: `port ${cls}` }));
  const item = (icon, text) => h('li', {}, icon, h('span', {}, text));
  const group = (title, items) => h('div', { class: 'legend-group' }, h('h4', {}, title), h('ul', {}, items));
  return h(
    'details',
    { class: 'topo-legend', open: true, 'data-testid': 'topo-legend' },
    h('summary', {}, t('topology.legend.title')),
    h(
      'div',
      { class: 'legend-body' },
      group(t('topology.legend.lines'), [
        item(line('carry'), t('topology.legend.line.carries')),
        item(line('inconsistent'), t('topology.legend.line.disagree')),
        item(line('dim'), t('topology.legend.line.dim')),
        item(line('vpn'), t('topology.legend.line.vpn')),
        item(line('lldp'), t('topology.legend.line.lldp')),
        item(line('mac'), t('topology.legend.line.mac')),
        item(line('manual'), t('topology.legend.line.manual')),
        item(line('wireless'), t('topology.legend.line.wireless')),
      ]),
      group(t('topology.legend.boxes'), [
        item(box('status-ok'), t('topology.legend.box.ok')),
        item(box('status-partial'), t('topology.legend.box.partial')),
        item(box('status-unreachable'), t('topology.legend.box.unreachable')),
        item(box('role-remote'), t('topology.legend.box.remote')),
        item(swatch(s('rect', { x: '3', y: '1', width: '34', height: '14', rx: '6', class: 'site-frame' })), t('topology.legend.box.site')),
        item(swatch(s('g', { class: 'badge' }, s('circle', { cx: '20', cy: '8', r: '7' }), s('text', { x: '20', y: '11', 'text-anchor': 'middle' }, '2'))), t('topology.legend.bundle')),
      ]),
      group(t('topology.legend.ports'), [
        item(port('up linked'), t('topology.legend.port.up')),
        item(port('down'), t('topology.legend.port.down')),
        item(port('up has-clients'), t('topology.legend.port.clients')),
        item(port('m-untagged'), t('topology.legend.port.untagged')),
        item(port('m-tagged'), t('topology.legend.port.tagged')),
        item(port('internal'), t('topology.legend.port.internal')),
      ]),
    ),
    h('p', { class: 'muted small' }, t('topology.legend.hint')),
  );
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
  let zoom = null;
  const nameOfSite = Object.fromEntries(sites.map((x) => [x.id, x.name]));
  const nodesOf = () => data.nodes.filter((n) => !state.site || n.site_id === state.site);
  const draw = () => {
    const nodes = nodesOf();
    const ids = new Set(nodes.map((n) => n.id));
    const view = { ...data, edges: data.edges.filter((e) => ids.has(e.a.device_id) || ids.has(e.b.device_id)) };
    const svg = drawGraph(view, nodes, (node, port) => place(clear(panel), portPanel(data, data.segments, node, port)), nameOfSite);
    svg.addEventListener('redraw', draw);
    place(clear(graphBox), svg);
    zoom = attachZoom(svg, svg.zoomable.vp, svg.zoomable);
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
  // zoom buttons and the large view: the Fullscreen API where it works, else an overlay
  const card_ = h('div', { class: 'card topo-card', 'data-full': 'false', 'data-testid': 'topo-card' });
  const button = (label, testid, onclick, extra) => {
    const b = h('button', { class: 'btn small', type: 'button', 'data-testid': testid, 'aria-label': label, title: label, ...extra }, label);
    b.addEventListener('click', onclick);
    return b;
  };
  const fullBtn = button(t('topology.fullscreen'), 'topo-full', () => setFull(card_.dataset.full !== 'true'), { 'aria-pressed': 'false' });
  const setFull = async (on) => {
    card_.dataset.full = String(on);
    card_.classList.toggle('full', on);
    fullBtn.setAttribute('aria-pressed', String(on));
    fullBtn.textContent = on ? t('topology.fullscreenExit') : t('topology.fullscreen');
    try {
      if (on && !document.fullscreenElement && card_.requestFullscreen) await card_.requestFullscreen();
      else if (!on && document.fullscreenElement) await document.exitFullscreen();
    } catch {
      // not allowed here: the overlay class already fills the window
    }
    if (zoom) zoom.fit();
  };
  const onFullChange = () => {
    if (!card_.isConnected) return document.removeEventListener('fullscreenchange', onFullChange);
    if (!document.fullscreenElement && card_.dataset.full === 'true' && card_.dataset.api === 'true') setFull(false);
    card_.dataset.api = String(Boolean(document.fullscreenElement));
    return null;
  };
  document.addEventListener('fullscreenchange', onFullChange);
  card_.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && card_.dataset.full === 'true' && !document.fullscreenElement) setFull(false);
  });
  const tools = h(
    'div',
    { class: 'topo-tools' },
    button('+', 'topo-zoom-in', () => zoom && zoom.by(1.25), { 'aria-label': t('topology.zoomIn'), title: t('topology.zoomIn') }),
    button('−', 'topo-zoom-out', () => zoom && zoom.by(0.8), { 'aria-label': t('topology.zoomOut'), title: t('topology.zoomOut') }),
    button(t('topology.zoomReset'), 'topo-zoom-reset', () => zoom && zoom.fit()),
    fullBtn,
  );
  place(card_, tools, graphBox, legendBlock(), h('p', { class: 'phone-only muted small' }, t('topology.phoneNote')), panel);
  const hasInternal = data.nodes.some((n) => n.ports.some((p) => p.external === false));
  const problems = data.nodes.filter((n) => n.status !== 'ok');
  place(main, 
    h('div', { class: 'filters' }, siteSelect, segSelect, hasInternal ? h('label', { class: 'check', title: t('topology.internalTitle') }, internalBox, t('topology.showInternal')) : null),
    problems.length ? notice('warn', 'topo-not-read', t('topology.notRead'), problems.map((n, i) => [i ? ', ' : '', n.name, ' ', statusBadge(n.status)])) : null,
    card_,
    card(t('topology.links'), linkList(ctx, data, data.nodes)),
    routedPathsCard(ctx, data.nodes),
    addLinkForm(ctx, data.nodes.filter((n) => n.role !== 'remote')),
  );
  draw();
}
