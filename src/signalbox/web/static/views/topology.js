// Topology: devices with their ports, links between ports, VLAN overlay, entered cables.
import { del, enc, get, post } from '../api.js';
import { by, clear, h, place, portDetails, portSpeed, s } from '../util.js';
import { card, confirmDialog, field, pageHead, run, select, statusBadge, table, tag, toast } from '../ui.js';

const LAYER = { gateway: 0, switch: 1, ap: 2, other: 3 };
const ORIGIN = { lldp: 'LLDP', mac: 'MAC table', manual: 'entered' };
const PORT = 18;
const PORT_GAP = 5;
const MAX_PORTS = 24;
const ROW = 150;
const BOX_H = 74;
const GAP = 36;
const state = { segment: '', site: '' };

function visiblePorts(node, linked) {
  if (node.ports.length <= MAX_PORTS) return node.ports;
  return node.ports.filter((p) => linked.has(p.id)).slice(0, MAX_PORTS);
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
      boxes.set(n.id, { node: n, x, y: 20 + i * ROW, w, ports });
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
  return { boxes, width: Math.max(width, 320), height: used.length * ROW + 10 };
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
  const svg = s('svg', { viewBox: `0 0 ${width} ${height}`, width: String(width), height: String(height), class: 'topo', role: 'img', 'aria-label': 'Network topology', 'data-testid': 'topology-graph' });
  const edgeLayer = s('g', { class: 'edges' });
  const nodeLayer = s('g', { class: 'nodes' });
  const markLayer = s('g', { class: 'marks' });
  place(svg, edgeLayer, nodeLayer, markLayer);
  for (const e of data.edges) {
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
    place(path, s('title', {}, `${e.a.port} ↔ ${e.b.port} (${ORIGIN[e.origin] || e.origin})`));
    place(edgeLayer, path);
    if (seg && !seg.consistent) {
      // the end that lacks the VLAN; both ends when they disagree on tagged / untagged
      const oneMissing = !seg.a !== !seg.b;
      for (const [end, pos, mode] of [[e.a, a, seg.a], [e.b, b, seg.b]]) {
        if (oneMissing && mode) continue;
        const mark = s('circle', { cx: String(pos.x), cy: String(pos.y), r: '13', class: 'bad-end', 'data-testid': 'bad-end' });
        place(mark, s('title', {}, `${end.port}: ${mode || 'not a member'}`));
        place(markLayer, mark);
      }
    }
  }
  for (const { node, x, y, w, ports } of boxes.values()) {
    const g = s('g', { class: `node role-${node.role} status-${node.status}`, 'data-testid': 'topo-node', 'data-id': node.id });
    place(g, s('rect', { x: String(x), y: String(y), width: String(w), height: String(BOX_H), rx: '10', class: 'box' }));
    place(g, s('text', { x: String(x + 10), y: String(y + 20), class: 'name' }, node.name));
    place(g, s('text', { x: String(x + 10), y: String(y + 36), class: 'role' }, `${node.role}${node.ports.length > ports.length ? ` · ${node.ports.length - ports.length} more ports` : ''}`));
    ports.forEach((p, i) => {
      const px = x + 10 + i * (PORT + PORT_GAP);
      const py = y + BOX_H - 14 - PORT;
      const member = state.segment && (p.untagged.includes(state.segment) ? 'untagged' : p.tagged.includes(state.segment) ? 'tagged' : null);
      const clients = (data.clients[p.id] || []).length;
      const cls = ['port', p.up === false ? 'down' : 'up', linked.has(p.id) ? 'linked' : '', member ? `m-${member}` : '', clients ? 'has-clients' : ''];
      const rect = s('rect', { x: String(px), y: String(py), width: String(PORT), height: String(PORT), rx: '3', class: cls.join(' ').trim(), tabindex: '0', role: 'button', 'aria-label': `${node.name} port ${p.name}${p.description ? ` (${p.description})` : ''}${clients ? `, ${clients} clients` : ''}`, 'data-testid': 'topo-port', 'data-id': p.id });
      place(rect, s('title', {}, `${p.name}${p.description ? ` (${p.description})` : ''}${member ? ` (${member})` : ''}${clients ? ` – ${clients} clients` : ''}`));
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
    parts.push(`untagged frames in: ${segments[port.pvid_segment] || port.pvid_segment}`);
  }
  const text = parts.filter(Boolean).join(' · ');
  return text ? h('p', { class: 'muted', 'data-testid': 'port-facts' }, text) : null;
}

function portPanel(data, segments, node, port) {
  const clients = data.clients[port.id] || [];
  return h(
    'div',
    { class: 'card port-panel', 'data-testid': 'port-panel' },
    h('h3', {}, `${node.name} · port ${port.name}`),
    port.description ? h('p', { 'data-testid': 'port-description' }, port.description) : null,
    h('p', { class: 'muted' }, [port.untagged.length ? `untagged: ${port.untagged.map((x) => segments[x] || x).join(', ')}` : null, port.tagged.length ? `tagged: ${port.tagged.map((x) => segments[x] || x).join(', ')}` : null].filter(Boolean).join(' · ') || 'No VLAN membership reported.'),
    portFacts(port, segments),
    clients.length
      ? table(
          [
            ['Name', (c) => c.hostname],
            ['MAC', (c) => h('span', { class: 'mono' }, c.mac)],
            ['Segment', (c) => (c.segment_id ? segments[c.segment_id] || c.segment_id : null)],
          ],
          clients,
          { rowTestid: 'port-client', compact: true },
        )
      : h('p', { class: 'muted', 'data-testid': 'no-port-clients' }, 'No clients seen on this port.'),
  );
}

function linkList(ctx, data, nodes) {
  const names = new Map(nodes.map((n) => [n.id, n.name]));
  const endText = (end) => `${names.get(end.device_id) || end.device_id} · ${end.port}`;
  const edges = [...data.edges].sort(by((e) => `${endText(e.a)} ${endText(e.b)}`));
  if (!edges.length) return h('p', { class: 'muted', 'data-testid': 'no-links' }, 'No links known yet. Devices that report LLDP neighbours or MAC tables add them automatically; you can also enter a cable below.');
  return table(
    [
      ['From', (e) => endText(e.a)],
      ['To', (e) => endText(e.b)],
      ['Kind', (e) => e.kind],
      ['Found by', (e) => tag(ORIGIN[e.origin] || e.origin, `origin-${e.origin}`)],
      [
        'VLANs',
        (e) =>
          e.segments.length
            ? e.segments.map((x, i) => [i ? ', ' : '', h('span', { class: x.consistent ? '' : 'error', title: x.consistent ? `${x.a} on both ends` : `${x.a || 'not a member'} ↔ ${x.b || 'not a member'}` }, `${x.name}${x.consistent ? '' : ' (!)'}`)])
            : null,
      ],
      [
        '',
        (e) => {
          if (e.origin !== 'manual') return null;
          const btn = h('button', { class: 'btn small', type: 'button', 'data-testid': 'link-delete', 'aria-label': `Delete link ${endText(e.a)} to ${endText(e.b)}` }, 'Delete');
          btn.addEventListener('click', () =>
            run(btn, async () => {
              if (!(await confirmDialog({ title: 'Delete this cable?', message: `${endText(e.a)} ↔ ${endText(e.b)} is removed from Signalbox. Nothing changes on the devices.`, confirmLabel: 'Delete', danger: true }))) return;
              await del(`/links/${enc(e.id)}`);
              toast('Link deleted.');
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
    const dev = select([['', 'Choose a device'], ...sorted.map((n) => [n.id, n.name])], '', { 'data-testid': `link-${side}-device` });
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
  const kind = select([['cable', 'Cable'], ['wireless', 'Wireless']], 'cable', { 'data-testid': 'link-kind' });
  const msg = h('p', { class: 'error', role: 'alert', 'data-testid': 'link-error' });
  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'link-add' }, 'Add cable');
  const form = h('form', {
    class: 'link-form',
    onsubmit: (e) => {
      e.preventDefault();
      msg.textContent = '';
      if (!a.port.value || !b.port.value) {
        msg.textContent = 'Choose a device and a port on both ends.';
        return;
      }
      if (a.port.value === b.port.value) {
        msg.textContent = 'The two ends must be different ports.';
        return;
      }
      run(save, async () => {
        await post('/links', { a: a.port.value, b: b.port.value, kind: kind.value });
        toast('Cable added.');
        ctx.refresh();
      });
    },
  });
  place(form, 
    h('div', { class: 'link-ends' }, h('fieldset', {}, h('legend', {}, 'One end'), field('Device', a.dev), field('Port', a.port)), h('fieldset', {}, h('legend', {}, 'Other end'), field('Device', b.dev), field('Port', b.port))),
    field('Kind', kind),
    msg,
    save,
  );
  return card('Enter a cable', h('p', { class: 'muted' }, 'For devices that do not report their neighbours. Entered cables win over what the devices report; a difference becomes a finding.'), form);
}

export async function renderTopology(main, ctx) {
  const id = ctx.renderId;
  const [data, sites] = await Promise.all([get('/topology'), get('/sites')]);
  if (!ctx.alive(id)) return;
  place(main, pageHead('Topology'));
  if (!data.nodes.length) {
    place(main, h('div', { class: 'card empty', 'data-testid': 'empty' }, h('h2', {}, 'Nothing to draw yet'), h('p', { class: 'muted' }, 'The topology shows devices that have been read, their ports and the cables between them.'), h('p', {}, h('a', { class: 'btn', href: '#/devices' }, 'Devices'))));
    return;
  }
  if (state.site && !sites.some((x) => x.id === state.site)) state.site = '';
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
        ? [h('span', { class: 'key carry' }), ' carries the VLAN  ', h('span', { class: 'key inconsistent' }), ' ends disagree (marked with a circle)  ', h('span', { class: 'key dim' }), ' does not carry it']
        : 'Click a port to see its clients. Pick a VLAN to see which links carry it.',
    );
  };
  const segSelect = select([['', 'No VLAN overlay'], ...Object.entries(data.segments).sort(by(([, n]) => n)).map(([sid, n]) => [sid, `${n}${sites.length > 1 ? ` – ${(sites.find((x) => sid.startsWith(`${x.id}/`)) || {}).name || ''}` : ''}`])], state.segment, { 'aria-label': 'Highlight a VLAN', 'data-testid': 'topo-segment' });
  segSelect.addEventListener('change', () => {
    state.segment = segSelect.value;
    draw();
  });
  let siteSelect = null;
  if (sites.length > 1) {
    siteSelect = select([['', 'All sites'], ...sites.map((x) => [x.id, x.name])], state.site, { 'aria-label': 'Site', 'data-testid': 'filter-site' });
    siteSelect.addEventListener('change', () => {
      state.site = siteSelect.value;
      draw();
    });
  }
  const problems = data.nodes.filter((n) => n.status !== 'ok');
  place(main, 
    h('div', { class: 'filters' }, siteSelect, segSelect),
    problems.length ? h('p', { class: 'notice small' }, 'Not read completely: ', problems.map((n, i) => [i ? ', ' : '', n.name, ' ', statusBadge(n.status)])) : null,
    h('div', { class: 'card topo-card' }, legend, graphBox, h('p', { class: 'phone-only muted small' }, 'The drawing needs a wider screen; the links are listed below.')),
    panel,
    card('Links', linkList(ctx, data, data.nodes)),
    addLinkForm(ctx, data.nodes),
  );
  draw();
}
