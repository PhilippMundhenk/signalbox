// Layout of the Wi-Fi map (#366). Pure functions, no DOM: the same input always gives the same
// picture. Every radio (ours or a neighbour's) is a bubble. The signal heard between two bubbles
// is the attraction: the stronger it is, the closer they sit and the more they overlap. Pairs
// without a signal are pushed apart until they no longer overlap. The positions are inferred
// from signal strength, not real geometry.
//
// Input:  nodes [{ id, kind: 'own'|'neighbour', band, channel, group?, signal_dbm? }]
//         edges [{ a, b, signal_dbm }]
// Output: { nodes: {id: {x, y, r}}, width, height, overlaps: [[a, b]] (co-channel pairs whose
//           bubbles overlap) }

const STEPS = 700;
const PAD = 24;
export const OWN_R = 46;
const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));

// Bubble radius: ours are all the same, a neighbour grows with its strongest signal.
export function radiusOf(node) {
  if (node.kind === 'own') return OWN_R;
  const dbm = node.signal_dbm ?? -90;
  return 20 + 16 * clamp((dbm + 95) / 50, 0, 1);
}

// Distance of two bubble centres as a share of the sum of their radii: -40 dBm and stronger
// sit at 0.3 (almost on top of each other), -90 dBm and weaker just touch (1.0).
export function distanceFactor(dbm) {
  if (dbm === null || dbm === undefined) return 0.9;
  return 0.3 + 0.7 * clamp((-40 - dbm) / 50, 0, 1);
}

// Channels (of the same band) whose signals overlap: 2.4 GHz channels closer than 5 apart;
// 5 and 6 GHz channels only when equal (20 MHz channels do not overlap each other).
export function channelsOverlap(a, b) {
  if (a.band !== b.band || a.channel === null || a.channel === undefined || b.channel === null || b.channel === undefined) return false;
  return a.band === '2.4' ? Math.abs(a.channel - b.channel) < 5 : a.channel === b.channel;
}

const HUE = { '2.4': 28, 5: 215, 6: 285 };
// Colour of a bubble: the band gives the hue, the channel the lightness inside the band, so
// equal colour means the same channel. Returns an hsl() string.
export function bubbleColor(band, channel) {
  const hue = HUE[band] ?? 160;
  const pos = channel === null || channel === undefined ? 0 : band === '2.4' ? (channel - 1) / 12 : (channel % 64) / 64;
  return `hsl(${hue} 70% ${Math.round(38 + 28 * clamp(pos, 0, 1))}%)`;
}

export function layoutWifiMap({ nodes, edges }) {
  const ids = nodes.map((n) => n.id).sort(cmp);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const r = new Map(ids.map((id) => [id, radiusOf(byId.get(id))]));
  // start on a golden-angle spiral in sorted order: deterministic, no coincident points
  const pos = new Map(ids.map((id, i) => [id, { x: Math.cos(i * 2.39996) * (40 + 38 * Math.sqrt(i)), y: Math.sin(i * 2.39996) * (40 + 38 * Math.sqrt(i)) }]));
  const links = new Map();
  for (const e of edges) {
    if (e.a === e.b || !byId.has(e.a) || !byId.has(e.b)) continue;
    const key = e.a < e.b ? `${e.a}|${e.b}` : `${e.b}|${e.a}`;
    const old = links.get(key);
    if (!old || (e.signal_dbm ?? -999) > (old.signal_dbm ?? -999)) links.set(key, { a: e.a < e.b ? e.a : e.b, b: e.a < e.b ? e.b : e.a, signal_dbm: e.signal_dbm ?? null });
  }
  const linked = [...links.values()].sort((p, q) => cmp(`${p.a}|${p.b}`, `${q.a}|${q.b}`));
  const isLinked = (a, b) => links.has(a < b ? `${a}|${b}` : `${b}|${a}`);
  for (let step = 0; step < STEPS; step++) {
    const cool = 1 - step / STEPS;
    const move = new Map(ids.map((id) => [id, { x: 0, y: 0 }]));
    const push = (a, b, want, k) => {
      const pa = pos.get(a);
      const pb = pos.get(b);
      let dx = pb.x - pa.x;
      let dy = pb.y - pa.y;
      let d = Math.hypot(dx, dy);
      if (d < 0.01) {
        dx = 1;
        dy = 0;
        d = 1;
      }
      const f = ((d - want) / d) * k;
      move.get(a).x += dx * f;
      move.get(a).y += dy * f;
      move.get(b).x -= dx * f;
      move.get(b).y -= dy * f;
    };
    for (const e of linked) push(e.a, e.b, distanceFactor(e.signal_dbm) * (r.get(e.a) + r.get(e.b)), 0.25);
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = ids[i];
        const b = ids[j];
        const pa = pos.get(a);
        const pb = pos.get(b);
        const d = Math.hypot(pb.x - pa.x, pb.y - pa.y);
        const apart = (r.get(a) + r.get(b)) * 1.04;
        // no signal: no overlap; a signal never lets two bubbles sit on one point
        if (!isLinked(a, b) && d < apart) push(a, b, apart, 0.4);
        else if (d < 0.25 * (r.get(a) + r.get(b))) push(a, b, 0.25 * (r.get(a) + r.get(b)), 0.5);
        // a weak pull of the bubbles of one group (the access points of one site)
        const ga = byId.get(a).group;
        if (ga !== undefined && ga === byId.get(b).group && !isLinked(a, b) && d > apart * 1.3) push(a, b, apart * 1.3, 0.02);
      }
    }
    for (const id of ids) {
      const p = pos.get(id);
      const m = move.get(id);
      // gravity towards the origin keeps unconnected parts on the page
      p.x += (m.x - p.x * 0.0015) * cool;
      p.y += (m.y - p.y * 0.0015) * cool;
    }
  }
  let x0 = Infinity;
  let y0 = Infinity;
  let x1 = -Infinity;
  let y1 = -Infinity;
  for (const id of ids) {
    const p = pos.get(id);
    x0 = Math.min(x0, p.x - r.get(id));
    y0 = Math.min(y0, p.y - r.get(id));
    x1 = Math.max(x1, p.x + r.get(id));
    y1 = Math.max(y1, p.y + r.get(id));
  }
  if (!ids.length) [x0, y0, x1, y1] = [0, 0, 0, 0];
  const out = {};
  for (const id of ids) {
    const p = pos.get(id);
    out[id] = { x: round(p.x - x0 + PAD), y: round(p.y - y0 + PAD), r: round(r.get(id)) };
  }
  const overlaps = [];
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = out[ids[i]];
      const b = out[ids[j]];
      if (Math.hypot(a.x - b.x, a.y - b.y) < a.r + b.r && channelsOverlap(byId.get(ids[i]), byId.get(ids[j]))) overlaps.push([ids[i], ids[j]]);
    }
  }
  return { nodes: out, width: round(x1 - x0 + 2 * PAD), height: round(y1 - y0 + 2 * PAD), overlaps };
}

const round = (v) => Math.round(v * 100) / 100;
