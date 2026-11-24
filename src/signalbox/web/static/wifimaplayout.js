// Layout of the Wi-Fi map (#366, #392). Pure functions, no DOM: the same input always gives the
// same picture. Every radio (ours or a neighbour's) is a bubble. The signal heard between two
// bubbles is the attraction: the stronger it is, the closer they sit. Pairs without a signal keep
// a minimum gap. The positions are inferred from signal strength, not real geometry.
//  - One cluster (frame) per site, side by side; no attraction across sites. A neighbour belongs
//    to the site of the own radio that hears it best.
//  - The radios of one access point (same `ap`) sit next to each other and get one label.
//  - Labels of access points sit outside the bubbles, moved clear of every bubble and every
//    other label, with a leader line to the access point.
//
// Input:  nodes [{ id, kind: 'own'|'neighbour', band, channel, group?, ap?, label?, signal_dbm? }]
//         edges [{ a, b, signal_dbm }], siteNames? { group: title }
// Output: { nodes: {id: {x, y, r}}, labels: [{ id, text, x, y, w, h, line }], sites: [{ id, name,
//           x, y, width, height }], aps: [{ id, ids }] (radios of one access point), links: [{ a, b }] (the edges drawn), width, height,
//           overlaps: [[a, b]] (co-channel pairs whose bubbles overlap) }

const STEPS = 600;
const PAD = 16; // inside a site frame
const GAP = 14; // least gap between two radios that do not hear each other
const SITE_GAP = 56; // between two site frames
const HEAD = 34; // site title strip
const LABEL_H = 20;
export const OWN_R = 34;
const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
const round = (v) => Math.round(v * 100) / 100;
const keyOf = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);

// Bubble radius: ours are all the same, a neighbour is smaller and grows with its strongest signal.
export function radiusOf(node) {
  if (node.kind === 'own') return OWN_R;
  const dbm = node.signal_dbm ?? -90;
  return 11 + 8 * clamp((dbm + 95) / 50, 0, 1);
}

// Distance of two bubble centres as a share of the sum of their radii. Radios of two access
// points sit at 0.75 (-40 dBm and stronger) to 1.0 (-90 dBm and weaker, just touching); a
// neighbour at 0.65 to 0.95, so it stays visible next to our bigger bubble.
export function distanceFactor(dbm, neighbour = false) {
  const lo = neighbour ? 0.8 : 0.75;
  const span = neighbour ? 0.18 : 0.25;
  if (dbm === null || dbm === undefined) return lo + span * 0.8;
  return lo + span * clamp((-40 - dbm) / 50, 0, 1);
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

// Distance of the point (px, py) from the rectangle {x, y, w, h} (0 inside).
function rectGap(rc, px, py) {
  const dx = Math.max(rc.x - px, 0, px - (rc.x + rc.w));
  const dy = Math.max(rc.y - py, 0, py - (rc.y + rc.h));
  return Math.hypot(dx, dy);
}

const rectsOverlap = (p, q, pad = 0) => p.x < q.x + q.w + pad && q.x < p.x + p.w + pad && p.y < q.y + q.h + pad && q.y < p.y + p.h + pad;

// Where the line from the centre of the rectangle towards (px, py) leaves it.
function clipToRect(rc, px, py) {
  const cx = rc.x + rc.w / 2;
  const cy = rc.y + rc.h / 2;
  const dx = px - cx;
  const dy = py - cy;
  if (!dx && !dy) return { x: cx, y: cy };
  const t = Math.min(dx ? rc.w / 2 / Math.abs(dx) : Infinity, dy ? rc.h / 2 / Math.abs(dy) : Infinity);
  return { x: cx + dx * Math.min(t, 1), y: cy + dy * Math.min(t, 1) };
}

// Force layout of the radios of one site; returns positions in a local frame.
function layoutSite(items, links, apOf, r) {
  const ids = items.map((n) => n.id).sort(cmp);
  const byId = new Map(items.map((n) => [n.id, n]));
  const pos = new Map(ids.map((id, i) => [id, { x: Math.cos(i * 2.39996) * (40 + 44 * Math.sqrt(i)), y: Math.sin(i * 2.39996) * (40 + 44 * Math.sqrt(i)) }]));
  const same = (a, b) => apOf.get(a) !== undefined && apOf.get(a) === apOf.get(b);
  const linkOf = new Map(links.map((l) => [keyOf(l.a, l.b), l]));
  const want = (a, b) => {
    if (same(a, b)) return r.get(a) + r.get(b) + 3;
    const l = linkOf.get(keyOf(a, b));
    if (!l) return r.get(a) + r.get(b) + GAP;
    const neighbour = byId.get(a).kind !== 'own' || byId.get(b).kind !== 'own';
    return distanceFactor(l.signal_dbm, neighbour) * (r.get(a) + r.get(b));
  };
  const hard = (a, b) => (same(a, b) ? r.get(a) + r.get(b) + 2 : linkOf.has(keyOf(a, b)) ? 0.5 * (r.get(a) + r.get(b)) : r.get(a) + r.get(b) + GAP);
  const pull = (move, a, b, target, k) => {
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
    const f = ((d - target) / d) * k;
    move.get(a).x += dx * f;
    move.get(a).y += dy * f;
    move.get(b).x -= dx * f;
    move.get(b).y -= dy * f;
  };
  for (let step = 0; step < STEPS + 80; step++) {
    const relax = step >= STEPS; // the last rounds only enforce the minimum distances
    const cool = relax ? 1 : 1 - step / STEPS;
    const move = new Map(ids.map((id) => [id, { x: 0, y: 0 }]));
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = ids[i];
        const b = ids[j];
        const pa = pos.get(a);
        const pb = pos.get(b);
        const d = Math.hypot(pb.x - pa.x, pb.y - pa.y);
        const linked = same(a, b) || linkOf.has(keyOf(a, b));
        if (relax) {
          if (d < hard(a, b)) pull(move, a, b, hard(a, b), 0.5);
        } else if (linked) {
          pull(move, a, b, want(a, b), same(a, b) ? 0.5 : 0.25);
        } else if (d < want(a, b)) {
          pull(move, a, b, want(a, b), 0.4);
        }
      }
    }
    for (const id of ids) {
      const p = pos.get(id);
      const m = move.get(id);
      // gravity towards the origin keeps unconnected parts together
      p.x += (m.x - (relax ? 0 : p.x * 0.004)) * cool;
      p.y += (m.y - (relax ? 0 : p.y * 0.004)) * cool;
    }
  }
  return { pos, ids };
}

// One label per access point, outside its radios and clear of everything placed so far.
function placeLabels(aps, circles) {
  const at = new Map(circles.map((c) => [c.id, c]));
  const placed = [];
  const labels = [];
  for (const ap of aps) {
    const w = Math.max(40, ap.text.length * 7.4 + 14);
    const h = LABEL_H;
    const mine = ap.ids.map((id) => at.get(id));
    const others = circles.filter((c) => !ap.ids.includes(c.id));
    const bx0 = Math.min(...mine.map((c) => c.x - c.r));
    const bx1 = Math.max(...mine.map((c) => c.x + c.r));
    const by0 = Math.min(...mine.map((c) => c.y - c.r));
    const by1 = Math.max(...mine.map((c) => c.y + c.r));
    const cx = (bx0 + bx1) / 2;
    const cy = (by0 + by1) / 2;
    const cost = (rc) => {
      let c = 0;
      for (const o of others) c += Math.max(0, o.r + 3 - rectGap(rc, o.x, o.y));
      for (const q of placed) if (rectsOverlap(rc, q, 3)) c += 50 + Math.min(rc.w, q.w);
      return c;
    };
    let best = null;
    for (const gap of [8, 22, 40, 64, 96, 140]) {
      const dirs = [
        { x: cx - w / 2, y: by0 - gap - h },
        { x: cx - w / 2, y: by1 + gap },
        { x: bx1 + gap, y: cy - h / 2 },
        { x: bx0 - gap - w, y: cy - h / 2 },
        { x: bx1 + gap, y: by0 - gap - h },
        { x: bx0 - gap - w, y: by0 - gap - h },
        { x: bx1 + gap, y: by1 + gap },
        { x: bx0 - gap - w, y: by1 + gap },
      ];
      for (const d of dirs) {
        const rc = { x: d.x, y: d.y, w, h };
        const c = cost(rc) + gap * 0.01;
        if (!best || c < best.c - 1e-9) best = { c, rc };
      }
      if (best && best.c < 1) break;
    }
    const rc = best.rc;
    // the leader ends on the rim of the radio of the access point nearest to the label
    const near = [...mine].sort((p, q) => rectGap(rc, p.x, p.y) - rectGap(rc, q.x, q.y) || cmp(p.id, q.id))[0];
    const lcx = rc.x + rc.w / 2;
    const lcy = rc.y + rc.h / 2;
    const dd = Math.hypot(lcx - near.x, lcy - near.y) || 1;
    const from = clipToRect(rc, near.x, near.y);
    const to = { x: near.x + ((lcx - near.x) / dd) * near.r, y: near.y + ((lcy - near.y) / dd) * near.r };
    placed.push(rc);
    labels.push({ id: ap.id, text: ap.text, x: rc.x, y: rc.y, w, h, line: { x1: from.x, y1: from.y, x2: to.x, y2: to.y } });
  }
  return labels;
}

export function layoutWifiMap({ nodes, edges, siteNames = {} }) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const r = new Map(nodes.map((n) => [n.id, radiusOf(n)]));
  const siteOf = new Map();
  for (const n of nodes) if (n.kind === 'own') siteOf.set(n.id, n.group ?? '');
  const sites = [...new Set(siteOf.values())].sort(cmp);
  if (!sites.length) sites.push('');
  // a neighbour belongs to the site of the own radio that hears it best
  for (const n of [...nodes].sort((p, q) => cmp(p.id, q.id))) {
    if (n.kind === 'own') continue;
    let best = null;
    for (const e of edges) {
      const other = e.a === n.id ? e.b : e.b === n.id ? e.a : null;
      if (other === null || !siteOf.has(other) || byId.get(other).kind !== 'own') continue;
      const sig = e.signal_dbm ?? -999;
      if (!best || sig > best.sig || (sig === best.sig && cmp(other, best.other) < 0)) best = { sig, other };
    }
    siteOf.set(n.id, best ? siteOf.get(best.other) : sites[0]);
  }
  const links = new Map();
  for (const e of edges) {
    if (e.a === e.b || !byId.has(e.a) || !byId.has(e.b) || siteOf.get(e.a) !== siteOf.get(e.b)) continue;
    const key = keyOf(e.a, e.b);
    const old = links.get(key);
    if (!old || (e.signal_dbm ?? -999) > (old.signal_dbm ?? -999)) links.set(key, { a: e.a < e.b ? e.a : e.b, b: e.a < e.b ? e.b : e.a, signal_dbm: e.signal_dbm ?? null });
  }
  const out = {};
  const labels = [];
  const frames = [];
  const apList = [];
  let cursor = 0;
  let height = 0;
  for (const site of sites) {
    const items = nodes.filter((n) => siteOf.get(n.id) === site);
    const mine = [...links.values()].filter((l) => siteOf.get(l.a) === site).sort((p, q) => cmp(keyOf(p.a, p.b), keyOf(q.a, q.b)));
    const apOf = new Map();
    for (const n of items) if (n.kind === 'own' && n.ap !== undefined && n.ap !== null) apOf.set(n.id, `${n.ap}`);
    const { pos, ids } = layoutSite(items, mine, apOf, r);
    const circles = ids.map((id) => ({ id, x: pos.get(id).x, y: pos.get(id).y, r: r.get(id) }));
    const aps = new Map();
    for (const id of ids) {
      if (byId.get(id).kind !== 'own') continue;
      const key = apOf.get(id) ?? id;
      if (!aps.has(key)) aps.set(key, { id: key, ids: [], text: byId.get(id).label ?? key });
      aps.get(key).ids.push(id);
    }
    for (const ap of aps.values()) apList.push({ id: ap.id, ids: ap.ids });
    const placed = placeLabels([...aps.values()].sort((p, q) => cmp(p.id, q.id)), circles);
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    for (const c of circles) {
      x0 = Math.min(x0, c.x - c.r);
      y0 = Math.min(y0, c.y - c.r);
      x1 = Math.max(x1, c.x + c.r);
      y1 = Math.max(y1, c.y + c.r);
    }
    for (const l of placed) {
      x0 = Math.min(x0, l.x);
      y0 = Math.min(y0, l.y);
      x1 = Math.max(x1, l.x + l.w);
      y1 = Math.max(y1, l.y + l.h);
    }
    if (!circles.length) [x0, y0, x1, y1] = [0, 0, 0, 0];
    const name = siteNames[site] ?? site;
    const width = Math.max(x1 - x0 + 2 * PAD, name.length * 8 + 2 * PAD);
    const frameH = HEAD + (y1 - y0) + PAD;
    const dx = cursor + PAD + (width - 2 * PAD - (x1 - x0)) / 2 - x0;
    const dy = HEAD - y0;
    for (const c of circles) out[c.id] = { x: round(c.x + dx), y: round(c.y + dy), r: round(c.r) };
    for (const l of placed) {
      labels.push({ id: l.id, text: l.text, x: round(l.x + dx), y: round(l.y + dy), w: round(l.w), h: l.h, line: { x1: round(l.line.x1 + dx), y1: round(l.line.y1 + dy), x2: round(l.line.x2 + dx), y2: round(l.line.y2 + dy) } });
    }
    frames.push({ id: site, name, x: round(cursor), y: 0, width: round(width), height: round(frameH) });
    cursor += width + SITE_GAP;
    height = Math.max(height, frameH);
  }
  const overlaps = [];
  const all = Object.keys(out).sort(cmp);
  for (let i = 0; i < all.length; i++) {
    for (let j = i + 1; j < all.length; j++) {
      const a = out[all[i]];
      const b = out[all[j]];
      if (Math.hypot(a.x - b.x, a.y - b.y) < a.r + b.r && channelsOverlap(byId.get(all[i]), byId.get(all[j]))) overlaps.push([all[i], all[j]]);
    }
  }
  const drawn = [...links.values()].map((l) => ({ a: l.a, b: l.b })).sort((p, q) => cmp(keyOf(p.a, p.b), keyOf(q.a, q.b)));
  return { nodes: out, labels, sites: frames, aps: apList.sort((p, q) => cmp(p.id, q.id)), links: drawn, width: round(cursor - SITE_GAP), height: round(height), overlaps };
}
