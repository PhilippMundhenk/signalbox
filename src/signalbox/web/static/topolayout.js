// Layered layout of the topology (#303). Pure functions, no DOM: the same input always gives the
// same picture. Devices are put in layers by role and uplink direction (remote sites, gateways,
// switches, access points and clients), ordered inside each layer by barycentre sweeps to keep
// the number of crossing wires low, and placed so that wires run as straight as the order allows.
// Parallel links between the same two devices are one "pair" here; the view bundles them.
//
// Input:  nodes [{ id, role, site, w, h }]
//         edges [{ id, a, b, kind, up }]   a, b are device ids; up is 'a' or 'b' when that end is
//                                          an uplink port (that device sits below the other one)
// Output: { nodes: {id: {x, y, w, h, rank, site}}, routes: {pairKey: [{x, y}]} (waypoints of
//           wires that cross layers, top to bottom of the pair's upper device), pairs,
//           sites [{id, x, w}], width, height, crossings, ranks }

export const TIER = { remote: 0, gateway: 1, switch: 2, ap: 3, other: 3 };
const GAP = 36; // between two devices of a layer
const DUMMY_GAP = 14;
const DUMMY_W = 6;
const ROW = 176; // distance of two layers
const TOP = 36; // room for VPN arcs and site titles above the first layer
const SITE_GAP = 56;
const SWEEPS = 14;

export const pairKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);
const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);

// Layer of every device: the tier of its role, pushed down below the device above it.
export function assignRanks(nodes, edges) {
  const ids = nodes.map((n) => n.id).sort(cmp);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const tier = (id) => TIER[byId.get(id).role] ?? 3;
  const links = edges.filter((e) => e.kind !== 'vpn' && e.a !== e.b && byId.has(e.a) && byId.has(e.b));
  // distance from the gateways decides the direction between two devices of the same role
  const adj = new Map(ids.map((i) => [i, []]));
  for (const e of links) {
    adj.get(e.a).push(e.b);
    adj.get(e.b).push(e.a);
  }
  const depth = new Map();
  let queue = ids.filter((i) => tier(i) <= 1);
  for (const i of queue) depth.set(i, 0);
  while (queue.length) {
    const next = [];
    for (const i of queue) for (const j of adj.get(i).sort(cmp)) if (!depth.has(j)) (depth.set(j, depth.get(i) + 1), next.push(j));
    queue = next;
  }
  const d = (i) => (depth.has(i) ? depth.get(i) : 1e6);
  const down = []; // [upper, lower]
  for (const e of links) {
    if (e.up === 'a') down.push([e.b, e.a]);
    else if (e.up === 'b') down.push([e.a, e.b]);
    else if (tier(e.a) !== tier(e.b)) down.push(tier(e.a) < tier(e.b) ? [e.a, e.b] : [e.b, e.a]);
    else if (d(e.a) !== d(e.b)) down.push(d(e.a) < d(e.b) ? [e.a, e.b] : [e.b, e.a]);
  }
  const rank = new Map(ids.map((i) => [i, tier(i)]));
  for (let pass = 0; pass < ids.length + 1; pass++) {
    let changed = false;
    for (const [u, v] of down) {
      if (rank.get(v) < rank.get(u) + 1 && rank.get(u) < ids.length + 4) {
        rank.set(v, rank.get(u) + 1);
        changed = true;
      }
    }
    if (!changed) break;
  }
  // close the gaps of empty layers
  const used = [...new Set(rank.values())].sort((x, y) => x - y);
  return new Map(ids.map((i) => [i, used.indexOf(rank.get(i))]));
}

// Number of crossings of the wires between two layers; `edges` are [position above, position below].
export function crossingsBetween(edges) {
  let n = 0;
  for (let i = 0; i < edges.length; i++) {
    for (let j = i + 1; j < edges.length; j++) {
      const [a1, b1] = edges[i];
      const [a2, b2] = edges[j];
      if ((a1 - a2) * (b1 - b2) < 0) n++;
    }
  }
  return n;
}

// Layers of node ids and the edges between neighbouring layers, dummies for the long ones.
function layered(ids, rank, pairs) {
  const layers = [];
  const link = []; // [upper id, lower id, weight]
  const dummies = new Map(); // pair key -> dummy ids top to bottom
  let nd = 0;
  for (const id of ids) {
    const r = rank.get(id);
    (layers[r] = layers[r] || []).push(id);
  }
  for (const p of pairs) {
    let u = p.a;
    let v = p.b;
    if (rank.get(u) > rank.get(v)) [u, v] = [v, u];
    const ru = rank.get(u);
    const rv = rank.get(v);
    if (ru === rv) continue;
    let prev = u;
    const chain = [];
    for (let r = ru + 1; r < rv; r++) {
      const id = `~${nd++}`;
      (layers[r] = layers[r] || []).push(id);
      link.push([prev, id, p.edges.length]);
      chain.push(id);
      prev = id;
    }
    link.push([prev, v, p.edges.length]);
    dummies.set(p.key, chain);
  }
  return { layers: Array.from(layers, (l) => l || []), link, dummies };
}

function orderLayers(layers, link, name) {
  const up = new Map(); // id -> upper neighbours
  const dn = new Map();
  for (const [u, v] of link) {
    (dn.get(u) || dn.set(u, []).get(u)).push(v);
    (up.get(v) || up.set(v, []).get(v)).push(u);
  }
  for (const l of layers) l.sort((x, y) => cmp(name(x), name(y)));
  const index = () => new Map(layers.flatMap((l) => l.map((id, i) => [id, i])));
  const total = () => {
    const pos = index();
    let n = 0;
    for (let r = 0; r + 1 < layers.length; r++) n += crossingsBetween(link.filter(([u]) => layers[r].includes(u)).map(([u, v]) => [pos.get(u), pos.get(v)]));
    return n;
  };
  const sweep = (r, nb) => {
    const pos = index();
    const bary = new Map();
    layers[r].forEach((id, i) => {
      const ns = nb.get(id) || [];
      bary.set(id, ns.length ? ns.reduce((a, x) => a + pos.get(x), 0) / ns.length : i);
    });
    layers[r].sort((x, y) => bary.get(x) - bary.get(y) || cmp(name(x), name(y)));
  };
  // adjacent swaps while they remove crossings
  const transpose = () => {
    let improved = true;
    for (let guard = 0; improved && guard < 6; guard++) {
      improved = false;
      for (let r = 0; r < layers.length; r++) {
        for (let i = 0; i + 1 < layers[r].length; i++) {
          const before = total();
          [layers[r][i], layers[r][i + 1]] = [layers[r][i + 1], layers[r][i]];
          if (total() < before) improved = true;
          else [layers[r][i], layers[r][i + 1]] = [layers[r][i + 1], layers[r][i]];
        }
      }
    }
  };
  let best = layers.map((l) => [...l]);
  let bestN = total();
  for (let k = 0; k < SWEEPS && bestN > 0; k++) {
    if (k % 2 === 0) for (let r = 1; r < layers.length; r++) sweep(r, up);
    else for (let r = layers.length - 2; r >= 0; r--) sweep(r, dn);
    const n = total();
    if (n < bestN) (bestN = n, (best = layers.map((l) => [...l])));
  }
  layers.forEach((l, r) => l.splice(0, l.length, ...best[r]));
  if (layers.reduce((a, l) => a + l.length, 0) <= 80) transpose();
  return { up, dn, crossings: total() };
}

// Left to right positions of one layer closest to the wanted centres, keeping order and gaps
// (pool adjacent violators on the least-squares problem).
function place(order, want, width, gapOf) {
  const off = [];
  let acc = 0;
  order.forEach((id, i) => {
    if (i) acc += width(order[i - 1]) / 2 + width(id) / 2 + gapOf(order[i - 1], id);
    off.push(acc);
  });
  const blocks = [];
  order.forEach((id, i) => {
    blocks.push({ sum: want(id) - off[i], n: 1 });
    while (blocks.length > 1 && blocks[blocks.length - 2].sum / blocks[blocks.length - 2].n > blocks[blocks.length - 1].sum / blocks[blocks.length - 1].n) {
      const b = blocks.pop();
      blocks[blocks.length - 1].sum += b.sum;
      blocks[blocks.length - 1].n += b.n;
    }
  });
  const out = new Map();
  let i = 0;
  for (const b of blocks) for (let k = 0; k < b.n; k++, i++) out.set(order[i], b.sum / b.n + off[i]);
  return out; // centre x
}

function layoutSite(siteNodes, rank, pairs, byId) {
  const ids = siteNodes.map((n) => n.id);
  const { layers, link, dummies } = layered(ids, rank, pairs);
  const name = (id) => (byId.has(id) ? `${byId.get(id).name || ''}\u0000${id}` : id);
  const { up, dn, crossings } = orderLayers(layers, link, name);
  const width = (id) => (byId.has(id) ? byId.get(id).w : DUMMY_W);
  const gapOf = (a, b) => (byId.has(a) && byId.has(b) ? GAP : DUMMY_GAP);
  const cx = new Map();
  for (const l of layers) {
    const row = place(l, () => 0, width, gapOf);
    const mid = l.length ? (row.get(l[0]) + row.get(l[l.length - 1])) / 2 : 0;
    for (const [id, x] of row) cx.set(id, x - mid);
  }
  for (let k = 0; k < 8; k++) {
    const down = k % 2 === 0;
    const seq = layers.map((_, r) => r);
    if (!down) seq.reverse();
    for (const r of seq) {
      const nb = down ? up : dn;
      layers[r].length &&
        place(layers[r], (id) => {
          const ns = nb.get(id) || [];
          return ns.length ? ns.reduce((a, x) => a + cx.get(x), 0) / ns.length : cx.get(id);
        }, width, gapOf).forEach((x, id) => cx.set(id, x));
    }
  }
  let min = Infinity;
  let max = -Infinity;
  for (const id of ids) {
    min = Math.min(min, cx.get(id) - byId.get(id).w / 2);
    max = Math.max(max, cx.get(id) + byId.get(id).w / 2);
  }
  return { cx, min, max, dummies, crossings, layers };
}

export function layoutTopology({ nodes, edges }) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const rank = assignRanks(nodes, edges);
  // one pair per two devices, however many cables
  const pairMap = new Map();
  for (const e of [...edges].sort((x, y) => cmp(x.id, y.id))) {
    if (e.kind === 'vpn' && !(byId.get(e.a)?.role === 'remote' || byId.get(e.b)?.role === 'remote')) continue;
    if (!byId.has(e.a) || !byId.has(e.b) || e.a === e.b) continue;
    const key = pairKey(e.a, e.b);
    if (!pairMap.has(key)) pairMap.set(key, { key, a: e.a < e.b ? e.a : e.b, b: e.a < e.b ? e.b : e.a, edges: [] });
    pairMap.get(key).edges.push(e);
  }
  const pairs = [...pairMap.values()].sort((x, y) => cmp(x.key, y.key));
  const siteIds = [...new Set(nodes.map((n) => n.site || ''))].sort(cmp);
  const out = { nodes: {}, routes: {}, pairs: pairs.map((p) => ({ key: p.key, a: p.a, b: p.b, edges: p.edges.map((e) => e.id) })), sites: [], width: 0, height: 0, crossings: 0, ranks: 0 };
  let x0 = 20;
  let maxRank = 0;
  for (const site of siteIds) {
    const members = nodes.filter((n) => (n.site || '') === site);
    const sitePairs = pairs.filter((p) => (byId.get(p.a).site || '') === site && (byId.get(p.b).site || '') === site);
    const lay = layoutSite(members, rank, sitePairs, byId);
    const dx = x0 - lay.min;
    for (const n of members) {
      const r = rank.get(n.id);
      maxRank = Math.max(maxRank, r);
      out.nodes[n.id] = { x: lay.cx.get(n.id) - n.w / 2 + dx, y: TOP + r * ROW, w: n.w, h: n.h, rank: r, site };
    }
    for (const p of sitePairs) {
      const chain = lay.dummies.get(p.key) || [];
      const upper = rank.get(p.a) <= rank.get(p.b) ? p.a : p.b;
      const lower = upper === p.a ? p.b : p.a;
      const r0 = rank.get(upper);
      out.routes[p.key] = chain.map((id, i) => ({ x: lay.cx.get(id) + dx, y: TOP + (r0 + 1 + i) * ROW + byId.get(upper).h / 2 }));
      out.routes[p.key].upper = upper;
      void lower;
    }
    out.sites.push({ id: site, x: x0 - 14, w: lay.max - lay.min + 28 });
    out.crossings += lay.crossings;
    x0 += lay.max - lay.min + SITE_GAP;
  }
  out.width = Math.max(320, x0 - SITE_GAP + 20);
  out.height = TOP + maxRank * ROW + Math.max(0, ...nodes.map((n) => n.h)) + 70;
  out.ranks = maxRank + 1;
  return out;
}

// Wire as a list of points (node centres and waypoints), for counting crossings of a picture.
export function polylines(lay) {
  const lines = [];
  for (const p of lay.pairs) {
    const a = lay.nodes[p.a];
    const b = lay.nodes[p.b];
    if (!a || !b) continue;
    const [u, l] = a.rank <= b.rank ? [a, b] : [b, a];
    const mid = lay.routes[p.key] || [];
    const upper = lay.routes[p.key]?.upper;
    const first = upper === p.b ? b : a;
    const last = first === a ? b : a;
    void u;
    void l;
    lines.push({ key: p.key, a: p.a, b: p.b, pts: [{ x: first.x + first.w / 2, y: first.y + first.h / 2 }, ...mid, { x: last.x + last.w / 2, y: last.y + last.h / 2 }] });
  }
  return lines;
}

function intersects(p1, p2, p3, p4) {
  const d = (a, b, c) => (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
  const d1 = d(p3, p4, p1);
  const d2 = d(p3, p4, p2);
  const d3 = d(p1, p2, p3);
  const d4 = d(p1, p2, p4);
  return d1 * d2 < 0 && d3 * d4 < 0;
}

// Crossings of wires of different pairs, drawn as the given polylines.
export function countCrossings(lines) {
  let n = 0;
  for (let i = 0; i < lines.length; i++) {
    for (let j = i + 1; j < lines.length; j++) {
      const A = lines[i];
      const B = lines[j];
      if (A.a === B.a || A.a === B.b || A.b === B.a || A.b === B.b) continue; // same device: not a crossing
      for (let s = 0; s + 1 < A.pts.length; s++) for (let u = 0; u + 1 < B.pts.length; u++) if (intersects(A.pts[s], A.pts[s + 1], B.pts[u], B.pts[u + 1])) n++;
    }
  }
  return n;
}
