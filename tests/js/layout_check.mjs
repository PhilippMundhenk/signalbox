// Runs the topology layout on a fixture read from stdin and prints the numbers the Python tests
// check: crossings of the new layout, crossings of the previous one (rows by role, sorted by
// name), a fingerprint of the picture, the layers.
import { readFileSync } from 'node:fs';
import { countCrossings, layoutTopology, pairKey, polylines } from '../../src/signalbox/web/static/topolayout.js';

const { nodes, edges } = JSON.parse(readFileSync(0, 'utf8'));
const sized = nodes.map((n) => ({ ...n, w: n.w || 150, h: 88 }));

// the layout before #303: four rows by role, sorted by name, centred
const ROWS = { gateway: 0, remote: 0, switch: 1, ap: 2, other: 3 };
function previous() {
  const rows = [[], [], [], []];
  for (const n of [...sized].sort((a, b) => (a.name < b.name ? -1 : 1))) rows[ROWS[n.role] ?? 3].push(n);
  const pos = {};
  const width = Math.max(...rows.map((r) => r.reduce((a, n) => a + n.w + 36, 0)));
  rows.forEach((row, i) => {
    let x = (width - row.reduce((a, n) => a + n.w + 36, 0)) / 2;
    for (const n of row) {
      pos[n.id] = { x, y: i * 150, w: n.w, h: 88, rank: i };
      x += n.w + 36;
    }
  });
  const seen = new Set();
  const pairs = [];
  for (const e of edges) {
    const key = pairKey(e.a, e.b);
    if (e.kind === 'vpn' || seen.has(key)) continue;
    seen.add(key);
    pairs.push({ key, a: e.a, b: e.b });
  }
  return countCrossings(polylines({ nodes: pos, pairs, routes: {} }));
}

const lay = layoutTopology({ nodes: sized, edges });
const lines = polylines(lay);
const canon = (l) => JSON.stringify(Object.entries(l.nodes).sort(([a], [b]) => (a < b ? -1 : 1)));
const again = layoutTopology({ nodes: [...sized].reverse(), edges: [...edges].reverse() });
console.log(
  JSON.stringify({
    crossings: countCrossings(lines),
    previous: previous(),
    deterministic: canon(layoutTopology({ nodes: sized, edges })) === canon(lay),
    sameForShuffledInput: canon(again) === canon(lay),
    ranks: Object.fromEntries(Object.entries(lay.nodes).map(([id, n]) => [id, n.rank])),
    boxes: Object.values(lay.nodes).map((n) => [n.x, n.y, n.w, n.h]),
    pairs: lay.pairs,
    width: lay.width,
    height: lay.height,
  }),
);
