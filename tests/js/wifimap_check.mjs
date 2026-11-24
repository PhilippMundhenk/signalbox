// Runs the Wi-Fi map layout on a fixture read from stdin and prints what the Python tests check.
import { readFileSync } from 'node:fs';
import { bubbleColor, channelsOverlap, distanceFactor, layoutWifiMap, radiusOf } from '../../src/signalbox/web/static/wifimaplayout.js';

const { nodes, edges } = JSON.parse(readFileSync(0, 'utf8'));
const lay = layoutWifiMap({ nodes, edges });
const again = layoutWifiMap({ nodes: [...nodes].reverse(), edges: [...edges].reverse() });
const dist = (l, a, b) => Math.hypot(l.nodes[a].x - l.nodes[b].x, l.nodes[a].y - l.nodes[b].y);
console.log(
  JSON.stringify({
    layout: lay,
    deterministic: JSON.stringify(layoutWifiMap({ nodes, edges })) === JSON.stringify(lay),
    sameForShuffledInput: JSON.stringify(again) === JSON.stringify(lay),
    distances: Object.fromEntries(edges.map((e) => [`${e.a}|${e.b}`, dist(lay, e.a, e.b)])),
    factors: { strong: distanceFactor(-40), weak: distanceFactor(-90), mid: distanceFactor(-65), none: distanceFactor(null) },
    radii: { own: radiusOf({ kind: 'own' }), loud: radiusOf({ kind: 'neighbour', signal_dbm: -45 }), quiet: radiusOf({ kind: 'neighbour', signal_dbm: -90 }) },
    overlapCases: {
      sameFive: channelsOverlap({ band: '5', channel: 36 }, { band: '5', channel: 36 }),
      otherFive: channelsOverlap({ band: '5', channel: 36 }, { band: '5', channel: 40 }),
      near24: channelsOverlap({ band: '2.4', channel: 1 }, { band: '2.4', channel: 4 }),
      far24: channelsOverlap({ band: '2.4', channel: 1 }, { band: '2.4', channel: 6 }),
      bands: channelsOverlap({ band: '2.4', channel: 1 }, { band: '5', channel: 1 }),
      unknown: channelsOverlap({ band: '5', channel: null }, { band: '5', channel: null }),
    },
    colors: { a: bubbleColor('5', 36), b: bubbleColor('5', 36), c: bubbleColor('5', 149), d: bubbleColor('2.4', 6), e: bubbleColor('6', 1) },
  }),
);
