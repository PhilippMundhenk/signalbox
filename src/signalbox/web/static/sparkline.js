// A small traffic sparkline per port (#471): the hourly average bit rates received and sent over
// the last day, drawn with DOM APIs only (no markup strings, strict CSP).
import { t } from './i18n.js';
import { s } from './util.js';

const WIDTH = 120;
const HEIGHT = 24;
const HOURS = 24;

export function fmtRate(bps) {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(1)} Gbit/s`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbit/s`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(0)} kbit/s`;
  return `${Math.round(bps)} bit/s`;
}

// buckets: [{at, seconds, rx_bps, tx_bps}] oldest first; now: Date (the right edge).
// Returns an svg element, or null when nothing in the last day was recorded.
export function sparkline(buckets, now = new Date()) {
  const end = now.getTime();
  const start = end - HOURS * 3600 * 1000;
  const recent = (buckets || []).filter((b) => new Date(b.at).getTime() + 3600 * 1000 > start);
  if (!recent.length) return null;
  const peak = Math.max(1, ...recent.map((b) => Math.max(b.rx_bps, b.tx_bps)));
  const x = (b) => Math.max(0, Math.min(WIDTH, ((new Date(b.at).getTime() + 1800 * 1000 - start) / (end - start)) * WIDTH));
  const y = (v) => (HEIGHT - 1 - (v / peak) * (HEIGHT - 2)).toFixed(1);
  const line = (cls, key) => s('polyline', { class: cls, fill: 'none', points: recent.map((b) => `${x(b).toFixed(1)},${y(b[key])}`).join(' ') });
  const label = t('device.port.traffic', { hours: HOURS, peak: fmtRate(peak) });
  return s(
    'svg',
    { class: 'spark', viewBox: `0 0 ${WIDTH} ${HEIGHT}`, width: String(WIDTH), height: String(HEIGHT), role: 'img', 'aria-label': label, 'data-testid': 'port-spark' },
    s('title', {}, label),
    line('rx', 'rx_bps'),
    line('tx', 'tx_bps'),
  );
}
