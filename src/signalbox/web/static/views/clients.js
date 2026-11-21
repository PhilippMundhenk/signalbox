// Clients: every MAC address the devices know, with addresses, name, segment and where it was seen.
import { loadNetwork, noData } from '../net.js';
import { by, clear, fmtAgo, fmtTime, h, place } from '../util.js';
import { pageHead, table } from '../ui.js';

let query = '';

export async function renderClients(main, ctx) {
  const id = ctx.renderId;
  const ix = await loadNetwork();
  if (!ctx.alive(id)) return;
  place(main, pageHead('Clients'));
  const clients = [...ix.net.clients].sort(by((c) => c.hostname || `~${c.mac}`));
  if (!clients.length) {
    place(main, noData('clients'));
    return;
  }
  // The same client can be reported by several devices: one row per MAC, every place it was seen.
  const rows = new Map();
  for (const c of clients) {
    const row = rows.get(c.mac) || { mac: c.mac, addresses: new Set(), hostname: null, segment_id: null, seen: [], last_seen: null };
    c.addresses.forEach((a) => row.addresses.add(a));
    row.hostname = row.hostname || c.hostname;
    row.segment_id = row.segment_id || c.segment_id;
    if (c.seen_on) row.seen.push(c.seen_on);
    if (c.last_seen && (!row.last_seen || c.last_seen > row.last_seen)) row.last_seen = c.last_seen;
    rows.set(c.mac, row);
  }
  const all = [...rows.values()];
  const search = h('input', { type: 'search', placeholder: 'Filter by name, MAC or address', 'aria-label': 'Filter clients', 'data-testid': 'client-filter', value: query });
  const body = h('div', {});
  const draw = () => {
    const q = query.trim().toLowerCase();
    const shown = all.filter((r) => !q || [r.mac, r.hostname || '', ...r.addresses].some((x) => String(x).toLowerCase().includes(q)));
    place(clear(body), 
      h('p', { class: 'muted', 'data-testid': 'client-count' }, `${shown.length} of ${all.length} clients`),
      table(
        [
          ['Name', (r) => r.hostname],
          ['MAC', (r) => h('span', { class: 'mono' }, r.mac)],
          ['Addresses', (r) => [...r.addresses].join(', ')],
          ['Segment', (r) => (r.segment_id ? ix.segmentName(r.segment_id) : null)],
          ['Seen on', (r) => r.seen.map((x) => ix.label(x)).join(', ')],
          ['Last seen', (r) => (r.last_seen ? h('span', { title: fmtTime(r.last_seen) }, fmtAgo(r.last_seen)) : null)],
        ],
        shown,
        { testid: 'clients', rowTestid: 'client-row' },
      ),
    );
  };
  search.addEventListener('input', () => {
    query = search.value;
    draw();
  });
  place(main, h('div', { class: 'filters' }, search), body);
  draw();
}
