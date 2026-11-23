// Clients: every MAC address the devices know, with addresses, name, segment and where it was seen.
import { get } from '../api.js';
import { fdbText, loadNetwork, noData } from '../net.js';
import { by, clear, fmtAgo, fmtDuration, fmtTime, h, place } from '../util.js';
import { pageHead, table } from '../ui.js';
import { editNote, noteOf } from '../annotations.js';

let query = '';

// Where an address came from (#183), as shown after it.
const SOURCE = { dhcp: 'DHCP', 'dhcp-reserved': 'DHCP reservation', static: 'fixed', slaac: 'SLAAC', 'slaac-privacy': 'SLAAC temporary', dhcpv6: 'DHCPv6', 'link-local': 'link-local' };

export async function renderClients(main, ctx) {
  const id = ctx.renderId;
  const [ix, past, fdb] = await Promise.all([loadNetwork(), get('/history'), get('/fdb').catch(() => [])]);
  const learned = new Map();
  for (const e of fdb) if (e.kind !== 'self') learned.set(e.mac, [...(learned.get(e.mac) || []), e]);
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
    const row = rows.get(c.mac) || { mac: c.mac, addresses: new Set(), sources: {}, lease_expires: null, hostname: null, segment_id: null, seen: [], last_seen: null };
    c.addresses.forEach((a) => row.addresses.add(a));
    Object.assign(row.sources, c.sources || {});
    if (c.lease_expires && (!row.lease_expires || c.lease_expires > row.lease_expires)) row.lease_expires = c.lease_expires;
    row.hostname = row.hostname || c.hostname;
    row.segment_id = row.segment_id || c.segment_id;
    if (c.seen_on) row.seen.push(c.seen_on);
    if (c.last_seen && (!row.last_seen || c.last_seen > row.last_seen)) row.last_seen = c.last_seen;
    rows.set(c.mac, row);
  }
  // First and last seen come from the observation history where it knows the client.
  for (const row of rows.values()) {
    const seen = past.clients[row.mac];
    row.first_seen = seen ? seen.first_seen : null;
    if (seen && (!row.last_seen || seen.last_seen > row.last_seen)) row.last_seen = seen.last_seen;
  }
  const all = [...rows.values()];
  const search = h('input', { type: 'search', placeholder: 'Filter by name, MAC or address', 'aria-label': 'Filter clients', 'data-testid': 'client-filter', value: query });
  const body = h('div', {});
  const draw = () => {
    const q = query.trim().toLowerCase();
    const note = (r) => noteOf(ix, `client/${r.mac}`);
    const shown = all.filter((r) => !q || [r.mac, r.hostname || '', (note(r) || {}).label || '', (note(r) || {}).owner || '', ...r.addresses].some((x) => String(x).toLowerCase().includes(q)));
    const name = (r) => {
      const n = note(r);
      if (!n || !n.label) return r.hostname;
      return h('span', { 'data-testid': 'client-label' }, n.label, r.hostname ? h('span', { class: 'muted small' }, ` (${r.hostname})`) : null);
    };
    const notesButton = (r) => {
      const n = note(r);
      if (n && n.source === 'declared') return h('span', { class: 'muted small', title: 'Declared in the desired state' }, n.owner || 'declared');
      const b = h('button', { class: 'btn small', type: 'button', 'data-testid': 'client-notes' }, n ? n.owner || 'Edit' : 'Add');
      b.addEventListener('click', async () => {
        if (await editNote(`client/${r.mac}`, 'client', n, `Notes on ${n && n.label ? n.label : r.hostname || r.mac}`)) ctx.refresh();
      });
      return b;
    };
    place(clear(body), 
      h('p', { class: 'muted', 'data-testid': 'client-count' }, `${shown.length} of ${all.length} clients`),
      table(
        [
          ['Name', name],
          ['MAC', (r) => h('span', { class: 'mono' }, r.mac)],
          ['Addresses', (r) => [...r.addresses].map((a) => (r.sources[a] && r.sources[a] !== 'unknown' ? `${a} (${SOURCE[r.sources[a]] || r.sources[a]})` : a)).join(', ')],
          ['Lease until', (r) => (r.lease_expires ? h('span', { title: fmtTime(r.lease_expires), 'data-testid': 'client-lease' }, fmtTime(r.lease_expires)) : null)],
          ['Segment', (r) => (r.segment_id ? ix.segmentName(r.segment_id) : null)],
          ['Seen on', (r) => seenOn(ix, r, learned.get(r.mac) || [])],
          ['First seen', (r) => (r.first_seen ? h('span', { title: fmtTime(r.first_seen), 'data-testid': 'client-first-seen' }, fmtAgo(r.first_seen)) : null)],
          ['Last seen', (r) => (r.last_seen ? h('span', { title: fmtTime(r.last_seen) }, fmtAgo(r.last_seen)) : null)],
          ['Notes', notesButton],
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

// Where the client is, and (collapsed) every port a MAC address table learned it on (#160).
function seenOn(ix, row, entries) {
  const where = [...new Set(row.seen)].map((x) => ix.placeName(x)).join(', ');
  if (!entries.length) return where || null;
  return h(
    'span',
    {},
    where ? h('span', { 'data-testid': 'client-seen-on' }, `Seen on ${where}`) : null,
    h(
      'details',
      { class: 'small', 'data-testid': 'client-learned' },
      h('summary', {}, `Learned on ${entries.length} ${entries.length === 1 ? 'port' : 'ports'}`),
      h('ul', {}, entries.map((e) => h('li', { 'data-testid': 'client-learned-port' }, `${ix.placeName(e.port_id)} (${fdbText(e, fmtDuration)})`))),
    ),
  );
}
