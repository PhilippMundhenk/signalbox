// Clients: every MAC address the devices know, with addresses, name, segment and where it was seen.
import { fmtNumber, t } from '../i18n.js';
import { get } from '../api.js';
import { fdbText, loadNetwork, noData } from '../net.js';
import { by, clear, fmtAgo, fmtDuration, fmtTime, h, ltr, place } from '../util.js';
import { pageHead, table } from '../ui.js';
import { editNote, noteOf } from '../annotations.js';

let query = '';

// Where an address came from (#183), as shown after it.
const SOURCE = { dhcp: 'clients.source.dhcp', 'dhcp-reserved': 'clients.source.dhcpReserved', static: 'clients.source.static', slaac: 'clients.source.slaac', 'slaac-privacy': 'clients.source.slaacPrivacy', dhcpv6: 'clients.source.dhcpv6', 'link-local': 'clients.source.linkLocal' };
const sourceLabel = (src) => (SOURCE[src] ? t(SOURCE[src]) : src);

export async function renderClients(main, ctx) {
  const id = ctx.renderId;
  const [ix, past, fdb] = await Promise.all([loadNetwork(), get('/history'), get('/fdb').catch(() => [])]);
  const learned = new Map();
  for (const e of fdb) if (e.kind !== 'self') learned.set(e.mac, [...(learned.get(e.mac) || []), e]);
  if (!ctx.alive(id)) return;
  place(main, pageHead(t('clients.title')));
  const clients = [...ix.net.clients].sort(by((c) => c.hostname || `~${c.mac}`));
  if (!clients.length) {
    place(main, noData('clients'));
    return;
  }
  // The same client can be reported by several devices: one row per MAC, every place it was seen.
  const rows = new Map();
  for (const c of clients) {
    const row = rows.get(c.mac) || { mac: c.mac, addresses: new Set(), sources: {}, lease_expires: null, hostname: null, vendor: null, segment_id: null, seen: [], sightings: [], last_seen: null, wireless: null };
    c.addresses.forEach((a) => row.addresses.add(a));
    Object.assign(row.sources, c.sources || {});
    if (c.lease_expires && (!row.lease_expires || c.lease_expires > row.lease_expires)) row.lease_expires = c.lease_expires;
    row.hostname = row.hostname || c.hostname;
    row.vendor = row.vendor || c.vendor;
    row.segment_id = row.segment_id || c.segment_id;
    row.wireless = row.wireless || c.wireless || null;
    if (c.seen_on) row.seen.push(c.seen_on);
    row.sightings.push(...(c.sightings || []));
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
  const search = h('input', { type: 'search', placeholder: t('clients.filter.placeholder'), 'aria-label': t('clients.filter.label'), 'data-testid': 'client-filter', value: query });
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
      if (n && n.source === 'declared') return h('span', { class: 'muted small', title: t('clients.declared.title') }, n.owner || t('clients.declared.short'));
      const b = h('button', { class: 'btn small', type: 'button', 'data-testid': 'client-notes' }, n ? n.owner || t('common.edit') : t('common.add'));
      b.addEventListener('click', async () => {
        if (await editNote(`client/${r.mac}`, 'client', n, t('clients.notesOn', { name: n && n.label ? n.label : r.hostname || r.mac }))) ctx.refresh();
      });
      return b;
    };
    place(clear(body), 
      h('p', { class: 'muted', 'data-testid': 'client-count' }, t('clients.count', { shown: fmtNumber(shown.length), total: fmtNumber(all.length) })),
      table(
        [
          [t('clients.col.name'), name],
          [t('clients.col.mac'), (r) => h('span', { class: 'mono' }, r.mac)],
          [t('clients.col.vendor'), (r) => r.vendor || null],
          [t('clients.col.addresses'), (r) => [...r.addresses].flatMap((a, i) => [i ? ', ' : null, ltr(a), r.sources[a] && r.sources[a] !== 'unknown' ? ` (${sourceLabel(r.sources[a])})` : null])],
          [t('clients.col.lease'), (r) => (r.lease_expires ? h('span', { title: fmtTime(r.lease_expires), 'data-testid': 'client-lease' }, fmtTime(r.lease_expires)) : null)],
          [t('clients.col.wifi'), (r) => wifiSummary(r.wireless)],
          [t('clients.col.segment'), (r) => (r.segment_id ? ix.segmentName(r.segment_id) : null)],
          [t('clients.col.seenOn'), (r) => seenOn(ix, r, learned.get(r.mac) || [])],
          [t('clients.col.firstSeen'), (r) => (r.first_seen ? h('span', { title: fmtTime(r.first_seen), 'data-testid': 'client-first-seen' }, fmtAgo(r.first_seen)) : null)],
          [t('clients.col.lastSeen'), (r) => (r.last_seen ? h('span', { title: fmtTime(r.last_seen) }, fmtAgo(r.last_seen)) : null)],
          [t('clients.col.notes'), notesButton],
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

// Signal, rates and standard of a Wi-Fi association (#170); units are the same in every language.
function wifiSummary(w) {
  if (!w) return null;
  const parts = [];
  if (w.signal_dbm != null) parts.push(`${w.signal_dbm} dBm`);
  if (w.tx_rate_mbps != null || w.rx_rate_mbps != null) parts.push(`${w.tx_rate_mbps ?? '?'}/${w.rx_rate_mbps ?? '?'} Mbit/s`);
  if (w.standard) parts.push(`802.11${w.standard}`);
  if (w.band) parts.push(`${w.band} GHz`);
  return parts.length ? h('span', { class: 'mono', 'data-testid': 'client-wifi' }, parts.join(', ')) : null;
}

// Where the client is, and (collapsed) every port a MAC address table learned it on (#160).
function seenOn(ix, row, entries) {
  const where = [...new Set(row.seen)].map((x) => ix.placeName(x)).join(', ');
  const sightings = row.sightings.length > 1 ? row.sightings : [];
  if (!entries.length && !sightings.length) return where || null;
  return h(
    'span',
    {},
    where ? h('span', { 'data-testid': 'client-seen-on' }, entries.length ? t('clients.seenOnWhere', { where }) : where) : null,
    entries.length
      ? h(
          'details',
          { class: 'small', 'data-testid': 'client-learned' },
          h('summary', {}, t('clients.learnedOn', { count: entries.length })),
          h('ul', {}, entries.map((e) => h('li', { 'data-testid': 'client-learned-port' }, `${ix.placeName(e.port_id)} (${fdbText(e, fmtDuration)})`))),
        )
      : null,
    sightings.length
      ? h(
          'details',
          { class: 'small', 'data-testid': 'client-sightings' },
          h('summary', {}, t('clients.sightings', { count: sightings.length })),
          h(
            'ul',
            {},
            sightings.map((x) =>
              h(
                'li',
                { 'data-testid': 'client-sighting' },
                t('clients.sighting', {
                  device: ix.deviceName(x.device_id),
                  segment: x.segment_id ? ix.segmentName(x.segment_id) : t('clients.sightingNoSegment'),
                  where: x.seen_on ? ix.placeName(x.seen_on) : t('clients.sightingNoPlace'),
                }),
              ),
            ),
          ),
        )
      : null,
  );
}
