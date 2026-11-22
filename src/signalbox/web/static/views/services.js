// DHCP & DNS: servers per segment with pools and reservations; DNS services with host records.
import { loadNetwork, noData } from '../net.js';
import { by, h, place, yesNo } from '../util.js';
import { card, kv, pageHead, table, tag } from '../ui.js';

// "12 active, 3 expired, 1 declined" (#183).
function leaseCount(leases) {
  const n = {};
  for (const l of leases) n[l.state] = (n[l.state] || 0) + 1;
  const order = ['active', 'offered', 'reserved', 'expired', 'declined'];
  const text = order.filter((s) => n[s]).map((s) => `${n[s]} ${s}`).join(', ');
  return h('span', { 'data-testid': 'dhcp-leases' }, text || 'none');
}

// A DNS forwarder (#241): {address, port}; older data has a bare address.
function forwarder(f) {
  if (typeof f === 'string') return f;
  if (!f.port || f.port === 53) return f.address;
  return f.address.includes(':') ? `[${f.address}]:${f.port}` : `${f.address}:${f.port}`;
}

function dhcpCard(ix, d) {
  return h(
    'section',
    { class: 'card', 'data-testid': 'dhcp-server' },
    h('h3', {}, ix.deviceName(d.device_id), ' ', d.enabled ? tag('serving', 'ok') : tag('disabled')),
    kv([
      ['Pools', d.pools.length ? d.pools.map((p) => `${p.start} – ${p.end}`).join(', ') : null],
      ['Lease', d.lease_seconds ? `${Math.round(d.lease_seconds / 60)} min` : null],
      ['Router', d.router],
      ['DNS servers', d.dns_servers.length ? d.dns_servers.join(', ') : null],
      ['Domain', d.domain],
      ['Search domains', d.search_domains.length ? d.search_domains.join(', ') : undefined],
      ['NTP servers', d.ntp_servers.length ? d.ntp_servers.join(', ') : undefined],
      ['Leases', d.leases ? leaseCount(d.leases) : undefined],
      ['Authoritative', d.authoritative === null ? undefined : yesNo(d.authoritative)],
      ['Failover peer', d.failover_peer || undefined],
    ]),
    d.reservations.length
      ? h(
          'div',
          {},
          h('h4', {}, `Reservations (${d.reservations.length})`),
          table(
            [
              ['MAC', (r) => h('span', { class: 'mono' }, r.mac)],
              ['Address', (r) => r.address],
              ['Hostname', (r) => r.hostname],
            ],
            [...d.reservations].sort(by((r) => r.address)),
            { rowTestid: 'reservation', compact: true },
          ),
        )
      : null,
  );
}

export async function renderServices(main, ctx) {
  const id = ctx.renderId;
  const ix = await loadNetwork();
  if (!ctx.alive(id)) return;
  place(main, pageHead('DHCP & DNS'));
  const { dhcp_servers: dhcp, dns_services: dns } = ix.net;
  if (!dhcp.length && !dns.length) {
    place(main, noData('DHCP or DNS services'));
    return;
  }
  const segs = [...new Set(dhcp.map((d) => d.segment_id))].sort(by((sid) => ix.label(sid)));
  if (segs.length) place(main, h('h2', {}, 'DHCP'));
  for (const sid of segs) {
    const servers = dhcp.filter((d) => d.segment_id === sid);
    const active = servers.filter((d) => d.enabled).length;
    place(main, 
      h(
        'section',
        { class: 'group', 'data-testid': 'dhcp-segment' },
        h('h3', {}, ix.label(sid), ' ', active > 1 ? tag(`${active} active servers`, 'danger') : null),
        h('div', { class: 'grid wide' }, servers.map((d) => dhcpCard(ix, d))),
      ),
    );
  }
  if (dns.length) {
    place(main, h('h2', {}, 'DNS'));
    for (const d of dns) {
      place(main, 
        card(
          null,
          h(
            'h3',
            {},
            ix.deviceName(d.device_id),
            d.name ? ` (${d.name})` : '',
            ' ',
            d.enabled ? tag('serving', 'ok') : tag('disabled'),
            d.config_read === false ? tag('not read') : null,
          ),
          kv([
            ['Listens on', d.listen.length ? d.listen.join(', ') : null],
            ['Port', String(d.port ?? 53)],
            [
              'Forwards to',
              d.config_read === false
                ? 'not read'
                : d.forwarders.length
                  ? d.forwarders.map(forwarder).join(', ')
                  : null,
            ],
            ['Enabled', yesNo(d.enabled)],
          ]),
          d.config_read === false
            ? h('p', { class: 'muted' }, 'Signalbox only knows that it answers on this port; its settings are not read.')
            : d.host_records.length
            ? table(
                [
                  ['Name', (r) => r.name],
                  ['Address', (r) => r.address],
                ],
                [...d.host_records].sort(by((r) => r.name)),
                { rowTestid: 'host-record', compact: true },
              )
            : h('p', { class: 'muted' }, 'No host records.'),
        ),
      );
      main.lastChild.setAttribute('data-testid', 'dns-service');
    }
  }
}
