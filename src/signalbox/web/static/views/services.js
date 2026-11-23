// DHCP & DNS: servers per segment with pools and reservations; DNS services with host records.
import { loadNetwork, noData } from '../net.js';
import { t } from '../i18n.js';
import { by, h, place, yesNo } from '../util.js';
import { card, kv, pageHead, table, tag } from '../ui.js';

// "12 active, 3 expired, 1 declined" (#183).
const LEASE_KEY = { active: 'services.lease.active', offered: 'services.lease.offered', reserved: 'services.lease.reserved', expired: 'services.lease.expired', declined: 'services.lease.declined' };
function leaseCount(leases) {
  const n = {};
  for (const l of leases) n[l.state] = (n[l.state] || 0) + 1;
  const order = ['active', 'offered', 'reserved', 'expired', 'declined'];
  const text = order.filter((s) => n[s]).map((s) => t(LEASE_KEY[s], { count: n[s] })).join(', ');
  return h('span', { 'data-testid': 'dhcp-leases' }, text || t('services.none'));
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
    h('h3', {}, ix.deviceName(d.device_id), ' ', d.enabled ? tag(t('services.serving'), 'ok') : tag(t('services.disabled'))),
    kv([
      [t('services.pools'), d.pools.length ? d.pools.map((p) => `${p.start} – ${p.end}`).join(', ') : null],
      [t('services.lease'), d.lease_seconds ? t('services.minutes', { count: Math.round(d.lease_seconds / 60) }) : null],
      [t('services.router'), d.router],
      [t('services.dnsServers'), d.dns_servers.length ? d.dns_servers.join(', ') : null],
      [t('services.domain'), d.domain],
      [t('services.searchDomains'), d.search_domains.length ? d.search_domains.join(', ') : undefined],
      [t('services.ntpServers'), d.ntp_servers.length ? d.ntp_servers.join(', ') : undefined],
      [t('services.leases'), d.leases ? leaseCount(d.leases) : undefined],
      [t('services.authoritative'), d.authoritative === null ? undefined : yesNo(d.authoritative)],
      [t('services.failoverPeer'), d.failover_peer || undefined],
    ]),
    d.reservations.length
      ? h(
          'div',
          {},
          h('h4', {}, t('services.reservations', { count: d.reservations.length })),
          table(
            [
              ['MAC', (r) => h('span', { class: 'mono' }, r.mac)],
              [t('services.address'), (r) => r.address],
              [t('services.hostname'), (r) => r.hostname],
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
  place(main, pageHead(t('services.title')));
  const { dhcp_servers: dhcp, dns_services: dns } = ix.net;
  if (!dhcp.length && !dns.length) {
    place(main, noData(t('services.noDataWhat')));
    return;
  }
  const segs = [...new Set(dhcp.map((d) => d.segment_id))].sort(by((sid) => ix.label(sid)));
  if (segs.length) place(main, h('h2', {}, t('services.dhcp')));
  for (const sid of segs) {
    const servers = dhcp.filter((d) => d.segment_id === sid);
    const active = servers.filter((d) => d.enabled).length;
    place(main, 
      h(
        'section',
        { class: 'group', 'data-testid': 'dhcp-segment' },
        h('h3', {}, ix.label(sid), ' ', active > 1 ? tag(t('services.activeServers', { count: active }), 'danger') : null),
        h('div', { class: 'grid wide' }, servers.map((d) => dhcpCard(ix, d))),
      ),
    );
  }
  if (dns.length) {
    place(main, h('h2', {}, t('services.dns')));
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
            d.enabled ? tag(t('services.serving'), 'ok') : tag(t('services.disabled')),
            d.config_read === false ? tag(t('services.notRead')) : null,
          ),
          kv([
            [t('services.listensOn'), d.listen.length ? d.listen.join(', ') : null],
            [t('services.port'), String(d.port ?? 53)],
            [
              t('services.forwardsTo'),
              d.config_read === false
                ? t('services.notRead')
                : d.forwarders.length
                  ? d.forwarders.map(forwarder).join(', ')
                  : null,
            ],
            [t('services.enabled'), yesNo(d.enabled)],
          ]),
          d.config_read === false
            ? h('p', { class: 'muted' }, t('services.configNotRead'))
            : d.host_records.length
            ? table(
                [
                  [t('services.name'), (r) => r.name],
                  [t('services.address'), (r) => r.address],
                ],
                [...d.host_records].sort(by((r) => r.name)),
                { rowTestid: 'host-record', compact: true },
              )
            : h('p', { class: 'muted' }, t('services.noHostRecords')),
        ),
      );
      main.lastChild.setAttribute('data-testid', 'dns-service');
    }
  }
}
