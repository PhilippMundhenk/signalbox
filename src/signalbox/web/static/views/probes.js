// DHCP servers and IPv6 routers seen answering (#184, #61), on the segments page: from the
// devices (their own leases, rogue-server alerts) and, while probes are on, from Signalbox's
// own probe; "Probe now" with its state per interface. Addresses and names are untrusted
// text: text nodes only.
import { get, post } from '../api.js';
import { by, clear, fmtAgo, h, place } from '../util.js';
import { t } from '../i18n.js';
import { run, table, tag, toast } from '../ui.js';

const DOCS = 'https://github.com/PhilippMundhenk/signalbox/blob/main/docs/PROBES.md';
const KIND = { dhcpv4: 'probes.kind.dhcpv4', dhcpv6: 'probes.kind.dhcpv6', ra: 'probes.kind.ra' };
const POLL_MS = 1500;

function server(s) {
  return [s.server_address || '', s.server_mac ? h('small', { class: 'muted block' }, s.server_mac) : null];
}

function offers(s) {
  const parts = [];
  if (s.routers.length) parts.push(t('probes.offers.gateway', { list: s.routers.join(', ') }));
  if (s.dns_servers.length) parts.push(t('probes.offers.dns', { list: s.dns_servers.join(', ') }));
  if (s.prefixes.length) parts.push(t('probes.offers.prefix', { list: s.prefixes.join(', ') }));
  if (s.relay) parts.push(t('probes.offers.relay', { relay: s.relay }));
  return parts.join(' · ');
}

function state(s) {
  if (s.known_as) return tag(t('probes.known', { name: s.known_name || s.known_as }), 'ok');
  if (s.kind === 'ra' && s.router_lifetime === 0) return tag(t('probes.routesOnly'), 'warn');
  return tag(t('probes.foreign'), 'danger');
}

function legs(status) {
  if (!status.legs.length) return null;
  return h(
    'ul',
    { class: 'plain small', 'data-testid': 'probe-legs' },
    status.legs.map((l) => h('li', { 'data-testid': 'probe-leg', 'data-state': l.state }, `${l.interface}: ${l.state}`, l.state === 'done' ? ` (${t('probes.answers', { count: l.answers })})` : '', l.errors.length ? h('span', { class: 'muted' }, ` — ${l.errors.join('; ')}`) : null)),
  );
}

export function foreignServersCard(ctx) {
  const box = h('section', { class: 'card', 'data-testid': 'foreign-servers' });
  const id = ctx.renderId;
  let timer = null;
  ctx.onCleanup(() => clearTimeout(timer));

  function controls(status) {
    const start = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'probe-now', disabled: status.running }, t('probes.probeNow'));
    start.addEventListener('click', () =>
      run(start, async () => {
        const got = await post('/probes', {});
        toast(t('probes.probing', { count: got.legs.filter((l) => l.state !== 'skipped').length }));
        await refresh();
      }),
    );
    const when = status.running ? t('probes.running') : status.finished_at ? t('probes.last', { ago: fmtAgo(status.finished_at) }) : t('probes.never');
    return h('div', { class: 'filters' }, start, h('span', { class: 'muted small', 'data-testid': 'probe-progress', 'data-running': status.running ? 'yes' : 'no' }, when, status.interval_hours ? ` · ${t('probes.every', { n: status.interval_hours })}` : ''));
  }

  function draw(data) {
    clear(box);
    place(box, h('h2', {}, t('probes.title')));
    const s = data.status;
    if (s.enabled) {
      place(box, h('p', { class: 'muted' }, t('probes.on')), controls(s), legs(s));
    } else {
      place(box, h('p', { class: 'muted', 'data-testid': 'probes-off' }, t('probes.off'), h('a', { href: DOCS, target: '_blank', rel: 'noopener noreferrer' }, t('probes.whatItNeeds'))));
    }
    if (!data.servers.length) {
      place(box, h('p', { class: 'muted', 'data-testid': 'no-servers' }, s.enabled ? t('probes.noAnswers') : t('probes.nothingReported')));
      return;
    }
    place(
      box,
      table(
        [
          [t('probes.col.network'), (x) => x.segment_name || x.site_id],
          [t('probes.col.kind'), (x) => (KIND[x.kind] ? t(KIND[x.kind]) : x.kind)],
          [t('probes.col.server'), server],
          [t('probes.col.handsOut'), offers],
          [t('probes.col.seenBy'), (x) => [x.seen_by.join(', '), x.where.length ? h('small', { class: 'muted block' }, t('probes.macOn', { where: x.where.join(', ') })) : null]],
          [t('probes.col.lastSeen'), (x) => fmtAgo(x.last_seen)],
          ['', state],
        ],
        [...data.servers].sort(by((x) => `${x.known_as ? 1 : 0} ${x.segment_name || ''} ${x.server_address || ''}`)),
        { testid: 'servers', rowTestid: 'server-row', rowAttrs: (x) => ({ 'data-id': x.id, 'data-known': x.known_as ? 'yes' : 'no' }) },
      ),
    );
  }

  async function refresh() {
    clearTimeout(timer);
    let data;
    try {
      data = await get('/probes');
    } catch {
      timer = setTimeout(refresh, POLL_MS * 2);
      return;
    }
    if (!ctx.alive(id)) return;
    draw(data);
    if (data.status.running) timer = setTimeout(refresh, POLL_MS);
  }

  refresh();
  return box;
}
