// DHCP servers and IPv6 routers seen answering (#184, #61), on the segments page: from the
// devices (their own leases, rogue-server alerts) and, while probes are on, from Signalbox's
// own probe; "Probe now" with its state per interface. Addresses and names are untrusted
// text: text nodes only.
import { get, post } from '../api.js';
import { by, clear, fmtAgo, h, place } from '../util.js';
import { run, table, tag, toast } from '../ui.js';

const DOCS = 'https://github.com/PhilippMundhenk/signalbox/blob/main/docs/PROBES.md';
const KIND = { dhcpv4: 'DHCP', dhcpv6: 'DHCPv6', ra: 'IPv6 router' };
const POLL_MS = 1500;

function server(s) {
  return [s.server_address || '', s.server_mac ? h('small', { class: 'muted block' }, s.server_mac) : null];
}

function offers(s) {
  const parts = [];
  if (s.routers.length) parts.push(`gateway ${s.routers.join(', ')}`);
  if (s.dns_servers.length) parts.push(`DNS ${s.dns_servers.join(', ')}`);
  if (s.prefixes.length) parts.push(`prefix ${s.prefixes.join(', ')}`);
  if (s.relay) parts.push(`via relay ${s.relay}`);
  return parts.join(' · ');
}

function state(s) {
  if (s.known_as) return tag(`known: ${s.known_name || s.known_as}`, 'ok');
  if (s.kind === 'ra' && s.router_lifetime === 0) return tag('routes only', 'warn');
  return tag('foreign', 'danger');
}

function legs(status) {
  if (!status.legs.length) return null;
  return h(
    'ul',
    { class: 'plain small', 'data-testid': 'probe-legs' },
    status.legs.map((l) => h('li', { 'data-testid': 'probe-leg', 'data-state': l.state }, `${l.interface}: ${l.state}`, l.state === 'done' ? ` (${l.answers} answers)` : '', l.errors.length ? h('span', { class: 'muted' }, ` — ${l.errors.join('; ')}`) : null)),
  );
}

export function foreignServersCard(ctx) {
  const box = h('section', { class: 'card', 'data-testid': 'foreign-servers' });
  const id = ctx.renderId;
  let timer = null;
  ctx.onCleanup(() => clearTimeout(timer));

  function controls(status) {
    const start = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'probe-now', disabled: status.running }, 'Probe now');
    start.addEventListener('click', () =>
      run(start, async () => {
        const got = await post('/probes', {});
        toast(`Probing ${got.legs.filter((l) => l.state !== 'skipped').length} interfaces.`);
        await refresh();
      }),
    );
    const when = status.running ? 'Probing…' : status.finished_at ? `Last probe ${fmtAgo(status.finished_at)}` : 'Not probed yet.';
    return h('div', { class: 'filters' }, start, h('span', { class: 'muted small', 'data-testid': 'probe-progress', 'data-running': status.running ? 'yes' : 'no' }, when, status.interval_hours ? ` · every ${status.interval_hours} h` : ''));
  }

  function draw(data) {
    clear(box);
    place(box, h('h2', {}, 'DHCP servers and routers answering'));
    const s = data.status;
    if (s.enabled) {
      place(box, h('p', { class: 'muted' }, "Signalbox's host sends one DHCPDISCOVER (never a request: no lease is taken) and one IPv6 router solicitation on each network it is attached to. Servers that are no device Signalbox knows are findings."), controls(s), legs(s));
    } else {
      place(box, h('p', { class: 'muted', 'data-testid': 'probes-off' }, "Probes are off: this lists only servers the devices report (their own leases, rogue DHCP alerts). With probes.enabled: true Signalbox's host also asks every network it is attached to who answers DHCP and router solicitations. ", h('a', { href: DOCS, target: '_blank', rel: 'noopener noreferrer' }, 'What it needs')));
    }
    if (!data.servers.length) {
      place(box, h('p', { class: 'muted', 'data-testid': 'no-servers' }, s.enabled ? 'No answers yet.' : 'Nothing reported.'));
      return;
    }
    place(
      box,
      table(
        [
          ['Network', (x) => x.segment_name || x.site_id],
          ['Kind', (x) => KIND[x.kind] || x.kind],
          ['Server', server],
          ['Hands out', offers],
          ['Seen by', (x) => [x.seen_by.join(', '), x.where.length ? h('small', { class: 'muted block' }, `MAC on ${x.where.join(', ')}`) : null]],
          ['Last seen', (x) => fmtAgo(x.last_seen)],
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
