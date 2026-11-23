// Routed paths on the topology page (#253): the layer-3 path of each stored trace (which router
// is in front of which, which hops lie in a VPN tunnel), "Trace now" with its progress, and
// the permission each source needs. Hop names and addresses are untrusted text: text nodes only.
import { get, post } from '../api.js';
import { by, clear, fmtAgo, h, place } from '../util.js';
import { card, field, run, select, table, tag, toast } from '../ui.js';

const DOCS = 'https://github.com/PhilippMundhenk/signalbox/blob/main/docs/TRACES.md';
const PURPOSE = { gateway: 'gateway', internet: 'internet', address: 'address' };
const POLL_MS = 1500;

function hopChip(hop) {
  if (!hop.address) return h('span', { class: 'hop none', 'data-testid': 'hop', 'data-kind': 'none', title: `hop ${hop.ttl}: no answer` }, '*');
  const text = hop.name ? `${hop.name}` : hop.address;
  const title = [`hop ${hop.ttl}`, hop.address, hop.rtt_ms !== null && hop.rtt_ms !== undefined ? `${hop.rtt_ms} ms` : null, hop.tunnel_id ? 'in a VPN tunnel' : null, hop.kind === 'private' && !hop.name ? 'private address, not a known device' : null].filter(Boolean).join(' · ');
  const cls = ['hop', `kind-${hop.kind}`, hop.tunnel_id ? 'tunnel' : ''].join(' ').trim();
  return h('span', { class: cls, 'data-testid': 'hop', 'data-kind': hop.kind, 'data-tunnel': hop.tunnel_id ? 'yes' : 'no', title }, hop.tunnel_id ? `${text} (tunnel)` : text);
}

function pathCell(p) {
  if (p.error) return h('span', { class: 'error', 'data-testid': 'trace-error' }, p.error, p.fix ? h('small', { class: 'muted block' }, p.fix) : null, p.remedy && p.source !== 'signalbox' ? h('a', { class: 'small block', href: `#/device/${encodeURIComponent(p.source)}`, 'data-testid': 'trace-fix-link' }, 'Fix it on the device page') : null);
  const parts = [h('span', { class: 'hop source' }, p.source_name)];
  for (const hop of p.hops) parts.push(h('span', { class: 'arrow', 'aria-hidden': 'true' }, ' → '), hopChip(hop));
  if (!p.reached) parts.push(h('span', { class: 'arrow', 'aria-hidden': 'true' }, ' → '), h('span', { class: 'hop none' }, '…'));
  return h('span', { class: 'route', 'data-testid': 'route' }, parts);
}

function stateTag(p) {
  if (p.error) return tag('failed', 'danger');
  return p.reached ? tag('reached', 'ok') : tag('partial', 'warn');
}

function inFront(data, names) {
  if (!data.in_front.length) return null;
  return h(
    'ul',
    { class: 'plain', 'data-testid': 'in-front' },
    data.in_front.map((x) =>
      h('li', { 'data-testid': 'in-front-row' }, x.front ? `${names.get(x.front) || x.front} is in front of ${names.get(x.behind) || x.behind}` : `an unknown router (${x.address}, ${x.kind === 'cgnat' ? 'provider NAT' : 'private address'}) is in front of ${names.get(x.behind) || x.behind}`),
    ),
  );
}

function progress(status) {
  if (!status.total) return null;
  const text = status.running ? `Tracing: ${status.done} of ${status.total} done` : `Last run ${status.finished_at ? fmtAgo(status.finished_at) : ''}: ${status.total} traces${status.limited ? ' (limited by traces.max_pairs)' : ''}`;
  return h('p', { class: 'muted small', 'data-testid': 'trace-progress', 'data-running': status.running ? 'yes' : 'no' }, text);
}

export function routedPathsCard(ctx, nodes) {
  const box = h('section', { class: 'card routed', 'data-testid': 'routed-paths' });
  const id = ctx.renderId;
  let timer = null;
  ctx.onCleanup(() => clearTimeout(timer));
  const names = new Map(nodes.map((n) => [n.id, n.name]));
  names.set('signalbox', 'Signalbox');

  function controls(data) {
    const sources = data.sources.filter((x) => x.supported);
    const source = select([['', 'All gateways (and Signalbox)'], ...sources.map((x) => [x.id, x.name])], '', { 'data-testid': 'trace-source', 'aria-label': 'Trace from' });
    const target = select([['', 'Every other gateway and the internet'], ...nodes.filter((n) => n.role !== 'remote').sort(by((n) => n.name)).map((n) => [n.id, n.name]), ['address', 'An address…']], '', { 'data-testid': 'trace-target', 'aria-label': 'Trace to' });
    const address = h('input', { type: 'text', maxlength: '45', placeholder: '192.0.2.1', 'data-testid': 'trace-address', hidden: true, autocomplete: 'off' });
    target.addEventListener('change', () => {
      address.hidden = target.value !== 'address';
    });
    const start = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'trace-now', disabled: data.status.running }, 'Trace now');
    start.addEventListener('click', () =>
      run(start, async () => {
        const body = {};
        if (source.value) body.source = source.value;
        if (target.value === 'address') body.target = address.value.trim();
        else if (target.value) body.target = target.value;
        const status = await post('/traces', body);
        toast(`Tracing ${status.total} paths.`);
        await refresh();
      }),
    );
    return h('div', { class: 'filters' }, field('From', source), field('To', target), address, start);
  }

  function sourcesNote(data) {
    const can = data.sources.filter((x) => x.supported && x.id !== 'signalbox');
    const cannot = data.sources.filter((x) => !x.supported && x.role === 'gateway');
    return h(
      'p',
      { class: 'muted small', 'data-testid': 'trace-sources' },
      can.length ? ['Traces run on ', can.map((x, i) => [i ? ', ' : '', h('span', { title: `needs ${x.permission}` }, x.name)]), '. '] : 'No device here can trace yet. ',
      cannot.length ? `Cannot trace (not supported by the integration): ${cannot.map((x) => x.name).join(', ')}. ` : '',
      h('a', { href: DOCS, target: '_blank', rel: 'noopener noreferrer' }, 'Permissions per device'),
    );
  }

  function draw(data) {
    clear(box);
    place(box, h('h2', {}, 'Routed paths'));
    if (!data.status.enabled) {
      place(box, h('p', { class: 'muted', 'data-testid': 'traces-off' }, 'Path traces are off. With traces.enabled: true in the configuration, the routers Signalbox reads (and Signalbox itself) run traceroutes to each other and to the internet, and this shows the routed path: which router is in front of which, and which traffic goes through a VPN tunnel. ', h('a', { href: DOCS, target: '_blank', rel: 'noopener noreferrer' }, 'What it needs')));
      return;
    }
    place(box, h('p', { class: 'muted' }, 'The layer-3 path from each router to the others and to the internet, as the routers themselves trace it. Switches and access points do not appear here (they are not routers).', data.status.interval_hours ? ` Traced every ${data.status.interval_hours} h.` : ''), controls(data), progress(data.status), sourcesNote(data));
    if (!data.paths.length) {
      place(box, h('p', { class: 'muted', 'data-testid': 'no-traces' }, 'No traces yet: press Trace now.'));
      return;
    }
    place(
      box,
      inFront(data, names),
      table(
        [
          ['From', (p) => p.source_name],
          ['To', (p) => [p.target_name || p.target, ' ', tag(PURPOSE[p.purpose] || p.purpose)]],
          ['Path', pathCell],
          ['Time', (p) => (p.rtt_ms !== null ? `${p.rtt_ms} ms` : null)],
          ['', stateTag],
        ],
        [...data.paths].sort(by((p) => `${p.source_name} ${p.target_name || p.target}`)),
        { testid: 'traces', rowTestid: 'trace-row', rowAttrs: (p) => ({ 'data-id': p.id, 'data-tunnel': p.tunnels.length ? 'yes' : 'no' }) },
      ),
    );
  }

  async function refresh() {
    clearTimeout(timer);
    let data;
    try {
      data = await get('/traces');
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
