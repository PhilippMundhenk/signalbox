// Routed paths on the topology page (#253): the layer-3 path of each stored trace (which router
// is in front of which, which hops lie in a VPN tunnel), "Trace now" with its progress, and
// the permission each source needs. Hop names and addresses are untrusted text: text nodes only.
import { get, post } from '../api.js';
import { by, clear, fmtAgo, h, place } from '../util.js';
import { card, field, run, select, table, tag, toast } from '../ui.js';
import { fmtNumber, t } from '../i18n.js';
import { errorFix, errorMessage } from '../texts.js';

const DOCS = 'https://github.com/PhilippMundhenk/signalbox/blob/main/docs/TRACES.md';
const PURPOSE = { gateway: 'traces.purpose.gateway', internet: 'traces.purpose.internet', address: 'traces.purpose.address' };
const POLL_MS = 1500;

function hopChip(hop) {
  if (!hop.address) return h('span', { class: 'hop none', 'data-testid': 'hop', 'data-kind': 'none', title: t('traces.hop.noAnswer', { ttl: hop.ttl }) }, '*');
  const text = hop.name ? `${hop.name}` : hop.address;
  const title = [t('traces.hop.title', { ttl: hop.ttl }), hop.address, hop.rtt_ms !== null && hop.rtt_ms !== undefined ? t('traces.ms', { value: hop.rtt_ms }) : null, hop.tunnel_id ? t('traces.hop.inTunnel') : null, hop.kind === 'private' && !hop.name ? t('traces.hop.privateUnknown') : null].filter(Boolean).join(' · ');
  const cls = ['hop', `kind-${hop.kind}`, hop.tunnel_id ? 'tunnel' : ''].join(' ').trim();
  return h('span', { class: cls, 'data-testid': 'hop', 'data-kind': hop.kind, 'data-tunnel': hop.tunnel_id ? 'yes' : 'no', title }, hop.tunnel_id ? t('traces.hop.tunnelName', { name: text }) : text);
}

function pathCell(p) {
  if (p.error) return h('span', { class: 'error', 'data-testid': 'trace-error' }, errorMessage({ message: p.error, message_id: p.message_id, params: p.params }), p.fix ? h('small', { class: 'muted block' }, errorFix({ fix: p.fix, fix_id: p.fix_id, params: p.params })) : null, p.remedy && p.source !== 'signalbox' ? h('a', { class: 'small block', href: `#/device/${encodeURIComponent(p.source)}`, 'data-testid': 'trace-fix-link' }, t('traces.fixOnDevice')) : null);
  const parts = [h('span', { class: 'hop source' }, p.source_name)];
  for (const hop of p.hops) parts.push(h('span', { class: 'arrow', 'aria-hidden': 'true' }, ' → '), hopChip(hop));
  if (!p.reached) parts.push(h('span', { class: 'arrow', 'aria-hidden': 'true' }, ' → '), h('span', { class: 'hop none' }, '…'));
  return h('span', { class: 'route', 'data-testid': 'route' }, parts);
}

function stateTag(p) {
  if (p.error) return tag(t('traces.state.failed'), 'danger');
  return p.reached ? tag(t('traces.state.reached'), 'ok') : tag(t('traces.state.partial'), 'warn');
}

function inFront(data, names) {
  if (!data.in_front.length) return null;
  return h(
    'ul',
    { class: 'plain', 'data-testid': 'in-front' },
    data.in_front.map((x) =>
      h('li', { 'data-testid': 'in-front-row' }, x.front ? t('traces.inFront.known', { front: names.get(x.front) || x.front, behind: names.get(x.behind) || x.behind }) : t('traces.inFront.unknown', { address: x.address, kind: x.kind === 'cgnat' ? t('traces.inFront.cgnat') : t('traces.inFront.private'), behind: names.get(x.behind) || x.behind })),
    ),
  );
}

function progress(status) {
  if (!status.total) return null;
  const text = status.running ? t('traces.progress.running', { done: fmtNumber(status.done), total: fmtNumber(status.total) }) : t('traces.progress.last', { ago: status.finished_at ? fmtAgo(status.finished_at) : '', total: fmtNumber(status.total), limited: status.limited ? t('traces.progress.limited') : '' });
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
    const source = select([['', t('traces.allSources')], ...sources.map((x) => [x.id, x.name])], '', { 'data-testid': 'trace-source', 'aria-label': t('traces.traceFrom') });
    const target = select([['', t('traces.allTargets')], ...nodes.filter((n) => n.role !== 'remote').sort(by((n) => n.name)).map((n) => [n.id, n.name]), ['address', t('traces.anAddress')]], '', { 'data-testid': 'trace-target', 'aria-label': t('traces.traceTo') });
    const address = h('input', { type: 'text', maxlength: '45', placeholder: '192.0.2.1', 'data-testid': 'trace-address', hidden: true, autocomplete: 'off' });
    target.addEventListener('change', () => {
      address.hidden = target.value !== 'address';
    });
    const start = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'trace-now', disabled: data.status.running }, t('traces.traceNow'));
    start.addEventListener('click', () =>
      run(start, async () => {
        const body = {};
        if (source.value) body.source = source.value;
        if (target.value === 'address') body.target = address.value.trim();
        else if (target.value) body.target = target.value;
        const status = await post('/traces', body);
        toast(t('traces.started', { total: fmtNumber(status.total) }));
        await refresh();
      }),
    );
    return h('div', { class: 'filters' }, field(t('traces.from'), source), field(t('traces.to'), target), address, start);
  }

  function sourcesNote(data) {
    const can = data.sources.filter((x) => x.supported && x.id !== 'signalbox');
    const cannot = data.sources.filter((x) => !x.supported && x.role === 'gateway');
    return h(
      'p',
      { class: 'muted small', 'data-testid': 'trace-sources' },
      can.length ? [t('traces.runOn'), can.map((x, i) => [i ? ', ' : '', h('span', { title: t('traces.needs', { permission: x.permission }) }, x.name)]), t('traces.runOnEnd')] : t('traces.noneCanTrace'),
      cannot.length ? t('traces.cannotTrace', { names: cannot.map((x) => x.name).join(', ') }) : '',
      h('a', { href: DOCS, target: '_blank', rel: 'noopener noreferrer' }, t('traces.permissions')),
    );
  }

  function draw(data) {
    clear(box);
    place(box, h('h2', {}, t('traces.title')));
    if (!data.status.enabled) {
      place(box, h('p', { class: 'muted', 'data-testid': 'traces-off' }, t('traces.off'), h('a', { href: DOCS, target: '_blank', rel: 'noopener noreferrer' }, t('traces.whatItNeeds'))));
      return;
    }
    place(box, h('p', { class: 'muted' }, t('traces.intro'), data.status.interval_hours ? t('traces.interval', { hours: data.status.interval_hours }) : ''), controls(data), progress(data.status), sourcesNote(data));
    if (!data.paths.length) {
      place(box, h('p', { class: 'muted', 'data-testid': 'no-traces' }, t('traces.none')));
      return;
    }
    place(
      box,
      inFront(data, names),
      table(
        [
          [t('traces.from'), (p) => p.source_name],
          [t('traces.to'), (p) => [p.target_name || p.target, ' ', tag(PURPOSE[p.purpose] ? t(PURPOSE[p.purpose]) : p.purpose)]],
          [t('traces.col.path'), pathCell],
          [t('traces.col.time'), (p) => (p.rtt_ms !== null ? t('traces.ms', { value: p.rtt_ms }) : null)],
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
