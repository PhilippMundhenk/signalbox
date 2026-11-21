// Start page: what is wrong, why, where and how to fix it.
import { get, post } from '../api.js';
import { loadNetwork, objectRef, siteFilter } from '../net.js';
import { clear, fmtAgo, fmtTime, h, place, sleep } from '../util.js';
import { empty, pageHead, run, select, severityBadge, showError, toast } from '../ui.js';

const ORDER = { error: 0, warning: 1, info: 2 };
const GROUP_TITLE = { error: 'Errors', warning: 'Warnings', info: 'Information' };
const filters = { site: '', severity: '', resolved: false };

function findingCard(ix, rec) {
  const f = rec.finding;
  const resolved = Boolean(rec.resolved_at);
  return h(
    'article',
    { class: `card finding sev-${f.severity}${resolved ? ' resolved' : ''}${f.incomplete ? ' incomplete' : ''}`, 'data-testid': 'finding', 'data-rule': f.rule_id, 'data-severity': f.severity },
    h('div', { class: 'finding-head' }, f.incomplete ? h('span', { class: 'badge sev-unknown' }, 'Not checked') : severityBadge(f.severity), h('h3', { 'data-testid': 'finding-title' }, f.title), resolved ? h('span', { class: 'badge status-ok', 'data-testid': 'resolved' }, 'Resolved') : null),
    h('p', { 'data-testid': 'finding-message' }, f.message),
    f.objects.length ? h('p', { class: 'objects' }, h('span', { class: 'muted' }, 'Affects: '), f.objects.map((id, i) => [i ? ', ' : '', objectRef(ix, id)])) : null,
    f.fix ? h('p', { class: 'fix', 'data-testid': 'finding-fix' }, h('strong', {}, 'How to fix: '), f.fix) : null,
    h(
      'p',
      { class: 'muted small' },
      h('span', { title: fmtTime(rec.first_seen), 'data-testid': 'finding-since' }, `Since ${fmtAgo(rec.first_seen)}`),
      resolved ? ` · resolved ${fmtAgo(rec.resolved_at)}` : '',
      ` · rule ${f.rule_id}`,
    ),
  );
}

function matches(ix, rec) {
  const f = rec.finding;
  if (filters.severity && f.severity !== filters.severity) return false;
  if (filters.site && !f.objects.some((id) => ix.siteOf(id) === filters.site)) return false;
  return true;
}

export async function renderFindings(main, ctx) {
  const id = ctx.renderId;
  let ix = await loadNetwork();
  let records = await get(`/findings${filters.resolved ? '?resolved=true' : ''}`);
  if (!ctx.alive(id)) return;
  const list = h('div', { 'data-testid': 'findings' });

  const draw = () => {
    clear(list);
    if (!ix.deviceList.length) {
      place(list, 
        empty(
          'empty',
          'No devices yet',
          h('p', { class: 'muted' }, 'Signalbox reads your router, switches and access points and checks that they agree with each other. Add your first device to start.'),
          h('p', {}, h('a', { class: 'btn primary', href: '#/devices/new', 'data-testid': 'empty-add-device' }, 'Add a device')),
        ),
      );
      return;
    }
    const shown = records.filter((r) => matches(ix, r));
    const problems = shown.filter((r) => !r.finding.incomplete);
    const unchecked = shown.filter((r) => r.finding.incomplete);
    if (!ix.net.devices.length) {
      place(list, 
        h(
          'div',
          { class: 'card empty', 'data-testid': 'not-read' },
          h('h2', {}, 'Not checked yet'),
          h('p', { class: 'muted' }, 'Your devices have not been read yet. Signalbox reads them regularly; use “Read all devices now” to start at once.'),
        ),
      );
    } else if (!problems.some((r) => !r.resolved_at)) {
      place(list, 
        h(
          'div',
          { class: 'card empty good', 'data-testid': 'no-problems' },
          h('h2', {}, 'No problems found'),
          h('p', { class: 'muted' }, records.length && shown.length !== records.length ? 'Nothing matches the filter.' : 'Your devices agree with each other on everything Signalbox checks.'),
        ),
      );
    }
    for (const sev of ['error', 'warning', 'info']) {
      const group = problems.filter((r) => r.finding.severity === sev);
      if (!group.length) continue;
      place(list, h('section', { class: 'group', 'data-testid': `group-${sev}` }, h('h2', {}, `${GROUP_TITLE[sev]} (${group.length})`), group.map((r) => findingCard(ix, r))));
    }
    if (unchecked.length) {
      place(list, 
        h(
          'section',
          { class: 'group unchecked', 'data-testid': 'group-incomplete' },
          h('h2', {}, `Could not check (${unchecked.length})`),
          h('p', { class: 'muted' }, 'These checks are missing data, for example because a device does not report it or could not be read. They are not confirmed problems.'),
          unchecked.map((r) => findingCard(ix, r)),
        ),
      );
    }
  };

  const reload = async () => {
    ix = await loadNetwork();
    records = await get(`/findings${filters.resolved ? '?resolved=true' : ''}`);
    records.sort((a, b) => ORDER[a.finding.severity] - ORDER[b.finding.severity] || a.finding.title.localeCompare(b.finding.title));
    if (ctx.alive(id)) draw();
  };
  records.sort((a, b) => ORDER[a.finding.severity] - ORDER[b.finding.severity] || a.finding.title.localeCompare(b.finding.title));

  const observe = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'observe' }, 'Read all devices now');
  observe.addEventListener('click', () =>
    run(observe, async () => {
      const before = (await get('/health')).last_run;
      await post('/observe');
      toast('Reading all devices…');
      for (let i = 0; i < 10 && ctx.alive(id); i += 1) {
        await sleep(i < 3 ? 700 : 1500);
        const health = await get('/health');
        if (health.last_run && health.last_run !== before) break;
      }
      await reload();
    }),
  );
  const sev = select([['', 'All severities'], ['error', 'Errors'], ['warning', 'Warnings'], ['info', 'Information']], filters.severity, { 'aria-label': 'Severity', 'data-testid': 'filter-severity' });
  sev.addEventListener('change', () => {
    filters.severity = sev.value;
    draw();
  });
  const site = siteFilter(ix, filters.site, (v) => {
    filters.site = v;
    draw();
  });
  const resolved = h('input', { type: 'checkbox', checked: filters.resolved, 'data-testid': 'show-resolved' });
  resolved.addEventListener('change', () => {
    filters.resolved = resolved.checked;
    reload().catch(showError);
  });

  place(main, 
    pageHead('Findings', observe),
    ix.deviceList.length ? h('div', { class: 'filters' }, site, sev, h('label', { class: 'check' }, resolved, ' Show resolved')) : null,
    list,
  );
  draw();
  const timer = setInterval(() => reload().catch(() => null), 30000);
  ctx.onCleanup(() => clearInterval(timer));
}
