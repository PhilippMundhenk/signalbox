// Start page: what is wrong, why, where and how to fix it.
import { del, enc, get, post } from '../api.js';
import { confirmRemoveAck } from '../annotations.js';
import { loadNetwork, objectRef, siteFilter } from '../net.js';
import { clear, fmtAgo, fmtTime, h, place, sleep } from '../util.js';
import { checkField, empty, field, modal, pageHead, run, select, severityBadge, showError, toast } from '../ui.js';

const ORDER = { error: 0, warning: 1, info: 2 };
const GROUP_TITLE = { error: 'Errors', warning: 'Warnings', info: 'Information' };
const filters = { site: '', severity: '', resolved: false };

// Accept a finding (#186): this finding, or every finding of its check about one object.
function acknowledgeDialog(ix, f, onDone) {
  const reason = h('textarea', { rows: 3, maxlength: 500, 'data-testid': 'ack-reason' });
  const scopes = [['finding', 'Only this finding'], ...f.objects.map((id) => [`target:${id}`, `Every “${f.title}” finding about ${ix.label(id)}`])];
  const scope = select(scopes, 'finding', { 'data-testid': 'ack-scope' });
  const until = h('input', { type: 'date', 'data-testid': 'ack-until' });
  const lapse = h('input', { type: 'checkbox', 'data-testid': 'ack-lapse' });
  modal({
    title: 'Acknowledge finding',
    body: h(
      'div',
      {},
      h('p', {}, f.message),
      field('Reason', reason, 'Why this is fine, for whoever looks next.'),
      f.objects.length ? field('Applies to', scope) : null,
      field('Until (optional)', until, 'After this day it counts as a problem again.'),
      checkField('Show it again when the details change', lapse),
      h('p', { class: 'muted small' }, 'Acknowledged findings are listed apart and do not count as problems (also in Home Assistant).'),
    ),
    actions: (close) => [
      h('button', { class: 'btn', type: 'button', 'data-testid': 'ack-cancel', onclick: () => close() }, 'Cancel'),
      h('button', { class: 'btn primary', type: 'button', 'data-testid': 'ack-save', onclick: (e) => run(e.target, async () => {
        const target = scope.value.startsWith('target:') ? scope.value.slice(7) : null;
        await post(`/findings/${enc(f.id)}/acknowledge`, {
          reason: reason.value || null,
          scope: target ? 'target' : 'finding',
          target,
          until: until.value ? `${until.value}T00:00:00Z` : null,
          lapse_on_change: lapse.checked,
        });
        toast('Finding acknowledged.');
        close();
        await onDone();
      }) }, 'Acknowledge'),
    ],
  });
}

function ackLine(f, onDone) {
  const a = f.acknowledged;
  const remove = h('button', { class: 'btn small', type: 'button', 'data-testid': 'ack-remove' }, 'Remove acknowledgement');
  remove.addEventListener('click', () =>
    run(remove, async () => {
      if (!(await confirmRemoveAck())) return;
      await del(`/acknowledgements/${enc(a.id)}`);
      toast('Acknowledgement removed.');
      await onDone();
    }),
  );
  return h(
    'p',
    { class: 'ack', 'data-testid': 'ack-info' },
    h('strong', {}, 'Acknowledged'),
    a.at ? h('span', { title: fmtTime(a.at) }, ` ${fmtAgo(a.at)}`) : '',
    a.reason ? `: ${a.reason}` : '',
    a.until ? ` · until ${fmtTime(a.until)}` : '',
    a.source === 'declared' ? h('span', { class: 'muted' }, ' · declared in the desired state') : [' ', remove],
  );
}

// fixable(f): the device's integration offers the finding's remedy (Fix it, #215).
function findingCard(ix, rec, onDone, fixable = () => false) {
  const f = rec.finding;
  const resolved = Boolean(rec.resolved_at);
  let ackButton = null;
  if (!resolved && !f.acknowledged && onDone) {
    ackButton = h('button', { class: 'btn small', type: 'button', 'data-testid': 'acknowledge' }, 'Acknowledge');
    ackButton.addEventListener('click', () => acknowledgeDialog(ix, f, onDone));
  }
  return h(
    'article',
    { class: `card finding sev-${f.severity}${resolved ? ' resolved' : ''}${f.incomplete ? ' incomplete' : ''}${f.acknowledged ? ' acknowledged' : ''}`, 'data-testid': 'finding', 'data-rule': f.rule_id, 'data-severity': f.severity },
    h('div', { class: 'finding-head' }, f.incomplete ? h('span', { class: 'badge sev-unknown' }, 'Not checked') : severityBadge(f.severity), h('h3', { 'data-testid': 'finding-title' }, f.title), resolved ? h('span', { class: 'badge status-ok', 'data-testid': 'resolved' }, 'Resolved') : null),
    h('p', { 'data-testid': 'finding-message' }, f.message),
    f.objects.length ? h('p', { class: 'objects' }, h('span', { class: 'muted' }, 'Affects: '), f.objects.map((id, i) => [i ? ', ' : '', objectRef(ix, id)])) : null,
    f.fix ? h('p', { class: 'fix', 'data-testid': 'finding-fix' }, h('strong', {}, 'How to fix: '), f.fix) : null,
    !resolved && fixable(f) ? h('p', {}, h('a', { class: 'btn small', href: `#/device/${encodeURIComponent(f.objects[0])}`, 'data-testid': 'finding-fix-it' }, 'Fix it on the device page')) : null,
    f.acknowledged ? ackLine(f, onDone) : null,
    h(
      'p',
      { class: 'muted small' },
      h('span', { title: fmtTime(rec.first_seen), 'data-testid': 'finding-since' }, `Since ${fmtAgo(rec.first_seen)}`),
      resolved ? ` · resolved ${fmtAgo(rec.resolved_at)}` : '',
      ` · rule ${f.rule_id}`,
      ackButton ? [' ', ackButton] : null,
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
  const adapters = records.some((r) => r.finding.remedy) ? await get('/adapters') : [];
  if (!ctx.alive(id)) return;
  const fixable = (f) => {
    const dev = f.remedy && f.objects.length ? ix.devices.get(f.objects[0]) : null;
    const a = dev && adapters.find((x) => x.id === dev.adapter);
    return Boolean(a && (a.remedies || []).some((r) => r.id === f.remedy));
  };
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
    const acknowledged = shown.filter((r) => r.finding.acknowledged);
    const problems = shown.filter((r) => !r.finding.incomplete && !r.finding.acknowledged);
    const unchecked = shown.filter((r) => r.finding.incomplete && !r.finding.acknowledged);
    const card = (r) => findingCard(ix, r, reload, fixable);
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
      place(list, h('section', { class: 'group', 'data-testid': `group-${sev}` }, h('h2', {}, `${GROUP_TITLE[sev]} (${group.length})`), group.map(card)));
    }
    if (unchecked.length) {
      place(list, 
        h(
          'section',
          { class: 'group unchecked', 'data-testid': 'group-incomplete' },
          h('h2', {}, `Could not check (${unchecked.length})`),
          h('p', { class: 'muted' }, 'These checks are missing data, for example because a device does not report it or could not be read. They are not confirmed problems.'),
          unchecked.map(card),
        ),
      );
    }
    if (acknowledged.length) {
      place(list,
        h(
          'details',
          { class: 'group acknowledged', 'data-testid': 'group-acknowledged' },
          h('summary', {}, h('h2', {}, `Acknowledged (${acknowledged.length})`)),
          h('p', { class: 'muted' }, 'Findings you have accepted. They are not counted as problems; remove an acknowledgement to count it again.'),
          acknowledged.map(card),
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
