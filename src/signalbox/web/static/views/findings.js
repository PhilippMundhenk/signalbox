// Start page: what is wrong, why, where and how to fix it.
import { compare, fmtNumber, t } from '../i18n.js';
import { findingFix, findingMessage, findingTitle } from '../texts.js';
import { del, enc, get, post } from '../api.js';
import { confirmRemoveAck } from '../annotations.js';
import { loadNetwork, objectRef, siteFilter } from '../net.js';
import { clear, fmtAgo, fmtTime, h, place, sleep } from '../util.js';
import { fixesNotice } from './fixes.js';
import { checkField, empty, field, modal, pageHead, run, select, severityBadge, showError, slot, toast } from '../ui.js';

const ORDER = { error: 0, warning: 1, info: 2 };
const GROUP_TITLE = { error: 'findings.group.error', warning: 'findings.group.warning', info: 'findings.group.info' };
const filters = { site: '', severity: '', resolved: false };

// Accept a finding (#186): this finding, or every finding of its check about one object.
function acknowledgeDialog(ix, f, onDone) {
  const reason = h('textarea', { rows: 3, maxlength: 500, 'data-testid': 'ack-reason' });
  const scopes = [['finding', t('findings.ack.scopeOne')], ...f.objects.map((id) => [`target:${id}`, t('findings.ack.scopeTarget', { title: f.title, object: ix.label(id) })])];
  const scope = select(scopes, 'finding', { 'data-testid': 'ack-scope' });
  const until = h('input', { type: 'date', 'data-testid': 'ack-until' });
  const lapse = h('input', { type: 'checkbox', 'data-testid': 'ack-lapse' });
  const problem = slot(); // the dialog's one place for a refusal, in view next to the button
  modal({
    title: t('findings.ack.dialogTitle'),
    body: h(
      'div',
      {},
      h('p', {}, findingMessage(f)),
      field(t('findings.ack.reason'), reason, t('findings.ack.reasonHint')),
      f.objects.length ? field(t('findings.ack.appliesTo'), scope) : null,
      field(t('findings.ack.untilOptional'), until, t('findings.ack.untilHint')),
      checkField(t('findings.ack.lapse'), lapse),
      h('p', { class: 'muted small' }, t('findings.ack.note')),
      problem,
    ),
    actions: (close) => [
      h('button', { class: 'btn', type: 'button', 'data-testid': 'ack-cancel', onclick: () => close() }, t('common.cancel')),
      h('button', { class: 'btn primary', type: 'button', 'data-testid': 'ack-save', onclick: (e) => run(e.target, async () => {
        const target = scope.value.startsWith('target:') ? scope.value.slice(7) : null;
        await post(`/findings/${enc(f.id)}/acknowledge`, {
          reason: reason.value || null,
          scope: target ? 'target' : 'finding',
          target,
          until: until.value ? `${until.value}T00:00:00Z` : null,
          lapse_on_change: lapse.checked,
        });
        toast(t('findings.ack.done'));
        close();
        await onDone();
      }, problem) }, t('findings.ack.submit')),
    ],
  });
}

function ackLine(f, onDone) {
  const a = f.acknowledged;
  const remove = h('button', { class: 'btn small', type: 'button', 'data-testid': 'ack-remove' }, t('findings.ack.remove'));
  remove.addEventListener('click', () =>
    run(remove, async () => {
      if (!(await confirmRemoveAck())) return;
      await del(`/acknowledgements/${enc(a.id)}`);
      toast(t('findings.ack.removed'));
      await onDone();
    }),
  );
  return h(
    'p',
    { class: 'ack', 'data-testid': 'ack-info' },
    h('strong', {}, t('findings.ack.label')),
    a.at ? h('span', { title: fmtTime(a.at) }, ` ${fmtAgo(a.at)}`) : '',
    a.reason ? `: ${a.reason}` : '',
    a.until ? ` · ${t('findings.ack.until', { time: fmtTime(a.until) })}` : '',
    a.source === 'declared' ? h('span', { class: 'muted' }, ` · ${t('findings.ack.declared')}`) : [' ', remove],
  );
}

// fixable(f): the device's integration offers the finding's remedy (Fix it, #215).
function findingCard(ix, rec, onDone, fixable = () => false) {
  const f = rec.finding;
  const resolved = Boolean(rec.resolved_at);
  let ackButton = null;
  if (!resolved && !f.acknowledged && onDone) {
    ackButton = h('button', { class: 'btn small', type: 'button', 'data-testid': 'acknowledge' }, t('findings.ack.submit'));
    ackButton.addEventListener('click', () => acknowledgeDialog(ix, f, onDone));
  }
  return h(
    'article',
    { class: `card finding sev-${f.severity}${resolved ? ' resolved' : ''}${f.incomplete ? ' incomplete' : ''}${f.acknowledged ? ' acknowledged' : ''}`, 'data-testid': 'finding', 'data-rule': f.rule_id, 'data-severity': f.severity },
    h('div', { class: 'finding-head' }, f.incomplete ? h('span', { class: 'badge sev-unknown' }, t('findings.notChecked')) : severityBadge(f.severity), h('h3', { 'data-testid': 'finding-title' }, findingTitle(f)), resolved ? h('span', { class: 'badge status-ok', 'data-testid': 'resolved' }, t('findings.resolved')) : null),
    h('p', { 'data-testid': 'finding-message' }, findingMessage(f)),
    f.objects.length ? h('p', { class: 'objects' }, h('span', { class: 'muted' }, t('findings.affects')), f.objects.map((id, i) => [i ? ', ' : '', objectRef(ix, id)])) : null,
    f.fix ? h('p', { class: 'fix', 'data-testid': 'finding-fix' }, h('strong', {}, t('findings.howToFix')), findingFix(f)) : null,
    !resolved && fixable(f) ? h('p', {}, h('a', { class: 'btn small', href: `#/device/${encodeURIComponent(f.objects[0])}`, 'data-testid': 'finding-fix-it' }, t('findings.fixIt'))) : null,
    f.acknowledged ? ackLine(f, onDone) : null,
    h(
      'p',
      { class: 'muted small' },
      h('span', { title: fmtTime(rec.first_seen), 'data-testid': 'finding-since' }, t('findings.since', { ago: fmtAgo(rec.first_seen) })),
      resolved ? ` · ${t('findings.resolvedAgo', { ago: fmtAgo(rec.resolved_at) })}` : '',
      ` · ${t('findings.rule', { id: f.rule_id })}`,
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
  const fixes = await fixesNotice();
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
          t('findings.noDevices.title'),
          h('p', { class: 'muted' }, t('findings.noDevices.text')),
          h('p', {}, h('a', { class: 'btn primary', href: '#/devices/new', 'data-testid': 'empty-add-device' }, t('findings.noDevices.add'))),
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
          h('h2', {}, t('findings.notRead.title')),
          h('p', { class: 'muted' }, t('findings.notRead.text')),
        ),
      );
    } else if (!problems.some((r) => !r.resolved_at)) {
      place(list, 
        h(
          'div',
          { class: 'card empty good', 'data-testid': 'no-problems' },
          h('h2', {}, t('findings.noProblems.title')),
          h('p', { class: 'muted' }, records.length && shown.length !== records.length ? t('findings.noProblems.filtered') : t('findings.noProblems.text')),
        ),
      );
    }
    for (const sev of ['error', 'warning', 'info']) {
      const group = problems.filter((r) => r.finding.severity === sev);
      if (!group.length) continue;
      place(list, h('section', { class: 'group', 'data-testid': `group-${sev}` }, h('h2', {}, t('findings.groupHeading', { title: t(GROUP_TITLE[sev]), count: fmtNumber(group.length) })), group.map(card)));
    }
    if (unchecked.length) {
      place(list, 
        h(
          'section',
          { class: 'group unchecked', 'data-testid': 'group-incomplete' },
          h('h2', {}, t('findings.incomplete.heading', { count: fmtNumber(unchecked.length) })),
          h('p', { class: 'muted' }, t('findings.incomplete.text')),
          unchecked.map(card),
        ),
      );
    }
    if (acknowledged.length) {
      place(list,
        h(
          'details',
          { class: 'group acknowledged', 'data-testid': 'group-acknowledged' },
          h('summary', {}, h('h2', {}, t('findings.acknowledged.heading', { count: fmtNumber(acknowledged.length) }))),
          h('p', { class: 'muted' }, t('findings.acknowledged.text')),
          acknowledged.map(card),
        ),
      );
    }
  };

  const reload = async () => {
    ix = await loadNetwork();
    records = await get(`/findings${filters.resolved ? '?resolved=true' : ''}`);
    records.sort((a, b) => ORDER[a.finding.severity] - ORDER[b.finding.severity] || compare(findingTitle(a.finding), findingTitle(b.finding)));
    if (ctx.alive(id)) draw();
  };
  records.sort((a, b) => ORDER[a.finding.severity] - ORDER[b.finding.severity] || compare(findingTitle(a.finding), findingTitle(b.finding)));

  const observe = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'observe' }, t('findings.observe'));
  observe.addEventListener('click', () =>
    run(observe, async () => {
      const before = (await get('/health')).last_run;
      await post('/observe');
      toast(t('findings.observing'));
      for (let i = 0; i < 10 && ctx.alive(id); i += 1) {
        await sleep(i < 3 ? 700 : 1500);
        const health = await get('/health');
        if (health.last_run && health.last_run !== before) break;
      }
      await reload();
    }),
  );
  const sev = select([['', t('findings.filter.all')], ['error', t(GROUP_TITLE.error)], ['warning', t(GROUP_TITLE.warning)], ['info', t(GROUP_TITLE.info)]], filters.severity, { 'aria-label': t('findings.filter.severity'), 'data-testid': 'filter-severity' });
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
    pageHead(t('findings.title'), observe),
    fixes,
    ix.deviceList.length ? h('div', { class: 'filters' }, site, sev, h('label', { class: 'check' }, resolved, t('findings.showResolved'))) : null,
    list,
  );
  draw();
  const timer = setInterval(() => reload().catch(() => null), 30000);
  ctx.onCleanup(() => clearInterval(timer));
}
