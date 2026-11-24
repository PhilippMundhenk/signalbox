// Changes: the change log; approve, deploy, revert; backups.
import { t } from '../i18n.js';
import { enc, get, post } from '../api.js';
import { clear, fmtTime, h, place, sleep } from '../util.js';
import { card, confirmDialog, empty, field, pageHead, run, table, tag, toast } from '../ui.js';
import { renderPlan } from './desired.js';

const STATUS_KEY = { applied: 'changes.status.applied', 'rolled-back': 'changes.status.rolled-back', failed: 'changes.status.failed', rejected: 'changes.status.rejected', planned: 'changes.status.planned', approved: 'changes.status.approved', deploying: 'changes.status.deploying' };
const STATUS_CLASS = { applied: 'ok', 'rolled-back': 'warn', failed: 'danger', rejected: '', planned: '', approved: '', deploying: 'warn' };

function statusTag(status) {
  return tag(STATUS_KEY[status] ? t(STATUS_KEY[status]) : status, STATUS_CLASS[status] || '');
}

export async function renderChanges(main, ctx) {
  const log = await get('/changes');
  const create = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-new' }, t('changes.newFromDesired'));
  create.addEventListener('click', () => ctx.navigate('#/change/new'));
  place(
    clear(main),
    pageHead(t('changes.title'), create),
    log.deploy_enabled ? null : h('p', { class: 'card', 'data-testid': 'deploy-off' }, t('changes.deployOff')),
    log.changes.length
      ? table(
          [
            [t('changes.col.when'), (c) => h('a', { href: `#/change/${enc(c.id)}` }, fmtTime(c.created_at))],
            [t('changes.col.why'), (c) => c.reason],
            [t('changes.col.status'), (c) => [statusTag(c.status), c.reverted_by ? tag(t('changes.tag.reverted')) : null, c.reverts ? tag(t('changes.tag.revert')) : null, c.restore_backup_id ? tag(t('changes.tag.restore')) : null]],
            [t('changes.col.changes'), (c) => (c.restore_backup_id ? t('changes.backupCell') : String(c.changes))],
            [t('changes.col.devices'), (c) => c.devices.join(', ')],
          ],
          log.changes,
          { testid: 'changes', rowTestid: 'change-row' },
        )
      : empty('no-changes', t('changes.none.title'), h('p', {}, t('changes.none.text'))),
    await backupsCard(ctx),
  );
}

async function backupsCard(ctx) {
  const backups = await get('/backups');
  if (!backups.length) return null;
  return card(
    t('changes.backups.title'),
    h('p', { class: 'muted' }, t('changes.backups.text')),
    table(
      [
        [t('changes.col.device'), (b) => b.device_id],
        [t('changes.col.taken'), (b) => fmtTime(b.taken_at)],
        [t('changes.col.change'), (b) => (b.change_id ? h('a', { href: `#/change/${enc(b.change_id)}` }, b.change_id) : '–')],
        [
          '',
          (b) => {
            const btn = h('button', { class: 'btn small', type: 'button', 'data-testid': 'backup-restore' }, t('changes.backups.restore'));
            btn.addEventListener('click', () => askReason(t('changes.backups.restoreTitle', { device: b.device_id }), t('changes.backups.restoreWarning'), async (reason) => {
              const rec = await post(`/backups/${enc(b.id)}/restore`, { reason });
              ctx.navigate(`#/change/${enc(rec.id)}`);
            }));
            return btn;
          },
          'actions',
        ],
      ],
      backups,
      { testid: 'backups', rowTestid: 'backup-row' },
    ),
  );
}

function askReason(title, message, fn) {
  const reason = h('input', { type: 'text', maxlength: '1000', 'data-testid': 'reason' });
  const go = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'reason-ok' }, t('changes.reason.continue'));
  const box = card(title, h('p', {}, message), field(t('changes.reason.label'), reason), h('div', { class: 'row' }, go));
  go.addEventListener('click', () => run(go, async () => {
    if (!reason.value.trim()) {
      reason.setAttribute('aria-invalid', 'true');
      reason.focus();
      return;
    }
    await fn(reason.value.trim());
    box.remove();
  }));
  document.getElementById('main').prepend(box);
  reason.focus();
}

export async function renderNewChange(main, ctx) {
  const plan = h('div', { 'data-testid': 'plan' }, h('p', { class: 'muted' }, t('changes.new.planning')));
  place(clear(main), pageHead(t('changes.new.title')), card(t('changes.plan'), plan));
  try {
    renderPlan(plan, await post('/plan'));
  } catch (err) {
    place(clear(plan), h('p', { class: 'error', 'data-testid': 'plan-error' }, err.message));
    return;
  }
  const reason = h('input', { type: 'text', maxlength: '1000', 'data-testid': 'change-reason' });
  const save = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-create' }, t('changes.new.record'));
  save.addEventListener('click', () => run(save, async () => {
    const rec = await post('/changes', { reason: reason.value.trim() });
    toast(t('changes.new.recorded'));
    ctx.navigate(`#/change/${enc(rec.id)}`);
  }));
  main.append(card(t('changes.new.recordCard'), field(t('changes.reason.label'), reason), h('div', { class: 'row' }, save)));
}

export async function renderChange(main, ctx, route) {
  const rec = await get(`/changes/${enc(route.id)}`);
  const actions = h('div', { class: 'row' });
  if (rec.status === 'planned') {
    const override = rec.plan.blocking.length ? h('input', { type: 'text', 'data-testid': 'override', placeholder: t('changes.override.placeholder') }) : null;
    const lockout = (rec.plan.lockouts || []).length ? h('input', { type: 'checkbox', 'data-testid': 'allow-lockout' }) : null;
    const approve = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-approve' }, t('changes.approve'));
    approve.addEventListener('click', () => run(approve, async () => {
      await post(`/changes/${enc(rec.id)}/approve`, { override: override ? override.value : null, allow_lockout: lockout ? lockout.checked : false });
      ctx.refresh();
    }));
    const reject = h('button', { class: 'btn', type: 'button', 'data-testid': 'change-reject' }, t('changes.reject'));
    reject.addEventListener('click', () => run(reject, async () => {
      await post(`/changes/${enc(rec.id)}/reject`);
      ctx.refresh();
    }));
    place(actions, override ? field(t('changes.override.label'), override) : null, lockout ? h('label', { class: 'error' }, lockout, ' ', t('changes.allowLockout')) : null, approve, reject);
  }
  if (rec.status === 'approved') {
    const deploy = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-deploy' }, t('changes.deploy.now'));
    deploy.addEventListener('click', () => run(deploy, async () => {
      if (!(await confirmDialog({ title: t('changes.deploy.title'), message: t('changes.deploy.message', { count: rec.devices.length }), confirmLabel: t('changes.deploy.confirm') }))) return;
      await post(`/changes/${enc(rec.id)}/deploy`);
      for (let i = 0; i < 120; i += 1) {
        await sleep(500);
        const now = await get(`/changes/${enc(rec.id)}`);
        if (!['approved', 'deploying'].includes(now.status)) break;
      }
      ctx.refresh();
    }));
    const reject = h('button', { class: 'btn', type: 'button', 'data-testid': 'change-reject' }, t('changes.reject'));
    reject.addEventListener('click', () => run(reject, async () => {
      await post(`/changes/${enc(rec.id)}/reject`);
      ctx.refresh();
    }));
    place(actions, deploy, reject);
  }
  if (rec.status === 'applied' && !rec.reverted_by && !rec.restore_backup_id) {
    const revert = h('button', { class: 'btn', type: 'button', 'data-testid': 'change-revert' }, t('changes.revert.button'));
    revert.addEventListener('click', () => askReason(t('changes.revert.title'), t('changes.revert.text'), async (reason) => {
      const back = await post(`/changes/${enc(rec.id)}/revert`, { reason });
      ctx.navigate(`#/change/${enc(back.id)}`);
    }));
    place(actions, revert);
  }
  const planBox = h('div', {});
  renderPlan(planBox, rec.plan);
  place(
    clear(main),
    pageHead(t('changes.heading', { id: rec.id })),
    card(
      null,
      h('p', { 'data-testid': 'change-status' }, statusTag(rec.status), ' ', rec.reason),
      h('p', { class: 'muted' }, t('changes.byAuthor', { time: fmtTime(rec.created_at), author: rec.author }), rec.desired_commit ? ` · ${t('changes.desiredState', { commit: rec.desired_commit.slice(0, 7) })}` : '', rec.override ? ` · ${t('changes.overrideNote', { text: rec.override })}` : '', rec.allow_lockout ? ` · ${t('changes.lockoutAllowed')}` : ''),
      rec.reverts ? h('p', {}, t('changes.reverts'), h('a', { href: `#/change/${enc(rec.reverts)}` }, rec.reverts)) : null,
      rec.reverted_by ? h('p', {}, t('changes.revertedBy'), h('a', { href: `#/change/${enc(rec.reverted_by)}` }, rec.reverted_by)) : null,
      actions,
    ),
    rec.restore_backup_id ? card(t('changes.restore.title'), h('p', {}, t('changes.restore.backup', { id: rec.restore_backup_id }))) : card(t('changes.plan'), planBox),
    card(
      t('changes.devices.title'),
      table(
        [
          [t('changes.col.device'), (d) => d.device_id],
          [t('changes.col.result'), (d) => statusTag(d.status)],
          [t('changes.col.calls'), (d) => h('ul', {}, d.calls.map((c) => h('li', {}, c.description)))],
          [t('changes.col.problem'), (d) => d.error || ''],
        ],
        rec.devices,
        { testid: 'change-devices', rowTestid: 'change-device' },
      ),
    ),
    card(t('changes.log.title'), h('ol', { 'data-testid': 'change-events' }, rec.events.map((e) => h('li', {}, `${fmtTime(e.at)} ${e.device_id || ''} ${e.event} ${e.detail}`)))),
  );
}
