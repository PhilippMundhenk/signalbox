// Changes: the change log; approve, deploy, revert; backups.
import { enc, get, post } from '../api.js';
import { clear, fmtTime, h, place, sleep } from '../util.js';
import { card, confirmDialog, empty, field, pageHead, run, table, tag, toast } from '../ui.js';
import { renderPlan } from './desired.js';

const STATUS_CLASS = { applied: 'ok', 'rolled-back': 'warn', failed: 'danger', rejected: '', planned: '', approved: '', deploying: 'warn' };

function statusTag(status) {
  return tag(status, STATUS_CLASS[status] || '');
}

export async function renderChanges(main, ctx) {
  const log = await get('/changes');
  const create = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-new' }, 'New change from desired state');
  create.addEventListener('click', () => ctx.navigate('#/change/new'));
  place(
    clear(main),
    pageHead('Changes', create),
    log.deploy_enabled ? null : h('p', { class: 'card', 'data-testid': 'deploy-off' }, 'Deploying is turned off. Changes can be planned and approved, but not deployed, until deploy.enabled is set in the configuration.'),
    log.changes.length
      ? table(
          [
            ['When', (c) => h('a', { href: `#/change/${enc(c.id)}` }, fmtTime(c.created_at))],
            ['Why', (c) => c.reason],
            ['Status', (c) => [statusTag(c.status), c.reverted_by ? tag('reverted') : null, c.reverts ? tag('revert') : null, c.restore_backup_id ? tag('restore') : null]],
            ['Changes', (c) => (c.restore_backup_id ? 'backup' : String(c.changes))],
            ['Devices', (c) => c.devices.join(', ')],
          ],
          log.changes,
          { testid: 'changes', rowTestid: 'change-row' },
        )
      : empty('no-changes', 'No changes yet', h('p', {}, 'Declare the desired state, plan it, and record it as a change here.')),
    await backupsCard(ctx),
  );
}

async function backupsCard(ctx) {
  const backups = await get('/backups');
  if (!backups.length) return null;
  return card(
    'Backups',
    h('p', { class: 'muted' }, 'Taken before every change. Restoring one is itself a change that is approved and tracked.'),
    table(
      [
        ['Device', (b) => b.device_id],
        ['Taken', (b) => fmtTime(b.taken_at)],
        ['Change', (b) => (b.change_id ? h('a', { href: `#/change/${enc(b.change_id)}` }, b.change_id) : '–')],
        [
          '',
          (b) => {
            const btn = h('button', { class: 'btn small', type: 'button', 'data-testid': 'backup-restore' }, 'Restore…');
            btn.addEventListener('click', () => askReason(`Restore backup of ${b.device_id}`, 'Later changes on this device are lost.', async (reason) => {
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
  const go = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'reason-ok' }, 'Continue');
  const box = card(title, h('p', {}, message), field('Why (kept in the change log)', reason), h('div', { class: 'row' }, go));
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
  const plan = h('div', { 'data-testid': 'plan' }, h('p', { class: 'muted' }, 'Planning…'));
  place(clear(main), pageHead('New change'), card('Plan', plan));
  try {
    renderPlan(plan, await post('/plan'));
  } catch (err) {
    place(clear(plan), h('p', { class: 'error', 'data-testid': 'plan-error' }, err.message));
    return;
  }
  const reason = h('input', { type: 'text', maxlength: '1000', 'data-testid': 'change-reason' });
  const save = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-create' }, 'Record change');
  save.addEventListener('click', () => run(save, async () => {
    const rec = await post('/changes', { reason: reason.value.trim() });
    toast('Change recorded. Review and approve it.');
    ctx.navigate(`#/change/${enc(rec.id)}`);
  }));
  main.append(card('Record', field('Why (kept in the change log)', reason), h('div', { class: 'row' }, save)));
}

export async function renderChange(main, ctx, route) {
  const rec = await get(`/changes/${enc(route.id)}`);
  const actions = h('div', { class: 'row' });
  if (rec.status === 'planned') {
    const override = rec.plan.blocking.length ? h('input', { type: 'text', 'data-testid': 'override', placeholder: 'Why deploy despite the errors' }) : null;
    const approve = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-approve' }, 'Approve');
    approve.addEventListener('click', () => run(approve, async () => {
      await post(`/changes/${enc(rec.id)}/approve`, { override: override ? override.value : null });
      ctx.refresh();
    }));
    const reject = h('button', { class: 'btn', type: 'button', 'data-testid': 'change-reject' }, 'Reject');
    reject.addEventListener('click', () => run(reject, async () => {
      await post(`/changes/${enc(rec.id)}/reject`);
      ctx.refresh();
    }));
    place(actions, override ? field('Override', override) : null, approve, reject);
  }
  if (rec.status === 'approved') {
    const deploy = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'change-deploy' }, 'Deploy now');
    deploy.addEventListener('click', () => run(deploy, async () => {
      if (!(await confirmDialog({ title: 'Deploy this change?', message: `Signalbox backs up, changes, checks and confirms ${rec.devices.length} device(s), one after another. If one fails, all are rolled back.`, confirmLabel: 'Deploy' }))) return;
      await post(`/changes/${enc(rec.id)}/deploy`);
      for (let i = 0; i < 120; i += 1) {
        await sleep(500);
        const now = await get(`/changes/${enc(rec.id)}`);
        if (!['approved', 'deploying'].includes(now.status)) break;
      }
      ctx.refresh();
    }));
    const reject = h('button', { class: 'btn', type: 'button', 'data-testid': 'change-reject' }, 'Reject');
    reject.addEventListener('click', () => run(reject, async () => {
      await post(`/changes/${enc(rec.id)}/reject`);
      ctx.refresh();
    }));
    place(actions, deploy, reject);
  }
  if (rec.status === 'applied' && !rec.reverted_by && !rec.restore_backup_id) {
    const revert = h('button', { class: 'btn', type: 'button', 'data-testid': 'change-revert' }, 'Revert…');
    revert.addEventListener('click', () => askReason('Revert this change', 'A new change is planned that undoes this one. You approve and deploy it like any change.', async (reason) => {
      const back = await post(`/changes/${enc(rec.id)}/revert`, { reason });
      ctx.navigate(`#/change/${enc(back.id)}`);
    }));
    place(actions, revert);
  }
  const planBox = h('div', {});
  renderPlan(planBox, rec.plan);
  place(
    clear(main),
    pageHead(`Change ${rec.id}`),
    card(
      null,
      h('p', { 'data-testid': 'change-status' }, statusTag(rec.status), ' ', rec.reason),
      h('p', { class: 'muted' }, `${fmtTime(rec.created_at)} by ${rec.author}`, rec.desired_commit ? ` · desired state ${rec.desired_commit.slice(0, 7)}` : '', rec.override ? ` · override: ${rec.override}` : ''),
      rec.reverts ? h('p', {}, 'Reverts ', h('a', { href: `#/change/${enc(rec.reverts)}` }, rec.reverts)) : null,
      rec.reverted_by ? h('p', {}, 'Reverted by ', h('a', { href: `#/change/${enc(rec.reverted_by)}` }, rec.reverted_by)) : null,
      actions,
    ),
    rec.restore_backup_id ? card('Restore', h('p', {}, `Backup ${rec.restore_backup_id}`)) : card('Plan', planBox),
    card(
      'Devices',
      table(
        [
          ['Device', (d) => d.device_id],
          ['Result', (d) => statusTag(d.status)],
          ['Calls', (d) => h('ul', {}, d.calls.map((c) => h('li', {}, c.description)))],
          ['Problem', (d) => d.error || ''],
        ],
        rec.devices,
        { testid: 'change-devices', rowTestid: 'change-device' },
      ),
    ),
    card('Log', h('ol', { 'data-testid': 'change-events' }, rec.events.map((e) => h('li', {}, `${fmtTime(e.at)} ${e.device_id || ''} ${e.event} ${e.detail}`)))),
  );
}
