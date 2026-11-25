// Fixes (#376): every fix Signalbox can make on the stored devices in one list, mandatory or
// optional, to run several together. Nothing changes without an explicit start and a
// confirmation that lists every device and what changes on it (each can be unticked); the
// device's identity is confirmed before any login; the admin logins are asked for last, used
// once, never stored. The run goes through a job (device by device, live state, a failure
// does not stop it) and ends with a summary; each touched device was read again.
import { ApiError, enc, get, post } from '../api.js';
import { fmtNumber, t } from '../i18n.js';
import { apiFix, apiMessage, errorFix, errorMessage } from '../texts.js';
import { clear, h, place, sleep } from '../util.js';
import { busy, checkField, clearNotice, empty, field, modal, notice, pageHead, run, select, setNotice, slot, statusBadge, toast } from '../ui.js';
import { adminStep, previewList } from './adminstep.js';
import { fingerprintText, stepList } from './devicesetup.js';
import { hostKeyChanged, hostKeyKnown, isChanged, isKnown } from './hostkey.js';
import { linked } from './devicetest.js';

const POLL_MS = 400;
const filters = { mandatory: false };

// The count with a link for the devices and findings pages: null while there is nothing to fix
// or Fix it is off. Never throws: a page must not fail because of this.
export async function fixesNotice() {
  let data;
  try {
    data = await get('/fixes');
  } catch (err) {
    return null;
  }
  if (!data.enabled || !data.counts.available) return null;
  return notice('info', 'fixes-count', t('fixes.count', { count: fmtNumber(data.counts.available), mandatory: fmtNumber(data.counts.mandatory) }), ' ', h('a', { href: '#/fixes', 'data-testid': 'fixes-link' }, t('fixes.open')));
}

const keyOf = (device, fix) => `${device.device_id}\u0000${fix.remedy}`;

function badge(fix) {
  return h('span', { class: `badge ${fix.mandatory ? 'sev-error' : 'sev-info'}`, 'data-testid': 'fix-kind', 'data-kind': fix.mandatory ? 'mandatory' : 'optional' }, fix.mandatory ? t('fixes.mandatory') : t('fixes.optional'));
}

export async function renderFixes(main, ctx) {
  const id = ctx.renderId;
  const [data, adapters] = await Promise.all([get('/fixes'), get('/adapters')]);
  if (!ctx.alive(id)) return;
  place(main, pageHead(t('fixes.title')));
  place(main, h('p', { class: 'muted' }, t('fixes.intro')));
  if (!data.enabled) {
    place(main, notice('info', 'fixes-off', t('fixes.off')));
    return;
  }
  const loginOf = (device) => (adapters.find((a) => a.id === device.adapter) || {}).admin_login;
  const adapterName = (device) => (adapters.find((a) => a.id === device.adapter) || {}).name || device.adapter;
  const runnable = [];
  for (const d of data.devices) for (const f of d.fixes) if (!f.manual && loginOf(d)) runnable.push({ device: d, fix: f });
  if (!data.devices.length) {
    place(main, empty('fixes-none', t('fixes.none')));
    return;
  }
  const selected = new Set();
  const list = h('div', { 'data-testid': 'fixes-list' });
  const runBtn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fixes-run' });
  const mode = select([['all', t('fixes.filter.all')], ['mandatory', t('fixes.filter.mandatory')]], filters.mandatory ? 'mandatory' : 'all', { 'data-testid': 'fixes-filter', 'aria-label': t('fixes.filter.label') });
  const visible = () => runnable.filter((r) => !filters.mandatory || r.fix.mandatory);
  const sync = () => {
    runBtn.textContent = t('fixes.runSelected', { count: fmtNumber(selected.size) });
    runBtn.disabled = !selected.size;
    for (const box of list.querySelectorAll('input[type=checkbox][data-key]')) box.checked = selected.has(box.dataset.key);
  };
  const toggle = (key, on) => {
    if (on) selected.add(key);
    else selected.delete(key);
    sync();
  };

  const draw = () => {
    clear(list);
    for (const d of data.devices) {
      const fixes = d.fixes.filter((f) => !filters.mandatory || f.mandatory);
      if (!fixes.length) continue;
      const items = fixes.map((f) => {
        const key = keyOf(d, f);
        const box = !f.manual && loginOf(d) ? h('input', { type: 'checkbox', 'data-key': key, 'data-testid': 'fix-select', 'aria-label': t('fixes.select', { title: f.title, name: d.name }), onchange: (e) => toggle(key, e.target.checked) }) : null;
        return h(
          'li',
          { class: 'fix-item', 'data-testid': 'fix-item', 'data-remedy': f.remedy, 'data-manual': f.manual ? 'true' : null },
          h('label', { class: 'check' }, box, box ? ' ' : null, h('strong', {}, f.title)),
          ' ',
          badge(f),
          f.description ? h('p', { class: 'muted small' }, f.description) : null,
          h('ul', { class: 'muted small' }, f.causes.map((c) => h('li', {}, errorMessage(c)))),
          f.manual ? notice('info', 'fix-manual', t('fixes.manual')) : null,
          f.manual || !box ? f.causes.filter((c) => c.fix).slice(0, 1).map((c) => h('p', { class: 'fix', 'data-testid': 'error-fix' }, t('fix.whatToDo'), ...linked(errorFix(c)))) : null,
        );
      });
      place(list, h('section', { class: 'card', 'data-testid': 'fixes-device', 'data-device': d.device_id }, h('h2', {}, h('a', { href: `#/device/${enc(d.device_id)}` }, d.name)), h('ul', { class: 'fix-list' }, items)));
    }
    if (!list.children.length) place(list, empty('fixes-none-filtered', t('fixes.noneFiltered')));
    sync();
  };

  mode.addEventListener('change', () => {
    filters.mandatory = mode.value === 'mandatory';
    for (const key of [...selected]) if (!visible().some((r) => keyOf(r.device, r.fix) === key)) selected.delete(key);
    draw();
  });
  const selectMandatory = h('button', { class: 'btn small', type: 'button', 'data-testid': 'fixes-select-mandatory' }, t('fixes.selectMandatory'));
  selectMandatory.addEventListener('click', () => {
    for (const r of runnable) if (r.fix.mandatory) selected.add(keyOf(r.device, r.fix));
    sync();
  });
  const selectNone = h('button', { class: 'btn small', type: 'button', 'data-testid': 'fixes-select-none' }, t('fixes.selectNone'));
  selectNone.addEventListener('click', () => {
    selected.clear();
    sync();
  });
  runBtn.addEventListener('click', () => {
    const chosen = runnable.filter((r) => selected.has(keyOf(r.device, r.fix))).map((r) => ({ ...r, login: loginOf(r.device), adapter: adapterName(r.device) }));
    confirmRun(chosen, () => ctx.refresh());
  });
  place(main, h('div', { class: 'filters' }, mode, selectMandatory, selectNone, runBtn));
  place(main, list);
  draw();
}

// The dialog: review (every device, what changes, each unticked-able) -> identities -> the
// logins -> the run with live state -> the summary.
function confirmRun(chosen, onClosed) {
  const body = h('div', { 'data-testid': 'fixes-dialog' });
  const problem = slot();
  let steps = []; // adminStep per login, disposed whenever the dialog ends
  let polling = true;
  const disposeAll = () => {
    for (const s of steps) s.dispose();
    steps = [];
  };
  const close = modal({
    title: t('fixes.dialog.title'),
    body: h('div', {}, body, problem),
    onClose: () => {
      polling = false;
      disposeAll();
      onClosed();
    },
    actions: () => [],
  });
  const closeBtn = () => h('button', { class: 'btn', type: 'button', 'data-testid': 'fixes-cancel', onclick: () => close() }, t('common.cancel'));
  const fail = (err) => setNotice(problem, 'error', 'fixes-error', apiMessage(err));

  // 1. what changes on which device
  const rows = chosen.map((c) => ({ ...c, on: true, port: c.fix.port_default || c.login.port_default || null }));
  function review() {
    clearNotice(problem);
    const go = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fixes-continue' }, t('fixes.dialog.continue'));
    const sync = () => {
      go.disabled = !rows.some((r) => r.on);
    };
    place(
      clear(body),
      h('p', {}, t('fixes.dialog.intro')),
      h(
        'ul',
        { class: 'fix-list', 'data-testid': 'fixes-review' },
        rows.map((r) => {
          const port = r.port ? h('input', { type: 'number', min: '1', max: '65535', value: String(r.port), 'data-testid': 'fixes-port', onchange: (e) => (r.port = Number(e.target.value) || null) }) : null;
          return h(
            'li',
            { class: 'fix-item', 'data-testid': 'fixes-review-item', 'data-device': r.device.device_id, 'data-remedy': r.fix.remedy },
            checkField(t('fixes.dialog.item', { title: r.fix.title, name: r.device.name }), h('input', { type: 'checkbox', checked: true, 'data-testid': 'fixes-review-tick', onchange: (e) => { r.on = e.target.checked; sync(); } })),
            r.fix.description ? h('p', { class: 'muted small' }, r.fix.description) : null,
            r.fix.preview.length ? previewList(r.fix.preview, 'fixes-review-steps') : null,
            port ? field(t('fix.sshPort'), port) : null,
          );
        }),
      ),
      h('p', { class: 'muted small' }, t('fixes.dialog.note')),
      h('div', { class: 'modal-actions' }, closeBtn(), go),
    );
    sync();
    go.addEventListener('click', () => run(go, identities, problem));
  }

  // 2. the identity of every ticked device, without any credential
  async function identities() {
    const todo = rows.filter((r) => r.on);
    place(clear(body), busy('fixes-fetching', t('fixes.identity.fetching')));
    const found = [];
    const left = [];
    for (const r of todo) {
      try {
        const admin = { user: r.login.user_default || '' };
        if (r.port) admin.port = r.port;
        const plan = await post(`/devices/${enc(r.device.device_id)}/fix`, { remedy: r.fix.remedy, admin });
        found.push({ ...r, plan });
      } catch (err) {
        left.push({ ...r, problem: apiMessage(err) });
      }
    }
    // SSH host keys (#526): a device whose key changed is left out with the warning (its new
    // key can be trusted right here, by name); one with the key confirmed before needs no
    // comparing; the others are compared as before
    const changed = found.filter((f) => isChanged(f.plan.host_key));
    const usable = found.filter((f) => !isChanged(f.plan.host_key));
    const ask = usable.filter((f) => !isKnown(f.plan.host_key));
    const warnings = changed.map((f) => hostKeyChanged(f.plan.host_key, { id: f.device.device_id, name: f.device.name }, 'fixes-host-key-changed', identities));
    if (!usable.length) {
      place(clear(body), h('p', {}, t(changed.length ? 'fixes.identity.noneUsable' : 'fixes.identity.none')), ...warnings, ...left.map(leftOut), h('div', { class: 'modal-actions' }, closeBtn()));
      return;
    }
    const trust = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fixes-trust' }, t(ask.length ? 'fixes.identity.trust' : 'fixes.identity.continue'));
    place(
      clear(body),
      h('p', {}, t(ask.length ? 'fixes.identity.intro' : 'fixes.identity.allKnown')),
      h(
        'ul',
        { class: 'fix-list', 'data-testid': 'fixes-identities' },
        usable.map((f) =>
          h(
            'li',
            { class: 'fix-item', 'data-testid': 'fixes-identity', 'data-device': f.device.device_id, 'data-host-key': f.plan.host_key ? f.plan.host_key.state : null },
            h('strong', {}, f.device.name),
            isKnown(f.plan.host_key)
              ? hostKeyKnown(f.plan.host_key, 'fixes-host-key-known')
              : [
                  h('p', { class: 'muted small' }, t(f.plan.fingerprint_kind === 'certificate' ? 'fix.presentedCertificate' : 'fix.presentedSshKey')),
                  h('p', { class: 'fingerprint mono', 'data-testid': 'fixes-fingerprint' }, fingerprintText(f.plan)),
                  f.plan.compare ? h('p', { class: 'muted small' }, f.plan.compare) : null,
                ],
          ),
        ),
      ),
      changed.length ? h('p', { class: 'muted small', 'data-testid': 'fixes-changed-left-out' }, t('fixes.identity.changedLeftOut')) : null,
      ...warnings,
      ...left.map(leftOut),
      h('div', { class: 'modal-actions' }, closeBtn(), trust),
    );
    trust.addEventListener('click', () => logins(usable.map((f) => ({ ...f, trust: f.plan.fingerprint })), left));
  }
  const leftOut = (r) => notice('warn', 'fixes-left-out', h('strong', {}, `${r.device.name}: `), t('fixes.identity.failed', { message: r.problem }));

  // 3. the logins, last: one per device, or one for the devices of a type
  function logins(ready, left) {
    clearNotice(problem);
    disposeAll();
    const groups = new Map();
    for (const r of ready) {
      const g = groups.get(r.device.adapter) || [];
      g.push(r);
      groups.set(r.device.adapter, g);
    }
    const blocks = [];
    for (const [, group] of groups) {
      const shared = group.length > 1 ? h('input', { type: 'checkbox', 'data-testid': 'fixes-same-login' }) : null;
      const els = group.map((r) => {
        const step = adminStep(r.login, 'fixes');
        steps.push(step);
        r.step = step;
        const wrap = h('div', { class: 'fix-login', 'data-testid': 'fixes-login', 'data-device': r.device.device_id }, h('h3', {}, t('fixes.login.for', { name: r.device.name })), step.el);
        return wrap;
      });
      if (shared) {
        shared.addEventListener('change', () => {
          els.forEach((el, i) => {
            if (i) el.hidden = shared.checked;
          });
          group.forEach((r, i) => {
            r.source = shared.checked ? group[0] : r;
            if (!i) r.source = r;
          });
        });
      }
      group.forEach((r) => (r.source = r));
      blocks.push(h('section', { class: 'card' }, shared ? checkField(t('fixes.login.same', { count: fmtNumber(group.length - 1), adapter: group[0].adapter }), shared) : null, els));
    }
    const go = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fixes-apply' }, t('fixes.login.run', { count: fmtNumber(ready.length) }));
    place(clear(body), h('h3', {}, t('fixes.login.title')), h('p', { class: 'muted small' }, t('fixes.login.note')), blocks, h('div', { class: 'modal-actions' }, closeBtn(), go));
    go.addEventListener('click', () => {
      const missing = ready.find((r) => !r.source.step.secret());
      if (missing) return setNotice(problem, 'error', 'fixes-error', t('fix.enterSecret', { label: missing.login.secret_label }) + ` (${missing.device.name})`);
      start(ready, left);
    });
  }

  // 4. start: the passwords go in this one request, then the fields are emptied
  async function start(ready, left) {
    clearNotice(problem);
    const items = ready.map((r) => {
      const admin = { user: r.source.step.user(), secret: r.source.step.secret() };
      if (r.port) admin.port = r.port;
      return { device_id: r.device.device_id, body: { remedy: r.fix.remedy, admin, trust: r.trust, plan_ids: r.fix.preview.map((s) => s.id) } };
    });
    let id;
    try {
      ({ id } = await post('/fixes/jobs', { items }));
    } catch (err) {
      for (const s of steps) s.wipe();
      fail(err);
      return;
    }
    disposeAll();
    items.length = 0;
    const live = h('div', { 'data-testid': 'fixes-progress' });
    const head = h('strong', {}, t('fixes.running'));
    place(clear(body), busy('fixes-busy', head, live));
    let view = { items: [], state: 'running' };
    let misses = 0;
    while (polling) {
      await sleep(POLL_MS);
      try {
        view = await get(`/fixes/jobs/${id}`);
        misses = 0;
      } catch (err) {
        if ((err instanceof ApiError && err.status === 404) || ++misses > 5) return fail(err);
        continue;
      }
      place(clear(live), runList(view));
      if (view.state === 'finished') break;
    }
    if (!polling) return;
    summary(view, left);
  }

  // one row per device with its state as the run reports it, and its steps
  function runList(view, finished = false) {
    return h(
      'ul',
      { class: 'fix-list', 'data-testid': finished ? 'fixes-summary-list' : 'fixes-run-list' },
      view.items.map((i) =>
        h(
          'li',
          { class: `fix-item state-${i.state}`, 'data-testid': 'fixes-run-item', 'data-device': i.device_id, 'data-state': i.state },
          h('span', { class: `badge step-${i.state === 'pending' ? 'waiting' : i.state}` }, t(`setup.state.${i.state === 'pending' ? 'waiting' : i.state}`)),
          ' ',
          h('strong', {}, t('fixes.dialog.item', { title: i.title, name: i.name })),
          i.steps.length ? stepList(i.steps, 'fixes-run-steps') : null,
          i.problem ? h('p', { class: 'error', 'data-testid': 'fixes-run-problem' }, errorMessage(i.problem), i.problem.fix ? h('span', { class: 'fix' }, ` ${t('fix.whatToDo')}${i.problem.fix}`) : null) : null,
          i.reading ? h('p', { class: 'muted small', 'data-testid': 'fixes-run-reading' }, t('fixes.summary.read'), ' ', statusBadge(i.reading.status), ' ', t('fixes.summary.problems', { count: fmtNumber(i.reading.problems) })) : null,
        ),
      ),
    );
  }

  // 5. the summary
  function summary(view, left) {
    const done = view.items.filter((i) => i.state === 'done').length;
    const failed = view.items.filter((i) => i.state === 'failed').length;
    const ok = !failed && !left.length;
    const closeNow = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fixes-close', onclick: () => close() }, t('fixes.summary.close'));
    place(
      clear(body),
      notice(ok ? 'info' : 'error', 'fixes-summary', h('strong', {}, t('fixes.summary.title')), ' ', t('fixes.summary.text', { done: fmtNumber(done), failed: fmtNumber(failed + left.length) })),
      runList(view, true),
      ...left.map((r) => notice('warn', 'fixes-not-run', h('strong', {}, `${r.device.name}: `), t('fixes.summary.notRun', { message: r.problem }))),
      h('div', { class: 'modal-actions' }, closeNow),
    );
    if (ok) toast(t('fixes.summary.toast', { done: fmtNumber(done) }));
  }

  review();
}
