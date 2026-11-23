// "Fix it" next to a read problem the device's integration can repair (#215). The order (#279):
// what it does, without any credential; the device's identity (SSH host key or certificate);
// only then the admin login, right before the button that runs it; then the steps as they ran
// and the device read again. The password is only in its input field and in the one request; it
// is cleared right after it, on navigation and when left unused. Never runs by itself.
import { enc, post } from '../api.js';
import { clear, h, place } from '../util.js';
import { confirmDialog, run, toast } from '../ui.js';
import { fingerprintText, stepList } from './devicesetup.js';
import { adminStep, previewList } from './adminstep.js';
import { testResult } from './devicetest.js';

// The remedy of an error or finding, when the integration offers it (setup.fixes on).
export function remedyOf(adapter, id) {
  if (!adapter || !id) return null;
  return (adapter.remedies || []).find((r) => r.id === id) || null;
}

// device: the stored device; adapter: its integration (with admin_login and remedies);
// remedy: one of adapter.remedies; onDone(reading): the remedy ran and the device was read.
export function fixPanel(device, adapter, remedy, onDone) {
  const login = adapter.admin_login;
  const portDefault = remedy.port_default || login.port_default;
  const transport = remedy.transport || login.transport;
  const out = h('div', { 'data-testid': 'fix-result', 'aria-live': 'polite' });
  const planBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'fix-plan' }, 'Show what it does');
  const url = `/devices/${enc(device.id)}/fix`;
  let trusted = null;
  let step = null;
  let acked = (remedy.preview || []).map((s) => s.id);

  const showError = (err) => {
    place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'fix-error' }, err.message), err.body && err.body.fix ? h('p', { class: 'fix' }, 'What to do: ', err.body.fix) : null);
    if (err.code === 'untrusted') trusted = null;
  };

  // 1. what it does, without any credential
  function showPreview() {
    if (step) step.dispose();
    step = null;
    const next = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-continue' }, 'Continue: check the device’s identity');
    next.addEventListener('click', () => run(next, identity));
    place(
      clear(out),
      h('p', {}, 'Signalbox would do this on the device, once. Usually:'),
      (remedy.preview || []).length ? previewList(remedy.preview, 'fix-plan-steps') : null,
      h('p', { class: 'muted small' }, 'The exact steps depend on the device and are shown after the login if they differ. Nothing has been sent, and no password is asked for yet.'),
      h('div', { class: 'row' }, next),
    );
  }

  // 2. the device's identity, still without any credential
  async function identity() {
    place(clear(out), h('p', { class: 'muted' }, 'Fetching the device’s identity (no login is sent)…'));
    try {
      const body = { remedy: remedy.id, admin: { user: login.user_default || '' } };
      if (portDefault) body.admin.port = portDefault;
      const plan = await post(url, body);
      const kind = plan.fingerprint_kind === 'certificate' ? 'certificate' : 'SSH host key';
      const trust = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-trust' }, `Trust this ${kind}`);
      trust.addEventListener('click', () => { trusted = plan.fingerprint; showFinal(null); });
      place(
        clear(out),
        h(
          'div',
          { class: 'notice', 'data-testid': 'fix-untrusted' },
          h('h3', {}, `The device presented this ${kind}`),
          h('p', {}, 'Compare it with what the device itself shows before you trust it. If they differ, someone may be in between: do not trust it. No password has been asked for yet.'),
          h('p', { class: 'fingerprint mono', 'data-testid': 'fix-fingerprint' }, fingerprintText(plan)),
          plan.compare ? h('p', { class: 'muted small' }, plan.compare) : null,
          trust,
        ),
      );
    } catch (err) {
      showError(err);
    }
  }

  // 3. the temporary password, right before the button
  function showFinal(extraNote) {
    if (step) step.dispose();
    step = adminStep(login, 'fix', portDefault);
    const go = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-apply' }, 'Run: fix it on the device');
    go.addEventListener('click', () => run(go, doApply));
    place(
      clear(out),
      extraNote,
      h('p', { class: 'muted small' }, 'The device’s identity is confirmed. Nothing is sent until you press Run.'),
      step.el,
      h('div', { class: 'row' }, go),
    );
  }

  // 4. Run: one request with the password, then it is gone
  async function doApply() {
    if (!step) return;
    if (!step.secret()) return showMissing();
    const ok = await confirmDialog({ title: `${remedy.title} on ${device.name}?`, message: 'Signalbox logs in with the admin login once and runs the steps. It changes only the packages and permissions it reads through, never network settings.', confirmLabel: 'Fix it' });
    if (!ok) {
      step.wipe(); // cancelled: the password does not stay in the field
      return;
    }
    const admin = { user: step.user(), secret: step.secret() };
    if (step.port()) admin.port = step.port();
    const body = { remedy: remedy.id, admin, trust: trusted, plan_ids: acked };
    const current = step;
    let res;
    try {
      res = await post(`${url}/apply`, body);
    } catch (err) {
      current.wipe();
      return failed(err);
    }
    current.dispose(); // the password is gone as soon as the request is answered
    step = null;
    place(
      clear(out),
      h('p', { 'data-testid': 'fix-outcome', class: res.ok ? '' : 'error' }, res.ok ? 'Done. Signalbox read the device again:' : 'The fix stopped at a failed step. Fix that and run it again: steps that are done already are skipped.'),
      stepList(res.steps, 'fix-done-steps'),
      res.reading ? testResult(res.reading) : null,
    );
    if (res.ok) {
      toast(`${remedy.title}: done on ${device.name}.`);
      if (onDone) onDone(res.reading);
    }
  }

  function showMissing() {
    const note = h('p', { class: 'error', role: 'alert', 'data-testid': 'fix-error' }, `Enter the ${login.secret_label}.`);
    step.el.append(note);
  }

  // a refusal: a changed plan goes back to the last step, with no password kept
  function failed(err) {
    if (err.code === 'plan_changed' && err.body && err.body.plan) {
      acked = err.body.plan.steps.filter((s) => s.state === 'todo').map((s) => s.id);
      return showFinal(h('div', { class: 'notice', 'data-testid': 'fix-plan-changed' }, h('p', {}, 'The device needs steps that were not in the first plan. Nothing was changed. Check the plan and run it again:'), stepList(err.body.plan.steps, 'fix-plan-steps')));
    }
    showError(err);
  }

  planBtn.addEventListener('click', () => run(planBtn, async () => showPreview()));
  return h(
    'div',
    { class: 'setup-guide notice fix-panel', 'data-testid': 'fix-panel', 'data-remedy': remedy.id },
    h('h3', {}, `Fix it: ${remedy.title}`),
    h('p', {}, remedy.description),
    h('p', { class: 'muted small' }, `Signalbox logs in once over ${transport}. First you see what it does and confirm the device’s identity; the admin password is asked for last, used once and never saved. You can also do it by hand, as described above.`),
    login.note ? h('p', { class: 'muted small' }, login.note) : null,
    h('div', { class: 'row' }, planBtn),
    out,
  );
}
