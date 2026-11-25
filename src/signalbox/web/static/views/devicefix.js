// "Fix it" next to a read problem the device's integration can repair (#215). The order (#279):
// what it does, without any credential; the device's identity (SSH host key or certificate);
// only then the admin login, right before the button that runs it; then the steps as they ran
// and the device read again. The password is only in its input field and in the one request; it
// is cleared right after it, on navigation and when left unused. Never runs by itself.
import { enc, post } from '../api.js';
import { t } from '../i18n.js';
import { apiFix, apiMessage } from '../texts.js';
import { clear, h, place } from '../util.js';
import { clearNotice, confirmDialog, field, notice, run, setNotice, slot, toast } from '../ui.js';
import { fingerprintText, stepList } from './devicesetup.js';
import { adminStep, previewList } from './adminstep.js';
import { hostKeyChanged, hostKeyKnown, isChanged, isKnown } from './hostkey.js';
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
  const port = portDefault ? h('input', { type: 'number', min: '1', max: '65535', value: String(portDefault), 'data-testid': 'fix-admin-port' }) : null;
  const planBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'fix-plan' }, t('fix.showPlan'));
  const url = `/devices/${enc(device.id)}/fix`;
  let trusted = null;
  let known = null; // the SSH host key confirmed before (#526), shown in place of the prompt
  let step = null;
  let acked = (remedy.preview || []).map((s) => s.id);

  const missBox = slot(); // "enter the password": one place, replaced by the next result
  const showError = (err) => {
    place(clear(out), notice('error', 'fix-error', h('p', {}, apiMessage(err)), apiFix(err) ? h('p', { class: 'fix' }, t('fix.whatToDo'), apiFix(err)) : null));
    if (err.code === 'untrusted') trusted = null;
  };

  // 1. what it does, without any credential
  function showPreview() {
    if (step) step.dispose();
    step = null;
    const next = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-continue' }, t('fix.continue'));
    next.addEventListener('click', () => run(next, identity));
    place(
      clear(out),
      h('p', {}, t('fix.planIntro')),
      (remedy.preview || []).length ? previewList(remedy.preview, 'fix-plan-steps') : null,
      h('p', { class: 'muted small' }, t('fix.planNote')),
      h('div', { class: 'row' }, next),
    );
  }

  // 2. the device's identity, still without any credential
  async function identity() {
    place(clear(out), h('p', { class: 'muted' }, t('fix.fetching')));
    try {
      const body = { remedy: remedy.id, admin: { user: login.user_default || '' } };
      if (port && port.value) body.admin.port = Number(port.value);
      const plan = await post(url, body);
      const cert = plan.fingerprint_kind === 'certificate';
      // a changed SSH host key (#526): the warning, nothing else; nothing was sent
      if (isChanged(plan.host_key)) return place(clear(out), hostKeyChanged(plan.host_key, device, 'fix-host-key-changed', identity));
      // the key confirmed before: no prompt, the step list says since when
      known = isKnown(plan.host_key) ? plan.host_key : null;
      if (known) {
        trusted = plan.fingerprint;
        return showFinal(null);
      }
      const trust = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-trust' }, t(cert ? 'fix.trustCertificate' : 'fix.trustSshKey'));
      trust.addEventListener('click', () => { trusted = plan.fingerprint; showFinal(null); });
      place(
        clear(out),
        notice('warn', 'fix-untrusted', h('h3', {}, t(cert ? 'fix.presentedCertificate' : 'fix.presentedSshKey')),
          h('p', {}, t('fix.compare')),
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
    step = adminStep(login, 'fix');
    const go = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-apply' }, t('fix.run'));
    go.addEventListener('click', () => run(go, doApply));
    place(
      clear(out),
      extraNote,
      h('p', { class: 'muted small' }, t('fix.confirmed')),
      known ? hostKeyKnown(known, 'fix-host-key-known') : null,
      step.el,
      clearNotice(missBox),
      h('div', { class: 'row' }, go),
    );
  }

  // 4. Run: one request with the password, then it is gone
  async function doApply() {
    if (!step) return;
    clearNotice(missBox);
    if (!step.secret()) return showMissing();
    const ok = await confirmDialog({ title: t('fix.confirmTitle', { title: remedy.title, name: device.name }), message: t('fix.confirmMessage'), confirmLabel: t('fix.fixIt') });
    if (!ok) {
      step.wipe(); // cancelled: the password does not stay in the field
      return;
    }
    const admin = { user: step.user(), secret: step.secret() };
    if (port && port.value) admin.port = Number(port.value);
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
      notice(res.ok ? 'info' : 'error', 'fix-outcome', res.ok ? t('fix.done') : t('fix.failedStep')),
      stepList(res.steps, 'fix-done-steps'),
      res.reading ? testResult(res.reading, { errors: false }) : null,
    );
    if (res.ok) {
      toast(t('fix.toastDone', { title: remedy.title, name: device.name }));
      if (onDone) onDone(res.reading);
    }
  }

  function showMissing() {
    setNotice(missBox, 'error', 'fix-error', t('fix.enterSecret', { label: login.secret_label }));
  }

  // a refusal: a changed plan goes back to the last step, with no password kept
  function failed(err) {
    if (err.code === 'host_key_changed' && err.body && err.body.host_key) {
      // another SSH host key than the confirmed one (#526): no password was sent
      trusted = null;
      known = null;
      return place(clear(out), hostKeyChanged(err.body.host_key, device, 'fix-host-key-changed', identity));
    }
    if (err.code === 'plan_changed' && err.body && err.body.plan) {
      acked = err.body.plan.steps.filter((s) => s.state === 'todo').map((s) => s.id);
      return showFinal(notice('warn', 'fix-plan-changed', h('p', {}, t('fix.planChanged')), stepList(err.body.plan.steps, 'fix-plan-steps')));
    }
    showError(err);
  }

  planBtn.addEventListener('click', () => run(planBtn, async () => showPreview()));
  return h(
    'div',
    { class: 'setup-guide notice fix-panel', 'data-testid': 'fix-panel', 'data-remedy': remedy.id },
    h('h3', {}, t('fix.title', { title: remedy.title })),
    h('p', {}, remedy.description),
    h('p', { class: 'muted small' }, t('fix.intro', { transport })),
    login.note ? h('p', { class: 'muted small' }, login.note) : null,
    port ? field(t('fix.sshPort'), port) : null,
    h('div', { class: 'row' }, planBtn),
    out,
  );
}
