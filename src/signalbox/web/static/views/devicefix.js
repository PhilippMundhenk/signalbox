// "Fix it" next to a read problem the device's integration can repair (#215): the admin login
// for one step, the exact plan (after the SSH host key or certificate is confirmed), a
// confirmation, the steps as they ran and the device read again. The admin password is only in
// the input field and in the request; it is cleared after every use. Never runs by itself.
import { enc, post } from '../api.js';
import { clear, h, place } from '../util.js';
import { confirmDialog, field, run, toast } from '../ui.js';
import { fingerprintText, stepList } from './devicesetup.js';
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
  const user = h('input', { type: 'text', value: login.user_default || '', autocomplete: 'off', spellcheck: 'false', 'data-testid': 'fix-admin-user' });
  const secret = h('input', { type: 'password', autocomplete: 'off', 'data-testid': 'fix-admin-secret' });
  const port = login.port_default ? h('input', { type: 'number', min: '1', max: '65535', value: String(login.port_default), 'data-testid': 'fix-admin-port' }) : null;
  const out = h('div', { 'data-testid': 'fix-result', 'aria-live': 'polite' });
  const planBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'fix-plan' }, 'Show what it does');
  const url = `/devices/${enc(device.id)}/fix`;
  let trusted = null;

  const showError = (err) => {
    place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'fix-error' }, err.message), err.body && err.body.fix ? h('p', { class: 'fix' }, 'What to do: ', err.body.fix) : null);
    if (err.code === 'untrusted') trusted = null;
  };

  const request = () => {
    if (!secret.value) {
      place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'fix-error' }, `Enter the ${login.secret_label}.`));
      return null;
    }
    const admin = { user: user.value.trim(), secret: secret.value };
    if (port && port.value) admin.port = Number(port.value);
    return { remedy: remedy.id, admin, trust: trusted };
  };

  const showPlan = (plan) => {
    clear(out);
    if (!plan.trusted) {
      const kind = plan.fingerprint_kind === 'certificate' ? 'certificate' : 'SSH host key';
      const trust = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-trust' }, `Trust this ${kind}`);
      trust.addEventListener('click', () =>
        run(trust, async () => {
          trusted = plan.fingerprint;
          await doPlan();
        }),
      );
      place(
        out,
        h(
          'div',
          { class: 'notice', 'data-testid': 'fix-untrusted' },
          h('h3', {}, `The device presented an ${kind} Signalbox does not trust yet`),
          h('p', {}, 'Compare it with what the device itself shows before you trust it. If they differ, someone may be in between: do not trust it, and do not send the admin login.'),
          h('p', { class: 'fingerprint mono', 'data-testid': 'fix-fingerprint' }, fingerprintText(plan)),
          plan.compare ? h('p', { class: 'muted small' }, plan.compare) : null,
          trust,
        ),
      );
      return;
    }
    const pending = plan.steps.some((s) => s.state === 'todo');
    const go = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'fix-apply' }, 'Fix it on the device');
    go.disabled = !pending;
    go.addEventListener('click', () => run(go, doApply));
    place(
      out,
      h('p', {}, pending ? 'Signalbox will do this on the device, with the admin login, once:' : 'Everything is already as needed; there is nothing to fix on the device.'),
      stepList(plan.steps, 'fix-plan-steps'),
      h('p', { class: 'muted small' }, `Trusted ${plan.fingerprint_kind === 'certificate' ? 'certificate' : 'SSH host key'}: `, h('span', { class: 'mono' }, fingerprintText(plan))),
      h('div', { class: 'row' }, go),
    );
  };

  async function doPlan() {
    const body = request();
    if (!body) return;
    place(clear(out), h('p', { class: 'muted' }, 'Asking the device…'));
    try {
      showPlan(await post(url, body));
    } catch (err) {
      showError(err);
    }
  }

  async function doApply() {
    const body = request();
    if (!body) return;
    const ok = await confirmDialog({ title: `${remedy.title} on ${device.name}?`, message: 'Signalbox logs in with the admin login once and runs the steps shown. It changes only the packages and permissions it reads through, never network settings.', confirmLabel: 'Fix it' });
    if (!ok) return;
    place(clear(out), h('p', { class: 'muted' }, 'Fixing…'));
    try {
      const res = await post(`${url}/apply`, body);
      secret.value = '';
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
    } catch (err) {
      showError(err);
    }
  }

  planBtn.addEventListener('click', () => run(planBtn, doPlan));
  return h(
    'div',
    { class: 'setup-guide notice fix-panel', 'data-testid': 'fix-panel', 'data-remedy': remedy.id },
    h('h3', {}, `Fix it: ${remedy.title}`),
    h('p', {}, remedy.description),
    h('p', { class: 'muted small' }, `Signalbox logs in once over ${login.transport}. The admin login is used for this step only: it is not stored and not logged. You can also do it by hand, as described above.`),
    login.note ? h('p', { class: 'muted small' }, login.note) : null,
    field(login.user_label, user),
    field(login.secret_label, secret),
    port ? field('SSH port', port) : null,
    h('div', { class: 'row' }, planBtn),
    out,
  );
}
