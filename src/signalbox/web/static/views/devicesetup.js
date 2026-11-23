// "Set up automatically" in the device form (#231): the admin login for one step, the plan
// (after the SSH host key or certificate is confirmed), then the steps as they ran. The admin
// password is only in the input field and in the request; it is cleared after every use.
import { post } from '../api.js';
import { clear, groupHex, h, place } from '../util.js';
import { checkField, confirmDialog, field, run, toast } from '../ui.js';

const STATE_TEXT = { todo: 'will be done', unchanged: 'already as needed', done: 'done', failed: 'failed', skipped: 'not run' };

export function stepList(steps, testid) {
  return h(
    'ol',
    { class: 'setup-steps', 'data-testid': testid },
    steps.map((s) =>
      h(
        'li',
        { class: `setup-step state-${s.state}`, 'data-testid': 'setup-step', 'data-step': s.id, 'data-state': s.state },
        h('span', { class: `badge step-${s.state}` }, STATE_TEXT[s.state] || s.state),
        ' ',
        h('strong', {}, s.title),
        s.message ? h('p', { class: s.state === 'failed' ? 'error' : 'muted small' }, s.message) : null,
        s.detail ? h('details', {}, h('summary', { class: 'small' }, 'What is sent'), h('pre', { class: 'commands' }, s.detail)) : null,
      ),
    ),
  );
}

export function fingerprintText(plan) {
  return plan.fingerprint_kind === 'certificate' ? groupHex(plan.fingerprint) : plan.fingerprint;
}

// a: the adapter (with admin_login); collect(): the device form's body or null (shows errors);
// onDone(device): the device was saved with the new login.
export function autoSetup(a, collect, onDone) {
  const login = a.admin_login;
  const user = h('input', { type: 'text', value: login.user_default || '', autocomplete: 'off', spellcheck: 'false', 'data-testid': 'setup-admin-user' });
  const secret = h('input', { type: 'password', autocomplete: 'off', 'data-testid': 'setup-admin-secret' });
  const port = login.port_default ? h('input', { type: 'number', min: '1', max: '65535', value: String(login.port_default), 'data-testid': 'setup-admin-port' }) : null;
  const remove = h('input', { type: 'checkbox', 'data-testid': 'setup-remove' });
  const out = h('div', { 'data-testid': 'setup-result', 'aria-live': 'polite' });
  const planBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'setup-plan' }, 'Show what it does');
  let trusted = null;
  // an optional second step over SSH (OPNsense: the ISC DHCP script, #242): off unless ticked
  const opt = login.ssh_option;
  const sshOn = opt ? h('input', { type: 'checkbox', 'data-testid': 'setup-ssh' }) : null;
  const sshSecret = opt ? h('input', { type: 'password', autocomplete: 'off', 'data-testid': 'setup-ssh-secret' }) : null;
  const sshPort = opt ? h('input', { type: 'number', min: '1', max: '65535', value: String(opt.port_default), 'data-testid': 'setup-ssh-port' }) : null;
  const sshFields = opt ? h('div', { class: 'ssh-option-fields', hidden: true, 'data-testid': 'setup-ssh-fields' }, field(`${opt.secret_label} (${opt.user})`, sshSecret), field('SSH port', sshPort)) : null;
  if (opt) sshOn.addEventListener('change', () => { sshFields.hidden = !sshOn.checked; trustedSsh = null; });
  let trustedSsh = null;
  // optional extras (OpenWrt: LLDP, #278): unticked; on Remove they mean "remove it too"
  const extras = (login.extras || []).map((x) => ({ x, box: h('input', { type: 'checkbox', 'data-testid': `setup-extra-${x.id}`, 'data-extra': x.id }), text: h('span', {}, x.label) }));
  const extraFields = extras.map(({ x, box, text }) => h('div', { class: 'field' }, h('label', { class: 'check' }, box, ' ', text), x.note ? h('small', { class: 'muted' }, x.note) : null));
  remove.addEventListener('change', () => extras.forEach(({ x, text }) => { text.textContent = remove.checked && x.remove_label ? x.remove_label : x.label; }));

  const request = () => {
    const device = collect();
    if (!device) return null;
    if (!secret.value) {
      place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'setup-error' }, `Enter the ${login.secret_label}.`));
      return null;
    }
    const admin = { user: user.value.trim(), secret: secret.value };
    if (port && port.value) admin.port = Number(port.value);
    const body = { device, admin, remove: remove.checked, trust: trusted, extras: extras.filter((e) => e.box.checked).map((e) => e.x.id) };
    if (opt && sshOn.checked) {
      if (!sshSecret.value) {
        place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'setup-error' }, `Enter the ${opt.secret_label} (${opt.user}), or untick “${opt.label}”.`));
        return null;
      }
      body.ssh = { secret: sshSecret.value, trust: trustedSsh };
      if (sshPort.value) body.ssh.port = Number(sshPort.value);
    }
    return body;
  };

  const showPlan = (plan, body) => {
    clear(out);
    if (!plan.trusted) {
      const kind = plan.fingerprint_kind === 'certificate' ? 'certificate' : 'SSH host key';
      const trust = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-trust' }, `Trust this ${kind}`);
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
          { class: 'notice', 'data-testid': 'setup-untrusted' },
          h('h3', {}, `The device presented an ${kind} Signalbox does not trust yet`),
          h('p', {}, 'Compare it with what the device itself shows before you trust it. If they differ, someone may be in between: do not trust it, and do not send the admin login.'),
          h('p', { class: 'fingerprint mono', 'data-testid': 'setup-fingerprint' }, fingerprintText(plan)),
          plan.compare ? h('p', { class: 'muted small' }, plan.compare) : null,
          trust,
        ),
      );
      return;
    }
    if (plan.ssh_trusted === false) {
      const trustSsh = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-trust-ssh' }, 'Trust this SSH host key');
      trustSsh.addEventListener('click', () =>
        run(trustSsh, async () => {
          trustedSsh = plan.ssh_fingerprint;
          await doPlan();
        }),
      );
      place(
        out,
        h(
          'div',
          { class: 'notice', 'data-testid': 'setup-untrusted-ssh' },
          h('h3', {}, 'The device presented an SSH host key Signalbox does not trust yet'),
          h('p', {}, 'Compare it with what the device itself shows before you trust it. If they differ, do not trust it: the SSH password has not been sent.'),
          h('p', { class: 'fingerprint mono', 'data-testid': 'setup-ssh-fingerprint' }, plan.ssh_fingerprint),
          plan.ssh_compare ? h('p', { class: 'muted small' }, plan.ssh_compare) : null,
          trustSsh,
        ),
      );
      return;
    }
    const pending = plan.steps.some((s) => s.state === 'todo');
    const go = h('button', { class: body.remove ? 'btn danger' : 'btn primary', type: 'button', 'data-testid': 'setup-apply' }, body.remove ? 'Remove it from the device' : 'Set up the device');
    go.disabled = !pending && body.remove;
    go.addEventListener('click', () => run(go, () => doApply(body.remove)));
    place(
      out,
      h('p', {}, body.remove ? 'Signalbox will remove what it set up:' : 'Signalbox will do this on the device, with the admin login, once:'),
      stepList(plan.steps, 'setup-plan-steps'),
      h('p', { class: 'muted small' }, `Trusted ${plan.fingerprint_kind === 'certificate' ? 'certificate' : 'SSH host key'}: `, h('span', { class: 'mono' }, fingerprintText(plan))),
      h('div', { class: 'row' }, go),
    );
  };

  async function doPlan() {
    const body = request();
    if (!body) return;
    place(clear(out), h('p', { class: 'muted' }, 'Asking the device…'));
    try {
      showPlan(await post('/devices/setup', body), body);
    } catch (err) {
      place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'setup-error' }, err.message), err.body && err.body.fix ? h('p', { class: 'fix' }, 'What to do: ', err.body.fix) : null);
      if (err.code === 'untrusted') { trusted = null; trustedSsh = null; }
    }
  }

  async function doApply(removing) {
    const body = request();
    if (!body) return;
    if (removing && !(await confirmDialog({ title: 'Remove the login?', message: 'Signalbox deletes the login and permissions it set up on the device. It cannot read the device with them afterwards.', confirmLabel: 'Remove', danger: true }))) return;
    place(clear(out), h('p', { class: 'muted' }, removing ? 'Removing…' : 'Setting up the device…'));
    try {
      const res = await post('/devices/setup/apply', body);
      secret.value = '';
      if (sshSecret) sshSecret.value = '';
      clear(out);
      place(out, h('p', { 'data-testid': 'setup-outcome', class: res.ok ? '' : 'error' }, res.ok ? (removing ? 'Removed.' : 'Done. The device is saved with its new login.') : 'The setup stopped at a failed step. Fix it and run it again: steps that are done already are skipped.'), stepList(res.steps, 'setup-done-steps'));
      if (res.ok && res.device) {
        toast(`${res.device.name} set up.`);
        onDone(res.device);
      }
    } catch (err) {
      place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'setup-error' }, err.message));
      if (err.code === 'untrusted') { trusted = null; trustedSsh = null; }
    }
  }

  planBtn.addEventListener('click', () => run(planBtn, doPlan));
  return h(
    'details',
    { class: 'setup-guide notice', 'data-testid': 'auto-setup' },
    h('summary', {}, 'Set up automatically with the admin login'),
    h('p', {}, `Signalbox logs in once over ${login.transport}, sets up its own login with the permissions of the setup guide (read-only unless “Allow changes” is on) and fills in the settings below. The admin login is used for this step only: it is not stored and not logged.`),
    login.note ? h('p', { class: 'muted small' }, login.note) : null,
    field(login.user_label, user),
    field(login.secret_label, secret),
    port ? field('SSH port', port) : null,
    opt ? checkField(opt.label, sshOn, opt.note) : null,
    sshFields,
    checkField('Remove what Signalbox set up instead', remove, null),
    ...extraFields,
    h('div', { class: 'row' }, planBtn),
    out,
  );
}
