// "Set up automatically" in the device form (#231). The order (#279): what it does, without any
// credential; the device's identity (SSH host key or certificate); only then the admin login,
// right before Run; then the steps as they ran. The password is only in its input field and in
// the one request; it is cleared right after it, on navigation and when left unused.
import { post } from '../api.js';
import { clear, groupHex, h, place } from '../util.js';
import { checkField, confirmDialog, field, run, toast } from '../ui.js';
import { adminStep, previewList, previewSteps } from './adminstep.js';

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
  const remove = h('input', { type: 'checkbox', 'data-testid': 'setup-remove' });
  const out = h('div', { 'data-testid': 'setup-result', 'aria-live': 'polite' });
  const planBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'setup-plan' }, 'Show what it does');
  let trusted = null;
  let trustedSsh = null;
  let step = null; // the admin step on screen, if any
  let acked = []; // ids of the steps the user has seen
  // an optional second step over SSH (OPNsense: the ISC DHCP script, #242): off unless ticked
  const opt = login.ssh_option;
  const sshOn = opt ? h('input', { type: 'checkbox', 'data-testid': 'setup-ssh' }) : null;
  // optional extras (OpenWrt: LLDP, #278): unticked; on Remove they mean "remove it too"
  const extras = (login.extras || []).map((x) => ({ x, box: h('input', { type: 'checkbox', 'data-testid': `setup-extra-${x.id}`, 'data-extra': x.id }), text: h('span', {}, x.label) }));
  const extraFields = extras.map(({ x, box, text }) => h('div', { class: 'field' }, h('label', { class: 'check' }, box, ' ', text), x.note ? h('small', { class: 'muted' }, x.note) : null));

  const ticked = () => [...extras.filter((e) => e.box.checked).map((e) => e.x.id), ...(opt && sshOn.checked ? ['ssh'] : [])];
  // a change of what is ticked starts over: the plan was for something else
  function reset() {
    if (step) step.dispose();
    step = null;
    clear(out);
  }
  remove.addEventListener('change', () => {
    extras.forEach(({ x, text }) => { text.textContent = remove.checked && x.remove_label ? x.remove_label : x.label; });
    reset();
  });
  for (const { box } of extras) box.addEventListener('change', reset);
  if (opt) sshOn.addEventListener('change', reset);

  const fail = (text, fix) => place(clear(out), h('p', { class: 'error', role: 'alert', 'data-testid': 'setup-error' }, text), fix ? h('p', { class: 'fix' }, 'What to do: ', fix) : null);

  // 1. what it does, without any credential
  function showPreview() {
    if (!collect()) return;
    if (step) step.dispose();
    step = null;
    const steps = previewSteps(login.preview, remove.checked, ticked());
    acked = steps.map((s) => s.id);
    const next = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-continue' }, 'Continue: check the device’s identity');
    next.addEventListener('click', () => run(next, identity));
    place(
      clear(out),
      h('p', {}, remove.checked ? 'Signalbox would remove what it set up. Usually:' : 'Signalbox would do this on the device, once. Usually:'),
      steps.length ? previewList(steps, 'setup-plan-steps') : null,
      h('p', { class: 'muted small' }, 'The exact steps depend on the device and are shown after the login if they differ. Nothing has been sent, and no password is asked for yet.'),
      h('div', { class: 'row' }, next),
    );
  }

  // 2. the device's identity, still without any credential
  async function identity() {
    const device = collect();
    if (!device) return;
    place(clear(out), h('p', { class: 'muted' }, 'Fetching the device’s identity (no login is sent)…'));
    try {
      const body = { device, admin: { user: login.user_default || '' }, remove: remove.checked, extras: ticked().filter((x) => x !== 'ssh') };
      if (login.port_default) body.admin.port = login.port_default;
      const plan = await post('/devices/setup', body);
      const kind = plan.fingerprint_kind === 'certificate' ? 'certificate' : 'SSH host key';
      const trust = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-trust' }, `Trust this ${kind}`);
      trust.addEventListener('click', () => { trusted = plan.fingerprint; showFinal(null); });
      place(
        clear(out),
        h(
          'div',
          { class: 'notice', 'data-testid': 'setup-untrusted' },
          h('h3', {}, `The device presented this ${kind}`),
          h('p', {}, 'Compare it with what the device itself shows before you trust it. If they differ, someone may be in between: do not trust it. No password has been asked for yet.'),
          h('p', { class: 'fingerprint mono', 'data-testid': 'setup-fingerprint' }, fingerprintText(plan)),
          plan.compare ? h('p', { class: 'muted small' }, plan.compare) : null,
          trust,
        ),
      );
    } catch (err) {
      fail(err.message, err.body && err.body.fix);
    }
  }

  // 3. the temporary password, right before Run
  function showFinal(extraNote) {
    if (step) step.dispose();
    let sshSecret = null;
    let sshPort = null;
    const more = [];
    if (opt && sshOn.checked) {
      sshSecret = h('input', { type: 'password', autocomplete: 'new-password', spellcheck: 'false', 'data-testid': 'setup-ssh-secret' });
      sshPort = h('input', { type: 'number', min: '1', max: '65535', value: String(opt.port_default), 'data-testid': 'setup-ssh-port' });
      more.push({ el: h('div', { class: 'ssh-option-fields', 'data-testid': 'setup-ssh-fields' }, field(`${opt.secret_label} (${opt.user})`, sshSecret), field('SSH port', sshPort)), input: sshSecret });
    }
    step = adminStep(login, 'setup', login.port_default, more);
    const removing = remove.checked;
    const go = h('button', { class: removing ? 'btn danger' : 'btn primary', type: 'button', 'data-testid': 'setup-apply' }, removing ? 'Run: remove it from the device' : 'Run: set up the device');
    go.addEventListener('click', () => run(go, () => doApply(sshSecret, sshPort)));
    place(
      clear(out),
      extraNote,
      h('p', { class: 'muted small' }, 'The device’s identity is confirmed. Nothing is sent until you press Run.'),
      step.el,
      h('div', { class: 'row' }, go),
    );
  }

  // 4. Run: one request with the password, then it is gone
  async function doApply(sshSecret, sshPort) {
    const device = collect();
    if (!device || !step) return;
    const removing = remove.checked;
    if (!step.secret()) return fail(`Enter the ${login.secret_label}.`);
    if (sshSecret && !sshSecret.value) return fail(`Enter the ${opt.secret_label} (${opt.user}), or untick “${opt.label}”.`);
    if (removing && !(await confirmDialog({ title: 'Remove the login?', message: 'Signalbox deletes the login and permissions it set up on the device. It cannot read the device with them afterwards.', confirmLabel: 'Remove', danger: true }))) {
      step.wipe(); // cancelled: the password does not stay in the field
      return;
    }
    const admin = { user: step.user(), secret: step.secret() };
    if (step.port()) admin.port = step.port();
    const body = { device, admin, remove: removing, trust: trusted, extras: ticked().filter((x) => x !== 'ssh'), plan_ids: acked };
    if (sshSecret) {
      body.ssh = { secret: sshSecret.value, trust: trustedSsh };
      if (sshPort && sshPort.value) body.ssh.port = Number(sshPort.value);
    }
    place(clear(out), h('p', { class: 'muted' }, removing ? 'Removing…' : 'Setting up the device…'));
    const current = step;
    let res;
    try {
      res = await post('/devices/setup/apply', body);
    } catch (err) {
      current.wipe();
      return failed(err);
    }
    current.dispose(); // the password is gone as soon as the request is answered
    step = null;
    place(out, h('p', { 'data-testid': 'setup-outcome', class: res.ok ? '' : 'error' }, res.ok ? (removing ? 'Removed.' : 'Done. The device is saved with its new login.') : 'The setup stopped at a failed step. Fix it and run it again: steps that are done already are skipped.'), stepList(res.steps, 'setup-done-steps'));
    if (res.ok && res.device) {
      toast(`${res.device.name} set up.`);
      onDone(res.device);
    }
  }

  // a refusal: a changed plan or identity goes back to that step, with no password kept
  function failed(err) {
    if (err.code === 'plan_changed' && err.body && err.body.plan) {
      acked = err.body.plan.steps.filter((s) => s.state === 'todo').map((s) => s.id);
      return showFinal(h('div', { class: 'notice', 'data-testid': 'setup-plan-changed' }, h('p', {}, 'The device needs steps that were not in the first plan. Nothing was changed. Check the plan and run it again:'), stepList(err.body.plan.steps, 'setup-plan-steps')));
    }
    if (err.code === 'untrusted_ssh') {
      const trustSsh = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-trust-ssh' }, 'Trust this SSH host key');
      trustSsh.addEventListener('click', () => { trustedSsh = err.body.fingerprint; showFinal(null); });
      return place(
        clear(out),
        h(
          'div',
          { class: 'notice', 'data-testid': 'setup-untrusted-ssh' },
          h('h3', {}, 'The device presented an SSH host key Signalbox does not trust yet'),
          h('p', {}, 'Compare it with what the device itself shows before you trust it. If they differ, do not trust it: the SSH password has not been sent.'),
          h('p', { class: 'fingerprint mono', 'data-testid': 'setup-ssh-fingerprint' }, err.body.fingerprint),
          err.body.compare ? h('p', { class: 'muted small' }, err.body.compare) : null,
          trustSsh,
        ),
      );
    }
    if (err.code === 'untrusted') { trusted = null; trustedSsh = null; }
    fail(err.message, err.body && err.body.fix);
  }

  planBtn.addEventListener('click', () => run(planBtn, async () => showPreview()));
  return h(
    'details',
    { class: 'setup-guide notice', 'data-testid': 'auto-setup' },
    h('summary', {}, 'Set up automatically with the admin login'),
    h('p', {}, `Signalbox logs in once over ${login.transport}, sets up its own login with the permissions of the setup guide (read-only unless “Allow changes” is on) and fills in the settings below. First you see what it does and confirm the device’s identity; the admin password is asked for last, used once and never saved.`),
    login.note ? h('p', { class: 'muted small' }, login.note) : null,
    opt ? checkField(opt.label, sshOn, opt.note) : null,
    checkField('Remove what Signalbox set up instead', remove, null),
    ...extraFields,
    h('div', { class: 'row' }, planBtn),
    out,
  );
}
