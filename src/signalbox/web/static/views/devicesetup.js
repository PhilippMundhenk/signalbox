// "Set up automatically" in the device form (#231). The order (#279): what it does, without any
// credential; the device's identity (SSH host key or certificate); only then the admin login,
// right before Run; then the steps as they ran. The password is only in its input field and in
// the one request; it is cleared right after it, on navigation and when left unused.
import { ApiError, get, post } from '../api.js';
import { t } from '../i18n.js';
import { apiFix, apiMessage, stepMessage, stepTitle } from '../texts.js';
import { clear, groupHex, h, place } from '../util.js';
import { busy, checkField, clearNotice, confirmDialog, field, notice, run, setNotice, slot, toast } from '../ui.js';
import { adminStep, previewList, previewSteps } from './adminstep.js';
import { hostKeyChanged, hostKeyKnown, isChanged, isKnown, offeredKeys } from './hostkey.js';

const STATE_KEY = { todo: 'setup.state.todo', unchanged: 'setup.state.unchanged', done: 'setup.state.done', failed: 'setup.state.failed', skipped: 'setup.state.skipped', running: 'setup.state.running', waiting: 'setup.state.waiting' };
const stateText = (state) => (STATE_KEY[state] ? t(STATE_KEY[state]) : state);

export function stepList(steps, testid) {
  return h(
    'ol',
    { class: 'setup-steps', 'data-testid': testid },
    steps.map((s) =>
      h(
        'li',
        { class: `setup-step state-${s.state}`, 'data-testid': 'setup-step', 'data-step': s.id, 'data-state': s.state },
        h('span', { class: `badge step-${s.state}` }, stateText(s.state)),
        ' ',
        h('strong', {}, stepTitle(s)),
        s.message ? h('p', { class: s.state === 'failed' ? 'error' : 'muted small' }, stepMessage(s)) : null,
        s.detail ? h('details', {}, h('summary', { class: 'small' }, t('setup.whatIsSent')), h('pre', { class: 'commands' }, s.detail)) : null,
      ),
    ),
  );
}

// The steps of a run on screen (#316): every planned step, each as the job reports it; the one
// running right now is marked, the ones not reached yet wait. Text nodes only.
function progressList(planned, view) {
  const seen = new Map((view.steps || []).map((s) => [s.id, s]));
  const rows = planned.map((p) => seen.get(p.id) || p);
  for (const s of view.steps || []) if (!planned.some((p) => p.id === s.id)) rows.push(s);
  return h(
    'ol',
    { class: 'setup-steps', 'data-testid': 'setup-progress-steps' },
    rows.map((s) => {
      const state = s.id === view.current ? 'running' : seen.has(s.id) ? s.state : 'waiting';
      return h(
        'li',
        { class: `setup-step state-${state}`, 'data-testid': 'setup-step', 'data-step': s.id, 'data-state': state, ...(state === 'running' ? { 'aria-current': 'step' } : {}) },
        h('span', { class: `badge step-${state}` }, stateText(state)),
        ' ',
        h('strong', {}, stepTitle(s)),
        s.message ? h('p', { class: s.state === 'failed' ? 'error' : 'muted small' }, stepMessage(s)) : null,
      );
    }),
  );
}

const POLL_MS = 400;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function fingerprintText(plan) {
  return plan.fingerprint_kind === 'certificate' ? groupHex(plan.fingerprint) : plan.fingerprint;
}

// The login Signalbox creates when the settings name an admin login (#299).
const OWN_LOGIN = 'signalbox';

// a: the adapter (with admin_login); collect(): the device form's body or null (shows errors);
// onDone(device): the device was saved with the new login;
// own: { get(), set(name) } the "user name" setting of the device form (or null).
export function autoSetup(a, collect, onDone, own = null) {
  const login = a.admin_login;
  let previewed = []; // the steps the user saw in the preview, kept for the password step
  let confirmedFingerprint = null;
  let knownKeys = []; // SSH host keys confirmed before (#526): shown in place of the prompt
  let adminUser = null; // what was typed last: kept when the login is refused
  const loginNote = h('div', { 'data-testid': 'setup-login-note', 'aria-live': 'polite' });
  const adminNames = () => new Set(['root', 'admin', login.user_default, step && step.user(), adminUser].filter(Boolean));
  // the user name in the settings is an admin login: the setup creates its own, so the name
  // is replaced (never refused); the note says so before and after
  function checkLogin(replace) {
    const now = own && own.get();
    if (!now || !adminNames().has(now)) return;
    if (replace) own.set(OWN_LOGIN);
    place(clear(loginNote), notice('info', 'setup-login-replaced', replace ? t('setup.loginReplaced', { old: now, name: OWN_LOGIN }) : t('setup.loginWillBeReplaced', { old: now, name: OWN_LOGIN })));
  }
  const collectOwn = () => {
    checkLogin(true);
    return collect();
  };
  const remove = h('input', { type: 'checkbox', 'data-testid': 'setup-remove' });
  const out = h('div', { 'data-testid': 'setup-result', 'aria-live': 'polite' });
  // the port is needed to fetch the identity, so it is asked before: it is no secret
  const port = login.port_default ? h('input', { type: 'number', min: '1', max: '65535', value: String(login.port_default), 'data-testid': 'setup-admin-port' }) : null;
  const planBtn = h('button', { class: 'btn', type: 'button', 'data-testid': 'setup-plan' }, t('setup.show'));
  let trusted = null;
  let trustedSsh = null;
  let step = null; // the admin step on screen, if any
  let acked = []; // ids of the steps the user has seen
  // an optional second step over SSH (OPNsense: the ISC DHCP script, #242): off unless ticked
  const opt = login.ssh_option;
  const sshOn = opt ? h('input', { type: 'checkbox', 'data-testid': 'setup-ssh' }) : null;
  // like the main port, the SSH port is no secret and is needed to fetch the SSH host key
  const sshPort = opt ? h('input', { type: 'number', min: '1', max: '65535', value: String(opt.port_default), 'data-testid': 'setup-ssh-port' }) : null;
  const sshPortField = opt ? h('div', { class: 'ssh-option-fields', hidden: true, 'data-testid': 'setup-ssh-port-field' }, field(t('setup.sshPort'), sshPort)) : null;
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
  if (opt) {
    sshOn.addEventListener('change', () => { sshPortField.hidden = !sshOn.checked; reset(); });
    sshPort.addEventListener('change', reset);
  }

  const errorNotice = (text, fix) => notice('error', 'setup-error', h('p', {}, text), fix ? h('p', { class: 'fix' }, t('setup.whatToDo'), fix) : null);
  const fail = (text, fix) => place(clear(out), errorNotice(text, fix));
  const missBox = slot(); // "enter the password": one place, replaced by the next result

  // 1. what it does, without any credential
  function showPreview() {
    if (!collectOwn()) return;
    if (step) step.dispose();
    step = null;
    const steps = previewSteps(login.preview, remove.checked, ticked());
    acked = steps.map((s) => s.id);
    previewed = steps;
    const next = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-continue' }, t('setup.continue'));
    next.addEventListener('click', () => run(next, identity));
    place(
      clear(out),
      h('p', {}, remove.checked ? t('setup.preview.remove') : t('setup.preview.do')),
      steps.length ? previewList(steps, 'setup-plan-steps') : null,
      h('p', { class: 'muted small' }, t('setup.preview.note')),
      h('div', { class: 'row' }, next),
    );
  }

  // 2. the device's identity, still without any credential
  async function identity() {
    const device = collectOwn();
    if (!device) return;
    place(clear(out), busy('setup-fetching', t('setup.fetching')));
    try {
      const body = { device, admin: { user: login.user_default || '' }, remove: remove.checked, extras: ticked().filter((x) => x !== 'ssh') };
      if (port && port.value) body.admin.port = Number(port.value);
      // the optional SSH step: its host key is fetched now too, without any password (#290)
      const withSsh = !!(opt && sshOn.checked);
      if (withSsh) body.ssh = sshPort.value ? { port: Number(sshPort.value) } : {};
      const plan = await post('/devices/setup', body);
      const cert = plan.fingerprint_kind === 'certificate';
      const both = withSsh && plan.ssh_fingerprint;
      // a changed SSH host key (#526) or certificate (#535): the warning, nothing else;
      // nothing was sent
      const changed = [plan.host_key, both ? plan.ssh_host_key : null].find(isChanged);
      if (changed) return place(clear(out), hostKeyChanged(changed, { id: device.device_id, name: device.name }, 'setup-host-key-changed', identity));
      const mainKnown = isKnown(plan.host_key);
      const sshKnown = both && isKnown(plan.ssh_host_key);
      knownKeys = [mainKnown ? plan.host_key : null, sshKnown ? plan.ssh_host_key : null].filter(Boolean);
      const accept = () => { trusted = plan.fingerprint; confirmedFingerprint = mainKnown ? null : fingerprintText(plan); trustedSsh = both ? plan.ssh_fingerprint : null; };
      // everything was confirmed before: no prompt, the step list says since when
      if (mainKnown && (!both || sshKnown)) {
        accept();
        return showFinal(null);
      }
      const askSsh = both && !sshKnown;
      const label = mainKnown ? t('setup.trust.ssh') : askSsh ? (cert ? t('setup.trust.certBoth') : t('setup.trust.sshBoth')) : cert ? t('setup.trust.cert') : t('setup.trust.ssh');
      const trust = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-trust' }, label);
      trust.addEventListener('click', () => { accept(); showFinal(null); });
      place(
        clear(out),
        notice('warn', 'setup-untrusted',
          mainKnown
            ? [hostKeyKnown(plan.host_key, 'setup-host-key-known'), h('h3', {}, t('setup.presented.ssh')), h('p', {}, t('setup.compare'))]
            : [
                h('h3', {}, cert ? t('setup.presented.cert') : t('setup.presented.ssh')),
                h('p', {}, t('setup.compare')),
                h('p', { class: 'fingerprint mono', 'data-testid': 'setup-fingerprint' }, fingerprintText(plan)),
                plan.compare ? h('p', { class: 'muted small' }, plan.compare) : null,
                offeredKeys(plan.host_key, 'setup-offered'),
              ],
          askSsh && !mainKnown ? h('h3', {}, t('setup.andSshKey')) : null,
          askSsh ? h('p', { class: 'fingerprint mono', 'data-testid': 'setup-ssh-fingerprint' }, plan.ssh_fingerprint) : null,
          askSsh && plan.ssh_compare ? h('p', { class: 'muted small' }, plan.ssh_compare) : null,
          askSsh ? offeredKeys(plan.ssh_host_key, 'setup-ssh-offered') : null,
          sshKnown ? hostKeyKnown(plan.ssh_host_key, 'setup-host-key-known') : null,
          trust,
        ),
      );
    } catch (err) {
      fail(apiMessage(err), apiFix(err));
    }
  }

  // 3. the temporary password, right before Run
  function showFinal(extraNote) {
    if (step) step.dispose();
    let sshSecret = null;
    const more = [];
    if (opt && sshOn.checked) {
      sshSecret = h('input', { type: 'password', autocomplete: 'new-password', spellcheck: 'false', 'data-testid': 'setup-ssh-secret' });
      more.push({ el: h('div', { class: 'ssh-option-fields', 'data-testid': 'setup-ssh-fields' }, field(t('setup.secretLabel', { label: opt.secret_label, user: opt.user }), sshSecret)), input: sshSecret });
    }
    step = adminStep(login, 'setup', more, adminUser);
    const removing = remove.checked;
    const go = h('button', { class: removing ? 'btn danger' : 'btn primary', type: 'button', 'data-testid': 'setup-apply' }, removing ? t('setup.run.remove') : t('setup.run.setup'));
    go.addEventListener('click', () => run(go, () => doApply(sshSecret)));
    place(
      clear(out),
      extraNote,
      h('p', { class: 'muted small' }, t('setup.confirmed')),
      // what was confirmed stays in view (also after a refused login)
      h('div', { class: 'setup-kept', 'data-testid': 'setup-kept' }, previewed.length ? previewList(previewed, 'setup-kept-steps') : null, confirmedFingerprint ? h('p', { class: 'fingerprint mono small', 'data-testid': 'setup-kept-fingerprint' }, t('setup.confirmedIdentity', { fingerprint: confirmedFingerprint })) : null, ...knownKeys.map((k) => hostKeyKnown(k, 'setup-host-key-known'))),
      step.el,
      clearNotice(missBox),
      h('div', { class: 'row' }, go),
    );
  }

  // 4. Run: one request with the password, then it is gone
  async function doApply(sshSecret) {
    const device = collectOwn();
    if (!device || !step) return;
    const removing = remove.checked;
    clearNotice(missBox);
    const missing = (text) => setNotice(missBox, 'error', 'setup-error', text);
    if (!step.secret()) return missing(t('setup.enter', { label: login.secret_label }));
    if (sshSecret && !sshSecret.value) return missing(t('setup.enterSsh', { label: opt.secret_label, user: opt.user, option: opt.label }));
    if (removing && !(await confirmDialog({ title: t('setup.removeLogin.title'), message: t('setup.removeLogin.message'), confirmLabel: t('common.remove'), danger: true }))) {
      step.wipe(); // cancelled: the password does not stay in the field
      return;
    }
    adminUser = step.user();
    const admin = { user: adminUser, secret: step.secret() };
    if (port && port.value) admin.port = Number(port.value);
    const body = { device, admin, remove: removing, trust: trusted, extras: ticked().filter((x) => x !== 'ssh'), plan_ids: acked };
    if (sshSecret) {
      body.ssh = { secret: sshSecret.value, trust: trustedSsh };
      if (sshPort.value) body.ssh.port = Number(sshPort.value);
    }
    // a clear progress state: spinner, what is going on, and the step that is running
    const head = h('strong', {}, removing ? t('setup.removing') : t('setup.settingUp'));
    const list = h('div', {});
    const showProgress = (view) => place(clear(list), progressList(previewed, view));
    place(clear(out), busy('setup-progress', head, h('p', { class: 'muted small' }, t('setup.progress.wait')), list));
    showProgress({ steps: [], current: null });
    const current = step;
    let res;
    try {
      // the password goes in this one request; the job only keeps the steps and the outcome
      const { id } = await post('/devices/setup/jobs', body);
      current.dispose();
      step = null;
      let view;
      let misses = 0;
      for (;;) {
        await sleep(POLL_MS);
        if (!out.isConnected) return; // left the page: the run goes on, nothing to show
        try {
          view = await get(`/devices/setup/jobs/${id}`);
          misses = 0;
        } catch (err) {
          if (err.status === 404 || ++misses > 5) throw err;
          continue;
        }
        showProgress(view);
        if (view.state === 'finished') break;
      }
      if (view.status !== 200) throw new ApiError(view.status, view.result || {});
      res = view.result;
    } catch (err) {
      if (step) current.wipe();
      return failed(err);
    }
    place(clear(out), notice(res.ok ? 'info' : 'error', 'setup-outcome', res.ok ? (removing ? t('setup.removed') : t('setup.done')) : t('setup.stopped')), stepList(res.steps, 'setup-done-steps'));
    if (res.ok && res.device) {
      toast(t('setup.deviceSetUp', { name: res.device.name }));
      onDone(res.device);
    }
  }

  // a refusal: a changed plan or identity goes back to that step, with no password kept
  function failed(err) {
    if (err.code === 'plan_changed' && err.body && err.body.plan) {
      acked = err.body.plan.steps.filter((s) => s.state === 'todo').map((s) => s.id);
      return showFinal(notice('warn', 'setup-plan-changed', h('p', {}, t('setup.planChanged')), stepList(err.body.plan.steps, 'setup-plan-steps')));
    }
    if (err.code === 'untrusted_ssh') {
      const trustSsh = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'setup-trust-ssh' }, t('setup.trust.ssh'));
      trustSsh.addEventListener('click', () => { trustedSsh = err.body.fingerprint; showFinal(null); });
      return place(
        clear(out),
        notice('warn', 'setup-untrusted-ssh', h('h3', {}, t('setup.untrustedSsh.title')),
          h('p', {}, t('setup.untrustedSsh.text')),
          h('p', { class: 'fingerprint mono', 'data-testid': 'setup-ssh-fingerprint' }, err.body.fingerprint),
          err.body.compare ? h('p', { class: 'muted small' }, err.body.compare) : null,
          trustSsh,
        ),
      );
    }
    if ((err.code === 'host_key_changed' || err.code === 'certificate_changed') && err.body && err.body.host_key) {
      // the device presented another SSH host key (#526) or certificate (#535) than the
      // confirmed one: no password was sent; only the button that names the new one goes on
      trusted = null;
      trustedSsh = null;
      const form = collectOwn() || {};
      return place(clear(out), hostKeyChanged(err.body.host_key, { id: form.device_id, name: form.name || err.body.params.device }, 'setup-host-key-changed', identity));
    }
    if (err.code === 'auth_failed') {
      // wrong admin login: back to the password step, preview and confirmed identity stay
      return showFinal(errorNotice(apiMessage(err), apiFix(err)));
    }
    if (err.code === 'untrusted') { trusted = null; trustedSsh = null; }
    fail(apiMessage(err), apiFix(err));
  }

  planBtn.addEventListener('click', () => run(planBtn, async () => showPreview()));
  const box = h(
    'details',
    { class: 'setup-guide notice', 'data-testid': 'auto-setup' },
    h('summary', {}, t('setup.summary')),
    h('p', {}, t('setup.intro', { transport: login.transport })),
    login.note ? h('p', { class: 'muted small' }, login.note) : null,
    port ? field(t('setup.sshPort'), port) : null,
    opt ? checkField(opt.label, sshOn, opt.note) : null,
    sshPortField,
    checkField(t('setup.removeInstead'), remove, null),
    ...extraFields,
    loginNote,
    h('div', { class: 'row' }, planBtn),
    out,
  );
  // The setup is its own step sequence, not part of the device form around it (#299): Enter in
  // any of its fields never saves the device; in the password step Enter is Run.
  box.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || !(e.target instanceof HTMLInputElement)) return;
    e.preventDefault();
    const go = box.querySelector('[data-testid="setup-apply"]');
    if (step && step.el.contains(e.target) && go && !go.disabled) go.click();
  });
  box.addEventListener('toggle', () => box.open && checkLogin(false));
  return box;
}
