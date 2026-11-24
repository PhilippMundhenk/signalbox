// The admin login of an automatic setup or a Fix it, asked for last and made to look temporary
// (#279): shown only after the plan and the device's identity were confirmed, right before the
// button that runs it. The password is never pre-filled, never sent before that button is
// pressed, and the field is emptied right after the request, when the page is left and after a
// while without use. The value is only ever read by value(); nothing else holds on to it.
import { t } from '../i18n.js';
import { stepTitle } from '../texts.js';
import { h } from '../util.js';
import { field } from '../ui.js';

const IDLE_MS = 120000;

// login: the integration's admin_login (labels); prefix: test id prefix ("setup" / "fix");
// more: further fields (the
// optional SSH step's password) as { el, input } entries that are wiped like the password.
export function adminStep(login, prefix, more = [], userValue = null) {
  const user = h('input', { type: 'text', value: userValue || login.user_default || '', autocomplete: 'off', spellcheck: 'false', 'data-testid': `${prefix}-admin-user` });
  const secret = h('input', { type: 'password', autocomplete: 'new-password', spellcheck: 'false', 'data-testid': `${prefix}-admin-secret` });
  const note = h('p', { class: 'temporary-note', 'data-testid': `${prefix}-temporary-note` }, t('adminstep.note'));
  const secrets = [secret, ...more.map((m) => m.input).filter(Boolean)];
  let timer = null;

  const wipe = () => {
    for (const s of secrets) s.value = '';
    clearTimeout(timer);
  };
  const touch = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      wipe();
      note.textContent = t('adminstep.cleared');
    }, IDLE_MS);
  };
  for (const s of secrets) s.addEventListener('input', touch);
  const leave = () => wipe();
  window.addEventListener('hashchange', leave);
  window.addEventListener('pagehide', leave);

  const el = h(
    'div',
    { class: 'admin-step notice', 'data-testid': `${prefix}-admin-step` },
    h('h3', {}, t('adminstep.title')),
    note,
    field(login.user_label || t('adminstep.userLabel'), user),
    field(login.secret_label || t('adminstep.secretLabel'), secret),
    ...more.map((m) => m.el),
  );
  return {
    el,
    user: () => user.value.trim(),
    secret: () => secret.value,
    // empties every secret field (after the request, on cancel, on navigation)
    wipe,
    dispose() {
      wipe();
      window.removeEventListener('hashchange', leave);
      window.removeEventListener('pagehide', leave);
    },
  };
}

// The steps the integration normally takes, in words (admin_login.preview / remedy.preview),
// for what is ticked; ``remove``: the removal's steps; ``extras``: ids of ticked extras.
export function previewSteps(preview, remove, extras) {
  return (preview || []).filter((s) => !!s.remove === !!remove && (!s.extra || extras.includes(s.extra)));
}

export function previewList(steps, testid) {
  return h(
    'ol',
    { class: 'setup-steps preview', 'data-testid': testid },
    steps.map((s) => h('li', { class: 'setup-step', 'data-testid': 'setup-step', 'data-step': s.id, 'data-state': 'preview' }, h('span', { class: 'badge step-todo' }, t('adminstep.usually')), ' ', h('strong', {}, stepTitle(s)))),
  );
}
