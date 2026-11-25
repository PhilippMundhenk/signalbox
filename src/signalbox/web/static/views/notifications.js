// Notification channels (#367): e-mail, ntfy, Matrix, Telegram, Gotify, webhook, the browser and
// Apprise. Tokens and passwords are write-only: the form never shows a stored one. Texts from the
// server (names, errors) are untrusted: text nodes only.
import { del, enc, get, put, post } from '../api.js';
import { clear, h, place } from '../util.js';
import { t } from '../i18n.js';
import { card, checkField, confirmDialog, field, run, select, tag, toast } from '../ui.js';

const KIND = {
  email: 'notify.kind.email',
  ntfy: 'notify.kind.ntfy',
  matrix: 'notify.kind.matrix',
  telegram: 'notify.kind.telegram',
  gotify: 'notify.kind.gotify',
  webhook: 'notify.kind.webhook',
  browser: 'notify.kind.browser',
  apprise: 'notify.kind.apprise',
};
const EVENT = {
  finding: 'notify.event.finding',
  device: 'notify.event.device',
  drift: 'notify.event.drift',
  deploy: 'notify.event.deploy',
};
const SEVERITY = [
  ['info', 'ui.severity.info'],
  ['warning', 'ui.severity.warning'],
  ['error', 'ui.severity.error'],
];
// Which settings a kind uses, besides the common ones.
const FIELDS = {
  email: ['host', 'port', 'security', 'username', 'sender', 'recipients', 'secret'],
  ntfy: ['url', 'topic', 'secret'],
  matrix: ['url', 'room_id', 'secret'],
  telegram: ['chat_id', 'secret'],
  gotify: ['url', 'secret'],
  webhook: ['url', 'secret'],
  browser: [],
  apprise: ['secret'],
};
const LABEL = {
  url: 'notify.url',
  topic: 'notify.topic',
  room_id: 'notify.room',
  chat_id: 'notify.chat',
  host: 'notify.host',
  port: 'notify.port',
  security: 'notify.security',
  username: 'notify.username',
  sender: 'notify.sender',
  recipients: 'notify.recipients',
  secret: 'notify.secret',
};

function channelForm(ctx, kinds, existing) {
  const spec = existing || { kind: kinds[0], enabled: false, min_severity: 'warning', events: Object.keys(EVENT), quiet_start: '', quiet_end: '', secret_set: false };
  const readonly = existing && existing.source === 'config';
  const inputs = {};
  const name = h('input', { type: 'text', maxlength: '40', pattern: '[a-z0-9][a-z0-9_-]*', value: existing ? existing.name : '', disabled: Boolean(existing), 'data-testid': 'notify-name' });
  const kind = select(kinds.map((k) => [k, t(KIND[k])]), spec.kind, { 'data-testid': 'notify-kind', disabled: Boolean(existing) });
  const enabled = h('input', { type: 'checkbox', checked: spec.enabled, 'data-testid': 'notify-enabled' });
  const severity = select(SEVERITY.map(([v, k]) => [v, t(k)]), spec.min_severity, { 'data-testid': 'notify-severity' });
  const events = Object.entries(EVENT).map(([v, k]) => {
    const box = h('input', { type: 'checkbox', checked: spec.events.includes(v), value: v, 'data-testid': `notify-event-${v}` });
    return [v, box, checkField(t(k), box)];
  });
  const quietStart = h('input', { type: 'text', size: '5', placeholder: '22:00', value: spec.quiet_start, 'data-testid': 'notify-quiet-start' });
  const quietEnd = h('input', { type: 'text', size: '5', placeholder: '07:00', value: spec.quiet_end, 'data-testid': 'notify-quiet-end' });
  const specific = h('div', {});
  const makeInput = (key) => {
    if (key === 'security') return select([['starttls', 'STARTTLS'], ['ssl', 'SSL/TLS'], ['none', t('notify.securityNone')]], spec.security || 'starttls', { 'data-testid': 'notify-security' });
    if (key === 'secret') return h('input', { type: 'password', autocomplete: 'new-password', placeholder: spec.secret_set ? t('notify.secretSet') : '', 'data-testid': 'notify-secret' });
    if (key === 'port') return h('input', { type: 'number', min: '0', max: '65535', value: spec.port || '', 'data-testid': 'notify-port' });
    if (key === 'recipients') return h('input', { type: 'text', value: (spec.recipients || []).join(', '), 'data-testid': 'notify-recipients' });
    return h('input', { type: 'text', value: spec[key] || '', 'data-testid': `notify-${key}` });
  };
  const drawSpecific = () => {
    clear(specific);
    for (const key of Object.keys(inputs)) delete inputs[key];
    for (const key of FIELDS[kind.value]) {
      inputs[key] = makeInput(key);
      if (readonly) inputs[key].disabled = true;
      place(specific, field(t(LABEL[key]), inputs[key]));
    }
  };
  kind.addEventListener('change', drawSpecific);
  drawSpecific();
  if (readonly) for (const c of [enabled, severity, quietStart, quietEnd, ...events.map((e) => e[1])]) c.disabled = true;

  const body = () => {
    const out = {
      kind: kind.value,
      enabled: enabled.checked,
      min_severity: severity.value,
      events: events.filter((e) => e[1].checked).map((e) => e[0]),
      quiet_start: quietStart.value.trim(),
      quiet_end: quietEnd.value.trim(),
    };
    for (const [key, input] of Object.entries(inputs)) {
      if (key === 'secret') {
        if (input.value) out.secret = input.value;
      } else if (key === 'port') out.port = Number(input.value || 0);
      else if (key === 'recipients') out.recipients = input.value.split(',').map((x) => x.trim()).filter(Boolean);
      else out[key] = input.value.trim();
    }
    return out;
  };

  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'notify-save', disabled: readonly }, t('common.save'));
  const test = h('button', { class: 'btn', type: 'button', 'data-testid': 'notify-test', disabled: !existing }, t('notify.test'));
  test.addEventListener('click', () =>
    run(test, async () => {
      const res = await post(`/notifications/channels/${enc(existing.name)}/test`, {});
      if (res.ok) toast(t('notify.testOk'));
      else toast(t('notify.testFailed', { error: res.error || '' }), 'error');
      ctx.refresh();
    }),
  );
  const buttons = [save, test];
  if (existing && !readonly) {
    const remove = h('button', { class: 'btn', type: 'button', 'data-testid': 'notify-delete' }, t('common.delete'));
    remove.addEventListener('click', () =>
      run(remove, async () => {
        if (!(await confirmDialog({ title: t('notify.deleteTitle', { name: existing.name }), message: t('notify.deleteMessage'), confirmLabel: t('common.delete'), danger: true }))) return;
        await del(`/notifications/channels/${enc(existing.name)}`);
        ctx.refresh();
      }),
    );
    buttons.push(remove);
  }
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      run(save, async () => {
        const key = existing ? existing.name : name.value.trim();
        await put(`/notifications/channels/${enc(key)}`, body());
        toast(t('notify.saved'));
        ctx.refresh();
      });
    },
  });
  place(
    form,
    existing ? null : field(t('notify.name'), name),
    field(t('notify.kind'), kind),
    checkField(t('notify.enabled'), enabled),
    specific,
    field(t('notify.minSeverity'), severity),
    h('fieldset', {}, h('legend', {}, t('notify.events')), ...events.map((e) => e[2])),
    field(t('notify.quietStart'), quietStart, t('notify.quietHint')),
    field(t('notify.quietEnd'), quietEnd),
    readonly ? h('p', { class: 'muted' }, t('notify.fromConfig')) : null,
    h('div', { class: 'row' }, ...buttons),
  );
  return form;
}

function summary(c) {
  return [
    h('strong', {}, c.name),
    ' ',
    tag(t(KIND[c.kind] || KIND.webhook)),
    ' ',
    c.enabled ? tag(t('notify.enabled'), 'ok') : tag(t('settings.off')),
    c.last_error ? h('span', { class: 'muted small' }, ` ${t('notify.lastError', { error: c.last_error })}`) : null,
  ];
}

function browserBox() {
  const box = h('div', { 'data-testid': 'notify-browser' });
  const draw = () => {
    clear(box);
    if (!('Notification' in window)) {
      place(box, h('p', { class: 'muted' }, t('notify.browserUnsupported')));
      return;
    }
    if (Notification.permission === 'granted') place(box, h('p', { class: 'muted' }, t('notify.browserOn')));
    else if (Notification.permission === 'denied') place(box, h('p', { class: 'muted' }, t('notify.browserDenied')));
    else {
      const ask = h('button', { class: 'btn', type: 'button', 'data-testid': 'notify-permission' }, t('notify.browserEnable'));
      ask.addEventListener('click', async () => {
        await Notification.requestPermission();
        draw();
      });
      place(box, h('p', { class: 'muted' }, t('notify.browserHint')), ask);
    }
  };
  draw();
  return box;
}

// Web Push (#372): notifications with no tab open. Opt-in per browser, on a button press: only
// then the service worker is registered and the browser's push service is asked for a subscription.
const PUSH_ID = 'signalbox.push.id';
function keyBytes(text) {
  const raw = atob((text + '='.repeat((4 - (text.length % 4)) % 4)).replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function pushBox(ctx) {
  const state = await get('/notifications/webpush');
  const box = h('div', { 'data-testid': 'notify-push' });
  place(box, h('h3', {}, t('notify.push.title')), h('p', { class: 'muted' }, t('notify.push.hint')));
  if (!state.available) {
    place(box, h('p', { class: 'muted', 'data-testid': 'notify-push-unavailable' }, t('notify.push.unavailable')));
    return box;
  }
  if (!('serviceWorker' in navigator) || !('PushManager' in window) || !window.isSecureContext) {
    place(box, h('p', { class: 'muted', 'data-testid': 'notify-push-unsupported' }, t('notify.push.unsupported')));
    return box;
  }
  const mine = localStorage.getItem(PUSH_ID);
  const own = state.subscriptions.some((s) => s.id === mine);
  const button = h('button', { class: 'btn', type: 'button', 'data-testid': own ? 'notify-push-off' : 'notify-push-on' }, own ? t('notify.push.unsubscribe') : t('notify.push.subscribe'));
  button.addEventListener('click', () =>
    run(button, async () => {
      if (own) {
        const reg = await navigator.serviceWorker.getRegistration('/');
        const sub = reg ? await reg.pushManager.getSubscription() : null;
        if (sub) await sub.unsubscribe();
        await del(`/notifications/webpush/subscriptions/${enc(mine)}`);
        localStorage.removeItem(PUSH_ID);
      } else {
        const permission = await Notification.requestPermission();
        if (permission !== 'granted') throw new Error(t('notify.browserDenied'));
        const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
        await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(state.public_key) });
        const saved = await post('/notifications/webpush/subscriptions', sub.toJSON());
        localStorage.setItem(PUSH_ID, saved.id);
        toast(t('notify.push.subscribed'));
      }
      ctx.refresh();
    }),
  );
  place(box, button);
  const list = h('ul', { 'data-testid': 'notify-push-list' });
  for (const s of state.subscriptions) {
    const remove = h('button', { class: 'btn', type: 'button', 'data-testid': 'notify-push-delete' }, t('common.delete'));
    remove.addEventListener('click', () =>
      run(remove, async () => {
        await del(`/notifications/webpush/subscriptions/${enc(s.id)}`);
        if (s.id === mine) localStorage.removeItem(PUSH_ID);
        ctx.refresh();
      }),
    );
    place(list, h('li', { 'data-testid': 'notify-push-item' }, t('notify.push.item', { host: s.host, date: s.created.slice(0, 10) }), s.id === mine ? ` (${t('notify.push.thisBrowser')}) ` : ' ', remove));
  }
  place(box, state.subscriptions.length ? list : h('p', { class: 'muted' }, t('notify.push.none')));
  return box;
}

export async function notificationsCard(ctx) {
  const state = await get('/notifications');
  const list = h('div', { 'data-testid': 'notify-channels' });
  if (!state.channels.length) place(list, h('p', { class: 'muted', 'data-testid': 'notify-none' }, t('notify.none')));
  for (const c of state.channels) {
    place(list, h('details', { 'data-testid': 'notify-channel', 'data-name': c.name }, h('summary', {}, ...summary(c)), channelForm(ctx, state.kinds, c)));
  }
  return card(
    t('notify.title'),
    h('p', { class: 'muted' }, t('notify.hint')),
    list,
    h('details', { 'data-testid': 'notify-new' }, h('summary', {}, t('notify.add')), channelForm(ctx, state.kinds, null)),
    h('hr', {}),
    browserBox(),
    await pushBox(ctx),
  );
}

// While the page is open: show the messages of the browser channels as notifications of this
// browser (Notification API; the permission is asked on a button press, not here).
let polling = false;
export function pollBrowserNotifications() {
  if (polling || !('Notification' in window)) return;
  polling = true;
  let after = null;
  const tick = async () => {
    if (Notification.permission === 'granted') {
      try {
        const messages = await get(`/notifications/browser?after=${after || 0}`);
        for (const m of messages) {
          if (after !== null) new Notification(m.subject, { body: m.lines.join('\n'), tag: `signalbox-${m.id}` });
          after = Math.max(after || 0, m.id);
        }
        if (after === null) after = 0;
      } catch (err) {
        /* offline: the next tick tries again */
      }
    }
    setTimeout(tick, 30000);
  };
  tick();
}
