// The SSH host key confirmed per device (#526, ADR 0031): shown instead of the prompt when a
// device presents the key confirmed before, a distinct warning when it presents another one,
// and the device page's card with the confirmed key, the old ones and "Forget". Re-trusting a
// changed key is only ever the button that names the new key; nothing is sent to the device.
import { del, enc, post } from '../api.js';
import { fmtDate, t } from '../i18n.js';
import { h } from '../util.js';
import { confirmDialog, kv, notice, run, toast } from '../ui.js';

const day = (iso) => (iso ? fmtDate(new Date(iso), { dateStyle: 'medium' }) : '');

export const isKnown = (hk) => !!hk && hk.state === 'known';
export const isChanged = (hk) => !!hk && hk.state === 'changed';

// "SSH host key as confirmed on <date>": the step that replaces the prompt
export function hostKeyKnown(hk, testid) {
  return h('p', { class: 'fingerprint mono small', 'data-testid': testid }, t('hostkey.known', { date: day(hk.confirmed_at), fingerprint: hk.fingerprint }));
}

// The warning for a changed key: old and new key, since when, and the one way on, a button
// that names the new key. onTrusted() runs after the new key was stored.
export function hostKeyChanged(hk, device, testid, onTrusted) {
  const retrust = h('button', { class: 'btn danger', type: 'button', 'data-testid': `${testid}-retrust` }, t('hostkey.retrust', { fingerprint: hk.fingerprint }));
  retrust.addEventListener('click', () =>
    run(retrust, async () => {
      await post(`/devices/${enc(device.id)}/ssh-host-key/trust`, { fingerprint: hk.fingerprint });
      toast(t('hostkey.retrusted', { name: device.name }));
      if (onTrusted) await onTrusted();
    }),
  );
  return notice(
    'error',
    testid,
    h('h3', {}, t('hostkey.changed.title', { name: device.name })),
    h('p', {}, t('hostkey.changed.text', { name: device.name, date: day(hk.confirmed_at) })),
    kv([
      [t('hostkey.changed.old'), h('code', { 'data-testid': `${testid}-old` }, hk.pinned)],
      [t('hostkey.changed.new'), h('code', { 'data-testid': `${testid}-new` }, hk.fingerprint)],
    ]),
    h('p', {}, t('hostkey.changed.compare')),
    device.id ? h('div', { class: 'row' }, retrust) : null,
  );
}

// The device page: the confirmed key, a changed one, earlier keys, and "Forget".
export function hostKeyCard(device, onChange) {
  const keys = device.ssh_host_key;
  if (!keys) return null;
  const parts = [];
  if (keys.changed && keys.pin) {
    parts.push(hostKeyChanged({ state: 'changed', fingerprint: keys.changed.fingerprint, pinned: keys.pin.fingerprint, confirmed_at: keys.pin.confirmed_at }, device, 'device-host-key-changed', onChange));
  }
  const rows = [];
  if (keys.pin) {
    rows.push([t('hostkey.card.key'), h('code', { 'data-testid': 'device-host-key' }, keys.pin.fingerprint)]);
    if (keys.pin.algorithm) rows.push([t('hostkey.card.algorithm'), keys.pin.algorithm]);
    rows.push([t('hostkey.card.confirmed'), day(keys.pin.confirmed_at)]);
  } else {
    rows.push([t('hostkey.card.key'), t('hostkey.card.none')]);
  }
  parts.push(kv(rows));
  if (keys.history.length) {
    parts.push(
      h('details', { 'data-testid': 'device-host-key-history' }, h('summary', { class: 'small' }, t('hostkey.card.history')),
        h('ul', { class: 'muted small' }, keys.history.map((p) => h('li', {}, h('code', {}, p.fingerprint), ' ', t('hostkey.card.historyItem', { from: day(p.confirmed_at), to: day(p.retired_at) }))))),
    );
  }
  if (keys.pin) {
    const forget = h('button', { class: 'btn', type: 'button', 'data-testid': 'device-host-key-forget' }, t('hostkey.forget'));
    forget.addEventListener('click', () =>
      run(forget, async () => {
        const ok = await confirmDialog({ title: t('hostkey.forget.title', { name: device.name }), message: t('hostkey.forget.message'), confirmLabel: t('hostkey.forget') });
        if (!ok) return;
        await del(`/devices/${enc(device.id)}/ssh-host-key`);
        toast(t('hostkey.forgotten', { name: device.name }));
        if (onChange) await onChange();
      }),
    );
    parts.push(h('p', { class: 'muted small' }, t('hostkey.forget.note')), h('div', { class: 'row' }, forget));
  }
  return h('section', { class: 'card', 'data-testid': 'device-host-key-card' }, h('h2', {}, t('hostkey.card.title')), ...parts);
}
