// The SSH host key (#526) and HTTPS certificate (#535) confirmed per device (ADR 0031): shown
// instead of the prompt when a device presents what was confirmed before, a distinct warning
// when it presents another one, and the device page's card with the confirmed key, the other
// key types confirmed with it, the old ones and "Forget". Re-trusting a changed key or
// certificate is only ever the button that names the new one; nothing is sent to the device.
import { del, enc, post } from '../api.js';
import { fmtDate, t } from '../i18n.js';
import { groupHex, h } from '../util.js';
import { confirmDialog, kv, notice, run, toast } from '../ui.js';

const day = (iso) => (iso ? fmtDate(new Date(iso), { dateStyle: 'medium' }) : '');

export const isKnown = (hk) => !!hk && hk.state === 'known';
export const isChanged = (hk) => !!hk && hk.state === 'changed';
// a certificate (#535) or an SSH host key: the texts and the re-trust differ
const isCert = (hk) => !!hk && hk.kind === 'certificate';
const shown = (hk, fp) => (isCert(hk) ? groupHex(fp) : fp);

// "SSH host key as confirmed on <date>" / "Certificate as trusted on <date>": the step that
// replaces the prompt
export function hostKeyKnown(hk, testid) {
  const fingerprint = shown(hk, hk.fingerprint);
  const text = isCert(hk)
    ? hk.confirmed_at ? t('hostkey.cert.known', { date: day(hk.confirmed_at), fingerprint }) : t('hostkey.cert.knownUndated', { fingerprint })
    : t('hostkey.known', { date: day(hk.confirmed_at), fingerprint });
  return h('p', { class: 'fingerprint mono small', 'data-testid': testid, 'data-kind': hk.kind || 'ssh' }, text);
}

// The other SSH host key types a device offers (#535), listed with a new key to confirm: they
// are pinned with it, so a device that later uses another of them is not taken as changed.
export function offeredKeys(hk, testid) {
  if (!hk || isCert(hk) || !hk.offered || !hk.offered.length) return null;
  return h('div', { 'data-testid': testid },
    h('p', { class: 'muted small' }, t('hostkey.offered')),
    h('ul', { class: 'muted small' }, hk.offered.map((k) => h('li', { 'data-testid': `${testid}-key` }, `${k.algorithm}: `, h('code', {}, k.fingerprint)))),
  );
}

// The warning for a changed key or certificate: old and new, since when, and the one way on,
// a button that names the new one. onTrusted() runs after the new one was stored.
export function hostKeyChanged(hk, device, testid, onTrusted) {
  const cert = isCert(hk);
  const retrust = h('button', { class: 'btn danger', type: 'button', 'data-testid': `${testid}-retrust` }, cert ? t('hostkey.cert.retrust', { fingerprint: shown(hk, hk.fingerprint) }) : t('hostkey.retrust', { fingerprint: hk.fingerprint }));
  retrust.addEventListener('click', () =>
    run(retrust, async () => {
      // a certificate: the device's certificate pin, which also its readings use (ADR 0019)
      await post(cert ? `/devices/${enc(device.id)}/trust` : `/devices/${enc(device.id)}/ssh-host-key/trust`, { fingerprint: hk.fingerprint });
      toast(cert ? t('hostkey.cert.retrusted', { name: device.name }) : t('hostkey.retrusted', { name: device.name }));
      if (onTrusted) await onTrusted();
    }),
  );
  const date = day(hk.confirmed_at);
  const text = !cert
    ? t('hostkey.changed.text', { name: device.name, date })
    : hk.confirmed_at ? t('hostkey.cert.changed.text', { name: device.name, date }) : t('hostkey.cert.changed.textUndated', { name: device.name });
  return notice(
    'error',
    testid,
    h('h3', {}, cert ? t('hostkey.cert.changed.title', { name: device.name }) : t('hostkey.changed.title', { name: device.name })),
    h('p', {}, text),
    kv([
      [cert ? t('hostkey.cert.changed.old') : t('hostkey.changed.old'), h('code', { 'data-testid': `${testid}-old` }, shown(hk, hk.pinned))],
      [cert ? t('hostkey.cert.changed.new') : t('hostkey.changed.new'), h('code', { 'data-testid': `${testid}-new` }, shown(hk, hk.fingerprint))],
    ]),
    h('p', {}, cert ? t('hostkey.cert.changed.compare') : t('hostkey.changed.compare')),
    device.id ? h('div', { class: 'row' }, retrust) : null,
  );
}

// The device page's certificate history (#535): pins a re-trust replaced.
export function certificateHistory(device) {
  const old = device.certificate_history || [];
  if (!old.length) return null;
  return h('details', { 'data-testid': 'device-certificate-history' }, h('summary', { class: 'small' }, t('hostkey.cert.history')),
    h('ul', { class: 'muted small' }, old.map((p) => h('li', {}, h('code', {}, groupHex(p.fingerprint)), ' ', p.pinned_since ? t('hostkey.card.historyItem', { from: day(p.pinned_since), to: day(p.retired_at) }) : t('hostkey.cert.historyItem', { to: day(p.retired_at) })))));
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
    // the other key types confirmed with it (#535)
    for (const k of keys.also || []) rows.push([t('hostkey.card.also', { algorithm: k.algorithm || '' }), h('code', { 'data-testid': 'device-host-key-also' }, k.fingerprint)]);
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
