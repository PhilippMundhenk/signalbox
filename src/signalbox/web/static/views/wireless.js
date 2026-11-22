// Wireless: SSIDs grouped by name with the settings of every access point, and the radios.
import { loadNetwork, noData } from '../net.js';
import { by, h, place, yesNo } from '../util.js';
import { card, pageHead, purposeTag, table, tag } from '../ui.js';

const SECURITY = {
  open: 'Open (no encryption)',
  owe: 'Enhanced Open (OWE)',
  wep: 'WEP',
  'wpa-psk': 'WPA Personal (version 1)',
  'wpa-wpa2-psk': 'WPA/WPA2 Personal',
  'wpa2-psk': 'WPA2 Personal',
  'wpa3-sae': 'WPA3 Personal',
  'wpa2-wpa3': 'WPA2/WPA3 Personal',
  'wpa2-enterprise': 'WPA2 Enterprise',
  'wpa-enterprise': 'WPA Enterprise (version 1)',
  'wpa3-enterprise': 'WPA3 Enterprise',
  'wpa3-enterprise-192': 'WPA3 Enterprise 192-bit',
  other: 'Other',
};

// Modes and ciphers that are broken or that keep a broken one on (#167).
const WEAK_SECURITY = new Set(['open', 'wep', 'wpa-psk', 'wpa-wpa2-psk', 'wpa-enterprise']);
const WEAK_CIPHER = new Set(['tkip', 'wep']);
const PWE = { 'hunting-and-pecking': 'H&P', 'hash-to-element': 'H2E', both: 'H&P + H2E' };

// Security details (#167): ciphers, SAE, WPS, group rekey, beacon protection; null if none known.
function details(w) {
  const out = [];
  if (w.ciphers && w.ciphers.length) {
    const weak = w.ciphers.some((c) => WEAK_CIPHER.has(c));
    out.push(tag(w.ciphers.map((c) => c.toUpperCase()).join('+'), weak ? 'warn' : ''));
  }
  if (w.group_cipher && !(w.ciphers && w.ciphers.length === 1 && w.ciphers[0] === w.group_cipher)) {
    out.push(tag(`group ${w.group_cipher.toUpperCase()}`, WEAK_CIPHER.has(w.group_cipher) ? 'warn' : ''));
  }
  if (w.sae && w.sae.pwe) out.push(tag(`SAE ${PWE[w.sae.pwe] || w.sae.pwe}`));
  if (w.sae && w.sae.sae_pk) out.push(tag('SAE-PK', 'ok'));
  if (w.wps) {
    const methods = (w.wps.methods || []).join(', ');
    out.push(tag(w.wps.enabled ? `WPS on${methods ? ` (${methods})` : ''}` : 'WPS off', w.wps.enabled ? 'warn' : 'ok'));
  }
  if (w.beacon_protection === true || w.beacon_protection === false) {
    out.push(tag(`beacon protection ${w.beacon_protection ? 'on' : 'off'}`, w.beacon_protection ? 'ok' : ''));
  }
  if (w.key_rotation_seconds !== null && w.key_rotation_seconds !== undefined) {
    out.push(tag(w.key_rotation_seconds ? `rekey ${w.key_rotation_seconds} s` : 'no rekey'));
  }
  if (!out.length) return null;
  return h('span', { 'data-testid': 'wlan-security-details' }, ...out.flatMap((x, i) => (i ? [' ', x] : [x])));
}

function roaming(w) {
  const on = [['802.11r', w.roaming_80211r], ['802.11k', w.roaming_80211k], ['802.11v', w.roaming_80211v]];
  if (on.every(([, v]) => v === null || v === undefined)) return null;
  return on.map(([name, v]) => tag(`${name} ${v ? 'on' : v === false ? 'off' : '?'}`, v ? 'ok' : '')).flatMap((x, i) => (i ? [' ', x] : [x]));
}

export async function renderWireless(main, ctx) {
  const id = ctx.renderId;
  const ix = await loadNetwork();
  if (!ctx.alive(id)) return;
  place(main, pageHead('Wireless'));
  const { wlans, radios } = ix.net;
  if (!wlans.length && !radios.length) {
    place(main, noData('wireless networks'));
    return;
  }
  const bySsid = new Map();
  for (const w of wlans) {
    if (!bySsid.has(w.ssid)) bySsid.set(w.ssid, []);
    bySsid.get(w.ssid).push(w);
  }
  const band = (w) => {
    const r = ix.radios.get(w.radio_id);
    return r ? `${r.band} GHz` : null;
  };
  for (const ssid of [...bySsid.keys()].sort(by((x) => x))) {
    const list = bySsid.get(ssid).sort(by((w) => `${ix.deviceName(w.device_id)} ${band(w)}`));
    const aps = new Set(list.map((w) => w.device_id)).size;
    place(main, 
      card(
        null,
        h('h2', { 'data-testid': 'ssid-name' }, ssid, ' ', h('span', { class: 'muted small' }, `on ${aps} access point${aps === 1 ? '' : 's'}`)),
        table(
          [
            ['Access point', (w) => h('a', { href: `#/device/${encodeURIComponent(w.device_id)}` }, ix.deviceName(w.device_id))],
            ['Band', band],
            ['Security', (w) => h('span', { class: WEAK_SECURITY.has(w.security) ? 'warn-text' : '' }, SECURITY[w.security] || w.security)],
            ['PMF', (w) => w.pmf],
            ['Details', details],
            ['Segment', (w) => (w.segment_id ? ix.segmentName(w.segment_id) : null)],
            ['Purpose', (w) => purposeTag(w.purpose ? w : ix.net.segments.find((s) => s.id === w.segment_id))],
            ['Client isolation', (w) => (w.client_isolation === true || w.client_isolation === false ? h('span', { class: w.client_isolation ? 'tag ok' : 'tag', 'data-testid': 'client-isolation' }, w.client_isolation ? 'on' : 'off') : null)],
            ['Roaming', roaming],
            ['State', (w) => [w.enabled ? 'enabled' : 'disabled', w.hidden ? ', hidden' : '']],
          ],
          list,
          { rowTestid: 'wlan-row' },
        ),
      ),
    );
    main.lastChild.setAttribute('data-testid', 'ssid');
  }
  if (radios.length) {
    place(main, 
      card(
        'Radios',
        table(
          [
            ['Access point', (r) => ix.deviceName(r.device_id)],
            ['Radio', (r) => r.name],
            ['Band', (r) => `${r.band} GHz`],
            ['Channel', (r) => r.channel],
            ['Width', (r) => (r.width_mhz ? `${r.width_mhz} MHz` : null)],
            ['Power', (r) => (r.tx_power_dbm !== null && r.tx_power_dbm !== undefined ? `${r.tx_power_dbm} dBm` : null)],
            ['Country', (r) => r.country],
            ['Security modes', (r) => (r.supported_security ? r.supported_security.map((m) => SECURITY[m] || m).join(', ') : null)],
            ['Enabled', (r) => yesNo(r.enabled)],
          ],
          [...radios].sort(by((r) => `${ix.deviceName(r.device_id)} ${r.band}`)),
          { testid: 'radios', rowTestid: 'radio-row' },
        ),
      ),
    );
  }
}
