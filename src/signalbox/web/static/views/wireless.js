// Wireless: SSIDs grouped by name with the settings of every access point, and the radios.
import { loadNetwork, noData } from '../net.js';
import { by, h, place, yesNo } from '../util.js';
import { card, pageHead, purposeTag, table, tabs, tag } from '../ui.js';
import { renderWifiMap } from './wifimap.js';
import { t } from '../i18n.js';

const SECURITY = {
  open: 'wireless.sec.open',
  owe: 'wireless.sec.owe',
  wep: 'wireless.sec.wep',
  'wpa-psk': 'wireless.sec.wpaPsk',
  'wpa-wpa2-psk': 'wireless.sec.wpaWpa2Psk',
  'wpa2-psk': 'wireless.sec.wpa2Psk',
  'wpa3-sae': 'wireless.sec.wpa3Sae',
  'wpa2-wpa3': 'wireless.sec.wpa2Wpa3',
  'wpa2-enterprise': 'wireless.sec.wpa2Enterprise',
  'wpa-enterprise': 'wireless.sec.wpaEnterprise',
  'wpa3-enterprise': 'wireless.sec.wpa3Enterprise',
  'wpa3-enterprise-192': 'wireless.sec.wpa3Enterprise192',
  other: 'wireless.sec.other',
};
const securityLabel = (m) => (SECURITY[m] ? t(SECURITY[m]) : m);

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
    out.push(tag(t('wireless.details.group', { cipher: w.group_cipher.toUpperCase() }), WEAK_CIPHER.has(w.group_cipher) ? 'warn' : ''));
  }
  if (w.sae && w.sae.pwe) out.push(tag(`SAE ${PWE[w.sae.pwe] || w.sae.pwe}`));
  if (w.sae && w.sae.sae_pk) out.push(tag('SAE-PK', 'ok'));
  if (w.wps) {
    const methods = (w.wps.methods || []).join(', ');
    out.push(tag(w.wps.enabled ? (methods ? t('wireless.details.wpsOnMethods', { methods }) : t('wireless.details.wpsOn')) : t('wireless.details.wpsOff'), w.wps.enabled ? 'warn' : 'ok'));
  }
  if (w.beacon_protection === true || w.beacon_protection === false) {
    out.push(tag(w.beacon_protection ? t('wireless.details.beaconOn') : t('wireless.details.beaconOff'), w.beacon_protection ? 'ok' : ''));
  }
  if (w.key_rotation_seconds !== null && w.key_rotation_seconds !== undefined) {
    out.push(tag(w.key_rotation_seconds ? t('wireless.details.rekey', { seconds: w.key_rotation_seconds }) : t('wireless.details.noRekey')));
  }
  if (!out.length) return null;
  return h('span', { 'data-testid': 'wlan-security-details' }, ...out.flatMap((x, i) => (i ? [' ', x] : [x])));
}

function roaming(w) {
  const on = [['802.11r', w.roaming_80211r], ['802.11k', w.roaming_80211k], ['802.11v', w.roaming_80211v]];
  if (on.every(([, v]) => v === null || v === undefined)) return null;
  return on.map(([name, v]) => tag(v ? t('wireless.roaming.on', { name }) : v === false ? t('wireless.roaming.off', { name }) : t('wireless.roaming.unknown', { name }), v ? 'ok' : '')).flatMap((x, i) => (i ? [' ', x] : [x]));
}

export async function renderWireless(main, ctx, route = {}) {
  const id = ctx.renderId;
  const ix = await loadNetwork();
  if (!ctx.alive(id)) return;
  place(main, pageHead(t('wireless.title')), tabs([['networks', t('wireless.tab.networks'), '#/wireless'], ['map', t('wireless.tab.map'), '#/wireless/map']], route.tab || 'networks', 'wireless-tab'));
  if (route.tab === 'map') {
    await renderWifiMap(main, ctx, ix);
    return;
  }
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
    return r ? t('wireless.ghz', { band: r.band }) : null;
  };
  for (const ssid of [...bySsid.keys()].sort(by((x) => x))) {
    const list = bySsid.get(ssid).sort(by((w) => `${ix.deviceName(w.device_id)} ${band(w)}`));
    const aps = new Set(list.map((w) => w.device_id)).size;
    place(main, 
      card(
        null,
        h('h2', { 'data-testid': 'ssid-name' }, ssid, ' ', h('span', { class: 'muted small' }, t('wireless.onAps', { count: aps }))),
        table(
          [
            [t('wireless.col.accessPoint'), (w) => h('a', { href: `#/device/${encodeURIComponent(w.device_id)}` }, ix.deviceName(w.device_id))],
            [t('wireless.col.band'), band],
            [t('wireless.col.security'), (w) => h('span', { class: WEAK_SECURITY.has(w.security) ? 'warn-text' : '' }, securityLabel(w.security))],
            [t('wireless.col.pmf'), (w) => w.pmf],
            [t('wireless.col.details'), details],
            [t('wireless.col.segment'), (w) => (w.segment_id ? ix.segmentName(w.segment_id) : null)],
            [t('wireless.col.purpose'), (w) => purposeTag(w.purpose ? w : ix.net.segments.find((s) => s.id === w.segment_id))],
            [t('wireless.col.clientIsolation'), (w) => (w.client_isolation === true || w.client_isolation === false ? h('span', { class: w.client_isolation ? 'tag ok' : 'tag', 'data-testid': 'client-isolation' }, w.client_isolation ? t('wireless.on') : t('wireless.off')) : null)],
            [t('wireless.col.roaming'), roaming],
            [t('wireless.col.state'), (w) => [w.enabled ? t('wireless.enabled') : t('wireless.disabled'), w.hidden ? t('wireless.hidden') : '']],
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
        t('wireless.radios'),
        table(
          [
            [t('wireless.col.accessPoint'), (r) => ix.deviceName(r.device_id)],
            [t('wireless.col.radio'), (r) => r.name],
            [t('wireless.col.band'), (r) => t('wireless.ghz', { band: r.band })],
            [t('wireless.col.channel'), (r) => r.channel],
            [t('wireless.col.width'), (r) => (r.width_mhz ? t('wireless.mhz', { value: r.width_mhz }) : null)],
            [t('wireless.col.power'), (r) => (r.tx_power_dbm !== null && r.tx_power_dbm !== undefined ? t('wireless.dbm', { value: r.tx_power_dbm }) : null)],
            [t('wireless.col.country'), (r) => r.country],
            [t('wireless.col.securityModes'), (r) => (r.supported_security ? r.supported_security.map((m) => securityLabel(m)).join(', ') : null)],
            [t('wireless.col.enabled'), (r) => yesNo(r.enabled)],
          ],
          [...radios].sort(by((r) => `${ix.deviceName(r.device_id)} ${r.band}`)),
          { testid: 'radios', rowTestid: 'radio-row' },
        ),
      ),
    );
  }
}
