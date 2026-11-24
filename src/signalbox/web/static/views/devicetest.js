// Connection test results and certificate trust, shared by the device page and the device form.
import { t } from '../i18n.js';
import { errorFix, errorMessage } from '../texts.js';
import { groupHex, h } from '../util.js';
import { notice, run, statusBadge } from '../ui.js';

const COUNT_TEXT = { ports: 'test.count.ports', segments: 'test.count.segments', subnets: 'test.count.subnets', wlans: 'test.count.wlans', clients: 'test.count.clients' };

// Text with its https:// addresses as links (built as text nodes and elements, no markup).
export function linked(text) {
  return text.split(/(https:\/\/[^\s)]+)/).map((part, i) => (i % 2 ? h('a', { href: part, target: '_blank', rel: 'noopener noreferrer' }, part.replace(/^https:\/\/github\.com\/[^/]+\/[^/]+\/blob\/main\//, '')) : part));
}

// Read errors: what failed, and what to do about it where the adapter knows (#fix).
// extra(e): more to show with an error (the Fix it button, #215), or null.
// Optional features that are missing (#278) are a muted note, not an error.
export function readErrors(errors, testid, extra = null) {
  if (!errors.length) return null;
  const item = (e) => h('li', { 'data-optional': e.optional ? 'true' : null }, h('span', {}, e.optional ? t('test.optional', { capability: e.capability, message: errorMessage(e) }) : t('test.error', { capability: e.capability, message: errorMessage(e) })), e.fix ? h('p', { class: 'fix', 'data-testid': 'error-fix' }, t('test.whatToDo'), ...linked(errorFix(e))) : null, extra ? extra(e) : null);
  const real = errors.filter((e) => !e.optional);
  const optional = errors.filter((e) => e.optional);
  return h(
    'div',
    { 'data-testid': testid },
    real.length ? notice('error', `${testid}-problems`, h('ul', { class: 'error read-errors' }, real.map(item))) : null,
    optional.length ? h('ul', { class: 'muted read-errors optional-notes', 'data-testid': `${testid}-optional` }, optional.map(item)) : null,
  );
}

// errors: false on the device page, where the problems belong to the device's read state (#300)
// and are shown there once, not again under the test.
export function testResult(res, { errors = true } = {}) {
  const d = res.device || {};
  const found = [d.vendor, d.model, d.firmware && t('test.firmware', { version: d.firmware })].filter(Boolean).join(', ');
  return h(
    'div',
    { class: `test-result status-${res.status}`, 'data-testid': 'test-result' },
    h('p', {}, t('test.result'), statusBadge(res.status), found ? ` ${found}` : ''),
    errors ? readErrors(res.errors, 'test-errors') : res.errors.length ? h('p', { class: 'muted small', 'data-testid': 'test-see-state' }, t('test.seeState')) : null,
    res.status === 'ok' || res.status === 'partial'
      ? h('p', { 'data-testid': 'test-counts' }, t('test.found'), Object.entries(res.counts).map(([k, v], i) => `${i ? ', ' : ''}${v} ${COUNT_TEXT[k] ? t(COUNT_TEXT[k]) : k}`), '.')
      : null,
  );
}

// onTrust(fingerprint) is called when the user trusts the certificate.
export function trustPanel(fingerprint, onTrust, note) {
  const btn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'trust' }, t('test.trust'));
  btn.addEventListener('click', () => run(btn, () => onTrust(fingerprint)));
  return notice('warn', 'untrusted', h('h3', {}, t('test.untrustedTitle')),
    h('p', {}, t('test.untrustedText')),
    h('p', { class: 'fingerprint mono', 'data-testid': 'fingerprint' }, groupHex(fingerprint)),
    note ? h('p', { class: 'muted small' }, note) : null,
    btn,
  );
}
