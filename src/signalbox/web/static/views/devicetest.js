// Connection test results and certificate trust, shared by the device page and the device form.
import { groupHex, h } from '../util.js';
import { run, statusBadge } from '../ui.js';

const COUNT_TEXT = { ports: 'ports', segments: 'segments', subnets: 'subnets', wlans: 'SSIDs', clients: 'clients' };

// Text with its https:// addresses as links (built as text nodes and elements, no markup).
export function linked(text) {
  return text.split(/(https:\/\/[^\s)]+)/).map((part, i) => (i % 2 ? h('a', { href: part, target: '_blank', rel: 'noopener noreferrer' }, part.replace(/^https:\/\/github\.com\/[^/]+\/[^/]+\/blob\/main\//, '')) : part));
}

// Read errors: what failed, and what to do about it where the adapter knows (#fix).
export function readErrors(errors, testid) {
  if (!errors.length) return null;
  return h(
    'ul',
    { class: 'error read-errors', 'data-testid': testid },
    errors.map((e) => h('li', {}, h('span', {}, `${e.capability}: ${e.message}`), e.fix ? h('p', { class: 'fix', 'data-testid': 'error-fix' }, 'What to do: ', ...linked(e.fix)) : null)),
  );
}

export function testResult(res) {
  const d = res.device || {};
  const found = [d.vendor, d.model, d.firmware && `firmware ${d.firmware}`].filter(Boolean).join(', ');
  return h(
    'div',
    { class: `test-result status-${res.status}`, 'data-testid': 'test-result' },
    h('p', {}, 'Result: ', statusBadge(res.status), found ? ` ${found}` : ''),
    readErrors(res.errors, 'test-errors'),
    res.status === 'ok' || res.status === 'partial'
      ? h('p', { 'data-testid': 'test-counts' }, 'Found ', Object.entries(res.counts).map(([k, v], i) => `${i ? ', ' : ''}${v} ${COUNT_TEXT[k] || k}`), '.')
      : null,
  );
}

// onTrust(fingerprint) is called when the user trusts the certificate.
export function trustPanel(fingerprint, onTrust, note) {
  const btn = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'trust' }, 'Trust this certificate');
  btn.addEventListener('click', () => run(btn, () => onTrust(fingerprint)));
  return h(
    'div',
    { class: 'notice', 'data-testid': 'untrusted' },
    h('h3', {}, 'The device presented a certificate Signalbox does not trust yet'),
    h('p', {}, 'Before you trust it, compare this SHA-256 fingerprint with the one the device shows in its own web interface or console. If they differ, someone may be in between: do not trust it.'),
    h('p', { class: 'fingerprint mono', 'data-testid': 'fingerprint' }, groupHex(fingerprint)),
    note ? h('p', { class: 'muted small' }, note) : null,
    btn,
  );
}
