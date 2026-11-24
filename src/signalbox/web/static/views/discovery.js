// "Find devices" on the devices page (#203): start a search, show its progress and what it
// found; "Add" opens the device form prefilled. Everything a device answered (model, name,
// firmware) is untrusted text: it only ever goes into text nodes (h() never parses markup).
import { enc, get, post } from '../api.js';
import { fmtNumber, t } from '../i18n.js';
import { clear, h, place } from '../util.js';
import { field, notice, run, table, tag } from '../ui.js';

// The candidate the device form takes its values from (set by "Add", taken once by the form).
let pending = null;

export function takePrefill() {
  const value = pending;
  pending = null;
  return value;
}

const ROLE_SHORT = { gateway: 'discovery.role.gateway', switch: 'discovery.role.switch', ap: 'discovery.role.ap', other: 'discovery.role.other' };
const roleShort = (role) => (ROLE_SHORT[role] ? t(ROLE_SHORT[role]) : role);

// panel: the card on the devices page. open: show the search form right away.
export function discoveryPanel(ctx, status, open) {
  const box = h('section', { class: 'card discovery', 'data-testid': 'discovery' });
  let timer = null;
  let showIgnored = false;
  let searchedOpen = false; // "What was searched" keeps its state across refreshes
  ctx.onCleanup(() => clearTimeout(timer));

  const ranges = h('input', {
    type: 'text',
    maxlength: '400',
    'data-testid': 'discovery-ranges',
    placeholder: '192.0.2.0/28, 192.0.2.10-20, fritz.box',
    autocomplete: 'off',
  });
  const known = h('input', { type: 'checkbox', checked: true, 'data-testid': 'discovery-known' });
  const start = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'discovery-start' }, t('discovery.search'));
  start.addEventListener('click', () =>
    run(start, async () => {
      const entries = ranges.value.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
      const next = await post('/discovery', { ranges: entries, known_networks: known.checked });
      draw(next);
    }),
  );

  const form = h(
    'div',
    { class: 'discovery-form', 'data-testid': 'discovery-form' },
    h('p', { class: 'muted' }, t('discovery.intro')),
    h('label', { class: 'check' }, known, t('discovery.known')),
    field(t('discovery.ranges'), ranges, t('discovery.rangesHelp')),
    h('div', { class: 'row' }, start, h('a', { href: 'https://github.com/PhilippMundhenk/signalbox/blob/main/docs/DISCOVERY.md', target: '_blank', rel: 'noopener noreferrer', class: 'small' }, t('discovery.whatIsSent'))),
  );

  async function poll() {
    try {
      const next = await get('/discovery');
      draw(next);
    } catch {
      timer = setTimeout(poll, 3000);
    }
  }

  function ignore(c, value) {
    return async () => {
      const next = await post('/discovery/ignore', { key: c.key, ignored: value });
      draw(next);
    };
  }

  function add(c) {
    pending = { adapter: c.adapter, role: c.role, name: c.name, config: c.config, note: c.note, model: c.model };
    ctx.navigate('#/devices/new');
  }

  function actions(c) {
    if (c.added) return h('a', { href: `#/device/${enc(c.added)}`, 'data-testid': 'candidate-added' }, t('discovery.added'));
    const addBtn = h('button', { class: 'btn small primary', type: 'button', 'data-testid': 'candidate-add' }, t('common.add'));
    addBtn.addEventListener('click', () => add(c));
    const ign = h('button', { class: 'btn small', type: 'button', 'data-testid': c.ignored ? 'candidate-unignore' : 'candidate-ignore' }, c.ignored ? t('discovery.showAgain') : t('discovery.ignore'));
    ign.addEventListener('click', () => run(ign, ignore(c, !c.ignored)));
    return h('div', { class: 'row tight' }, addBtn, ign);
  }

  function results(status) {
    const ignored = status.candidates.filter((c) => c.ignored && !c.added).length;
    const rows = status.candidates.filter((c) => showIgnored || !c.ignored || c.added);
    const parts = [];
    if (rows.length) {
      parts.push(
        table(
          [
            [t('discovery.col.type'), (c) => [c.adapter_name, ' ', tag(roleShort(c.role))]],
            [
              t('discovery.col.address'),
              (c) => [
                h('span', { 'data-testid': 'candidate-address' }, c.address),
                c.addresses.length > 1
                  ? h('span', { class: 'muted small', 'data-testid': 'candidate-other-addresses', title: t('discovery.otherAddresses') }, t('discovery.also', { addresses: c.addresses.slice(1).join(', ') }))
                  : null,
              ],
            ],
            [t('discovery.col.model'), (c) => h('span', { 'data-testid': 'candidate-model' }, [c.model || c.name, c.firmware ? ` (${c.firmware})` : ''].join(''))],
            [t('discovery.col.found'), (c) => h('span', { class: 'muted small', title: c.evidence || '' }, c.why)],
            ['', actions],
          ],
          rows,
          { testid: 'candidates', rowTestid: 'candidate', rowAttrs: (c) => ({ 'data-key': c.key, 'data-adapter': c.adapter }) },
        ),
      );
    } else if (status.state !== 'running') {
      parts.push(h('p', { class: 'muted', 'data-testid': 'discovery-none' }, t('discovery.none')));
    }
    if (ignored) {
      const toggle = h('button', { class: 'btn small', type: 'button', 'data-testid': 'discovery-show-ignored' }, showIgnored ? t('discovery.hideIgnored') : t('discovery.showIgnored', { count: fmtNumber(ignored) }));
      toggle.addEventListener('click', () => {
        showIgnored = !showIgnored;
        draw(status);
      });
      parts.push(h('p', {}, toggle));
    }
    return parts;
  }

  function draw(status) {
    clearTimeout(timer);
    clear(box);
    place(box, h('h2', {}, t('discovery.title')));
    if (!status.enabled) {
      place(box, h('p', { class: 'muted', 'data-testid': 'discovery-off' }, t('discovery.off')));
      return;
    }
    const running = status.state === 'running';
    if (running) {
      place(
        box,
        h('p', { 'data-testid': 'discovery-progress', 'aria-live': 'polite' }, t('discovery.progress', { done: fmtNumber(status.done), total: fmtNumber(status.total), found: fmtNumber(status.candidates.length) })),
        h('progress', { max: String(Math.max(status.total, 1)), value: String(status.done) }),
      );
      timer = setTimeout(poll, 1000);
    } else {
      place(box, form);
      if (status.state !== 'idle') place(box, h('p', { class: 'muted small', 'data-testid': 'discovery-done' }, t('discovery.lastSearch', { total: fmtNumber(status.total), found: fmtNumber(status.candidates.length) })));
    }
    if (status.scope.length) {
      const details = h('details', { class: 'small', 'data-testid': 'discovery-searched' }, h('summary', {}, t('discovery.searched')), h('ul', {}, status.scope.map((s) => h('li', {}, s))));
      details.open = searchedOpen;
      details.addEventListener('toggle', () => {
        searchedOpen = details.open;
      });
      place(box, details);
    }
    if (status.notes.length) {
      place(box, notice('warn', 'discovery-notes', h('ul', {}, status.notes.map((n) => h('li', {}, n)))));
    }
    if (status.state !== 'idle') place(box, ...results(status));
  }

  draw(status);
  if (!open && status.state === 'idle') box.hidden = true;
  return box;
}

// The "Find devices" button that shows the panel.
export function findButton(panel) {
  const btn = h('button', { class: 'btn', type: 'button', 'data-testid': 'find-devices' }, t('discovery.title'));
  btn.addEventListener('click', () => {
    panel.hidden = false;
    const start = panel.querySelector('[data-testid="discovery-start"]');
    if (start) start.focus();
  });
  return btn;
}
