// Settings: sites, password, rules (read-only).
import { del, enc, get, post, put } from '../api.js';
import { clear, h, place } from '../util.js';
import { availableLanguages, savedLanguage, setLanguage, t } from '../i18n.js';
import { card, clearNotice, confirmDialog, field, pageHead, run, select, setNotice, severityBadge, slot, table, tag, toast } from '../ui.js';
import { notificationsCard } from './notifications.js';
import { ruleExplanation, ruleTitle } from '../texts.js';

function sitesCard(ctx, sites, devices) {
  const list = h('div', {});
  const draw = () => {
    clear(list);
    if (!sites.length) place(list, h('p', { class: 'muted', 'data-testid': 'no-sites' }, t('settings.noSites')));
    place(list, 
      table(
        [
          [t('settings.colName'), (x) => x.name],
          [t('settings.colDevices'), (x) => String(devices.filter((d) => d.site_id === x.id).length)],
          [
            '',
            (x) => {
              const rename = h('button', { class: 'btn small', type: 'button', 'data-testid': 'site-rename' }, t('common.rename'));
              rename.addEventListener('click', () => renameSite(x));
              const remove = h('button', { class: 'btn small', type: 'button', 'data-testid': 'site-delete', disabled: devices.some((d) => d.site_id === x.id), title: t('settings.deleteHint') }, t('common.delete'));
              remove.addEventListener('click', () =>
                run(remove, async () => {
                  if (!(await confirmDialog({ title: t('settings.deleteTitle', { name: x.name }), message: t('settings.deleteMessage'), confirmLabel: t('common.delete'), danger: true }))) return;
                  await del(`/sites/${enc(x.id)}`);
                  toast(t('settings.deleted', { name: x.name }));
                  ctx.refresh();
                }),
              );
              return h('span', { class: 'row tight' }, rename, remove);
            },
            'actions',
          ],
        ],
        sites,
        { testid: 'sites', rowTestid: 'site-row' },
      ),
    );
  };
  const renameSite = (x) => {
    const name = h('input', { type: 'text', value: x.name, maxlength: '100', 'data-testid': 'site-rename-name' });
    const ok = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'site-rename-save' }, t('common.save'));
    ok.addEventListener('click', () =>
      run(ok, async () => {
        await put(`/sites/${enc(x.id)}`, { name: name.value.trim() });
        toast(t('settings.renamed'));
        ctx.refresh();
      }),
    );
    place(clear(list), field(t('settings.newName', { name: x.name }), name), h('div', { class: 'row' }, ok, h('button', { class: 'btn', type: 'button', onclick: draw }, t('common.cancel'))));
    name.focus();
  };
  const name = h('input', { type: 'text', maxlength: '100', 'data-testid': 'site-name', placeholder: sites.length ? t('settings.placeholderOffice') : t('settings.placeholderHome') });
  const add = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'site-add' }, t('settings.addSite'));
  const form = h(
    'form',
    {
      class: 'row',
      onsubmit: (e) => {
        e.preventDefault();
        run(add, async () => {
          const site = await post('/sites', { name: name.value.trim() || (sites.length ? '' : t('settings.defaultSite')) });
          toast(t('settings.added', { name: site.name }));
          ctx.refresh();
        });
      },
    },
    h('label', { class: 'sr-only', for: 'new-site' }, t('settings.newSiteName')),
    name,
    add,
  );
  name.id = 'new-site';
  draw();
  return card(t('settings.sites'), h('p', { class: 'muted' }, t('settings.sitesHint')), list, h('hr', {}), form);
}

function passwordCard(session) {
  if (session.password_fixed) {
    return card(t('settings.password'), h('p', { class: 'muted', 'data-testid': 'password-fixed' }, t('settings.passwordFixed')));
  }
  const current = h('input', { type: 'password', autocomplete: 'current-password', 'data-testid': 'pw-current' });
  const next = h('input', { type: 'password', autocomplete: 'new-password', minlength: '10', 'data-testid': 'pw-new' });
  const again = h('input', { type: 'password', autocomplete: 'new-password', 'data-testid': 'pw-again' });
  const msg = slot(); // the form's one place for problems
  const problem = (text) => setNotice(msg, 'error', 'pw-error', text);
  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'pw-save' }, t('settings.changePassword'));
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      clearNotice(msg);
      if (next.value.length < 10) {
        problem(t('settings.pwShort'));
        return;
      }
      if (next.value !== again.value) {
        problem(t('settings.pwMismatch'));
        return;
      }
      run(save, async () => {
        try {
          await post('/password', { current: current.value, new: next.value });
          toast(t('settings.pwChanged'));
          setTimeout(() => location.reload(), 800);
        } catch (err) {
          problem(err.message);
        }
      });
    },
  });
  place(form, field(t('settings.pwCurrent'), current), field(t('settings.pwNew'), next, t('settings.pwNewHint')), field(t('settings.pwAgain'), again), msg, save);
  return card(t('settings.password'), form);
}

// Language of this browser (#204): automatic from the browser, or one of the offered languages.
function languageCard(ctx) {
  const options = [['auto', t('settings.langAuto')], ...availableLanguages().map((l) => [l.code, l.name])];
  const pick = select(options, savedLanguage(), { 'data-testid': 'language' });
  pick.addEventListener('change', () => {
    setLanguage(pick.value);
    location.reload();
  });
  return card(t('settings.language'), h('p', { class: 'muted' }, t('settings.languageHint')), field(t('settings.language'), pick));
}

// The parameters of a rule (#441), read-only, from the JSON Schema the API sends: the value in
// force for the whole rule next to its default, then what each scope changes.
function paramsView(r) {
  const p = r.parameters;
  const props = (p && p.schema && p.schema.properties) || {};
  const names = Object.keys(props);
  if (!names.length && !(p && p.scopes.length)) return null;
  const unit = (n) => (props[n] && props[n].unit ? ` ${props[n].unit}` : '');
  const rows = names.map((n) =>
    h(
      'li',
      { 'data-testid': 'rule-param', 'data-name': n },
      h('code', {}, n),
      ` = ${p.values[n]}${unit(n)} `,
      h('span', { class: 'muted small' }, `(${t('settings.paramDefault', { value: p.defaults[n] })}) ${props[n].description || ''}`),
    ),
  );
  const scopes = p.scopes.map((s) => {
    const match = Object.entries(s.match).map(([k, v]) => `${k}=${v}`).join(', ');
    const set = names.filter((n) => n in s.params).map((n) => `${n} = ${s.values[n]}${unit(n)}`);
    if (s.enabled !== null) set.push(`enabled = ${s.enabled}`);
    if (s.severity) set.push(`severity = ${s.severity}`);
    return h('li', { 'data-testid': 'rule-scope' }, h('strong', {}, t('settings.paramScope', { match })), ` ${set.join(', ')}`);
  });
  return h('div', { class: 'rule-params', 'data-testid': 'rule-params' }, h('h4', {}, t('settings.params')), h('ul', {}, rows, scopes), h('p', { class: 'muted small' }, t('settings.paramsFile')));
}

function rulesCard(rules) {
  return card(
    t('settings.rules'),
    h('p', { class: 'muted' }, t('settings.rulesHint'), ' ', h('code', {}, 'rules: {dhcp.one-server: {enabled: false}}')),
    h(
      'div',
      { class: 'rules', 'data-testid': 'rules' },
      rules.map((r) =>
        h(
          'details',
          { class: 'rule', 'data-testid': 'rule', 'data-id': r.id },
          h('summary', {}, severityBadge(r.severity), ' ', h('strong', {}, ruleTitle(r)), ' ', r.enabled ? null : tag(t('settings.off')), h('span', { class: 'muted small' }, ` ${r.id}`)),
          h('p', {}, ruleExplanation(r)),
          paramsView(r),
        ),
      ),
    ),
  );
}

export async function renderSettings(main, ctx, session) {
  const id = ctx.renderId;
  const [sites, devices, rules, notify] = await Promise.all([get('/sites'), get('/devices'), get('/rules'), notificationsCard(ctx)]);
  if (!ctx.alive(id)) return;
  place(main, pageHead(t('nav.settings')), languageCard(ctx), sitesCard(ctx, sites, devices), passwordCard(session), notify, rulesCard(rules));
}
