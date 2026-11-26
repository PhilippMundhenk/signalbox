// Desired state: what the network should look like (YAML), and the secrets it names.
import { t } from '../i18n.js';
import { del, enc, get, post, put } from '../api.js';
import { clear, h, place } from '../util.js';
import { card, confirmDialog, field, notice, pageHead, run, select, setNotice, slot, table, toast } from '../ui.js';

function editorCard(ctx, current, sites) {
  const text = h('textarea', { class: 'code', rows: '22', spellcheck: 'false', 'data-testid': 'desired-yaml' });
  text.value = current.yaml;
  // the one place for what the declared state is: valid, empty, or why it is not; a newer
  // result (a save, an import) replaces it
  const status = slot();
  const setStatus = (kind, text) => setNotice(status, kind, 'desired-status', text);
  if (current.valid) setStatus('info', current.yaml ? t('desired.status.valid', { sites: current.sites.join(', ') || t('desired.status.none') }) : t('desired.status.empty'));
  else setStatus('error', current.error);
  const message = h('input', { type: 'text', maxlength: '500', placeholder: t('desired.messagePlaceholder'), 'data-testid': 'desired-message' });
  const save = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'desired-save' }, t('common.save'));
  save.addEventListener('click', () =>
    run(save, async () => {
      try {
        const r = await put('/desired', { yaml: text.value, message: message.value });
        toast(r.commit ? t('desired.savedCommit', { commit: r.commit.slice(0, 7) }) : t('desired.saved'));
        ctx.refresh();
      } catch (err) {
        setStatus('error', err.message);
      }
    }),
  );
  const site = select(sites.map((s) => [s.id, s.name]), sites[0] ? sites[0].id : '', { 'data-testid': 'desired-import-site', 'aria-label': t('desired.import.site') });
  const imp = h('button', { class: 'btn', type: 'button', 'data-testid': 'desired-import', disabled: !sites.length }, t('desired.import.button'));
  imp.addEventListener('click', () =>
    run(imp, async () => {
      if (text.value.trim() && !(await confirmDialog({ title: t('desired.import.confirmTitle'), message: t('desired.import.confirmMessage'), confirmLabel: t('desired.import.replace') }))) return;
      const r = await post(`/desired/import/${enc(site.value)}`);
      text.value = r.yaml;
      setStatus('info', t('desired.import.done'));
    }),
  );
  return card(
    t('desired.title'),
    h('p', { class: 'muted' }, t('desired.help')),
    h('div', { class: 'row' }, site, imp),
    field('YAML', text),
    status,
    field(t('desired.changeNote'), message, t('desired.changeNoteHint')),
    h('div', { class: 'row' }, save),
  );
}

function secretsCard(ctx, names) {
  const list = h('div', {});
  place(
    list,
    names.length
      ? table(
          [
            [t('desired.secrets.name'), (n) => h('code', {}, n)],
            [
              '',
              (n) => {
                const b = h('button', { class: 'btn small', type: 'button', 'data-testid': 'secret-delete' }, t('common.delete'));
                b.addEventListener('click', () =>
                  run(b, async () => {
                    if (!(await confirmDialog({ title: t('desired.secrets.deleteTitle', { name: n }), message: t('desired.secrets.deleteMessage'), confirmLabel: t('common.delete'), danger: true }))) return;
                    await del(`/secrets/${enc(n)}`);
                    ctx.refresh();
                  }),
                );
                return b;
              },
              'actions',
            ],
          ],
          names,
          { testid: 'secrets', rowTestid: 'secret-row' },
        )
      : h('p', { class: 'muted' }, t('desired.secrets.none')),
  );
  const name = h('input', { type: 'text', maxlength: '64', placeholder: t('desired.secrets.namePlaceholder'), 'data-testid': 'secret-name' });
  const value = h('input', { type: 'password', maxlength: '200', autocomplete: 'new-password', 'data-testid': 'secret-value' });
  const add = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'secret-add' }, t('desired.secrets.store'));
  const form = h('form', {}, field(t('desired.secrets.name'), name), field(t('desired.secrets.value'), value, t('desired.secrets.valueHint')), h('div', { class: 'row' }, add));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    run(add, async () => {
      await put(`/secrets/${enc(name.value.trim())}`, { value: value.value });
      toast(t('desired.secrets.stored'));
      ctx.refresh();
    });
  });
  return card(t('desired.secrets.title'), h('p', { class: 'muted' }, t('desired.secrets.text')), list, form);
}

function findingList(title, findings, testid) {
  if (!findings.length) return null;
  return h('div', { 'data-testid': testid }, h('h3', {}, title), h('ul', {}, findings.map((f) => h('li', {}, `${f.severity}: ${f.message}`))));
}

export function renderPlan(box, p) {
  clear(box);
  const pending = (p.pending || []).length ? notice('info', 'plan-pending', h('strong', {}, t('desired.plan.pending')), h('ul', {}, p.pending.map((x) => h('li', {}, x)))) : null;
  if (!p.changes.length) {
    place(box, h('p', { 'data-testid': 'plan-empty' }, t('desired.plan.empty')), pending);
    return;
  }
  place(
    box,
    h('p', {}, t('desired.plan.summary', { changes: p.changes.length, devices: p.devices.length })),
    h(
      'ol',
      { 'data-testid': 'plan-changes' },
      p.changes.map((c) => h('li', {}, c.text, c.risk ? h('div', { class: 'error' }, t('desired.plan.risk', { risk: c.risk })) : null)),
    ),
    (p.lockouts || []).length ? notice('error', 'plan-lockouts', h('strong', {}, t('desired.plan.lockouts')), h('ul', {}, p.lockouts.map((x) => h('li', {}, x)))) : null,
    pending,
    p.blocking.length ? notice('error', 'plan-blocked', t('desired.plan.blocked')) : null,
    findingList(t('desired.plan.newFindings'), p.new_findings, 'plan-new'),
    findingList(t('desired.plan.resolvedFindings'), p.resolved_findings, 'plan-resolved'),
  );
}

function planCard() {
  const box = h('div', { 'data-testid': 'plan' }, h('p', { class: 'muted' }, t('desired.plan.hint')));
  const btn = h('button', { class: 'btn', type: 'button', 'data-testid': 'plan-make' }, t('desired.plan.make'));
  btn.addEventListener('click', () => run(btn, async () => renderPlan(box, await post('/plan'))));
  return card(t('desired.plan.title'), h('div', { class: 'row' }, btn), box);
}

export async function renderDesired(main, ctx) {
  const [current, sites, names] = await Promise.all([get('/desired'), get('/sites'), get('/secrets')]);
  place(clear(main), pageHead(t('desired.title')), editorCard(ctx, current, sites), planCard(), secretsCard(ctx, names));
}
