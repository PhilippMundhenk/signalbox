// Desired state: what the network should look like (YAML), and the secrets it names.
import { del, enc, get, post, put } from '../api.js';
import { clear, h, place } from '../util.js';
import { card, confirmDialog, field, pageHead, run, select, table, toast } from '../ui.js';

const HELP =
  'Declare only what Signalbox should manage: segments (VLANs, router address, DHCP), Wi-Fi networks and port VLANs. ' +
  'Differences to the devices appear as findings ("drift"). Wi-Fi passphrases are never written here: an SSID names a secret.';

function editorCard(ctx, current, sites) {
  const text = h('textarea', { class: 'code', rows: '22', spellcheck: 'false', 'data-testid': 'desired-yaml' });
  text.value = current.yaml;
  const status = h('p', { role: 'status', 'data-testid': 'desired-status', class: current.valid ? 'muted' : 'error' },
    current.valid ? (current.yaml ? `Valid. Sites: ${current.sites.join(', ') || 'none'}.` : 'Nothing declared yet.') : current.error);
  const message = h('input', { type: 'text', maxlength: '500', placeholder: 'What changed and why', 'data-testid': 'desired-message' });
  const save = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'desired-save' }, 'Save');
  save.addEventListener('click', () =>
    run(save, async () => {
      try {
        const r = await put('/desired', { yaml: text.value, message: message.value });
        toast(r.commit ? `Saved (commit ${r.commit.slice(0, 7)}).` : 'Saved.');
        ctx.refresh();
      } catch (err) {
        status.className = 'error';
        status.textContent = err.message;
        throw err;
      }
    }),
  );
  const site = select(sites.map((s) => [s.id, s.name]), sites[0] ? sites[0].id : '', { 'data-testid': 'desired-import-site', 'aria-label': 'Site to import' });
  const imp = h('button', { class: 'btn', type: 'button', 'data-testid': 'desired-import', disabled: !sites.length }, 'Import what the devices report');
  imp.addEventListener('click', () =>
    run(imp, async () => {
      if (text.value.trim() && !(await confirmDialog({ title: 'Replace the editor content?', message: 'The YAML in the editor is replaced by what the devices of this site report. Nothing is saved until you press Save.', confirmLabel: 'Replace' }))) return;
      const r = await post(`/desired/import/${enc(site.value)}`);
      text.value = r.yaml;
      status.className = 'muted';
      status.textContent = 'Imported. Review, remove what Signalbox should not manage, then save.';
    }),
  );
  return card(
    'Desired state',
    h('p', { class: 'muted' }, HELP),
    h('div', { class: 'row' }, site, imp),
    field('YAML', text),
    status,
    field('Change note', message, 'Kept in the git history when the desired folder is a git repository.'),
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
            ['Name', (n) => h('code', {}, n)],
            [
              '',
              (n) => {
                const b = h('button', { class: 'btn small', type: 'button', 'data-testid': 'secret-delete' }, 'Delete');
                b.addEventListener('click', () =>
                  run(b, async () => {
                    if (!(await confirmDialog({ title: `Delete secret ${n}?`, message: 'SSIDs that name it can no longer be checked or deployed.', confirmLabel: 'Delete', danger: true }))) return;
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
      : h('p', { class: 'muted' }, 'No secrets stored.'),
  );
  const name = h('input', { type: 'text', maxlength: '64', placeholder: 'e.g. main-wifi', 'data-testid': 'secret-name' });
  const value = h('input', { type: 'password', maxlength: '200', autocomplete: 'new-password', 'data-testid': 'secret-value' });
  const add = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'secret-add' }, 'Store');
  const form = h('form', {}, field('Name', name), field('Value', value, 'Stored encrypted; it is never shown again.'), h('div', { class: 'row' }, add));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    run(add, async () => {
      await put(`/secrets/${enc(name.value.trim())}`, { value: value.value });
      toast('Secret stored.');
      ctx.refresh();
    });
  });
  return card('Secrets', h('p', { class: 'muted' }, 'Wi-Fi passphrases named by passphrase_secret in the desired state.'), list, form);
}

function findingList(title, findings, testid) {
  if (!findings.length) return null;
  return h('div', { 'data-testid': testid }, h('h3', {}, title), h('ul', {}, findings.map((f) => h('li', {}, `${f.severity}: ${f.message}`))));
}

export function renderPlan(box, p) {
  clear(box);
  if (!p.changes.length) {
    place(box, h('p', { 'data-testid': 'plan-empty' }, 'Nothing to change: the devices already match the desired state.'));
    return;
  }
  place(
    box,
    h('p', {}, `${p.changes.length} change(s) on ${p.devices.length} device(s), in this order:`),
    h(
      'ol',
      { 'data-testid': 'plan-changes' },
      p.changes.map((c) => h('li', {}, c.text, c.risk ? h('div', { class: 'error' }, `Risk: ${c.risk}`) : null)),
    ),
    p.blocking.length ? h('p', { class: 'error', 'data-testid': 'plan-blocked' }, 'This plan would create errors; it cannot be deployed as it is.') : null,
    findingList('New findings after the change', p.new_findings, 'plan-new'),
    findingList('Findings this resolves', p.resolved_findings, 'plan-resolved'),
  );
}

function planCard() {
  const box = h('div', { 'data-testid': 'plan' }, h('p', { class: 'muted' }, 'Compute what would change on the devices. Nothing is changed.'));
  const btn = h('button', { class: 'btn', type: 'button', 'data-testid': 'plan-make' }, 'Plan changes');
  btn.addEventListener('click', () => run(btn, async () => renderPlan(box, await post('/plan'))));
  return card('Plan', h('div', { class: 'row' }, btn), box);
}

export async function renderDesired(main, ctx) {
  const [current, sites, names] = await Promise.all([get('/desired'), get('/sites'), get('/secrets')]);
  place(clear(main), pageHead('Desired state'), editorCard(ctx, current, sites), planCard(), secretsCard(ctx, names));
}
