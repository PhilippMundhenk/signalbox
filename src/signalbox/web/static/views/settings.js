// Settings: sites, password, rules (read-only).
import { del, enc, get, post, put } from '../api.js';
import { clear, h, place } from '../util.js';
import { card, confirmDialog, field, pageHead, run, severityBadge, table, tag, toast } from '../ui.js';

function sitesCard(ctx, sites, devices) {
  const list = h('div', {});
  const draw = () => {
    clear(list);
    if (!sites.length) place(list, h('p', { class: 'muted', 'data-testid': 'no-sites' }, 'No site yet. Add one, for example “Home”.'));
    place(list, 
      table(
        [
          ['Name', (x) => x.name],
          ['Devices', (x) => String(devices.filter((d) => d.site_id === x.id).length)],
          [
            '',
            (x) => {
              const rename = h('button', { class: 'btn small', type: 'button', 'data-testid': 'site-rename' }, 'Rename');
              rename.addEventListener('click', () => renameSite(x));
              const remove = h('button', { class: 'btn small', type: 'button', 'data-testid': 'site-delete', disabled: devices.some((d) => d.site_id === x.id), title: 'Only a site without devices can be deleted' }, 'Delete');
              remove.addEventListener('click', () =>
                run(remove, async () => {
                  if (!(await confirmDialog({ title: `Delete ${x.name}?`, message: 'The site is removed. It has no devices.', confirmLabel: 'Delete', danger: true }))) return;
                  await del(`/sites/${enc(x.id)}`);
                  toast(`${x.name} deleted.`);
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
    const ok = h('button', { class: 'btn primary', type: 'button', 'data-testid': 'site-rename-save' }, 'Save');
    ok.addEventListener('click', () =>
      run(ok, async () => {
        await put(`/sites/${enc(x.id)}`, { name: name.value.trim() });
        toast('Site renamed.');
        ctx.refresh();
      }),
    );
    place(clear(list), field(`New name for ${x.name}`, name), h('div', { class: 'row' }, ok, h('button', { class: 'btn', type: 'button', onclick: draw }, 'Cancel')));
    name.focus();
  };
  const name = h('input', { type: 'text', maxlength: '100', 'data-testid': 'site-name', placeholder: sites.length ? 'e.g. Office' : 'Home' });
  const add = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'site-add' }, 'Add site');
  const form = h(
    'form',
    {
      class: 'row',
      onsubmit: (e) => {
        e.preventDefault();
        run(add, async () => {
          const site = await post('/sites', { name: name.value.trim() || (sites.length ? '' : 'Home') });
          toast(`Site ${site.name} added.`);
          ctx.refresh();
        });
      },
    },
    h('label', { class: 'sr-only', for: 'new-site' }, 'New site name'),
    name,
    add,
  );
  name.id = 'new-site';
  draw();
  return card('Sites', h('p', { class: 'muted' }, 'A site is one place with its own network. Segments and checks are per site.'), list, h('hr', {}), form);
}

function passwordCard(session) {
  if (session.password_fixed) {
    return card('Password', h('p', { class: 'muted', 'data-testid': 'password-fixed' }, 'The password is set by SIGNALBOX_AUTH_PASSWORD or in signalbox.yaml and can only be changed there.'));
  }
  const current = h('input', { type: 'password', autocomplete: 'current-password', 'data-testid': 'pw-current' });
  const next = h('input', { type: 'password', autocomplete: 'new-password', minlength: '10', 'data-testid': 'pw-new' });
  const again = h('input', { type: 'password', autocomplete: 'new-password', 'data-testid': 'pw-again' });
  const msg = h('p', { class: 'error', role: 'alert', 'data-testid': 'pw-error' });
  const save = h('button', { class: 'btn primary', type: 'submit', 'data-testid': 'pw-save' }, 'Change password');
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      msg.textContent = '';
      if (next.value.length < 10) {
        msg.textContent = 'The new password needs at least 10 characters.';
        return;
      }
      if (next.value !== again.value) {
        msg.textContent = 'The new passwords do not match.';
        return;
      }
      run(save, async () => {
        try {
          await post('/password', { current: current.value, new: next.value });
          toast('Password changed. Please sign in again.');
          setTimeout(() => location.reload(), 800);
        } catch (err) {
          msg.textContent = err.message;
        }
      });
    },
  });
  place(form, field('Current password', current), field('New password', next, 'At least 10 characters. All sessions end.'), field('New password again', again), msg, save);
  return card('Password', form);
}

function rulesCard(rules) {
  return card(
    'Rules',
    h(
      'p',
      { class: 'muted' },
      'These checks run after every reading. To turn one off or change its severity, edit ',
      h('code', {}, 'rules:'),
      ' in ',
      h('code', {}, 'signalbox.yaml'),
      ' in the data directory, for example ',
      h('code', {}, 'rules: {dhcp.one-server: {enabled: false}}'),
      ', and restart Signalbox.',
    ),
    h(
      'div',
      { class: 'rules', 'data-testid': 'rules' },
      rules.map((r) =>
        h(
          'details',
          { class: 'rule', 'data-testid': 'rule', 'data-id': r.id },
          h('summary', {}, severityBadge(r.severity), ' ', h('strong', {}, r.title), ' ', r.enabled ? null : tag('off'), h('span', { class: 'muted small' }, ` ${r.id}`)),
          h('p', {}, r.explanation),
        ),
      ),
    ),
  );
}

export async function renderSettings(main, ctx, session) {
  const id = ctx.renderId;
  const [sites, devices, rules] = await Promise.all([get('/sites'), get('/devices'), get('/rules')]);
  if (!ctx.alive(id)) return;
  place(main, pageHead('Settings'), sitesCard(ctx, sites, devices), passwordCard(session), rulesCard(rules));
}
