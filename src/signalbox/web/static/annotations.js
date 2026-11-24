// The user's own notes on objects (#186): label, owner, purpose, notes, expectations.
import { t } from './i18n.js';
import { del, enc, put } from './api.js';
import { h } from './util.js';
import { checkField, confirmDialog, field, kv, modal, run, select, slot, toast } from './ui.js';

// Category labels are looked up at render time.
const CATEGORY_KEYS = { '': 'ack.category.none', computer: 'ack.category.computer', phone: 'ack.category.phone', tablet: 'ack.category.tablet', iot: 'ack.category.iot', camera: 'ack.category.camera', printer: 'ack.category.printer', media: 'ack.category.media', server: 'ack.category.server', network: 'ack.category.network', other: 'ack.category.other' };
export const categories = () => Object.entries(CATEGORY_KEYS).map(([id, key]) => [id, t(key)]);

export function noteOf(ix, target) {
  return (ix.net.annotations || []).find((a) => a.target === target) || null;
}

// Expectations offered per kind of object (the server refuses the others).
const EXPECT = {
  device: [['may_be_unreachable', 'ack.expect.deviceUnreachable']],
  client: [
    ['static_address', 'ack.expect.clientStatic'],
    ['may_be_unreachable', 'ack.expect.clientAway'],
    ['known_neighbour', 'ack.expect.clientNeighbour'],
  ],
  port: [['uplink', 'ack.expect.portUplink']],
};

// Opens the editor; resolves to true when something was saved or removed.
export function editNote(target, kind, note, title) {
  return new Promise((resolve) => {
    let changed = false;
    const n = note || { expected: {}, tags: [] };
    const input = (name, value, attrs = {}) => h('input', { type: 'text', value: value || '', 'data-testid': `note-${name}`, ...attrs });
    const label = input('label', n.label, { maxlength: 100 });
    const owner = input('owner', n.owner, { maxlength: 100 });
    const purpose = input('purpose', n.purpose, { maxlength: 200 });
    const tags = input('tags', (n.tags || []).join(', '));
    const notes = h('textarea', { rows: 4, maxlength: 2000, 'data-testid': 'note-notes' });
    notes.value = n.notes || '';
    const checks = (EXPECT[kind] || []).map(([key, text]) => [key, h('input', { type: 'checkbox', checked: n.expected[key] === true, 'data-testid': `note-${key}` }), t(text)]);
    const category = kind === 'client' ? select(categories(), n.expected.category || '', { 'data-testid': 'note-category' }) : null;
    const problem = slot(); // the dialog's one place for a refusal
    const body = h(
      'div',
      {},
      field(t('ack.field.name'), label, t('ack.field.nameHint')),
      field(t('ack.field.owner'), owner),
      field(t('ack.field.purpose'), purpose),
      category ? field(t('ack.field.kind'), category) : null,
      field(t('ack.field.notes'), notes),
      field(t('ack.field.tags'), tags, t('ack.field.tagsHint')),
      checks.map(([, box, text]) => checkField(text, box)),
      h('p', { class: 'muted small' }, t('ack.localOnly')),
      problem,
    );
    modal({
      title,
      body,
      onClose: () => resolve(changed),
      actions: (close) => [
        note ? h('button', { class: 'btn danger', type: 'button', 'data-testid': 'note-remove', onclick: (e) => run(e.target, async () => {
          await del(`/annotations/${enc(target)}`);
          changed = true;
          toast(t('ack.removed'));
          close();
        }, problem) }, t('common.remove')) : null,
        h('button', { class: 'btn', type: 'button', 'data-testid': 'note-cancel', onclick: () => close() }, t('common.cancel')),
        h('button', { class: 'btn primary', type: 'button', 'data-testid': 'note-save', onclick: (e) => run(e.target, async () => {
          const expected = {};
          for (const [key, box] of checks) if (box.checked) expected[key] = true;
          if (category && category.value) expected.category = category.value;
          await put(`/annotations/${enc(target)}`, {
            label: label.value || null,
            owner: owner.value || null,
            purpose: purpose.value || null,
            notes: notes.value || null,
            tags: tags.value.split(',').map((tag) => tag.trim()).filter(Boolean),
            expected,
          });
          changed = true;
          toast(t('ack.saved'));
          close();
        }, problem) }, t('common.save')),
      ],
    });
  });
}

// A card with the notes of one object and a button to edit them.
export function notesCard(ix, target, kind, title, onChange) {
  const note = noteOf(ix, target);
  const declared = note && note.source === 'declared';
  const edit = h('button', { class: 'btn', type: 'button', 'data-testid': 'edit-notes' }, note ? t('ack.edit') : t('ack.add'));
  edit.addEventListener('click', async () => {
    if (await editNote(target, kind, note, title)) onChange();
  });
  const rows = note
    ? [
        [t('ack.field.name'), note.label || undefined],
        [t('ack.field.owner'), note.owner || undefined],
        [t('ack.field.purpose'), note.purpose || undefined],
        [t('ack.field.notes'), note.notes || undefined],
        [t('ack.field.tags'), note.tags.length ? note.tags.join(', ') : undefined],
        [t('ack.field.mayBeUnreachable'), note.expected.may_be_unreachable ? t('ack.yes') : undefined],
      ]
    : [];
  return h(
    'section',
    { class: 'card', 'data-testid': 'notes' },
    h('h2', {}, t('ack.card.title')),
    note ? kv(rows) : h('p', { class: 'muted' }, t('ack.card.empty')),
    declared ? h('p', { class: 'muted small', 'data-testid': 'notes-declared' }, t('ack.card.declared')) : h('div', { class: 'row' }, edit),
  );
}

export function confirmRemoveAck() {
  return confirmDialog({ title: t('ack.confirmRemove.title'), message: t('ack.confirmRemove.message'), confirmLabel: t('common.remove') });
}

