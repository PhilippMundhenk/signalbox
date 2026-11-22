// The user's own notes on objects (#186): label, owner, purpose, notes, expectations.
import { del, enc, put } from './api.js';
import { h } from './util.js';
import { checkField, confirmDialog, field, kv, modal, run, select, toast } from './ui.js';

export const CATEGORIES = [['', 'Not said'], ['computer', 'Computer'], ['phone', 'Phone'], ['tablet', 'Tablet'], ['iot', 'Smart home (IoT)'], ['camera', 'Camera'], ['printer', 'Printer'], ['media', 'TV / media'], ['server', 'Server / NAS'], ['network', 'Network device'], ['other', 'Other']];

export function noteOf(ix, target) {
  return (ix.net.annotations || []).find((a) => a.target === target) || null;
}

// Expectations offered per kind of object (the server refuses the others).
const EXPECT = {
  device: [['may_be_unreachable', 'May be off or unreachable for long (a laptop, a seasonal device)']],
  client: [
    ['static_address', 'Uses a fixed address on purpose'],
    ['may_be_unreachable', 'May be away for long'],
    ['known_neighbour', 'A known foreign device (not ours, not a problem)'],
  ],
  port: [['uplink', 'Uplink towards the router']],
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
    const checks = (EXPECT[kind] || []).map(([key, text]) => [key, h('input', { type: 'checkbox', checked: n.expected[key] === true, 'data-testid': `note-${key}` }), text]);
    const category = kind === 'client' ? select(CATEGORIES, n.expected.category || '', { 'data-testid': 'note-category' }) : null;
    const body = h(
      'div',
      {},
      field('Name', label, 'A friendly name, shown next to the one the device reports.'),
      field('Owner', owner),
      field('Purpose', purpose),
      category ? field('What it is', category) : null,
      field('Notes', notes),
      field('Tags', tags, 'Separated by commas.'),
      checks.map(([, box, text]) => checkField(text, box)),
      h('p', { class: 'muted small' }, 'Kept in Signalbox only: never written to the device and never sent to MQTT.'),
    );
    modal({
      title,
      body,
      onClose: () => resolve(changed),
      actions: (close) => [
        note ? h('button', { class: 'btn danger', type: 'button', 'data-testid': 'note-remove', onclick: (e) => run(e.target, async () => {
          await del(`/annotations/${enc(target)}`);
          changed = true;
          toast('Notes removed.');
          close();
        }) }, 'Remove') : null,
        h('button', { class: 'btn', type: 'button', 'data-testid': 'note-cancel', onclick: () => close() }, 'Cancel'),
        h('button', { class: 'btn primary', type: 'button', 'data-testid': 'note-save', onclick: (e) => run(e.target, async () => {
          const expected = {};
          for (const [key, box] of checks) if (box.checked) expected[key] = true;
          if (category && category.value) expected.category = category.value;
          await put(`/annotations/${enc(target)}`, {
            label: label.value || null,
            owner: owner.value || null,
            purpose: purpose.value || null,
            notes: notes.value || null,
            tags: tags.value.split(',').map((t) => t.trim()).filter(Boolean),
            expected,
          });
          changed = true;
          toast('Notes saved.');
          close();
        }) }, 'Save'),
      ],
    });
  });
}

// A card with the notes of one object and a button to edit them.
export function notesCard(ix, target, kind, title, onChange) {
  const note = noteOf(ix, target);
  const declared = note && note.source === 'declared';
  const edit = h('button', { class: 'btn', type: 'button', 'data-testid': 'edit-notes' }, note ? 'Edit notes' : 'Add notes');
  edit.addEventListener('click', async () => {
    if (await editNote(target, kind, note, title)) onChange();
  });
  const rows = note
    ? [
        ['Name', note.label || undefined],
        ['Owner', note.owner || undefined],
        ['Purpose', note.purpose || undefined],
        ['Notes', note.notes || undefined],
        ['Tags', note.tags.length ? note.tags.join(', ') : undefined],
        ['May be unreachable', note.expected.may_be_unreachable ? 'yes' : undefined],
      ]
    : [];
  return h(
    'section',
    { class: 'card', 'data-testid': 'notes' },
    h('h2', {}, 'Notes'),
    note ? kv(rows) : h('p', { class: 'muted' }, 'Your own notes: a name, who looks after it, what it is for.'),
    declared ? h('p', { class: 'muted small', 'data-testid': 'notes-declared' }, 'Declared in the desired state; change them there.') : h('div', { class: 'row' }, edit),
  );
}

export function confirmRemoveAck() {
  return confirmDialog({ title: 'Remove the acknowledgement?', message: 'The finding counts as a problem again.', confirmLabel: 'Remove' });
}

