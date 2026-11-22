# 0007: Annotations and acknowledged findings are user data on the network (#186)

## Context

Real networks produce findings that are correct by the rule but fine for the user: a café
hotspot that is open on purpose, a lab port that is slow, a printer with a fixed address in the
pool. Until now the only answer was turning the whole rule off. Several planned checks also need
to know what the user intends ("this device may be off", "this MAC is a neighbour's access
point"). Labels, owners and notes make the views readable. None of this can be read from a
device, and it must survive observation rounds, model ids that are stable across runs, and
desired/predicted states of a plan.

## Decision

- **Model.** `Annotation` (target, label, purpose, owner, notes, tags, typed `Expected`) and
  `Acknowledgement` (rule, a finding id *or* a target object, reason, by, at, until, optional
  fingerprint of the finding's message) are model objects. `Network.annotations` and
  `Network.acknowledgements` carry them; rules read them, adapters never set them, snapshots
  never contain them.
- **Targets are model ids**, canonicalised: a device id, `<device>/port/<name>`,
  `<site>/segment/<key>` (including `native-<router>`, ADR 0005), `<device>/subnet/<name>`,
  other `<device>/<kind>/<name>` objects, and `client/<mac>` for anything known by a MAC
  address (a bare MAC is accepted). The kind follows from the id; expectations that do not fit
  the kind are refused.
- **Two sources.** Declared in the desired state (`sites.<site>.annotations`,
  `sites.<site>.acknowledgements`: reviewable, in git, read-only in the UI) and stored in the
  database (schema version 4, set in the UI). Per target a declared annotation replaces a
  stored one; acknowledgements of both sources apply. The runner adds both to every network it
  builds (`signalbox.annotate.apply`), like declared purposes (`apply_declared`). The UI can
  export the stored ones as desired-state YAML.
- **Acknowledging does not hide.** `evaluate()` applies the network's active acknowledgements:
  the finding keeps its id and is still stored, with `Finding.acknowledged` set. A finding is a
  *problem* (`Finding.problem`) only when it is neither incomplete nor acknowledged: the start
  page lists acknowledged findings apart, MQTT counts them apart (`acknowledged`) and never
  switches the problem sensor on for them, and an acknowledged error does not block a plan.
  An acknowledgement with `until` lapses then (`ack.expired`, info, from the engine itself);
  one with a fingerprint lapses when the finding's message changes.
- **Stale ids are findings.** `annotations.stale` (info) reports annotations and
  acknowledgements whose object is gone (renamed port, moved VLAN, removed device, a client not
  seen for the history period), so ids that change never orphan user data silently.

## Consequences

- `Finding` and the findings API gain `acknowledged`; MQTT site state gains `acknowledged` and
  the counts change meaning to "open problems". Clients that counted `incomplete` see
  acknowledged incomplete findings no longer counted there.
- Checks get annotation-aware helpers instead of on/off switches: `Network.annotation()`,
  `Network.expected()`, `Network.label()`, `Network.knows()`, `client_target()`. Changing a check
  to respect an expectation is a rule change, not a model change.
- Labels, owners and notes are personal data: shown in the UI and API, kept out of MQTT; they
  never cause writes to devices (pushing labels as port descriptions is a later option).
- There are no users: `by` is free text from the YAML; the UI leaves it empty.
- Seeding labels from device comments (`source: imported`) is reserved but not built.
