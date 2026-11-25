# 0027. Typed rule parameters and per-scope rule settings (#187)

Date: 2026-11-25 · Status: accepted

## Context

Per rule, the configuration had only `enabled` and `severity`. Thresholds (storage fill level,
PoE budget share, lease-time bounds, channel utilisation, clock offset, ...) were constants in
the rule modules, so a user whose lab site or guest network needs other limits could only turn
the whole rule off. Many proposed checks (#108, #115, #116, #121, #128 to #131) need thresholds
too. Annotations (#186, ADR 0007) already give objects tags.

## Decision

- **A parameter model per rule, next to the rule.** A Pydantic `RuleParams` subclass in the
  rule's module; every field is declared with `param(default, unit=..., description=...,
  ge=..., le=...)`. `@rule(..., params=Model)` binds the model to its rule (one model per rule;
  a field without default, unit or description is refused when the module loads).
- **Typed accessor.** A rule reads its values with `ctx.params(Model, obj)`, where `obj` is the
  model object (or id) the values apply to, never from a dictionary. The model class names the
  rule, so the accessor needs no rule id string and mypy knows the fields (the issue sketched
  `ctx.params(rule_id, scope_object)`). Outside `evaluate` (a rule called directly in a test)
  it returns the defaults; rule signatures do not change.
- **Configuration shape**, only in the file:
  `rules: {<id>: {enabled, severity, params: {...}, scopes: [{match: {...}, enabled, severity,
  params}]}}`. Everything is optional; a configuration without `params` or `scopes` means what
  it meant before.
- **Scope selectors**: `site` (id or name), `device` (id or name), `device_role`, `segment` (id,
  name or VLAN id), `segment_purpose` and `tag` (a tag of the object's annotation, #186). The
  selectors of one scope must all match. An object's facts: a device has its site and role; a
  network its site and purpose; a port, server, radio or tunnel counts for its device and, where
  it has one, its network; tags are the annotation tags of the object, its device and its
  network.
- **Which object a finding belongs to**: its first affected object (`objects[0]`), which is
  also the object the migrated rules pass to `ctx.params`. Scope `enabled`/`severity` are
  applied per finding; a rule that is off but has a scope with `enabled: true` runs, and only
  the findings in that scope are kept.
- **Precedence: most specific wins, then order.** Rank: device > segment > tag > device_role =
  segment_purpose > site; with equal rank, more selectors win. Among equally specific scopes
  the first listed wins. Layers merge per key: defaults, then `rules.<id>.params`, then the
  matching scopes from the least to the most specific; a scope changes only what it sets.
- **Validation at start.** `service.build` checks `rules:` against the installed rules and
  stops with every problem and its path (`rules.health.storage-full.scopes.0.params.warn_pct:
  Input should be less than or equal to 100`). An unknown parameter, a value of the wrong type
  or out of range, and `params` on a rule without parameters or on a rule that is not installed
  are errors. Other settings for a missing rule stay allowed (a plugin may be absent for a
  while).
- **Published contract.** `docs/rules-schema.json` (JSON Schema of the whole `rules:` section,
  units as `unit` on each property) and a generated *Parameters* section in `docs/RULES.md`
  (default, unit and meaning of each parameter) come from the models (`tools/gen_docs.py`); a
  test fails when either is stale. The UI can render forms from the schema later.
- **Explainability.** `Finding.parameters` lists, for a rule with parameters, every value the
  finding was judged with and its origin (`default`, `rule`, or `scope` with the selectors,
  e.g. `site=lab`). The finding card shows it.
- **Few parameters, behaviour unchanged.** Migrated: `device.resources` (memory %, generic
  temperature), `health.storage-full` (warning and error %), `health.ups-runtime-low`,
  `health.ups-not-tested`, `health.uptime-very-long`, `poe.budget` (warning %), `dhcp.pool-usage`
  (nearly full %), `dhcp.lease-time` (min, max, guest max), `time.offset`,
  `vpn.handshake-stale`, `account.stale`, `wifi.channel-busy` (info and warning %),
  `wifi.channel-crowded` (signal and count). Defaults are the former constants. Values that
  are facts rather than taste stay constants (100 % of a PoE budget, the PoE class tolerance,
  DFS channel ranges, the minimum RSA key size).

### The open questions of #187

- *Scopes in the configuration, or annotations as the only scope mechanism?* Both, with one
  mechanism: scopes live in the configuration next to the rule, and annotations take part
  through the `tag` selector. Thresholds are a property of the check, not of the object, so a
  user reads them in one place; tagging objects is how to group things the other selectors
  cannot name.
- *Parameters per site in the desired state rather than the global configuration?* No: they
  stay in `signalbox.yaml` with the other rule settings. The desired state describes the
  network that should exist, not how strictly Signalbox judges it; per-site values are a
  `site` scope. The configuration is still a file only, so a UI editor is a later step.

## Consequences

- Existing configurations and every finding's text and severity stay the same by default; the
  findings of the migrated rules carry `parameters`.
- Thresholds that already had a global setting stay where they are for now: `counters.*`
  (`port.errors`) and `certificates.warn_days`/`urgent_days` (certificate rules). Moving them to
  rule parameters, so they can be scoped too, is a follow-up together with the UI form.
- Engine rules (`signalbox.read`, `ack.expired`) take `enabled`/`severity` as before; scopes
  apply to discovered rules.
- A rule must pass the same object to `ctx.params` that it lists first in the finding,
  otherwise the recorded parameters could differ from those it used; the migrated rules do.
- A device-reported limit still wins over the generic one where the model has it (temperature
  sensors with their own limit).
