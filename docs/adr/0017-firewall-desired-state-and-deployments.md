# 0017. Firewall desired state and deployments: owned objects, zone references, a lockout check

Date: 2026-11-23 · Status: accepted

## Context

Firewalls are read since #135 ([ADR 0013](0013-firewall-zones-rules-and-reachability.md)). The
next step (#295) is to declare zone policies, filter rules and port forwards and to deploy them
through the existing transaction (plan, backup, apply with a confirm timer, verify, confirm or
roll back). Three things make firewalls different from VLANs and SSIDs:

- A router's firewall is mostly the owner's: vendor defaults (OpenWrt's `Allow-*` rules), rules
  made in LuCI or the OPNsense GUI, port forwards for a game console. A partial desired state
  must never delete or rewrite them as a side effect.
- Rules are ordered and first match wins, so "add this rule" also means "where".
- A firewall change can cut Signalbox off from the very device it changes, or from devices
  behind it; the confirm timer undoes that, but only after `deploy.confirm_seconds` without
  access, and it is better not to approve such a plan by accident.

## Decision

- **Syntax** (docs/DESIRED.md): `sites.<site>.firewalls`, one entry per device, with
  `policies` (`from`, `to` and `action` between two zones, or `to: device` for traffic to the
  router itself), `rules` (`name`, `from` / `to` with a zone or a segment and addresses,
  `protocol`, `port`, `family`, `action`) and `forwards` (`name`, `protocol`, external `port`,
  `to: {address, port}`, `from` defaulting to the one internet zone). Zones are referenced by the
  device's zone name or as `{segment: <vlan>}`, which the planner resolves to the one zone that
  holds the segment on that device (none or several: the plan is refused with the reason).
- **Three change kinds**: `zone-policy` (key `policy/<from>/<to|device>`, value: the action),
  `firewall-rule` (key `rule/<key>`) and `port-forward` (key `forward/<key>`), with old and new
  values like every other kind. They are applied after the network kinds; removals before.
- **Ownership by tag**: the key of a rule or forward is its declared name (`-` becomes `_`);
  integrations tag what they create with it, and the readers report it as `signalbox_key` on
  `FirewallRule`, `PortForward` and `ZonePolicy`. Only tagged objects are changed or removed. A
  declared firewall owns its device's tagged rules and forwards: one that is no longer declared
  is removed by the next plan (and reported by `drift.firewall` until then). The device's own
  objects are touched only when the desired state says so: `adopt: <name>` on a rule or forward
  replaces the device's object of that name with a tagged one; `adopt: true` on a policy lets
  Signalbox remove the device's own forwarding of that pair. A policy is a setting of the
  zones, which exist on the device; Signalbox never creates or removes zones.
- **Order**: Signalbox's rules come before the device's own ones, in the order they were
  created. The prediction (`apply_change`) puts them there too, so the checks and the lockout
  check see the same first-match order the device will have.
- **Lockout check**: for plans with firewall changes, `management_cuts` evaluates
  `signalbox.firewall.reach` to every device's management address (and port) before and after
  the plan, from `deploy.signalbox_address` or, without it, from the network of that address.
  When the answer gets worse (allowed to denied or unknown, unknown to denied), the plan lists
  it under `lockouts`; approving it needs the explicit `allow_lockout` override, which the
  change record keeps and the event log and UI show in capitals. The confirm timer stays the
  last safeguard for what the model cannot see.
- **Drift** (`drift.firewall`) is the planner's own comparison: whatever a plan would change is
  a finding, so drift and plan never disagree.

### OpenWrt (this change)

Named UCI sections with a prefix: `sb_rule_<key>` (rule), `sb_fwd_<key>` (redirect, DNAT),
`sb_pol_<src>_<dest>` (forwarding); OpenWrt's own sections are anonymous or named otherwise, and
no unknown option is added that fw4 might warn about. Policies to the router or inside a zone
are the zone's `input` / `forward`; between zones `accept` is a forwarding, `reject` its absence
(`drop` between zones cannot be expressed and is refused). New rules are moved to the top with
`uci order`. The `firewall` config joins the written configs: the write ACL, the backup and the
restore include it; an older login that cannot read it keeps working for the other kinds.

### Later: OPNsense and MikroTik

- **OPNsense**: filter rules through `/api/firewall/filter` (`addRule`, `setRule`, `delRule`),
  tagged by a description prefix and kept in a category `signalbox`; port forwards through the
  d_nat API where the release has it (the first release with it is to be checked; without it
  forwards are refused).
  Transaction: `savepoint` before `apply`, `cancelRollback` to confirm, the automatic revert
  after 60 s as the timer; zone policies map to "block/pass from interface X to net Y" rules
  (OPNsense has no zone pair defaults), so a policy becomes a tagged rule at the end of
  Signalbox's block.
- **MikroTik**: `/ip/firewall/filter` and `/ip/firewall/nat` over REST with
  `comment=signalbox:<key>` as the tag and `place-before` the first rule that is not
  Signalbox's; policies as tagged rules on interface lists. Safe mode is not available over REST,
  so the integration schedules its own revert (a `/system/scheduler` entry that restores the
  backup) and removes it to confirm.

## Consequences

- Deployments never surprise the owner: a plan lists only tagged objects, policies they
  declared and objects they adopted; drift on the device's own rules is shown, never fixed.
- Declared names are identities: renaming a rule removes the old one and creates a new one.
- The ordering between overlapping declared rules is "first created first"; a declared order
  is not enforced yet. Rules are input or forward only (no output, no source ports, no
  negation), port forwards a single external range.
- The lockout check is as good as the reachability model: where it cannot decide it says
  "unknown", which counts as worse than "allowed", so it errs towards asking for the override.
- OPNsense and MikroTik plans with firewall changes are refused until their writers exist (the
  manifests do not list the kinds).
