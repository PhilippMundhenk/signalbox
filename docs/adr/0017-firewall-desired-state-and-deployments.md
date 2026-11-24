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

### OPNsense (#295, second part)

- **Objects**: rules of the new rules page (`/api/firewall/filter/add_rule`, `set_rule`,
  `del_rule`) and port forwards of the destination NAT page (`/api/firewall/d_nat/*`), tagged by
  the description: `signalbox:<key>` (and ` <name>` when the name is not the key), zone
  policies `signalbox:policy/<from>/<to|device>`. Only rows with the tag are changed or removed;
  the device's own rows only when a change says `adopt`, and only rows of the new pages (the
  API cannot delete legacy or automatic rules). Signalbox's rules have the sequences 1, 2, ...
  (the web interface numbers the device's own from 100), its policies come last (900000 and up).
- **Zone policies** map to rules: pass, block or reject from interface X to the network of
  zone Y (or `(self)` for the device); `drop` is no rule at all, because pf blocks what no
  rule passes. Zones are the assigned interfaces and the interface groups. A policy of the
  device's own (its rules) is never removed: `adopt: true` on a policy changes nothing here.
- **No rollback timer**: OPNsense 25.7 and 26.1 had `savepoint`, `apply/<revision>` (an
  automatic revert after 60 s) and `cancel_rollback`; the controllers of 26.7 (checked against
  26.7.9) have none of them, `apply` only reloads. Signalbox does not fake one: the changes are
  saved with the add, set and delete calls, applied with `filter/apply` (and `d_nat/apply`), and
  when the verification fails the backup is restored (configuration history revert plus
  `filter/apply`), as for the other OPNsense kinds. What the timer would have caught, a change
  that cuts Signalbox off, is caught before by the lockout check, which needs the explicit
  override; a change that slips through cannot be undone from here and needs the console.
- A rule declares one thing per side: a destination zone **or** destination addresses (the
  destination of an OPNsense rule is one network field), one port or range, one protocol set;
  the rest is refused with the reason.

- **MikroTik**: rows of `/ip/firewall/filter`, `/ipv6/firewall/filter` and `/ip/firewall/nat`
  over REST, tagged by `comment=signalbox:<key>` (policies `signalbox:policy/<from>/<to|device>`);
  rules go before the first row of their chain that is not Signalbox's, policies at the end;
  zones are interface lists; `drop`/`reject` policies are rules, `accept` is no rule. Safe mode is
  not available over REST, so the integration arms its own revert: a `/system/scheduler` entry
  (`signalbox-revert`) at the router's clock plus the confirm time, whose script undoes exactly
  the changes of the deployment (built line by line while they are planned), removed by `confirm`
  after the verification and before a restore. A router whose clock cannot be read gets no
  firewall change. Details: [MikroTik](../adapters/mikrotik.md#firewall-changes-295).

## Consequences

- Deployments never surprise the owner: a plan lists only tagged objects, policies they
  declared and objects they adopted; drift on the device's own rules is shown, never fixed.
- Declared names are identities: renaming a rule removes the old one and creates a new one.
- The ordering between overlapping declared rules is "first created first"; a declared order
  is not enforced yet. Rules are input or forward only (no output, no source ports, no
  negation), port forwards a single external range.
- The lockout check is as good as the reachability model: where it cannot decide it says
  "unknown", which counts as worse than "allowed", so it errs towards asking for the override.
- OPNsense applies firewall changes without a rollback timer (see above); OpenWrt and MikroTik
  have one (a commit timer, a scheduler entry).
