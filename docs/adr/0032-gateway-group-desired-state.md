# 0032. Gateway group desired state: tiers, weights and monitors of adopted groups

Date: 2026-11-25 · Status: accepted

## Context

Multi-WAN gateway groups are read since #150 (`GatewayGroup` with its members, their tier,
weight, monitor addresses and state; OpenWrt mwan3, OPNsense 26.7, MikroTik default routes,
UniFi and Omada). #463 asks for the desired state of these groups and for writes, through the
existing transaction of [DESIRED.md](../DESIRED.md) and [DESIGN.md](../DESIGN.md#changing-configuration):
plan, review and approval, lock and re-read, backup, apply, verify, confirm or roll back, per
device, and the devices already changed are rolled back when a later one fails.

Gateway groups differ from the objects of [ADR 0017](0017-firewall-desired-state-and-deployments.md)
and [ADR 0021](0021-logging-and-snmp-desired-state.md):

- A group is made of the device's internet lines: mwan3 interfaces and members on OpenWrt, the
  default routes on MikroTik, gateways on OPNsense. Creating a member means creating a line
  (an interface, a route with a next hop), which the desired state does not model, and a wrong
  one takes the internet away from the whole site.
- The tiers are an order, not numbers: OpenWrt compares mwan3 `metric`s, MikroTik route
  `distance`s, and the model reports the rank (1 is the first choice).
- A monitor belongs to a line, not to a group: mwan3 keeps `track_ip` on the interface, RouterOS
  checks the route's next hop (`check-gateway`), a netwatch entry pings another address.

## Decision

- **Syntax** (docs/DESIRED.md): `sites.<site>.gateway_groups`, one entry per group with
  `device`, `name` (the device's name of the group: the mwan3 policy, `default` on MikroTik),
  `adopt` and `members`; a member has `name` (the device's name of the member, as the device
  page shows it) and optionally `tier` (1 or more), `weight` (0 or more) and `monitor` (a list
  of IP addresses; `[]` means none). Only what is written is compared, like every other field of
  the desired state. A group and a member may be declared once.
- **Signalbox never creates or removes groups or members.** It changes the tier, weight and
  monitor addresses of members of a group that exists on the device. A declared group or member
  the device does not have is drift ("missing") and a planning error.
- **Ownership by adoption**: every group is the device's own, so a plan changes a group only
  when its entry says `adopt: true`; without it the plan is refused with that hint, and
  `drift.gateway-group` still compares it. Groups that are not declared, and the members of a
  declared group that are not listed, are left as they are.
- **One change kind** `gateway-group` (key `group/<name>`), applied after the logging kinds. Its
  value holds every member of the group (name, tier, weight, monitor addresses), the
  undeclared ones as the device has them, so the verification sees side effects on them too.
  Tiers are compared as ranks: the declared tiers of all members are renumbered 1, 2, ...
  in their order before the comparison (tier 1 and 5 are the same as 1 and 2). Monitor
  addresses are compared as a set. The mode is not declared: members on one tier share the
  load, several tiers are a failover, as the readers already report it.
- **Drift** (`drift.gateway-group`) is the planner's comparison, so drift and plan agree. A
  device that was not read gives an incomplete finding.
- **Import** writes every group of a site with all its members as the devices report them, and
  without `adopt`: adopting is a decision the user writes into the file.
- **Writers** (each documented in the integration's page):
  - **OpenWrt mwan3** (UCI through rpcd, `mwan3` added to the write ACL; a login with the older
    ACL is refused with the reason, the other kinds keep working): the tier becomes the
    `metric` of the member section (written as the tier number for all members of the policy
    when the order changes), the weight its `weight`, the monitor the `track_ip` list of the
    mwan3 interface. A member section that another policy also uses is not changed: Signalbox
    adds a copy (`sb_<policy>_<interface>`, option `signalbox '1'`) and puts it into this
    policy's `use_member` list in its place. The interface's `track_ip` is the line's monitor
    in every group it is in; two declarations with different monitors for one line are refused.
    Everything runs inside the existing `uci apply` with its confirm timer.
  - **MikroTik** (REST): the tier becomes the `distance` of the static default route (written
    as the tier number for all members when the order changes); a monitor that holds the
    route's gateway is `check-gateway=ping`, one without it unsets `check-gateway`; another
    address changes the `host` of the netwatch entry that is tied to the route by its comment,
    where there is one. Signalbox does not create netwatch entries: their up and down scripts
    are what moves the traffic, and those are the owner's. Routes learned from a DHCP or PPPoE
    client are dynamic and refused with the setting to change instead (the client's
    `default-route-distance`); a weight is refused (RouterOS shares the load equally). The
    route and netwatch changes are armed by the scheduler revert of the firewall changes
    (#326), and the backup holds the distance, `check-gateway` and netwatch host of these rows,
    which a restore sets back.
  - **OPNsense 26.7 and UniFi** refuse a plan with gateway group changes for now. The OPNsense
    group API (`/api/routing/group_settings/...`) is new in 26.7 and its row layout is not yet
    confirmed on a device (#21), and UniFi has no documented API for its WAN failover settings;
    both stay on a follow-up issue.

## Consequences

- No surprise changes to the internet path: a group is only written after the user adopted it,
  only the declared fields change, and no line is ever created or removed.
- An undo of a deployment writes the old tiers as tier numbers again (the old order, not the
  old metric or distance numbers) and leaves Signalbox's member copies in place with the old
  values; restoring the backup puts back the exact configuration.
- The tier renumbering, the mwan3 reload by `uci apply` and the RouterOS netwatch tie by comment
  are guesses until a real device confirms them (#21).
