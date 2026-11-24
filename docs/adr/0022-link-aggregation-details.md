# 0022: Link aggregation details on the LAG port and its members (#157)

## Context

Signalbox knew which ports belong to a LAG (`Port.lag` on the members, a port of role `lag`
with its members in `Port.lower`, ADR 0008), but not how the LAG works. Half-configured LAGs
(LACP on one end, static on the other; a member cabled to another switch) cause loops or silent
loss and are a common home-lab problem. Devices report the mode and the LACP state in very
different shapes: Linux and OpenWrt through the kernel's bonding driver, MikroTik through
`/interface/bonding`, Omada per switch port, and the small NETGEAR / TP-Link switches only know
static LAGs. The issue proposed an explicit `members` list on the LAG port as well.

## Decision

- **The LAG is a port** (ADR 0008: role and kind `lag`); its settings are fields on that port:
  `lag_mode` (`LagMode`: `static`, `lacp-active`, `lacp-passive`, the Linux modes
  `active-backup`, `balance-rr`, `balance-xor`, `broadcast`, `balance-tlb`, `balance-alb`,
  `other`), `hash_policy` (`l2`, `l2+l3`, `l3+l4`, `other`), `min_links`, `lacp_rate`
  (`slow`, `fast`). `None` everywhere means "not reported".
- **No second member list.** The members are `Port.lower` of the LAG port (one source of truth,
  bottom-up as in ADR 0008) and the ports whose `Port.lag` names it, for devices that report
  members without a LAG interface. `Network.lag_groups()` joins both into `LagGroup` (name, LAG
  port if any, members); rules, the topology and the UI use only that.
- **Member state on the member:** `Port.lag_member_state` (`LagMemberState`: `selected`,
  `collecting_distributing`, `partner_system_id`, `partner_port`, `partner_key`). It is what
  the device says right now, so it lives with the observed port, not in the desired state.
- **One parser for the Linux bonding driver** (`signalbox.adapters.bonding`): the Linux
  integration reads `/proc/net/bonding/*` in its script, OpenWrt reads the same values from
  sysfs through rpcd `file read` (two new ACL paths; an older ACL falls back to the UCI
  configuration). MikroTik maps `/interface/bonding` and, best effort, `monitor-slaves`;
  Omada maps `lagType`; NETGEAR / TP-Link LAGs are `static`.
- **Rules** (`lag_checks`): `lag.mode-mismatch` (both ends report the mode and do not work
  together), `lag.member-not-selected` (an LACP member up but not aggregating),
  `lag.partner-mismatch` (members with different LACP partners). `lag.consistent` now finds
  members through `lower` too, and reports a LAG with one carrying member also when LACP is
  the reason.
- **Topology:** each cable end names its LAG; a device pair whose cables all belong to one LAG
  on each side is drawn as one LAG bundle (thicker, its own badge and title with both LAG names
  and the mode).

## Consequences

- Devices that do not report modes or LACP state look and are checked as before.
- Links from LACP partner ids (`LinkOrigin.LACP`) need a mapping from an LACP system id to a
  device (usually a switch's base MAC, which few integrations report); left for a follow-up.
- The vendor field names for MikroTik `monitor-slaves`, OpenWrt's bonding options and Omada's
  `lagType` values are taken from documentation, not from real devices (#21); the CHR in CI
  verifies `/interface/bonding`.
- Writing LAGs (desired state) is not part of this decision.
