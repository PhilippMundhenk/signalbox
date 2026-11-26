# 0036. PoE in the desired state: on or off per declared port, outage and budget protection

Date: 2026-11-26 · Status: accepted

## Context

PoE is read since #159 (`PortPoe` per port: on or off, status, class, power; `PoeSupply` per
switch: budget, power in use, reserved power), and #437 / #468 / #478 / #497 added who powers
whom (`signalbox.power.powered_by`) and the `poe.*` checks. #484 asks for the writes: switch PoE
on or off per port (and the priority or power limit where a device documents them), through the
existing transaction of [DESIRED.md](../DESIRED.md) and
[DESIGN.md](../DESIGN.md#changing-configuration): explicit start, plan, approval per device,
*Changes allowed*, lock and re-read, backup, apply, verify, confirm or roll back, as
[ADR 0032](0032-gateway-group-desired-state.md) to [ADR 0035](0035-upnp-desired-state.md) did
for gateway groups, Wi-Fi roaming, tunnels and UPnP.

PoE differs from those objects:

- Switching PoE off does not change a setting of the network, it takes the power away from
  whatever is plugged in: an access point, a switch, a camera, a phone, maybe the very device
  Signalbox reaches the switch through. A mistake is an outage, and the device that is off
  cannot be reached to undo it; the confirm timer of a deployment does not help when the
  switch itself stays reachable but the powered device is gone.
- Switching PoE on is harmless for the network, but it adds load on a supply with a fixed
  budget; a switch over its budget turns ports off by its own priority, again an outage.
- The port's other settings (VLANs) are a separate object (`ports:`), and a PoE declaration
  must never change them.

## Decision

- **Syntax** (docs/DESIRED.md, `poe:` of a site, a list of its own, not a field of `ports:`):
  one entry per port with `device`, `port`, `enabled` (on or off) and `allow_outage` (default
  `false`). Only declared ports are compared and written; a port may be declared once. Ports
  without an entry are never touched. A declared port that has no PoE Signalbox could read is a
  planning error.
- **Priority and power limit are not written yet.** The model's priority (`low`, `high`,
  `critical`, from POWER-ETHERNET-MIB) does not map onto RouterOS's `poe-priority` (0 to 99,
  lower first) or realtek-poe's numbers without inventing a scale, and no writer has a
  documented per-port power limit that this model reads back. They stay a leftover of #484.
- **One change kind** `poe` (key: the port id), value `enabled`, applied after the other kinds.
  `enabled: true` is the standard mode with detection (RouterOS `auto-on`), never a forced or
  passive mode, which powers devices that did not ask for it; a port the device reports on in
  any mode (also `forced-on`) satisfies `enabled: true`.
- **Outage protection** (switching off): the plan names what is on the port, from the links
  between the managed devices (the far end of a cable link), the LLDP / CDP / MNDP neighbours
  of the port, and otherwise the power it draws now ("an unknown device that draws 5.8 W" or
  "no powered device detected"); the change carries the risk *cuts power to ...*. The plan is
  refused, with the device named, when the port feeds
  - a device Signalbox manages (any role: its loss is an outage of a managed device, and the
    device Signalbox reaches the switch through is always one of them or behind one), or
  - a neighbour that announces itself as a bridge, router or access point (LLDP capabilities
    `bridge`, `router`, `wlan-access-point`), managed or not,

  unless the entry says `allow_outage: true`. The override is per port, so it is a decision
  for exactly that cable; the risk stays in the plan for the approval to see.
- **Budget protection** (switching on): for each switch, the power it uses now (its reported
  draw or the sum of its ports, or the reserved power where that is larger) plus, for each port
  the plan switches on, the port's power limit where the switch reports one, else 15.4 W (the
  most an 802.3af / class 0 device asks for), must stay within the budget the switch reports.
  Otherwise the plan is refused with the numbers. A switch that reports no budget is not
  checked; the plan says so in the change's risk.
- **Drift** (`drift.poe`) is the planner's comparison; a device that was not read gives an
  incomplete finding, a port without PoE data an error with the reason.
- **Import** writes no `poe:` entries: which ports Signalbox may switch, and where an outage is
  accepted, is the owner's decision.
- **Writers** (each documented in the integration's page):
  - **MikroTik** (REST): `poe-out` of the port's row in `/interface/ethernet/poe` (`auto-on` or
    `off`), armed by the scheduler revert of the firewall changes; the backup holds `poe-out`
    of every row, a restore sets it back. CHR has no PoE: tested against the simulator only.
  - **OpenWrt** with `realtek-poe` (UCI `poe`, the `port` section of that interface, option
    `enable`): in a follow-up step of #484, inside the existing `uci apply` with its confirm
    timer, `poe` added to the write ACL and the backup.
  - **UniFi, Omada**: the controllers have PoE modes in their port overrides and profiles, but
    no documented write for them that this integration uses; they refuse a plan with PoE
    changes for now (leftover of #484). **NETGEAR, TP-Link plus switches and SNMP** are read
    only and refuse it like every write.

## Consequences

- PoE can be switched from the desired state with the usual plan, approval and rollback, and a
  plan never takes the power from an access point, a switch or a managed device unless that
  port's entry accepts the outage.
- The budget check is an estimate on the safe side: a port with a high reported limit may be
  refused although the device on it would draw little; declare fewer ports at a time, or let
  the switch report its real limits.
- What sits on a port is only known from links and neighbour discovery; an unmanaged device
  that does not announce itself is "unknown" and not protected beyond the named risk.
- The RouterOS REST `PATCH` of a `/interface/ethernet/poe` row and the realtek-poe UCI option
  names are guesses until a real device confirms them (#21).
