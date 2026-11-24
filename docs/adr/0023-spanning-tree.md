# 0023: Spanning tree per bridge on the device, per port on the port (#155)

## Context

Loops and an accidental root bridge are among the hardest home-lab problems to find, and the
devices report their spanning tree in very different shapes: a MikroTik router has several
bridges, each with its own protocol and root; a Linux or OpenWrt bridge runs the kernel's
802.1D STP (or none); a managed switch has one tree for the whole switch; a NETGEAR or TP-Link
plus switch has no spanning tree at all, only a loop detection flag. Bridge ids come in several
spellings (`8000.020000000001`, `8000.2:0:0:0:0:1`, `0x8000.02:00:00:00:00:01`). Port roles
and states are runtime values that change at every reconvergence.

## Decision

- **`Device.stp_bridges: list[StpBridge] | None`, one entry per bridge.** A `StpBridge` has a
  name, `port_id` (the bridge's own port of role `bridge`; None for a whole switch), the
  protocol (`stp`, `rstp`, `mstp`, `loop-detect`, `none`), priority, bridge id, root bridge id,
  root port, root path cost and topology change count and time. `None` is "not read", `[]`
  "read, no bridge". It arrives like the accounts (`Observation.stp_bridges` per device id), so
  controllers can report it for their managed switches. Kept on the device rather than a
  network-wide list: a bridge belongs to its device, and no merge or history code changes.
- **`Port.stp: StpPort | None`** on each bridge member: role, state, edge, path cost, BPDU
  guard, root guard, loop protection. Separate from the LAG fields (#157) on purpose.
- **Bridge ids are stored in one canonical form** (`stp_bridge_id`, `parse_stp_bridge_id`:
  four hex digits of priority, a dot, the MAC with colons), so the root a bridge sees can be
  compared with another bridge's own id. A device's root bridge follows from
  `root_bridge_id == bridge_id`; the contract tests refuse other spellings.
- **No MSTP instances yet.** For MSTP the common (CIST) tree is reported; per-instance roots
  can be added as a list later without changing the existing fields.
- **Readers only read**: MikroTik uses the print of bridges and bridge ports and the read-only
  `monitor ... once` commands; Linux the `ip -j -d link show` it already runs; OpenWrt UCI,
  netifd's `bridge-attributes` and sysfs through `file read` (two new paths in the read ACL; an
  older ACL keeps the setting with an optional gap); the plus switches Switchyard's
  `read_features`. Omada is not read yet: the controller's field names are not known.
- **Core derives the layer-2 networks** (`signalbox.rules.stp_checks.domains`): bridges joined
  by known cables. The rules and the topology's root marker use it.

## Consequences

- Devices that report nothing look and are checked as before; the rules stay quiet.
- A Linux bridge has no edge ports and no port roles: the role is derived from the root port
  and the designated bridge; edge stays unknown, so `stp.client-port-not-edge` skips it.
- Topology change counts are in the model, but no built-in reader fills them yet.
- The field names of the RouterOS monitor, netifd's `bridge-attributes` and the sysfs reads on
  DSA ports are verified in the simulators and, for RouterOS, on CHR in CI; real switches with
  hardware offload should confirm them (#21).
