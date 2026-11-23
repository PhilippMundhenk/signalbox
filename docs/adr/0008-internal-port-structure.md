# 0008: The internal port structure of a device: `Port.role` and `Port.lower` (#252)

## Context

Signalbox flattened every device into one list of ports. Real devices have an internal
structure: on an OpenWrt router with DSA the CPU reaches the switch chip through a conduit
(`eth0`), the jacks on the case are DSA user ports (`lan1`…`lan4`, `wan`), a bridge (`br-lan`)
runs over jacks and Wi-Fi interfaces, VLAN interfaces (`br-lan.10`) on top; older swconfig
devices have one CPU port with VLAN devices `eth0.1`, `eth0.2`; an access point has radios with
several virtual Wi-Fi interfaces each. MikroTik (switch chip, bridge ports, VLAN interfaces) and
OPNsense (VLAN parents, laggs, bridges) look alike. Flat, the topology drew internal ports as if
a cable could be plugged in, and link and VLAN checks compared a CPU port (which carries every
VLAN tagged) with the far end of a cable.

## Decision

- **Two fields on `Port`, bottom-up.** `role` (`PortRole`: `jack`, `cpu`, `switch-port`,
  `bridge`, `vlan`, `wireless`, `lag`, `tunnel`, `virtual`) says where a port sits; `kind`
  stays what it is made of. `lower` lists the ids of the ports of the same device it runs on:
  a bridge's members, a VLAN interface's parent, a DSA user port's conduit, a LAG's members.
  Only the upper port names the lower one, so one source of truth and no back references to
  keep in sync. `None` / empty means "not reported": old snapshots and adapters that do not
  report it stay valid and behave as before.
- **Derived, not stored: `Port.external`.** `True` for jacks and LAGs (a cable ends there),
  `False` for every internal role, `None` when unknown (no role, or a `switch-port` the device
  says nothing more about). Rules and the topology use only this.
- **Radios stay `Radio` objects.** A radio is not a network interface on every platform
  (OpenWrt's `phy0`); the Wi-Fi interface is a port of role `wireless`, and `Wlan.port_id`
  names the interface an SSID runs on. The radio of an interface follows from its SSIDs
  (`Wlan.radio_id`).
- **Helpers on `Network`:** `ports_of`, `external_ports(device, unknown=True)`,
  `lower_ports`, `upper_ports`, and `port_tree(device)`: every port once, a port over exactly
  one other port as its child (DSA user port under its CPU port, VLAN interface under its
  parent), a port over several (bridge, LAG) as a root listing its `members`, Wi-Fi interfaces
  under the radio of their SSIDs. Unknown lower ids and cycles are ignored there; the contract
  tests (`signalbox.testing.structure_problems`) refuse them: lower ports must be reported and
  belong to the same device, no cycles, a `bridge`/`wireless`/`lag` role needs the same kind, a
  VLAN interface runs on one port, `Wlan.port_id` is a Wi-Fi port of the device.
- **Rules:** a port with `external is False` is never a cable end (link speed, duplex, MTU,
  auto-negotiation, native VLAN and tagged VLAN comparisons, `vlan.single-untagged`, half
  duplex, hidden devices and client VLAN mismatches behind it), and a bridge in a VLAN is not
  an access port for `vlan.path-to-gateway`.
- **UI:** the device page shows the tree (`GET /api/devices/{id}/port-tree`); the topology
  shows jacks and ports of unknown role, internal ports on request. A link reported on an
  internal port ends at the device box.
- **OpenWrt first** (rpcd only, no shell): netifd `network.device status` (bridges with
  `bridge-members`, VLAN devices), `luci-rpc getNetworkDevices` (kernel `devtype` `dsa` and
  `parent` = the conduit; one new method in the read ACL, no sysfs reads), UCI `switch_vlan`
  for the swconfig CPU port. Other integrations fill the fields in follow-ups (ADAPTERS.md).

## Consequences

- Devices that report roles get a cleaner topology and no false findings on CPU ports; all
  others look and are checked exactly as before.
- OpenWrt now reports VLAN devices (`br-lan.10`, `eth0.2`) as ports; an uplink on a VLAN
  device names its port.
- swconfig switch ports are not reported: which switch port is the CPU port, and which are
  jacks, OpenWrt only says in `/etc/board.json`, which the ACL does not allow. DSA itself is
  verified only in the simulator (from the rpcd-mod-luci and kernel sources); a real DSA
  device should confirm it (#21).
