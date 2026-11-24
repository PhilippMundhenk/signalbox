<!-- rules of src/signalbox/rules/ports.py; part of the rules documentation (docs/RULES.md lists all) -->

# Ports

These rules use the port configuration details a device reports with its interfaces: PVID,
admin state, MTU or jumbo frames, auto-negotiation, energy-efficient Ethernet and the port
description. A port that does not report a detail is skipped for the rules that need it. Port
names in findings include the port description ("port 5 (office desk)").
Internal ports (CPU port, bridge, VLAN interface; #252) are skipped: no cable or device is
plugged in there.

## `vlan.single-untagged`

- **Severity:** error
- **Checks:** a wired port is untagged member of at most one network (VLAN). Where the switch
  reports a PVID (the VLAN for incoming untagged frames, a separate setting on NETGEAR Plus and
  TP-Link Easy Smart switches), it is the port's untagged VLAN.
- **Stays quiet** for the PVID when the port has no untagged VLAN (a tagged-only trunk), when
  the port accepts tagged frames only, and when the PVID is not reported.
- **Fix:** keep one untagged VLAN on the port and set the PVID to it; make the other VLANs
  tagged.

## `vlan.client-port-mismatch`

- **Severity:** warning
- **Checks:** a client seen on a wired access port (no tagged VLANs, no known link, no other
  client on the port) uses addresses in the network of that port: the port's PVID where it is
  reported, otherwise its only untagged VLAN. The client's network is taken from the subnets
  its addresses lie in (link-local addresses are ignored). Where the switch reports a MAC
  address table, the VLAN it learned the client in is the port's network (also on a tagged
  port), and a port whose table shows other addresses too counts as having several clients.
- **Stays quiet** for trunk ports, uplinks, ports with several clients (see
  `topology.hidden-device`), clients whose addresses lie in no or several networks (see
  `addr.client-subnet`), and when the port's network has no known subnet.
- **Fix:** check the VLAN of the port and the network settings of the device: a fixed address,
  VLAN tagging on the device itself (a hypervisor or NAS), or a switch in between.

## `link.mtu`

- **Severity:** warning
- **Checks:** both ends of a cable link have the same MTU. Where an end reports only a jumbo
  frames setting, both ends must agree on jumbo frames on or off.
- **Stays quiet** for wireless links and when an end reports neither MTU nor jumbo frames.
  VLAN interfaces and bridges are not compared with their parent port (the model does not link
  them yet).
- **Fix:** use the same MTU on both ends: 1500, unless every device on the path supports jumbo
  frames.

## `port.admin-down-with-neighbour`

- **Severity:** warning
- **Checks:** a port that is disabled in its configuration, but has a cable link or an LLDP
  neighbour (a device connected to it).
- **Fix:** enable the port, or move the cable to an enabled port; remove a link entered by hand
  if the cable is gone.

## `port.eee-on-uplink`

- **Severity:** info
- **Checks:** energy-efficient Ethernet (EEE, 802.3az, "green Ethernet") is on at an end of a
  cable between two network devices (router, switch, access point). EEE on such links saves
  little and is a known cause of link drops and latency.
- **Fix:** turn off EEE on the ports named in the finding.

## `port.autoneg-mismatch`

- **Severity:** warning
- **Checks:** both ends of a cable link use auto-negotiation, or both have a fixed speed. A
  fixed speed on one end makes the auto-negotiating end fall back to half duplex.
- **Fix:** set both ports to auto-negotiation (or the same fixed speed and duplex on both, only
  if a device requires it).

## `port.description-mismatch`

- **Severity:** info
- **Checks:** a port description that names a device Signalbox knows (its name as whole words,
  at least 4 letters) names the device connected to the port by a cable link or LLDP.
- **Stays quiet** for ports without a description or without a known link to a known device,
  and when the description also names the connected device (or its LLDP system name).
- **Fix:** update the port description, or check whether the cable is in the right port.
