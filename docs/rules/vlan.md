<!-- rules of src/signalbox/rules/vlan.py; part of the rules documentation (docs/RULES.md lists all) -->

# VLANs and links

These rules use the known links (discovered by LLDP or entered by hand) and the VLAN memberships
of the ports at both ends. A device that reports no VLAN memberships at all (an unmanaged switch,
or one that could not be read) is treated as unknown: checks through it are reported as
incomplete, never as errors. The same goes for a device that was not fully read this round
(unreachable, or reading its interfaces failed), and for a disagreement on a link that is only
inferred from a MAC table: such a link may run through switches Signalbox does not read.

A router's uplink (WAN) port is in no network of its own router; it carries the network of the
router in front of it untagged (the router whose subnet holds the uplink address). Where an
integration does not report uplinks, a router port in no network that is cabled to another
router is taken for its uplink and not compared.

Internal ports (#252) are never the end of a cable: a link that ends on a CPU port, a bridge or
a VLAN interface is not compared, and a bridge in a VLAN is not an access port that needs the
VLAN on the uplink. Ports whose role the device does not report are compared as before.

## `vlan.path-to-gateway`

- **Severity:** error
- **Checks:** every network (VLAN) that an access point offers on an enabled SSID, or that an
  access point or switch puts untagged on an access port, is carried (tagged, or untagged as the
  native VLAN) on both ends of every link along the shortest known path from that device to the
  router that has a subnet for the network. One finding per missing link, listing the devices
  whose clients need it.
- **Incomplete:** a device that is not connected to the router in the known topology (once per
  device), a link end whose device does not report VLAN memberships or was not fully read, or a
  missing VLAN on a link that is only inferred from a MAC table.
- **Fix:** add the VLAN as tagged VLAN to the ports named in the finding. For an incomplete
  finding, add the missing link by hand or enable LLDP on the devices in between.

## `vlan.native-mismatch`

- **Severity:** error
- **Checks:** both ends of a link send the same network untagged (or both send nothing untagged).
  A router's uplink port counts as sending the network of the router in front of it.
- **Incomplete:** the ends disagree on a link that is only inferred from a MAC table. Silent when
  an end was not fully read or is an uplink to a router Signalbox does not know.
- **Fix:** set the same untagged (native) VLAN on both ports, or none on both.

## `vlan.tagged-both-ends`

- **Severity:** warning (a VLAN the far end actually needs is an error of `vlan.path-to-gateway`)
- **Checks:** a VLAN tagged on one end of a link is configured on the other end as well. Uplink
  cables between routers are skipped.
- **Incomplete:** on a link that is only inferred from a MAC table.
- **Fix:** add the VLAN as tagged VLAN to the other port, or remove it from the first one.

## `vlan.unused`

- **Severity:** info
- **Checks:** a network that has a subnet on the router but no member port on any other device
  and no SSID that uses it. Often left over from an earlier setup.
- **Fix:** remove the VLAN and its subnet if it is no longer needed, or add it to the ports and
  SSIDs that should use it.

## `link.speed-duplex`

- **Severity:** warning
- **Checks:** the two ends of a cable link report a different speed or duplex mode (only where
  both ends report it and neither port is down; wireless links are skipped). Speed and duplex are
  separate findings.
- **Fix:** set both ports to auto-negotiation (or the same fixed speed and duplex); if the
  mismatch stays, replace the cable.

## `vlan.trunk-scope`

- **Severity:** info
- **Checks:** a cable from a switch or router to an access point carries tagged only the networks
  the access point uses: those of its enabled SSIDs, of its own access ports, of its own
  addresses (subnets it reports) and of its management address. One finding per link lists the
  extra VLANs. Every extra VLAN can be reached by anyone who unplugs the access point.
- **Stays quiet** for links to switches, for access points with further links (they forward to
  other devices), for access points whose Wi-Fi could not be read or that have an SSID without a
  known network, for access points reported by a controller (it may move SSIDs between them), and
  when the network the access point is managed in is not known.
- **Fix:** remove the VLANs named in the finding from the switch port.

## `link.slow`

- **Severity:** warning; info for a single port at 10 Mbit/s
- **Checks:** a cable between two network devices (router, switch, access point) runs below
  1 Gbit/s or in half duplex. Unlike `link.speed-duplex` this checks the value itself, so it also
  works when only one end reports it. A port of a network device that is up in half duplex is
  reported even without a known link; one that is up at 10 Mbit/s is reported as info. Ports that
  are down, wireless, aggregates or virtual are skipped. Where the ports report their maximum
  speed, a link that runs as fast as the slower port can go (a 100 Mbit/s-only device) is not
  reported, and a link slower than both ports support (1 Gbit/s on two 2.5 Gbit/s ports) is
  reported as info.
- **Fix:** replace the cable (a damaged cable often uses only two pairs, which limits it to
  100 Mbit/s) and check that both ports are set to auto-negotiation. For a link below the
  ports' maximum, use a cable rated for that speed (Cat 5e or better for 2.5 Gbit/s, Cat 6a for
  10 Gbit/s). If a device only has 100 Mbit/s ports and does not report it, turn the rule off or
  accept the finding.

## `vlan.name-consistent`

- **Severity:** info
- **Checks:** a VLAN (not the untagged network) that devices name differently, for example `IoT`
  on the router and `Guest` on the switch. The merge keeps the name each device reports
  (`Segment.names_by_device`, #165). One finding per VLAN, listing the names and devices and
  suggesting the name most devices use (on a tie the first by device id). The segments page
  shows the names per device.
- **Quiet:** differences in case or white space, devices without a name, and names derived from
  the id (`vlan20`, `VLAN 20`, `ether1.20`, `br-lan.20`). Only VLAN ids are compared; one name
  used for two different ids is not checked.
- **Fix:** check that the devices mean the same network (a wrong VLAN id on one device is the
  usual cause), then use one name.
