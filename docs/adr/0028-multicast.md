# 0028: Multicast settings and reflectors on the device (#161)

## Context

IoT networks break casting, AirPlay and printing because multicast discovery does not cross
networks, IPTV needs an IGMP proxy, and IGMP snooping without a querier stops streams after
a few minutes. Devices report this in very different places: a MikroTik bridge property, a UCI
bridge option plus the kernel's sysfs, a plugin of OPNsense, a flag of a UniFi network.

## Decision

- **`Device.multicast: DeviceMulticast | None`**, filled like the accounts and the spanning tree
  (`Observation.multicast` per device id, read with `interfaces`). `None` is "not read".
- **`MulticastSettings`** per bridge, and per VLAN where the device reports it per VLAN
  (OpenWrt): name, `segment_id`, IGMP and MLD snooping, `querier` (this device is the querier),
  its version, `observed_querier` (the address a device reports it sees), fast leave and what
  happens to unknown multicast. Every field may be `None`.
- **`ServiceReflector`** per kind (mDNS, SSDP, IGMP proxy, UDP broadcast relay; at most one per
  kind and device): enabled, the networks it joins, the interfaces as the device names them, and
  for the IGMP proxy the upstream interface and network. An empty list of networks means Signalbox
  could not map the interfaces, and the rules treat that as unknown.
- The querier "observed on the segment" is a field of the settings, not of `Segment`: only the
  device that sees it knows it, and the rule needs the network it is seen on anyway.
- Only settings are read, never the names of the services that are reflected.
- Writes (a desired state for snooping and reflectors) are left for later.

## Consequences

- The checks (`multicast.*`) join the settings of all devices by network, so a router that is
  the querier satisfies the switches behind it only when both report their network.
- A bridge with VLAN filtering on MikroTik is reported with the network of its own interface and
  one entry per VLAN where it learned groups (#508).
- NETGEAR and TP-Link switches (snooping on or off, no querier) and SNMP (IGMP-STD-MIB: the
  querier an interface sees) are read as far as the protocols go (#508). The IGMP proxy page of
  OPNsense has no API and is not read.
