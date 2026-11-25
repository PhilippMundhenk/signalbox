<!-- rules of src/signalbox/rules/segment_views.py; part of the rules documentation (docs/RULES.md lists all) -->

# Per-device views of networks and clients

The merge joins what several devices report into one network or client and keeps each device's
own view (#165): `Segment.views` (name, interface and role of every device for a network: gateway,
trunk, access, wireless) and `Client.sightings` (segment, port, addresses and time per device).
`Segment.name` is the display name: the name the gateway gives the network, else the first name
by device id. A name declared in the desired state is not written into it, so that drift can
still compare declared and reported names. It is `Segment.declared_name`, an overlay the
segments page and the findings show first (declared > gateway > first), marked "declared" in
the UI. `Segment.names_by_device` stays as before.

`SegmentView.interface` comes from what the adapter reported: the one VLAN interface among the
network's member ports (`br-lan.20`), else the one bridge, else the one VLAN interface of the
device named after the VLAN (`vlan20`, `eth0.20`). Several candidates at one level: not known.

## `clients.segment-disagreement`

- **Severity:** warning
- **Checks:** a client that the router places in one network and a switch or access point in
  another (a wrong untagged VLAN on the port, a bridge between VLANs, a device that tags its own
  frames). One finding per router and device pair.
- **Quiet:** sightings without a network, two devices that agree, two non-router devices, and
  devices that were not fully read this round.
- **Fix:** check the untagged VLAN of the port (or the SSID's VLAN) and whether a device bridges
  the two networks.

## `segment.name-missing`

- **Severity:** info
- **Checks:** a VLAN that no device gives a name. Names derived from the id count as names.
- **Quiet:** the untagged network, and any VLAN that at least one device names.
- **Fix:** give the network a name on the router, for example its purpose.
