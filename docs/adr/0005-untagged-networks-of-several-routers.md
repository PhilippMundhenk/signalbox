# 0005. Untagged networks of several routers

Date: 2026-11-22 · Status: accepted

## Context

Every integration reports a device's plain LAN as the native segment `<site>/segment/native`, so
that the same untagged network seen on a router, its switches and access points is one segment.
A site with two routers in a row, an ISP router and a firewall behind it (#205), got one segment
holding both LANs: `addr.one-gateway` and `dhcp.one-server` reported two routers and two DHCP
servers on one network, and the cable from the ISP router to the firewall's WAN port was a native
VLAN mismatch. The two LANs are different layer-2 networks; only the devices cannot say so,
because each only knows its own LAN.

## Decision

The merge decides which native networks are one network (`signalbox.merge._native_split`):

- every router (a gateway subnet on the native segment) has a network; routers with overlapping
  subnets share it;
- switches and access points join the network whose subnet holds their management address,
  clients the one that holds their address;
- a link between two ports that both send the native network untagged joins the networks of its
  ends (a switch or access point that carries both makes them one layer-2 network).

At a site with one network after this, nothing changes. With several, the main one keeps
`<site>/segment/native`: the one that is not in front of another router (no other router's uplink
address in it), then the one most switches and access points are managed in, then the lowest
router id. Every further one is `<site>/segment/native-<router id>` (lowest router id of that
network, characters other than letters, digits, `.`, `_`, `-` replaced by `-`;
`model.native_segment_id()`), with `vlan` None and its router's name added to its name
(`lan (Fritz!Box)`). `model.is_native_segment()` recognises both forms and
`Network.native_segment(device)` gives a device's own untagged network.

In the desired state, `native` keeps meaning "untagged": for a port or an SSID it is the
device's own untagged network; as a segment entry it is the main one. The LANs of further routers
are not declared (an import leaves them out) and cannot be planned as segments.

## Consequences

- Single-router sites, their ids, findings, desired state and plans are unchanged.
- A site behind another router gets a stable id for the outer LAN as long as the router's id
  stays the same. Which LAN is the main one can change when the inventory changes (an access
  point added in the other LAN, uplinks reported for the first time); history and declared
  purposes then follow the new id.
- Rules need no change for the split itself. Link rules learn that a router's uplink port carries
  the upstream router's network untagged.
- Declaring the outer router's LAN (purpose, DHCP) needs a way to name it in the desired state,
  for example `native: <router device>`; not built.
