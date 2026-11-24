# 0016. MAC address tables: raw entries per device, one core module derives placement and links

Date: 2026-11-23 · Status: accepted

## Context

Without LLDP (most small switches, the Fritz!Box, many access points) a switch's forwarding
database (FDB, MAC address table) is the only way to tell what sits behind a port: an
unmanaged switch, a second router, a hidden access point. Signalbox already used it, but
ad hoc: MikroTik turned `/interface/bridge/host` into `Client.seen_on`, Omada its client list's
switch port, and `topology.mac_links` linked a port to a device whose port MAC was the
`seen_on` of a client there. `merge` keeps one `seen_on` per client, so the per-switch view
was lost: which ports a MAC is learned on, on which VLAN, which ports are uplinks. #160 asked
for the raw table; #85, #112, #113 and new checks (MAC flapping, stale static entries) need it.

## Decision

- **Model.** `FdbEntry` (`<device>/fdb/<port name>/<vlan or ->/<mac>`): `device_id`,
  `port_id` (the physical port where the device says so), `mac`, `vlan`, `segment_id`,
  `kind` `dynamic | static | self`, `age_seconds`. A list on `Observation`, `Snapshot` and
  `Network` (`fdb`), with `Network.fdb_of(mac)` and `fdb_on(port)`. A controller reports the
  entries of the switches it manages under their ids. Raw, not aggregated: the checks need
  every port a MAC is on, per VLAN.
- **Bounded.** At most `FDB_LIMIT` (2048) entries per device; `observe()` keeps the device's
  own and static entries, then the most recently refreshed, and adds an optional read error
  (the device stays "ok"), so checks can treat the table as incomplete. The contract tests
  refuse more, duplicates, multicast addresses, ports of another device, unknown segments.
- **Read with `clients`**, or `interfaces` where an integration has no client read (Linux); no
  adapter API version, like uplinks and relays: an older adapter reports none.
- **Personal data like clients.** `GET /api/network` leaves `fdb` out (it can be large);
  `GET /api/fdb?device=…&mac=…` returns entries with the merged client of each MAC. Never in
  MQTT. Stored in the snapshots like every other observation.
- **One core module, `signalbox.fdb`,** replaces the ad-hoc logic:
  - *Sightings*: every dynamic or static entry on a port that is not internal
    (`Port.external` is not False, ADR 0008). A device that reports no table contributes its
    clients' `seen_on` ports, so integrations without a table (OPNsense ARP, Fritz!Box)
    count as before.
  - *Uplinks*: ports that learn another managed device's MAC (its ports' MACs and its own
    `self` entries), and cable link ends.
  - *Placement* (`merge` → `place_clients`): a wired client's `seen_on` becomes the sighting
    port that is not an uplink and learns the fewest addresses; with only uplinks the one with
    the fewest, unless a device without a table named a port. Wireless `seen_on` (an SSID or a
    Wi-Fi interface) is kept: the access point knows better.
  - *Links* (`topology.mac_links`, origin `mac`): a port that learns another managed device's
    MAC is linked to it unless a third managed device it also learns sits between them (the
    far device learns the third on the same port as this one, and the third learns them on
    different ports or has no table). Devices joined by an unmanaged switch are all linked to
    each other. The far end is the port where the far device learns this device's MACs, else
    the port owning the MAC. LLDP still wins per port.
- **Readers where cheap and confirmable**: MikroTik `/interface/bridge/host` (`local` → self,
  `dynamic`, else static; the VLAN where the bridge filters VLANs); Omada wired clients with
  `switchMac`/`port` (the controller's view of each switch's table); Linux `bridge -j -s fdb
  show` as the read user (netlink, no root; entries with a `master`, age from `updated`),
  confirmed in CI with a static entry on the integration target.
- **Not read**, documented per integration: OpenWrt (read since #378, ADR 0026; no rpcd method exposes the bridge FDB;
  `/sys/class/net/<bridge>/brforward` is binary, has no VLAN and its port numbers need more
  sysfs reads and a wider ACL; the read ACL stays as it is), OPNsense (no API for
  `ifconfig bridge addr`), ProSAFE / Easy Smart (NSDP and the Easy Smart protocol have no MAC
  table on the supported models; Switchyard reads none), Fritz!Box (host list without ports).

## Consequences

- Links through unmanaged switches and the access port of a client behind two switches come
  from one place; MikroTik and Omada keep reporting `seen_on`, core may refine it.
- Topology results change only where a device reports a table: a chain of read switches no
  longer links the gateway to every switch behind the first.
- The checks of #85, #112, #113 and the new MAC checks can work on exact per-port, per-VLAN
  entries; they are follow-ups.
- Snapshots grow by up to 2048 entries per device; the network API does not.
