<!-- rules of src/signalbox/rules/mesh_checks.py; part of the rules documentation (docs/RULES.md lists all) -->

# Wi-Fi mesh and wireless backhaul

Checks on the wireless links that join mesh nodes and repeaters (#171). A backhaul link is read
from the device that knows it: the FRITZ!Box mesh list (`X_AVM-DE_GetMeshListPath`, repeaters
appear as devices the box manages; a repeater that is also a device of its own is merged with its
mesh node by MAC address, #459), the Omada controller and UniFi (wireless uplink of an access point),
OpenWrt (802.11s mesh points, `sta` interfaces with or without WDS, `iwinfo assoclist`) and
MikroTik (`station-bridge`, `station-pseudobridge` and `station-wds` interfaces with their
registration table). The topology draws these links as wireless links with band, signal and rate,
and colours a weak one (the limits of `mesh.weak-backhaul`).
Readings a device did not report are never judged, and a reading is one moment, not a trend.
Signalbox only observes the mesh: its settings belong to the vendor's controller.

The thresholds can be changed per site, device or network (see
[Parameters](../RULES.md#parameters)). SSIDs that are only used between mesh nodes (an 802.11s
mesh id) are marked as backhaul and left out of the SSID checks (count, coverage, consistency,
roaming).

## `mesh.weak-backhaul`

- **Severity:** warning
- **Checks:** the backhaul link of a mesh node has a signal below -75 dBm or a rate below
  100 Mbit/s (the lower of both directions). Everything behind the node shares this link.
- **Fix:** move the node closer to the one in front of it, or connect it with a cable.

## `mesh.backhaul-2-4`

- **Severity:** warning
- **Checks:** a backhaul link runs on 2.4 GHz although both nodes have an enabled 5 GHz or
  6 GHz radio (radios are read from OpenWrt, MikroTik and Omada devices; a FRITZ!Repeater is
  not read, so the check stays quiet for links to it).
- **Fix:** let the node use the 5 GHz band for its uplink.

## `mesh.chain-too-long`

- **Severity:** warning
- **Checks:** a node is more than two wireless hops from the wired network (the hop count the
  device reports, else counted along the backhaul links). Each hop shares the air with the one
  before it. Equal peers of an 802.11s mesh have no direction, so only a reported hop count
  counts for them.
- **Fix:** connect a node of the chain with a cable.

## `mesh.wired-possible`

- **Severity:** info
- **Checks:** a node with a wireless uplink also has a cable to another device (found by
  LLDP, MAC tables or entered by hand). The cable could carry the backhaul.
- **Fix:** use the cable as the uplink (Ethernet backhaul), or remove it if it is not meant to
  be used.

## `mesh.channel-locked`

- **Severity:** info
- **Checks:** a mesh of at least three nodes whose backhaul links all report the same band and
  channel. Mesh systems work this way; the finding explains why the nodes cannot each pick the
  quietest channel.
- **Fix:** nothing to fix. A cable backhaul takes nodes off the shared channel.
