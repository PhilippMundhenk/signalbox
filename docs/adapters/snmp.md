# SNMP switch adapter (generic, read only)

Reads any managed switch that offers the standard SNMP MIBs, whatever the vendor: ports and
their state, VLANs with tagged and untagged members and PVIDs, the MAC address table per VLAN,
spanning tree, LLDP neighbours and link aggregation ([#400](https://github.com/PhilippMundhenk/signalbox/issues/400)).
It is one adapter for Cisco, HPE/Aruba, Juniper, Zyxel, D-Link, TP-Link JetStream, NETGEAR
Smart/Managed, MikroTik and many more. **Read only**: Signalbox sends SNMP `GET`, `GETNEXT` and
`GETBULK` and never `SET`; there is no change deployment for this adapter, and a vendor adapter
(where there is one) stays the better choice when you want Signalbox to change the switch.

| | |
| --- | --- |
| Adapter id | `snmp` |
| Roles | `switch` |
| Capabilities | interfaces, neighbours, health |
| Writes | none |
| SNMP versions | v2c (read-only community), v3 authPriv (SHA or SHA-256 with AES-128) |
| Library | [pysnmp](https://github.com/lextudio/pysnmp) 7 (optional extra `signalbox-net[snmp]`, in the container image) |
| Simulator | `signalbox.sim.snmp` (`.snmprec` recordings, [snmpsim](https://github.com/lextudio/snmpsim)) |

> **Based on the MIB definitions and a simulator, not on a real switch.** Parts marked *(guess)*
> are not certain. Please report your switch in
> [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).

## Setup

Enable SNMP on the switch with a **read-only** login, preferably SNMP v3. The exact menus differ
per vendor; this is what to look for.

### SNMP v3 (recommended)

1. Find *SNMP* in the switch's management settings (web interface or command line) and enable
   the SNMP agent. Leave SNMP v1 and v2c off if you use v3.
2. Create a **read-only** group (for example `readonly`, security level `authPriv`) with a
   *view* that includes the whole tree (`1.3.6.1`) or at least these standard subtrees:
   `1.3.6.1.2.1` (MIB-II: system, interfaces, bridge, Q-bridge, entity), `1.0.8802.1.1.2`
   (LLDP) and `1.2.840.10006.300.43` (link aggregation). Give it no write view.
3. Create a user in that group with **authentication SHA-256** (or SHA, if the switch offers
   nothing better) and **privacy AES-128** (sometimes called AES or AES128), and two different
   passwords of 8 or more characters. Many switches call these "authentication password" and
   "privacy password" or "encryption password".
4. If the switch has an SNMP access list or management ACL, allow the host Signalbox runs on
   (UDP port 161). Switch SNMP off for networks that do not need it.
5. Optional but useful for the neighbour list and the topology: enable LLDP on the ports, and
   spanning tree if you use it.
6. In Signalbox add a device of kind *SNMP switch*: the address, version `v3`, the user name,
   the algorithm and both passwords, then *Test connection*.

### SNMP v2c (only where v3 is not available)

1. Enable SNMP v2c and create a community with **read-only** access (a *view* as above).
   Never enter a read-write community: Signalbox does not need it, and anyone who learns it can
   change the switch.
2. Do not use the factory communities `public` and `private`: Signalbox reports a login that
   is a factory default (`security.default-password`).
3. Restrict the community to the host Signalbox runs on (SNMP access list or ACL of the
   switch).
4. In Signalbox add the device with version `v2c` and the community.

### Why v2c is weaker

SNMP v2c has no encryption and no real authentication: the community string is sent in clear
text with every request, so anyone who can see one packet of the management network (a mirror
port, a compromised host, a shared Wi-Fi) can read the switch and, if the community allows,
write it. The answers (MAC tables, VLANs, neighbours) cross the network readable too. Source
address lists do little against someone who can fake the address. SNMP v3 with `authPriv`
authenticates each request with a key derived from a password (so a stolen packet cannot be
replayed or altered) and encrypts it. Signalbox marks a v2c switch as *not encrypted*
(`transport_encrypted`), and the management-service checks treat SNMP as unencrypted unless the
agent is read with v3 and privacy.

## What is read

One observation is one session: a few scalar reads (`GET`), then walks (`GETBULK`) of the columns
needed. The reads are the same for every vendor; what a switch does not offer is left out and
reported as an optional gap (below), never invented.

| MIB (OID) | Used for |
| --- | --- |
| SNMPv2-MIB (`1.3.6.1.2.1.1`) | `sysDescr`, `sysName`, `sysObjectID` (vendor from the enterprise number), `sysUpTime` (capability *health*: uptime) |
| ENTITY-MIB (`entPhysicalTable`) | model, hardware, firmware and software revision, serial, manufacturer of the chassis (first chassis of a stack) |
| IF-MIB (`ifTable`, `ifXTable`) | ports: name (`ifName`, else `ifDescr`), alias as description, admin and oper state, speed (`ifHighSpeed`, else `ifSpeed`), MTU, MAC; only Ethernet types (6, 62, 69, 117) and aggregations (161) are ports, VLAN, loopback and CPU interfaces are not |
| EtherLike-MIB `dot3StatsDuplexStatus` | duplex |
| Q-BRIDGE-MIB (`dot1qVlanStaticTable`, else `dot1qVlanCurrentTable`, `dot1qPortVlanTable`) | one segment per VLAN with its tagged and untagged ports (egress and untagged port lists), PVID, acceptable frame types, ingress filtering |
| Q-BRIDGE-MIB `dot1qTpFdbTable`, else BRIDGE-MIB `dot1dTpFdbTable` | the MAC address table as forwarding database (`fdb`), per VLAN; learned, static and invalid entries; the switch's own addresses are not on a port and are left out |
| BRIDGE-MIB `dot1dBasePortIfIndex` | bridge port number to interface (the other tables use bridge ports) |
| BRIDGE-MIB `dot1dStp`, RSTP-MIB | spanning tree of the switch: protocol (STP, RSTP, MSTP), priority and bridge id, root bridge, root port and cost, topology changes; per port the state, path cost and operational edge flag |
| LLDP-MIB (`lldpRemTable`, `lldpLocPortTable`, `lldpRemManAddrTable`) | neighbours: chassis id (MAC for subtype MAC address), remote port id and description, system name and description, enabled system capabilities, management address |
| IEEE8023-LAG-MIB, IF-MIB `ifStackTable` | link aggregation: LACP aggregators with their members, active/passive, LACP rate, the partner's system id, key and port; aggregations that only the stack table shows (static LAGs) get no mode |

The MAC tables and the LLDP neighbours feed the topology inference
([#388](https://github.com/PhilippMundhenk/signalbox/issues/388)) exactly like those of the
other adapters; the adapter does nothing special for it.

### How things map

- **Ports.** Names are the interface names (`Gi1/0/1`, `1`, `ge-0/0/3`); two interfaces with the
  same name get `#<ifIndex>` appended. A port that is not present (`notPresent`) is left out.
  The alias (`ifAlias`) is the description (user text).
- **VLANs.** One segment per VLAN; VLAN 1 is the site's native segment. Egress ports that are
  not in the untagged set are tagged members. Switches that only have the *current* VLAN table
  (not the static one) are read too.
- **LAG.** A port of role `lag` per aggregation over its member ports; members carry `lag`
  and, with LACP, the member state.
- **MAC table.** An entry is `dynamic` (learned), `static` (management) or `self`; the
  forwarding database id of Q-BRIDGE is taken as the VLAN id (independent VLAN learning). On
  switches with one shared table (SVL) where the id is no VLAN the entry has no VLAN.
- **Spanning tree.** The bridge is the whole switch (`switch`); MSTP switches report their
  common tree where the BRIDGE-MIB shows it.
- **Management service.** One SNMP service on the configured port, with the version Signalbox
  reads with (the switch may answer more versions; they are not probed).

### Gaps

A switch that does not offer a MIB (or hides it from the SNMP user's view) is not an error:
the rest is read and an **optional** gap says what is missing:

| Missing | Effect |
| --- | --- |
| Q-BRIDGE-MIB (VLANs) | no segments; ports, MAC table (BRIDGE-MIB), STP and LLDP are still read |
| MAC address table | no forwarding database; the topology uses the tables of the devices around |
| BRIDGE-MIB spanning tree | no STP checks for this switch |
| LLDP-MIB | no neighbours (enable LLDP on the switch, or add the LLDP subtree to the SNMP view) |
| ENTITY-MIB | no model, serial or firmware (`sysDescr` stays in the advanced tab) |

No standard MIB tells whether an update exists, whether the device installs updates by itself or
whether its configuration is saved (those are vendor MIBs), so SNMP devices report the firmware
revision and nothing more about updates (#181).

Errors that stop the read: no answer at all (wrong address, SNMP off, an access list, or a wrong
v2c community or v3 user, which an agent silently drops), a refused v3 login (wrong
authentication password or algorithm, unknown user, missing privacy), no `sysDescr`, or no
Ethernet interfaces.

## Versions and older switches

SNMP has no software version of its own to follow, but switches differ in what they implement;
the adapter covers these older or partial variants:

- SNMP v2c and v3 (`authPriv`); v1 is not used (counters and `GETBULK` need v2c).
- SHA-256 or SHA authentication (older switches stop at SHA; MD5 and DES are not offered).
- `ifXTable` missing (RFC 1213 switches): `ifDescr` and `ifSpeed` are used (speeds of 4.29
  Gbit/s and more are not shown then).
- Q-BRIDGE-MIB with only the *current* VLAN table, or only BRIDGE-MIB's MAC table (no VLAN
  ids); BRIDGE-MIB's spanning tree without RSTP-MIB (reported as STP).
- Aggregations without IEEE8023-LAG-MIB (found through `ifStackTable`, mode unknown).
- No ENTITY-MIB, no LLDP-MIB: optional gaps, as above.

PoE (#159): POWER-ETHERNET-MIB (RFC 3621) is walked when the switch has it: `pethMainPsePower` and
`pethMainPseConsumptionPower` of group 1 as budget and used power, per port the admin state,
detection status, priority and class (`pethPsePortPowerClassifications`, 1..5 is class 0..4). The
MIB has no per-port power, so `power_w` stays empty on SNMP.

## Guesses (need a real switch, [#21](https://github.com/PhilippMundhenk/signalbox/issues/21))

- PoE: the port number of `pethPsePortTable` (`group.port`) is read as the bridge port or ifIndex
  of group 1; stacked groups above 1 are skipped *(guess: the MIB does not say how it maps)*.
- The IEEE8023-LAG-MIB port column numbers (`dot3adAggPortAttachedAggID` 13, actor admin and
  oper state 21 and 22, partner system 9, key 11 and port 17) are from the MIB definition
  *(guess)*; they are only used for the LACP details, the members come from the stack table
  too.
- Which interface a LLDP local port number stands for: Signalbox matches the local port id
  text or MAC against the interface names, then the number as `ifIndex`, then as bridge port
  *(guess: vendors differ)*.
- Per vendor: which VLAN table a stacked or virtualised (VSF, IRF) switch shows, and whether a
  vendor limits `GETBULK` or the number of values per request.
- SNMP v3 with a non-empty context name (the *Context name* setting, advanced) is for switches
  that need one; almost none do.

## Tests

`tests/test_snmp.py` replays `tests/fixtures/snmp/managed-switch.snmprec` (a made-up 8-port
managed switch with VLANs, a LACP aggregation, RSTP and LLDP neighbours; documentation addresses
and `02:` MACs) through the adapter without a network, checks the adapter contract and the stored
snapshot (`tests/fixtures/snmp/managed-switch.snapshot.json`, regenerated by
`python tools/regen_recordings.py`) and covers the missing-MIB variants. `tests/test_snmp_snmpsim.py`
serves the same recording with snmpsim and reads it over UDP with pysnmp, for v2c and v3
(SHA-256, AES-128), so the real client code is exercised. All community strings and passwords of
the tests are made up at runtime.

## Settings

| Setting | Meaning |
| --- | --- |
| `address` | the switch's address (IPv4, IPv6 or a name) |
| `port` | UDP port of the agent (161) |
| `version` | `v3` (default) or `v2c` |
| `community` | v2c only, secret: the read-only community |
| `username`, `auth_protocol` (`sha256`, `sha`), `auth_password`, `priv_password` | v3 only; both passwords are secrets, 8 or more characters; privacy is AES-128 |
| `context_name` | v3 only, advanced: the SNMP context (usually empty) |

Secrets are stored encrypted like those of the other adapters and never appear in a snapshot,
log or error.

## 802.1X per port (IEEE8021-PAE-MIB, #162)

- `dot1xAuthAuthControlledPortControl` (auto means 802.1X) and `...PortStatus` per ifIndex, when
  the switch exposes the MIB. Without it nothing is reported.
