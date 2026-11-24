# NETGEAR ProSAFE Plus and TP-Link Easy Smart switches

Small managed switches that have no API of their own, only the UDP protocol of the vendor's
configuration utility: NETGEAR's *ProSAFE Plus Utility* (NSDP: GS105E, GS108E, GS116E, JGS516PE
and similar) and TP-Link's *Easy Smart Configuration Utility* (TL-SG105E, TL-SG108E, TL-SG108PE,
TL-SG116E and similar). Signalbox speaks both through
[Switchyard](https://github.com/PhilippMundhenk/switchyard), which implements the protocols
and their simulators ([ADR 0003](../adr/0003-switchyard-library.md)). They read the switch and,
in 802.1Q mode, can change which VLANs a port carries ([Changing ports](#changing-ports)).

| | NETGEAR | TP-Link |
| --- | --- | --- |
| Adapter id | `prosafe` | `easysmart` |
| Roles | `switch` | `switch` |
| Capabilities | interfaces | interfaces |
| Writes | port | port |
| Protocol | NSDP, UDP 63321 (Signalbox) ↔ 63322 (switch) | UDP 29809 (Signalbox) ↔ 29808 (switch) |
| Simulator | `switchyard.sim` | `switchyard.easysmart.sim` |

> The protocols are documented by Switchyard (`docs/PROTOCOL.md`,
> `docs/PROTOCOL-EASYSMART.md` there) from vendor tools, captures and other open source
> implementations. Signalbox is tested against Switchyard's simulators only; reading real
> switches through Signalbox still needs to be confirmed (#21).

## Installation

The adapters need the optional extra `switches`:

```sh
pip install "signalbox-net[switches]"      # or, from a checkout: pip install -e ".[switches]"
```

The container image includes it. Without the extra Signalbox starts normally; a switch of
these kinds is then reported as *could not be read* with the install hint.

## Settings

| Key | Adapter | Default | Meaning |
| --- | --- | --- | --- |
| `address` | both | | IPv4 address of the switch (a unicast address, no host name) |
| `username` | `easysmart` | `admin` | the switch's user name |
| `password` | both | | the switch's password; stored encrypted, never sent back to the UI. NETGEAR (`prosafe`): optional, only needed to deploy changes; Easy Smart: required (its protocol needs a login to read) |

## Security: read this first

- **No TLS, no certificate.** These switches have no certificate, so there is nothing to pin;
  `DeviceHttp` and certificate pinning do not apply.
- **The password is obfuscated, not encrypted.** NSDP sends it in clear text (very old
  firmware), XOR-ed with a key that is the same on every switch, or as a short hash over a salt
  the switch hands out to anybody. Easy Smart scrambles the whole packet with an RC4 key that is
  the same on every switch; newer firmware uses a per-session key, exchanged with an unpadded
  RSA key that is built into every switch. Anyone who can capture the traffic can recover the
  password or replay it. The protocols also have no way for Signalbox to check that the answer really comes from
  the switch.
- **Signalbox must sit in the switch's network**, the network the switch is managed from, and
  that network should only reach trusted hosts. Do not read these switches across untrusted
  networks.
- **When the password is sent.** NETGEAR switches are read without logging in, as Switchyard
  and the vendor utility do; the password is only sent (checked with a write that changes
  nothing) when a change is deployed, starting with its backup. A wrong password therefore
  shows up when deploying, not while reading. (Checking it on every read was dropped: an old
  GS108E v1 refused that check while reading worked; Easy Smart switches still log in to read.)
- **Lock-out.** NETGEAR switches lock the Plus Utility access for 30 minutes after three wrong
  passwords. When a switch refuses a password, Signalbox does not send that password again for
  30 minutes; entering a different password in the device settings
  tries it at once.

## Network

- **TP-Link Easy Smart switches always answer by broadcast** to UDP 29809. Signalbox must be in
  the same layer-2 network and receive broadcasts: run the container with host networking
  (`network_mode: host`), or Signalbox directly on a host in that network.
- **NETGEAR switches** answer by unicast or by broadcast to UDP 63321, depending on the
  firmware. Host networking is the safe choice; with Docker's bridged network a switch that
  answers by unicast may work (not confirmed).
- Signalbox sends every request by unicast to the configured address (switches outside the
  local subnet, reached through a router, are possible for NSDP where the switch answers by
  unicast). It does not search the network; use Switchyard or the vendor utility to find
  switches and their addresses.
- The UDP client ports are fixed by the protocols. Signalbox reads switches of one kind one
  after the other, so that two sessions never share the port at the same time. It can run next
  to Switchyard on the same host (both open the ports with address reuse).

## What is read

One observation is one short session: Signalbox asks the address who it is (NSDP read of the
identity; Easy Smart discovery request), logs in only where the protocol needs it (Easy
Smart) or for a change, then reads identity, port status, VLAN tables, link aggregation and the
port settings (speed and flow control; a switch that does not answer them is read without), and
closes the socket. Every read goes through Switchyard's
driver, which copes with the firmware differences (unsupported settings, silent firmware,
both Easy Smart protocol generations).

| Model | From |
| --- | --- |
| Device vendor, model, firmware | identity |
| Device management address | the configured address |
| Device `vendor_extra` | MAC, name, IP, netmask, gateway, DHCP, serial, hardware version, port count, password scheme (NSDP), protocol generation (Easy Smart) |
| Ports `1`…`n` | link up/down, speed and duplex; LAG membership as `lagN`; PVID (802.1Q modes); from the port settings enabled (speed setting not `disabled`; Easy Smart also reports it with the status), auto-negotiation (speed setting `auto`, else a fixed speed), flow control (the setting; ProSAFE without port settings: the link's); `vendor_extra`: link text, VLAN mode, port groups |
| Segments | VLANs, see below |
| Loop protection (#155) | Switchyard's `read_features`: `loop_detection` (NETGEAR loop detection, TP-Link loop prevention) as one bridge `switch` of the whole switch with protocol `loop-detect` (on) or `none` (off); nothing when the switch does not answer. These switches have no spanning tree |

Not read: neighbours (these switches do not speak LLDP), clients (they do not expose a MAC
address table), QoS, mirroring, IGMP, statistics.

### Port structure (#252)

Every port is a `jack`. An enabled link aggregation group (ProSAFE `read_lag`, Easy Smart
`lags`) is also a port of role `lag` named `lagN` over its member ports, with `lag_mode`
`static`: these switches have no LACP (#157). Confirmed against the simulators only (no real
switch in CI).

### VLANs

| VLAN mode on the switch | Segments |
| --- | --- |
| 802.1Q (basic or advanced) | one segment per VLAN; tagged members tagged, the other members untagged. VLAN 1 is the default VLAN and becomes the site's native segment, like the untagged LAN of the router. The PVID (the VLAN for untagged incoming frames) is the port's `pvid`; it can differ from the VLAN the port sends untagged. |
| none | every port an untagged member of the native segment |
| port-based (basic or advanced) | every port an untagged member of the native segment, with the groups of each port in `vendor_extra.port_groups` |

Port-based VLANs never put a tag on a frame. They only decide which ports may forward to which
inside the switch, so on every cable the traffic is the untagged, native network. Making each
group a segment of its own would make the other end of every cable look like it carries a
different untagged network (`vlan.native-mismatch`) even in the usual setup where the uplink is
in every group. Checks that understand the groups can be added later on `vendor_extra`.

## Changing ports

With *Allow changes* on the switch and `deploy.enabled` ([CHANGES.md](../CHANGES.md)), the
desired state's `ports:` entries for the switch are deployed (kind `port`, nothing else):

```yaml
ports:
  - {device: office-switch, port: "3", untagged: 20, tagged: [10]}
  - {device: office-switch, port: "8", untagged: native}
```

| A port change says | The switch gets |
| --- | --- |
| `untagged: 20` | port 3 an untagged member of VLAN 20, and its PVID 20 (untagged frames that arrive go to VLAN 20) |
| `untagged: native` | the same for VLAN 1, the default VLAN |
| `tagged: [10]` | port 3 a tagged member of VLAN 10 |
| no `untagged` | the port only tagged; its PVID stays if the port is still a member of that VLAN, else it moves to the first tagged VLAN (the switch needs a PVID the port is a member of) |

- The port leaves every other VLAN. VLANs that do not exist yet are created; VLANs other than 1
  that the change leaves without a member are deleted (VLANs that were empty before stay).
- One session per deployment step: Signalbox reads the 802.1Q table and the PVIDs, computes the
  new table and hands it to Switchyard's `apply_dot1q`, which writes it in an order the switch
  accepts (add members, move PVIDs, remove members, delete VLANs) and saves it (Easy Smart).
- **802.1Q mode only.** A switch in port-based VLAN mode, or with VLANs switched off, is refused
  with "the switch is in port_basic mode ...; Signalbox changes VLANs only in 802.1Q mode" and
  nothing is changed. Signalbox never switches the VLAN mode: that resets the whole table.
- Refused before anything is sent: VLAN 1 tagged, a VLAN both untagged and tagged, a port in no
  VLAN at all, a port the switch does not have, more VLANs than the switch holds (Switchyard's
  checks: "VLAN table refused: ...").
- **Backup** (`switchyard-dot1q-json`): the 802.1Q table (VLAN id, members, tagged members,
  name) and every port's PVID. **Restore** writes that table back the same way. No secrets in
  it.
- No confirm timer: the switches cannot roll back by themselves. A change is verified by
  reading the switch again; when it does not read back as planned, the backup is restored.
- Not changed: VLAN names, the VLAN mode, link aggregation, anything outside VLANs.

## Errors

| Situation | Status |
| --- | --- |
| no answer within the timeout, only answers that are not of this protocol | unreachable |
| several Easy Smart switches answer for the address | unreachable, with the number |
| password (or Easy Smart user name) refused, switch locked | authentication failed |
| the UDP client port cannot be opened | unreachable, naming the port |
| identity read, but ports or VLANs not (error, garbled answer) | partial, *interfaces could not be read* |
| Switchyard not installed | unreachable, with the install hint |

Each UDP request waits up to 1.5 s (less with a short `observe.timeout_seconds`) and is
repeated twice. Old firmware that stays silent for settings it does not know makes the first
read slower; raise `observe.timeout_seconds` if a switch is reported unreachable although it
answers Switchyard.

## Tests

`tests/test_plusswitch.py` runs both adapters against Switchyard's simulators on local UDP
ports: the contract checks for several models (password schemes, unsupported settings, both
Easy Smart generations), 802.1Q and port-based VLANs, link aggregation, wrong password and
user, no answer, datagrams that are not switch replies, garbled setting values, two switches
answering for one address, a busy client port and two switches read at once.
`tests/test_plusswitch_write.py` changes ports on both simulators and reads them back (and the
inverse), backs up and restores the VLAN table, refuses port-based and switched-off VLAN modes,
a write the switch refuses and a password the switch refused (not resent), and deploys a desired
state through the deployment component and reverts it. Without the extra
these tests are skipped; CI sets `REQUIRE_SWITCH_TESTS=1`, so they can never be skipped
there.


## Management services (#173)

Fixed by the product line, nothing is read from the switch: a `vendor` service (`nsdp`, UDP
63322, for NETGEAR ProSAFE Plus; `easy-smart`, UDP 29808, for TP-Link Easy Smart) and the web
interface `http` on port 80 (most models have no HTTPS *(guess per model)*), both always on,
unencrypted and listening everywhere. `transport_encrypted` is false: both protocols send the
password only obfuscated.

## MAC address table (#160)

Not read: NSDP (NETGEAR) and the Easy Smart protocol (TP-Link) have no MAC address table on
the supported models, and Switchyard reads none. Links to these switches come from their port
MACs in the tables of the devices around them.

## Factory password (#126, #175)

Both switch families have one management login. When a password is configured, Signalbox
compares it in memory with the factory default (ProSAFE Plus `password`, Easy Smart
`admin`/`admin`) and reports `default_credentials`; it never tries another password (the
switches lock after a few wrong ones). The login can change everything (`admin`, also the least
these integrations need). Easy Smart's user becomes the device's one account. A NETGEAR switch
read without a password reports nothing.
