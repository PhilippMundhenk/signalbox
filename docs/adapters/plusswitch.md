# NETGEAR ProSAFE Plus and TP-Link Easy Smart switches

Small managed switches that have no API of their own, only the UDP protocol of the vendor's
configuration utility: NETGEAR's *ProSAFE Plus Utility* (NSDP: GS105E, GS108E, GS116E, JGS516PE
and similar) and TP-Link's *Easy Smart Configuration Utility* (TL-SG105E, TL-SG108E, TL-SG108PE,
TL-SG116E and similar). Signalbox speaks both through
[Switchyard](https://github.com/PhilippMundhenk/switchyard), which implements the protocols
and their simulators ([ADR 0003](../adr/0003-switchyard-library.md)). Read only; nothing on the
switch is changed.

| | NETGEAR | TP-Link |
| --- | --- | --- |
| Adapter id | `prosafe` | `easysmart` |
| Roles | `switch` | `switch` |
| Capabilities | interfaces | interfaces |
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
| `password` | both | | the switch's password; stored encrypted, never sent back to the UI |

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
- **Why a password at all?** Reading needs none on these protocols. Signalbox sends it once per
  observation, in a write that changes nothing (as the vendor tools do), so that a wrong
  password shows up as *authentication failed* now and not when changes arrive (phase 3).
- **Lock-out.** NETGEAR switches lock the Plus Utility access for 30 minutes after three wrong
  passwords. When a switch refuses a password, Signalbox does not send that password again for
  30 minutes; entering a different password in the device settings tries it at once.

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
identity; Easy Smart discovery request), checks the password, then reads identity, port status,
VLAN tables and link aggregation, and closes the socket. Every read goes through Switchyard's
driver, which copes with the firmware differences (unsupported settings, silent firmware,
both Easy Smart protocol generations).

| Model | From |
| --- | --- |
| Device vendor, model, firmware | identity |
| Device management address | the configured address |
| Device `vendor_extra` | MAC, name, IP, netmask, gateway, DHCP, serial, hardware version, port count, password scheme (NSDP), protocol generation (Easy Smart) |
| Ports `1`…`n` | link up/down, speed and duplex; LAG membership as `lagN`; `vendor_extra`: link text, VLAN mode, PVID, port groups, administratively enabled (Easy Smart) |
| Segments | VLANs, see below |

Not read: neighbours (these switches do not speak LLDP), clients (they do not expose a MAC
address table), QoS, mirroring, IGMP, statistics.

### VLANs

| VLAN mode on the switch | Segments |
| --- | --- |
| 802.1Q (basic or advanced) | one segment per VLAN; tagged members tagged, the other members untagged. VLAN 1 is the default VLAN and becomes the site's native segment, like the untagged LAN of the router. The PVID (the VLAN for untagged incoming frames) is in the port's `vendor_extra.pvid`; the model has no field for it. |
| none | every port an untagged member of the native segment |
| port-based (basic or advanced) | every port an untagged member of the native segment, with the groups of each port in `vendor_extra.port_groups` |

Port-based VLANs never put a tag on a frame. They only decide which ports may forward to which
inside the switch, so on every cable the traffic is the untagged, native network. Making each
group a segment of its own would make the other end of every cable look like it carries a
different untagged network (`vlan.native-mismatch`) even in the usual setup where the uplink is
in every group. Checks that understand the groups can be added later on `vendor_extra`.

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
answering for one address, a busy client port and two switches read at once. Without the extra
these tests are skipped; CI sets `SIGNALBOX_REQUIRE_SWITCHES=1`, so they can never be skipped
there.
