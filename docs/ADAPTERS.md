# Writing an adapter

An adapter teaches Signalbox one kind of device. It reads the device and returns objects of the
[network model](schema.json); everything else (rules, topology, UI, export) works on that model
and never sees vendor code.

## The parts

```python
from pydantic import SecretStr
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
)
from signalbox.model import DeviceRole


class MyConfig(AdapterConfig):  # rendered as the setup form in the UI
    host: str
    password: SecretStr  # SecretStr: stored encrypted, never sent back


class MyAdapter(Adapter):
    manifest = Manifest(
        id="mydevice",  # lower case, used in ids and the configuration
        name="My Device",
        version="0.1.0",
        api_version="1.0",  # adapter API this was written for
        vendor="Example",
        roles=frozenset({DeviceRole.AP}),
        capabilities=frozenset({Capability.INTERFACES, Capability.WIRELESS}),
        config=MyConfig,
    )

    async def read_system(self) -> SystemInfo: ...  # required
    async def read_interfaces(self) -> Observation: ...  # because INTERFACES is declared
    async def read_wireless(self) -> Observation: ...  # because WIRELESS is declared
```

- `read_system` is the only required method. It raises `Unreachable`, `AuthFailed` or
  `UntrustedCertificate` when the device cannot be read at all. Device details the model has
  no field for (MAC, serial, protocol version) go into `SystemInfo.vendor_extra`.
- Every declared capability must be implemented (`ReadsInterfaces`, `ReadsDhcp`, `ReadsDns`,
  `ReadsWireless`, `ReadsClients`, `ReadsNeighbours`, `ReadsHealth`, `ReadsTime`); a missing one
  is an error when the adapter is constructed, not a silent gap.
- A capability that fails at run time raises `AdapterError` with a message for the user. Signalbox
  turns it into a "could not read" finding and keeps the rest of the snapshot. Pass
  `fix="..."` with what the user can do about it, in plain words (where to click on the
  device, which package or permission is missing, the right address): the device form and the
  finding show it as "What to do". An error that names a call but not a remedy leaves the user
  stuck.
- Help the user before the first error: `Manifest.setup_steps` (what to prepare on the device,
  step by step), `Manifest.setup_commands` (commands to paste on the device, if any) and
  `Manifest.setup_url` (the full guide) are shown in the device form above the settings. Let
  the address field accept the bare host name (`signalbox.adapters.https.device_url` completes
  scheme, default port and path), and put options only meant for simulators into the closed
  "Advanced" part with `json_schema_extra={"advanced": True}`.
- Do not override `observe()`. It calls the capabilities with a timeout, stamps every object with
  its source and time, and builds the snapshot.

## Identifiers

Use the helpers in `signalbox.model`: `port_id(device, name)`, `object_id(device, kind, name)`
for everything that belongs to the device, and `segment_id(site, vlan)` for VLANs, so that the
same VLAN seen on several devices becomes one segment. `vlan=None` (a device without VLANs) and
VLAN 1 (the default VLAN) are both the native, untagged network of the site. Unknown vendor fields go into `vendor_extra`; rules never read it.

WPA passphrases are never stored: put `passphrase_fingerprint(ssid, passphrase)` into
`Wlan.passphrase_fingerprint`, so access points can be compared without revealing the key.

## HTTPS and certificate pinning

Devices nearly always present a self-signed certificate. Do not use `verify=False` and do not
write your own TLS code: use `signalbox.adapters.https.DeviceHttp`, which every built-in adapter
uses.

```python
from signalbox.adapters.https import DeviceHttp


class MyAdapter(Adapter):
    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        self.http = DeviceHttp(
            cfg.url,  # https://host[:port]; paths are passed per request
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            auth=(cfg.user, cfg.password.get_secret_value()),  # or headers=..., or in the body
            allow_insecure_http=cfg.allow_insecure_http,
        )

    async def read_system(self) -> SystemInfo:
        await self.http.reset()  # new observation: check the certificate again
        data = await self.http.get_json("/api/status")  # or post_json(path, body)
        ...

    async def close(self) -> None:
        await self.http.close()
```

- Before the first request it reads the device certificate with a handshake that sends nothing,
  and compares the SHA-256 fingerprint with the pinned one. Not pinned yet, or different: it
  raises `UntrustedCertificate`, the UI shows the fingerprint and the user confirms it. No
  credential leaves the machine for a certificate that is not pinned.
- The requests then use a TLS context whose only trust anchor is the pinned certificate (host
  name and dates are not checked), so a certificate swapped after the check fails the handshake.
- Not JSON (SOAP, XML, text)? `await self.http.request(method, path, accept={500}, ...)` returns
  the `httpx.Response` with the same error mapping; statuses in `accept` are returned instead of
  raised (SOAP faults come with HTTP 500). Authentication can be any `httpx.Auth`, for example
  `httpx.DigestAuth(user, password)` (the Fritz!Box adapter).
- Errors are already mapped: connection problems and timeouts raise `Unreachable`, HTTP 401/403
  `AuthFailed`, 404 `signalbox.adapters.https.NotFound`, other statuses and invalid JSON
  `AdapterError`. Each message names the path.
- Plain `http://` is refused unless the adapter passes `allow_insecure_http=True`. Expose it as
  a config field of exactly that name, `allow_insecure_http: bool = False`, and say in its
  description that credentials then travel in clear text; it is meant for simulators.

Devices without HTTPS (the UDP protocols of small switches, see
[adapters/plusswitch.md](adapters/plusswitch.md)) cannot use `DeviceHttp`; such an adapter says
in its documentation what protects the credentials, and maps timeouts to `Unreachable` and
refused logins to `AuthFailed` itself.

For tests, `signalbox.sim.server` serves a simulator app on a free local port:
`serve(app, tls=self_signed_certificate(tmp_path))` yields the base URL, the returned
`TlsFiles.fingerprint` is what to pin, and `free_port()` gives a port nothing listens on.

## Tests

Ship a simulator of the device API with neutral sample data (documentation addresses
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, MACs starting with `02:`), run the
real adapter against it, and pass the contract check:

```python
from signalbox.testing import assert_contract


async def test_contract(simulator):
    snapshot = await assert_contract(MyAdapter(context_for(simulator)))
```

Also test the refused paths: wrong credentials, changed certificate, timeouts, unexpected answers.

## Packaging

A separate package registers the adapter through an entry point:

```toml
[project.entry-points."signalbox.adapters"]
mydevice = "mypackage.adapter:MyAdapter"
```

Signalbox refuses to start with an adapter whose API major version differs from its own, or with
two adapters of the same id.

## Discovery

An integration can let *Find devices* ([DISCOVERY.md](DISCOVERY.md)) find its devices with two
optional class methods (no adapter API version needed; without them the integration simply
finds nothing):

```python
from signalbox.discovery import BroadcastResult, Candidate, HostProbe, NetworkProbe


class MyAdapter(Adapter):
    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """Is there a device of this kind at probe.host?"""
        port = probe.port("mydevice.https", 443)  # tests and simulators can move it
        answer = await probe.get("https", port, "/api/status")  # None: no answer
        data = answer.json() if answer is not None and answer.status == 200 else None
        if not isinstance(data, dict) or data.get("product") != "MyDevice":
            return None
        return Candidate(
            address=probe.host,
            role=DeviceRole.AP,
            config={"url": probe.origin("https", port)},  # prefilled, non-secret settings
            model=data.get("model"),
            firmware=data.get("version"),
            evidence=f"status page on https port {port}",
        )

    @classmethod
    async def discover_broadcast(cls, probe: NetworkProbe) -> BroadcastResult | None:
        """Once per run, for protocols that find devices by broadcast."""
        ...
```

- Send only requests that need no login, and only through `probe` (`get`, `post`,
  `request`): it adds no credentials, keeps no cookies, uses no proxy, does not verify TLS or
  pin anything, follows no redirects, reads at most 256 KiB, waits for the run's rate limiter
  and gives up an address that does not answer. A broadcast probe calls
  `await probe.limiter.acquire()` before each packet.
- Never raise for what a device answers; return None. An exception is caught, reported once as
  "the X probe failed" and the run goes on.
- The answer is untrusted: `Candidate` cleans and shortens `name`, `model`, `firmware`,
  `vendor`, `mac`, `evidence`, `note`; the engine keeps only `config` keys of the integration's
  settings that are not secrets, and a role the integration supports (a router for a known
  gateway address). Parse XML with `signalbox.adapters.fritzbox.soap.parse_xml` (no DTDs, no
  entities) or the like.
- Set `note` when the device needs something before it can be added ("switch on the API").
- Test the probe against the simulator: `HostProbe("127.0.0.1", timeout=2,
  limiter=RateLimiter(1000), extra={"ports": {"mydevice.https": port}})`, and check that it
  does not mistake the other simulators for its device (`tests/test_discovery.py`).

## Writing to devices

An integration that can change a device declares the kinds of change it supports in
`Manifest.writes` (`router`, `dhcp`, `reservation`, `port`, `wlan`; see `signalbox.changes`) and
implements `WritesConfig`:

| Method | Job |
| --- | --- |
| `plan_changes(changes, secrets)` | the vendor calls it would make, for the review; secrets as `***` |
| `backup()` | the full configuration as the device exports it, before anything is touched |
| `apply(changes, secrets, rollback_seconds)` | stage and apply; if the device can roll itself back unless confirmed, return the deadline |
| `confirm()` | keep the applied change (stop the device's rollback timer) |
| `restore(backup)` | put the backed-up configuration back |

Each change carries the value before and after, so an integration never has to guess what to
undo. The deployment component calls these in order (lock, backup, apply, verify, confirm or
restore) and records everything; integrations do not decide on their own to keep or undo a
change. Declaring `writes` without implementing `WritesConfig` is refused when the adapter is
constructed.

The deployment verifies by reading the device again: after `apply`, the read side must report
exactly each change's `new` value. A `None` in `pmf`, the roaming flags of a WLAN or the lease
time of a DHCP server means "not specified" and accepts what the device reports; a switched-off
DHCP server is not expected to report a pool. Raise `AdapterError` with a message for the user
for a change the device cannot take (`plan_changes` already raises it, so the change is refused
when it is recorded). The OpenWrt integration is the reference
([adapters/openwrt.md](adapters/openwrt.md#writing)).

## Controllers (adapter API 1.1)

An integration that observes a controller (for example Omada) reports the devices it manages in
`Observation.devices` (ids `<configured device>/<slug>`, role, vendor, model, firmware) and their
reachability in `Observation.device_status`. Objects of a managed device use its id as
`device_id` and as the prefix of their own ids. Site, adapter and `managed_by` are filled in by
Signalbox. See [ADR 0004](adr/0004-controllers-report-several-devices.md).

Changes of a managed device are sent to the controller's adapter (`Deployer.owner`): its
`WritesConfig` gets changes whose `device_id` is the managed device, and *Allow changes* is set
on the controller. Changing an object that several managed devices share (an SSID of a WLAN
group) reaches all of them; say so in the vendor call's description.

## Port details

`Port` has optional configuration details, read with the `interfaces` capability (no API
version needed; leave out what the device does not report, never guess):

| Field | Meaning |
| --- | --- |
| `description` | the user's port label (alias, comment); blank becomes `None` |
| `admin_up` | administratively enabled; a disabled port also reports `up=False` |
| `pvid`, `frame_types`, `ingress_filter` | VLAN of untagged ingress frames (1: native), accepted frames (`all`, `tagged-only`, `untagged-only`), filtering of non-member VLANs |
| `mtu`, `l2_mtu`, `jumbo` | layer-3 MTU, the device's own layer-2 MTU, or only a jumbo-frames flag |
| `max_speed_mbps`, `advertised_speeds_mbps`, `autoneg`, `media` | fastest supported speed, speeds offered in auto-negotiation, auto-negotiation on, `copper`/`sfp`/`sfp+`/`other` |
| `profile` | port profile name a controller applies |
| `flow_control`, `eee` | pause frames, energy-efficient Ethernet |

Keep reporting VLAN membership as the device forwards frames (`Segment.members`); the PVID does
not replace it. The contract checks report a speed above `max_speed_mbps` and link up on a
disabled port. What each integration fills (the adapter pages say from which answer; values
that moved here are no longer in `vendor_extra`):

| Integration | Fields | Where |
| --- | --- | --- |
| ProSAFE / Easy Smart | `pvid` (802.1Q modes), `admin_up`, `autoneg`, `flow_control` (port settings: `read_port_admin`, Easy Smart's enable flag) | `plusswitch/mapping.py`, `interfaces()` |
| MikroTik | `description` (`comment`), `admin_up`, `mtu`, `l2_mtu`; bridge ports of a VLAN-filtering bridge `pvid`, `frame_types`, `ingress_filter`; `/interface/ethernet` `advertised_speeds_mbps`, `autoneg`, `flow_control` | `mikrotik/__init__.py`, `_build_layout()` |
| OpenWrt | `mtu`, `max_speed_mbps` (`link-supported`), `advertised_speeds_mbps` (`link-advertising`), `autoneg`, `admin_up` (`device` section `enabled`, or the device up), `pvid` (`*` in `bridge-vlan`) | `openwrt/__init__.py`, `read_interfaces()` |
| OPNsense | `description`, `admin_up` (assigned interfaces), `mtu`, `max_speed_mbps` (`supported_media`), `media`, `autoneg` (`media_raw`) | `opnsense/__init__.py`, `_parse_layout()` |
| Omada | `profile`, `admin_up` (`disable`), `pvid` (VLAN of the native network), `max_speed_mbps` (`maxSpeed`), `jumbo` (switch setting) | `omada/__init__.py`, switch ports |
| Fritz!Box | `admin_up`, `max_speed_mbps` (`NewMaxBitRate`: TR-064's maximum, `Auto` is `autoneg`; no longer `speed_mbps`) | `fritzbox/__init__.py`, LAN port |

## Uplinks

A gateway reports each WAN connection as an `Uplink` in `Observation.uplinks`, read with the
`interfaces` capability (no API version needed; leave the list empty where the device cannot
tell, never guess). Id `object_id(device, "uplink", <name>)`, for example `gw/uplink/wan`.

| Field | Meaning |
| --- | --- |
| `kind` | `dhcp`, `static`, `pppoe`, `dslite`, `map-e`, `lte`, `bridge` (modem only, no address), `other` |
| `port_id`, `name` | the port it uses (must be one of the snapshot's ports), the device's name for the connection |
| `up`, `since` | connected (address bound, PPP session up), not only link; when the current connection came up (time zone aware) |
| `addresses`, `delegated_prefixes` | the device's own addresses on the uplink with prefix length, IPv4 and IPv6; IPv6 prefixes delegated by the provider |
| `upstream_gateway`, `dns_servers` | the next hop of the default route; the resolvers the provider handed out |
| `public_ipv4` | only an address the device knows apart from its own (a cloud lookup it does itself); its own WAN address goes into `addresses` |
| `downstream_kbps`, `upstream_kbps` | line rate where the modem knows it (DSL sync, LTE) |

Do not compute a NAT class: core derives it (`Uplink.nat_class()`). The contract checks report
an id outside `<device>/uplink/`, an unknown port, a naive `since`, `since` on a down uplink, a
`bridge` with addresses and a `public_ipv4` that is not public. What each integration fills
(details and the answers they come from on the integration's page under `docs/adapters/`;
values marked there as a guess still need a real device, #21):

| Integration | Kind, state, uptime | Addresses, prefix, gateway, DNS | Line rate, public IPv4 |
| --- | --- | --- | --- |
| OPNsense | `/api/interfaces/overview/interfaces_info`, row `identifier` `wan`: `link_type` (`dhcp`, `pppoe`, `static`), `status` and an address; no session uptime in the API | same row: `ipv4[]`/`ipv6[]`, `ifctl.prefix` (delegated prefix), `gateways[]` (else `ifctl.router`), `ifctl.nameserver` | none (`media` is the Ethernet rate only; no public address) |
| OpenWrt (role `gateway`) | `network.interface dump` entries `wan`/`wan6` (and other WAN protocols or a default route outside the site's networks): `proto`, `up`, `uptime` | `ipv4-address[]`, `ipv6-address[]`, `ipv6-prefix[]`, the default route's `nexthop`, `dns-server[]`; `device` gives the port | none |
| MikroTik | members of the interface list `WAN`: `/rest/ip/dhcp-client` (`status` bound), `/rest/interface/pppoe-client` with its `monitor` (`status`, `uptime`), interface type `lte` | dhcp-client `address`, `gateway`, `primary-dns`/`secondary-dns`; pppoe monitor `local-address`, `remote-address`; `/rest/ipv6/dhcp-client` `prefix`; `/ip/address` and `/ipv6/address` on the interface | `/rest/ip/cloud` `public-address` (only after the device's own cloud update) is `public_ipv4`; no line rate |
| Fritz!Box (role `gateway`) | TR-064 `WANPPPConnection:1` or `WANIPConnection:1` `GetInfo` (`NewEnable`, `NewConnectionStatus`, `NewUptime`, `NewConnectionType`); `WANCommonInterfaceConfig:1 GetCommonLinkProperties` `NewWANAccessType` for LTE | `NewExternalIPAddress` (own address, /32), `NewDNSServers`, `NewRemoteIPAddress` on PPP; IPv6 and DS-Lite only over IGD (`X_AVM_DE_GetIPv6Prefix`, `X_AVM_DE_GetDsliteStatus`, not read) | `GetCommonLinkProperties` `NewLayer1DownstreamMaxBitRate`/`NewLayer1UpstreamMaxBitRate` (bit/s, reported in kbit/s) |
| Omada | gateway `GET .../gateways/{mac}/wan-status`, one entry per port in WAN mode (`mode` 0): `port`/`name`, `proto` (Static IP, DHCP, PPPoE, DS-Lite, MAP-E), `status`, `internetState`; no uptime | `wanPortIpv4Config` `ip`/`netmask`, `gateway`, `priDns`/`sndDns`; `wanPortIpv6Config` `addr`, `gateway`, DNS; no delegated prefix | none (`speed` is the Ethernet rate) |
| ProSAFE / Easy Smart | switches: no uplinks | | |

The IGD services of the Fritz!Box (`/igdupnp/control/...`) spell AVM's actions with `_`, the
TR-064 ones with `-`. Recordings replace public and private WAN addresses with documentation
addresses, so a recorded uplink classifies as `public` whatever the line was.

## Management services

A device reports each way to manage it as a `ManagementService` in `Observation.services`
(#173), read with the `interfaces` capability (no API version needed). Report **every**
service the integration knows, disabled ones too (`enabled=False`): an empty list means "not
read". If the extra call fails or is not allowed (an older ACL), leave the list empty rather
than failing the whole `interfaces` read. Id `object_id(device, "service", <key>)` with the
device's own name or the kind as key (`gw/service/ssh`, `gw/service/www-ssl`), unique per device.

| Field | Meaning |
| --- | --- |
| `kind`, `name` | `ssh`, `telnet`, `http`, `https`, `api`, `api-ssl`, `snmp`, `ftp`, `tftp`, `winbox`, `mac-telnet`, `mac-winbox`, `romon`, `tr-064`, `upnp`, `vendor` (NSDP, Easy Smart UDP), `other`; the device's own word for it |
| `enabled`, `port` | on or off; the port it listens on (none for layer-2 services; `SERVICE_PORTS` has the usual ones) |
| `transport`, `encrypted` | leave them out unless the device says otherwise: they are filled from the kind (`SERVICE_TRANSPORT`, `SERVICE_ENCRYPTED`); set `encrypted` for TR-064 (49443 is TLS) and `other` |
| `listen`, `interfaces`, `segments` | restrictions the device applies: addresses (empty or `0.0.0.0`/`::`: all), ports it is bound to, networks it is offered in (map a logical interface such as OpenWrt `lan` or OPNsense `opt2` to its segment id) |
| `allowed_from` | the service's own source filter (MikroTik `address`), never firewall rules (#135) |
| `from_wan` | only where the device itself says whether the internet can reach it (Fritz!Box internet access); otherwise leave `None` and core derives it |
| `password_login`, `root_login`, `root_password_login` | SSH only: password logins at all, root at all, root with a password |
| `redirects_to_https` | HTTP only: plain HTTP just redirects |
| `snmp` | SNMP only: versions, a factory community (`public`/`private`) configured, v3 privacy required, write access. Never the community string itself |

`SystemInfo.transport_encrypted` says how the integration itself talks to the device: `False`
for NSDP, Easy Smart UDP and `allow_insecure_http`, `True` for HTTPS/TLS. Do not compute
reachability: core derives the reachable segments and internet exposure
(`Network.service_segments()`, `Network.service_from_wan()`). The contract checks report an id
outside `<device>/service/`, a service reported twice, an unknown port or segment, a layer-2
service with a port or address, a disabled service reachable from the internet, root login
options on a service other than SSH, `redirects_to_https` on one other than HTTP and SNMP
settings on one other than SNMP.

What each integration reads (all fill `Observation.services` and `SystemInfo.transport_encrypted`
since #173; details and the data shapes are in `docs/adapters/<id>.md`). **CI** marks what the
integration tests against the real software confirmed; **guess** what still needs a real device
(#21).

| Integration | Services read | Logins, redirect, SNMP | Internet exposure | Status |
| --- | --- | --- | --- | --- |
| OpenWrt | `uci get dropbear` (each section: `enable`, `Port`, `Interface` to `segments`, `DirectInterface` to `interfaces`) and `uci get uhttpd` (`main`: `listen_http`, `listen_https`). Needs `dropbear` and `uhttpd` in the ACL's `uci` list: a router with the old ACL answers "access denied" and its services stay unread, the rest of the read works. No telnet, no `snmpd` | `PasswordAuth`, `RootLogin`, `RootPasswordAuth` (default on); `redirect_https` | `from_wan` unknown (`rfc1918_filter` is not mapped; the firewall is #135) | **CI** (24.10 and 25.12): dropbear and uhttpd read through the documented ACL. *Guess:* `Interface` to segment on a router with VLANs, telnet in older releases |
| MikroTik | `/rest/ip/service` (`available-from` is `allowed_from`; dynamic rows and unknown names such as `reverse-proxy` are skipped), `/rest/tool/mac-server` and `/mac-winbox` (`allowed-interface-list`: `none` is off, `all` is every port, else the list's members), `/rest/tool/romon`, `/rest/ip/upnp`, `/rest/ip/ssh`, `/rest/snmp` with `/community` | `password-authentication` (`yes`, `no`, `yes-if-no-key` is unknown; `always-allow-password-login` before 7.25); community named `public`, `write-access`, `security` (`none` v1/v2c, `authorized`, `private` is authPriv); the community string is never kept | `from_wan` unknown (firewall: #135) | **CI** (CHR 7.25.1): every menu and field above, read as the read-only user. *Guess:* the member-list mapping of a non-default MAC server list, the `trap` and `vrf` fields are ignored, behaviour of older RouterOS 7 |
| OPNsense | The web interface Signalbox itself uses (scheme and port of the configured address) and, with `os-net-snmp`, `/api/netsnmp/general/get` (`enabled`, `listen`, `community` compared with `public`). **Not readable:** SSH, the web interface's own settings and SNMPv3 users are only in the configuration backup, which needs a privilege that exposes every secret of the firewall; it is not downloaded (see `docs/adapters/opnsense.md`) | SNMP v2c only | `from_wan` unknown | **CI** for the web interface (the VM has no `os-net-snmp`). *Guess:* the plugin's answer shape (`listen` as a selection map or a string) and the privilege it needs |
| Fritz!Box | TR-064: `DeviceInfo GetSecurityPort` (`tr-064`), `X_AVM-DE_UPnP GetInfo`, `X_AVM-DE_RemoteAccess GetInfo` (`https` `remote-access`), `X_AVM-DE_MyFritz GetInfo`, `X_AVM-DE_Storage GetInfo` (`ftp` in the LAN, `ftp-internet`); the LAN web interface (80, 443) is adapter knowledge | none | the box says it: `from_wan` from `NewEnabled`, `NewFTPWANEnable` | SCPD of the four services for FRITZ!OS 7.57 and 8.02 in `tests/fixtures/tr064` and checked by the conformance test; no CI. *Guess:* the web interface ports, that MyFRITZ! means internet access on `NewPort`, the answers of a real box (#21) |
| Omada | `GET .../sites/{siteId}/ssh` (`sshEnable`, `sshServerPort`) and `.../setting/service/snmp` (`snmpV1V2CEnable`, `snmpV3Enable`, `securityLevel`, `communityString` compared with `public`, never kept), the same two services for every managed device | `securityLevel` 2 is authPriv | `from_wan` unknown (cloud access is the controller's) | the CI controller has no managed device: the settings are read and mapped in `test_site_services_shape`, and `/v3/api-docs` is dumped (`spec`, `services`). *Guess* until a real site is read (#21) |
| ProSAFE / Easy Smart | Fixed, from the adapter's knowledge: `vendor` service `nsdp` (UDP 63322) or `easy-smart` (UDP 29808) and the web UI `http` on 80, always on | none | `from_wan` unknown (switches have no uplink) | no CI. *Guess:* that the web interface is HTTP only on every model; `transport_encrypted` is false: NSDP and Easy Smart UDP send the password obfuscated, not encrypted |

## Health and time (adapter API 1.2)

Two capabilities fill value objects on the device itself, keyed by device id so that a
controller can report them for its managed devices too. Declare `api_version="1.2"` (or later)
to use them; an adapter written for 1.0 or 1.1 keeps working unchanged.

```python
from signalbox.model import DeviceHealth, DeviceTime, NtpClient, StorageKind, StorageUsage


class MyAdapter(Adapter):
    manifest = Manifest(
        ..., api_version="1.2", capabilities=frozenset({Capability.HEALTH, Capability.TIME})
    )

    async def read_health(self) -> Observation:  # Capability.HEALTH, ReadsHealth
        return Observation(
            health={
                self.context.device_id: DeviceHealth(
                    uptime_seconds=273906,
                    cpu_load_pct=4,
                    memory_total_bytes=268435456,
                    memory_used_bytes=78435456,
                    storage=[
                        StorageUsage(
                            name="flash",
                            kind=StorageKind.SYSTEM,
                            total_bytes=16777216,
                            used_bytes=5242880,
                        )
                    ],
                )
            }
        )

    async def read_time(self) -> Observation:  # Capability.TIME, ReadsTime
        return Observation(
            time={
                self.context.device_id: DeviceTime(
                    clock=device_now,  # timezone-aware: the device's time as it answered
                    timezone="Europe/Berlin",
                    ntp_client=NtpClient(enabled=True, servers=["192.0.2.1"], synchronised=True),
                )
            }
        )
```

- `DeviceHealth`: `uptime_seconds` or `boot_time` (the other is derived at observation time),
  `last_reboot_reason`, `cpu_load_pct`, `load_average` (1/5/15 min), `cpu_count`,
  `memory_total_bytes` and `memory_used_bytes` (without page cache and buffers: total minus
  available), `storage` per mount with `kind` (`system` for root/overlay/flash where settings
  live, `data`, `temporary` for tmpfs, `other`) and `wear_pct`, `temperatures` (with the device's
  own `limit_c` where it reports one), `fans`, `power_supplies`, `ups` (a UPS the device
  monitors). Leave out what the device does not report; do not guess or put zeros.
- `DeviceTime`: set `clock` to the device's time. Leave `read_at` empty and `observe()` sets it
  to the middle of the `read_time` call, with half its duration as `uncertainty_seconds`; an
  adapter that reads the clock inside a longer call sets both itself. `timezone` is the IANA
  name where the device has one, else its POSIX string. `ntp_server.segments` lists the
  segments where the device serves time (empty while enabled: all of them).
- NTP servers handed out by DHCP (option 42) go into `DhcpServer.ntp_servers` (capability `dhcp`).
- The contract checks (`signalbox.testing`) report a declared capability that returns nothing,
  values without the capability, used above total, times without a time zone and empty names.

