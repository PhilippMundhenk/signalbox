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
`Wlan.passphrase_fingerprint`, so access points can be compared without revealing the key, and
`passphrase_digest(passphrase)` into `Wlan.passphrase_digest` (see
[Wi-Fi security details](#wi-fi-security-details)). Both only for personal (PSK/SAE) networks.

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
- Set `mac` and `identities` (`["serial:<n>", "udn:<uuid>"]`: what the device says about itself
  and that is the same on every address) when the answer tells them: candidates of one
  integration that share one, or the TLS certificate the probe saw, are listed as one device
  (#224). Never put anything in them that changes with the address.
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

## Wi-Fi security details

`Wlan` and `Radio` have optional security details, read with the `wireless` capability (no API
version needed; leave out what the device does not report, never guess):

| Field | Meaning |
| --- | --- |
| `Wlan.security` | also `wep`, `wpa-psk` (WPA1), `wpa-wpa2-psk` (mixed), `wpa-enterprise` (WPA1 or WPA/WPA2 Enterprise), `wpa3-enterprise-192`; `other` only for what has no name |
| `Wlan.ciphers`, `Wlan.group_cipher` | pairwise ciphers offered and the group cipher: `ccmp` ("AES"), `ccmp-256`, `gcmp`, `gcmp-256`, `tkip`, `wep` |
| `Wlan.sae` | `SaeSettings`: `pwe` (`hunting-and-pecking`, `hash-to-element`, `both`), `sae_pk`, `anti_clogging_threshold` |
| `Wlan.wps` | `Wps`: `enabled`, `methods` (`push-button`, `pin`, `nfc`), `ap_pin_locked`; `Wps(enabled=False)` when the device says it is off |
| `Wlan.passphrase_digest` | `passphrase_digest(passphrase)`: keyed, SSID-independent, for "same passphrase on two SSIDs" |
| `Wlan.key_rotation_seconds`, `Wlan.beacon_protection` | group rekey interval (0: never); beacon protection on |
| `Radio.supported_security` | modes the radio's hardware and firmware can offer (not those configured) |

`passphrase_digest()` returns `None` until the service has installed the installation's key
(`set_passphrase_digest_key`, done at start): store what it returns, never the passphrase, and
do not compute it yourself. In tests wrap the observation in
`signalbox.testing.passphrase_digest_key()`; recorded snapshots are made without a key, so
they keep `None`. A remote adapter (its own process) has no key and leaves it `None`.

The contract checks (`signalbox.testing.wlan_problems`, `radio_problems`) report a digest or
fingerprint on a network without a passphrase, an empty `ciphers` list (use `None`), a
duplicate cipher, ciphers or a group cipher on an open network, `wep` with WPA or WPA without
`wep` on a WEP network, SAE settings without SAE, WPS methods while WPS is off, an empty or
duplicated `supported_security`, and a WLAN mode its radio says it cannot offer.

What each integration could fill (nothing is filled yet; *guess* marks what the API
description or vendor documentation does not settle and needs a real device, #21):

| Integration | Security, ciphers | SAE | WPS | Rekey, beacon protection | `supported_security` | Passphrase digest |
| --- | --- | --- | --- | --- | --- | --- |
| OpenWrt | `uci get wireless` `encryption`: `wep-open`/`wep-shared` WEP, `psk` WPA1, `psk-mixed` WPA/WPA2, `psk2` WPA2, `wpa` WPA-Enterprise, `wpa3-192` 192-bit; suffix `+ccmp`/`+tkip`/`+tkip+ccmp`/`+gcmp` gives `ciphers` (no suffix: `ccmp`, `tkip+ccmp` for `psk`/`psk-mixed`); the group cipher is not configured *(guess: the weakest pairwise one)* | `sae_pwe` (`0` hunting-and-pecking, `1` hash-to-element, `2` both; unset: hostapd's default *(guess)*); no SAE-PK in UCI | `wps_pushbutton` `1` push-button, `wps_label` `1` PIN (full `wpad-*` builds only); `ap_pin_locked` from hostapd *(guess)* | `wpa_group_rekey`; `beacon_protection` *(guess: option name)* | LuCI's `luci-rpc getFeatures` `hostapd.sae`/`owe`/`eap` *(needs luci-rpc)*, else the `wpad-*` package from `rpc-sys packagelist` (`wpad-basic*`: no SAE, OWE, EAP) *(guess)* | yes, from `key` |
| MikroTik (`wifi` package) | `/interface/wifi/security` `authentication-types` (`wpa-psk`, `wpa2-psk`, `wpa3-psk`, `owe`, `wpa-eap`, `wpa2-eap`, `wpa3-eap`, `wpa3-eap-192`), `encryption` (`ccmp`, `ccmp-256`, `gcmp`, `gcmp-256`, `tkip`), `group-encryption` | `sae-pwe` (`hunting-and-pecking`, `hash-to-element`, `both`), `sae-anti-clogging-threshold`; no SAE-PK | `wps` (`push-button`, `disable`); no PIN *(guess)* | `group-key-update` (duration); no beacon protection *(guess)* | every mode incl. SAE and OWE (the `wifi` drivers do WPA3) *(guess for wifi-qcom-ac)* | only with the `sensitive` policy (`passphrase`) |
| MikroTik (`wireless` package) | security profile `mode` (`none`, `static-keys-required` WEP, `dynamic-keys`), `authentication-types` (`wpa-psk`, `wpa2-psk`, `wpa-eap`, `wpa2-eap`), `unicast-ciphers`/`group-ciphers` (`tkip`, `aes-ccm`) | none (no WPA3) | `/interface/wireless` `wps-mode` (`disabled`, `push-button`, `push-button-virtual-only`) | profile `group-key-update` | open, WEP, WPA/WPA2 Personal and Enterprise (no SAE, no OWE) | only with `sensitive` (`wpa2-pre-shared-key`) |
| Fritz!Box | `WLANConfiguration:<n> GetInfo` `NewBeaconType` (`Basic` WEP, `WPA`, `WPAand11i` mixed, `11iandWPA3`), `NewBasicEncryptionModes` (`None`, `WEPEncryption`), `NewWPAEncryptionModes` (`AESEncryption`, `TKIPEncryption`, `TKIPandAESEncryption`) | not in TR-064 | `X_AVM-DE_GetWPSInfo` `NewX_AVM-DE_WPSMode`, `NewX_AVM-DE_WPSStatus` *(guess: values such as `pbc`, `pin`, `stop`)* | not in TR-064 | `NewX_AVM-DE_PossibleBeaconTypes` (already read; map like `NewBeaconType`) | yes, `GetSecurityKeys` `NewKeyPassphrase` |
| Omada | SSID `security` with `pskSetting.versionPsk` (1 WPA, 2 WPA2, 3 WPA/WPA2 *(guess: 3)*, 4 WPA2/WPA3) and `entSetting.versionEnt`; `pskSetting.encryptionPsk` (auto = `tkip`+`ccmp`, AES = `ccmp`, TKIP *(guess: codes 1/3/2)*) | none in the Open API | no WPS on Omada EAPs *(guess: leave `None` unless the model is known)* | `gikRekeyPskEnable` with its interval *(guess: interval field)*; no beacon protection | by EAP model and firmware *(guess: not in the API)* | yes, `pskSetting.securityKey` (not with `hidePwd`) |
| OPNsense | not an access point: nothing | | | | | |
| ProSAFE / Easy Smart | switches: nothing | | | | | |

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

Where each integration could fill the fields (no adapter fills them yet). Sources: OpenWrt from
the `dropbear` and `uhttpd` init scripts and default configs, OPNsense from the core and
`os-net-snmp` sources, Fritz!Box from AVM's SCPD files as boxes serve them (FRITZ!OS 8.02),
Omada from the Open API as published in a generated SDK. *(guess)* marks what could not be
checked against a source or a device; MikroTik is from the RouterOS documentation and still has
to be confirmed against the CHR 7.25.1 the integration tests run.

| Integration | Services and where they listen | Logins, redirect, SNMP | Internet exposure | Read by Signalbox |
| --- | --- | --- | --- | --- |
| OPNsense | No API for the administration settings (legacy page, no MVC controller in `core/Api`): parse `system/webgui` and `system/ssh` of the configuration from `/api/core/backup/download/this` (the write side already uses it; needs the backup privilege, and the file holds secrets: read the two elements, discard the rest). `webgui/protocol` (`http`/`https`), `webgui/port` (empty: 80/443), `webgui/interfaces` (empty: all; logical names to segments); `ssh/enabled` (`enabled`), `ssh/port`, `ssh/interfaces`. SNMP plugin: `/api/netsnmp/general/get` (`general.enabled`, `listen`) | `webgui/disablehttpredirect` set: no redirect; `ssh/passwordauth`, `ssh/permitrootlogin` (`1`); SNMP `general.community` compared with `public` (v2c only in the plugin's general settings *(guess)*) | not from the device: the anti-lockout rule (`system/webgui/noantilockout` *(guess: key)*) and WAN rules are #135; leave `from_wan` `None` | `True` (HTTPS), `False` with `allow_insecure_http` |
| OpenWrt | `uci get` `dropbear` (each `dropbear` section: `enable`, `Port`, `Interface` = logical network → `segments`, `DirectInterface` → `interfaces`) and `uhttpd` (`main`: `listen_http`, `listen_https` as `addr:port`, `0.0.0.0`/`[::]` = all); `rpcd`/`luci` need nothing. **The read ACL allows only `network`, `wireless`, `dhcp`, `system`**: add `dropbear` and `uhttpd` to `READ_ACL`, docs/adapters/openwrt.md and the integration image; routers set up earlier will refuse the call (leave the list empty). Telnet is not in current releases *(guess: since which one)*; `snmpd` only when installed (`uci get snmpd` *(guess: section layout)*) | dropbear `PasswordAuth`, `RootPasswordAuth`, `RootLogin` (all default on); uhttpd `redirect_https` (default `0`) | `uhttpd` `rfc1918_filter` (default `1`) refuses requests from public addresses to private ones; the WAN zone's input policy is #135; leave `from_wan` `None` | `True` (HTTPS), `False` with `allow_insecure_http` |
| MikroTik | `/rest/ip/service`: one row per service, `name` (`telnet`, `ftp`, `www`, `ssh`, `www-ssl`, `api`, `winbox`, `api-ssl`), `port`, `disabled`, `address` (comma-separated prefixes → `allowed_from`), `certificate`; `/rest/tool/mac-server` and `/rest/tool/mac-server/mac-winbox` `allowed-interface-list` (`all`, `none` or a list: resolve with `/rest/interface/list/member` to ports), `/rest/tool/romon` `enabled`, `/rest/ip/upnp` `enabled`, `/rest/tool/bandwidth-server` `enabled` (`other`) *(guess: field names, confirm on CHR)* | `/rest/ip/ssh` `always-allow-password-login`, `strong-crypto` *(guess)*; `/rest/snmp` `enabled`, `/rest/snmp/community` (`name` = `public`, `security`, `write-access`, `addresses`) | services listen on every interface, the default firewall drops WAN input: #135; leave `from_wan` `None`. MAC server on `all` includes the WAN port | `True` (REST over `www-ssl`) |
| Fritz!Box | Web UI: HTTP 80 and HTTPS 443 in the LAN are fixed (adapter knowledge, *(guess)*: no TR-064 action reports them); `DeviceInfo:1 GetSecurityPort` (`NewSecurityPort`, TR-064 over TLS) and TR-064 on 49000; `X_AVM-DE_UPnP:1 GetInfo` (`NewEnable`); `X_AVM-DE_Storage:1 GetInfo` (`NewFTPEnable` in the LAN) | `LANConfigSecurity:1 GetInfo` `NewX_AVM-DE_IsDefaultPasswordActive` and `X_AVM-DE_GetAnonymousLogin` are login facts the model has no field for yet (`vendor_extra`) | the device says: `X_AVM-DE_RemoteAccess:1 GetInfo` (`NewEnabled`, `NewPort`, `NewLetsEncryptEnabled`) → `https`, `name` `remote-access`, `from_wan` = `NewEnabled`; `X_AVM-DE_MyFritz:1 GetInfo` (`NewEnabled`, `NewPort`); `X_AVM-DE_Storage:1 GetInfo` `NewFTPWANEnable`, `NewFTPWANPort`, `NewFTPWANSSLOnly` → `ftp` from the internet (`encrypted` from SSL only); `X_AVM-DE_AppSetup:1 GetConfig` `NewAccessFromInternet` is per app user | `True` (TR-064 on 49443), `False` with `allow_insecure_http` |
| Omada | Controller Open API per site: `GET .../sites/{siteId}/ssh` (`sshEnable`, `sshServerPort`, `layer3Access`: `false` = only from the management network, so `segments` is the devices' management VLAN), `GET .../sites/{siteId}/setting/service/snmp` (`snmpV1V2CEnable`, `snmpV3Enable`, `securityLevel` 2 = authPriv, `communityString` compared with `public`, never stored); the settings apply to every managed device: report them per device id of `Observation.devices`. Device web UIs are off under a controller *(guess)*; the controller's own HTTPS port and cloud access *(guess: no Open API call found)* | SSH password login: device account only, no key login *(guess)* | cloud access is the controller's, not a device service; leave `from_wan` `None` | `True` (HTTPS), `False` with `allow_insecure_http` |
| ProSAFE / Easy Smart | Fixed, from the adapter's knowledge: `vendor` service `nsdp` (UDP 63322) or `easy-smart` (UDP 29808), always on, unencrypted, listening everywhere; the web UI `http` on 80 (most models have no HTTPS *(guess per model)*) | none | `False` (switches have no uplink) | `False`: NSDP and Easy Smart UDP send the password obfuscated, not encrypted |

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

