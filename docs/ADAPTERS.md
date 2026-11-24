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
  `ReadsWireless`, `ReadsClients`, `ReadsNeighbours`, `ReadsHealth`, `ReadsTime`, `ReadsVpn`,
  `ReadsFirewall`); a missing one
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

## Automatic setup with an admin login

An integration can set up its own least-privilege login when the user gives the admin login
once (#231, [ADR 0009](adr/0009-automatic-setup-with-an-admin-login.md)); the device form then
offers *Set up automatically*. Optional, no adapter API version needed:

```python
manifest = Manifest(
    ...,
    admin_login=AdminLogin(
        transport="SSH as root",
        user_default="root",
        secret_label="root password",
        port_default=22,
        note="What must be possible on the device first.",
    ),
)


@classmethod
async def plan_setup(cls, request: SetupRequest) -> SetupPlan: ...
@classmethod
async def apply_setup(cls, request: SetupRequest) -> SetupResult: ...
```

`SetupRequest` carries the form's settings without secrets (`config`), the admin login
(`admin_user`, `admin_secret`, `port`), `allow_writes`, `remove` and `trust`, the fingerprint
the user confirmed. Rules, checked by the tests of the built-in integrations:

- Send the admin login only over a pinned channel: `DeviceHttp` with `trust` as the pin, or
  `signalbox.adapters.ssh.PinnedSsh`. Without `trust`, or with another fingerprint, the plan
  returns the presented one (`trusted=False`, `fingerprint_kind` `certificate` or
  `ssh-host-key`, and `compare`: how to check it on the device) and sends nothing else.
- The plan changes nothing. Build `signalbox.adapters.provision.Step`s (title, what is sent
  as `detail`, `needed`, the action) and report them with `plan_steps`; run them with
  `run_steps`, which stops at the first failure. Steps that are already right are `unchanged`.
- Create exactly the access the setup guide documents, write access only with `allow_writes`,
  and refuse to set up the admin login itself. A re-run repairs and upgrades; `remove` deletes
  what the setup creates and keeps what something else still uses.
- Generate secrets with `new_password()` and return them in `SetupResult.secrets` (stored
  encrypted, never sent to the UI), the other settings in `settings`, and a certificate learnt
  over the pinned channel in `certificate`. Add the admin secret and every generated secret to a
  `Redactor` and pass every text you return or raise through it.

`load_adapters` refuses an integration that declares `admin_login` without both methods.
With `setup.enabled: false` the hooks are never called.

### Fix it: remedies for read problems

An integration with `admin_login` can also repair what its setup owns (#215,
[ADR 0012](adr/0012-fix-it-for-read-problems.md)): declare the remedies and name one where a read
fails; the device page then offers *Fix it* next to that error. A remedy with `read_side=True` (only packages and permissions Signalbox reads through)
needs no *Allow changes*; others do (#278).

A missing optional feature is no read failure: return `Observation(incomplete=[Gap(...,
optional=True)])`. It is shown with its fix but does not make the device *partly read* and gives
an info finding at most. `AdminLogin.extras` offers optional setup steps as unticked checkboxes
(`SetupRequest.extras`; with `remove`, ticked ones are removed again).

```python
manifest = Manifest(..., remedies=(Remedy(id="lldp", title="Install LLDP", description="..."),))

raise AdapterError("LLDP is not installed", fix="Install lldpd ...", remedy="lldp")
Gap(message="...", fix="...", remedy="access")  # in Observation.incomplete


@classmethod
async def plan_remedy(cls, request: RemedyRequest) -> SetupPlan: ...
@classmethod
async def apply_remedy(cls, request: RemedyRequest) -> SetupResult: ...
```

`RemedyRequest` has the remedy id, the stored settings without secrets (`config`), the stored
secrets (`secrets`, to identify the device's login; redact them), the admin login, `allow_writes`
and `trust`. The rules of the setup apply; in addition a remedy changes only the packages and
permissions Signalbox reads through (never network settings), keeps the stored login's
credentials, and returns no settings. Keep the `fix` text: the manual way is always shown.
`load_adapters` refuses remedies without `admin_login` or without both methods. With
`setup.enabled: false` or `setup.fixes: false` they are never called.

## Path traces (optional, #253)

An integration whose devices can run a traceroute declares `Manifest.traces`
(`TraceSupport`: the permission the login needs and how it runs, in plain words; shown on the
topology page) and implements `Adapter.trace(target, max_hops, wait) -> TraceAnswer`. No adapter
API version is needed; `load_adapters` refuses `traces` without the method. It is called only
while `traces.enabled` is on, on a stored device with its stored login, with the whole trace's
timeout as the context timeout: send nothing but the traceroute, one probe per hop, numeric
output, and return the raw hops (`TraceHop`: TTL, address or None for no answer, RTT) and
whether the target answered. Core matches hops to devices. A login that may not trace raises
`AuthFailed` with a `fix` (and a `remedy` where *Fix it* can add the permission). The automatic
setup and remedies get `SetupRequest.traces` / `RemedyRequest.traces`: add the permission only
when it is true. Built in: OPNsense, MikroTik, Linux; [TRACES.md](TRACES.md) lists what each
needs and why OpenWrt and the others cannot.

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

## Port structure

`Port.role` and `Port.lower` describe the internal structure of a device (#252, ADR 0008;
`interfaces` capability, no API version needed). Report a role only where the device says it,
and `lower` bottom-up: the upper port names the ports it runs on (a bridge its members, a VLAN
interface its parent, a DSA user port its conduit, a LAG its members), never the other way.
`Wlan.port_id` names the Wi-Fi interface of an SSID. `Port.external` (a cable can end there)
is derived from the role; rules and the topology skip internal ports. The contract tests
refuse lower ports that are not reported or belong to another device, cycles, a bridge, Wi-Fi
or LAG role with another kind, and a VLAN interface on several ports.

| Role | Meaning |
| --- | --- |
| `jack` | connector on the case (DSA user port, NIC) |
| `cpu` | internal link between CPU and switch chip (DSA conduit, swconfig / MikroTik switch CPU port) |
| `switch-port` | port of a switch chip, jack or not unknown |
| `bridge`, `vlan`, `wireless`, `lag`, `tunnel`, `virtual` | interfaces built on other ports, or none |

| Integration | Fills | Where |
| --- | --- | --- |
| OpenWrt | every role: netifd bridges and VLAN devices, DSA conduit and user ports (`luci-rpc getNetworkDevices`), swconfig CPU port (UCI `switch_vlan`); `Wlan.port_id` | `openwrt/structure.py`, `read_interfaces()`, `read_wireless()` |
| MikroTik | `/interface` types: `ether` jacks, `bridge` over `/interface/bridge/port`, `vlan` on its parent, `bond` over `/interface/bonding` slaves, `wifi`/`wlan` Wi-Fi interfaces (virtual APs on their `master-interface`; `Wlan.port_id`), tunnels (`wg`, `eoip`, `gre`, ...); switch CPU port from `/interface/ethernet/switch/port` | `mikrotik/__init__.py` |
| OPNsense | NICs (`is_physical`) as jacks, VLAN devices (`vlan_settings`, `if` = parent), `lagg*`/`bridge*` with `members` where the row has them, `wg*`/`ovpn*`/... tunnels; read with the existing privileges | `opnsense/__init__.py` |
| Omada | switch ports as jacks, link aggregation groups (`lagId`) as `lag` ports; EAP radios and SSIDs need no ports | `omada/__init__.py` |
| ProSAFE / Easy Smart | every port a jack, enabled LAGs as `lag` ports over their members | `plusswitch/mapping.py` |
| Linux | `ip -d link` kinds: `bridge` over its `master` members, `vlan` on its `link`, `bond`/`team`, `dsa` user ports on their conduit (CPU port), tunnels (`wireguard`, `ppp`, `gre`, ...), virtual (`veth`, `dummy`, ...); a NIC (`/sys/class/net/<n>/device`) is a jack, `wireless` a Wi-Fi interface | `linux/parse.py`, `role_of()` |
| Fritz!Box | nothing: TR-064 has one LAN interface and names no jack, bridge or WLAN interface (no role is better than a guessed one) | `fritzbox/__init__.py` |

What CI confirmed (real software, #252): OpenWrt (QEMU: NICs, bridge, VLAN interfaces), MikroTik
(CHR: jacks, bridge members, VLAN parent, WireGuard tunnel) and OPNsense (jacks, VLAN parent).
Simulator only: DSA, the MikroTik switch CPU port, bonding and virtual APs, laggs and bridges of
OPNsense, Omada and ProSAFE/Easy Smart LAGs.

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

What each integration fills (#167). *Guess* marks what the API description or vendor
documentation does not settle and needs a real device (#21); **CI** marks what the integration
tests confirm against the real software:

| Integration | Security, ciphers | SAE | WPS | Rekey, beacon protection | `supported_security` | Passphrase digest |
| --- | --- | --- | --- | --- | --- | --- |
| OpenWrt | `uci get wireless` `encryption`: `wep*` WEP, `psk` WPA1, `psk-mixed` WPA/WPA2, `psk2` WPA2, `sae`/`sae-mixed`, `wpa`/`wpa-mixed` WPA-Enterprise, `wpa2`, `wpa3*`, `wpa3-192` 192-bit; suffix `+ccmp`/`+aes`/`+tkip`/`+gcmp` gives `ciphers` (no suffix: `ccmp`, `tkip`+`ccmp` for `psk`/`psk-mixed`, `gcmp-256` for `wpa3-192`); the group cipher is not configured *(guess: the weakest pairwise one)* | `sae_pwe` (`0` hunting-and-pecking, `1` hash-to-element, `2` both; unset: not reported); no SAE-PK in UCI | `wps_pushbutton` `1` push-button, `wps_label` `1` PIN, neither: off (full `wpad-*` builds only); no `ap_pin_locked` | `wpa_group_rekey`; `beacon_prot` *(guess: option name)* | `luci getFeatures` `hostapd` flags `sae`/`owe`/`eap`/`suiteb192` *(guess: object name; needs luci-base; the CI image has it)*, else the `wpad-*` package from `rpc-sys packagelist` (`wpad-basic*`: no SAE, OWE, EAP) *(guess)* | yes, from `key` (**CI** checks it) |
| MikroTik (`wifi` package) | `/interface/wifi/security` `authentication-types` (`wpa-psk`, `wpa2-psk`, `wpa3-psk`, `owe`, `wpa-eap`, `wpa2-eap`, `wpa3-eap`, `wpa3-eap-192`), `encryption` (`ccmp`, `ccmp-256`, `gcmp`, `gcmp-256`, `tkip`), `group-encryption` (only when set) | `sae-pwe` (`hunting-and-pecking`, `hash-to-element`, `both`), `sae-anti-clogging-threshold`; no SAE-PK | `wps` (`push-button`, `disable`); no PIN *(guess)* | `group-key-update` (duration); no beacon protection *(guess)* | every mode incl. SAE and OWE (the `wifi` drivers do WPA3) *(guess for wifi-qcom-ac)* | only with the `sensitive` policy (`passphrase`) |
| MikroTik (`wireless` package) | security profile `mode` (`none`, `static-keys-*` WEP, `dynamic-keys`), `authentication-types` (`wpa-psk`, `wpa2-psk`, `wpa-eap`, `wpa2-eap`), `unicast-ciphers`/`group-ciphers` (`tkip`, `aes-ccm`) | none (no WPA3) | `/interface/wireless` `wps-mode` (`disabled`, `push-button`, `push-button-virtual-only`) | profile `group-key-update` | open, WEP, WPA/WPA2 Personal and Enterprise (no SAE, no OWE) | only with `sensitive` (`wpa2-pre-shared-key`) |
| Fritz!Box | `WLANConfiguration:<n> GetInfo` `NewBeaconType` (`Basic` WEP or open by `NewBasicEncryptionModes`, `WPA`, `WPAand11i` mixed, `11i`, `11iandWPA3`); **no ciphers**: `NewWPAEncryptionModes` is not in the SCPD of FRITZ!OS 7.57, 8.02 or 8.25 (WEP: `wep`) | not in TR-064 | `X_AVM-DE_GetWPSInfo` `NewX_AVM-DE_WPSStatus` `off` disabled, else enabled, `NewX_AVM-DE_WPSMode` `pbc` push-button *(guess: the meaning of the values; the SCPD lists them)* | not in TR-064 | `NewX_AVM-DE_PossibleBeaconTypes` (mapped like `NewBeaconType`) | yes, `GetSecurityKeys` `NewKeyPassphrase` |
| Omada | SSID `security` with `pskSetting.versionPsk` (1 WPA, 2 WPA2, 3 WPA/WPA2 *(guess: 3)*, 4 WPA2/WPA3) and `entSetting.versionEnt` (4 WPA3; 1 and 3 WPA-Enterprise *(guess)*); `pskSetting.encryptionPsk` (1 auto = `tkip`+`ccmp`, 2 TKIP, 3 AES = `ccmp` *(guess: codes 1/2; **CI** confirms 3)*) | none in the Open API | no WPS on Omada EAPs (not reported) | `gikRekeyPskEnable` `false` is 0 (**CI** confirms), with `true` the interval `rekeyPskInterval` *(guess: field name)*; no beacon protection | not in the API (not reported) | yes, `pskSetting.securityKey` (not with `hidePwd`) |
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
| Linux (role `gateway`) | the interfaces of the default routes (`ip -j route`), not tunnels; `dhcp` (route protocol `dhcp` or a dynamic address), `pppoe`, else `static`; no uptime | the interface's global addresses, the route's next hop; no provider DNS, no prefix | none |
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
| OpenWrt | `uci get dropbear` (each section: `enable`, `Port`, `Interface` to `segments`, `DirectInterface` to `interfaces`) and `uci get uhttpd` (`main`: `listen_http`, `listen_https`). Needs `dropbear` and `uhttpd` in the ACL's `uci` list: a router with the old ACL answers "access denied" and its services stay unread, the rest of the read works. With the `snmpd` package, its agent (see log and monitoring targets). No telnet | `PasswordAuth`, `RootLogin`, `RootPasswordAuth` (default on); `redirect_https` | `from_wan` unknown (`rfc1918_filter` is not mapped; the firewall is #135) | **CI** (24.10 and 25.12): dropbear and uhttpd read through the documented ACL. *Guess:* `Interface` to segment on a router with VLANs, telnet in older releases |
| MikroTik | `/rest/ip/service` (`available-from` is `allowed_from`; dynamic rows and unknown names such as `reverse-proxy` are skipped), `/rest/tool/mac-server` and `/mac-winbox` (`allowed-interface-list`: `none` is off, `all` is every port, else the list's members), `/rest/tool/romon`, `/rest/ip/upnp`, `/rest/ip/ssh`, `/rest/snmp` with `/community` | `password-authentication` (`yes`, `no`, `yes-if-no-key` is unknown; `always-allow-password-login` before 7.25); community named `public` or `private`, `write-access`, `security` (`none` v1/v2c, `authorized`, `private` is authPriv); the community string is never kept | `from_wan` unknown (firewall: #135) | **CI** (CHR 7.25.1): every menu and field above, read as the read-only user. *Guess:* the member-list mapping of a non-default MAC server list, the `trap` and `vrf` fields are ignored, behaviour of older RouterOS 7 |
| OPNsense | The web interface Signalbox itself uses (scheme and port of the configured address) and, with `os-net-snmp`, `/api/netsnmp/general/get` (`enabled`, `listen`, `community` compared with `public`). **Not readable:** SSH, the web interface's own settings and SNMPv3 users are only in the configuration backup, which needs a privilege that exposes every secret of the firewall; it is not downloaded (see `docs/adapters/opnsense.md`) | SNMP v2c only | `from_wan` unknown | **CI** for the web interface (the VM has no `os-net-snmp`). *Guess:* the plugin's answer shape (`listen` as a selection map or a string) and the privilege it needs |
| Fritz!Box | TR-064: `DeviceInfo GetSecurityPort` (`tr-064`), `X_AVM-DE_UPnP GetInfo`, `X_AVM-DE_RemoteAccess GetInfo` (`https` `remote-access`), `X_AVM-DE_MyFritz GetInfo`, `X_AVM-DE_Storage GetInfo` (`ftp` in the LAN, `ftp-internet`); the LAN web interface (80, 443) is adapter knowledge | none | the box says it: `from_wan` from `NewEnabled`, `NewFTPWANEnable` | SCPD of the four services for FRITZ!OS 7.57 and 8.02 in `tests/fixtures/tr064` and checked by the conformance test; no CI. *Guess:* the web interface ports, that MyFRITZ! means internet access on `NewPort`, the answers of a real box (#21) |
| Omada | `GET .../sites/{siteId}/ssh` (`sshEnable`, `sshServerPort`) and `.../setting/service/snmp` (`snmpV1V2CEnable`, `snmpV3Enable`, `securityLevel`, `communityString` compared with `public`, never kept), the same two services for every managed device | `securityLevel` 2 is authPriv | `from_wan` unknown (cloud access is the controller's) **CI** (Omada 6.3): both paths and every field are in the controller's own `/v3/api-docs` and answer to the viewer (`sshEnable`, `sshServerPort`, `layer3Access`, `snmpV1V2CEnable`, `snmpV3Enable`; `securityLevel` 0 NoAuthNoPriv, 1 AuthNoPriv, 2 AuthPriv). The test site has no managed device, so the per-device mapping runs on those answers only. *Guess* until a real site is read (#21): that the devices apply the site settings, `layer3Access` is not mapped |
| Linux | `sshd_config` with `Include` (`Port`, `ListenAddress`), enabled from `ssh.service` or a listening port | `PasswordAuthentication`, `PermitRootLogin` | `from_wan` unknown | **CI** (Debian 12 container). *Guess:* `Match` blocks are ignored |
| ProSAFE / Easy Smart | Fixed, from the adapter's knowledge: `vendor` service `nsdp` (UDP 63322) or `easy-smart` (UDP 29808) and the web UI `http` on 80, always on | none | `from_wan` unknown (switches have no uplink) | no CI. *Guess:* that the web interface is HTTP only on every model; `transport_encrypted` is false: NSDP and Easy Smart UDP send the password obfuscated, not encrypted |

## Log and monitoring targets (#180)

Where a device sends syslog, flow records, SNMP traps or metrics: `Observation.log_targets`,
keyed by device id like `health` and `time` (a controller can report its devices), read with
`interfaces` (no API version needed, [ADR 0018](adr/0018-log-and-monitoring-targets.md)).
`observe()` puts the list on `Device.log_targets`. Report `[]` for a device that was read and
sends nothing; leave a device out when its targets could not be read and add a `Gap` (with
`optional=True` where the targets need an optional package or privilege). List disabled targets
too (`enabled=False`, also for a target that is configured but not used). Never a community or
key. The SNMP agent itself is a management service of kind `snmp`; only its trap destinations
are targets (`snmp-trap`).

| Field | Meaning |
| --- | --- |
| `kind` | `syslog`, `netflow`, `ipfix`, `sflow`, `snmp-trap`, `metrics` (collectd), `other` |
| `address`, `port` | address or host name as configured; the port (`LOG_PORTS` has the usual ones) |
| `transport` | `udp`, `tcp` or `tls` (syslog over TLS only) |
| `name`, `topics` | the device's name of the target; facilities, levels or topics, flow version |

The contract checks report targets without the `interfaces` capability, a target listed twice,
TLS on a target that is not syslog and an address with spaces.

| Integration | Targets read | Status |
| --- | --- | --- |
| OpenWrt | `uci get system` (`log_ip`, `log_port`, `log_proto`, `log_remote`); with the packages installed `snmpd` (the agent as a service: `com2sec` communities compared with `public`/`private`, `group` versions, `access` write, `agentaddress` port, `general.enabled`; `trapsink`/`trap2sink`/`informsink` as traps), `luci_statistics` (collectd `collectd_network` servers) and `softflowd` (`host_port`, `export_version` 10 is IPFIX). Needs `snmpd`, `luci_statistics`, `softflowd` in the ACL's `uci` list; an older ACL is an optional gap | **CI** (24.10 and 25.12): `system` and an `snmpd` config written by the image, through the documented ACL. *Guess:* the snmpd, luci_statistics and softflowd layouts of real packages (#21) |
| MikroTik | `/rest/system/logging/action` (`target=remote`: `remote`, `remote-port`, `remote-protocol`; `0.0.0.0` is unset) with `/rest/system/logging` (an action no enabled rule uses is disabled; the rules' topics), `/rest/ip/traffic-flow` and `/target` (`dst-address`, `port`, `version`: `ipfix` or NetFlow), `/rest/snmp` `trap-target` (enabled with `trap-generators`) | **CI** (CHR 7.25.1): the defaults read as "nothing sent"; the `logging` dump group records the answers. *Guess:* `remote-protocol` (7.18 and later), the traffic-flow target and trap fields of a configured router |
| OPNsense | `/api/syslog/settings/search_destinations` (`hostname`, `port`, `transport` `udp4`/`tcp4`/`tls6`..., `enabled`, `level`, `facility`, `description`) and `/api/diagnostics/netflow/getconfig` (`capture.targets`, on when `capture.interfaces` is set, `version`; the local collector 127.0.0.1:2056 is left out). Privileges *System: Settings: Logging* and *Diagnostics: Netflow configuration*; a refused page is an optional gap | **CI** (26.7): the destination and export vm.py configures, as the read user. *Guess:* option fields as display text on other versions |
| Linux | `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf` (`@`, `@@`, `action(type="omfwd")` with `StreamDriverMode="1"` as TLS) and syslog-ng (`destination` with `network`/`syslog`/`udp`/`tcp`, enabled when a `log` statement uses it). journald alone forwards nothing | no CI (the test containers have no syslog daemon). *Guess:* includes beyond those directories, templates |
| Fritz!Box, Omada, ProSAFE / Easy Smart, Pi-hole, AdGuard Home | not read (`None`) | Fritz!Box has no syslog or SNMP; Omada's site remote logging is a later step |

## DHCP leases, address sources, options and relays

Read with the `dhcp` capability (no API version needed, #183): `DhcpServer.leases`, the
option fields and `Observation.dhcp_relays`; `Client.address_sources` with `clients`.

| Field | Meaning |
| --- | --- |
| `DhcpServer.leases` | `None`: not read (the default); `[]`: read, no leases. Report every entry of the server's table with its `state` (`active`, `expired`, `declined`, `offered`, `reserved` for a reservation not in use). A very long table may be capped; say so with a read error |
| `DhcpLease` | `address`; `mac` (may be missing for DHCPv6, then `client_id` = DUID); `client_id` (option 61); `hostname`; `reserved` (lease of a reservation); `starts`, `expires` (absolute, UTC; convert "seconds remaining" with the observation time); `vendor_class` (option 60) |
| `search_domains`, `static_routes`, `boot` | option 119, option 121 (`DhcpRoute`: destination, gateway), next server and options 66/67 |
| `options` | further options as `DhcpOption(code, name, value)`; never a code in `TYPED_OPTION_CODES` (3, 6, 15, 42, 51, 66, 67, 119, 121) |
| `authoritative`, `failover_peer` | NAK for unknown addresses; HA/failover partner name or address |
| `DhcpRelay` | `object_id(device, "dhcp-relay", <segment key>)`, `segment_id`, `servers`, `enabled` |
| `Client.address_sources` | address → `AddressSource` for addresses in `addresses` only: `dhcp`, `dhcp-reserved`, `static`, `slaac`, `slaac-privacy`, `dhcpv6`, `link-local`, `unknown`. Leave an address out when the device does not know; do not infer `static` from a missing lease (core and checks do that with `Network.leases_read()`) |

The contract checks report a lease with neither MAC nor client id, one that expires before it
starts, `state` `reserved` with `reserved=False`, one address active for two clients on one
server, an option that belongs in a typed field or appears twice, a relay id outside
`<device>/dhcp-relay/`, a relay in an unknown segment or reported twice or without the `dhcp`
capability, and an address source for an address the client does not list or of the wrong
family (SLAAC for IPv4, `dhcp` for IPv6).

What each integration fills today (#183) and could fill. Today's sources: the leases the
integrations already merged into clients now mark those addresses `dhcp` (`dhcp-reserved` for
static leases where the device says), and the Fritz!Box `AddressSource` moved from
`vendor_extra` to `address_sources`. *(guess)* marks field names or behaviour not checked
against a device or the vendor's source.

| Integration | Lease table | Address source today | Options, authoritative, failover | Relays |
| --- | --- | --- | --- | --- |
| OPNsense (Kea) | `/api/kea/leases4/search` (already read for clients): `address`, `hwaddr`, `client_id`, `hostname`, `expire` (epoch), `valid_lifetime` (start = expire − lifetime), `state` (0 active, 1 declined, 2 expired-reclaimed), `if`; reserved by matching `search_reservation` (`hw_address`); vendor class not in the lease *(guess)*. `/api/kea/leases6/search` (`duid`, `iaid`) for DHCPv6 *(guess: exists on 24.7+)* | lease addresses `dhcp` | subnet `option_data` in `search_subnet` (`domain_search`, `ntp_servers`, `static_routes`, `tftp_server_name`, `boot_file_name`, `time_servers`) *(guess: key names per release)*; Kea HA in `/api/kea/dhcpv4/get` `ha.enabled`, `ha.this_server_name`, peers `search_peer` → `failover_peer`; authoritative not exposed *(guess)* | `/api/dhcrelay/settings/search_relay` (`enabled`, `interface`, `destination` → `search_dest` `server`) *(guess: names, core since 24.1)* |
| OPNsense (ISC) | `/api/dhcpv4/leases/search_lease` (already read for DHCP and clients): `address`, `mac`, `hostname`, `starts`, `ends`, `state` (`active`, `expired`, `free`, `abandoned`, `backup`), `type` (`static` → `reserved`), `if`, `man` (vendor from the OUI, not option 60) | lease addresses `dhcp`, `static` type `dhcp-reserved` | the API has no ranges or options (see `vendor_extra.note`); failover peer only in the configuration (`dhcpd/<if>/failover_peerip` from the backup) *(guess)* | ISC relay in the legacy page only *(guess)* |
| OPNsense (dnsmasq, 25.1+) | `/api/dnsmasq/leases/search` (`address`, `hwaddr`, `client_id`, `hostname`, `expire`, `if`, `is_reserved`) *(guess: not read by Signalbox yet, no dnsmasq DHCP support)* | — | `/api/dnsmasq/settings/search_option` (`option`, `value`, `interface`) *(guess)* | — |
| OpenWrt | `luci-rpc getDHCPLeases` (already read for clients): `dhcp_leases` `macaddr`, `ipaddr`, `hostname`, `expires` (seconds left, `false` for infinite *(guess)*); `dhcp6_leases` from odhcpd `duid`, `ip6addr`/`ip6addrs`, `hostname`, `expires`; fallback `/tmp/dhcp.leases` `<expiry epoch> <mac> <ip> <name or *> <client id or *>`. `reserved` by matching `uci dhcp host` sections (already read as reservations). dnsmasq keeps no vendor class in the file | IPv4 lease addresses `dhcp` | `uci dhcp` per pool `dhcp_option` / `dhcp_option_force` (`6,192.0.2.1`, `option:ntp-server,...`, `121,...`); `dnsmasq` section `authoritative` (default `1`); no failover | `relayd` (`network` interface with `proto relay`) bridges rather than relays; dnsmasq `dhcp_relay` / odhcpd `dhcpv6 relay` *(guess: list names)* |
| MikroTik | `/rest/ip/dhcp-server/lease` (already read): `address`, `mac-address`, `client-id`, `host-name`, `class-id` (option 60), `status` (`bound` active, `offered`, `waiting` → `reserved` for static / `expired` for dynamic, `busy`/`conflict` → `declined` *(guess)*), `dynamic` (`false` → `reserved`), `expires-after` (duration from now), `last-seen`, `active-*` fields, `server` → its DHCP server, `blocked`, `disabled`. IPv6: `/rest/ipv6/dhcp-server/binding` (`duid`, `iaid`, `address`) is prefix delegation, not addresses | bound leases `dhcp`, static ones `dhcp-reserved` | `/rest/ip/dhcp-server/network` (`ntp-server` already, `domain`, `next-server`, `boot-file-name`, `dhcp-option` names); `/rest/ip/dhcp-server/option` (`name`, `code`, `value`); `/rest/ip/dhcp-server` `authoritative` (`yes`, `no`, `after-2sec-delay`, `after-10sec-delay`: all but `no` count as authoritative); no failover | `/rest/ip/dhcp-relay` (`name`, `interface`, `dhcp-server` comma list, `local-address`, `disabled`, `invalid`) |
| Fritz!Box | No lease table of its own: `Hosts:1` host list (`X_AVM-DE_GetHostListPath`, already read) has `AddressSource` and `LeaseTimeRemaining` (seconds) per host, active and remembered ones; hosts with source `DHCP` could become leases (`expires` = observation + remaining, inactive ones `expired` *(guess)*) | `NewAddressSource`: `DHCP` → `dhcp`, `Static` → `static`, `AutoIP` → `link-local` *(guess: AutoIP spelling)* | none over TR-064 beyond `LANHostConfigManagement:1 GetInfo` (router, DNS, domain, range already) | `LANHostConfigManagement:1 GetInfo` `NewDHCPRelay` (boolean, no server address) *(guess: ever true on a box)* |
| Omada | No lease table in the Open API *(guess)*; clients (already read) have `ip`, `ipv6List`, `hostName`, no lease expiry | none: whether a client's address is static is not reported *(guess: `ipSetting` / `staticIp` fields in newer controllers)* | LAN network DHCP settings (already read: `dhcpns`, `priDns`, `leasetime`): options 60, 66, 138 as `option60`, `option66`, `option138` *(guess)* | network `dhcpSettings` in relay mode with the relay server address (`dhcpRelay` *(guess)*) |
| Linux | dnsmasq `/var/lib/misc/dnsmasq.leases`, Kea `kea-leases4.csv`, ISC `dhcpd.leases`; systemd-networkd none; `reserved` by matching the reservations | — | dnsmasq `dhcp-option` (119, 121 decoded), `dhcp-authoritative`; Kea `option-data`, `authoritative`, HA peer; ISC `option`, `authoritative`, `failover peer` | none |
| ProSAFE / Easy Smart | none (switches) | none | none | none |

Filled since (#183; details in each `docs/adapters/<id>.md`): OPNsense (Kea and ISC leases, Kea
options and HA peer, dhcrelay; needs the privilege *Services: DHCRelay*), OpenWrt (leases from
luci-rpc or the file, `dhcp_option`, `authoritative`, `relay` sections), MikroTik (leases, options
with 119/121 decoded, `authoritative`, `/ip/dhcp-relay`), Fritz!Box (leases from the host list,
`NewDHCPRelay`). Not filled: Omada (no lease table; options and relay mode wait for the
`/v3/api-docs` dump of CI), OPNsense dnsmasq and ISC options. Still *(guess)* until a real device
is read (#21): the Kea option key names, route format and peer fields, the dhcrelay field names,
the OpenWrt relay sections and `false` for an endless lease, MikroTik `busy`/`conflict`, the
Fritz!Box countdown and its expired entries. CI-confirmed: see the integration notes of
OPNsense, OpenWrt and MikroTik (the lease table is read, MikroTik's static lease; MikroTik 7.25.1 has no `authoritative` property).

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


## VPN tunnels (adapter API 1.3)

The `vpn` capability (#239, [ADR 0011](adr/0011-vpn-tunnels-and-site-links.md)) reports every
VPN interface of the device with its peers. Declare `api_version="1.3"` and implement
`ReadsVpn`:

```python
from signalbox.model import Tunnel, TunnelPeer, object_id


async def read_vpn(self) -> Observation:  # Capability.VPN, ReadsVpn
    d = self.context.device_id
    return Observation(
        tunnels=[
            Tunnel(
                id=object_id(d, "tunnel", "wg0"),
                device_id=d,
                name="wg0",
                up=True,
                listen_port=51820,
                public_key="<base64 public key>",
                addresses=[ip_interface("2001:db8:ff::1/64")],
                peers=[
                    TunnelPeer(
                        public_key="<the other end's public key>",
                        name="site-b",
                        endpoint_host="203.0.113.20",
                        endpoint_port=51820,
                        allowed_ips=[
                            ip_network("2001:db8:ff::2/128"),
                            ip_network("198.51.100.0/24"),
                        ],
                        latest_handshake=datetime.fromtimestamp(epoch, UTC),  # None: none
                        rx_bytes=1834567,
                        tx_bytes=2934871,
                        keepalive_seconds=25,  # 0: off
                    )
                ],
            )
        ]
    )
```

- Every interface, also one without peers; every peer, road-warrior clients too. Leave out
  what the device does not say (`None`), never guess.
- **Never a private or pre-shared key**, not even in `vendor_extra`: the contract checks refuse
  a field named like one and every WireGuard-shaped key that is not a public key of the
  snapshot. `preshared_key` is only `True`/`False` (one is set). Prefer the running state where
  the device leaves the keys out; if the only source returns them, drop them while parsing.
- `port_id` where the interface is also one of the device's ports; `addresses` are the
  device's own tunnel addresses (they are not `Subnet` objects: the tunnel is not a network of
  the site).
- `endpoint_host` is the configured endpoint or, once a handshake happened, where the peer was
  last seen; `None` when the peer connects to us. `latest_handshake` is absolute (timezone-aware).

What each integration can fill (*(guess)*: not checked against a device or the vendor's
source):

| Integration | Tunnels | Peers | Handshake, transfer |
| --- | --- | --- | --- |
| OPNsense | `/api/wireguard/service/show` `interface` rows (`if`, `public-key`, `listen-port`, `status`, instance name); addresses and MTU from the interface overview (done) | `peer` rows: `public-key`, `name`, `endpoint`, `allowed-ips`, `persistent-keepalive` (done) | `latest-handshake` (epoch), `transfer-rx`/`-tx` (done) |
| OpenWrt (done, #152) | `uci network` sections with `proto wireguard` (`listen_port`, `addresses`, `mtu`, `disabled`); `private_key` is in the same section: never copy it. Public key from `ubus call luci.wireguard getWgInstances` (luci-proto-wireguard) *(guess: method and field names per release)* | `wireguard_<iface>` sections: `public_key`, `description`, `endpoint_host`, `endpoint_port`, `allowed_ips`, `persistent_keepalive`, `disabled`; `preshared_key` only as set / not set | `getWgInstances` peers: `latest_handshake`, `transfer_rx`, `transfer_tx`, `endpoint` *(guess)* |
| MikroTik (done, #152) | `/rest/interface/wireguard` (`name`, `listen-port`, `public-key`, `mtu`, `running`, `disabled`; `private-key` is returned too: drop it); addresses from `/ip/address` and `/ipv6/address` on that interface | `/rest/interface/wireguard/peers` (`interface`, `public-key`, `endpoint-address`, `endpoint-port`, `current-endpoint-address`/`-port`, `allowed-address`, `persistent-keepalive` as a duration, `comment`/`name`, `disabled`; `preshared-key` and, on 7.15+, `private-key` for client configs: drop them) | `last-handshake` (a duration ago, `rx`, `tx`) *(guess: field names per 7.x)* |
| Linux gateway (#240) | `wireguard` links of `ip -j -d link` (port, up, MTU) and `ip -j addr`; `wg show all public-key` / `listen-port` (never `dump`, `private-key`) (done) | `wg show all peers`, `endpoints`, `allowed-ips`, `persistent-keepalive` (`off` is 0); no names, `preshared_key` not read (only `preshared-keys` would say, and it prints the keys) (done) | `latest-handshakes` (epoch, 0: none), `transfer` (done; **CI**: Debian 12 container) |
| Fritz!Box | WireGuard since FRITZ!OS 7.50; no TR-064 service known *(guess)* | — | — |
| Omada, ProSAFE / Easy Smart | none | none | none |

## Firewall and NAT (adapter API 1.4)

The `firewall` capability (#135, [ADR 0013](adr/0013-firewall-zones-rules-and-reachability.md))
reports the device's packet filter and NAT as one `Firewall`. Declare `api_version="1.4"` and
implement `ReadsFirewall`:

```python
from signalbox.model import (
    Firewall,
    FirewallAction,
    FirewallChain,
    FirewallMatch,
    FirewallProtocol,
    FirewallRule,
    FirewallZone,
    PortForward,
    PortRange,
    ZonePolicy,
    firewall_id,
    object_id,
    segment_id,
)

ACCEPT, REJECT = FirewallAction.ACCEPT, FirewallAction.REJECT


async def read_firewall(self) -> Observation:  # Capability.FIREWALL, ReadsFirewall
    d, site = self.context.device_id, self.context.site_id
    return Observation(
        firewalls=[
            Firewall(
                id=firewall_id(d),
                device_id=d,
                zones=[
                    FirewallZone(name="lan", segments=[segment_id(site, None)]),
                    FirewallZone(name="guest", segments=[segment_id(site, 30)]),
                    FirewallZone(
                        name="wan", uplinks=[object_id(d, "uplink", "wan")], masquerade=True
                    ),
                ],
                policies=[
                    ZonePolicy(source="lan", destination=None, action=ACCEPT),  # to the device
                    ZonePolicy(source="lan", destination="wan", action=ACCEPT),  # a forwarding
                    ZonePolicy(source="guest", destination=None, action=REJECT),
                    ZonePolicy(source="wan", destination=None, action=REJECT),
                ],
                input_policy=ACCEPT,  # defaults.input
                forward_policy=REJECT,  # defaults.forward
                rules=[  # in evaluation order: the first match decides
                    FirewallRule(
                        name="Allow-DNS-Guest",
                        chain=FirewallChain.INPUT,
                        protocols=[FirewallProtocol.UDP],
                        source=FirewallMatch(zones=["guest"]),
                        destination=FirewallMatch(ports=[PortRange(start=53)]),
                        action=ACCEPT,
                    ),
                ],
                port_forwards=[
                    PortForward(
                        name="nas",
                        protocols=[FirewallProtocol.TCP],
                        zones=["wan"],
                        external_ports=[PortRange(start=8443)],
                        target_address=ip_address("192.0.2.10"),
                        target_port=443,
                        passes_filter=True,  # an OpenWrt redirect needs no rule
                    )
                ],
            )
        ]
    )
```

- **Zones** are the names the device's rules use; map their interfaces to the model's
  segments, uplinks, tunnels or ports. An interface that maps to nothing known makes the zone
  `complete=False` (do not drop it silently). A rule that names a single interface (MikroTik
  `in-interface=ether1`, nftables `iifname "eth0"`) gets a zone of its own named after it.
- **Policies** are what happens when no rule decides, per pair of zones (`destination=None`:
  the device itself). Put the vendor's built-in behaviour here, not as rules: OPNsense's
  default block on every interface, RouterOS' default `accept`, OpenWrt forwardings and zone
  `input`/`forward` (intra-zone) policies, the Fritz!Box's guest isolation.
- **Rules** in the order the device evaluates them, the first match decides. Flatten what you
  can (OPNsense floating, then group, then interface rules; jumps to chains without loops).
  Leave out rules that do not filter new connections (`established,related` accept,
  `invalid` drop, `log`, `mark`, `fasttrack`). Set `exact=False` for a rule with a condition the
  model cannot express (schedule, GeoIP, connection mark, limit, user, an alias you cannot
  resolve, a non-`quick` pf rule you cannot place) and `rules_complete=False` when you know
  rules exist that you cannot read. Resolve aliases and address lists into `networks`.
- **Port forwards** with the external side (zones, address, ports) and the target; an exposed
  host (DMZ) is one without `external_ports`. `passes_filter=True` where the device lets a
  forward through by itself; else the filter rules decide (`forwarded=True` on a rule matches
  only such connections). Source NAT as `NatRule`, or `masquerade` on an OpenWrt zone.
- Keep `vendor_extra` small: no raw rule dumps (descriptions may hold host names and
  addresses the user typed; they go into `name` only).

Core answers reachability (`signalbox.firewall.reach`, `service_reach`,
`service_from_internet`); adapters never compute it. The contract checks report an id other
than `<device>/firewall`, two firewalls for one device, a zone listed twice, a zone member that
is not in the snapshot, two policies for one zone pair, rules, policies, forwards or NAT that
name an unknown zone, ports on a rule without TCP or UDP, an input rule with a destination
zone, a NAT rule without masquerade or address, and firewalls without the `firewall`
capability.

What each integration can read, and the privilege it needs (all of them are implemented, see their
pages in docs/adapters/; *(guess)*: not checked against a device or the vendor's documentation;
**CI**: read from the real software in CI):

| Integration | Zones | Filter rules and policies | NAT and port forwards | Privilege |
| --- | --- | --- | --- | --- |
| OPNsense | Every assigned interface (`lan`, `wan`, `opt1`, ...) is a zone; members from `/api/interfaces/overview/interfaces_info` (already read for subnets and uplinks); interface groups from `/api/interfaces/group_settings/...` *(guess)* are zones too, with the members' objects; WireGuard instances (`wg0`) to their tunnel | MVC rules `GET /api/firewall/filter/search_rule` (`sequence`, `enabled`, `action` pass/block/reject, `quick`, `interface`, `direction`, `ipprotocol`, `protocol`, `source_net`/`_not`/`_port`, `destination_net`/`_not`/`_port`, `description`), aliases via `/api/firewall/alias/search_item` and `/api/firewall/alias_util/list/<name>`; order: floating, group, interface; `direction out` and non-`quick` rules inexact unless placed. Rules on the legacy *Firewall: Rules* pages that the API does not list: detect (rule count from `/api/diagnostics/firewall/stats` or the pf rule list, *(guess)*) and set `rules_complete=False`. Policies: every interface → device and → other zones `drop` (pf default block), `lan` → device accept for the anti-lockout ports unless disabled, outbound pass | Destination NAT `GET /api/firewall/d_nat/search_rule` (26.x, *(guess)* for older releases: legacy port forwards then `port_forwards_complete=False`), `filter rule association` to `passes_filter`; source NAT `GET /api/firewall/source_nat/search_rule` and the outbound mode (automatic: masquerade per WAN); one-to-one NAT `/api/firewall/one_to_one/search_rule` as forwards without ports | A group with *Firewall: Rules* (API, read only), *Firewall: Aliases*, *Firewall: NAT* pages for the API user *(guess: exact privilege names per release)*; GET only, nothing that exposes the configuration backup **CI** (26.7): rule, alias and port forward added to the VM are read; the privilege ids are those of the release's ACL. |
| OpenWrt | `uci get firewall`: `zone` (`name`, `network` → the interfaces already mapped to segments/uplinks, `device`/`subnet` options make the zone `complete=False`, `masq`) | `defaults` (`input`, `forward` as fallbacks), zone `input` (zone → device) and `forward` (intra-zone), `forwarding` (`src` → `dest` accept), `rule` in section order (`src`, `dest`, `proto`, `src_ip`, `dest_ip`, `dest_port`, `family`, `target` ACCEPT/DROP/REJECT, `enabled`; `start_time`/`weekdays`/`ipset`/`mark` inexact; other targets skipped); `include` sections and `/etc/nftables.d` set `rules_complete=False` | `redirect` (`target DNAT`: `src`, `src_dport`, `dest_ip`, `dest_port`, `proto`, `src_ip`, `reflection`, `enabled`; `passes_filter=True`), `nat` sections and zone `masq` | `firewall` in the **read** `uci` list of the rpcd ACL (`/usr/share/rpcd/acl.d/signalbox.json`); the write ACL keeps leaving `firewall` out until writes are built **CI** (24.10 and 25.12): the default firewall config is read through the ACL. |
| MikroTik | `/rest/interface/list` and `/rest/interface/list/member` (lists are zones), single interfaces named by rules as zones of their own; bridge/VLAN interfaces to segments, WAN interface to the uplink | `/rest/ip/firewall/filter` and `/rest/ipv6/firewall/filter` in list order: `chain` input/forward, `action` accept/drop/reject (`jump` flattened, `passthrough`, `log`, `fasttrack-connection` skipped), `in-interface(-list)`/`out-interface(-list)` with `!`, `src-address`, `dst-address`, `src-address-list`/`dst-address-list` (via `/rest/ip/firewall/address-list`), `protocol`, `dst-port`, `connection-state` (rules only for established/related/invalid skipped), `connection-nat-state=dstnat` to `forwarded`, `disabled`, `comment`; chain policy accept; `/ip/firewall/raw` drops make rules inexact | `/rest/ip/firewall/nat`: `srcnat` masquerade/`src-nat` to `NatRule`, `dstnat` with `dst-port`, `to-addresses`, `to-ports`, `in-interface(-list)`, `dst-address-type=local` to `PortForward` (the filter decides: `passes_filter=False`) | The existing read-only group (`read`, `api`/`rest-api`) **CI** (CHR 7.25.1): a rule, masquerade and a dst-nat are read as the read-only user. |
| Linux gateway (done, **CI**: Debian 12 container) | One zone per interface named in `iifname`/`oifname` (single names, literal and named sets), mapped like the networks: segment, uplink, `wireguard` tunnel, else its port; `lo` maps to nothing, a wildcard makes the zone `complete=False` | `nft -j list ruleset`: base chains with hook `input`/`forward` (their `policy` as `input_policy`/`forward_policy`), rules in order with `iifname`/`oifname`, `ip(6) saddr/daddr`, `tcp/udp/th sport/dport`, `meta l4proto`/`nfproto`, `ct status dnat` as `forwarded`, verdicts accept/drop/reject; `ct state established,related` and `invalid` rules skipped; `jump`/`goto` to regular chains flattened (the jump's conditions merged in); conditions the model lacks (marks, limits, ICMP types, iptables-nft `xt` matches, empty or dynamic sets) make the rule `exact=False`; several base chains on one hook that cannot be merged, a verdict map, an unknown jump target, a dropping `prerouting` chain or `iptables-legacy` (or no `nft` command but iptables) give `rules_complete=False` and a gap | `nat` table: `dnat to` in prerouting to `PortForward` (`passes_filter=False`, the filter decides), `masquerade`/`snat` in postrouting to `NatRule`; `redirect` and ranges make the forwards incomplete | `nft -j list ruleset` needs `CAP_NET_ADMIN`: the sudoers line of the read user (the one for `wg`, optional, set up like the automatic setup does) allows exactly `/usr/sbin/nft -j list ruleset` with `NOPASSWD`; without it nothing is reported (not read) and a gap names the fix |
| Fritz!Box | (done, simulator and the SCPD of 7.57 and 8.02; no CI) Fixed: `lan` (the home network), `guest` (guest LAN/Wi-Fi segment where present), `wan` (the uplink) | No readable filter: policies from the box's fixed behaviour: `lan` → device and → `wan` accept; `guest` → `wan` accept, → `lan` and → device drop (DNS and DHCP accepted, *(guess)*); `wan` → device drop (services the box reports with `from_wan` stay as they are), `wan` → `lan` drop. IPv6 port sharing (pinholes) is not in TR-064 *(guess)*: `port_forwards_complete=False` always (the uplink's IPv6 is not read either) | TR-064 `WANIPConnection:1` / `WANPPPConnection:1` `GetPortMappingNumberOfEntries` and `GetGenericPortMappingEntry` (index loop: `NewRemoteHost`, `NewExternalPort`, `NewProtocol`, `NewInternalPort`, `NewInternalClient`, `NewEnabled`, `NewPortMappingDescription`), `passes_filter=True`; UPnP-created mappings appear there too *(guess)*; `X_AVM-DE_HostFilter` (`GetWANAccessByIP`) only blocks a host's internet access (a `lan` → `wan` drop rule for that address), not port sharing; exposed host *(guess: not in TR-064)* | The TR-064 user the integration already uses (*FRITZ!Box settings* right) |
| Omada | (done against the simulator; **#21**: no gateway in CI) Gateway networks (LAN interfaces / VLANs, already mapped to segments) and the WAN ports as zones | Gateway ACLs `GET …/sites/{siteId}/acls/osg-acls` (`policy` 0 drop / 1 allow, `protocols`, `sourceType`/`sourceIds` and `destinationType`/`destinationIds` (0 network; groups unresolved: inexact), `direction` `lanToWan`/`lanToLan`/`wanInIds`, `status`, `index`; custom mode `osg-custom-acls`), paths and fields confirmed in CI from `/v3/api-docs`, values *(guess)*; default inter-VLAN routing allowed, WAN in denied; switch and EAP ACLs belong to the managed devices' own `Firewall` (`complete=False` for EAP ACLs, which filter by SSID) | Port forwarding `…/nat/port-forwardings` (`externalPort`, `forwardIp`, `forwardPort`, `protocol` 0/1/2, `status`, `dMZ`; confirmed in CI), `passes_filter=True` | The viewer role of the OpenAPI client already used |
| ProSAFE / Easy Smart | none: switches without a packet filter (no `Firewall`; core treats them as not filtering) | — | — | — |

## MAC address tables (#160)

The forwarding database of a switch or bridge (#160,
[ADR 0016](adr/0016-mac-address-tables.md)): report `Observation.fdb` with `clients` (or with
`interfaces` where the integration has no client read). No API version needed.

```python
from signalbox.model import FdbEntry, FdbKind, fdb_id, port_id

FdbEntry(
    id=fdb_id(d, "lan3", "02:00:00:00:00:10", 20),  # <device>/fdb/<port>/<vlan or ->/<mac>
    device_id=d,  # a controller: the managed switch's id
    port_id=port_id(d, "lan3"),  # the physical port where the device says so
    mac="02:00:00:00:00:10",
    vlan=20,  # None: one table for all VLANs, or not said
    segment_id=segment_id(site, 20),  # only a segment the snapshot reports
    kind=FdbKind.DYNAMIC,  # STATIC (entered), SELF (the device's own address)
    age_seconds=31,  # None: not reported
)
```

- What the device keeps, unicast only, each entry once; never merged into clients. Core
  (`signalbox.fdb`) derives where a wired client is plugged in and links between managed
  devices, also through switches that are not read.
- At most `FDB_LIMIT` (2048) per device: `observe()` keeps own and static entries, then the
  newest, and adds an optional read error. Not in `GET /api/network`; `GET /api/fdb`.
- Personal data, like clients: never in MQTT, no extra fields in `vendor_extra`.

| Integration | Source | Notes |
| --- | --- | --- |
| MikroTik | `/rest/interface/bridge/host` (already read for clients): `mac-address`, `on-interface`, `vid`, `local` → `self`, `dynamic` → `dynamic`, else `static` | VLAN only where the bridge filters VLANs; `age` if present *(guess: RouterOS 7 has none)*. **CI** (CHR 7.25.1): the bridge's own entries |
| Omada | Wired clients (`switchMac`, `port`, `vid`; already read) | One `dynamic` entry per client on the managed switch's port; the switch MAC table endpoint is not used *(guess: `…/switches/{mac}/mac-table` not in the Open API)* |
| Linux gateway | `bridge -j -s fdb show` as the read user (netlink, no root) | Entries with a `master` only (the bridge's table, not a port's own address list), `permanent` → `self`, `static` → `static`, `updated` → age. **CI**: a static entry on the Debian 12 target |
| OpenWrt | not read | No rpcd method exposes the bridge FDB; `/sys/class/net/<bridge>/brforward` is binary, has no VLAN, needs `brif/*/port_no` and a wider ACL. The read ACL is unchanged |
| OPNsense | not read | No API for the bridge address cache (`ifconfig bridge0 addr`); ARP gives the interface only (`Client.seen_on`, which core counts for devices without a table) |
| ProSAFE / Easy Smart | not read | NSDP and the Easy Smart protocol have no MAC table on the supported models; Switchyard reads none |
| Fritz!Box | not read | The host list has no per-port data |
