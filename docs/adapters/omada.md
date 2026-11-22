# TP-Link Omada adapter

Reads one site of a TP-Link Omada controller (Software Controller, OC200/OC300 hardware
controller or Omada Cloud-Based Controller reachable over HTTPS) through its **Open API**: the
gateway's LAN networks and DHCP, the switches' ports and VLANs, the access points' radios and
SSIDs, and the clients. It can also change the site through the controller: LAN networks and
their DHCP, switch ports, SSIDs ([Changing the site](#changing-the-site)).

| | |
| --- | --- |
| Adapter id | `omada` |
| Roles | `other` (recommended: the controller), `ap`, `switch`, `gateway` |
| Capabilities | interfaces, DHCP, wireless, clients |
| Writes | router, dhcp, port, wlan (through the controller) |
| Simulator | `signalbox.sim.omada` (`uvicorn --factory signalbox.sim.omada:create_app`) |

| Capability | What is read |
| --- | --- |
| system | controller version (`/api/info`), site lookup |
| interfaces | LAN networks → segments; gateway subnets; switch ports with their profile (native network untagged, tagged networks) |
| dhcp | DHCP settings of each LAN network (range, lease time, DNS, gateway, domain) |
| wireless | radios of every EAP; SSIDs of its WLAN group per band (security, VLAN, hidden, PMF) |
| clients | wired and wireless clients with address, network and where they were seen (switch port or EAP WLAN) |

> **Verified against Omada Controller 6.3.0.111 in CI.** What the controller holds itself
> (sites, LAN networks, DHCP, port profiles, WLAN groups and SSIDs, the token, roles and
> refusals) is checked every night against TP-Link's Omada Software Controller, the official
> Linux package in Docker, set up through its own first-start wizard:
> tests/integration/test_omada_real.py, set up by tools/integration/omada/
> ([Integration tests](#integration-tests)). Answers about **managed devices** (switch ports,
> EAP radios, clients, the device list) cannot be recorded without hardware: their paths and
> fields follow the controller's own Open API description (`/v3/api-docs`) of that version and
> are marked *(API description)*; they are tested against the simulator only. Parsing stays
> tolerant: a missing field is left empty, unknown fields are ignored, and an answer of the wrong
> shape becomes a readable "could not read" finding (`unexpected answer from <endpoint>: ...`).

## The controller and the devices it manages

The Signalbox device you add with adapter `omada` stands for the controller's **site** (give it
the role `other`): vendor `TP-Link`, model `Omada Controller`, firmware the controller version.
The gateway, switches and access points the controller manages are reported as devices of their
own (adapter API 1.1, [ADR 0004](../adr/0004-controllers-report-several-devices.md)), with ids
`<configured device>/<type>-<mac>`, for example `omada1/switch-020000000b01`, and their ports,
radios, WLANs, subnets and DHCP servers belong to them: `omada1/switch-020000000b01/port/3`,
`omada1/eap-020000000c01/radio/5g`. They appear under *Devices*, *Managed through a
controller*, in the topology and in every rule; they need no settings of their own. A site
without a gateway: the controller itself owns the networks' subnets and DHCP servers
(`omada1/gateway/subnet/…`), and router and DHCP changes go to it.

## Setup

1. In the controller: *Global View > Settings > Platform Integration > Open API*, add an
   application in **Client** mode with the **Viewer** role (read only) and access to the site
   you want to read. Note the *Client ID*, *Client Secret* and the *Omada ID* shown there.
   To deploy changes, give it the **Admin** role for the site instead; with the viewer role
   every change is refused by the controller (`-1007`).
2. In Signalbox add a device with adapter `omada`, role `other`:

```yaml
adapter: omada
url: https://192.0.2.5:8043     # controller address and its HTTPS management port
omadac_id: ""                   # Omada ID; empty: read from /api/info
site: Default                   # name of the site to read
client_id: "..."
client_secret: "..."            # stored encrypted
```

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | | controller, `https://host:port` (Software Controller: 8043; OC200/OC300: 443) |
| `omadac_id` | empty | the controller id (`omadacId`); empty: read from `/api/info` |
| `site` | `Default` | site name (exact, or case-insensitive if no exact match) |
| `client_id` | | client id of the Open API application |
| `client_secret` | | its secret; stored encrypted, never sent back to the UI |
| `allow_insecure_http` | `false` | accept an `http://` URL; the secret then crosses the network in clear text (simulator only) |

Add one Signalbox device per Omada site you want to see.

## Certificate pinning

The controller ships a self-signed certificate. On the first connection Signalbox shows its
SHA-256 fingerprint (the device is "untrusted certificate"); compare it with the certificate in
your browser and confirm it. From then on it is pinned; a changed certificate stops reading
until it is confirmed again. Nothing, the client secret included, is sent before the pinned
certificate was presented (`signalbox.adapters.https.DeviceHttp`, see
[ADAPTERS.md](../ADAPTERS.md)).

## Protocol

Every answer is wrapped (a write that creates nothing has no `result`):

```json
{"errorCode": 0, "msg": "Success.", "result": {...}}
```

| Answer | Signalbox |
| --- | --- |
| `errorCode` 0 | `result` is used |
| `-44112` ("The access token has expired", also the answer to a token the controller never issued), `-44113` (invalid) | requests a new token **once** and repeats the request; refused again: "the controller refused the access token" for that capability |
| HTTP 401 with `-44116` | no access token at all |
| `-44106` from the token request ("The Client Id Or Client Secret is Invalid.", also for a wrong `omadacId`) | device status auth-failed: "the controller refused the client credentials: ... Omada error -44106: ..." |
| any other non-zero `errorCode` | "<path>: Omada error <code>: <msg>" for that capability (device status partial); for example `-1505` (no permission for the site), `-33503` (no such network), `-39303` (no such AP), `-39050` (no such device) |
| HTTP 400/404/405 | Tomcat's own HTML page: a query without `page`/`pageSize`, an unknown path, a wrong method |

Lists are paged: Signalbox asks for `page=1..n&pageSize=100` (the controller takes 1 to 1000)
and follows `totalRows` (also when the controller returns smaller pages than asked for); a plain
list instead of a page object is accepted too (the WLAN groups are one).

```json
{"totalRows": 5, "currentPage": 1, "currentSize": 100, "data": [{...}, ...]}
```

## Endpoints and the JSON they return

`{omadacId}` is the controller id, `{siteId}` the id of the configured site; `{mac}` is a device MAC
as the controller writes it (`AA-BB-CC-DD-EE-FF`).

### `GET /api/info` (no authentication)

```json
{"controllerVer": "6.3.0.111", "apiVer": "3", "configured": true, "type": 1, "supportApp": true,
 "omadacId": "0123…", "registeredRoot": true, "omadacCategory": "advanced", "mspMode": false}
```

### `POST /openapi/authorize/token?grant_type=client_credentials`

Body `{"omadacId": "…", "client_id": "…", "client_secret": "…"}` →

```json
{"accessToken": "AT-…", "tokenType": "bearer", "expiresIn": 7200, "refreshToken": "RT-…"}
```

A new token is requested at the start of every observation; requests carry
`Authorization: AccessToken=<accessToken>`. The refresh token is not used.

### `GET /openapi/v1/{omadacId}/sites` (paged)

`[{"siteId": "…", "name": "Default", "region": "…", "timeZone": "UTC", "scenario": "Home",
"type": 0, "primary": false, ...}]`: the site whose `name` is the configured `site`.
Its `timeZone` (`"UTC"` on a new controller, as Omada Software Controller 6.3 answers in the
integration tests of #140) is the time zone of the controller device (time): the zone the
site's devices run on.

### `GET /openapi/v1/{omadacId}/sites/{siteId}/devices` (paged) *(API description)*

```json
{"mac": "02-00-00-00-0B-01", "name": "Switch", "type": "switch", "model": "TL-SG2008P v1.0",
 "modelName": "TL-SG2008P", "ip": "192.0.2.2", "status": 1, "firmwareVersion": "1.0.5"}
```

`type` `gateway`, `switch` or `ap`. The WLAN group of an EAP is not in this list (the API
description names a field `wlan group id` in the AP's own answer); without it the primary WLAN
group is used, `wlanId` is taken when present.

Health of each managed device, from the same rows: `cpuUtil` (%), the uptime from `uptimeLong`
(seconds) or the text `uptime` (`"12day(s) 3h 4m 5s"`, `"2 days 04:05:06"`). The field names are
those of the controller's own API description (6.3: `cpuUtil`, `memoryUtil`, `uptimeLong` on
the device details); the CI site has no devices, so the values are not confirmed. `memUtil` is
a percentage without the memory size and is not reported (the model holds bytes). *Guess*:
`temp` or `temperature` (°C, one sensor `device`), `fanStatus` and `powerStatus` (a fan `fan`,
a power supply `power`), read only when they are words that leave no doubt (`normal`,
`abnormal`, `ok`, `fault`, ...). The controller itself has an empty health: the Open API does
not describe the machine it runs on.

Time: the controller's clock is the `Date` header of `GET /api/info` (whole seconds, read with
the round trip as uncertainty), its zone the site's `timeZone`. The managed devices take their
time from the controller; their clocks and the site's NTP settings are not in the endpoints read
here, so the NTP client and server stay unknown.

### `GET …/sites/{siteId}/lan-networks` (paged)

```json
{"id": "…", "name": "Lab", "purpose": 1, "interfaceIds": ["2_…", "3_…"], "vlanType": 0,
 "vlan": 40, "application": 0, "gatewaySubnet": "203.0.113.1/24", "igmpSnoopEnable": false,
 "dhcpSettingsVO": {"enable": true, "ipaddrStart": "203.0.113.100", "ipaddrEnd": "203.0.113.199",
                    "ipRangeStart": 3405803776, "ipRangeEnd": 3405804031, "dhcpns": "manual",
                    "priDns": "203.0.113.1", "sndDns": "198.51.100.53", "leasetime": 1440,
                    "options": []},
 "allLan": true, "primary": false, ...}
```

- `purpose` is a number: 0 VLAN only (no `gatewaySubnet`, no DHCP), 1 interface.
- The v1 list has the DHCP settings as `dhcpSettingsVO` with one range; the network's own
  answer (`…/lan-networks/{id}`) and the v3 list call them `dhcpSettings`, with a list of
  ranges `ipRangePool`. Signalbox reads both.
- Each network is the segment `<site>/segment/<vlan>`; VLAN 1 is the native segment. The
  controller always has one: "Default" (`primary: true`, 192.168.0.1/24 until changed).
- `gatewaySubnet` becomes a subnet with `gateway: true` (the gateway's address on it).
- The DHCP settings become a DHCP server: pool `ipaddrStart`–`ipaddrEnd` (every range of
  `ipRangePool`), lease time `leasetime` in **minutes** (2 to 2880; the controller's default is
  120), router `gateway` (else the gateway address), DNS `priDns`/`sndDns` when `dhcpns` is
  `manual`, else the gateway address. What the controller leaves of removed DHCP settings
  (`{"enable": false, …}` without a range) is no DHCP server.

### `GET …/sites/{siteId}/lan-profiles` (paged)

```json
{"id": "…", "flag": 0, "name": "All", "poe": 2, "nativeNetworkId": "…",
 "tagNetworkIds": ["…", "…"], "untagNetworkIds": ["…"], "type": 0, ...}
```

The controller has "All" (`type` 0: every network tagged), "Default" and "Disable", and makes
one profile per network it gets (`flag` 1, named like the network).

### `GET …/sites/{siteId}/switches/{mac}` → `portList` *(API description)*

There is no list of ports of its own (`…/switches/{mac}/ports` is HTTP 404); the ports are the
`portList` of the switch:

```json
{"port": 3, "name": "Port3", "profileId": "…", "profileName": "All", "disable": false,
 "linkStatus": 1, "linkSpeed": 3, "duplex": 2, "poe": true, "profileOverrideEnable": false,
 "nativeNetworkId": "…", "tagNetworkIds": ["…"]}
```

- The port's native network is a member **untagged**, its tagged networks **tagged**. Port-level
  `nativeNetworkId` / `tagNetworkIds` win over the profile's (an override of the profile).
- `linkStatus` 1 is up. `linkSpeed`: 1 = 10, 2 = 100, 3 = 1000, 4 = 2500, 5 = 10000,
  6 = 5000, 7 = 25000, 8 = 100000 Mbit/s; `duplex`: 1 half, 2 full.
- Port details (#156): `profileName` is the port profile, `disable` the admin state (a disabled
  port is down), the PVID the VLAN of the native network. `maxSpeed` *(guess: the field and
  that it uses the `linkSpeed` codes)* is the maximum speed.
- `jumbo` of the switch itself *(guess)*, next to `portList`: the largest frame the switch
  forwards (1518, the default, to 9216); above 1518 every port of the switch has jumbo frames
  on. Without the field, jumbo frames are unknown.

### `GET …/sites/{siteId}/gateways/{mac}/wan-status` (optional) *(API description)*

The gateway's ports with their WAN state, a plain list (not paged), with the fields of the
controller's API description (6.3, recorded by tools/integration/omada/dump.py `spec`):

```json
[{"port": 1, "name": "SFP WAN", "type": 0, "mode": 0, "status": 1, "internetState": 1,
  "proto": "DHCP", "ip": "203.0.113.45", "speed": 3,
  "wanPortIpv4Config": {"ip": "203.0.113.45", "netmask": "255.255.255.0",
   "gateway": "203.0.113.1", "priDns": "203.0.113.53", "sndDns": "203.0.113.54"},
  "wanPortIpv6Config": {"enable": 1, "addr": "2001:db8:ffff::45", "gateway": "fe80::1",
   "priDns": "2001:db8:ffff::53", "sndDns": ""}}]
```

Each port in WAN mode (`mode` 0; `type` 0 WAN, 1 WAN/LAN, 2 LAN) is an uplink of the gateway,
`<device>/gateway-<mac>/uplink/port<n>` (#148). Kind from `proto` ("Static IP, DHCP, PPPoE,
L2TP, PPTP, DS-Lite, and MAP-E" in the description; L2TP and PPTP are `other`), down when
`status` is 0, else up from `internetState`; the addresses from `wanPortIpv4Config`
(`ip`/`netmask`) and `wanPortIpv6Config` (`addr`, while `enable` is not 0), the gateway and
`priDns`/`sndDns` of both. No uptime, no delegated prefix and no public address in the answer;
`speed` is the port's Ethernet rate, and the DSL fields (`maxRxRate`, `maxTxRate`) have no unit in
the description, so neither is read as the line rate. A refused answer leaves the uplinks out.
*To confirm with a gateway (#21): the spelling of `proto` and of `addr` (with or without a prefix
length).*

### `GET …/sites/{siteId}/aps/{mac}/radio-config` (optional) *(API description)*

```json
{"radioSetting2g": {"radioEnable": true, "channel": "6", "channelWidth": "2", "txPower": 20},
 "radioSetting5g": {"radioEnable": true, "channel": "36", "channelWidth": "5", "txPower": 23}}
```

Keys `radioSetting2g`, `radioSetting5g`, `radioSetting5g1` and `radioSetting5g2` (tri-band),
`radioSetting6g`. `channelWidth` is a code: 2 = 20, 3 = 40, 5 = 80, 7 = 160, 10 = 320 MHz;
4, 6 and 8 are "auto" (unknown). Channel 0 is auto (unknown). An unknown AP answers `-39303`;
if there are no radio settings, the radios are derived from the bands of the SSIDs (channel and
power unknown).

### `GET …/sites/{siteId}/wireless-network/wlans` and `…/wlans/{wlanId}/ssids` (paged)

```json
{"wlanId": "…", "name": "Default", "primary": true, "clone": false, "site": "…", "resource": 0}
{"ssidId": "…", "id": "…", "name": "IoT", "ssidEnable": true, "band": 1, "guestNetEnable": false,
 "security": 3, "broadcast": false, "vlanEnable": true, "vlanId": 20, "vlanPoolIds": "20"}
```

The SSID list leaves out the security settings; Signalbox reads every SSID's own answer
`…/ssids/{ssidId}` too:

```json
{"ssidId": "…", "name": "Home", "band": 3, "security": 3, "broadcast": true, "vlanEnable": false,
 "vlanSetting": {"mode": 0, "customConfig": {}}, "mloEnable": false, "pmfMode": 2,
 "enable11r": false, "deviceType": 1, "ssidEnable": true, "apGroupIds": ["…"],
 "pskSetting": {"securityKey": "…", "versionPsk": 2, "encryptionPsk": 3,
                "gikRekeyPskEnable": false}}
```

- One WLAN per SSID and radio of every EAP that uses the WLAN group; `band` is a bit mask
  (1 = 2.4 GHz, 2 = 5 GHz, 4 = 6 GHz).
- `security`: 0 none (OWE when `oweEnable` is true), 2 WPA-Enterprise (`entSetting.versionEnt`
  4 = WPA3, 1 and 3 = WPA-Enterprise *(guess: codes 1 and 3)*, 2 = WPA2), 3 WPA-Personal with
  `pskSetting.versionPsk` 1 = WPA, 2 = WPA2, 3 = WPA/WPA2 *(guess: 3)*, 4 = WPA2/WPA3 (WPA3-SAE
  alone for a 6 GHz-only SSID); 4 and 5 (PPSK) are other.
- Security details (#167), personal SSIDs: `pskSetting.encryptionPsk` 1 auto (`tkip` and
  `ccmp`), 2 TKIP, 3 AES (`ccmp`) *(guess: codes 1/2/3; the integration test confirms 3 on the
  CI controller)*; `pskSetting.gikRekeyPskEnable` `false` is `key_rotation_seconds` 0 (confirmed
  by CI), `true` with `rekeyPskInterval` is that interval *(guess: field name; without it not
  reported)*. No SAE settings, no WPS (EAPs have none), no group cipher, no beacon protection
  and no `supported_security` in the Open API. `passphrase_digest` is computed next to the
  fingerprint from `pskSetting.securityKey`.
- `vlanEnable`/`vlanId` gives the segment (only when such a LAN network exists; otherwise the VLAN
  is in `vendor_extra`). `broadcast: false` is hidden. `pmfMode`: 1 mandatory (required),
  2 capable (optional), 3 disabled; an open SSID has none. `ssidEnable` is on or off.
  `guestNetEnable: true` is the Omada guest network: the SSID gets the purpose `guest` (source
  `reported`), and the guest Wi-Fi check trusts the controller to keep it out of the local
  networks. Client isolation is not read.
- The SSID's answer **has the passphrase** (`pskSetting.securityKey`); only its fingerprint is
  kept (`passphrase_fingerprint`), so a passphrase in the desired state is verified. With
  `hidePwd: true` the key is hidden *(API description)*: then no fingerprint, and a revert
  trusts only a passphrase Signalbox deployed itself.

### `GET …/sites/{siteId}/clients` (paged) *(API description)*

```json
{"mac": "02-00-00-00-00-21", "name": "laptop", "hostName": "laptop", "ip": "192.0.2.100",
 "ipv6List": ["2001:db8:1::21"], "wireless": true, "ssid": "Home", "apMac": "02-00-00-00-0C-01",
 "radioId": 1, "vid": 1, "networkName": "LAN", "lastSeen": 1767225600000}
{"mac": "02-00-00-00-00-10", "wireless": false, "switchMac": "02-00-00-00-0B-01", "port": 5, "vid": 1}
```

- Segment from `vid`, else from `networkName`. Where it was seen: a wired client's switch port;
  a wireless client's WLAN on that EAP, from `radioId` (0 = 2.4 GHz, 1 = 5 GHz (-1), 2 = 5 GHz-2,
  3 = 6 GHz) and `ssid`.
- `lastSeen` is in milliseconds since 1970. A `name` that is just the MAC is no host name.
- The controller's own managed devices are not reported as clients.

## DHCP leases, options and relay (#183)

Not read. The Open API has no lease table, and the DHCP settings of a LAN network are mapped
only as far as they are confirmed: the real controller's answer has `options: []` inside
`dhcpSettingsVO` (see the example above), but neither the shape of an option nor a relay mode
is in anything checked yet. The integration dump now records the controller's own
`/v3/api-docs` description of the LAN network lists and details (`tools/integration/omada/dump.py`),
so the fields of options 60/66/138 and the relay mode can be confirmed from the next CI run;
until then `DhcpServer.options` and `DhcpRelay` stay empty for Omada.

## Changing the site

The gateway, switches and EAPs are devices of their own in Signalbox, so the desired state names
them (`omada1/gateway-020000000a01`, `omada1/switch-020000000b01`, ...); on a site without a
gateway the networks belong to the controller (`gateway: {device: omada1, ...}`). The
deployment sends their changes to the controller's adapter: *Allow changes* is set on the
controller device, and the application needs the Admin role (see [Setup](#setup)). The
controller provisions the devices by itself, some seconds later; Signalbox verifies what the
**controller** reports after the change (which is what it reads anyway), not the devices. There
is no confirm timer: a change that does not read back as planned is undone from the backup.

| Kind | Device | Calls |
| --- | --- | --- |
| `router` | the gateway (the controller itself when the site has no gateway) | new network: `POST …/lan-networks` with `name`, `purpose: 1`, `vlanType: 0`, `vlan`, `gatewaySubnet`, `igmpSnoopEnable`, `interfaceIds` (those of the native network, else those the controller gave another network) and `dhcpSettingsVO` when the same change adds DHCP; answer `{"id": …}`. Changed: `PATCH …/lan-networks/{id}` with the **whole** network as listed and the changes (the controller refuses a partial one: `-1001` "Parameter [purpose] should not be empty"). Removed: `DELETE …/lan-networks/{id}`, or, while a port, port profile or SSID still uses the VLAN, `PATCH` to a VLAN-only network (`purpose: 0`, no `gatewaySubnet`, no DHCP). The built-in profile "All" and the network's own profile do not count as a use. |
| `dhcp` | the gateway | `dhcpSettingsVO` of the network in the same call: `enable`, `ipaddrStart`/`ipaddrEnd`, `leasetime` (minutes), DNS: exactly the gateway address → `dhcpns: auto`, otherwise `manual` with `priDns`/`sndDns`; removed: `dhcpSettingsVO: null` |
| `port` | a switch | `PATCH …/switches/{mac}/ports/{port}` *(API description)* with `nativeNetworkId`, `tagNetworkIds` and the port profile with exactly these networks (`profileId`, `profileOverrideEnable: false`), or, when no profile matches, `profileOverrideEnable: true` (an override on the port) |
| `wlan` | an EAP | the SSID in the EAP's WLAN group. New: `POST …/wlans/{wlanId}/ssids` with `name`, `deviceType: 1`, `band: 3`, `guestNetEnable`, `security`, `broadcast`, `vlanEnable`/`vlanId`, `mloEnable`, `pmfMode`, `enable11r`, `hidePwd`, `ssidEnable` and `pskSetting` (`versionPsk`, `encryptionPsk: 3`, `gikRekeyPskEnable`, `securityKey`); answer `{"ssidId": …}`. Changed: `PATCH …/ssids/{ssidId}/update-basic-config` with the whole basic configuration (a `PATCH …/ssids/{ssidId}` is HTTP 405; the controller refuses a partial one with `-1001`, and needs `securityKey` with every WPA change), on or off: `PATCH …/wireless-network/ssids/{ssidId}/enable` `{"ssidEnable": …}`. Removed: `DELETE …/ssids/{ssidId}` |

- **An SSID belongs to the WLAN group**, not to one EAP: creating, changing or removing it
  changes every EAP of the group. The review names them ("in WLAN group Default (EAPs AP 1,
  AP 2)"). When a deployment has the same SSID for several EAPs of one group, the first one
  changes it and the others find it already done.
- **Passphrases** come from the desired state's secrets; the review and the change log show
  `***`. Without a new passphrase an SSID keeps its key (the controller answers it, and it is
  sent back with the change). An SSID that goes to open loses its key; back to WPA needs one.
- Security that can be set: open, WPA2, WPA2/WPA3 (`versionPsk` 2 and 4). WPA3 alone is refused
  (the controller sets it only for 6 GHz-only SSIDs), OWE too: the controller takes `oweEnable`
  but does not answer it, so it cannot be verified. Enterprise needs a RADIUS profile and is
  refused, as are 802.11r/k/v and client isolation (not read, so not verifiable). The guest
  network flag is not written.
- Refused before anything is sent: a network without a name, removing the native network, DHCP
  on a network without a gateway address, more than two DNS servers, lease times that are not
  whole minutes, a port without an untagged network or with VLAN 1 tagged, a VLAN the
  controller has no network for (a port or SSID on VLAN 40 needs the LAN network of VLAN 40
  first: a segment with a gateway; within one plan the gateway comes first), a WPA SSID without
  a passphrase, a passphrase that is not 8 to 63 characters.
- Refused by the controller, with its code in the message ("the controller refused: … Omada
  error <code>: <msg>"), which fails the device's step: a VLAN used twice (`-34517`), a subnet
  that overlaps another network's (`-33502` "This range of IP address already exists."), an
  interface network without LAN interfaces (`-33515`), an SSID name used twice (`-33219`), a
  passphrase the controller does not take (`-33223`); with a permission error (`-1007` for the
  viewer role) the message names the Admin role. A network with a domain the controller does not
  take as one (`lan.example`) is refused too (`-1001`).
- **Backup** (`omada-openapi-json`, stored encrypted): the LAN networks, the SSIDs of every WLAN
  group with their settings (passphrases included) and the ports of every switch, as the
  controller answers them. **Restore** compares them with the controller: networks are patched
  (the whole network) or created again (a network deleted meanwhile gets a new id, and the ports
  that used it are pointed at it), ports patched, SSIDs changed back (`update-basic-config`, the
  passphrase included, and `enable`), created or deleted, networks created since deleted last.
  Port profiles, reservations and everything else are not touched.

## Integration tests

`tools/integration/omada/controller.py` runs on the GitHub Actions runner only (job
`Integration / Omada`), never locally; tests/integration/test_omada_real.py skips without
`IT_OMADA_URL` (and fails in CI, `REQUIRE_INTEGRATION`).

- **The controller**: `mbentley/omada-controller:6.3.0.111`, pinned by digest, a maintained
  community image that installs TP-Link's official Linux package unchanged; it answers
  `/api/info` some 40 seconds after the start.
- **Setup** through the calls of the controller's own web UI (read from its scripts): the
  administrator (`POST /{omadacId}/api/v2/anon/register`), the first-start wizard
  (`POST /{omadacId}/api/v2/anon/cmd/wizardConfig`: controller name, site "Default", device
  account), the login (`POST /{omadacId}/api/v2/login`, then the `Csrf-Token` header and the
  session cookie), the roles (`GET /{omadacId}/api/v2/roles-available`: Super Admin, Admin,
  Viewer) and two Open API applications in client mode for all sites
  (`POST /{omadacId}/api/v2/open-api/applications` `{"name", "mode": 1, "permission":
  {"roleId", "sitePrivilege": 0}}`), one Viewer, one Admin. The rest through the Open API with
  the Admin application: the native network on 192.0.2.1/24 with DHCP, VLAN-only networks 20 and
  30, an interface network 40 with DHCP, a port profile, three SSIDs.
- **Recorded answers**: `tools/integration/omada/dump.py` posts the controller's answers as
  `::notice::` annotations of the job (viewer reads, SSID and network details, refusals, the
  managed-device fields of the API description).
- **What is tested**: certificate pinning with the real certificate, the read contract and the
  mapping of the site (no managed devices: segments, subnets and DHCP servers of the controller),
  SSIDs and port profiles through the parser, a wrong secret (`-44106` → auth-failed), an
  unknown site, an unknown token renewed once (`-44112`), the viewer role refused (`-1007`);
  through the Deployer: a new network with DHCP and its revert, the native network's address and
  another network's DHCP changed and reverted, a VLAN-only network given a gateway and the
  restore of the backup taken before; a refusal with the controller's code; SSIDs created,
  changed (security, PMF, hidden, VLAN, passphrase), switched off and deleted through the write
  module for a stand-in EAP, and the restore of a backup after an SSID was opened and another
  deleted. **Simulator only** (no hardware in CI): switch ports, EAP radios, clients and the
  device list.

Found on the real controller and fixed in the adapter and the simulator (they were guesses
before): `purpose` is a number, not `interface`/`vlan`; the v1 network list has
`dhcpSettingsVO`, the detail `dhcpSettings` with `ipRangePool`; a network `PATCH` needs the
whole network; a new interface network needs `interfaceIds`; removed DHCP settings stay as
`{"enable": false}`; the SSID list has no security settings, the SSID detail has them and the
passphrase; SSIDs change through `update-basic-config` (a `PATCH` of the SSID is HTTP 405) and
are switched on and off through `…/ssids/{id}/enable`; the SSID's state is `ssidEnable`;
`security` 1 is not OWE (OWE is `oweEnable` and is not answered), `versionPsk` 3 is WPA/WPA2
and 4 is WPA2/WPA3 (there is no 5); an open SSID has no `pmfMode`; the permission error is
`-1007` (not `-1005`), the role is called Admin; an unknown token reads as expired (`-44112`), no
token is HTTP 401 `-44116`; the controller deletes a network an SSID or profile still uses
(Signalbox makes it VLAN only instead) and refuses overlapping subnets (`-33502`); the built-in
"All" profile has every network. From the controller's own API description (no hardware to
record): an EAP's radio settings are `…/aps/{mac}/radio-config` (not `…/eaps/{mac}/radios`,
HTTP 404) with `channelWidth` as a code, a switch's ports are the `portList` of
`…/switches/{mac}` (`…/switches/{mac}/ports` is HTTP 404), `linkSpeed` 8 is 100 Gbit/s.

## Simulator

`signalbox.sim.omada` answers these endpoints like the controller above, with a neutral site: a
gateway (WAN port 1 on DHCP, port 2 a PPPoE WAN that is down, port 3 in LAN mode), one 8-port switch with three port profiles and a port override, two EAPs, LAN
192.0.2.0/24 (native), IoT VLAN 20 198.51.100.0/24, Guest VLAN 30 (VLAN only), three SSIDs and
five clients. Failure switches: bad client secret, a token that expires once, an error code on
one endpoint, slow answers, broken JSON, small pages. It also takes the writes above and
refuses what the controller does, with its codes (a missing field, a VLAN used twice, an
overlapping subnet, an interface network without LAN interfaces, an SSID name used twice, a bad
passphrase, an unknown network or profile on a port); failure switches for writes:
`read_only` (a viewer-role application) and an error code per path.


## Management services (#173)

Read with the `interfaces` capability, from two site settings that the controller applies to
every device it manages; each managed device (`Observation.devices`) gets the same two services:

- `GET /openapi/v1/{omadacId}/sites/{siteId}/ssh`: `sshEnable`, `sshServerPort`. `layer3Access`
  (off: SSH only from the management network) is not mapped, the management VLAN is not read.
- `GET /openapi/v1/{omadacId}/sites/{siteId}/setting/service/snmp`: `snmpV1V2CEnable`,
  `snmpV3Enable`, `securityLevel` (2 is authPriv: `v3_privacy`) and `communityString`, which is
  only compared with `public`/`private` and never stored.

*Verified against Omada 6.3 in CI*: both paths and all fields are in the controller's own
`/v3/api-docs` and answer to the viewer application (`securityLevel`: 0 NoAuthNoPriv, 1
AuthNoPriv, 2 AuthPriv; a site with both versions off answers only `snmpV1V2CEnable`,
`snmpV3Enable`, `location`, `contact`). The test site has no managed device, so which devices
apply the settings is a *guess* until a real site is read (#21). A site setting the controller
refuses or does not have leaves its service out; the controller's own web interface and cloud
access are not read (no Open API call). `transport_encrypted` is true for https.
