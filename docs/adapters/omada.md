# TP-Link Omada adapter

Reads one site of a TP-Link Omada controller (Software Controller, OC200/OC300 hardware
controller or Omada Cloud-Based Controller reachable over HTTPS) through its **Open API**: the
gateway's LAN networks and DHCP, the switches' ports and VLANs, the access points' radios and
SSIDs, and the clients. Read only; every request except the token request is a `GET`.

| | |
| --- | --- |
| Adapter id | `omada` |
| Roles | `other` (recommended: the controller), `ap`, `switch`, `gateway` |
| Capabilities | interfaces, DHCP, wireless, clients |
| Simulator | `signalbox.sim.omada` (`uvicorn --factory signalbox.sim.omada:create_app`) |

| Capability | What is read |
| --- | --- |
| system | controller version (`/api/info`), site lookup |
| interfaces | LAN networks → segments; gateway subnets; switch ports with their profile (native network untagged, tagged networks) |
| dhcp | DHCP settings of each LAN network (range, lease time, DNS, gateway, domain) |
| wireless | radios of every EAP; SSIDs of its WLAN group per band (security, VLAN, hidden, PMF) |
| clients | wired and wireless clients with address, network and where they were seen (switch port or EAP WLAN) |

> **Not yet confirmed on a real controller.** The endpoint paths and JSON shapes below are a best
> effort from TP-Link's Omada Open API documentation (controller 5.9 and later), not from a
> recorded answer. Shapes marked *(guess)* are the least certain. Real-device validation is
> [issue #21](https://github.com/PhilippMundhenk/signalbox/issues/21). Parsing is tolerant: a
> missing field is left empty, unknown fields are ignored, and an answer of the wrong shape
> becomes a readable "could not read" finding (`unexpected answer from <endpoint>: ...`).

## One Signalbox device for the whole site (limitation)

An Omada controller manages many devices, but a Signalbox adapter instance reports one device.
Until the model can carry several devices per observation
([#46](https://github.com/PhilippMundhenk/signalbox/issues/46)), the adapter works like this:

- The Signalbox device you add with adapter `omada` stands for the controller's **site**. Its
  device is the controller itself (give it the role `other`); vendor `TP-Link`, model `Omada
  Controller`, firmware the controller version.
- The ports, radios, WLANs, subnets and DHCP servers of the managed devices all belong to this
  one Signalbox device. Their ids carry the configured device id and a slug of the managed
  device, `<type>-<mac>`: `omada1/switch-020000000b01/port/3`,
  `omada1/eap-020000000c01/radio/5g`, `omada1/eap-020000000c01/wlan/<ssidId>-2g`,
  `omada1/gateway-020000000a01/subnet/<networkId>`.
- Each of these objects has the managed device's identity in `vendor_extra["omada_device"]`:
  `name`, `model`, `mac`, `firmware`, `type` (`gateway`, `switch`, `eap`). The UI shows it on
  the advanced tab; rules do not read it. Port names start with the switch name
  (`Switch Port3`), radio names with the EAP name (`AP 1 5 GHz`).

So the device list and the topology show the controller, not the individual EAPs and switches,
and rules that compare devices (firmware, channels between access points) see one device.

## Setup

1. In the controller: *Global View > Settings > Platform Integration > Open API*, add an
   application in **Client** mode with the **Viewer** role (read only) and access to the site
   you want to read. Note the *Client ID*, *Client Secret* and the *Omada ID* shown there.
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

Every answer is wrapped:

```json
{"errorCode": 0, "msg": "Success.", "result": {...}}
```

| Answer | Signalbox |
| --- | --- |
| `errorCode` 0 | `result` is used |
| `-44112` (token expired), `-44113` (token invalid) | requests a new token **once** and repeats the request; refused again: "the controller refused the access token" for that capability |
| any other non-zero `errorCode` from the token request | device status auth-failed: "the controller refused the client credentials: ... Omada error <code>: <msg>" |
| any other non-zero `errorCode` | "<path>: Omada error <code>: <msg>" for that capability (device status partial) |
| HTTP 401/403/404, invalid JSON, other shape | the usual messages of `DeviceHttp`, or "unexpected answer from <path>" |

Lists are paged: Signalbox asks for `page=1..n&pageSize=100` and follows `totalRows` (also when the
controller returns smaller pages than asked for); a plain list instead of a page object is
accepted too.

```json
{"totalRows": 5, "currentPage": 1, "currentSize": 100, "data": [{...}, ...]}
```

## Endpoints and the JSON they return

`{omadacId}` is the controller id, `{siteId}` the id of the configured site; `{mac}` is a device MAC
as the controller writes it (`AA-BB-CC-DD-EE-FF`).

### `GET /api/info` (no authentication)

```json
{"controllerVer": "5.14.26", "apiVer": "3", "configured": true, "type": 1, "omadacId": "0123…"}
```

### `POST /openapi/authorize/token?grant_type=client_credentials`

Body `{"omadacId": "…", "client_id": "…", "client_secret": "…"}` →

```json
{"accessToken": "AT-…", "tokenType": "bearer", "expiresIn": 7200, "refreshToken": "RT-…"}
```

A new token is requested at the start of every observation; requests carry
`Authorization: AccessToken=<accessToken>`. The refresh token is not used.

### `GET /openapi/v1/{omadacId}/sites` (paged)

`[{"siteId": "…", "name": "Default", ...}]`: the site whose `name` is the configured `site`.

### `GET /openapi/v1/{omadacId}/sites/{siteId}/devices` (paged)

```json
{"mac": "02-00-00-00-0B-01", "name": "Switch", "type": "switch", "model": "TL-SG2008P",
 "ip": "192.0.2.2", "status": 1, "firmwareVersion": "1.0.5", "wlanId": "…"}
```

`type` `gateway`, `switch` or `ap`. `wlanId` (the WLAN group of an EAP) is a *(guess)*; without it
the primary WLAN group is used.

### `GET …/sites/{siteId}/lan-networks` (paged)

```json
{"id": "…", "name": "IoT", "purpose": "interface", "vlan": 20, "gatewaySubnet": "198.51.100.1/24",
 "domain": "…",
 "dhcpSettings": {"enable": true, "ipaddrStart": "198.51.100.100", "ipaddrEnd": "198.51.100.150",
                  "leasetime": 1440, "dhcpns": "manual", "priDns": "198.51.100.1",
                  "sndDns": "192.0.2.53", "gateway": "198.51.100.1"}}
```

- Each network is the segment `<site>/segment/<vlan>`; VLAN 1 is the native segment.
- `gatewaySubnet` becomes a subnet with `gateway: true` (the gateway's address on it).
- `dhcpSettings` becomes a DHCP server: pool `ipaddrStart`–`ipaddrEnd`, lease time `leasetime`
  in **minutes** *(guess)*, router `gateway` (else the gateway address), DNS `priDns`/`sndDns`
  when `dhcpns` is `manual`, else the gateway address *(guess)*.

### `GET …/sites/{siteId}/lan-profiles` (paged, optional) *(guess)*

```json
{"id": "…", "name": "All", "nativeNetworkId": "…", "tagNetworkIds": ["…", "…"]}
```

### `GET …/sites/{siteId}/switches/{mac}/ports` (paged or a list)

```json
{"port": 3, "name": "Port3", "profileId": "…", "profileName": "All", "disable": false,
 "linkStatus": 1, "linkSpeed": 3, "duplex": 2, "poe": true,
 "nativeNetworkId": "…", "tagNetworkIds": ["…"]}
```

- The port's native network is a member **untagged**, its tagged networks **tagged**. Port-level
  `nativeNetworkId` / `tagNetworkIds` win over the profile's (an override of the profile).
- `linkStatus` 1 is up. `linkSpeed` codes *(guess)*: 1 = 10, 2 = 100, 3 = 1000, 4 = 2500,
  5 = 10000, 6 = 5000 Mbit/s; `duplex` *(guess)*: 1 half, 2 full.

### `GET …/sites/{siteId}/eaps/{mac}/radios` (optional) *(guess)*

```json
{"radioSetting2g": {"radioEnable": true, "channel": "6", "channelWidth": "20", "txPower": 20},
 "radioSetting5g": {"radioEnable": true, "channel": "36", "channelWidth": "80", "txPower": 23}}
```

Keys `radioSetting2g`, `radioSetting5g`, `radioSetting5g2` (tri-band), `radioSetting6g`. Channel
0/`auto` is reported as unknown; a width that is not a plain MHz number is dropped. If the
endpoint is missing, the radios are derived from the bands of the SSIDs (channel and power
unknown).

### `GET …/sites/{siteId}/wireless-network/wlans` and `…/wlans/{wlanId}/ssids` (paged)

```json
{"wlanId": "…", "name": "Default", "primary": true}
{"ssidId": "…", "name": "Home", "band": 3, "security": 3, "broadcast": true,
 "vlanEnable": true, "vlanId": 20, "pmfMode": 2,
 "pskSetting": {"versionPsk": 2, "encryptionPsk": 3}}
```

- One WLAN per SSID and radio of every EAP that uses the WLAN group; `band` is a bit mask
  (1 = 2.4 GHz, 2 = 5 GHz, 4 = 6 GHz).
- `security` *(guess for everything but 0 and 3)*: 0 open, 1 OWE, 2 enterprise (`entSetting.versionEnt`
  4 = WPA3), 3 personal with `pskSetting.versionPsk` 2 or 3 = WPA2, 4 = WPA3, 1 (WPA only) =
  other; anything else (PPSK) is other.
- `vlanEnable`/`vlanId` gives the segment (only when such a LAN network exists; otherwise the VLAN
  is in `vendor_extra`). `broadcast: false` is hidden. `pmfMode` *(guess)*: 1 required,
  2 optional, 3 disabled.
- The passphrase is normally **not** returned by the Open API, so `passphrase_fingerprint` is
  empty. If an answer carries `pskSetting.securityKey`, only its fingerprint is kept.

### `GET …/sites/{siteId}/clients` (paged)

```json
{"mac": "02-00-00-00-00-21", "name": "laptop", "hostName": "laptop", "ip": "192.0.2.100",
 "ipv6List": ["2001:db8:1::21"], "wireless": true, "ssid": "Home", "apMac": "02-00-00-00-0C-01",
 "radioId": 1, "vid": 1, "networkName": "LAN", "lastSeen": 1767225600000}
{"mac": "02-00-00-00-00-10", "wireless": false, "switchMac": "02-00-00-00-0B-01", "port": 5, "vid": 1}
```

- Segment from `vid`, else from `networkName`. Where it was seen: a wired client's switch port;
  a wireless client's WLAN on that EAP, from `radioId` *(guess: 0 = 2.4 GHz, 1 = 5 GHz,
  2 = second 5 GHz, 3 = 6 GHz)* and `ssid`.
- `lastSeen` is in milliseconds since 1970. A `name` that is just the MAC is no host name.
- The controller's own managed devices are not reported as clients.

## Simulator

`signalbox.sim.omada` answers these endpoints with a neutral site: a gateway, one 8-port switch
with three port profiles and a port override, two EAPs, LAN 192.0.2.0/24 (native), IoT VLAN 20
198.51.100.0/24, Guest VLAN 30 (VLAN only), three SSIDs and five clients. Failure switches: bad
client secret, a token that expires once, an error code on one endpoint, slow answers, broken
JSON, small pages.
