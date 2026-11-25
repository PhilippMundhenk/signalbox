# AVM Fritz!Box adapter

Reads an AVM Fritz!Box (FRITZ!OS 7) over TR-064, AVM's SOAP interface for applications, on its
HTTPS port `49443`. It can also change the DHCP server and the existing Wi-Fi networks
(see [Writing](#writing)), only when changes are allowed (see [CHANGES.md](../CHANGES.md)).

| | |
| --- | --- |
| Adapter id | `fritzbox` |
| Roles | `gateway`, `ap` |
| Capabilities | interfaces, DHCP, wireless, clients, firewall (fixed policies and port sharing) |
| Writes | `dhcp` (LAN), `wlan` (existing SSIDs only) |
| Simulator | `signalbox.sim.fritzbox` (`uvicorn --factory signalbox.sim.fritzbox:create_app`), built from AVM's service descriptions |

> Every action and argument below is checked against AVM's TR-064 descriptions
> (`tr64desc.xml` and the SCPD files of FRITZ!OS 7.57 and 8.02, in `tests/fixtures/tr064/`,
> see [Checked against AVM's service descriptions](#checked-against-avms-service-descriptions)).
> The descriptions fix names, data types and allowed values; what the box *does* with a call
> (and which fault code it gives for what) still needs confirmation on a real device (#21).
> Points marked *(guess)* are the least certain.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | | the box's address, for example `fritz.box` or `192.0.2.1`; Signalbox uses `https://<box>:49443` (another port only if the box reports one, see below) |
| `username` | empty | the Fritz!Box user (see below); empty when the box asks only for its password: Signalbox then reads the user name from the box (see [Password-only login](#password-only-login-373)) |
| `password` | | its password; stored encrypted, never sent back to the UI |
| `allow_insecure_http` | `false` | accept an `http://` URL; meant for simulators, nothing is encrypted then |

## Setting up the Fritz!Box

1. *Home Network > Network > Network Settings > Home Network Sharing* (German: *Heimnetz > Netzwerk > Netzwerkeinstellungen > Heimnetzfreigaben*): switch on
   **Allow access for applications** (this is TR-064). The HTTPS port is shown there; it is
   `49443` unless changed.
2. *System > FRITZ!Box Users*: add a user only for Signalbox, for example `signalbox`, with a
   long password. Give it the right **FRITZ!Box settings** and nothing else; *Access from the
   internet* stays off. TR-064 has no read-only right: the user can change settings through
   TR-064; Signalbox only does so for a deployed change on a device with *Allow changes*. Keep
   the password in Signalbox only. A box set to log in with its password only: see
   [Password-only login](#password-only-login-373).
3. Add the device in Signalbox with the box's address (`fritz.box` or its IP address); the
   form completes it to `https://<box>:49443`. If nothing answers TR-064 there, Signalbox asks
   the box for its TR-064 port on `http://<box>:49000` (the one action AVM answers without
   login, no credentials are sent) and names the address to use. On the first connection Signalbox
   shows the fingerprint of the box's self-signed certificate; compare it (the browser shows it
   for `https://<box>:49443`) and trust it.

The Wi-Fi passphrases are read only to compute a fingerprint (`passphrase_fingerprint`, so
access points can be compared); the passphrase itself is never stored. If the user lacks the
right for `GetSecurityKeys` (UPnP error 606), wireless is reported as "could not read" with a
message naming the right; everything else is still read.

## FRITZ!OS versions (#413, part of #389)

Supported: the current major version (8.x) and the two before it (7.x, 6.x). Real boxes in
use run 6.x and 7.x. Every action below is read with a fallback or as an optional gap: a missing
action never fails the whole read. `FritzboxSim(release="6.83" | "7.29" | "7.57" | "8.02")`
serves the descriptions of that release without the actions it lacks.

| FRITZ!OS | Descriptions | CI | What differs |
| --- | --- | --- | --- |
| 8.x | real (8.02) | simulator, contract tests | spelling `None` of the open beacon type |
| 7.57 | real | simulator, contract tests | `LANConfigSecurity GetInfo` has `NewX_AVM-DE_IsDefaultPasswordActive` |
| 7.29 | real (FRITZ!Box 7530 AX dump) | simulator, contract tests | no `NewX_AVM-DE_IsDefaultPasswordActive` (default-password state stays unknown); no `NewX_AVM-DE_FrequencyBand` in `WLANConfiguration GetInfo`/`GetChannelInfo` (the band comes from the channel), no `NewX_AVM-DE_AutoChannelEnabled`, no `NewX_AVM-DE_WLANGlobalEnable`; the login page `?version=2` exists |
| 6.x (6.83) | derived from 7.29, **guesses** | simulator, contract tests | login page version 1 only (see below); no `LANConfigSecurity X_AVM-DE_GetUserList`/`X_AVM-DE_GetCurrentUser` (optional gap "accounts: FRITZ!OS 6.83 has no user list"); no `X_AVM-DE_GetWLANExtInfo` (guest WLAN = the last one); no `X_AVM-DE_GetHostListPath` (host table entry by entry); no WPA3 beacon types (`WPA3`, `11iandWPA3`, `OWE`) |

None of these versions is tested on a real box in CI; the 7.29 descriptions are a real
box's, the 6.83 ones are derived (`tests/fixtures/tr064/SOURCES.md`). The FRITZ!OS version is
read from `DeviceInfo:1 GetInfo` (`NewSoftwareVersion`, for example `154.07.57` is 7.57); the
last two numbers are the release.

Login page: `/login_sid.lua?version=2` (the user list of [password-only
login](#password-only-login-373)) exists from FRITZ!OS 7.24. Before that the box ignores the
parameter and answers the version 1 page (a challenge for the MD5 login, no `<Users>`); a box
that refuses the parameter (404) is asked again for `/login_sid.lua`. A version 1 page has no
user list, so with an empty user name the empty name stays and the error says the page cannot
name the user (a box of that age without users often accepts `dslf-config` *(guess)*). With a
configured user name nothing is looked up.

### Guesses to confirm on real boxes (#21)

- Which actions FRITZ!OS 6.83 lacks (the user list and current user, `X_AVM-DE_GetWLANExtInfo`,
  `X_AVM-DE_GetHostListPath`) and that it has no WPA3: AVM's pages with the version of each
  action could not be reached, so the 6.83 files are the 7.29 ones minus these. A box that has
  them is used with them; one that lacks others is handled by the same fallbacks.
- That a 6.x box answers `/login_sid.lua?version=2` with the version 1 page (not 404); both are
  handled.
- That `dslf-config` is the TR-064 user of a 6.x box without users.
- The `NewSoftwareVersion` spelling of a 6.x box (`113.06.83`).
- The layout of the user list and rights on 7.x (see [Accounts](#accounts-175)).

## Password-only login (#373)

Even if the box asks only for a password in its web interface, it has a user (since
FRITZ!OS 7.24 every box does; in this mode it is created automatically, `fritz` and four
digits, for example `fritz0000`). TR-064 needs that name: an empty user name gets HTTP 401.

Even if the box asks only for a password, it usually has a user: look under *System >
FRITZ!Box Users* (German: *System > FRITZ!Box-Benutzer*), or open
`https://<box>/login_sid.lua?version=2` in a browser, and enter that name with the same
password. This is the manual way to find the name.

If you leave the user name empty, Signalbox looks it up itself before the first TR-064 call:
`GET /login_sid.lua?version=2` on the box's web port (https 443 with the pinned certificate)
answers without a login and lists `<Users><User last="1">fritz0000</User></Users>`; the
user marked `last="1"`, or the only one, is used. The password is never sent to that page. If the
lookup fails, the error says so and names the page. With a user name, a 401 is explained
too: the user needs the right *FRITZ!Box settings* (German: *FRITZ!Box Einstellungen*), the
name is case-sensitive, and after several failed logins the box blocks further attempts for a
while.

## Certificate pinning and authentication

The Fritz!Box presents a self-signed certificate. At the start of every observation Signalbox
opens one TLS connection without sending anything, reads the certificate and compares its
SHA-256 fingerprint with the pinned one; not pinned yet, or different: the device is reported as
`untrusted-certificate` and nothing else is sent. The SOAP requests then go over a TLS context
whose only trust anchor is the pinned certificate. This is the shared helper
`signalbox.adapters.https.DeviceHttp` (see [ADAPTERS.md](../ADAPTERS.md)).

Authentication is HTTP Digest (MD5, `qop=auth`): the first request is answered with `401` and a
challenge such as `Digest realm="HTTPS Access",nonce="0123456789ABCDEF",algorithm=MD5,qop="auth"`,
then every request carries the digest. The realm is taken from the challenge: `HTTPS Access`
over HTTPS (port 49443), `F!Box SOAP-Auth` over plain HTTP (port 49000, only used with
simulators) *(both seen in other TR-064 clients' tests; AVM's "TR-064 First Steps" could not be
fetched to confirm them, see below)*. Wrong user or password: `401` again, the device is
reported as `auth-failed`. `tr64desc.xml` and the SCPD files are served without
authentication.

## Protocol

Every action is a `POST` to the control URL of its service:

```
POST /upnp/control/deviceinfo
SOAPAction: "urn:dslforum-org:service:DeviceInfo:1#GetInfo"
Content-Type: text/xml; charset="utf-8"

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body><u:GetInfo xmlns:u="urn:dslforum-org:service:DeviceInfo:1"/></s:Body>
</s:Envelope>
```

The answer is `<u:GetInfoResponse>` with one element per output argument, or HTTP 500 with a SOAP
fault:

```xml
<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
  <UPnPError xmlns="urn:dslforum-org:control-1-0">
    <errorCode>606</errorCode><errorDescription>Action Not Authorized</errorDescription>
  </UPnPError></detail></s:Fault>
```

| Answer | Signalbox |
| --- | --- |
| `<Action>Response` | the output arguments are used |
| fault `401` Invalid Action | "action not supported by this FRITZ!OS"; for `WLANConfiguration<n>` the end of the list, for the host list path the entry-by-entry fallback |
| fault `402` Invalid Args, `501` Action Failed, `600` Argument Value Invalid, `601` Argument Value Out of Range, `713`/`714` no such entry, `820` internal error | "`<service> <action>`: UPnP error ..." for that capability |
| fault `606` Action Not Authorized | "not authorised: the Fritz!Box user lacks the right for this action" |
| HTTP 401 / 403 | `auth-failed` |
| HTTP 404 | "not found" (for `wlanconfig<n>`: no such WLAN) |
| not XML, no SOAP body, no `<Action>Response` | "unexpected answer" / "not valid XML" |
| a `<!DOCTYPE` or `<!ENTITY` anywhere | refused before parsing ("contains a DTD or entity declaration"): no device answer needs one, and refusing them rules out entity expansion |

Services and control URLs:

| Service | Control URL |
| --- | --- |
| `DeviceInfo:1` | `/upnp/control/deviceinfo` |
| `LANHostConfigManagement:1` | `/upnp/control/lanhostconfigmgm` |
| `LANEthernetInterfaceConfig:1` | `/upnp/control/lanethernetifcfg` |
| `WLANConfiguration:1`..`4` | `/upnp/control/wlanconfig1`..`4` |
| `Hosts:1` | `/upnp/control/hosts` |
| `Time:1` | `/upnp/control/time` |

## Actions and the arguments they return

### `DeviceInfo:1 GetInfo` (system)

`NewManufacturerName`, `NewModelName`, `NewSoftwareVersion` (for example `154.07.57`) become
vendor, model and firmware. The serial number and the device log in the same answer are not kept.
`NewUpTime` (seconds) is the uptime (health); it is all TR-064 tells about the box's health:
CPU, memory and temperatures are only on the web interface's pages, which Signalbox does not
read.

### `Time:1 GetInfo` (time)

The arguments and their data types are those of AVM's service description `timeSCPD.xml`
(FRITZ!OS 7.57 and 8.02, identical; in `tests/fixtures/tr064/`, so the simulator serves the
action and checks the answer's types). *Guess*: the values of the zone fields, which the
description does not show (no real Fritz!Box in CI):

```
NewNTPServer1          ntp.example.net
NewNTPServer2
NewCurrentLocalTime    2026-11-22T17:12:00+01:00
NewLocalTimeZone       CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00
NewLocalTimeZoneName   CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00
NewDaylightSavingsUsed 1
```

`NewCurrentLocalTime` is the clock with its UTC offset (whole seconds: the middle of the second,
half a second more uncertainty; a time without an offset is not used). The zone is
`NewLocalTimeZoneName`, else `NewLocalTimeZone`, as the box reports it. The NTP servers are the
NTP client's (the Fritz!Box always synchronises; whether it is in sync is not reported). Whether
the Fritz!Box serves time to the LAN (*Heimnetz > Netzwerk > Zeitsynchronisation*) is not in
TR-064, so the NTP server stays unknown.

### `LANEthernetInterfaceConfig:1 GetInfo`, `GetStatistics` (interfaces)

`NewEnable` (the port's admin state), `NewStatus` (`Up`), `NewMACAddress`, `NewMaxBitRate`
(Mbit/s or `Auto`), `NewDuplexMode` (`Full`, `Half`, `Auto`); statistics `NewBytesSent`,
`NewBytesReceived`, `NewPacketsSent`, `NewPacketsReceived` go into `vendor_extra`.

`NewMaxBitRate` is the interface's *maximum* bit rate (TR-064's `MaxBitRate`: 10, 100, 1000 or
`Auto`; AVM's description only says it is a string), not the speed of a link: it is reported as
`max_speed_mbps`, `Auto` as auto-negotiation, and the port has no `speed_mbps` (TR-064 has no
link rate for the LAN side). Before #156 it was reported as the link speed. *To confirm on a
real box*: what FRITZ!OS answers here (a number or `Auto`).

Port structure (#252): TR-064 names no LAN jack and no bridge. The one `LANEthernetInterfaceConfig`
is the LAN side as a whole, so it keeps no role (reporting it as a jack or a bridge would be a
guess, and a role would take it out of the link checks); the WLAN services name no interface
either, so `Wlan.port_id` stays empty. Jacks and the LAN bridge are not filled.

TR-064 describes the LAN side as one interface: the switch ports LAN 1-4 are not listed
individually in AVM's documentation *(to confirm: some FRITZ!OS versions may offer an
`X_AVM-DE_` action per port)*. The adapter therefore reports one bridge port `lan`, the only
member (untagged) of the native segment `<site>/segment/native`.

### `LANHostConfigManagement:1 GetInfo` (interfaces, DHCP)

```
NewDHCPServerEnable 1           NewMinAddress 192.0.2.20      NewMaxAddress 192.0.2.200
NewIPRouters 192.0.2.1          NewSubnetMask 255.255.255.0   NewDNSServers 192.0.2.1
NewDomainName fritz.box         NewDHCPRelay 0                NewReservedAddresses
```

- The subnet of the native segment is the first `NewIPRouters` with `NewSubnetMask`; with role
  `gateway` the Fritz!Box is its gateway. *(guess: in IP-client mode, role `ap`, `NewIPRouters`
  may name the upstream router instead of the box.)*
- One DHCP server on the native segment: enabled from `NewDHCPServerEnable`, the pool
  `NewMinAddress`-`NewMaxAddress` (also while the server is off: the box keeps the range),
  router, DNS servers (comma-separated list) and domain.
- When `GetInfo` leaves fields empty, `GetIPRoutersList`, `GetSubnetMask` and `GetAddressRange`
  are read as a fallback.
- **Reservations** ("always assign this IPv4 address") are not exposed by TR-064, so the DHCP
  server never lists any. The lease time is not exposed either.

### `WANPPPConnection:1 GetInfo`, `WANIPConnection:1 GetInfo`, `WANCommonInterfaceConfig:1 GetCommonLinkProperties` (interfaces: the uplink)

```
WANPPPConnection:1 GetInfo   NewEnable 1   NewConnectionStatus Connected   NewUptime 7200
  NewConnectionType IP_Routed   NewName internet   NewExternalIPAddress 203.0.113.45
  NewRemoteIPAddress 203.0.113.1   NewDNSServers 203.0.113.53, 203.0.113.54   (and more)
WANCommonInterfaceConfig:1 GetCommonLinkProperties   NewWANAccessType DSL
  NewLayer1DownstreamMaxBitRate 116790000   NewLayer1UpstreamMaxBitRate 46719000
  NewPhysicalLinkStatus Up
```

With role `gateway` the internet connection is one uplink `<device>/uplink/internet` (#148),
from the service whose `NewEnable` is `1`, PPP first. The three actions are read with the same
right; a fault or a missing service leaves the uplink (or its line rate) out, the rest is read.

**Behind another router** ("Internetzugang über LAN 1", "existing access via LAN", #375): the
box's internet side is LAN 1 with an address in the front router's network. Only actions that
FRITZ!OS 6.8x already has are used: `WANIPConnection:1` `GetInfo` and `GetExternalIPAddress`,
`Layer3Forwarding:1`. When `GetInfo` of `WANIPConnection` has no address and PPP is not
enabled, `GetExternalIPAddress` is asked; a `WANIPConnection` with an address is the uplink
even with `NewEnable` `0`. The upstream gateway is the next hop of an enabled `0.0.0.0/0`
entry of `GetGenericForwardingEntry` (which then is the default route, listed once). The
topology finds the front router by that address and draws the link (see DESIGN.md, Topology).
Neither enabled and no address: no access configured, no uplink.
*To confirm on a real box (#21)*: whether LAN 1 mode reports `WANIPConnection` enabled with the
LAN 1 address in `GetInfo`, disabled with it only in `GetExternalIPAddress`, or neither (then
no uplink is read); whether `Layer3Forwarding` lists the default route with the front
router as gateway; the `NewWANAccessType` in that mode (assumed `Ethernet`).

- **Kind**: `pppoe` on `WANPPPConnection`; on `WANIPConnection` `other`, because TR-064 does
  not say whether the address is from DHCP or fixed; `lte` for the access types
  `X_AVM-DE_LTE`/`X_AVM-DE_UMTS`; `bridge` for `NewConnectionType` `IP_Bridged` (no address).
- **State**: up when `NewConnectionStatus` is `Connected`; `since` is the read time minus
  `NewUptime` (seconds).
- **Addresses**: `NewExternalIPAddress` as /32 (TR-064 gives no prefix length); the PPP peer
  `NewRemoteIPAddress` is the upstream gateway (`WANIPConnection` has none: the default
  route's next hop, see above); `NewDNSServers` the
  provider's resolvers. The PPP user name in the same answer is not kept.
- **Line rate**: `NewLayer1DownstreamMaxBitRate`/`NewLayer1UpstreamMaxBitRate` in bit/s, reported
  in kbit/s (0: not known). `NewWANAccessType`, `NewConnectionType` and `NewPhysicalLinkStatus`
  go into `vendor_extra`.
- **Not read**: IPv6 (addresses, delegated prefix) and DS-Lite are only in the IGD services of
  `/igdupnp/` (`X_AVM_DE_GetExternalIPv6Address`, `X_AVM_DE_GetIPv6Prefix`,
  `X_AVM_DE_GetDsliteStatus`), which answer only with "status information over UPnP" switched on
  and whose descriptions are not in the fixtures yet; a DS-Lite line therefore shows as kind
  `other` without an IPv4 address. `X_AVM-DE_WANMobileConnection:1` (signal, provider) is not read.
- *To confirm on a real box (#21)*: the format of `NewDNSServers` on a WAN connection (read as
  a comma-separated list like the LAN one), `NewEnable` of the connection a box does not use,
  and what `NewExternalIPAddress` holds on a DS-Lite line.

### `WLANConfiguration:<n> GetInfo`, `X_AVM-DE_GetWLANExtInfo`, `GetSecurityKeys` (wireless)

Services `WLANConfiguration:1` to `:4` are tried in order until one answers 404 or fault 401.
AVM numbers them 1 = 2.4 GHz, 2 = 5 GHz, then (on a tri-band box) the second 5 GHz or 6 GHz
radio, and the guest network last.

`GetInfo`: `NewEnable`, `NewStatus`, `NewSSID`, `NewChannel`, `NewStandard` (`n`, `ac`, `ax`),
`NewBSSID`, `NewBeaconType`, `NewX_AVM-DE_PossibleBeaconTypes`, `NewX_AVM-DE_FrequencyBand`
(`2400`, `5000`, `6000`).

- **Band**: `NewX_AVM-DE_FrequencyBand`; without it the channel (above 14: 5 GHz); without that
  the index.
- **Guest network**: `X_AVM-DE_GetWLANExtInfo` `NewX_AVM-DE_APType` `guest` *(guess)*; when the
  action is missing, the last WLAN of a box with three or more is the guest WLAN. The guest WLAN
  is in its own segment `<site>/segment/guest` (no VLAN, no ports; `vendor_extra` says it is the
  Fritz!Box guest network) and uses the radio of its band; it is not a radio of its own. That
  segment and the guest WLAN have the purpose `guest` (source `reported`), and the segment is
  `isolated` (the box keeps guests out of the LAN). It has no subnet in the model (TR-064 does
  not report the guest addresses); `wifi.segment-at-gateway` treats it as served by the box.
  Whether guests may reach each other is not read.
- **Security** from `NewBeaconType`:

  | `NewBeaconType` | Security |
  | --- | --- |
  | `None` (FRITZ!OS 8), `none` (FRITZ!OS 7.57) | open |
  | `Basic` | WEP with `NewBasicEncryptionModes` `WEPEncryption`, open with `None`, else other |
  | `WPA` | WPA (version 1) |
  | `11i` | WPA2 |
  | `WPAand11i` | WPA/WPA2 mixed |
  | `WPA3` | WPA3 |
  | `11iandWPA3` | WPA2/WPA3 |
  | `OWE`, `OWETrans` | OWE |

- `GetSecurityKeys` `NewKeyPassphrase` becomes the passphrase fingerprint and, next to it,
  `passphrase_digest` (personal security only).
- Security details (#167): `Radio.supported_security` from `NewX_AVM-DE_PossibleBeaconTypes`
  (mapped like `NewBeaconType`, unknown words left out). `wps` for personal networks from
  `X_AVM-DE_GetWPSInfo`: `NewX_AVM-DE_WPSStatus` `off` is WPS disabled, any other status is
  enabled, and `NewX_AVM-DE_WPSMode` `pbc` is the push button *(guess: that `off` means
  disabled; the description lists `other`, `stop`, `pbc` and the statuses but not their
  meaning)*; fault 401 leaves it unreported. WEP networks have the cipher `wep`. **Not
  available**: `NewWPAEncryptionModes` is not in the `WLANConfiguration` description of
  FRITZ!OS 7.57, 8.02 or 8.25 (checked against the SCPD files in
  `tests/fixtures/tr064/`, and the 8.25 file of udondan/fritz), so there are no ciphers for WPA
  networks (`X_AVM-DE_GetWLANExtInfo` `NewX_AVM-DE_EncryptionMode` has no documented values),
  no group cipher, no SAE settings, no rekey interval and no beacon protection.
- **Hidden**: `GetBeaconAdvertisement` `NewBeaconAdvertisementEnabled` `0`; without the
  action (fault 401) the SSID counts as broadcast.
- PMF and 802.11r/k/v are not read *(not documented for TR-064)*.
- Radio capabilities and state (#172): `standard` from `NewStandard`; `GetChannelInfo`
  `NewPossibleChannels` (`supported_channels`, `dfs_capable` on 5 GHz) and
  `NewX_AVM-DE_AutoChannelEnabled` (`channel_auto`); `client_count` the sum of
  `GetTotalAssociations` of the WLANs on the radio (the guest WLAN counts on the radio of its
  band). A refused action (any fault) leaves the field unreported. Not available over TR-064:
  supported standards and widths, utilisation, noise, DFS state *(the action list of the
  SCPD files in `tests/fixtures/tr064/`)*.

- **BSSID** (#169): `NewBSSID` is `Wlan.bssid`. Neighbouring networks: TR-064 has no action
  for the box's list of neighbouring Wi-Fi networks (the web UI's *Funkkanal* page), so none
  are read.

### `Hosts:1` and `WLANConfiguration:<n> GetGenericAssociatedDeviceInfo` (clients)

- Stations: `GetTotalAssociations`, then `GetGenericAssociatedDeviceInfo` for every
  `NewAssociatedDeviceIndex`: `NewAssociatedDeviceMACAddress`, `NewAssociatedDeviceIPAddress`.
  A station is seen on that WLAN, in the guest segment for the guest WLAN.
- Host table: `X_AVM-DE_GetHostListPath` gives `NewX_AVM-DE_HostListPath`, a path such as
  `/devicehostlist.lua?sid=...` that is fetched with `GET` from the same host. It must be a path;
  anything else (a URL to another host) is refused. The XML:

  ```xml
  <List><Item><Index>1</Index><IPAddress>192.0.2.50</IPAddress><AddressSource>DHCP</AddressSource>
    <LeaseTimeRemaining>86400</LeaseTimeRemaining><MACAddress>02:00:00:00:10:01</MACAddress>
    <InterfaceType>Ethernet</InterfaceType><Active>1</Active><HostName>printer</HostName></Item></List>
  ```

  Without that action (fault 401): `GetHostNumberOfEntries`, then `GetGenericHostEntry` for
  every `NewIndex` with the same fields (`NewMACAddress`, `NewIPAddress`, ...).
- Only active hosts (`Active` 1) become clients: the Fritz!Box remembers hosts that left long
  ago. Ethernet hosts are seen on the `lan` port. Host name, address, `InterfaceType` and
  `AddressSource` are kept.

## DHCP leases and relay (#183)

The box has no lease table over TR-064. The host list (`Hosts:1`, read once per observation
for DHCP and clients) is the nearest: every host with `AddressSource` `DHCP` and an IPv4 address
is a lease of the one DHCP server. An active host is `active` with `expires` = observation +
`LeaseTimeRemaining` (no `expires` when that is 0), a remembered inactive host is `expired`
*(guess: how a box counts down and whether it keeps expired entries)*; `reserved` and the
client id are not known. When the host list cannot be read the leases are `None`, the server is
still read. `LANHostConfigManagement:1 GetInfo` `NewDHCPRelay` true is a relay in the native
segment with no server address (TR-064 does not give it) *(guess: ever true on a box)*. No
options, boot or authoritative: TR-064 has none. Nothing here is checked against a real box.

## Writing

What maps cleanly onto TR-064 and is therefore declared in `Manifest.writes`: **`dhcp`** of the
LAN and **`wlan`** for the SSIDs the box already has. The action names, arguments and values
below are checked against AVM's service descriptions; their effect still needs confirmation on a
real device (#21). The simulator implements exactly this.

| Change | TR-064 actions |
| --- | --- |
| DHCP on/off | `LANHostConfigManagement:1 SetDHCPServerEnable` (`NewDHCPServerEnable` `0`/`1`) |
| DHCP pool | `LANHostConfigManagement:1 SetAddressRange` (`NewMinAddress`, `NewMaxAddress`) |
| SSID (rename) | `WLANConfiguration:<n> SetSSID` (`NewSSID`) |
| security | `WLANConfiguration:<n> SetBeaconType` (`NewBeaconType`: open `None`, WPA2 `11i`, WPA3 `WPA3`, WPA2/WPA3 `11iandWPA3`, spelled as the box lists them in `NewX_AVM-DE_PossibleBeaconTypes`) |
| passphrase | `WLANConfiguration:<n> SetSecurityKeys` (`NewWEPKey0`..`3` and `NewPreSharedKey` empty, `NewKeyPassphrase`) *(guess: that empty WEP/PSK arguments are accepted)* |
| hidden | `WLANConfiguration:<n> SetBeaconAdvertisement` (`NewBeaconAdvertisementEnabled` `0` hides) |
| on/off | `WLANConfiguration:<n> SetEnable` (`NewEnable`) |

- Only what differs from what the box reports now is sent. Switching something on comes last,
  switching it off first (DHCP: the range is set before the server is switched on).
- A WLAN change applies to every `WLANConfiguration<n>` that has the SSID of the change's old
  value, so "Example" on 2.4 and 5 GHz is changed on both. A rename is an update of the same
  index (`SetSSID`); a later change finds it by its new name. The planner keys WLANs by SSID,
  so a new name in the desired state is planned as a *create* (refused); a rename is an update
  change whose new value carries the other SSID.
- **Refused before anything is sent** (with a message saying why): creating an SSID (the Wi-Fi
  networks of a Fritz!Box are fixed: one per band and the guest network), removing one (set
  `enabled: false` instead), a VLAN (`segment` other than `native`), PMF, 802.11r/k/v, client
  isolation,
  security other than open, WPA2, WPA3 and WPA2/WPA3 (or a beacon type the box does not list in
  `NewX_AVM-DE_PossibleBeaconTypes`), an SSID or passphrase outside the limits the box reports in
  `GetInfo` (`NewMinCharsSSID`/`NewMaxCharsSSID`, at most 32 bytes; `NewMinCharsPSK`/
  `NewMaxCharsPSK`, never outside 8-63); for DHCP a DHCP
  server other than the LAN's, removing it, a lease time, other DNS servers (TR-064 cannot set
  what the box announces; it always announces itself), IPv6 pools. `router`, `reservation` and
  `port` changes are not offered (changing the box's own LAN address is not done over TR-064 by
  Signalbox; reservations and VLANs do not exist in TR-064).
- The passphrase comes from the secret named in `passphrase_secret`; review and change records
  show it as `***`, it is never logged, and error messages never contain it.
- A UPnP fault on a write becomes "`<what>`: refused by the Fritz!Box (`<service> <action>`:
  UPnP error ...)"; the deployer then restores the backup.

**No confirm timer.** TR-064 applies each action at once and has neither a transaction nor a
rollback timer, so `apply` returns `confirm_deadline: None`. The deployer verifies by reading
again and rolls back itself when something is wrong.

**Backup** (format `fritzbox-tr064-values`): a JSON document with the TR-064 values of every
setting the adapter may change, read just before the change:

```json
{"format": "fritzbox-tr064-values",
 "lan": {"NewDHCPServerEnable": "1", "NewMinAddress": "192.0.2.20", "NewMaxAddress": "192.0.2.200"},
 "wlans": {"1": {"NewSSID": "Example", "NewBeaconType": "11iandWPA3", "NewEnable": "1",
                 "NewBeaconAdvertisementEnabled": "1", "NewKeyPassphrase": "..."}, "...": {}}}
```

It holds the passphrases (when the user may read them), so a restore also puts the old key back;
backups are stored encrypted and their content never leaves the server. **Restore** sets these
values back with the same actions, only where they differ. A full configuration export
(`DeviceConfig:1 X_AVM-DE_GetConfigFile`) is not used: it needs an export password, it can only
be imported as a whole (with a reboot, cutting off the network), and it is more than a change
of a few settings needs.

Undoing a passphrase change through *Revert* plans the inverse change, which has no secret: the
new passphrase stays (restore the backup to get the old one back).

## Not available

- **DNS**: the Fritz!Box resolves names for its clients, but TR-064 exposes neither its
  forwarders nor local host records, so the adapter has no DNS capability.
- **Neighbours (LLDP)**: FRITZ!OS does not speak LLDP.
- **DHCP reservations, lease time, VLANs, per-port LAN state**: not in TR-064 (see above).
- **IPv6 and DS-Lite of the uplink**: only over the IGD services (see the uplink above).
- **Filter rules, IPv6 port sharing, exposed host (DMZ)**: not in TR-064 *(guess)*, see
  [Firewall](#firewall-135).

## Checked against AVM's service descriptions

`tests/fixtures/tr064/` holds `tr64desc.xml` and the SCPD files of the services used here, as
FRITZ!OS 7.57 (FRITZ!Box 7590) and 8.02 (FRITZ!Box 7530) serve them; `SOURCES.md` there says
where they come from (AVM's own download area could not be reached when they were added, so
they are a public dump of what boxes serve) and what was neutralised. The two WAN connection
descriptions are from a FRITZ!OS 8.25 box (the dump of 7.57 and 8.02 does not include them);
their actions and arguments are the same in a FRITZ!OS 7.29 dump. The simulator is built
from them: it serves them, answers only described actions with exactly their arguments and
data types, and refuses anything else with the UPnP fault (401, 402, 600, 601).
`tests/test_fritzbox_scpd.py` runs every read, write, restore and fallback path of the adapter
for both versions and checks each call against the descriptions, and checks that every action
and `New...` argument named in the adapter's source is described.

What the descriptions showed to be wrong in the earlier, hand-written version (#141):

| Was | Is |
| --- | --- |
| `WLANConfiguration X_AVM-DE_GetBeaconAdvertisement` / `X_AVM-DE_SetBeaconAdvertisement` *(guess)* | `GetBeaconAdvertisement` / `SetBeaconAdvertisement`, without the `X_AVM-DE_` prefix (the old names are fault 401 on a real box: every SSID read as broadcast, and hiding one failed) |
| open security written as `NewBeaconType` `None` | the allowed values are `none` in FRITZ!OS 7.57 and `None` in 8.02; the adapter now writes the spelling the box lists in `NewX_AVM-DE_PossibleBeaconTypes` |
| passphrase length fixed at 8-63, SSID length not checked | `GetInfo` reports `NewMinCharsPSK`, `NewMaxCharsPSK`, `NewMinCharsSSID`, `NewMaxCharsSSID`; the adapter uses them (within 8-63 and 32 bytes) |
| digest realm `HTTPS Access` "on FRITZ!OS 7" | the realm comes from the challenge; over plain HTTP it is `F!Box SOAP-Auth` (simulator: both) |
| a value of the wrong type answered with 402 | UPnP 600 (not of the data type or not an allowed value) and 601 (out of range) are mapped too |
| the simulator answered a subset of the output arguments | every answer has all described output arguments (for example `GetInfo` of `DeviceInfo` with `NewManufacturerOUI`, `NewProvisioningCode`, `NewDeviceLog`; `X_AVM-DE_GetWLANExtInfo` with ten values) |

Confirmed by the descriptions: the services, control URLs and SCPD URLs (`LANEthernetInterfaceConfig:1`
is described by `ethifconfigSCPD.xml`), every other action and argument the adapter uses, that
`LANHostConfigManagement` has no action to set DNS servers or a lease time, that there is one
`LANEthernetInterfaceConfig` (no per-port LAN state), and that `SetSecurityKeys` takes all six
key arguments. Still open (not in the descriptions): the value `guest` of
`NewX_AVM-DE_APType`, which fault a box gives for which mistake, and whether empty WEP/PSK
arguments are accepted by `SetSecurityKeys`.


## Firewall (#135)

A Fritz!Box has no readable packet filter, so the `firewall` capability (adapter API 1.4,
[ADR 0013](../adr/0013-firewall-zones-rules-and-reachability.md)) reports what the box does by
itself plus its port sharing. Gateways only (an access point or repeater reports none).

- **Zones**: `lan` (the home network, the native segment), `guest` (the guest segment, only
  where a guest Wi-Fi exists) and `wan` (the uplink of the internet connection, masquerading;
  none while neither WAN connection is enabled).
- **Policies** (fixed behaviour of FRITZ!OS, not read): `lan` to the box and to `wan` accept;
  `guest` to `wan` accept, to `lan` and to the box drop, `lan` to `guest` drop *(guess)*; `wan`
  to the box and to `lan` drop (services the box itself says are reachable from the internet
  keep their `from_wan` flag, see Management services). One rule lets `guest` use the box's DNS
  and DHCP (UDP 53 and 67) *(guess: nothing else)*.
- **Port sharing**: `WANPPPConnection:1` or, when that is not the enabled connection,
  `WANIPConnection:1` `GetGenericPortMappingEntry` with `NewPortMappingIndex` 0, 1, 2, ... until
  the box answers UPnP fault 713 (714 ends it too) or 512 entries: `NewExternalPort` (0: every
  port), `NewProtocol` (`TCP`/`UDP`), `NewInternalPort`, `NewInternalClient`, `NewEnabled`,
  `NewPortMappingDescription` (name only), `NewRemoteHost` (a source address). Each is a
  `PortForward` on `wan` with `passes_filter=True`; mappings that UPnP clients opened appear in
  the same list *(guess)*. An entry without a usable internal client is a gap. A fault other
  than 713 (606 without the *FRITZ!Box settings* right) is a gap and the list read so far is
  kept.
- **Not readable**: IPv6 port sharing (pinholes) and the exposed host are not in the TR-064
  descriptions *(guess)*, so `port_forwards_complete` is always `False`: "no forward to this
  address" is `unknown`, never `denied`. The host filter (`X_AVM-DE_HostFilter`) only blocks
  a host's internet access and is not read.

The actions are in the SCPD files that are already in `tests/fixtures/tr064/` (the two WAN
connection descriptions of FRITZ!OS 8.25, see `SOURCES.md`, MIT and Apache-2.0 licence texts
next to them), so `tests/test_fritzbox_scpd.py` checks `GetGenericPortMappingEntry` and its
argument names against them for both versions. The simulator serves four sample mappings
(documentation addresses) and fault 713 after the last.

## Management services (#173)

Read with the `interfaces` capability; every call is optional (a FRITZ!OS without it, or a user
without the right, only leaves that service out).

| Service | TR-064 | Reported |
| --- | --- | --- |
| `http`, `https` | none: adapter knowledge *(guess)* | web interface in the LAN, 80 and 443, always on |
| `tr-064` | `DeviceInfo:1 GetSecurityPort` | `NewSecurityPort`, encrypted |
| `upnp` | `X_AVM-DE_UPnP:1 GetInfo` | `NewEnable` |
| `remote-access` | `X_AVM-DE_RemoteAccess:1 GetInfo` | `https`, `NewEnabled`, `NewPort`; `from_wan` = `NewEnabled` |
| `myfritz` | `X_AVM-DE_MyFritz:1 GetInfo` | `https`, `NewEnabled`, `NewPort`; `from_wan` = `NewEnabled` *(guess: that MyFRITZ! reaches the box from the internet on that port)* |
| `myfritz-cloud` | the same call: `NewEnabled` and `NewDeviceRegistered` | kind `cloud` (#327): the box is registered with AVM's MyFRITZ! account; on only when both are set. Feeds the info check `cloud.enabled`. *(guess: that `NewDeviceRegistered` is 1 exactly when an account is linked)* |
| `ftp` | `X_AVM-DE_Storage:1 GetInfo` | `NewFTPEnable` on port 21, LAN only |
| `ftp-internet` | the same: `NewFTPWANEnable`, `NewFTPWANPort`, `NewFTPWANSSLOnly` | FTP from the internet; encrypted when SSL only |

The descriptions of the four `X_AVM-DE_*` services are in `tests/fixtures/tr064` for FRITZ!OS
7.57 and 8.02 (see SOURCES.md there) and the conformance test checks every action and argument
against them. `transport_encrypted` is true for the https URL. Not read: SSH (the box has none),
the password policy and the app users' internet access (`X_AVM-DE_AppSetup`).

## MAC address table (#160)

Not read: the host list says only whether a host is on LAN or Wi-Fi, not on which port.

## Accounts (#175)

`LANConfigSecurity:1` (`lanconfigsecuritySCPD.xml`): `GetInfo` gives
`NewX_AVM-DE_IsDefaultPasswordActive`, the box's own word on whether its printed default
password is still in use (`default_credentials`). `X_AVM-DE_GetCurrentUser` names Signalbox's
user and its rights (`<rights><path>BoxAdmin</path><access>readwrite</access>...</rights>`):
the right "FRITZ!Box settings" (`BoxAdmin`) with `readwrite` is admin. The setup guide's user
needs exactly that right, so admin is also the least this integration needs and
`account.signalbox-privileged` stays quiet. `X_AVM-DE_GetUserList`
(`<List><Username last_user="1">name</Username>...</List>`) gives the other user names, without
rights. The layouts of both XML strings are taken from AVM's documentation (*guess* until a box
confirms them, #21); they are parsed with the SOAP parser, which refuses document type
declarations. A FRITZ!OS without these actions reports nothing; a user without the right
(UPnP error 606 on the user list) gives an optional gap naming the right instead of an empty
list (#349).

## Routes (#149)

TR-064 `Layer3Forwarding:1` (the SCPD is in `tests/fixtures/tr064/`): `GetForwardNumberOfEntries`
and `GetGenericForwardingEntry` give the static IPv4 routes (`NewDestIPAddress`,
`NewDestSubnetMask`, `NewGatewayIPAddress`, `NewEnable`, `NewForwardingMetric`; a `Host` entry is
a /32). An entry with a source address is a policy route and left out. The default route is
derived from the internet connection (its gateway) while `GetDefaultConnectionService` names a
connection. Not readable: IPv6 routes, the kernel table, policy routing. A FRITZ!OS without the
service reports no routes.

## IPv6 router advertisements and DHCPv6 (#151)

Not read. TR-064 offers no action for the box's IPv6 LAN settings (the router advertisement mode and
the DHCPv6 server of *Home Network > Network > Network Settings > IPv6 Settings*); only the
delegated prefix and the external address are in the IGD services (see the uplink). Signalbox
therefore reports no `RouterAdvert` or `Dhcp6Server` for a Fritz!Box and `ipv6.ra-consistent` is
silent for its network unless another device reports one (*guess: FRITZ!OS 7.5x and 8 have no such
action; not checked on a device*).

## Dynamic DNS (#154)

`X_AVM-DE_RemoteAccess:1 GetDDNSInfo` (in the descriptions of FRITZ!OS 6.83, 7.29, 7.57 and
8.02): `NewEnabled`, `NewProviderName`, `NewDomain`, `NewMode` (`ddns_v4`, `ddns_v6`,
`ddns_both`), `NewStatusIPv4`/`NewStatusIPv6`. A status with `error` or `fail` is an error, `ok`
or `updated` a success, anything else unknown *(guess: the words are the box's, #21)*.
`NewUpdateURL` and `NewUsername` are never read. `NewServerIPv4` is the provider's server, not
the address announced, so `published_address` stays empty (and `ddns.mismatch` quiet).
`X_AVM-DE_MyFritz:1 GetInfo` gives the MyFRITZ! name (`NewDynDNSName`, `NewState`); the account
(`NewEmail`) is never read. A box without a DDNS domain reports none. Multi-WAN: the mobile
fallback of FRITZ!OS is not in TR-064, nothing is read.

### Firmware update and auto-update (#181)

`UserInterface:1 GetInfo` gives whether an update exists (`NewUpgradeAvailable`), its version
(`NewX_AVM-DE_Version`) and the build type (`Release` is stable, `Labor_Beta` beta, `Labor_RC`
rc, other `Labor*` testing, `Inhaus` development); `X_AVM-DE_GetInfo` the auto-update mode
(`off` and `notify` are not automatic, `important` and `all` are). Both are optional: a box
whose description lacks the service (FRITZ!OS 6.83 and 7.29 in the simulator) reports the
version only. TR-064 has no configuration state or backup without a password for
`X_AVM-DE_GetConfigFile`, which Signalbox does not use.
