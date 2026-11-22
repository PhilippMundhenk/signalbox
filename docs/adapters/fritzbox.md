# AVM Fritz!Box adapter

Reads an AVM Fritz!Box (FRITZ!OS 7) over TR-064, AVM's SOAP interface for applications, on its
HTTPS port `49443`. It can also change the DHCP server and the existing Wi-Fi networks
(see [Writing](#writing)), only when changes are allowed (see [CHANGES.md](../CHANGES.md)).

| | |
| --- | --- |
| Adapter id | `fritzbox` |
| Roles | `gateway`, `ap` |
| Capabilities | interfaces, DHCP, wireless, clients |
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
| `username` | empty | the Fritz!Box user (see below); empty when the box asks only for its password |
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
   the password in Signalbox only. A box set to log in with its password only (no users) is
   read with an empty user name and that password.
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

`NewStatus` (`Up`), `NewMACAddress`, `NewMaxBitRate` (Mbit/s or `Auto`), `NewDuplexMode`
(`Full`, `Half`, `Auto`); statistics `NewBytesSent`, `NewBytesReceived`, `NewPacketsSent`,
`NewPacketsReceived` go into `vendor_extra`.

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
  | `Basic` (WEP), `WPA` | other |
  | `11i` | WPA2 |
  | `WPAand11i` | WPA2 (mixed WPA/WPA2) |
  | `WPA3` | WPA3 |
  | `11iandWPA3` | WPA2/WPA3 |
  | `OWE`, `OWETrans` | OWE |

- `GetSecurityKeys` `NewKeyPassphrase` becomes the passphrase fingerprint (personal security
  only).
- **Hidden**: `GetBeaconAdvertisement` `NewBeaconAdvertisementEnabled` `0`; without the
  action (fault 401) the SSID counts as broadcast.
- PMF and 802.11r/k/v are not read *(not documented for TR-064)*.

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

## Checked against AVM's service descriptions

`tests/fixtures/tr064/` holds `tr64desc.xml` and the SCPD files of the services used here, as
FRITZ!OS 7.57 (FRITZ!Box 7590) and 8.02 (FRITZ!Box 7530) serve them; `SOURCES.md` there says
where they come from (AVM's own download area could not be reached when they were added, so
they are a public dump of what boxes serve) and what was neutralised. The simulator is built
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
