# AVM Fritz!Box adapter

Reads an AVM Fritz!Box (FRITZ!OS 7) over TR-064, AVM's SOAP interface for applications, on its
HTTPS port `49443`. Read only; nothing on the device is changed (writing follows with #38).

| | |
| --- | --- |
| Adapter id | `fritzbox` |
| Roles | `gateway`, `ap` |
| Capabilities | interfaces, DHCP, wireless, clients |
| Simulator | `signalbox.sim.fritzbox` (`uvicorn --factory signalbox.sim.fritzbox:create_app`) |

> The actions and answer shapes below are taken from AVM's public TR-064 documentation
> (`tr64desc.xml` and the service descriptions of FRITZ!OS 7). They are implemented by the
> simulator but still need to be confirmed on a real device (#21). Shapes marked *(guess)* are
> the least certain.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | | `https://<box>:49443`, for example `https://192.0.2.1:49443` (no port: `49443`) |
| `username` | `signalbox` | the Fritz!Box user (see below) |
| `password` | | its password; stored encrypted, never sent back to the UI |
| `allow_insecure_http` | `false` | accept an `http://` URL; meant for simulators, nothing is encrypted then |

## Setting up the Fritz!Box

1. *Home Network > Network > Network Settings > Home Network Sharing*: switch on
   **Allow access for applications** (this is TR-064). The HTTPS port is shown there; it is
   `49443` unless changed.
2. *System > FRITZ!Box Users*: add a user only for Signalbox, for example `signalbox`, with a
   long password. Give it the right **FRITZ!Box settings** and nothing else; *Access from the
   internet* stays off. TR-064 has no read-only right: the user could change settings through
   TR-064, which this adapter never does. Keep the password in Signalbox only.
3. Add the device in Signalbox with `https://<box>:49443`. On the first connection Signalbox
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

Authentication is HTTP Digest (MD5, `qop=auth`, realm `HTTPS Access` on FRITZ!OS 7): the first
request is answered with `401` and a challenge, then every request carries the digest. Wrong
user or password: `401` again, the device is reported as `auth-failed`.

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
| fault `402` Invalid Args, `501` Action Failed, `713`/`714` no such entry, `820` internal error | "`<service> <action>`: UPnP error ..." for that capability |
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

## Actions and the arguments they return

### `DeviceInfo:1 GetInfo` (system)

`NewManufacturerName`, `NewModelName`, `NewSoftwareVersion` (for example `154.07.57`) become
vendor, model and firmware. The serial number and the device log in the same answer are not kept.

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
  `NewMinAddress`-`NewMaxAddress`, router, DNS servers (comma-separated list) and domain.
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
  Fritz!Box guest network) and uses the radio of its band; it is not a radio of its own.
- **Security** from `NewBeaconType`:

  | `NewBeaconType` | Security |
  | --- | --- |
  | `None` | open |
  | `Basic` (WEP), `WPA` | other |
  | `11i` | WPA2 |
  | `WPAand11i` | WPA2 (mixed WPA/WPA2) |
  | `WPA3` | WPA3 |
  | `11iandWPA3` | WPA2/WPA3 |
  | `OWE`, `OWETrans` | OWE |

- `GetSecurityKeys` `NewKeyPassphrase` becomes the passphrase fingerprint (personal security
  only). PMF, 802.11r/k/v and hidden SSIDs are not read *(not documented for TR-064)*.

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

## Not available

- **DNS**: the Fritz!Box resolves names for its clients, but TR-064 exposes neither its
  forwarders nor local host records, so the adapter has no DNS capability.
- **Neighbours (LLDP)**: FRITZ!OS does not speak LLDP.
- **DHCP reservations, lease time, VLANs, per-port LAN state**: not in TR-064 (see above).
