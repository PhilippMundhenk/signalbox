# MikroTik adapter

Adapter id `mikrotik`, roles `gateway`, `switch` and `ap`. Reads a RouterOS 7 router, switch or
access point through the REST API (`/rest`, served by the `www-ssl` service); it never changes
anything (every request is a `GET`). Writing follows with the change transactions of
[#38](https://github.com/PhilippMundhenk/signalbox/issues/38).

| Capability | What is read |
| --- | --- |
| system | model (RouterBOARD model, else board name), RouterOS version and the newest available version |
| interfaces | ports (state, MAC, speed), bridge VLAN filtering (VLAN table, pvid of access ports), VLAN interfaces, IPv4/IPv6 addresses: segments and subnets |
| dhcp | DHCP servers with pools, lease time, gateway, DNS, domain and static leases as reservations |
| dns | DNS server: enabled (remote requests allowed), listen addresses, upstream servers, static `A`/`AAAA` entries |
| wireless | radios and SSIDs from the RouterOS 7 `wifi` package (`/interface/wifi`), else the older `wireless` package |
| clients | ARP and IPv6 neighbours, DHCP leases, the bridge host table (port) and the Wi-Fi registration table (SSID) |
| neighbours | `/ip/neighbor` (LLDP, MNDP, CDP): identity, chassis MAC, remote port, address |

> **Not yet confirmed on a real device.** The endpoints and JSON shapes below come from the
> RouterOS documentation (REST API, and the property lists of each menu), not from a recorded
> answer. Real-device validation is [issue #21](https://github.com/PhilippMundhenk/signalbox/issues/21).
> Parsing is deliberately tolerant: a missing field is left empty, unknown fields are ignored,
> and an answer of the wrong shape becomes a readable "could not read" finding
> (`unexpected answer from <endpoint>: ...`), never a crash.

## Setup

```yaml
adapter: mikrotik
url: https://192.0.2.1          # address of the www-ssl service, optional :port
username: signalbox             # default
password: "..."                 # stored encrypted
```

### HTTPS with a certificate

The REST API is served by the `www-ssl` service, which needs a certificate. A self-signed one is
enough, because Signalbox pins it:

```
/certificate add name=signalbox-www common-name=router days-valid=3650 \
    key-usage=digital-signature,key-encipherment,tls-server
/certificate sign signalbox-www
/ip service set www-ssl certificate=signalbox-www disabled=no address=192.0.2.0/24
```

`address=` limits who can reach the service; use the network Signalbox runs in. On the first
connection Signalbox shows the SHA-256 fingerprint of the certificate (the device is "untrusted
certificate"). Compare it with `/certificate print detail where name=signalbox-www`
(`fingerprint`) and confirm it; from then on the certificate is pinned and a changed certificate
stops reading until it is confirmed again. The password is only sent after the pinned
certificate was presented (see `signalbox/adapters/https.py`).

`allow_insecure_http: true` allows an `http://` URL (service `www`). It sends the password in
clear text and is only meant for the simulator.

### A read-only user group

```
/user group add name=signalbox-read \
    policy=read,api,rest-api,!write,!policy,!password,!sensitive,!reboot,!test,!sniff,!romon,!local,!telnet,!ssh,!ftp,!winbox,!web
/user add name=signalbox group=signalbox-read password="<a long random password>"
```

- `read` and `rest-api` are what the REST API needs to answer `GET` requests; without `write`
  every changing request is refused by the router itself. `api` is listed for RouterOS
  versions before the separate `rest-api` policy existed.
- Without `sensitive` RouterOS hides secrets in its answers, Wi-Fi passphrases included. Then
  SSIDs are read without a passphrase fingerprint, and the "same SSID, different passphrase"
  check has nothing to compare. Adding `sensitive` lets the user read every secret of the
  device (Wi-Fi keys, VPN keys, RADIUS secrets): decide whether the check is worth that.
  Signalbox never stores or shows the passphrase itself, only a fingerprint derived from it.
- A missing permission shows up as `access denied (HTTP 403); check the user's privileges` (or
  401) for the capability that needs it; the rest is still read.

## Mapping to the model

- **Ports**: every `/interface` entry except VLAN interfaces and loopback. Kind from `type`
  (`ether`, `bridge`, `bond` as a LAG, `wifi`/`wlan` as wireless, everything else virtual), `up`
  from `running` (a disabled port is down), MAC from `mac-address`, speed and duplex from the
  `speed` of `/interface/ethernet` (`1Gbps`, `1G-baseT-full`, ...).
- **Segments, bridge with `vlan-filtering=yes`**: every VLAN id of `/interface/bridge/vlan`
  (ranges like `100-105` expanded) is `<site>/segment/<vid>`, VLAN 1 the native segment. Members
  are the ports in `tagged`/`current-tagged` (tagged) and `untagged`/`current-untagged`
  (untagged), plus every bridge port whose `pvid` it is unless `frame-types` is
  `admit-only-vlan-tagged`. The bridge itself is the router's side and not a member. The bridge's
  own address is in the segment of its `pvid`.
- **Segments, bridge without VLAN filtering**: the bridge is one untagged network with all its
  ports; it is the native segment if no filtering bridge exists and it is the first one. Any
  further untagged network, and a routed port of its own with an address (a DMZ), is
  `<site>/segment/<name>`.
- **VLAN interfaces** (`/interface/vlan`): the router's address in VLAN `vlan-id`; on a plain
  port that port is a tagged member. The segment name is the VLAN table entry's `comment`, else
  the VLAN interface's comment or name; the native segment is named after the bridge's comment.
- **Uplink**: members of the interface list `WAN` (RouterOS' default configuration) are ports
  only: no segment, no subnets, and their ARP neighbours are not clients. Without that list the
  uplink port with its address becomes a network of its own.
- **Subnets**: every enabled, non-link-local address from `/ip/address` and `/ipv6/address` on a
  bridge, VLAN interface or routed port, with `gateway: true` when the device's role is
  `gateway`.
- **DHCP**: one server per `/ip/dhcp-server` entry on a known interface. Pools from the
  `ranges` of its `address-pool` (and `next-pool`), lease time from `lease-time` (`30m`,
  `1d00:00:00`), router, DNS and domain from the `/ip/dhcp-server/network` entry containing the
  interface address. Static leases (`dynamic=false`) of that server, or of `all` in its network,
  are reservations; the hostname is the lease comment, else `host-name`.
- **DNS**: one service. Enabled when `allow-remote-requests=yes`; it then listens on the
  addresses of every non-uplink interface. `servers` are the forwarders, `dynamic-servers`
  (from DHCP/PPP) go to `vendor_extra`. Enabled static entries of type `A` (the default) and
  `AAAA` with a name become host records; regexp entries and CNAMEs are skipped.
- **Wireless (`wifi` package)**: every `/interface/wifi` entry without `master-interface` is a
  radio, band from `channel.band` (`2ghz-ax`, `5ghz-ax`, `6ghz-ax`) or the frequency, channel
  from `channel.frequency`, width from `channel.width` (the widest listed), tx power and country
  from `configuration.*`. Every entry in mode `ap` with an SSID is a WLAN on its own radio or its
  master's. Properties are read inline (`security.authentication-types`) or from the named
  profile (`security=home` → `/interface/wifi/security`), likewise for `configuration`,
  `channel`, `datapath` and `steering`. Security from `authentication-types`
  (`wpa2-psk,wpa3-psk` → WPA2/WPA3, empty → open), PMF from `management-protection`
  (`allowed` → optional), 802.11r from `ft`, 802.11k/v from `steering.rrm`/`steering.wnm`,
  hidden from `hide-ssid`, segment from the bridge port's `pvid`, else `datapath.vlan-id`.
- **Wireless (`wireless` package)**: radios from `/interface/wireless` entries without
  `master-interface` (`band` like `2ghz-b/g/n`, `frequency`, `channel-width`), WLANs in mode
  `ap-bridge` or `bridge`, security and passphrase from the `security-profile`
  (`/interface/wireless/security-profiles`, `mode=none` is open), segment from the bridge port,
  else `vlan-id` with `vlan-mode=use-tag`.
- **No wireless package** (both menus answer 404, as on a router without radios): the
  wireless capability reports `no wireless package: ...` as a "could not read" finding.
- **Clients**: merged by MAC from ARP, IPv6 neighbours, bound DHCP leases (dynamic and static),
  the bridge host table and the Wi-Fi registration table; the device's own MACs (port MACs and
  `local` bridge hosts), failed or incomplete entries and the uplink's neighbours are skipped.
  The segment comes from the interface of the ARP entry or lease, else the bridge host's `vid`,
  else the address; the location is the bridge host's port, or the WLAN for registered Wi-Fi
  stations.
- **Neighbours**: `/ip/neighbor` entries with a MAC on a known port (`interface` may list the
  port and its bridge, `ether2,bridge`). `identity` is the system name, `interface-name` the
  remote port, `address4` (else `address`) the management address.

## Endpoints and assumed answers

All `GET /rest/<menu>` with HTTP basic auth. RouterOS answers a menu with a list of objects, each
with an `.id`, and a single-value menu with one object (a list holding one object is accepted
too). Every value is a string: booleans are `"true"`/`"false"`, numbers are digits, lists are
comma separated. A 404 on an endpoint marked *optional* means "not on this device" and is not an
error. A 404 on `/rest/system/resource` means the REST API is not reachable as configured.

### `/rest/system/resource`, `/rest/system/routerboard` *(optional)*, `/rest/system/package/update` *(optional)* (system)

```json
{"version": "7.15.3 (stable)", "board-name": "hAP ax^2", "architecture-name": "arm64"}
{"routerboard": "true", "model": "C52iG-5HaxD2HaxD", "current-firmware": "7.15.3"}
{"channel": "stable", "installed-version": "7.15.3", "latest-version": "7.16"}
```

`version` is required. `latest-version` is only filled after the router checked for updates;
a refused or missing update menu is ignored. CHR and x86 answer `{"routerboard": "false"}`.

### `/rest/interface`, `/rest/interface/ethernet` *(optional)* (interfaces)

```json
[{".id": "*1", "name": "ether1", "type": "ether", "mac-address": "02:00:00:00:00:01",
  "running": "true", "disabled": "false", "mtu": "1500", "comment": "uplink"}]
[{".id": "*1", "name": "ether1", "speed": "1G-baseT-full", "auto-negotiation": "true"}]
```

`speed` is the configured (or advertised) speed; the negotiated rate is only available from
`monitor`, which is not a `GET`. *Guess*: the format changed from `1Gbps` to `1G-baseT-full` in
RouterOS 7.12; both are parsed.

### `/rest/interface/bridge`, `/rest/interface/bridge/port`, `/rest/interface/bridge/vlan` (interfaces)

```json
[{".id": "*1", "name": "bridge", "vlan-filtering": "true", "pvid": "1", "comment": "LAN"}]
[{".id": "*1", "interface": "ether4", "bridge": "bridge", "pvid": "20",
  "frame-types": "admit-only-untagged-and-priority-tagged", "disabled": "false"}]
[{".id": "*2", "bridge": "bridge", "vlan-ids": "20", "tagged": "bridge,ether2",
  "untagged": "ether4", "current-tagged": "bridge,ether2", "current-untagged": "ether4,wifi3",
  "dynamic": "false", "disabled": "false"}]
```

Dynamic entries (VLAN 1 from the pvids) are listed too and read the same way.

### `/rest/interface/vlan`, `/rest/interface/list/member` *(optional)* (interfaces)

```json
[{".id": "*1", "name": "iot", "vlan-id": "20", "interface": "bridge"}]
[{".id": "*1", "list": "WAN", "interface": "ether1", "disabled": "false"}]
```

### `/rest/ip/address`, `/rest/ipv6/address` *(optional)* (interfaces)

```json
[{".id": "*1", "address": "192.0.2.1/24", "network": "192.0.2.0", "interface": "bridge",
  "actual-interface": "bridge", "disabled": "false", "dynamic": "false", "invalid": "false"}]
[{".id": "*1", "address": "2001:db8:1::1/64", "interface": "bridge", "link-local": "false"}]
```

`/ipv6/address` answers 404 when IPv6 is disabled.

### `/rest/ip/dhcp-server`, `/rest/ip/dhcp-server/network`, `/rest/ip/pool`, `/rest/ip/dhcp-server/lease` (dhcp, clients)

```json
[{".id": "*1", "name": "defconf", "interface": "bridge", "address-pool": "default-dhcp",
  "lease-time": "30m", "disabled": "false"}]
[{".id": "*1", "address": "192.0.2.0/24", "gateway": "192.0.2.1", "dns-server": "192.0.2.1",
  "domain": "home.example"}]
[{".id": "*1", "name": "default-dhcp", "ranges": "192.0.2.100-192.0.2.199", "next-pool": ""}]
[{".id": "*1", "address": "192.0.2.10", "mac-address": "02:00:00:00:00:10", "server": "defconf",
  "comment": "printer", "host-name": "PRN-0010", "status": "bound", "dynamic": "false",
  "active-address": "192.0.2.10", "active-mac-address": "02:00:00:00:00:10"}]
```

### `/rest/ip/dns`, `/rest/ip/dns/static` (dns)

```json
{"servers": "192.0.2.53,2001:db8:53::53", "dynamic-servers": "203.0.113.1",
 "allow-remote-requests": "true", "cache-size": "2048KiB"}
[{".id": "*1", "name": "nas.home.example", "address": "192.0.2.10", "ttl": "1d",
  "disabled": "false"},
 {".id": "*2", "name": "nas.home.example", "type": "AAAA", "address": "2001:db8:1::10"}]
```

*Guess*: `type` is left out for `A` records.

### `/rest/interface/wifi` and profiles (wireless, `wifi` package)

```json
[{".id": "*1", "name": "wifi1", "configuration.mode": "ap", "configuration.ssid": "Example",
  "configuration.country": "Germany", "configuration.tx-power": "17",
  "channel.band": "2ghz-ax", "channel.frequency": "2437", "channel.width": "20/40mhz",
  "security": "home", "steering.rrm": "yes", "steering.wnm": "yes", "disabled": "false"},
 {".id": "*3", "name": "wifi3", "master-interface": "wifi1",
  "configuration.ssid": "Example-IoT", "configuration.hide-ssid": "true",
  "security.authentication-types": "wpa2-psk", "datapath.vlan-id": "20"}]
```

Profiles, all *optional*: `/rest/interface/wifi/security`
(`{"name": "home", "authentication-types": "wpa2-psk,wpa3-psk", "passphrase": "...",
"management-protection": "allowed", "ft": "yes"}`), `/rest/interface/wifi/configuration`,
`/rest/interface/wifi/channel`, `/rest/interface/wifi/datapath`, `/rest/interface/wifi/steering`.
*Guess*: the REST API returns the inline settings as dotted names (`configuration.ssid`), as the
CLI shows them. The `steering.*` names (802.11k/v) are from RouterOS 7.13+.

### `/rest/interface/wireless`, `/rest/interface/wireless/security-profiles` (wireless, `wireless` package)

```json
[{".id": "*1", "name": "wlan1", "mode": "ap-bridge", "ssid": "Example", "band": "2ghz-b/g/n",
  "frequency": "2412", "channel-width": "20/40mhz-XX", "country": "germany",
  "security-profile": "home", "hide-ssid": "false", "vlan-mode": "no-tag", "vlan-id": "1"}]
[{".id": "*1", "name": "home", "mode": "dynamic-keys", "authentication-types": "wpa2-psk",
  "wpa2-pre-shared-key": "...", "management-protection": "allowed"}]
```

### `/rest/ip/arp`, `/rest/ipv6/neighbor` *(optional)*, `/rest/interface/bridge/host`, registration tables *(optional)* (clients)

```json
[{".id": "*1", "address": "192.0.2.10", "mac-address": "02:00:00:00:00:10",
  "interface": "bridge", "status": "reachable", "dynamic": "true"}]
[{".id": "*1", "address": "2001:db8:1::10", "mac-address": "02:00:00:00:00:10",
  "interface": "bridge", "status": "reachable"}]
[{".id": "*2", "mac-address": "02:00:00:00:00:10", "on-interface": "ether3",
  "bridge": "bridge", "vid": "1", "local": "false"}]
[{".id": "*1", "interface": "wifi3", "mac-address": "02:00:00:00:00:22", "ssid": "Example-IoT"}]
```

Registration tables: `/rest/interface/wifi/registration-table`, or
`/rest/interface/wireless/registration-table` for the older package.

### `/rest/ip/neighbor` (neighbours)

```json
[{".id": "*1", "interface": "ether2,bridge", "address4": "192.0.2.2",
  "mac-address": "02:00:00:00:00:50", "identity": "switch", "platform": "MikroTik",
  "board": "CRS326-24G-2S+", "interface-name": "ether24", "discovered-by": "lldp,mndp"}]
```

*Guess*: on a bridged port `interface` lists the port and the bridge.

## Simulator

`signalbox.sim.mikrotik.MikrotikSimulator` answers these endpoints with neutral sample data (a
hEX-like router with Wi-Fi and bridge VLAN filtering, documentation addresses, `02:` MACs). Its
switches simulate a wrong password (401), a disabled REST API (404 everywhere), slow answers,
malformed JSON per path, a status code per path, and the wireless package installed (`wifi`,
`legacy` or `none`).
