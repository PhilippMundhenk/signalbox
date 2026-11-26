# MikroTik adapter

Adapter id `mikrotik`, roles `gateway`, `switch` and `ap`. Reads a RouterOS 7 router, switch or
access point through the REST API (`/rest`, served by the `www-ssl` service), and deploys
changes of every kind (`router`, `dhcp`, `reservation`, `port`, `wlan`, the firewall kinds `firewall-rule`, `port-forward`, `zone-policy`, `log-target`, `snmp-policy`, and `gateway-group`) through the change
transactions of [#38](https://github.com/PhilippMundhenk/signalbox/issues/38) when the device's
"allow changes" setting is on and the user may write: see [Writing](#writing). Reading only ever
sends `GET` requests.

**Supported versions:** RouterOS 7.1 and newer (the REST API). RouterOS 6 has no REST API and is not supported: Signalbox reports "RouterOS 6 is not supported" when the device says its version is 6.x. When `/rest` answers 404 or a web page and the version is unknown, it says "no RouterOS REST API at this address (RouterOS 6, REST disabled, or wrong address/port)" ([#425](https://github.com/PhilippMundhenk/signalbox/issues/425)). Update to 7.1+, or read the device through the generic SNMP integration ([#400](https://github.com/PhilippMundhenk/signalbox/issues/400)).

| Capability | What is read |
| --- | --- |
| system | model (RouterBOARD model, else board name), RouterOS version and the newest available version |
| interfaces | ports (state, MAC, speed), bridge VLAN filtering (VLAN table, pvid of access ports), VLAN interfaces, IPv4/IPv6 addresses: segments and subnets |
| dhcp | DHCP servers with pools, lease time, gateway, DNS, domain and static leases as reservations |
| dns | DNS server: enabled (remote requests allowed), listen addresses, upstream servers, static `A`/`AAAA` entries |
| wireless | radios and SSIDs from the RouterOS 7 `wifi` package (`/interface/wifi`), else the older `wireless` package |
| clients | ARP and IPv6 neighbours, DHCP leases, the bridge host table (port) and the Wi-Fi registration table (SSID) |
| neighbours | `/ip/neighbor` (LLDP, MNDP, CDP): identity, chassis MAC, remote port, address, protocol, port VLAN; `last_seen` = read time minus `age` (RouterOS counts the age from the last update, lldpd from the first sighting, so only RouterOS fills it, #448) |

> **Verified against RouterOS 7.25.1 CHR in CI.** The setup commands, user groups, the answers of
> every menu the read side uses and the write calls for router interfaces, DHCP, static leases,
> bridge VLANs on ports, the backup and the restore are checked against the official CHR image
> running in QEMU: tests/integration/test_mikrotik_real.py, set up by tools/integration/mikrotik/
> ([Integration tests](#integration-tests)). Not covered there, because CHR has no radios, no
> LLDP neighbours and no clients: Wi-Fi (both packages), the neighbour table and client
> tables with real hosts; their shapes still come from the RouterOS documentation (marked
> *Guess* below; real devices: [issue #21](https://github.com/PhilippMundhenk/signalbox/issues/21)).
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

The REST API is served by the `www-ssl` service, which needs a certificate. One signed by a
local CA on the router is enough, because Signalbox pins it:

```
/certificate add name=signalbox-ca common-name=signalbox-ca days-valid=3650 \
    key-usage=key-cert-sign,crl-sign
/certificate sign signalbox-ca
/certificate add name=signalbox-www common-name=router days-valid=3650 \
    key-usage=digital-signature,key-encipherment,tls-server
/certificate sign signalbox-www ca=signalbox-ca
/ip service set www-ssl certificate=signalbox-www disabled=no address=192.0.2.0/24
```

Verified on RouterOS 7.25.1 CHR: `/certificate sign` of the server certificate alone fails with
`failure: CA not found`, so the CA comes first. `address=` limits who can reach the service
(use the network Signalbox runs in); 7.25 accepts it and shows it as `available-from` in the
export. On the first
connection Signalbox shows the SHA-256 fingerprint of the certificate (the device is "untrusted
certificate"). Compare it with `/certificate print detail where name=signalbox-www`
(`fingerprint`) and confirm it; from then on the certificate is pinned and a changed certificate
stops reading until it is confirmed again. The password is only sent after the pinned
certificate was presented (see `signalbox/adapters/https.py`).

`allow_insecure_http: true` allows an `http://` URL (service `www`). It sends the password in
clear text and is only meant for the simulator.

### Automatic setup

*Set up automatically* in the device form (#231, [ADR 0009](../adr/0009-automatic-setup-with-an-admin-login.md))
creates the group and the user below through the REST API as admin, once HTTPS is set up as
above.
After creating or changing the user the setup waits (up to 20 s) until RouterOS accepts the new login, because RouterOS applies a new user a moment later and the first request would otherwise get HTTP 401 (#520).
It is optional: the manual setup below is the same result and always works. Nothing is
changed on the device unless you start it for that device and confirm the plan (never from
*Find devices*, a read or in the background), and `setup.enabled: false` in the
configuration turns it off completely (the API refuses it, the form does not show it).


1. In the device form: the address, the user to create (`signalbox`), then admin's password
   under *Set up automatically*. *Show what it does* shows the certificate fingerprint first;
   nothing is sent before you trust it.
2. The plan: the group `signalbox-read` with the policies below (or `signalbox-write` with those
   of [A user group that may write](#a-user-group-that-may-write) when *Allow changes* is on),
   created (`PUT /rest/user/group`) or its policies put back (`PATCH`), and the user in it with a
   new generated password (`PUT /rest/user`, or `PATCH` of the existing one). Policies are
   compared as the set of granted ones, because RouterOS lists them in its own order.
3. *Set up the device* runs it and saves the device with the new password, stored encrypted and
   never shown; admin's password is not stored or logged.

*Remove what Signalbox set up* deletes the user, and each of the two groups when no other user
is in it. Verified in CI on the RouterOS CHR (`tests/integration/test_mikrotik_setup_real.py`):
pinning, a refused admin password, the image's group recognised as already right, the user
created and the router read with it (contract), moved to the write group with a new password
(the old one refused), and the removal keeping the groups the image's users are in.

### Fix it

Two remedies (#267, [ADR 0012](../adr/0012-fix-it-for-read-problems.md)), both optional: on a
device with *Allow changes* the device page offers *Fix it* next to the read error ("What to do"
stays the manual way, and the commands of this guide are what *Fix it* runs). Each needs the
admin login for that one request (never stored or logged), the confirmed certificate or SSH
host key and the confirmed plan; afterwards the router is read again. Off with
`setup.fixes: false` or `setup.enabled: false`. Network settings are never changed.

- **Add the missing policies** (`policies`, named by `not enough permissions (9)`), over the
  REST API as admin with the certificate pinned: the group of the stored user (it must be one of
  Signalbox's, a name starting with `signalbox`) gets the policies `read`, `api` and `rest-api`,
  and `write` and `sensitive` too since changes are allowed (`PATCH /rest/user/group/<id>`).
  Policies it has already stay, every other policy is written as `!policy` like in the guide; the
  user, its password and its members are not touched. Groups of other names (`full`, `read`) are
  refused.
- **Turn on the REST service** (`rest-service`, named when the router cannot be reached), over
  **SSH** as admin with the host key pinned, because the REST API is what is down. It reads
  `/ip service www-ssl`, the certificates and the address of the admin SSH session
  (`/user active`), then does only what is missing: creates the local CA `signalbox-ca` and the
  server certificate `signalbox-www` with the commands of [HTTPS with a
  certificate](#https-with-a-certificate) if `www-ssl` has no certificate, sets it as the
  service's certificate, enables the service, and adds that address (`/32`) to `address=` when the
  list excludes it (the other entries stay; no list means every address and stays). The address
  is the one the router sees for the SSH session, so it is right behind NAT too, if the REST
  connection takes the same path. A new certificate has a new fingerprint: confirm it again in
  the device form. The SSH port field defaults to 22.

Verified in CI on the RouterOS 7.25.1 CHR (`tests/integration/test_mikrotik_fix_real.py`): a group
without `api` and `rest-api` gives the error with the remedy and is repaired with the same login
reading afterwards; `www-ssl` limited to another address (unreachable) and without a certificate
is repaired over SSH. Not verified: creating the CA and certificate by this path on the CHR (the
commands are those the image preparation runs); real devices: [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).

### A read-only user group

```
/user group add name=signalbox-read \
    policy=read,api,rest-api,!write,!policy,!password,!sensitive,!reboot,!test,!sniff,!romon,!local,!telnet,!ssh,!ftp,!winbox,!web
/user add name=signalbox group=signalbox-read password="<a long random password>"
```

- `read` and `rest-api` are what the REST API needs to answer `GET` requests; without `write`
  every changing request is refused by the router itself (verified on RouterOS 7.25.1 CHR: the group is
  accepted with the `!` entries as written, every menu of the read side answers, a `PUT` is
  refused with HTTP 500 `not enough permissions (9)`). `api` is listed for RouterOS
  versions before the separate `rest-api` policy existed. The uplinks need no further policy:
  the DHCP, PPPoE and cloud menus are read with `read`, and the PPPoE monitor is a read
  command *(guess, #21: a group without the right for it only loses the session's uptime and
  addresses)*.
- Without `sensitive` RouterOS hides secrets in its answers, Wi-Fi passphrases included. Then
  SSIDs are read without a passphrase fingerprint, and the "same SSID, different passphrase"
  check has nothing to compare. Adding `sensitive` lets the user read every secret of the
  device (Wi-Fi keys, VPN keys, RADIUS secrets): decide whether the check is worth that.
  Signalbox never stores or shows the passphrase itself, only a fingerprint derived from it.
- A missing permission shows up as `access denied (not enough permissions (9)); check the
  user's group policies` (RouterOS answers HTTP 500 with that detail; a 403 is shown as
  `access denied (HTTP 403)`) for the capability that needs it; the rest is still read. A
  wrong password is HTTP 401.

### Path traces (optional, #253)

Only while `traces.enabled` is on ([TRACES.md](../TRACES.md)): `POST /rest/tool/traceroute`
with `{"address": "<address>", "count": "1", "max-hops": "16", "timeout": "1000ms",
"use-dns": "no"}`, answered with one row per hop (`address`, `loss`, `last`, ...; several
`.section`s when RouterOS printed more than one round: the last counts). The group needs the
policy **test** (ping and traceroute), which the groups of the setup guide do not have: add it
by hand (`/user group set signalbox-read policy=read,api,rest-api,test`), or, while path traces
are on, use *Fix it* (`policies`) or run the automatic setup again. Without it RouterOS answers HTTP 500 `not enough
permissions` and the trace says which policy is missing.

## Mapping to the model

- **Port structure** (#252, ADR 0008): role from the `/interface` `type`: `ether` (also SFP) is
  `jack`, `bridge` is `bridge` over the `interface` of its active `/interface/bridge/port`
  rows, `vlan` is `vlan` on its `interface`, `bond` is `lag` over the `slaves` of
  `/interface/bonding`, `wifi`/`wlan`/`cap` is `wireless` (a virtual AP, `master-interface` in
  `/interface/wifi` or `/interface/wireless`, runs on its master; `Wlan.port_id` is the
  interface of the SSID), `wg`, `eoip`, `gre`, `ipip`, `vxlan`, `pppoe-out`, `l2tp-out`,
  `sstp-out`, `ovpn-out` and the like are `tunnel` (kind virtual). Devices with a switch chip
  (`/interface/ethernet/switch/port`, *optional*, a missing menu is skipped): the row named
  `<switch>-cpu` becomes a port of role `cpu` (not an interface in `/interface`) and the
  ethernet ports of the chip list it as lower port. *Confirmed on the CHR in CI*: jacks, the
  bridge over its ports, the VLAN interface on the bridge, a WireGuard tunnel; *not confirmed*
  (CHR has no switch chip, no radio): the switch CPU port and virtual APs (from the RouterOS
  documentation).

- **Link aggregation** (#157, ADR 0022): a `bond` interface gets from its `/interface/bonding`
  row `lag_mode` (`mode` `802.3ad` is LACP, passive where `lacp-mode` is `passive`; the other
  modes keep their Linux names), `hash_policy` (`transmit-hash-policy` `layer-2`,
  `layer-2-and-3`, `layer-3-and-4`), `lacp_rate` (`30secs` slow, `1sec` fast) and
  `min_links`; its `slaves` get `lag`. Then `POST /rest/interface/bonding/monitor-slaves`
  (`{"bond": "<name>", "once": ""}`) gives per member `active` (selected), the actor flags
  (`collecting`, `distributing`) and the partner's `partner-sys-id`, `partner-port-number`
  and `partner-key`; a refused or failing monitor leaves the member state unknown.
  *Confirmed on the CHR in CI*: the bonding row and its members. *Guess* (#21): the
  `monitor-slaves` field names, from the RouterOS manual (the CHR's bond has no LACP partner).

- **Ports**: every `/interface` entry except loopback (VLAN interfaces are ports of role `vlan`
  and also become segments). Kind from `type`
  (`ether`, `bridge`, `bond` as a LAG, `wifi`/`wlan` as wireless, everything else virtual), `up`
  from `running` (a disabled port is down), MAC from `mac-address`, speed and duplex from the
  `speed` of `/interface/ethernet` (`1Gbps`, `1G-baseT-full`, ...). Port details (#156):
  `comment` (of the interface, or of the bridge) is the description, `disabled` the admin
  state, `mtu` (`actual-mtu` where it is `auto`) and `l2mtu` the MTUs; from
  `/interface/ethernet` `advertise` (the offered speeds), `auto-negotiation`, and flow control
  (`rx-`/`tx-flow-control`: on if either is `on`, off if both are `off`, unknown for `auto`).
  Ports of a bridge with `vlan-filtering` (and the bridge itself) get `pvid`, `frame-types`
  (`admit-all`, `admit-only-vlan-tagged`, `admit-only-untagged-and-priority-tagged`) and
  `ingress-filtering`. Not read: the maximum speed and the medium (only `monitor` has them).
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
  the VLAN interface's comment or name (except the default name `vlan<id>`, which names
  nothing); the native segment is named after the bridge's comment.
- **Uplink**: members of the interface list `WAN` (RouterOS' default configuration) are ports
  only: no segment, no subnets, and their ARP neighbours are not clients. Without that list the
  uplink port with its address becomes a network of its own, and no uplink is reported.
- **Uplinks** (#148): each member of the list `WAN` is `<device>/uplink/<interface>`, except a
  port that only carries a PPPoE client of the list. A member with a `/ip/dhcp-client` is kind
  `dhcp`, up when `status` is `bound`, with the lease `address`, `gateway` and
  `primary-dns`/`secondary-dns`; a `/interface/pppoe-client` is kind `pppoe` on the port of its
  `interface`, with `status` (`connected`), `uptime` (`since`), `local-address` and
  `remote-address` (the upstream gateway) from its monitor, else `running`; type `lte` is `lte`;
  a member with an address of its own is `static`, without one `other`. Addresses are those of
  `/ip/address` and `/ipv6/address` on the interface, the delegated prefix is the `prefix` of
  `/ipv6/dhcp-client`. `public-address` of `/ip/cloud` is the `public_ipv4` of the first
  connected uplink when it is a public address and not the uplink's own (it is only there after
  the router's own cloud update). No line rate: `/interface/lte monitor` is not read.
- **Subnets**: every enabled, non-link-local address from `/ip/address` and `/ipv6/address` on a
  bridge, VLAN interface or routed port, with `gateway: true` when the device's role is
  `gateway`.
- **DHCP**: one server per `/ip/dhcp-server` entry on a known interface. Pools from the
  `ranges` of its `address-pool` (and `next-pool`), lease time from `lease-time` (`30m`,
  `1d00:00:00`), router, DNS and domain from the most specific `/ip/dhcp-server/network` entry
  containing the interface address. Static leases (`dynamic=false`) of that server, or of `all` in its network,
  are reservations; the hostname is the lease comment, else `host-name`.
  Answering servers (#184, [PROBES.md](../PROBES.md)): a bound `/ip/dhcp-client` on an
  interface that is not in the `WAN` list gives the server it got its address from
  (`dhcp-server`, with `gateway`, `primary-dns`/`secondary-dns` and the lease); every
  `/ip/dhcp-server/alert` entry (the built-in rogue DHCP detector) gives the MAC addresses
  in `unknown-server` *(format of that list a guess, #21)*. Configure the detector with
  `/ip dhcp-server alert add interface=bridge valid-server=<your router's MAC>`; Signalbox
  decides itself which servers are known.
- **DNS**: one service on port 53 (`<device>/dns/dns`). Enabled when `allow-remote-requests=yes`; it then listens on the
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
  (`wpa2-psk,wpa3-psk` → WPA2/WPA3, `wpa-psk,wpa2-psk` → WPA/WPA2, `wpa-psk` → WPA,
  `wpa-eap` → WPA-Enterprise (also with `wpa2-eap`), `wpa3-eap-192` → 192-bit, empty → open),
  PMF from `management-protection`
  (`allowed` → optional), 802.11r from `ft` (`ft-nas-identifier` set: key holder `pmk-r1-push` *(guess)*; `/interface/wifi/steering` has no band steering, so none is reported), 802.11k/v from `steering.rrm`/`steering.wnm`
  (not set at all: unknown, RouterOS' default applies), hidden from `hide-ssid`, segment from the bridge port's `pvid`, else `datapath.vlan-id`. Client isolation and a network purpose are not read (declare the purpose in the desired state); a plan that sets `client_isolation` is refused.
- **Wireless (`wireless` package)**: radios from `/interface/wireless` entries without
  `master-interface` (`band` like `2ghz-b/g/n`, `frequency`, `channel-width`), WLANs in mode
  `ap-bridge` or `bridge`, security and passphrase from the `security-profile`
  (`/interface/wireless/security-profiles`, `mode=none` is open, `static-keys-*` WEP), segment
  from the bridge port, else `vlan-id` with `vlan-mode=use-tag`.
- **Security details (#167)**, `wifi` package, from the security profile: `ciphers` from
  `encryption` and `group_cipher` from `group-encryption` (only what is set; REST leaves out
  defaults), `sae.pwe` from `sae-pwe`, `sae.anti_clogging_threshold` from
  `sae-anti-clogging-threshold` (SAE modes), `wps` from `wps` (`push-button`, `disable`; no PIN
  *(guess)*), `key_rotation_seconds` from `group-key-update`; no SAE-PK, no beacon protection
  *(guess)*. `supported_security`: every mode incl. SAE, OWE, 192-bit *(guess for wifi-qcom-ac)*.
  `wireless` package: `unicast-ciphers`/`group-ciphers` (`tkip`, `aes-ccm`), profile
  `group-key-update`, interface `wps-mode` (`disabled`, `push-button`,
  `push-button-virtual-only`); no SAE; `supported_security`: open, WEP, WPA/WPA2 Personal and
  Enterprise. `passphrase_digest` is computed next to the fingerprint, from the same passphrase
  (readable with the `sensitive` policy only). The CI controller's CHR has no radios: nothing of
  this is confirmed by CI.
- **No wireless package** (neither `/interface/wifi` nor `/interface/wireless` exists): the
  wireless capability reports `no wireless package: ...` as a "could not read" finding. On
  RouterOS 7.25.1 CHR the `wifi` menu exists without radios (an empty list: no radios, no finding);
  `/interface/wireless` is missing there.
- **Clients**: merged by MAC from ARP, IPv6 neighbours, bound DHCP leases (dynamic and static),
  the bridge host table and the Wi-Fi registration table; the device's own MACs (port MACs and
  `local` bridge hosts), failed or incomplete entries and the uplink's neighbours are skipped.
  The segment comes from the interface of the ARP entry or lease, else the bridge host's `vid`,
  else the address; the location is the bridge host's port, or the WLAN for registered Wi-Fi
  stations.
- **Neighbours**: `/ip/neighbor` entries with a MAC on a known port (`interface` may list the
  port and its bridge, `ether2,bridge`). `identity` is the system name, `interface-name` the
  remote port, `address4` (else `address`) the management address.
- **Health** (#178): `uptime`, `cpu-load` (%), `cpu-count`, memory (used = `total-memory` -
  `free-memory`) and the `hdd` (`total-hdd-space`/`free-hdd-space`: the flash of a RouterBOARD,
  the disk of CHR, storage of kind `system`) from `/system/resource`; temperatures, fans, power
  supplies and the input voltage from `/system/health`. `/system/ups` is not read (CHR has
  none to confirm the fields with).
- **Time** (#179): the clock, `time-zone-name` (`manual`: no zone, only the offset) and
  `gmt-offset` from `/system/clock`; `/system/ntp/client` (`enabled`, `servers`, `status`,
  `synced-server`, `synced-stratum`) and `/system/ntp/server` (`enabled`; RouterOS serves time
  on every interface, so no segments). `ntp-server` of the DHCP network is the NTP server
  handed out by DHCP (option 42).

### DHCP leases, options and relays (#183)

- **Leases**: `/rest/ip/dhcp-server/lease` rows to the server named in `server` (`all` or empty:
  by the server's network). `status` `bound` is active, `offered` offered, `busy`/`conflict`
  declined *(guess)*, `waiting` and anything else `reserved` for a static lease, else expired;
  `dynamic` `false` is `reserved`; `expires-after` (a duration) from the observation time is
  `expires` (static leases have none); `class-id` is option 60, `client-id` option 61;
  `host-name`, else the comment, is the host name. Disabled leases are left out.
- **Options**: the names listed in `dhcp-option` of the server's network (and of the server) are
  looked up in `/rest/ip/dhcp-server/option` (`name`, `code`, `value`): code 119 and 121 are
  decoded from their hex value (RFC 1035 labels, RFC 3442 routes), 66 and 67 fill `boot`, other
  codes are `DhcpOption`s with the value as RouterOS shows it. The network's `next-server` and
  `boot-file-name` are `boot` too. `authoritative` of the server is true for `yes`,
  `after-2sec-delay` and `after-10sec-delay`, false for `no`; RouterOS 7.25.1 (CI) has no such property on `/ip/dhcp-server`, so it is unknown there. No failover.
- **Relays**: `/rest/ip/dhcp-relay` (`interface`, `dhcp-server` comma list, `disabled`).
- The read user needs nothing more (`read` covers all three menus). The CI router has a static
  lease and no relay: the integration test checks the static lease (`reserved`, status `waiting`), that `authoritative` is absent, the empty option and relay menus (both exist on 7.25.1).

## Endpoints and answers

All `GET /rest/<menu>` with HTTP basic auth. RouterOS answers a menu with a list of objects, each
with an `.id`, and a single-value menu with one object (a list holding one object is accepted
too). Every value is a string: booleans are `"true"`/`"false"`, numbers are digits, lists are
comma separated. The examples are shortened; unless marked *Guess* they are the shapes RouterOS 7.25.1 CHR
answers in CI (the full answers are posted by tools/integration/mikrotik/dump.py).

A menu the device does not have (a package that is not installed, `/system/routerboard` on CHR)
is answered with HTTP 400 `{"error": 400, "message": "Bad Request", "detail": "no such command
or directory (routerboard)"}` (`no such command prefix` for an unknown path), not 404: on an
endpoint marked *optional* that means "not on this device" and is not an error. A 404 on
`/rest/system/resource` means the REST API is not reachable as configured; a `PATCH` or
`DELETE` of an `.id` that does not exist is 404 too.

### `/rest/system/resource`, `/rest/system/routerboard` *(optional)*, `/rest/system/package/update` *(optional)* (system)

```json
{"version": "7.25.1", "board-name": "CHR QEMU Standard PC (i440FX + PIIX, 1996)",
 "architecture-name": "x86_64", "platform": "MikroTik", "free-memory": "843321344"}
{"routerboard": "true", "model": "C52iG-5HaxD2HaxD", "current-firmware": "7.15.3"}
{"channel": "stable", "check-certificate": "yes", "installed-version": "7.25.1", "mode": "https"}
```

`version` is required (older versions answered `7.15.3 (stable)`; the part after the space is
dropped). `latest-version` is only there after the router checked for updates; a refused or
missing update menu is ignored. CHR has no routerboard menu (HTTP 400 `no such command or
directory (routerboard)`): the model is the `board-name`. The routerboard answer is a *Guess*
from the documentation.

### `/rest/system/resource`, `/rest/system/health` *(optional)* (health)

As RouterOS 7.25.1 CHR answers them in CI:

```json
{"uptime": "9s", "cpu-count": "2", "cpu-load": "17", "free-memory": "842952704",
 "total-memory": "1073741824", "free-hdd-space": "72327168", "total-hdd-space": "93564928",
 "write-sect-since-reboot": "312", "write-sect-total": "312", "version": "7.25.1", ...}
{"state": "disabled", "state-after-reboot": "enabled"}
```

`uptime` uses the duration format of the other menus (`9s`, `3d04:05:06`, `1w2d3h4m5s`).
CHR has no sensors: `/system/health` is one object with the monitoring state, no values, which
gives no temperatures and is not an error. On RouterBOARD and CRS devices RouterOS 7 answers one
row per sensor; *Guess* from the documentation (no hardware in CI):

```json
[{".id": "*D", "name": "cpu-temperature", "value": "52", "type": "C"},
 {".id": "*E", "name": "fan1-speed", "value": "5400", "type": "RPM"},
 {".id": "*F", "name": "psu1-state", "value": "ok", "type": ""},
 {".id": "*10", "name": "voltage", "value": "24.1", "type": "V"}]
```

A row of type `C` (or with `temperature` in the name) is a temperature, `fanN-speed` (type
`RPM`) and `fanN-state` a fan, `psuN-state` a power supply (`ok` is fine). `voltage` and
`power-consumption` (W) without PSU rows describe the one power input (`power`). The single
object of older versions (`{"temperature": "45", "voltage": "24.1"}`) is read the same way.

### `/rest/system/clock`, `/rest/system/ntp/client`, `/rest/system/ntp/server` (time)

As RouterOS 7.25.1 CHR answers them in CI (defaults: no zone, NTP off):

```json
{"date": "2026-11-22", "time": "16:06:45", "time-zone-name": "manual", "gmt-offset": "+00:00",
 "time-zone-autodetect": "true", "dst-active": "false"}
{"enabled": "false", "mode": "unicast", "servers": "", "status": "stopped", "vrf": "main",
 "freq-drift": "0"}
{"enabled": "false", "broadcast": "false", "multicast": "false", "manycast": "false",
 "use-local-clock": "false", "local-clock-stratum": "5", "vrf": "main", "auth-key": "none"}
```

`date` is ISO since RouterOS 7.10 (`nov/22/2026` before; both are read), `time` is local time
with whole seconds, so the clock is the middle of that second and its uncertainty half the
round trip of the request plus half a second. `status` `synchronized` (with `synced-server`
and `synced-stratum`) is in sync; `started`, `reached`, `waiting`, ... of an enabled client is
not (yet) in sync (*Guess*: the values of a client that reached its server come from the
documentation, CHR in CI has no NTP server to reach). `primary-ntp`/`secondary-ntp` (RouterOS
6 style) are read when `servers` is empty. `/rest/system/ups` answers `[]` on CHR; it is not
read.

### `/rest/interface`, `/rest/interface/ethernet` *(optional)* (interfaces)

```json
[{".id": "*1", "name": "ether1", "type": "ether", "mac-address": "02:00:00:00:00:01",
  "running": "true", "disabled": "false", "mtu": "1500", "comment": "uplink"}]
[{".id": "*1", "name": "ether1", "speed": "1G-baseT-full", "auto-negotiation": "true",
  "advertise": "10M-baseT-half,10M-baseT-full,100M-baseT-half,100M-baseT-full,1G-baseT-full",
  "rx-flow-control": "off", "tx-flow-control": "off", "l2mtu": "1568"}]
```

*Guess*: `advertise`, the flow-control properties and `l2mtu` of hardware ports, from the
RouterOS documentation (the integration test checks only what CHR's virtio ports have; a
missing property leaves the detail unknown). Before RouterOS 7.12 `advertise` listed
`10M-full,1000M-full`, which is parsed too.

`speed` is the configured (or advertised) speed; the negotiated rate is only available from
`monitor`, which is not a `GET`. The virtio ports of CHR have no `speed` at all (the port is read
without one), so the format is a *Guess*: it changed from `1Gbps` to `1G-baseT-full` in
RouterOS 7.12; both are parsed.

### `/rest/interface/bridge`, `/rest/interface/bridge/port`, `/rest/interface/bridge/vlan` (interfaces)

```json
[{".id": "*1", "name": "bridge", "vlan-filtering": "true", "pvid": "1", "comment": "LAN"}]
[{".id": "*1", "interface": "ether4", "bridge": "bridge", "pvid": "20",
  "frame-types": "admit-only-untagged-and-priority-tagged", "ingress-filtering": "true",
  "disabled": "false"}]
[{".id": "*2", "bridge": "bridge", "vlan-ids": "20", "tagged": "bridge,ether2",
  "untagged": "ether4", "current-tagged": "bridge,ether2", "current-untagged": "ether4,wifi3",
  "dynamic": "false", "disabled": "false"}]
```

Dynamic entries (VLAN 1 from the pvids) are listed too and read the same way, with the
bridge and its pvid ports in `untagged` and `current-untagged` and the comment
`added by pvid`, which is not taken as the name of the network. The bridge port answer also
carries the spanning tree state and counters (`rx-bpdu`, `forward-transitions`, `debug-info`,
...): read only, never written back by a restore.

### Spanning tree: `/rest/interface/bridge/monitor`, `/rest/interface/bridge/port/monitor` (interfaces, #155)

Per bridge `Device.stp_bridges`: `protocol-mode` (`none`, `stp`, `rstp` (RouterOS' default),
`mstp`) and `priority` (hex, `0x8000`) from the bridge row; the own bridge id is the priority
and `current-mac-address` (else `mac-address`). For a bridge with spanning tree the read-only
`POST /rest/interface/bridge/monitor {"numbers": "<.id>", "once": ""}` gives `root-bridge`,
`root-bridge-id` (`0x8000.64:D1:54:00:00:01`), `root-port` and `root-path-cost`.

Per bridge port `Port.stp`: `bpdu-guard`, `restricted-role` (root guard), `edge` (`yes`,
`no`, `auto`, `*-discover`) and `path-cost` from the port row; `role` (`root-port`,
`designated-port`, `alternate-port`, `backup-port`, `disabled-port`), `forwarding`,
`learning`, `edge-port` and `actual-path-cost` from the print when RouterOS puts the running
state there, else from one `POST /rest/interface/bridge/port/monitor` with all port ids.
Not forwarding and not learning is `discarding` (RSTP, MSTP) or `blocking` (STP).
`loop-protect` of `/interface/ethernet` (`on`; `off` and `default` are off for Ethernet) is
the port's loop protection; `loop-protect-status` `disable` (a loop was detected) is state
`disabled`. A refused monitor keeps the settings and adds an optional gap
(`mikrotik.stpMonitor`). *(guess: the monitor fields are those of the RouterOS manual; the CHR
integration test checks the bridge, a real switch with hardware offload should confirm the
port roles, #21)*

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

IPv6 link-local addresses (`fe80::/64`, dynamic) are skipped by their address; only some of
them carry `link-local: true`. Without IPv6 `/ipv6/address` is a missing menu (optional).

### `/rest/ip/dhcp-client`, `/rest/ipv6/dhcp-client`, `/rest/interface/pppoe-client`, `/rest/ip/cloud` *(optional)* (interfaces: uplinks)

Read only when the list `WAN` has members.

```json
[{".id": "*1", "interface": "ether1", "status": "bound", "address": "203.0.113.2/24",
  "gateway": "203.0.113.1", "primary-dns": "203.0.113.53", "secondary-dns": "203.0.113.54",
  "expires-after": "23h12m5s", "disabled": "false", "invalid": "false"}]
[{".id": "*1", "interface": "ether1", "status": "bound", "prefix": "2001:db8:1::/56, 2d23h50m10s"}]
[{".id": "*1", "name": "pppoe-out1", "interface": "ether1", "running": "true", "disabled": "false"}]
{"public-address": "203.0.113.2", "ddns-enabled": "false", "status": "updated"}
```

The DHCP client is as RouterOS 7.25.1 CHR answers it in CI (`ether1`, bound, with `gateway`
and `primary-dns`); there `/ip/cloud` has no `public-address` (no cloud update), and the other
two menus are empty lists (tools/integration/mikrotik/dump.py `uplink` records all four).
*Guess* (#21): the IPv6 client's `prefix` with its lifetime after the comma, and the PPPoE
client and monitor fields, are from the RouterOS documentation. For a PPPoE client the adapter runs its monitor once,
`POST /rest/interface/pppoe-client/monitor` with `{"numbers": "pppoe-out1", "once": ""}`, a read
command of the `read` policy *(guess: not tried on a device with a PPPoE session)*:

```json
[{"status": "connected", "uptime": "1d2h3m4s", "local-address": "203.0.113.77",
  "remote-address": "203.0.113.1", "service-name": "", "ac-name": "isp-bras", "mtu": "1492"}]
```

A monitor of a client that does not exist is HTTP 404 `{"error": 404, "message": "Not Found"}`
on the CHR. A refused monitor leaves the uplink with the client's `running` flag and without
addresses or uptime; a refused `/ip/cloud` without a public address.

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

RouterOS 7.25.1 CHR answers `type: "A"` for `A` records too (an entry without `type` is still read
as `A`), and `cache-size` as KiB without a unit (`"2048"`).

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

### BSSIDs and neighbouring networks (#169)

`mac-address` of each `/interface/wifi` and `/interface/wireless` row (virtual APs included) is
the WLAN's `bssid`. Neighbouring networks are not read: `/interface/wifi/scan` (and the old
package's `/interface/wireless/scan`) is an active scan that takes the radio off its channel and
disconnects its clients while it runs, and RouterOS has no passive neighbour list for the
`wifi` package. The registration table holds only our own clients (#172: counts per radio).

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

Radio capabilities and state (#172), with the wireless read: `Radio.standard` is the newest
standard of the configured band (`channel.band` `2ghz-ax`: ax; legacy `band` `5ghz-a/n/ac`:
ac), `channel_auto` is on when no single frequency is set (legacy: `frequency` `auto`), and
`client_count` counts the registration-table rows of the radio and its virtual interfaces
(not readable: not reported). For the `wifi` package, `/rest/interface/wifi/radio` gives
`standards` from `bands` (`2ghz-g,2ghz-n,2ghz-ax`), `supported_channels` from `2g-channels` /
`5g-channels` (MHz), `antennas` from `tx-chains`/`rx-chains` (`0,1`: 2x2) and `dfs_capable`;
rows are matched by `interface`, else by `radio-mac` *(guess: the REST field names and the
`interface` column; from the RouterOS 7.13 `print` output)*. Missing or refused: not
reported. Not read: utilisation, noise and DFS state (`/interface/wifi/monitor` is a command
that runs until stopped), `max_tx_power_dbm`, `mlo`.

### `/rest/ip/neighbor` (neighbours)

```json
[{".id": "*1", "interface": "ether2,bridge", "address4": "192.0.2.2",
  "mac-address": "02:00:00:00:00:50", "identity": "switch", "platform": "MikroTik",
  "board": "CRS326-24G-2S+", "interface-name": "ether24", "discovered-by": "lldp,mndp"}]
```

*Guess*: on a bridged port `interface` lists the port and the bridge.

### `/rest/interface/wireguard`, `/rest/interface/wireguard/peers` *(optional)* (vpn, #152)

```json
[{".id": "*1", "name": "wg0", "mtu": "1420", "listen-port": "51820", "public-key": "...",
  "running": "true", "disabled": "false", "comment": "site link"}]
[{".id": "*2", "interface": "wg0", "public-key": "...", "allowed-address": "2001:db8:ff::2/128,203.0.113.0/24",
  "endpoint-address": "203.0.113.20", "endpoint-port": "51820", "current-endpoint-address": "203.0.113.20",
  "persistent-keepalive": "25s", "last-handshake": "42s", "rx": "1834567", "tx": "2934871",
  "name": "peer1", "comment": "site-b", "disabled": "false"}]
```

Both menus can also return `private-key` (interface; peers of 7.15 and later for client
configurations) and `preshared-key` (peer). RouterOS shows them only to a user with the
`sensitive` policy, which the read-only group does not have; a login that has it gets them
anyway, so the adapter deletes `private-key` and turns `preshared-key` into a flag while
parsing, and reads these two menus without its answer cache. `last-handshake` is how long ago
(absent before the first handshake); `comment` names the peer (else `name`, which RouterOS fills with `peer1`, `peer2`, ... itself); addresses come
from `/ip/address` and `/ipv6/address` of the interface. Without the menu (no
`wireguard` package) there are no tunnels and no error. *Guess*: field names per 7.x release; CI
(CHR) confirms the interface, the peer, the allowed addresses and the keepalive, not a handshake.

### IPsec and OpenVPN: `/rest/ip/ipsec/*`, `/rest/interface/ovpn-server*`, `/rest/interface/ovpn-client` *(optional)* (vpn, #153)

Read policy only. A tunnel is one IPsec `peer` (`address`, `exchange-mode`: `ike2` is IKEv2,
`aggressive` sets the aggressive flag, `profile`) with its `identity` (`auth-method` only), its
`profile` (RouterOS 7.1 and later: `enc-algorithm`, `hash-algorithm`, `dh-group`,
`dpd-interval`; before that the peer holds them itself, read the same way), the `policy` rows
naming the peer (child SAs: `src-address`, `dst-address`, `ph2-state`, `proposal`), the
`proposal` (`enc-algorithms`, `auth-algorithms`, `pfs-group`, `lifetime`) and
`active-peers` (`remote-address`, `uptime`: the peer is up). RouterOS lists algorithms per
kind, so every entry becomes one `CryptoProposal` and a weak one is reported whatever it is
combined with. `/rest/ip/ipsec/identity` carries `secret`, `eap-password` and key names: every
secret-like field is dropped while the answer is parsed (nothing is cached), only `auth-method`
is used. OpenVPN: `/interface/ovpn-server/server` (a tunnel `ovpn-server` once enabled or in
use: `port`, `protocol`, `cipher`), the connected clients of `/interface/ovpn-server`
(`user`, `client-address`) and every `/interface/ovpn-client` (`connect-to`, `running`,
`cipher`); the `password` of a client is dropped. RouterOS has no `tls-auth`/`tls-crypt`, so
`tls_auth` stays unknown. A menu that is missing is skipped, one the group may not read is an
optional gap. Guesses until a CHR run (#21): `ph2-state`, the `active-peers` field names and
the `ovpn-server` menu answers.

### Configuration state and backups (#181)

RouterOS saves every change at once, so `config_state.unsaved` and `pending` are `false`.
`last_changed` and `changed_by` come from the newest row of `/rest/system/history` (undoable
actions since the boot: no row means none since the restart). `local_backups` counts the `backup`
files and `.rsc` exports of `/rest/file` (count 0 when the list is readable and has none; unknown
when the login may not list files, as with the read-only group above, which has no `ftp` policy *(guess)*) with the newest `creation-time`. The firmware channel is
`/rest/system/package/update` `channel` (stable, long-term, testing, development). *(Guess: the
`/rest/file` `type` and `creation-time` spelling of older 7.x releases, #21.)*

## Writing

Signalbox changes a RouterOS device only through a reviewed and approved change (see
[docs/CHANGES.md](../CHANGES.md)), only when "allow changes" is on for the device, and only with
a user whose group has the `write` policy. Each RouterOS menu entry is changed with one REST
request:

| Request | Meaning |
| --- | --- |
| `PUT /rest/<menu>` with the properties | create an entry; the answer is the new entry with its `.id` |
| `PATCH /rest/<menu>/<.id>` with the changed properties | change an entry |
| `DELETE /rest/<menu>/<.id>` | remove an entry |
| `POST /rest/<menu>/unset` with `{"numbers": "<.id>", "value-name": "<property>"}` | clear a property (it falls back to its profile or default) |
| `POST /rest/execute` with `{"script": "/export", "as-string": ""}` | the configuration as text, for the backup (for people only, see below) |

The review shows exactly these requests. The Wi-Fi passphrase is shown as `***`; it is never
logged or put into an error message.

### A user group that may write

```
/user group add name=signalbox-write \
    policy=read,write,api,rest-api,sensitive,!policy,!password,!reboot,!test,!sniff,!romon,!local,!telnet,!ssh,!ftp,!winbox,!web
/user set signalbox group=signalbox-write
```

- `write` lets the user change the configuration. Without it every change is refused with
  `access denied (not enough permissions (9)); the user's group needs write` (RouterOS:
  HTTP 500), and nothing is changed.
- `sensitive` is needed for a complete backup: without it RouterOS hides the Wi-Fi passphrases
  in its answers, so the backup cannot put a changed passphrase back. If you keep a read-only
  group for everyday reading, switch the user's group only for deployments.
- `policy` and `password` stay off: Signalbox never manages users.

### What each change does

| Kind | Calls |
| --- | --- |
| `router` | A VLAN network: creates the VLAN interface `vlan<id>` on the bridge (comment = the segment name), tags the bridge itself in the bridge VLAN table (a new entry, or `bridge` added to `tagged`) and adds the address in `/ip/address`. An existing network: changes its address entry. A new name goes to the first of: the comment of the bridge (native network), of the single-VLAN bridge VLAN entry, of the VLAN interface (the one the read side takes it from); no name clears them all. Removing deletes the address, the VLAN interface if no address is left on it, and the bridge from the VLAN's `tagged` list (the entry too if it is then empty). |
| `dhcp` | Creates or changes the `/ip/dhcp-server` entry on the network's interface (`disabled`, `lease-time`), the first range of its `/ip/pool` (a pool `dhcp-<interface>` if it has none) and the DNS servers of the `/ip/dhcp-server/network` entry (created with gateway = the router's address when missing). Removing deletes the server, and its pool and network entry when nothing else uses them. |
| `reservation` | A static `/ip/dhcp-server/lease` with `address`, `mac-address` (upper case), `server` and the hostname as `comment`. |
| `port` | Ports of a bridge with `vlan-filtering`: the untagged VLAN is the bridge port's `pvid` (`frame-types` set to `admit-all`, or to `admit-only-vlan-tagged` for no untagged VLAN); tagged VLANs are the port's place in the `tagged` lists of `/interface/bridge/vlan` (new single-VLAN entries where needed). The port leaves every other `tagged`/`untagged` list; an entry left empty is removed. |
| `wlan` | Every `/interface/wifi` entry with the SSID gets the values inline: `configuration.hide-ssid`, `security.authentication-types`, `security.passphrase` (from the stored secret), `security.management-protection`, `security.ft` (802.11r) with `security.ft-mobility-domain` (written as a number) and `security.ft-over-ds` where declared, `steering.rrm`/`steering.wnm` (802.11k/v), `disabled`; the VLAN is the `pvid` of its static bridge port and `datapath.vlan-id`. A value the change leaves unset is unset inline. A new SSID is a virtual interface `<radio>-<ssid>` on every radio, with `datapath.bridge` = the filtering bridge. Removing deletes those virtual interfaces. A minimum signal (`min_rssi_dbm`) lives in `/interface/wifi/access-list` together with the owner's MAC rules and is refused for now ([ADR 0033](../adr/0033-wifi-roaming-desired-state.md)). |

Refused with a readable message, before anything is sent:

- a network without an interface that is not a VLAN (Signalbox only creates VLAN interfaces),
  and an address that is dynamic (a DHCP client on the uplink)
- a VLAN in a bridge VLAN entry shared with other VLANs (`vlan-ids=20,30`) when the change needs
  that VLAN on its own: split the entry on the device first
- ports that are not in a bridge with `vlan-filtering` (VLAN interfaces on plain ports are not
  written)
- WPA2/WPA3 Enterprise and other security modes (only open, OWE and WPA2/WPA3 personal), a
  personal SSID without a passphrase, removing the SSID of a radio interface (it can be
  disabled, not removed), and the legacy `wireless` package (read only)

Known limits:

- An SSID on several radios is set to the same values on all of them; undoing the change sets
  them all to the values Signalbox read (those of the first radio). The backup restores each
  exactly.
- Making an SSID open clears its `security` profile reference, passphrase included. The inverse
  change cannot set the passphrase back (it is not known to Signalbox), so such a rollback uses
  the backup.
- The hostname of a reservation is its `comment`. Without a comment RouterOS shows the
  `host-name` the client sent, so "no hostname" cannot be set on such a lease.

### Transaction and rollback

RouterOS has `safe-mode` only for interactive terminal sessions; the REST API has no confirm
timer. So `apply` returns no deadline for the other kinds (firewall changes arm a scheduler
revert, see [Firewall changes](#firewall-changes-295)): a change is in effect as soon as
each request is answered, and Signalbox's own verification decides. It reads the device again
and rolls back if a value is not as planned, the device does not answer, or the checks report
new errors.

- **Backup**: before applying, a JSON snapshot (`GET`) of every menu Signalbox may change
  (`/interface/vlan`, `/interface/bridge`, `/interface/bridge/vlan`, `/interface/bridge/port`,
  `/ip/address`, `/ip/pool`, `/ip/dhcp-server`, `/ip/dhcp-server/network`,
  `/ip/dhcp-server/lease`, `/interface/wifi`, `/ip/firewall/filter`, `/ipv6/firewall/filter`,
  `/ip/firewall/nat`), plus the text of `/export` for people (backup
  format `routeros-export`, stored encrypted with the change record). `POST /rest/export`
  answers `[]` (the export goes to a terminal, which a REST request does not have), so the text
  comes from `POST /rest/execute` with `{"script": "/export", "as-string": ""}`, answered as
  `{"ret": "# ... by RouterOS 7.25.1 ..."}`; without `sensitive` secrets are left out of it. An export cannot be
  imported through the REST API (`/import` needs a file on the router), so it is not used for
  restoring.
- **Rollback**: first the inverse changes; if that fails, the backup. Restoring compares every
  saved menu with the device and undoes the difference: entries that are not in the backup are
  removed, missing ones are added again (with a new `.id`), changed ones are set back, and
  properties that were added are unset. Entries are matched by `.id`, else by equal content, so
  a second restore changes nothing. Dynamic entries are left to RouterOS.

### Verified against RouterOS 7.25.1 CHR

- `PUT` answers the new entry with its `.id`; `PATCH`, `DELETE` and `unset` as above.
- A refused change is HTTP 400 `{"error": 400, "message": "Bad Request", "detail": "input does
  not match any value of interface"}` (or `invalid value for argument address`, ...); the
  error shows `<what>: the router refused the change: <detail>`.
- A new DHCP server on the interface of a new address is `invalid` (`.about`: `No IP address on
  interface`) for about a second. After writing a DHCP server Signalbox waits (up to 15 s)
  until it is valid, so the verification does not read it as disabled.
- The name of a network goes to the comment the read side takes it from first (the bridge, else
  the single-VLAN bridge VLAN entry, else the VLAN interface), and only there: setting the
  comment on all of them made undoing a rename leave a comment that was not there before.
- The read-only properties a restore leaves out: besides the documented ones (`running`,
  `dynamic`, `current-*`, `actual-interface`, `network`, `mac-address` of interfaces, ...) the
  spanning tree state and counters of bridge ports, `l2mtu`, `available`/`total`/`used` of
  pools, the `agent-*` fields of leases and `.about`. Every round trip in the tests (deploy,
  revert, restore) leaves these menus exactly as they were, entry by entry.

### Not confirmed on a real device

CHR has no radios, so the Wi-Fi writes are tested against the simulator only
([issue #21](https://github.com/PhilippMundhenk/signalbox/issues/21)). To confirm:

- *Guess*: dotted property names (`security.passphrase`, `datapath.vlan-id`) are accepted by
  `PUT`/`PATCH` on `/interface/wifi` as by the CLI's `set`, and `unset` with
  `value-name=security` detaches the security profile.
- *Guess*: a Wi-Fi interface with `datapath.bridge` becomes a dynamic bridge port whose `pvid` is
  `datapath.vlan-id`, and a pvid no VLAN entry lists gets a dynamic entry (as the simulator
  models it).
- *Guess*: a static lease can be added for a MAC that has a dynamic lease (RouterOS might want
  `make-static` instead).
- The read-only properties of `/interface/wifi`; a property RouterOS refuses to set stops the
  restore with its message.

## Simulator

`signalbox.sim.mikrotik.MikrotikSimulator` answers these endpoints with neutral sample data (a
hEX-like router with Wi-Fi and bridge VLAN filtering, a DHCP client on the uplink `ether1`,
documentation addresses, `02:` MACs). A PPPoE client added to `/interface/pppoe-client`
answers its monitor with `pppoe_session` (`read_only_monitor`: refused). Its
switches simulate a wrong password (401), a disabled REST API (404 everywhere), slow answers,
malformed JSON per path, a status code per path, a menu the group has no policy for
(`no_policy`: HTTP 500 `not enough permissions (9)`), and the wireless package installed
(`wifi`, `legacy` or `none`; a missing menu is HTTP 400 `no such command or directory`, as on
RouterOS 7.25.1 CHR).

It also takes the write requests above and changes its data: it refuses what RouterOS would
(missing properties, unknown interfaces, pools or servers, duplicate names, bad addresses,
dynamic entries) with HTTP 400 and a `detail`, and then settles what RouterOS computes itself
(VLAN and Wi-Fi interfaces in `/interface`, the dynamic bridge port of a Wi-Fi interface with
`datapath.bridge`, the `current-*` lists and dynamic entries of the bridge VLAN table, a new
DHCP server that answers `invalid` once). `POST /rest/export` answers `[]` and
`POST /rest/execute` the export, as the real one. Write switches: `read_only` (HTTP 500
`not enough permissions (9)`, a group without `write`), `fail_write` (a status code per menu)
and `ignore_writes` (answer success, change nothing).

## Integration tests

`.github/workflows/integration.yml` (job `mikrotik`, nightly, on demand and on pull requests
that touch adapters or simulators) downloads the official `chr-7.25.1.img.zip` (the stable
channel on 2026-11-22) from download.mikrotik.com and checks it against a pinned SHA-256
(MikroTik publishes no checksum file next to the image; the hash was taken from the first
download in CI). tools/integration/mikrotik/vm.py boots it in QEMU with KVM:

- first boot over the serial console: log in as `admin` (no password), set a random one, add
  the CA, the `www-ssl` certificate and the service exactly as in
  [HTTPS with a certificate](#https-with-a-certificate); then through the REST API as admin:
  ether1 (QEMU user network, DHCP client) in the interface list `WAN`, the bridge `bridge`
  (comment `LAN`) with ether2 and ether3, VLAN 20 (`IoT`) tagged on ether3 and the bridge, the
  VLAN interface `iot`, 192.0.2.1/24 and 2001:db8:1::1/64 on the bridge, 198.51.100.1/24 on
  `iot`, a DHCP server with pool, network and a static lease, DNS with remote requests, a
  forwarder and static `A`/`AAAA` entries, `vlan-filtering=yes`, and the groups and users of
  [A read-only user group](#a-read-only-user-group) and
  [A user group that may write](#a-user-group-that-may-write) with their policies verbatim. The
  prepared disk is cached.
- every run boots a throw-away overlay of that disk; the runner reaches `www-ssl` at
  `https://127.0.0.1:8443` (a port forward to ether1). tools/integration/mikrotik/dump.py posts
  the answers of every menu (read user, write user, refused requests) as notices.
- tests/integration/test_mikrotik_real.py: the read contract, the mapping of the configured
  router, certificate pinning with the real certificate, a wrong password (auth failed), the
  missing menus of CHR, the read user refused on a change, a refused change with RouterOS'
  detail, the backup with the export, the adapter's apply, read back and restore, deployments
  through the Deployer (a new VLAN network with DHCP and a static lease; changed router
  address and name, DHCP pool, DNS and lease time, a static lease and the tagged VLANs of a
  trunk port), each reverted, and the restore of a backup (a VLAN on a port, a new router
  interface). After every round trip the menus are compared entry by entry.

The test VM is never run locally: without `IT_MIKROTIK_URL` the tests skip.


## Management services (#173)

Read with the `interfaces` capability; every service is reported, disabled ones too.
*Verified on the RouterOS 7.25.1 CHR in CI* (`test_management_services_of_chr`; the raw answers
are the `services` dump group), as the read-only user of this page.

- `GET /rest/ip/service`: one row per service (`telnet`, `ftp`, `www` as `http`, `ssh`,
  `www-ssl` as `https`, `api`, `winbox`, `api-ssl`) with `port`, `disabled`, `proto`, `vrf` and
  `available-from` (comma-separated prefixes: `allowed_from`; `address` before 7.25).
  Dynamic rows (the `resolver`, one per open connection) and names the adapter does not know
  (`reverse-proxy`) are skipped.
- `GET /rest/tool/mac-server` and `/rest/tool/mac-server/mac-winbox` (`mac-telnet`,
  `mac-winbox`; layer 2, no port): `allowed-interface-list` `none` is off, `all` is every
  interface, another list name is resolved with `/rest/interface/list/member` to the ports
  *(guess: not tried with a custom list)*. `GET /rest/tool/romon` and `GET /rest/ip/upnp`:
  `enabled`.
- `GET /rest/ip/ssh`: `password-authentication` `yes` or `no` is `password_login`;
  `yes-if-no-key` (a password only while the user has no key) is left unknown.
  `always-allow-password-login` is read when the router has no such field.
- `GET /rest/snmp` (`enabled`) and `/rest/snmp/community`: whether a community named `public`
  exists, whether any community has `write-access`, and the versions: `security` `none` is
  v1/v2c, `authorized` is authNoPriv and `private` is authPriv (`v3_privacy`). The protocol
  fields are filled whatever the level (`DES` on `public`). The community string itself is
  never stored. The read user sees the community names without the `sensitive` policy (the
  passwords are `*****`).
- `GET /rest/ip/cloud` (#327, kind `cloud`, name `mikrotik-cloud`): on when `ddns-enabled` is
  `yes`, when it is `auto` and `status` is `updated` (the router has reached the cloud), or
  when `back-to-home-vpn` is `enabled`. *Guess (#21)*: what `auto` means on each RouterOS
  version and the field names `back-to-home-vpn` and `status`; the CHR in CI has no cloud
  update. Feeds the info check `cloud.enabled`.
- A menu the read group may not read (or `/ip/service` itself) leaves out its services; when
  `/ip/service` fails the list stays empty (not read) and the rest of the read is unaffected.
- `transport_encrypted` is true for the https URL, false for `allow_insecure_http`.
- `from_wan` stays unknown: the firewall is not read (#135).


## Log and flow targets (#180)

- `GET /rest/system/logging/action`: every action with `target=remote` and a `remote` address
  other than `0.0.0.0` is a syslog target (`remote-port`, 514; `remote-protocol` `tcp` where
  RouterOS has it, else UDP). It is enabled when an enabled, valid rule of
  `GET /rest/system/logging` uses it; the topics are those rules' `topics`.
- `GET /rest/ip/traffic-flow` (`enabled`) and `/rest/ip/traffic-flow/target` (`dst-address`,
  `port`, `version` `1`/`5`/`9` as NetFlow or `ipfix`, `disabled`).
- `GET /rest/snmp`: `trap-target` (comma-separated) as `snmp-trap` targets, enabled while SNMP is
  on and `trap-generators` is not empty; `trap-community` is never read.

The read user's `read` policy covers all of them. A refused `/system/logging/action` leaves the
targets unread with an optional gap; a missing traffic-flow menu only leaves out flows. *CI*
(CHR 7.25.1, dump group `logging`): the defaults read as "nothing sent". *Guess:* the fields of
a router with targets configured.

## Firewall and NAT (#135)

Read with the `firewall` capability (adapter API 1.4, [ADR 0013](../adr/0013-firewall-zones-rules-and-reachability.md))
with the existing read-only group (`read`, `api`, `rest-api`): `/rest/ip/firewall/filter`,
`/rest/ipv6/firewall/filter`, `/rest/ip/firewall/nat`, `/rest/ip/firewall/raw`,
`/rest/ip/firewall/address-list` (and `ipv6/`), `/rest/interface/list` with its members and
`/rest/ip/ipsec/policy`.

- **Zones**: every interface list a rule names (`in-interface-list`, `out-interface-list`;
  `include` and `exclude` resolved; `all` is no condition), and every single interface a rule
  names (`in-interface=iot`) as a zone of its own. Members map to segments (bridges, VLAN
  interfaces, routed ports), uplinks, WireGuard tunnels or bare ports.
- **Rules** of the `input`, `forward` and `output` chains, IPv4 then IPv6, in list order. `jump`
  is flattened (the jump rule's conditions joined with each rule of the chain; two different
  conditions make the rule inexact; a loop makes the list incomplete); a conditional `return`
  makes the rest of its chain inexact. Left out: rules that only match
  `established`/`related`/`invalid`/`untracked`, `fasttrack-connection`, `passthrough`, `log`.
  `connection-nat-state=dstnat` is `forwarded`. `src-address-list` and `dst-address-list` are
  resolved (ranges become prefixes); a dynamic entry or a host name makes the rule inexact, as
  do the conditions the model has no field for (`limit`, `connection-mark`, `src-mac-address`,
  `tcp-flags`, `time`, `!protocol`, `!dst-port`, ...). `ipsec-policy`: without an active IPsec
  policy `in,ipsec` can never match (the rule is left out) and `out,none` matches all.
  Both chains' defaults are `accept` (`input_policy`, `forward_policy`). A `drop` in
  `/ip/firewall/raw` makes `rules_complete` false.
- **NAT**: `srcnat` masquerade and `src-nat` to `NatRule` (an `accept` rule in the chain makes
  them inexact), `dstnat` `dst-nat` to `PortForward` (`passes_filter = False`: the filter decides;
  `dst-address-type=local` is the router's own address); `redirect` goes to the router itself
  and is not a forward; `netmap`, `jump` and a target that is no single address make
  `port_forwards_complete` false.
- **CI** (CHR 7.25.1): `rest_setup` adds a LAN list, an address list, a forward rule, masquerade
  and a `dst-nat`; `test_firewall_rules_and_nat` asserts them as the read-only user.
  *Guess*: the `/interface/list` row fields `include`/`exclude`, jumps and address ranges on
  a real router (the simulator has them), `ipsec-policy` rows with IPsec configured.

## Log targets and SNMP (#327)

The kinds `log-target` and `snmp-policy`
([ADR 0021](../adr/0021-logging-and-snmp-desired-state.md)):

- **Syslog target**: an action `signalbox<address>` (`192.0.2.5` becomes `signalbox192x0x2x5`: RouterOS allows only letters and numbers in the name) in `/system/logging/action`
  (`target=remote`, `remote`, `remote-port`, `remote-protocol` `udp` or `tcp`) and four rules in
  `/system/logging` (`topics` `info`, `warning`, `error`, `critical`; RouterOS needs all topics of
  a rule on a message, so each is a rule of its own) that send to it. Only actions with that name
  prefix are changed or removed, together with the rules that use them; the device's own action
  (the one the user made) only when the change adopts its address (it and its rules are then
  removed, and an undo creates it again as `signalbox<address>`). Several targets are fine. TLS
  is refused.
- **SNMP**: `POST /rest/snmp/set {"enabled": "false"}`; the revert sets `enabled=yes`. `v3-only` is
  refused (SNMPv3 users need secrets). Communities are neither read into the model nor touched.
- **Revert**: both are protected by the scheduler entry `signalbox-revert` of the firewall
  changes (armed first, removed by `confirm`); its script removes the created action and rules,
  re-adds removed ones, resets changed properties and sets `/snmp` back. The backup holds the two
  logging menus and the state of `/snmp`.
- *Guess (#21)*: `remote-protocol=tcp` and the four-topic rules on a real router; that RouterOS
  accepts `/snmp set enabled=yes` in the scheduler's script for the revert.

## Gateway group (#463)

The kind `gateway-group` ([ADR 0032](../adr/0032-gateway-group-desired-state.md)) for the group
`default`, the enabled IPv4 default routes of the `main` table (see [Multi-WAN](#multi-wan-and-mikrotik-cloud-150-154)). Members are
found by their gateway; routes and netwatch entries are never added or removed.

- **Tier**: the route's `distance`. When the order of the tiers changes, every member gets its
  tier number (1, 2, ...) as distance; otherwise distances are left as they are.
- **Monitor**: the route's gateway in the monitor is `check-gateway=ping`; without it
  `check-gateway` is unset (`POST /rest/ip/route/unset`; an `arp` check is not a monitor address
  and stays). Another address changes the `host` of the netwatch entry whose comment is the
  route's comment (its up and down scripts stay as they are). Without such an entry, or to drop
  that address, the change is refused: Signalbox does not add or remove netwatch entries.
- **Refused**: a weight (RouterOS shares the load of one distance equally), and any change of a
  route a DHCP or PPPoE client added (dynamic; change the client's `default-route-distance`).
- **Revert and backup**: the scheduler entry `signalbox-revert` (see Firewall changes) sets
  `distance`, `check-gateway` and the netwatch host back unless the change is confirmed; the
  backup holds these values of the static default routes and the netwatch entries, and a restore
  sets them back by `.id`.
- *Guess (#21)*: the netwatch tie by comment, `unset` of `check-gateway` on RouterOS 7, and the
  `/ip route set *<id>` lines in the scheduler's script on a real router.

## WireGuard tunnels (#152)

The kinds `tunnel` and `tunnel-peer` ([ADR 0034](../adr/0034-wireguard-tunnels-desired-state.md)).
What Signalbox creates carries the comment `signalbox:wg/<tunnel>`; an adopted interface or peer
keeps its own comment and is found by its name or the other end's public key.

- **Interface**: `/interface/wireguard` with `name`, `listen-port`, `mtu`, added without
  `private-key`, so RouterOS generates the key pair; the tunnel addresses are `/ip/address` and
  `/ipv6/address` entries on it (the declared ones replace the others on that interface).
- **Peer**: `/interface/wireguard/peers` with `interface`, `public-key` (the other end's, read
  from it), `allowed-address`, `endpoint-address` and `endpoint-port` where the other end
  declares an endpoint, `persistent-keepalive` where declared. RouterOS does not route allowed
  addresses: each network behind the other end gets a static route (`/ip/route`,
  `/ipv6/route`, `gateway` the interface, tagged), unless the router already routes it into
  the interface.
- **Keys**: the menus are read with `private-key` and `preshared-key` dropped on arrival; no
  key is ever sent, and a peer's pre-shared key is left as it is. The backup's export has both
  removed (RouterOS 7 leaves them out unless asked), and the backup keeps the interface, peer
  and route rows without keys.
- **Revert and backup**: the scheduler entry `signalbox-revert` (see Firewall changes) removes
  what was added and sets changed values back unless the change is confirmed; a removed
  interface comes back with a new key pair, so its peer on the other end needs the next
  deployment. A restore puts the rows of the backup back by `.id`.
- *Guess (#21)*: the property spellings in a write (`allowed-address` as a comma list,
  `persistent-keepalive=25s`) and the scheduler script lines on a real router.

## UPnP (#513)

The kind `upnp` ([ADR 0035](../adr/0035-upnp-desired-state.md)), only with the fields the
desired state declares:

- **On or off**: `POST /rest/ip/upnp/set` with `enabled`. Turning it off comes before the
  networks change, turning it on after them.
- **Networks**: the `internal` rows of `/ip/upnp/interfaces` are the layer-3 interfaces of the
  declared segments (the bridge or VLAN interface, the first by name): an internal row of
  another network is disabled, a disabled one of a declared network enabled again, a missing
  one added (`interface`, `type=internal`). `external` rows are left alone. A segment without
  an interface on the router is refused.
- **Refused**: `secure_mode` and `allow`: RouterOS has no secure mode and no permission rules
  (limit the networks instead).
- **Mappings**: the dynamic `dst-nat` rows are not removed by Signalbox; they end with their
  lease, and RouterOS may drop them itself when the service stops (*guess*, #21).
- **Revert and backup**: the scheduler entry `signalbox-revert` (see Firewall changes) switches
  the service and the interface rows back unless the change is confirmed; the backup holds
  `enabled` of `/ip/upnp` and the rows of `/ip/upnp/interfaces`, and a restore sets them back.
- The write user's group needs nothing more (`write` covers `/ip/upnp`).
- *Guess (#21)*: the script lines `/ip upnp set enabled=...` and `/ip upnp interfaces ...` on a
  real router.

## PoE (#484)

The kind `poe` ([ADR 0036](../adr/0036-poe-desired-state.md)), one change per declared port:

- **On or off**: `PATCH /rest/interface/ethernet/poe/<id>` of the port's row with
  `poe-out=auto-on` or `poe-out=off`. Signalbox never writes `forced-on` (it powers a device
  that did not ask for it); a port on `forced-on` already counts as on and is left alone.
  `poe-priority` and `poe-voltage` are not changed. A port without a row in that menu is
  refused.
- **What it reads back**: `poe-out` of the row and the `poe-out-status` of `monitor once`, as
  for reading (#159).
- **Revert and backup**: the scheduler entry `signalbox-revert` (see Firewall changes) sets
  `poe-out` back unless the change is confirmed; the backup holds `poe-out` of every row, and a
  restore sets it back.
- The write user's group needs nothing more (`write` covers `/interface/ethernet/poe`).
- *Tested against the simulator only*: CHR has no PoE-out, so the integration test on CHR
  cannot cover it. *Guess (#21)*: the REST `PATCH` of a row of this menu and the script line
  `/interface ethernet poe set [find where name=...] poe-out=...` on a real board.

## Firewall changes (#295)

The kinds `firewall-rule`, `port-forward` and `zone-policy` are written
([ADR 0017](../adr/0017-firewall-desired-state-and-deployments.md), the same ownership rules as
on [OpenWrt](openwrt.md) and [OPNsense](opnsense.md)):

- **Ownership**: Signalbox creates rows with the comment `signalbox:<key>` (` <name>` follows when
  the name is not the key; zone policies `signalbox:policy/<from>/<to|device>`). Only rows with
  that comment are changed or removed. The device's own rows are touched only when a change says
  `adopt` (the row with that comment is changed in place: new comment and the declared properties,
  every other property such as `log` or `connection-state` stays and is listed in the plan;
  `in-interface` and the address lists are replaced by the declared zone and networks; a kept
  property that does not fit the declaration, e.g. `reject-with` for a non-reject action, refuses
  the adoption with the list; the comment must match exactly one row). A tagged row that is no longer declared is removed.
  The lockout check of the plan runs before (the plan needs the override if it cuts Signalbox
  off) and after (the verification reads the router again and the findings are evaluated).
- **Mapping**: a rule is a row of `/ip/firewall/filter` (`family: 4`) or
  `/ipv6/firewall/filter` (`family: 6`; RouterOS has separate filters, so `family` is required),
  a port forward a `dst-nat` row of `/ip/firewall/nat`, a zone policy a tagged `drop` or `reject`
  rule on interface lists in both filters (an `accept` policy is no rule: the chains accept what
  no rule matches, so removing the rule is the same). Zones are interface lists
  (`in-interface-list`, `out-interface-list`; one list per side, `!LIST` allowed).
- **Order**: new rules go `place-before` the first row of their chain that is not Signalbox's,
  so the device's default rules do not shadow them; zone policies are fallbacks and go to the
  end of their chain. A changed rule is changed in place (`PATCH`, `unset` for a property it no
  longer has), so it keeps its place.
- Refused with the reason before anything is sent: no `family`; several protocols (RouterOS
  matches one per rule: declare one rule each); several source or destination networks (one per
  rule); ports without tcp or udp; a destination zone on a rule to the router itself; an interface
  list the router does not have; a port forward with another protocol than tcp or udp, several
  external ranges or an IPv6 target; an adopted row that does not exist or is not unique.

### The revert timer

RouterOS safe mode belongs to an interactive terminal; the REST API has no session to attach it to,
so it cannot be used (not faked either). The backstop is a scheduler entry, as in ADR 0017:

1. Before the first row is written, `PUT /rest/system/scheduler` creates `signalbox-revert`
   (`interval=0s`, `policy=read,write`) with `start-date`/`start-time` = the router's own clock
   (`/system/clock`, in the format it uses: `2026-11-24` or `nov/24/2026`) plus the confirm time
   of the deployment (setting `deploy.confirm_seconds`). `on-event` holds a script with one block per
   change, in reverse order: `remove [find where comment="..."]` for what was created, `set`/`unset`
   for what was changed, `add ... place-before=[find where comment="..."]` for what was
   removed or adopted, and as the last line the removal of the entry itself.
2. The verification reads the router; if it passes, `confirm` removes the entry. If the router
   cut Signalbox off, or the verification fails and the backup restore cannot reach it, the
   entry runs by itself when the time comes and the router has its old rules again.
3. A restore (failed verification, failed apply) removes the entry first, so it cannot undo
   a restored state again. If `confirm` finds the entry gone it fails: the timer ran, the change
   is undone.

A router whose clock cannot be read gets no firewall change (nothing is sent). The backup of
firewall changes is the JSON snapshot of the three firewall menus too; a restore re-adds a removed
row before the row that followed it, so the order is back.

### Write user (least privilege)

The group of [A user group that may write](#a-user-group-that-may-write) is what the firewall
kinds need: `read` and `write` (rows of the filter, NAT and scheduler menus), `api` and
`rest-api`. Nothing more is asked for: `policy`, `password`, `reboot`, `test`, `sniff`, `ftp`,
`local`, `romon` and the console services stay off, and the scheduler entry runs with the
policies `read,write` only (it cannot create users, reboot or run tools). Reading the lists
(`/interface/list`) needs only `read`.

### Not confirmed on a real device

CI (CHR 7.25.1) adds one rule and one `dst-nat` as the write user, reads them back, reverts, and
lets an unconfirmed change run into its timer (`test_revert_timer_undoes_an_unconfirmed_change`).
What that does not cover ([#21](https://github.com/PhilippMundhenk/signalbox/issues/21)):

- *Guess*: the policies `read,write` suffice to create the scheduler entry and for its script on
  other RouterOS versions and with the group above; the clock format of older versions.
- *Guess*: `place-before` in the body of `PUT` (CI covers the plain case, not other chains).
- Re-adding a removed row in the revert script puts it before the row that followed it, found
  by its comment or, without one, by that row's `.id` (a deployment only removes rows with a
  comment, so the id is still valid). *Guess*: `place-before=*<id>` in a script line, which the
  simulator accepts, needs a real device.
- *Guess*: which kept properties RouterOS refuses next to the declared ones (the writer knows
  `reject-with`, `jump-target` and ports without tcp/udp); any other clash shows up as the
  router's error during the apply (then the change is undone).
- A timer that runs while Signalbox is still working (a very slow router) undoes the change and
  `confirm` reports it.

## PoE-out (#159)

`GET /rest/interface/ethernet/poe` lists the ports with PoE-out (`poe-out`: `auto-on`, `forced-on`,
`off`); boards without PoE-out answer 404 and report nothing. `POST /rest/interface/ethernet/poe/monitor`
with `once` adds `poe-out-status` (`powered-on`, `waiting-for-load`, `overload`, `short-circuit`, ...),
`poe-out-voltage`, `poe-out-current` (mA) and `poe-out-power` (W). A group without the monitor policy keeps the
settings and gets the optional gap `mikrotik.poeMonitor`. RouterOS has no total PoE budget: the
budget stays empty (*guess: `/system/health` shows no PoE total on the boards we know of*).

## MAC address table (#160)

`/rest/interface/bridge/host` (already read for clients) gives one `FdbEntry` per row on the
port in `on-interface`: `local` entries are the bridge's own addresses (`self`), `dynamic`
ones learned, the rest `static`; `vid` is the VLAN where the bridge filters VLANs (otherwise
no VLAN and the bridge's segment). No extra policy. Confirmed in CI (CHR 7.25.1): the bridge's
own entries; learned entries only in the simulator (the CI router has no clients).

## Accounts (#175)

`GET /rest/user` (`name`, `group`, `disabled`, `address`, `last-logged-in`), `/rest/user/group`
(`policy`) and, optional, `/rest/user/ssh-keys` (`user`) become `Device.accounts`. RouterOS
never shows a password, so `password_set` stays unknown. The privilege comes from the group's
policies: `write` with `policy` is admin, `write` alone write, `read` alone read (negated
policies `!write` of older versions are ignored). `address` becomes `allowed_from`,
`last-logged-in` (`2026-11-20 10:11:12`, or `nov/20/2026 10:11:12` before 7.10) `last_login`,
taken as UTC (*guess*: the device's local time, #21). Signalbox's own user is marked and gives
`signalbox_account_privilege`; the read-only group of the setup guide is `read`, the least this
integration needs. A group without the `read` policy for `/user` gives an optional gap.

`default_credentials` is true when the configured login is `admin` with an empty password (the
factory state of RouterOS before 6.49 and of CHR), compared in memory; no other login is ever
tried. The rules are in [account_checks](../rules/account_checks.md).

## Stored certificates (#330)

- `GET /rest/certificate` (policy `read`): `name`, `common-name`, `subject-alt-name`, `issuer`,
  `fingerprint`, `invalid-before`, `invalid-after`, `key-type`, `key-size`, `digest-algorithm`,
  `authority` (a CA), `trusted` and the flag `private-key` (only whether a key exists). Export
  and the key itself need the `sensitive` policy and are never requested; a test shows that a
  row full of key material leaves none of it in the model.
- Who uses a certificate: the `certificate` of `www-ssl` and `api-ssl` in `/rest/ip/service`
  (becomes `used_by`, the service ids) and, where the menu exists, `/rest/ip/ipsec/identity`,
  `/rest/interface/ovpn-server/server`, `/rest/interface/sstp-server/server` (VPN) and
  `/rest/user-manager` (RADIUS), best effort.
- *Guess until a CHR run confirms it (#21)*: the date format of `invalid-after`, `key-size` of
  elliptic-curve keys, the issuer text, which of the optional menus the CHR has.

## Routes and routing rules (#149)

- `GET /rest/ip/route` and `/rest/ipv6/route`: `dst-address`, `gateway` (an address, or an
  interface name for a route without next hop; `%interface` is dropped), `distance` (the
  metric), `routing-table`, `disabled`, `active`, the flags `blackhole`, `unreachable`,
  `prohibit` and the origin flags `dhcp`, `vpn`, `bgp`, `ospf`, `rip`, `static`. Connected routes
  (`connect`) are left out: derived from the subnets.
- `GET /rest/routing/rule`: `src-address`, `dst-address`, `interface` (as a segment),
  `action` (`lookup` and `lookup-only-in-table` with `table`; `drop` is a blackhole;
  `unreachable`), `disabled`. RouterOS has no priority number: the position in the list is the
  priority.

The read policy covers them; a refused route menu is an optional gap and no routes are
reported. *CI* (CHR): a static route and a blackhole route written by the VM setup. *Guess:*
flag names of older RouterOS 7 releases (#21).

## DNS transport and block lists (#182, #80)

Static entries with `type=FWD` (`name` = the domain, `forward-to` = the server; a guess for the field names, #21) are forwarders with `domain` set; `/ip/dns` `cache-size` (kiB) is `cache_size`.

RouterOS has no setting that registers lease names in DNS: the DHCP server's `lease-script` has to add `/ip dns static` entries. `register_dhcp` is true when an enabled DHCP server has a `lease-script` mentioning `dns` (a guess, #21), false when there is none; `dynamic_records` is true when the static table has `dynamic` entries. `listen_segments` are the segments of the layer-3 interfaces when `allow-remote-requests` is on. RouterOS (7.x) has no DNS rebinding protection setting in `/ip/dns`, so `rebind_protection` stays unknown (#456).

`/ip/dns` `use-doh-server` (RouterOS 7.x; absent on older 7.x releases: plain DNS) marks the
forwarders as `https` with the host of the URL as `tls_name`. `/ip/dns/adlist` (RouterOS 7.15
and later; absent before: no block lists) gives the block lists by the host of their URL. Guess
for #21: `match-count` as the number of entries. RouterOS 6 has no REST API (see #389).

## IPv6 router advertisements and DHCPv6 (#151)

Read with `dhcp`; all four menus are *(optional)*: without the `ipv6` package they are missing
and nothing is reported.

- `/rest/ipv6/nd`: per `interface` (`all` is the default of every interface without a row):
  `managed-address-configuration` (M), `other-configuration` (O), `advertise-dns` and `dns` (RDNSS),
  `ra-lifetime`, `disabled`. M gives mode `stateful`, O `stateless`, neither `slaac`, `disabled`
  `off`. The WAN interface is skipped.
- `/rest/ipv6/nd/prefix`: `prefix`, `interface`, `autonomous` (A flag), `on-link`, `disabled`.
- `/rest/ipv6/dhcp-server`: `name`, `interface`, `address-pool`, `lease-time`, `disabled`. RouterOS'
  DHCPv6 server only delegates prefixes (no addresses), so it is reported as `stateless` with
  `prefix_pools`.
- `/rest/ipv6/pool`: `name`, `prefix`, `prefix-length` of the pool the server names.

*(guess: the field names of RouterOS 7 `nd` and `dhcp-server`; the DNS servers of the DHCPv6 server
(option 23) and the bindings `/ipv6/dhcp-server/binding` are not read.)* The simulator answers all
four menus. RouterOS 6 has no REST API (see #389).

## Queues (#166)

`/rest/queue/simple`, `/rest/queue/tree` and `/rest/queue/type` (cake and fq-codel types need
RouterOS 7.1; 6.49 has the menus with plain types). Needs only the read policy; a menu that is
refused or missing reports nothing. One shaper per static queue (dynamic queues of the hotspot and
PPP are left out). A simple queue gives `max-limit` as `upload/download` for its target (a network
or addresses); with a WAN interface as target the two values are read from the interface's side
(first: our download). A tree queue with a WAN interface as parent limits the upload, with another
interface as parent the download; children of other queues and queues with parent `global` are not
interface shapers and are left out. The kind comes from the queue type (`cake`, `fq-codel`, else a
plain queue). *(guess: field names and the direction of interface targets, #21.)*

## Hotspot (#460)

`/rest/ip/hotspot` (one captive portal per server: `name`, `interface`, `profile`, `disabled`),
`/rest/ip/hotspot/profile` (`login-by`, `use-radius`) and `/rest/ip/hotspot/user/profile`
(`session-timeout` of the profile `default`). The portal covers the segment of the hotspot's
interface (a bridge or VLAN interface; a hotspot on a Wi-Fi interface is not tied to an SSID).
Login: `use-radius=yes` is RADIUS; `trial` without `http-chap`, `http-pap` or `https` in
`login-by` is click-through; one of those three is a password (hotspot users and vouchers cannot
be told apart); `mac` or `cookie` alone: not known. *(guess: the derivation and the field names,
#21.)* A missing menu (no hotspot, `hotspot` package not installed) or one refused to the user
reports nothing. Hotspot users and their passwords (`/ip/hotspot/user`) are never read. RouterOS
7 (REST) only, like the rest of the adapter. The simulator has one hotspot with a trial login.

## Multi-WAN and MikroTik Cloud (#150, #154)

- **Gateway group**: two or more enabled `0.0.0.0/0` routes of the `main` table with a next hop
  (`/rest/ip/route`, already read) are the group `default`. Different `distance` values are the
  tiers of a failover (lowest first), one value is load balancing. `check-gateway=ping` makes the
  monitor target the route's own gateway, which `wan.monitor-local` reports. `gateway-status`
  (`... reachable via ether1` or `... unreachable`) is the state *(guess for the wording, #21)*.
  `/rest/tool/netwatch` (`host`, `status`, `comment`): an entry with the same comment as a route
  is that route's monitor *(guess: a convention, netwatch has no link to routes)*. The member's
  uplink is the one whose next hop is the route's gateway.
  RouterOS 7.1 and later (REST); RouterOS 6 has no REST API.
- **Cloud DDNS**: `/rest/ip/cloud` `dns-name`, `public-address`, `status` (`updated` is ok,
  `error...` is an error) and `ddns-enabled`; no name, no client.

## Wireless uplinks (#171)

Interfaces in `configuration.mode` (`wifi` package) or `mode` (`wireless` package)
`station-bridge`, `station-pseudobridge`(`-clone`) or `station-wds` are wireless uplinks: their
rows in the registration table (`interface`, `mac-address` of the access point, `signal`,
`tx-rate`, `rx-rate`) become a `MeshPeer` (role `uplink`, kind client bridge or WDS), and the
router gets `Device.mesh` role `repeater`. A plain `station` is a router's uplink, not a mesh node.
*Guess (#21): the mode names of the `wifi` package and that the registration table of a station
interface lists the access point.*

**WDS, access point side (#475, `wireless` package only; the `wifi` package has no WDS).** The
registration rows of an access point that are marked `wds` or whose `mac-address` is the
`wds-address` of an entry of `/interface/wireless/wds` (dynamic or static) become a `MeshPeer`
(role `downlink`, kind WDS) on the port of the entry's `master-interface`; signal and rates are
the row's. The router gets `Device.mesh` role `agent` unless it is a repeater itself. *Guess (#21):
the `wds` column of the registration table and the `wds-address` of the dynamic entries.*

**CAPsMAN (#475).** The CAPs a controller manages are devices of the controller (`<id>/cap/<MAC>`,
role access point, `managed_by` the controller): `/interface/wifi/capsman/remote-cap` (RouterOS 7,
`wifi` package from 7.13, `wifiwave2` from 7.6) and `/caps-man/remote-cap` (RouterOS 6, and 7 with
the `wireless` package) with `identity`, `address` (a port suffix is dropped), `base-mac`, `model`
or `board`, `version`, `serial` and `state` (kept in `vendor_extra`). The controller has
`Device.mesh` role `controller`, each CAP `agent` (hop 1). Radios and SSIDs of a CAP are
`Radio`/`Wlan` of the CAP device (#481): the interfaces of `/caps-man/interface` (band and channel
from `current-channel`, `channel.band`; SSID `configuration.ssid`; client count from
`/caps-man/registration-table`), or, on RouterOS 7 `wifi`, the controller's own `/interface/wifi`
rows that `/interface/wifi/radio` (or `/caps-man/radio`) assigns to a CAP (`remote-cap-identity`,
`remote-cap-mac` or `remote-cap-address`); they leave the controller's own radios. Clients of those
interfaces (the controller's registration table, `rx-signal` for the legacy one) are `Client`s with
`seen_on` and `wireless.wlan_id` on the CAP. Uplink: `capsman_segment` (the segment its address lies
in, or of the interface that answers ARP for it), `capsman_path` (`layer2` when the controller sees
the CAP in ARP or in an own network, `layer3` when a router lies between), `capsman_port` (the
controller port whose bridge table holds the CAP, from ARP and `base-mac`, or the MAC address an L2
CAPsMAN lists as `address`) in `vendor_extra`, and `mesh.uplink` `wired` or `wireless` (a Wi-Fi
port) only when that port is known. Everything is read-only with the policy `read`: the group of
the setup guide and *Repair Signalbox's access* are unchanged. *Guess (#21): the column names are
from the RouterOS manual, in particular the `remote-cap-*` columns of the radio tables and the
dotted `channel.*`/`configuration.*` columns of `/caps-man/interface` in REST; the CAP's
bridge-table MAC is assumed to be its `base-mac` or ARP MAC.*

## Multicast (#161)

Read with `interfaces`, no new privilege beyond the read policy. `/rest/interface/bridge` gives
`igmp-snooping`, `multicast-querier`, `igmp-version` (the querier's version; only kept where the
bridge is the querier); RouterOS snoops MLD together with IGMP. The bridge ports give
`fast-leave` and `unknown-multicast-flood` (all ports alike: the value, otherwise unknown). The
network of a bridge is the one of its own interface (`pvid`); the other VLANs of a filtering
bridge gets one more entry per VLAN where it learned groups (`/rest/interface/bridge/mdb`, only
the VLAN ids are used, never the groups), repeating the bridge's own settings. The querier a
bridge sees is read from `/rest/interface/bridge/monitor` (`once`) when the monitor names one;
without the field or the right to run the monitor the bridge is reported without it. The mDNS repeater is `mdns-repeat-ifaces` of `/rest/ip/dns` (RouterOS 7.16
and later; the field is absent before, then there is no repeater to report). The IGMP proxy is
`/rest/routing/igmp-proxy/interface` (RouterOS 7; `upstream=yes` marks the uplink side);
a login that may not read it gets an optional gap. *(Guess, #21: the field names
`mdns-repeat-ifaces` and the proxy menu path are from the RouterOS documentation, not yet seen on
a device; the monitor field of the observed querier is a guess among `multicast-querier-address`,
`current-igmp-querier`, `igmp-querier`, `current-querier` and `querier`, and the `mdb` menu
(`bridge`, `vid`) is read as RouterOS 7 prints it.)* Covered:
RouterOS 7.16 and later for the repeater, 7.x for the rest; RouterOS 6 has no REST API.

## UPnP and its mappings (#176)

Read with `interfaces`. `/ip/upnp` gives `enabled`; `/ip/upnp/interfaces` the interfaces with
`type=internal` (where it listens, mapped to the networks Signalbox knows). The mappings are
the dynamic `dstnat` rows of `/ip/firewall/nat` (`dynamic=true`, action `dst-nat`, a comment
with `upnp`): protocol, `dst-port`, `to-addresses` and `to-ports`; rows with ranges are left
out. RouterOS answers UPnP IGD only: no NAT-PMP or PCP, no secure mode, no permission rules and
no lease time. When the NAT rules cannot be read the list is marked not complete. *(Guess, #21:
the comment of dynamic rows, matched by the word `upnp`.)* Covered: RouterOS 6.49 (REST needs 7,
so only 7.x is read), 7.x.
## Access control: RADIUS, 802.1X, MAC filters (interfaces and wifi, #162)

- `/radius` (service wireless, dot1x, ppp, hotspot, login; ports; whether a secret is set, never
  the secret), `/interface/dot1x/server` (RouterOS 7.1 and later; guest and reject VLAN),
  bridge ports with `learn=no` (reported as static MACs) and `/interface/wifi/access-list`
  (an entry without MAC and `action=reject` makes the list an allow-list; only counted). A
  `/radius` this login may not read is an optional gap. *Guess for a real device (#21):* the
  allow/deny reading of the access list and which interfaces an entry applies to.
