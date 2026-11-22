# OpenWrt adapter

Reads an OpenWrt device (21.02 or later; DSA bridge VLANs or plain bridges) over ubus JSON-RPC,
the API that LuCI uses: `rpcd` behind `uhttpd` at `https://<device>/ubus`. With a read-only login
nothing on the device is changed; with write access to UCI `network`, `wireless` and `dhcp`
Signalbox can deploy port VLANs, SSIDs, DHCP pools and reservations ([Writing](#writing)).

| | |
| --- | --- |
| Adapter id | `openwrt` |
| Roles | `ap`, `switch`, `gateway` |
| Capabilities | interfaces, wireless, DHCP, DNS (dnsmasq), clients, neighbours (LLDP) |
| Writes | `port`, `wlan`, `dhcp`, `reservation` (not `router`, see [Writing](#writing)) |
| Simulator | `signalbox.sim.openwrt` (`uvicorn --factory signalbox.sim.openwrt:create_app`) |

> Verified against OpenWrt 24.10.8 and 25.12.6 (x86-64 in QEMU) in CI: every call below, the read-only and
> the write ACL of this page, and the write transaction including the rollback timer
> ([TESTING.md](../TESTING.md), #137). What the real device showed differently from the first
> version of the simulator is listed under
> [Verified against the real OpenWrt](#verified-against-the-real-openwrt).

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | | ubus endpoint, for example `https://192.0.2.2/ubus` (no path: `/ubus`) |
| `username` | `signalbox` | rpcd login: read-only, or with write access (see below) |
| `password` | | its password; stored encrypted, never sent back to the UI |
| `allow_insecure_http` | `false` | accept an `http://` URL; the password then crosses the network in clear text |

## Certificate pinning

OpenWrt ships a self-signed certificate (`px5g`/`uhttpd`), so there is no CA to check. At the
start of every observation Signalbox opens one TLS connection without sending anything, reads the
certificate and compares its SHA-256 fingerprint with the pinned one; if nothing is pinned yet,
or the fingerprint differs, the device is reported as `untrusted-certificate` with the
fingerprint to confirm, and the password is not sent. The ubus requests then go over a TLS
context whose only trust anchor is the pinned certificate, so a certificate swapped after the
check fails the handshake. Colons and case in a pinned fingerprint are ignored. This is the
shared helper `signalbox.adapters.https.DeviceHttp` (see [ADAPTERS.md](../ADAPTERS.md)).

## Protocol

Every request is a JSON-RPC 2.0 `call`:

```json
{"jsonrpc": "2.0", "id": 1, "method": "call",
 "params": ["<ubus_rpc_session>", "<object>", "<method>", {"arg": "value"}]}
```

The answer is `{"result": [<ubus status>, <data>]}`, `{"result": [<ubus status>]}` or a JSON-RPC
error `{"error": {"code": ..., "message": ...}}`.

| Answer | Meaning | Signalbox |
| --- | --- | --- |
| `result [0, {...}]` | OK | data is used |
| `result [6]` / error `-32002` "Access denied" | not allowed by the ACL, or session expired | logs in once more, then "access denied for `object.method`", with what to do: install the ACL file |
| `result [3]`, `[4]` / error `-32000` "Object not found", `-32601` | object or method missing (package not installed) | "not found" |
| other `result [n]` | ubus status (`2` invalid argument, `7` timeout, ...) | "ubus `object.method` failed: ..." |
| not JSON, other shape, HTTP status other than 200 | | "unexpected answer" |

Login (session `00000000000000000000000000000000`):

```json
["0000…0000", "session", "login", {"username": "signalbox", "password": "…"}]
→ [0, {"ubus_rpc_session": "c1ed6c7b…", "timeout": 300, "expires": 300, "acls": {…}, "data": {…}}]
→ [6]                      wrong user or password: device status auth-failed
```

## Calls and the JSON they return

### `system board` (device model and firmware)

```json
{"kernel": "5.15.167", "hostname": "ap", "model": "Example AP", "board_name": "example,ap",
 "release": {"distribution": "OpenWrt", "version": "23.05.5", "revision": "r24106-…",
             "target": "mediatek/filogic", "description": "OpenWrt 23.05.5 …"}}
```

`model` becomes the device model, `release.version` the current firmware.

### `system info` (health, and the clock for time)

```json
{"localtime": 1795435200, "uptime": 273906, "load": [6912, 4352, 2880],
 "memory": {"total": 515878912, "free": 382853120, "shared": 1069056, "buffered": 0,
            "available": 371363840, "cached": 38051840},
 "root": {"total": 104320, "free": 100736, "used": 3584, "avail": 96512},
 "tmp": {"total": 251892, "free": 251488, "used": 404, "avail": 251488},
 "swap": {"total": 0, "free": 0}}
```

- `uptime` in seconds; `load` the 1/5/15 minute load averages times 65536 (rpcd passes the
  kernel's fixed-point numbers on). There is no CPU percentage and no CPU count.
- `memory` in bytes: used is `total - available` (without page cache); rpcd before 21.02 has
  no `available`, then `free + buffered + cached` counts as available.
- `root` and `tmp` in **KiB**: `/` (the overlay on squashfs images, where the configuration
  lives) is storage of kind `system`, `/tmp` (RAM) of kind `temporary`.
- `localtime` is the wall clock in the device's zone, in seconds since the epoch (UTC seconds
  plus the zone's offset); see `uci get system` below.

### `file read` of `/sys/class/thermal/thermal_zone<N>/temp` and `.../type` *(optional)* (health)

```json
{"data": "47823\n"}      temp: milli-degrees Celsius
{"data": "cpu-thermal\n"} type: the sensor's name (empty: thermal_zone<N>)
```

Zones 0 to 7 are read until the first one that is missing (ubus status 4), refused or
unreadable; then health carries no temperatures, which is not an error. Needs `rpcd-mod-file`
and the two thermal paths in the ACL. *Guess*: the x86-64 VM in CI has no thermal zones, so only
"missing" is confirmed on a real OpenWrt; the values follow the kernel's sysfs ABI.

### `uci get {"config": "system"}` (time)

```json
{"values": {
  "cfg01e48a": {".type": "system", "hostname": "ap", "zonename": "Europe/Berlin",
                "timezone": "CET-1CEST,M3.5.0,M10.5.0/3"},
  "ntp": {".type": "timeserver", "enabled": "1", "enable_server": "1", "interface": "lan",
          "server": ["0.openwrt.pool.ntp.org", "1.openwrt.pool.ntp.org"]}}}
```

- `timezone` is the POSIX string OpenWrt runs on (`/etc/TZ`; default `UTC`), `zonename` the
  IANA name LuCI sets with it. The time zone shown is `zonename`, else `timezone`. The UTC
  offset comes from the POSIX string at the moment of the read (`Mm.w.d` rules, as in LuCI's
  zone table; a string with other rules gives no offset and so no clock).
- The clock is `localtime` minus that offset, with whole seconds: the middle of the second,
  with half the round trip plus half a second as uncertainty.
- `ntp` (`timeserver`): `enabled` (default on) and `server` are the NTP client,
  `enable_server` (default off) the server; `interface` (OpenWrt 21.02+) binds the server to
  that network, which becomes its segment (none: all networks). sysntpd does not report
  whether it is in sync, so that stays unknown.
- Needs `system` in the ACL's `uci` list (added for #179; an older ACL makes only the time
  capability fail, with "access denied for uci.get (system)").

`dhcp_option` `42,<addresses>` (or `option:ntp-server,…`) of a `dhcp` section is the NTP
server handed out by DHCP (`DhcpServer.ntp_servers`).

### `network.device status` (ports)

```json
{"lan1": {"type": "Network device", "up": true, "carrier": true, "macaddr": "02:…",
          "speed": "1000F", "mtu": 1500, "autoneg": true,
          "link-supported": ["10baseT-H", "10baseT-F", "100baseT-H", "100baseT-F", "1000baseT-F"],
          "link-advertising": ["100baseT-F", "1000baseT-F"]},
 "br-lan": {"type": "bridge", "up": true, "bridge-members": ["lan1", …]},
 "br-lan.1": {"type": "VLAN", …}, "lo": {…}, "phy0-ap0": {…}}
```

Every device except `lo` and VLAN devices (`name.vid`) becomes a port; `carrier` is the link
state, `speed` `"<Mbit/s><F|H>"` speed and duplex (`-1F`: no link). `type: bridge` is a bridge
port, `phy*`/`wlan*` (or `"wireless": true`) a wireless one.

Port details (#156): `mtu`; the fastest mode of `link-supported` is the maximum speed, the
modes of `link-advertising` the offered speeds, `autoneg` auto-negotiation (netifd adds these
for Ethernet ports only; virtual NICs may leave them out). A port is enabled when netifd has it
`up`, disabled when a UCI `device` section for it says `enabled 0` *(guess: the option name,
from netifd's device options)*; otherwise unknown. The PVID is the VLAN whose `bridge-vlan`
port list marks the port primary (`lan1:u*`); a port without `*` has no PVID reported.

### `uci get {"config": "network"}` (bridges, VLANs, interfaces)

```json
{"values": {
  "cfg030f15": {".type": "device", ".name": "cfg030f15", ".anonymous": true,
                "name": "br-lan", "type": "bridge", "ports": ["lan1", "lan2", "lan3", "lan4"]},
  "cfg040f15": {".type": "bridge-vlan", "device": "br-lan", "vlan": "1",
                "ports": ["lan1:u*", "lan2:u*", "lan3"]},
  "cfg050f15": {".type": "bridge-vlan", "device": "br-lan", "vlan": "20", "ports": ["lan1:t"]},
  "lan": {".type": "interface", "device": "br-lan.1", "proto": "static", "ipaddr": "192.0.2.2/24"},
  "iot": {".type": "interface", "device": "br-lan.20", "proto": "none"}}}
```

- Every `bridge-vlan` is a segment `<site>/segment/<vlan>`, named after the interface on
  `<bridge>.<vlan>`. Port suffix `:t` is tagged, `:u` untagged, `*` the primary VLAN (PVID). A port
  without a suffix is untagged when it is in only one VLAN of the bridge, tagged otherwise
  (netifd's rule; the test device uses explicit suffixes, so this one is not verified yet).
- A bridge without `bridge-vlan` sections is the untagged network (`<site>/segment/native`), with
  all its ports untagged.
- Interfaces on other devices (WAN port, loopback, tunnels) do not map to a segment and are left out.
- Options may be lists or space-separated strings; both are read. `ifname` (before 21.02) is read
  like `device`.

### `network.interface dump` (addresses, routes)

```json
{"interface": [{"interface": "lan", "up": true, "device": "br-lan.1", "l3_device": "br-lan.1",
  "ipv4-address": [{"address": "192.0.2.2", "mask": 24}],
  "ipv6-address": [{"address": "2001:db8::2", "mask": 64}],
  "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "192.0.2.1"}]}]}
```

Each address of an interface that maps to a segment becomes a subnet. The device is the subnet's
gateway only when its role is `gateway` and the interface has no default route of its own (an
interface with a default route leads upstream).

**Uplinks** (#148, role `gateway` only): the interfaces named `wan`, `wan6`, `wan2`, ...,
those with a protocol only uplinks use (`pppoe`, `pppoa`, `dslite`, `map`, `464xlat`, `dhcpv6`,
and the mobile `qmi`, `mbim`, `ncm`, `3g`, `modemmanager`), and any other interface with a
default route that is not a network of the site. `<name>6` joins `<name>` as one uplink
`<device>/uplink/<name>` (`wan6` into `wan`):

```json
{"interface": "wan", "up": true, "uptime": 5400, "proto": "dhcp", "device": "eth0",
 "l3_device": "eth0", "ipv4-address": [{"address": "203.0.113.45", "mask": 24}],
 "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "203.0.113.1"}],
 "dns-server": ["203.0.113.53"]}
{"interface": "wan6", "up": true, "proto": "dhcpv6", "device": "eth0", "l3_device": "eth0",
 "ipv6-address": [{"address": "2001:db8:ffff::45", "mask": 64}],
 "ipv6-prefix": [{"address": "2001:db8:1::", "mask": 56, "class": "wan6"}],
 "route": [{"target": "::", "mask": 0, "nexthop": "fe80::1"}],
 "dns-server": ["2001:db8:ffff::53"]}
```

Kind from `proto` of the first one (`dhcp`, `static`, `pppoe`/`pppoa`, `dslite`, `map` as
MAP-E, the mobile protocols as `lte`, anything else `other`); `up` and `uptime` (seconds; `since`
is the read time minus it); the addresses, `ipv6-prefix` (delegated prefixes), the `nexthop`
of the first default route and `dns-server` of both. The port is `device` (else `l3_device`)
where it is one of the ports; a PPPoE session's `pppoe-wan` is not. netifd reports no line rate
and no public address. `network.interface dump` is read already, so the ACL needs nothing more.

### `uci get {"config": "wireless"}` and `network.wireless status` (radios, WLANs)

```json
{"values": {
  "radio0": {".type": "wifi-device", "band": "2g", "channel": "6", "htmode": "HE20",
             "txpower": "20", "country": "DE"},
  "default_radio0": {".type": "wifi-iface", "device": "radio0", "mode": "ap", "network": "lan",
                     "ssid": "Example", "encryption": "sae-mixed", "key": "…",
                     "ieee80211r": "1", "ieee80211k": "1", "bss_transition": "1"}}}
```

```json
{"radio0": {"up": true, "pending": false, "disabled": false,
            "interfaces": [{"section": "default_radio0", "ifname": "phy0-ap0", "config": {…}}]}}
```

Since OpenWrt 25.12 netifd's wireless object (now ucode) answers `network.wireless status`
through rpcd with "invalid argument". Signalbox then calls `luci-rpc getWirelessDevices`
(rpcd-mod-luci, what LuCI uses), which runs it on the device and answers the same shape with
`iwinfo` added.

- Radio: `band` `2g`/`5g`/`6g` (before 21.02: `hwmode` `11g`/`11a`, else from the channel),
  width from the digits of `htmode` (`NOHT` = 20), `txpower` dBm, `country`. Enabled when not
  `disabled` and `up` in `network.wireless status`. 60 GHz radios are skipped.
- WLAN: only `mode ap`. `encryption` (cipher suffix `+ccmp` ignored): `none` open, `owe`,
  `psk2` WPA2, `psk-mixed` WPA/WPA2 mixed, `psk` WPA (version 1), `wep*` WEP, `sae` WPA3,
  `sae-mixed` WPA2/WPA3, `wpa`/`wpa-mixed` WPA-Enterprise (WPA1 or WPA/WPA2), `wpa2`
  WPA2-Enterprise, `wpa3`/`wpa3-mixed` WPA3-Enterprise, `wpa3-192` WPA3-Enterprise 192-bit;
  anything else is `other`. `ieee80211w` `0`/`1`/`2` is PMF disabled/optional/
  required; unset means hostapd's default (required for `sae`, `owe`, `wpa3`; optional for
  `sae-mixed`; otherwise unknown). `ieee80211r`, `ieee80211k`, `bss_transition` (or `ieee80211v`)
  are the roaming flags, `hidden` the hidden SSID, `isolate` client isolation (unset: off). The
  segment is that of the first `network`. OpenWrt does not know a network purpose; declare it in
  the desired state.
- The `key` is read (rpcd cannot hide single options) but only
  `passphrase_fingerprint(ssid, key)` and `passphrase_digest(key)` are kept, and only for
  personal (PSK/SAE) networks; the digest is `None` in a process without the installation's key.
- Security details (#167): `ciphers` from the `encryption` suffix (`+ccmp`, `+aes`, `+tkip`,
  `+tkip+ccmp`, `+gcmp`, `+gcmp-256`, `+ccmp-256`); without a suffix hostapd.sh's default
  (`tkip` and `ccmp` for `psk`/`psk-mixed`, `gcmp-256` for `wpa3-192`, else `ccmp`); a suffix
  with an unknown word: not reported. `group_cipher` is not a UCI option: it is the weakest
  pairwise cipher *(guess; hostapd's behaviour)*. `sae.pwe` from `sae_pwe` (`0`
  hunting-and-pecking, `1` hash-to-element, `2` both; unset: not reported); no SAE-PK, no
  anti-clogging threshold in UCI. `wps` for personal networks: `wps_pushbutton` `1`
  push-button, `wps_label` `1` PIN, neither set: `Wps(enabled=False)`. `key_rotation_seconds`
  from `wpa_group_rekey` (unset: not reported). `beacon_protection` from `beacon_prot` when set
  *(guess: option name)*.
- `Radio.supported_security`: `luci getFeatures` (luci-base, part of a LuCI install, not of rpcd-mod-luci; the `hostapd` flags `sae`,
  `owe`, `eap`, `suiteb192` as LuCI reads them *(guess: object `luci`, not `luci-rpc`)*), else
  the `wpad-*` package of `rpc-sys packagelist` (`wpad-basic*`: no SAE, OWE, EAP; every other
  `wpad-*`: all *(guess)*). Both are in the ACL below; an ACL from before #167 or a missing
  package leaves it unreported, which is not an error. WEP is never listed (current hostapd
  builds have no WEP).

### `uci get {"config": "dhcp"}` (dnsmasq)

```json
{"values": {
  "lan": {".type": "dhcp", "interface": "lan", "start": "100", "limit": "150",
          "leasetime": "12h", "ignore": "1"},
  "cfg06fe63": {".type": "host", "name": "printer", "mac": "00:00:5e:00:53:01", "ip": "192.0.2.50"}}}
```

One DHCP server per `dhcp` section whose interface maps to a segment and has an IPv4 address.
`ignore 1` is disabled (typical for an access point behind a gateway). The pool is
`<network> + start` for `limit` addresses (defaults 100 and 150), the lease time `12h`/`30m`/
`3600`/`infinite`, router and DNS from `dhcp_option` `3,…` and `6,…` (else the interface address).
`host` sections inside the subnet are reservations. odhcpd (DHCPv6, RA) is not modelled yet.

DNS (#241, the same answer): one service per `dnsmasq` section (`<device>/dns/dnsmasq`, or the
section name when there are several). `port` (default 53; 0 turns DNS off: disabled),
`listen_address`, else the addresses of `interface` (empty: all). `server` entries are the
forwarders, `192.0.2.53#5353` with its port, an `@interface` suffix dropped; domain-specific
ones (`/corp.example/192.0.2.53`) are not counted. Without `noresolv` dnsmasq also uses the
servers of `resolvfile` (the WAN's), which are not read (`vendor_extra.upstream`). `domain`
sections (`name`, `ip`) are host records. *Guess*: not yet checked against the CI VMs.

### `hostapd.<ifname> get_clients` (associated stations)

```json
{"freq": 2437, "clients": {"02:00:00:00:20:01": {"auth": true, "assoc": true,
                                                  "authorized": true, "signal": -55}}}
```

Called for every running interface listed by `network.wireless status`; each station is a client
seen on that WLAN, in its segment. An interface without hostapd object (not up) is skipped.

### `luci-rpc getDHCPLeases`, else `file read {"path": "/tmp/dhcp.leases"}` (addresses, names)

```json
{"dhcp_leases": [{"expires": 43000, "hostname": "laptop", "macaddr": "02:…", "ipaddr": "192.0.2.103"}],
 "dhcp6_leases": []}
```

```json
{"data": "4102444800 02:00:00:00:20:03 192.0.2.103 laptop 01:02:…\n"}
```

Leases add addresses and host names to the stations (and add wired clients of a DHCP server).
They are also `DhcpServer.leases` (#183): every lease whose address lies in a network of the
server's interface (IPv4 and the DHCPv6 leases of odhcpd, which have a DUID as `client_id` and
no MAC). `expires` is now + `expires` seconds from luci-rpc (`false`: never), the epoch of the
file (0: never); dnsmasq lists active leases only, so every lease is `active`. `reserved` when a
`uci dhcp host` section has the same MAC and address. `leases` is `None` when neither luci-rpc nor
the file is readable. Options come from the `dhcp_option` / `dhcp_option_force` lists of the
`dhcp` section (`119` search domains, `121` pairs of destination and gateway, `66`, `67`, any
other numeric or known `option:name` entry as `DhcpOption`); `dhcp_boot` of the dnsmasq section
(`file,server name,server address`) is `boot`; `authoritative` is the dnsmasq section's option
(default on; unknown without such a section); `config relay` sections (`interface`,
`server_addr`) are `DhcpRelay` *(guess: the real relay sections were not seen)*. The ACL needs no
change. The leases and `authoritative` are checked in CI against the QEMU image.
Both are optional: if neither is installed or allowed, clients have no addresses.

### `luci.lldpd getStatus` (LLDP)

`lldpd` itself has no ubus object. `luci-app-lldpd` (OpenWrt 24.10 and later) adds the rpcd
object `luci.lldpd`, whose `getStatus` returns `lldpcli -f json0 show ...` of the statistics,
the neighbours, the interfaces and the chassis; Signalbox reads `neighbors`:

```json
{"neighbors": {"lldp": [{"interface": [{"name": "lan1", "via": "LLDP",
   "chassis": [{"id": [{"type": "mac", "value": "02:00:00:00:30:01"}],
                "name": [{"value": "switch"}], "mgmt-ip": [{"value": "192.0.2.3"}]}],
   "port": [{"id": [{"type": "ifname", "value": "port 8"}]}]}]}]},
 "statistics": {…}, "interfaces": {…}, "chassis": {…}}
```

Without the object the neighbours read fails with "LLDP is not installed on the router"; when
`lldpd` is not running, `neighbors` is missing ("lldpd is installed but not running"). Both
errors say what to install or start. Either shows as an incomplete
device; the other capabilities are unaffected.

## Read-only user on the device

The device form shows these steps as commands to paste on the router (`ssh root@<router>`):
packages, the ACL file below and a login `signalbox`. A router without Wi-Fi (no
`/etc/config/wireless`) or without DHCP server (no `/etc/config/dhcp`) is read as having none.
Every "access denied" error says to install this ACL; root may call whatever an installed ACL
file allows (`list read '*'`), so with the file in place root works too.

Packages: `rpcd`, `uhttpd`, `uhttpd-mod-ubus` (all part of a LuCI install); `rpcd-mod-file` for
the lease file, `rpcd-mod-luci` for `luci-rpc`, `luci-base` for `luci getFeatures` (the security modes the radios support) and `luci-app-lldpd` for LLDP are optional; on
OpenWrt 25.12 and later `rpcd-mod-luci` is needed for the wireless status.

`/usr/share/rpcd/acl.d/signalbox.json`:

```json
{
  "signalbox": {
    "description": "Signalbox: read-only network inventory",
    "read": {
      "ubus": {
        "system": ["board", "info"],
        "network.device": ["status"],
        "network.interface": ["dump"],
        "network.wireless": ["status"],
        "uci": ["get"],
        "hostapd.*": ["get_clients"],
        "luci-rpc": ["getDHCPLeases", "getWirelessDevices", "getNetworkDevices"],
        "luci": ["getFeatures"],
        "rpc-sys": ["packagelist"],
        "file": ["read"],
        "luci.lldpd": ["getStatus"]
      },
      "uci": ["network", "wireless", "dhcp", "system", "dropbear", "uhttpd"],
      "file": {
        "/tmp/dhcp.leases": ["read"],
        "/sys/class/thermal/thermal_zone*/temp": ["read"],
        "/sys/class/thermal/thermal_zone*/type": ["read"]
      }
    }
  }
}
```

Login entry in `/etc/config/rpcd` (hash the password with `uhttpd -m '<password>'`):

```
config login
	option username 'signalbox'
	option password '$1$…'
	list read 'signalbox'
```

Then `service rpcd restart`. There is no `write` entry, so the user cannot change anything. A call
the ACL does not allow is reported by name ("access denied for `hostapd.phy0-ap0.get_clients`"),
and only that capability is missing from the snapshot.

## Writing

Off unless `deploy.enabled` is on, *Allow changes* is set on the device and the login has the
write ACL below (see [CHANGES.md](../CHANGES.md)). Every change goes through rpcd's `uci` object
in the login's session, as LuCI does it:

1. `uci get` of `network`, `wireless`, `dhcp` and `network.interface dump`; the changes are
   translated one after another on that copy, so a later change sees an earlier one (the WLAN on
   VLAN 30 finds the VLAN the port change creates). The review shows exactly these calls
   (`plan_changes`); Wi-Fi keys appear as `***`.
2. **Backup**: the `uci get` answers of the three configs as one JSON document (format
   `openwrt-uci-json`, stored encrypted with the change).
3. **Stage**: `uci set` / `add` / `delete` into the session's staging area. Nothing is live yet;
   another session does not see it.
4. **Apply**: `uci apply {"rollback": true, "timeout": <deploy.confirm_seconds>}`. rpcd commits,
   reloads the services and starts a timer: unless `uci confirm` comes from the same session
   before it runs out, rpcd puts the previous configuration back by itself. So a change that cuts
   Signalbox off undoes itself.
5. **Verify**: Signalbox reads the device again (a new session) and compares every changed value.
6. **Confirm** (`uci confirm`), or restore the backup.

Failures:

- Any error while staging: `uci revert` of the touched configs, nothing was applied.
- "Access denied" while staging or applying: the session may have expired, which also drops
  what it had staged, so the whole transaction starts over once after a new login. Denied again:
  the ACL forbids it, and the error names the call (`access denied for uci.add (wireless)`). rpcd
  also refuses `uci apply` while another change waits for its confirmation.
- Another change waits for its confirmation: rpcd gives every new login of the same user the
  session of that apply, and refuses `uci revert` until it is confirmed or rolled back. Changes
  left staged in the session (by another client, or put back by a rollback) that cannot be
  dropped stop the transaction before anything is staged ("another change waits for its
  confirmation").
- Verification fails: `uci rollback` of the pending change (immediately, rather than waiting for
  the timer), then the backup is compared with the device and put back if anything differs.
- `uci confirm` fails (session gone): the device rolls back at the deadline; Signalbox restores
  the backup at once.
- **Restore** of a backup: sections not in the backup are deleted, the backup's sections are set
  (options not in the backup removed) or added under their old names, `uci order` restores the
  section order, then `uci apply {"rollback": false}`. rpcd answers OK to that while another
  change waits for its confirmation but applies nothing; Signalbox checks `uci changes` afterwards
  and reports the restore as failed if anything is still staged.

### What each change does in UCI

| Change | UCI |
| --- | --- |
| `port` | The port's entries in the `bridge-vlan` sections of its bridge: `<port>:u*` for the untagged VLAN (untagged and primary VLAN), `<port>:t` for each tagged one. The native network is VLAN 1. A VLAN that has no section yet gets one (`config bridge-vlan` `<bridge>_<vid>`); a section without ports is deleted. Ports of a bridge without `bridge-vlan` sections (no VLAN filtering) are refused. |
| `wlan` | All `wifi-iface` sections in AP mode with this SSID. New SSID: one section per radio (`<ssid>_<radio>`). Only options that differ are written: `ssid`, `encryption` (open `none`, OWE `owe`, WPA2 `psk2`, WPA3 `sae`, WPA2/WPA3 `sae-mixed`; enterprise is refused, it needs RADIUS settings), `key` from the passphrase secret, `ieee80211w` (PMF 0/1/2), `ieee80211r`, `ieee80211k`, `bss_transition`, `isolate` (client isolation, only when the desired state sets `client_isolation`), `hidden`, `disabled`, `network`. Removed SSID: its sections are deleted. |
| `wlan` network | The interface on the segment's VLAN (the first by name). If the VLAN is on the bridge but has no interface, Signalbox adds `config interface vlan<vid>` with `device <bridge>.<vid>` and `proto none` (DSA creates the VLAN device itself, no `config device` is needed). If the VLAN is on no port of the access point, the change is refused: tag it on the uplink in the same plan. When a later change removes that VLAN, an unused `proto none` interface on it is deleted too. |
| `dhcp` | The `dhcp` section of the segment's interface (created if missing): `ignore`, `start` and `limit` from the pool (offsets in the interface's IPv4 subnet), `leasetime`, DNS as `dhcp_option 6,…` (other options kept). The interface must already have an IPv4 address. Enabling without a pool is refused. |
| `reservation` | The `host` section with that MAC: `ip`, `name`; a new one is `host_<mac>`. A host section shared by several MACs keeps the others. |
| `router` | Not supported: a routed VLAN on OpenWrt also needs a firewall zone and forwarding rules, which are policy Signalbox does not model, and the write ACL deliberately excludes `firewall`. Create routed interfaces by hand (or in LuCI); DHCP and reservations on them can then be deployed. |

### Login with write access

Same packages as for reading. `/usr/share/rpcd/acl.d/signalbox.json` with a `write` part that
only allows the `uci` methods of a transaction on the three configs:

```json
{
  "signalbox": {
    "description": "Signalbox: network inventory, changes to network, wireless and dhcp",
    "read": {
      "ubus": {
        "system": ["board", "info"],
        "network.device": ["status"],
        "network.interface": ["dump"],
        "network.wireless": ["status"],
        "uci": ["get"],
        "hostapd.*": ["get_clients"],
        "luci-rpc": ["getDHCPLeases", "getWirelessDevices", "getNetworkDevices"],
        "luci": ["getFeatures"],
        "rpc-sys": ["packagelist"],
        "file": ["read"],
        "luci.lldpd": ["getStatus"]
      },
      "uci": ["network", "wireless", "dhcp", "system", "dropbear", "uhttpd"],
      "file": {
        "/tmp/dhcp.leases": ["read"],
        "/sys/class/thermal/thermal_zone*/temp": ["read"],
        "/sys/class/thermal/thermal_zone*/type": ["read"]
      }
    },
    "write": {
      "ubus": {
        "uci": ["set", "add", "delete", "order", "revert", "changes", "apply", "confirm", "rollback"]
      },
      "uci": ["network", "wireless", "dhcp"]
    }
  }
}
```

and `list write 'signalbox'` next to `list read 'signalbox'` in the login entry of
`/etc/config/rpcd`. Without the write part, deploying fails at the first staged call with
"access denied for uci.…", and nothing is changed.

802.11v (`bss_transition`) needs the full `wpad` (`wpad-mbedtls`, `wpad-openssl`,
...): the hostapd of `wpad-basic-*` rejects `bss_transition` as an unknown option and then does
not start the interface at all. Signalbox only checks the UCI values after a change, not that
hostapd runs it.

## Verified against the real OpenWrt

The integration job (`.github/workflows/integration.yml`, [TESTING.md](../TESTING.md)) builds
OpenWrt 24.10.8 and 25.12.6 x86-64 images with the official image builder, installs the ACL of this page
verbatim and runs `tests/integration/test_openwrt_real.py`: contract and mapping of a lab
configuration (bridge VLANs, hwsim radios, SSIDs, dnsmasq, a wireless station with a lease),
certificate pinning, a refused login, `port`, `wlan`, `dhcp` and `reservation` through the
Deployer with a revert that leaves UCI exactly as before, the restore of a backup, the rollback
timer without confirm, a refused change with the read-only login, and two clients at once.

Confirmed as documented: the answer shapes of every read call; `uci add` with `name` (named
sections); `uci apply` with nothing staged answers "no data"; a pending apply makes another
`uci apply` with rollback answer "permission denied"; `uci confirm` and `uci rollback` only from
the session that applied.

Found on the real device (and in rpcd's source, `uci.c` and `session.c`), fixed in the adapter
and in the simulator:

- **OpenWrt 25.12**: `network.wireless status` answers "invalid argument" through rpcd; the
  adapter falls back to `luci-rpc getWirelessDevices` (new in the ACL).
- **LLDP**: there is no `lldpd` ubus object. `luci-app-lldpd` provides `luci.lldpd getStatus`,
  which the adapter reads now (ACL entry `"luci.lldpd": ["getStatus"]` instead of
  `"lldpd": ["show_neighbours"]`).
- **Rollback**: after the timer runs out (or `uci rollback`), rpcd puts the rolled back changes
  into the applying session's staging again (LuCI shows them as unsaved changes). A later
  transaction in that session would have committed them; the adapter drops them first.
- **Confirm after the deadline**: `uci confirm` answers "no data" (not "permission denied") when
  nothing waits; the adapter reports that the device rolled the change back.
- **A second client**: a new login of the same user during a pending apply gets that apply's
  session; its staging is shared and `uci revert` is refused. The adapter reported "nothing to do"
  for its own staged change; it refuses now.
- **Apply without rollback** while another change waits answers OK and applies nothing (the
  restore checks for it now); `uci revert` is refused while a change waits.
- `uci add` with an existing name changes only the section type; `uci order` and
  `uci delete` of options that do not exist answer "not found"; `uci changes` lists rpcd's
  delta entries (`["set", section, option, value]`, ...). The simulator answers like that.


## Management services (#173)

*Verified on OpenWrt 24.10 and 25.12 in CI* (the test image installs this page's ACL):
`uci get dropbear` and `uci get uhttpd` (both are in the ACL's `uci` list; a router set up
before #173 answers "access denied for uci.get (dropbear)": its services stay unread and the
rest of the read is unaffected, add the two names to the ACL to read them).

- Each `dropbear` section is an SSH service (`dropbear`, a second instance `dropbear-<port>`):
  `enable` (default on), `Port` (22), `Interface` (a network, mapped to its segment),
  `DirectInterface` (a port), `PasswordAuth`, `RootLogin`, `RootPasswordAuth` (default on).
- The `main` section of `uhttpd` gives `uhttpd` (HTTP, `listen_http`, off when empty) and
  `uhttpd-ssl` (HTTPS, `listen_https`); `addr:port` entries, `0.0.0.0` and `[::]` mean all.
  `redirect_https` is `redirects_to_https` of the HTTP service.
- No `snmpd` and no telnet are read. `from_wan` stays unknown (firewall: #135).
- `transport_encrypted` is true for https, false for `allow_insecure_http`.
