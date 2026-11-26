# OpenWrt adapter

Reads an OpenWrt device (21.02 or later; DSA bridge VLANs or plain bridges) over ubus JSON-RPC,
the API that LuCI uses: `rpcd` behind `uhttpd` at `https://<device>/ubus`. With a read-only login
nothing on the device is changed; with write access to UCI `network`, `wireless`, `dhcp`, `firewall`, `system` and `snmpd`
Signalbox can deploy port VLANs, SSIDs, DHCP pools, reservations, firewall zone policies, rules and
port forwards, the remote syslog target and switching the SNMP agent off ([Writing](#writing)).

| | |
| --- | --- |
| Adapter id | `openwrt` |
| Roles | `ap`, `switch`, `gateway` |
| Capabilities | interfaces, wireless, DHCP, DNS (dnsmasq), clients, neighbours (LLDP) |
| Writes | `port`, `wlan`, `dhcp`, `reservation` (not `router`, see [Writing](#writing)) |
| Simulator | `signalbox.sim.openwrt` (`uvicorn --factory signalbox.sim.openwrt:create_app`) |

> Verified against OpenWrt 23.05.6, 24.10.8 and 25.12.6 (x86-64 in QEMU) in CI: every call below, the read-only and
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
| `scan_neighbours` | `false` | active probe: let each running radio scan for neighbouring access points at every read (#169, below) |

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

### Spanning tree: `device` sections, `bridge-attributes`, `file read` of sysfs (#155)

`Device.stp_bridges`, one per UCI `device` of type `bridge`: `option stp '1'` (netifd's
default is off) and `option priority` (default 32767, `0x7fff`), the running values of
`network.device status` `bridge-attributes` (`stp`, `priority`; OpenWrt 22.03 and later) first.
netifd runs the kernel's 802.1D STP, so the protocol is `stp` or `none`. With STP on, the
running state comes from sysfs through `file read` (the read ACL allows
`/sys/class/net/*/bridge/*` and `/sys/class/net/*/brport/*`):

```json
/sys/class/net/br-lan/bridge/bridge_id   {"data": "1000.020000000001\n"}
/sys/class/net/br-lan/bridge/root_id     {"data": "1000.020000000001\n"}
/sys/class/net/br-lan/bridge/root_port   {"data": "0\n"}      port number, 0 on the root
/sys/class/net/lan1/brport/state         {"data": "3\n"}      0 disabled ... 3 forwarding, 4 blocking
/sys/class/net/lan1/brport/port_no       {"data": "0x1\n"}
```

plus `root_path_cost`, `path_cost`, `bpdu_guard` and `root_block` (root guard). The kernel has
no port roles and no edge ports: the root port follows from `root_port`, a blocking port is an
alternate one, `edge` stays unknown. A member without `brport` files (not found) has no
`Port.stp`; an ACL without the sysfs paths keeps the setting with an optional gap
(`openwrt.stpState`, *Fix it*: the ACL update). *(guess: DSA user ports with hardware offload
should have the kernel's `brport` files, unconfirmed on a real device, #21)*

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

Every device except `lo` becomes a port, VLAN devices (`name.vid`) too (#252); `carrier` is
the link state, `speed` `"<Mbit/s><F|H>"` speed and duplex (`-1F`: no link). `type: bridge` is a
bridge port, `phy*`/`wlan*` (or `"wireless": true`) a wireless one.

Port structure (#252, ADR 0008): `type: bridge` is role `bridge` with `bridge-members` as its
lower ports; `type` `VLAN`/`8021q`/`8021ad` role `vlan` on its `parent` (else the name before the
last dot); a Wi-Fi interface role `wireless`. With swconfig (UCI `switch_vlan` sections), a
device whose `<device>.<vid>` VLAN devices exist for a switch VLAN is the switch's CPU port
(role `cpu`); the switch ports themselves are not reported (only `/etc/board.json` says which
is the CPU port and which are jacks). Everything else comes from the next call.

### `luci-rpc getNetworkDevices` *(optional)* (port structure)

```json
{"lan1": {"name": "lan1", "devtype": "dsa", "parent": "eth1", "type": 1, "master": "br-lan", …},
 "eth1": {"name": "eth1", "devtype": "ethernet", "type": 1, …},
 "br-lan": {"bridge": true, "ports": ["lan1", …], "devtype": "bridge", …},
 "br-lan.1": {"devtype": "vlan", "parent": "br-lan", …}, "phy0-ap0": {"wireless": true, …}}
```

rpcd-mod-luci reads the kernel's facts per device: `devtype` is `DEVTYPE` of the device's
uevent (`ethernet` when there is none), `parent` the device whose ifindex is this one's
`iflink`, `type` the ARP hardware type. A `dsa` device is a jack (a DSA user port) on its
`parent`, the conduit, which gets role `cpu`. Another device of `devtype` `ethernet` and `type`
1 is a jack (a NIC of its own); `wireguard`/`ppp`/… or `type` 512/65534 a tunnel; `veth`,
`dummy`, `macvlan` virtual. *(DSA is a guess from the rpcd-mod-luci and kernel sources, tested
in the simulator only: #21. The QEMU image has no switch chip; its NICs are jacks.)* Without
rpcd-mod-luci the roles above stay unknown; with an older ACL that does not allow the call the
read is complete otherwise and reports the gap with the fix.

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

### Link aggregation: UCI bonding devices and `file read` of sysfs *(optional)* (ports, #157)

```json
{".type": "device", "name": "bond0", "type": "bonding", "ports": ["lan2", "lan3"],
 "policy": "802.3ad", "xmit_hash_policy": "layer2+3", "lacp_rate": "fast", "min_links": "1"}
{".type": "interface", ".name": "nas", "proto": "bonding", "slaves": ["lan2", "lan3"],
 "bonding_policy": "balance-xor"}        proto-bonding (older): the device is bonding-nas
{"data": "802.3ad 4\n"}                 /sys/class/net/bond0/bonding/mode
{"data": "61\n"}                        /sys/class/net/lan2/bonding_slave/ad_actor_oper_port_state
```

- A `device` of `type bonding` (netifd, OpenWrt 23.05+) or an `interface` with `proto bonding`
  is a port of role `lag` over its `ports` / `slaves`; so is a device netifd reports with type
  `bonding` or the kernel with `devtype` `bond`. Its members get `lag` (the bond's name).
- Where the ACL allows it, the kernel's state is read from sysfs: of the bond `mode`,
  `xmit_hash_policy`, `lacp_rate`, `lacp_active`, `min_links`, `slaves`, `ad_aggregator`,
  `ad_partner_mac`, `active_slave`; of each member `state`, `ad_aggregator_id` and
  `ad_actor_oper_port_state`. A member is selected when its aggregator is the bond's active
  one, collecting and distributing when bits 4 and 5 of its actor state are set; the partner's
  system id is the active aggregator's `ad_partner_mac` (the partner port is not in sysfs).
- Without those paths (an older ACL) the UCI options alone fill mode, hash, LACP rate and
  minimum links. *Guess*: the option names follow netifd's `bonding.c` and proto-bonding, the
  sysfs values the kernel's bonding documentation; no real OpenWrt with a bond was read (#21).

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
- Band steering (#447, `Wlan.band_steering` of every AP SSID, *guess: option names and defaults
  from the READMEs, #21*): `uci get {"config": "usteer"}` (package `usteer`; section type `usteer`):
  `band_steering_interval` in ms (default 120000; above 0: `prefer-5ghz`), else
  `load_balancing_threshold` above 0: `balance`, else `off`. `dawn` (`{"config": "dawn"}`,
  section type `metric`): `freq_5` (default 100) above `freq_2` (default 0): `prefer-5ghz`, else
  `off`. Neither installed (no such config) or an ACL from before #447: not reported. The
  daemons' `network` filter and whether the service runs are not looked at.
- `Radio.supported_security`: `luci getFeatures` (luci-base, part of a LuCI install, not of rpcd-mod-luci; the `hostapd` flags `sae`,
  `owe`, `eap`, `suiteb192` as LuCI reads them *(guess: object `luci`, not `luci-rpc`)*), else
  the `wpad-*` package of `rpc-sys packagelist` (`wpad-basic*`: no SAE, OWE, EAP; every other
  `wpad-*`: all *(guess)*). Both are in the ACL below; an ACL from before #167 or a missing
  package leaves it unreported, which is not an error. WEP is never listed (current hostapd
  builds have no WEP).

### Radio capabilities and state: `iwinfo` and `hostapd.<ifname> get_status` (#172)

For every running radio, with its first interface from `network.wireless status`
(`{"device": "phy0-ap0"}`), from rpcd-mod-iwinfo:

```json
{"hwmodes": ["b", "g", "n", "ax"], "htmodes": ["HT20", "HT40", "HE20", "HE40"],
 "channel": 6, "center_chan1": 6, "frequency": 2437, "noise": -92, "txpower": 20}
```

- `iwinfo info`: `standards` from `hwmodes` (only those of the radio's band, a dual-band phy
  lists both), `supported_widths_mhz` from `htmodes`, `noise_dbm` from `noise` (0: not
  reported), `center_channel` from `center_chan1` when it differs from the channel.
- `iwinfo freqlist` (`{"results": [{"channel": 36, "mhz": 5180, ...}]}`):
  `supported_channels` (the channels of the radio's band the country code allows),
  `dfs_capable` (5 GHz: any of 52-144 listed).
- `iwinfo txpowerlist` (`{"results": [{"dbm": 20, "mw": 100}]}`): `max_tx_power_dbm`.
- `iwinfo survey` (`{"results": [{"mhz": 2437, "noise": -92, "active_time": …,
  "busy_time": …, "rx_time": …, "tx_time": …}]}`): for the radio's frequency,
  `channel_utilisation_pct` = busy of active time and `interference_pct` = busy time neither
  received nor sent by the radio; the counters run since the driver started, so these are
  averages *(guess: survey on ubus, its field names; not every driver fills it)*.
- `hostapd.<ifname> get_status`: `dfs_state` on a radar channel (`dfs.cac_active` true:
  `cac`, else `available`) and, without a survey, `channel_utilisation_pct` from
  `airtime.utilization` (0-255) *(guess: field names)*. Radar events are ubus events, not
  part of the status: `last_radar` and `radar-detected` are not read.
- `client_count`: the stations of `hostapd.<ifname> get_clients` of all the radio's
  interfaces.
- From UCI: `standard` from `htmode` (`EHT*` be, `HE*` ax, `VHT*` ac, `HT*` n, `NOHT` a or g
  by band), `channel_auto` from `channel auto` (or no channel).

An ACL from before #172 (no `iwinfo`, no `hostapd get_status`) or a missing rpcd-mod-iwinfo
is an optional gap (*radio state*): everything else is read, the fields stay unreported. Not
read: `antennas`, `mlo`. A device without radios makes no such call. Checked in CI against the mac80211_hwsim radios
of the QEMU image (with rpcd-mod-iwinfo); survey and `get_status` values of real drivers are
the guesses above (#21).

### BSSIDs and neighbouring networks: `iwinfo info` and `iwinfo scan` (#169)

- `Wlan.bssid`: `bssid` of `iwinfo info` of the WLAN's running interface (`phy0-ap0`,
  `phy0-ap1`, ...), passive, at every read.
- `iwinfo scan` (`{"device": "phy0-ap0"}`, the radio's first interface) only with the setting
  **scan_neighbours** (off by default). It is an **active probe**: the radio leaves its
  channel to listen on the others, and on some drivers its clients stall for a moment; on
  others the scan fails while the radio serves clients (then nothing is reported). Each
  answer row
  (`{"results": [{"ssid": "Example", "bssid": "02:…", "mode": "Master", "channel": 6,
  "mhz": 2437, "signal": -61, "ht_operation": {"channel_width": 2040}, "vht_operation":
  {"channel_width": 80}, "encryption": {"enabled": true, "wpa": [2], "authentication":
  ["psk"]}}]}`) of an access point (`mode` `Master`) becomes a `WifiScanResult`: band from
  `mhz`, width from `vht_operation` (`8080`: 160) or `ht_operation` (`2040`: 40), security
  from `encryption` (`sae`+`psk`: WPA2/WPA3, `802.1x` with `wpa [3]`: WPA3-Enterprise, `owe`:
  Enhanced Open, not enabled: open). An empty SSID is a hidden network. Nothing about the
  stations of foreign networks is read.
- An ACL without `iwinfo scan` (from before #169) is the optional gap *radio state*; the rest
  of the radio is read.
- The radios are scanned at once, after the rest of the wireless read, within what is left of
  `observe.timeout_seconds` (minus a second). A scan takes a few seconds per band; one that
  does not finish in time is given up with the optional gap *neighbour scan: not finished*.
  rpcd answers one call at a time, so while a scan runs on the router other ubus calls (also
  LuCI's) wait for it.

The results stay on the server (device page only; not in `GET /api/network`, exporters or
MQTT). Checked in CI against the QEMU image's mac80211_hwsim radios, which hear each other;
real drivers' scan behaviour while serving clients is a guess (#21).

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
ones (`/corp.example/192.0.2.53`, also `/a.example/b.example/192.0.2.53`) are forwarders with `domain` set (#182). Without `noresolv` dnsmasq also uses the
servers of `resolvfile` (the WAN's), which are not read (`vendor_extra.upstream`). `domain`
sections (`name`, `ip`) are host records. `register_dhcp` and `dynamic_records` are true while a `dhcp` section serves a network (not `ignore`, `dhcpv4` not `disabled`): dnsmasq then answers the names of its leases (#456). *Guess*: not yet checked against the CI VMs.

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

### WireGuard: `uci get {"config": "network"}` and `luci.wireguard getWgInstances` *(optional)* (vpn)

Interfaces with `option proto 'wireguard'` are tunnels (`listen_port`, `addresses`, `mtu`,
`disabled`); their peers are the sections `config wireguard_<interface>` (`public_key`,
`description`, `endpoint_host`, `endpoint_port`, `allowed_ips`, `persistent_keepalive`,
`disabled`). The same answer holds `private_key` (interface) and `preshared_key` (peer): the
adapter deletes the private key and turns the pre-shared key into "set" the moment the answer
arrives, before anything else looks at it; no key but a public key is ever stored or logged.

The running state comes from `luci.wireguard getWgInstances` (package `luci-proto-wireguard`,
rpcd ucode): `{"wg0": {"public_key": "...", "listen_port": 51820, "peers": [{"public_key":
"...", "endpoint": "203.0.113.20:51820", "allowed_ips": [...], "latest_handshake": 1700000000,
"transfer_rx": 1234, "transfer_tx": 5678, "persistent_keepalive": 25}]}}` *(guess: field names
per release; only the public key, endpoint, handshake and transfer are read)*. Without the
package the tunnels are read from the configuration alone (no own public key, handshake or
transfer); with a read ACL from before this method was added the read fails with "access
denied" for the `vpn` capability only. ACL entry: `"luci.wireguard": ["getWgInstances"]`, the
only addition.


### OpenVPN: `uci get {"config": "openvpn"}` *(optional)* (vpn, #153)

Every `config openvpn '<name>'` section is a tunnel (`openvpn-<name>`): a client with
`client '1'` or a `remote` and no `server`, a server with `server`. Read: `enabled`, `proto`,
`port`, `server` (tunnel network, address and mask), `remote`, `cipher`/`data_ciphers`, the
`push`/`route` lines (routes) and whether `tls_auth`, `tls_crypt` or `tls_crypt_v2` is set. The
static key (`secret`), the key files, `askpass` and `auth_user_pass` are dropped when the
answer arrives; only the flags remain. A static-key tunnel counts as no TLS (no finding about
`tls-auth`). The runtime is the status file, `/var/run/openvpn.<section>.status` or the
section's `status` option, through `file read` (#527): format 2 and 3 (`status_version '2'`
or `'3'`) carry epoch times, so a `TIME` line not older than 15 minutes gives `up` and the
`CLIENT_LIST` rows give the sessions (common name, virtual address, connected since); format 1
(the default) gives the client names only and `up` stays unknown (its times are local text
without zone). *Guess (#21): layouts from the OpenVPN 2.4 to 2.6 manual; OpenWrt's update
interval of the file is not assumed.* No package: no tunnels. An ACL without `openvpn` or
without the status path (set up before #153 or #527): an optional gap, fixed by adding the
entries of the ACL above. Covered: OpenWrt 21.02, 22.03, 23.05 and 24.10 (the section type is
`openvpn` in all).

### strongSwan: `file read` of `/etc/swanctl/swanctl.conf` *(optional)* (vpn, #527)

Every connection of the `connections` section is an IPsec tunnel (`ipsec-<name>`): IKE
`version`, `aggressive`, `remote_addrs`, how the device authenticates (`local` `auth`: `psk`,
`pubkey`, `eap-*`), `proposals` and the children's `esp_proposals`, `local_ts`/`remote_ts` and
`rekey_time`, and whether `dpd_delay` is set. The `secrets` section (pre-shared keys,
passphrases, EAP passwords) is skipped while the text is parsed and never stored; certificate
and key file names are not read, so the certificate subject stays unknown. The state of the
security associations is not reachable through rpcd (vici is a local socket): `up` and
`established` stay unknown. No file or the legacy `ipsec.conf` (strongSwan 5.x
`strongswan-ipsec`): no tunnels; `include` lines are not followed. ACL entry:
`"/etc/swanctl/swanctl.conf": ["read"]`; an older ACL: an optional gap. *Guess (#21): the
file layout of strongSwan 5.9 and 6.0 on OpenWrt 22.03 to 24.10.*

### Smart queue management: `uci get` of `sqm` *(optional)* (interfaces, #166)

The package `sqm-scripts` is optional: without it there is no config and nothing is reported,
and an ACL from before #166 (without the config) reads as none. ACL entry: the UCI config `sqm`,
nothing else. One shaper per `queue` section: `enabled`, `interface` (the device, matched to the
uplink by its name or port), `download` and `upload` (kbit/s, `0`: not limited), `qdisc` (`cake`,
default, or `fq_codel`; anything else is reported as SQM) and `script`. `diffserv` in
`qdisc_opts` / `iqdisc_opts` marks DSCP use. Per-client limits and WMM are not read.
*(guess: option names from the sqm-scripts documentation, #21; sqm-scripts 1.5 on OpenWrt 21.02
to 25.12.)*

### Captive portals: `uci get` of `opennds` and `nodogsplash` *(optional)* (interfaces)

Both packages are optional (#460): without them there is no config and nothing is reported, and
an ACL from before #460 (without the two configs) reads as none. ACL entries: the UCI configs
`opennds` and `nodogsplash`, nothing else. One portal per `opennds` / `nodogsplash` section:
`enabled`, `gatewayinterface` (the device, mapped to its network), `sessiontimeout` (minutes;
defaults 1440 and 1200; 0: no limit). Login: `fasremoteip` is external, a `binauth` script a
password, a `preauth` script not known, else click-through (the built-in splash page).
*(guess: option names and defaults from the READMEs, #21; openNDS 9 and 10, nodogsplash 4.)* The
`faskey` and any voucher or user data are never read.

### Multi-WAN and dynamic DNS: `uci get` of `mwan3` and `ddns`, `mwan3 status` *(optional)* (interfaces)

Both packages are optional; without them there is no config and nothing is reported (#150, #154).

- **mwan3** (`uci get {"config": "mwan3"}`): `interface` sections (`enabled`, `track_ip`,
  `interval`) are the monitors, `member` sections (`interface`, `metric`, `weight`) and `policy`
  sections (`use_member`) the gateway groups. Members of different metrics are the tiers of a
  failover (metric 1 first), members of one metric share the load. The state per interface comes
  from `ubus call mwan3 status {"section": "interfaces"}` (`status` `online`/`offline`,
  `track_ip` with `latency` and `packetloss`) *(guess: not yet seen on a device, #21)*; without
  it the groups come without state. Written for mwan3 2.x (OpenWrt 22.03, 23.05, 24.10 and
  25.12 ship it; *guess*: the option names are the same in all of them, #21).
- **ddns-scripts** (`uci get {"config": "ddns"}`): `service` sections with `enabled`,
  `service_name` (the provider), `lookup_host` (the name), `interface` and `use_ipv6`. The
  `username`, `password` and `update_url` options are never read. The last update and the
  announced address come from `file read /var/run/ddns/<section>.update` (epoch seconds) and
  `<section>.ip` *(guess, #21)*; a section with an update file counts as `ok`, otherwise the
  result is unknown (the failure state is not read).
- ACL entries: `"mwan3": ["status"]`, the UCI configs `mwan3` and `ddns`, and the file
  `/var/run/ddns/*`; with an older ACL the rest is read and an optional gap names them.

## Path traces: not supported (#253)

rpcd has no traceroute method. LuCI's *Network > Diagnostics* runs `/usr/bin/traceroute`
through `file exec` with an ACL of its own (`luci-mod-network-diagnostics`), an exec right on
the router that Signalbox does not ask for, so the integration declares no traces. An OpenWrt
router is still a destination of the other routers' traces ([TRACES.md](../TRACES.md)).

## Automatic setup

*Set up automatically* in the device form (#231, [ADR 0009](../adr/0009-automatic-setup-with-an-admin-login.md))
does the steps of the next section for you, over SSH as root.
It is optional: the manual setup below is the same result and always works. Nothing is
changed on the device unless you start it for that device and confirm the plan (never from
*Find devices*, a read or in the background), and `setup.enabled: false` in the
configuration turns it off completely (the API refuses it, the form does not show it).


1. Enter the router's address and the login to create (`signalbox` by default), and the SSH port
   (22). *Show what it does* lists what the setup normally does, without any password.
   *Continue* connects to dropbear and shows the router's SSH host key (`SHA256:…`); nothing is
   sent before you trust it. Compare it on the router:
   `dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key` (or the `_rsa_` key) prints it.
   Only then root's password is asked for, in a small field right before *Run* (used once,
   never saved, cleared after the request).
2. Signalbox lists the steps, each *will be done* or *already as needed*: the missing packages
   (`apk add` on 25.12 and later, `opkg install` before; the router needs internet access only
   then), `/usr/share/rpcd/acl.d/signalbox.json` (the read-only ACL below, or the ACL with write
   access when *Allow changes* is on), the rpcd login with a new generated password (only the
   md5-crypt hash is sent), `/etc/init.d/rpcd restart`, and the web server's certificate,
   read over this SSH connection (`uci get uhttpd.main.cert`, DER or PEM) to pin it for reading.
   Optional extras are unticked checkboxes: *Also install LLDP* adds installing `lldpd` and
   `luci-app-lldpd`, enabling and starting lldpd (before the rpcd restart). Without it the device
   stays *ok*; the missing LLDP is only shown as an optional note (#278).
3. *Set up the device* runs them and saves the device with the new login. The password is stored
   encrypted like any other and never shown; root's password is not stored or logged.

Running it again repairs a partial setup and updates the ACL file after an update of Signalbox;
without *Allow changes* it takes write access away again. *Remove what Signalbox set up* deletes
the login, and the ACL file unless another login lists `signalbox`; packages stay (ticking
*Also remove LLDP* stops lldpd and removes its two packages). Every script
goes over standard input of `sh -s`, so no secret appears in a process list on the router.
Needs dropbear with password login for root (OpenWrt's default).

Verified in CI on 24.10 and 25.12 (`tests/integration/test_openwrt_setup_real.py`): host key
pinning and a refused root password; a login `signalbox-auto` created with the image's packages
and ACL already in place, the router read with it (contract) over the certificate read through
SSH; again read-only (the ACL file loses its write part, the old password stops working); the
removal keeps the ACL file the image's other logins use. *Not verified*: installing packages
(the CI router has no internet access, the simulator covers it) and dropbear builds without
password authentication.

### Fix it

Some read problems name a remedy (#215, [ADR 0012](../adr/0012-fix-it-for-read-problems.md)):
the device page shows *Fix it* next to the error (it does not need *Allow changes*: it only adds
packages and permissions Signalbox reads through, #278), below its
"What to do", which stays the manual way. *Fix it* asks for root's password (and the SSH port),
shows the host key to trust, then the exact steps; *Fix it on the device* asks once more and
runs them, then reads the router again. It is optional like the setup: never in the background,
off with `setup.fixes: false` or `setup.enabled: false`. It changes only Signalbox's own
packages and permissions, never network settings.

- **Repair Signalbox's access** (`access`; an "access denied" for a call, the port structure
  gap, wireless on 25.12 without rpcd-mod-luci): installs the missing packages of the setup,
  writes `/usr/share/rpcd/acl.d/signalbox.json` as above (with the write part, since changes are
  allowed), adds `list read 'signalbox'` / `list write 'signalbox'` to the stored login's
  section if missing (its password is not touched; root needs nothing) and restarts rpcd.
- **Install LLDP** (`lldp`; "LLDP is not installed", "lldpd is installed but not running"):
  `apk add lldpd luci-app-lldpd` (24.10: `opkg install`) if missing, `/etc/init.d/lldpd enable`
  and `start`, then the permission steps and an rpcd restart. lldpd then sends and receives
  LLDP on the router's ports.

Verified in CI on 24.10 and 25.12: an ACL file without `luci-rpc getNetworkDevices` gives the
port structure gap with `access`, the fix rewrites the file and the next read is complete; a
stopped lldpd is found with its packages installed and started. Installing from the feeds is
offline in CI: simulator only (#21).

## Read-only user on the device

The device form shows these steps as commands to paste on the router (`ssh root@<router>`):
packages, the ACL file below and a login `signalbox`. A router without Wi-Fi (no
`/etc/config/wireless`) or without DHCP server (no `/etc/config/dhcp`) is read as having none.
Every "access denied" error says to install this ACL; root may call whatever an installed ACL
file allows (`list read '*'`), so with the file in place root works too.

Packages: `rpcd`, `uhttpd`, `uhttpd-mod-ubus` (all part of a LuCI install); `rpcd-mod-file` for
the lease file, `rpcd-mod-luci` for `luci-rpc`, `luci-base` for `luci getFeatures` (the security modes the radios support), `rpcd-mod-iwinfo` for the radios' capabilities and utilisation (#172; part of a LuCI install) and `luci-app-lldpd` for LLDP are optional; on
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
        "uci": ["get", "changes"],
        "hostapd.*": ["get_clients", "get_status"],
        "iwinfo": ["info", "freqlist", "txpowerlist", "survey", "scan", "assoclist"],
        "luci-rpc": ["getDHCPLeases", "getWirelessDevices", "getNetworkDevices"],
        "dhcp": ["ipv6leases"],
        "luci": ["getFeatures"],
        "rpc-sys": ["packagelist"],
        "file": ["read"],
        "luci.lldpd": ["getStatus"],
        "luci.wireguard": ["getWgInstances"],
        "mwan3": ["status"],
        "poe": ["info"]
      },
      "uci": ["network", "wireless", "dhcp", "system", "dropbear", "uhttpd", "firewall",
              "snmpd", "luci_statistics", "softflowd", "rpcd", "mwan3", "ddns", "usteer", "dawn", "opennds", "nodogsplash", "igmpproxy", "upnpd", "openvpn", "sqm", "poe"],
      "file": {
        "/tmp/dhcp.leases": ["read"],
        "/sys/class/thermal/thermal_zone*/temp": ["read"],
        "/sys/class/thermal/thermal_zone*/type": ["read"],
        "/sys/class/net/*/bonding/*": ["read"],
        "/sys/class/net/*/bonding_slave/*": ["read"],
        "/sys/class/net/*/bridge/*": ["read"],
        "/sys/class/net/*/brport/*": ["read"],
        "/sys/class/net/*/brforward": ["read"],
        "/sys/devices/*/net/*/brforward": ["read"],
        "/sys/devices/*/net/*/bridge/*": ["read"],
        "/sys/devices/*/net/*/brport/*": ["read"],
        "/var/run/ddns/*": ["read"],
        "/etc/avahi/avahi-daemon.conf": ["read"],
        "/var/run/miniupnpd.leases": ["read"],
        "/var/run/openvpn.*.status": ["read"],
        "/etc/swanctl/swanctl.conf": ["read"]
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

1. `uci get` of `network`, `wireless`, `dhcp`, `firewall`, `system` and (if installed) `snmpd`, and `network.interface dump`; the changes are
   translated one after another on that copy, so a later change sees an earlier one (the WLAN on
   VLAN 30 finds the VLAN the port change creates). The review shows exactly these calls
   (`plan_changes`); Wi-Fi keys appear as `***`.
2. **Backup**: the `uci get` answers of those configs as one JSON document (format
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
| `wlan` | All `wifi-iface` sections in AP mode with this SSID. New SSID: one section per radio (`<ssid>_<radio>`). Only options that differ are written: `ssid`, `encryption` (open `none`, OWE `owe`, WPA2 `psk2`, WPA3 `sae`, WPA2/WPA3 `sae-mixed`; enterprise is refused, it needs RADIUS settings), `key` from the passphrase secret, `ieee80211w` (PMF 0/1/2), `ieee80211r`, `ieee80211k`, `bss_transition`, `isolate` (client isolation, only when the desired state sets `client_isolation`), `hidden`, `disabled`, `network`; with 802.11r on, `mobility_domain` and `ft_over_ds` where declared, and `rssi_reject_assoc_rssi` for `min_rssi_dbm` (`off` deletes it; a client below it cannot associate, associated ones are not kicked). netifd passes `rssi_reject_assoc_rssi` to hostapd since OpenWrt 22.03 *(guess, #21)*: on an older release (read from `system board`) a plan that sets it is refused ([ADR 0033](../adr/0033-wifi-roaming-desired-state.md)). Removed SSID: its sections are deleted. |
| `wlan` network | The interface on the segment's VLAN (the first by name). If the VLAN is on the bridge but has no interface, Signalbox adds `config interface vlan<vid>` with `device <bridge>.<vid>` and `proto none` (DSA creates the VLAN device itself, no `config device` is needed). If the VLAN is on no port of the access point, the change is refused: tag it on the uplink in the same plan. When a later change removes that VLAN, an unused `proto none` interface on it is deleted too. |
| `dhcp` | The `dhcp` section of the segment's interface (created if missing): `ignore`, `start` and `limit` from the pool (offsets in the interface's IPv4 subnet), `leasetime`, DNS as `dhcp_option 6,…` (other options kept). The interface must already have an IPv4 address. Enabling without a pool is refused. |
| `reservation` | The `host` section with that MAC: `ip`, `name`; a new one is `host_<mac>`. A host section shared by several MACs keeps the others. |
| `zone-policy` | Between a zone and the router (`to: device`): the zone's `input`; inside a zone: its `forward`. Between two zones: `accept` adds `config forwarding 'sb_pol_<src>_<dest>'` unless one exists; `reject` deletes Signalbox's forwardings of the pair, and the device's own one only when the policy says `adopt: true` (else refused); `drop` between two zones is refused (OpenWrt rejects what no forwarding allows). Zones themselves are never created or removed. |
| `firewall-rule` | `config rule 'sb_rule_<key>'`: `name`, `src` (zone or `*`), `dest` (forward rules; zone or `*`), `src_ip`, `dest_ip`, `dest_port`, `proto` (`all` for every protocol), `family`, `target`, `enabled`. A new rule is moved before the device's own rules (`uci order`), after Signalbox's older ones. `adopt: <name>` replaces the device's own rule of that name with Signalbox's section, which carries over every option the declaration does not model (`log`, `limit`, `extra`, `src_port`, ...; the plan lists them); an option that does not fit (`icmp_type` without icmp) refuses the adoption with the list. |
| `port-forward` | `config redirect 'sb_fwd_<key>'` with `target DNAT`: `name`, `src` (the internet zone), `src_dport`, `dest` (the zone of the interface whose subnet holds the target), `dest_ip`, `dest_port`, `proto`, `enabled`. `adopt: <name>` as for rules. |
| `log-target` | `system.@system[0]`: `log_ip`, `log_port`, `log_proto` (`udp` or `tcp`) and the tag `signalbox_syslog '1'`; `log_remote` is removed so the target is used. logd has one slot: a second declared target is refused, and a target of the device's own (no tag) is replaced only when the change adopts it. Removal deletes the four options when the slot still holds that address. Syslog over TLS is refused. *Guess (#21): that `uci apply` makes logd pick up the new target on every release.* |
| `snmp-policy` | `snmpd.general.enabled` `0` (off) or `1` (back on, as a revert); the section is created if the package has none. `v3-only` is refused (it needs SNMPv3 users and their secrets); a router without the `snmpd` config is refused. *Guess (#21): that the package's init script reloads on `uci apply` and honours `enabled`.* |
| `gateway-group` | The mwan3 `policy` of the group's name (#463, [ADR 0032](../adr/0032-gateway-group-desired-state.md)): the members in its `use_member` list get the tier as `metric` (every member gets its tier number when the order of the tiers changes) and `weight`; the line's monitor is `track_ip` of the mwan3 `interface` of the same name (removed for an empty monitor; refused on a disabled interface). A member section that another policy also uses is not changed: a copy `sb_<policy>_<line>` (option `signalbox '1'`) with the new values replaces it in this policy's `use_member`. Policies, members and interfaces are never created or removed; a router without the `mwan3` config is refused. *Guess (#21): that `uci apply` makes mwan3 reload on every 2.x release.* |
| `tunnel` | A `proto wireguard` interface ([ADR 0034](../adr/0034-wireguard-tunnels-desired-state.md)): `listen_port`, `addresses`, `mtu` and the option `signalbox` with the tunnel's name; the [key helper](#wireguard-key-helper) gives a new one its key pair on the router after `uci apply`, inside the confirm window. An adopted interface keeps its section and only the declared options change. Removal deletes Signalbox's interface and its `wireguard_<interface>` sections. The interface is not added to a firewall zone: put it into one yourself (LuCI, or `firewall.@zone[...].network`), else the zone defaults decide what passes. Interface names are letters, digits and `_` (15 at most). Private and pre-shared keys are never read, written or backed up (the backup and a restore leave `private_key` and `preshared_key` as they are). |
| `tunnel-peer` | The `wireguard_<interface>` section of the other end (`sb_<interface>`, option `signalbox`, `description` the tunnel's name): `public_key`, `allowed_ips`, `route_allowed_ips '1'` (netifd routes the other end's networks), `endpoint_host` and `endpoint_port` where the other end declares an endpoint, `persistent_keepalive` where declared. An adopted peer (the other end's public key, no tag) keeps its section and its pre-shared key. |
| `upnp` | The `upnpd` section of miniupnpd (#513, [ADR 0035](../adr/0035-upnp-desired-state.md)): `enabled` (`0` off, `1` on only when the desired state says so; refused when both `enable_upnp` and `enable_natpmp` are off), `secure_mode`, and `internal_iface` (the UCI networks of the declared segments, space separated; a segment without an interface on the router is refused). A declared `allow` list replaces every `perm_rule` section with `sb_upnp_<n>` sections (`action`, `ext_ports`, `int_addr`, `int_ports`, `comment 'Signalbox'`), one `allow` per entry and a final `deny 0-65535 0.0.0.0/0 0-65535`. Undeclared options are left as they are. Open mappings are not removed by Signalbox: they end with their lease, and miniupnpd may remove them as it stops. A router without the `upnpd` config (package `miniupnpd` not installed) is refused. *Guess (#21): that `uci apply` restarts miniupnpd on every release.* |
| `poe` | The `port` section of UCI `poe` (realtek-poe) whose `name` is the port (#484, [ADR 0036](../adr/0036-poe-desired-state.md)): `enable '1'` or `enable '0'`; `priority` and `poe_plus` are left alone. A switch without the `poe` config or without a section for the port is refused. The daemon reloads its ports on a change of the config. *Guess (#21): that the reload switches the port on every release.* |
| `router` | Not supported: a routed VLAN on OpenWrt also needs its own firewall zone, which Signalbox does not create. Create routed interfaces and their zones by hand (or in LuCI); DHCP, reservations and the zone's policies and rules can then be deployed. |

### Login with write access

Same packages as for reading. `/usr/share/rpcd/acl.d/signalbox.json` with a `write` part that
only allows the `uci` methods of a transaction on the nine configs it changes (`system` for the syslog target, `snmpd` for the agent, `mwan3` for gateway groups, `upnpd` for UPnP, `poe` for PoE; a login set up with an older ACL still works for the other changes, those kinds are refused):

```json
{
  "signalbox": {
    "description": "Signalbox: network inventory, changes to network, wireless, dhcp, firewall, system, snmpd, mwan3, upnpd and poe, WireGuard key helper",
    "read": {
      "ubus": {
        "system": ["board", "info"],
        "network.device": ["status"],
        "network.interface": ["dump"],
        "network.wireless": ["status"],
        "uci": ["get", "changes"],
        "hostapd.*": ["get_clients", "get_status"],
        "iwinfo": ["info", "freqlist", "txpowerlist", "survey", "scan", "assoclist"],
        "luci-rpc": ["getDHCPLeases", "getWirelessDevices", "getNetworkDevices"],
        "dhcp": ["ipv6leases"],
        "luci": ["getFeatures"],
        "rpc-sys": ["packagelist"],
        "file": ["read"],
        "luci.lldpd": ["getStatus"],
        "luci.wireguard": ["getWgInstances"],
        "mwan3": ["status"],
        "poe": ["info"]
      },
      "uci": ["network", "wireless", "dhcp", "system", "dropbear", "uhttpd", "firewall",
              "snmpd", "luci_statistics", "softflowd", "rpcd", "mwan3", "ddns", "usteer", "dawn", "opennds", "nodogsplash", "igmpproxy", "upnpd", "openvpn", "sqm", "poe"],
      "file": {
        "/tmp/dhcp.leases": ["read"],
        "/sys/class/thermal/thermal_zone*/temp": ["read"],
        "/sys/class/thermal/thermal_zone*/type": ["read"],
        "/sys/class/net/*/bonding/*": ["read"],
        "/sys/class/net/*/bonding_slave/*": ["read"],
        "/sys/class/net/*/bridge/*": ["read"],
        "/sys/class/net/*/brport/*": ["read"],
        "/sys/class/net/*/brforward": ["read"],
        "/sys/devices/*/net/*/brforward": ["read"],
        "/sys/devices/*/net/*/bridge/*": ["read"],
        "/sys/devices/*/net/*/brport/*": ["read"],
        "/var/run/ddns/*": ["read"],
        "/etc/avahi/avahi-daemon.conf": ["read"],
        "/var/run/miniupnpd.leases": ["read"],
        "/var/run/openvpn.*.status": ["read"],
        "/etc/swanctl/swanctl.conf": ["read"]
      }
    },
    "write": {
      "ubus": {
        "file": ["exec"],
        "uci": ["set", "add", "delete", "order", "revert", "changes", "apply", "confirm", "rollback"]
      },
      "uci": ["network", "wireless", "dhcp", "firewall", "system", "snmpd", "mwan3", "upnpd", "poe"],
      "file": {
        "/usr/libexec/signalbox-wg-key": ["exec"]
      }
    }
  }
}
```

and `list write 'signalbox'` next to `list read 'signalbox'` in the login entry of
`/etc/config/rpcd`. Without the write part, deploying fails at the first staged call with
"access denied for uci.…", and nothing is changed.

### WireGuard key helper

Only for WireGuard tunnels Signalbox creates (#152, [ADR 0034](../adr/0034-wireguard-tunnels-desired-state.md)).
A new interface needs a key pair, and its private key must never pass through Signalbox: the
router generates it. rpcd cannot do that without returning the key (`luci.wireguard
generateKeyPair` answers with it), so the ACL above lets Signalbox run this one script, which
writes a key from `wg genkey` (package `wireguard-tools`) into `/etc/config/network` of an
interface Signalbox created (option `signalbox`) and prints nothing:

```sh
cat > /usr/libexec/signalbox-wg-key <<'END'
#!/bin/sh
# Signalbox: a private key for a WireGuard interface Signalbox created (#152).
# Generated here with wg genkey and written to /etc/config/network; nothing is printed.
[ "$1" = "--check" ] && { command -v wg >/dev/null; exit $?; }
s="$1"
case "$s" in ""|*[!A-Za-z0-9_]*) exit 2 ;; esac
[ "$(uci -q get "network.$s.proto")" = wireguard ] || exit 3
[ -n "$(uci -q get "network.$s.signalbox")" ] || exit 3
[ -z "$(uci -q get "network.$s.private_key")" ] || exit 0
umask 077
d=$(mktemp -d) || exit 4
k=$(wg genkey) || { rm -rf "$d"; exit 5; }
uci -t "$d" set "network.$s.private_key=$k" && uci -t "$d" commit network
r=$?
rm -rf "$d"
[ $r -eq 0 ] || exit 6
ifup "$s" >/dev/null 2>&1
exit 0
END
chmod 755 /usr/libexec/signalbox-wg-key
```

It runs after `uci apply` and before the confirmation, so a rollback also takes the key away;
it uses a save directory of its own, so changes staged elsewhere are not committed. Without
the script (or with an ACL from before #152), creating a tunnel is refused with that reason;
changing an interface you created yourself and adopted still works. Signalbox never sets or
changes a pre-shared key.

802.11v (`bss_transition`) needs the full `wpad` (`wpad-mbedtls`, `wpad-openssl`,
...): the hostapd of `wpad-basic-*` rejects `bss_transition` as an unknown option and then does
not start the interface at all. Signalbox only checks the UCI values after a change, not that
hostapd runs it.

## PoE switches (#159)

On a switch with the `realtek-poe` daemon, `ubus call poe info` gives the budget, the total
consumption and per port the mode (`PoE`, `PoE+`, `PoE++`), the status and the consumption. The
units are a *guess* (#21): the total in watts, the port value in milliwatts (a value above the
budget is read as milliwatts, below as watts). A device without that object (or an rpcd ACL that
hides it: `"poe": ["info"]` is in the ACL since #484) reports no PoE. The older `poemgr`
daemon is not read.

PoE is switched (#484, [ADR 0036](../adr/0036-poe-desired-state.md)) through UCI `poe`: the
`port` section whose `name` is the port gets `enable '1'` or `enable '0'`, inside the usual
`uci apply` with its confirm timer; the daemon's init script reloads the ports on a change of
that config (`procd_add_config_trigger "config.change" "poe" ubus call poe reload`), and
the next `poe info` shows the new state. `priority` and `poe_plus` are left alone. The
package ships with OpenWrt 23.05, 24.10 and 25.12 (from 25.12 the config is generated from
`board.json` on first boot; the option names are the same); a switch without the `poe`
config, or a login whose ACL predates #484, refuses PoE changes with the reason and the
other kinds keep working. *Guess (#21)*: that a reload powers a port down and up as the
option says on every release.

## Supported versions

| Release | Package manager | CI (QEMU) | Simulator | Known differences |
| --- | --- | --- | --- | --- |
| 25.12 | apk | yes | `wireless_ucode = True` | `network.wireless status` through `luci-rpc` |
| 24.10 | opkg | yes | `release = "24.10.8"` | none known |
| 23.05 | opkg | yes (23.05.6) | `release = "23.05.6"` | `luci.lldpd` of `luci-app-lldpd` may be missing: LLDP is then an optional gap (*guess*, confirmed by CI only if the test shows it) |

22.03 and older are not supported (fw3, swconfig targets, no `bridge-vlan` guarantee).

## Verified against the real OpenWrt

The integration job (`.github/workflows/integration.yml`, [TESTING.md](../TESTING.md)) builds
OpenWrt 23.05.6, 24.10.8 and 25.12.6 x86-64 images with the official image builder, installs the ACL of this page
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


## Log and monitoring targets (#180)

- **logd**: `uci get system`, first `system` section: `log_ip` (a list on newer releases),
  `log_port` (514), `log_proto` (`udp` or `tcp`), `log_remote` (`0` turns it off). Read with the
  ACL as before (*verified in CI*: the image sets a TCP target on 1514).
- **snmpd** (package `snmpd`): the agent becomes the management service `snmp` (name `snmpd`):
  `com2sec`/`com2sec6` communities are only compared with `public` and `private` (never kept),
  `source` other than `default` is `allowed_from` (`localhost` as 127.0.0.1/32), `group`
  `version` (`v1`, `v2c`, `usm` is v3; none given: v1 and v2c), `access` `write` other than
  `none` is write access, the port from `agent.agentaddress`, `general.enabled`. `trapsink`,
  `trap2sink` and `informsink` are `snmp-trap` targets (port 162). *CI reads a config written by
  the image in the package's layout; the package itself is not installed (guess, #21).*
- **collectd** (luci-app-statistics): `uci get luci_statistics`, `collectd_network.enable` and
  the `collectd_network_server` sections (`host`, `port` 25826) as `metrics` targets (*guess*).
- **softflowd**: each `softflowd` section, `host_port` and `export_version` (10 is IPFIX),
  enabled with `enabled=1` (*guess*).

A package that is not installed has no config (nothing to report). The three configs are in the
ACL's `uci` list since #180; a router set up with an older ACL answers "access denied" for them:
an optional gap with the fix (*Fix it* updates the ACL), the rest is read.

## Firewall and NAT (#135)

Read with the `firewall` capability (adapter API 1.4, [ADR 0013](../adr/0013-firewall-zones-rules-and-reachability.md))
from `uci get firewall`; `firewall` is in the **read** ACL's `uci` list (above, in
`setup.py` `READ_ACL`, and so in the setup and *Fix it* steps; since #295 the write ACL has it too).
A router set up with an older ACL answers "access denied for uci.get (firewall)": the capability
reports a gap with the usual fix (update the ACL file, `service rpcd restart`), the rest is read.

- `zone` (`name`, `network` mapped like the interfaces: a bridge or VLAN network to its segment,
  `wan`/`wan6` to the uplink, a WireGuard interface to its tunnel; `masq`; a zone with `device`,
  `subnet` or `extra`, or a network that maps to nothing is `complete = False`); a zone without
  any is the network of its own name.
- Policies: a zone's `input` (zone to the router) and `forward` (inside the zone), else the
  `defaults`; a `forwarding` (`src` to `dest`) is an accept; `forward_policy` is reject (traffic
  between zones without a forwarding is rejected), `input_policy` is `defaults.input`.
- `rule`: no `dest` is an input rule, a `dest` zone or `*` a forward rule, no `src` an output rule;
  `src_ip`, `dest_ip`, `dest_port` (ranges `a-b`), `proto` (default `tcp udp`; `all`), `family`,
  `target` (default DROP; MARK, NOTRACK and the like are skipped), `enabled`. Inexact:
  `icmp_type`, `limit`, `ipset`, `mark`, `start_time`, `weekdays`, `src_mac`, `extra` and similar.
  An `include` section (other than the default `/etc/firewall.user`) makes `rules_complete` false.
- `redirect` with DNAT: `src` (zone), `src_dport`, `src_dip`, `src_ip`, `dest_ip`, `dest_port`,
  `proto`, `reflection`; `passes_filter` is true. One without `dest_ip` (to the router itself)
  is no forward, and makes the list incomplete only on an uplink zone. SNAT redirects and `nat`
  sections are `NatRule`s; zone `masq` is `masquerade` of the zone.
- **CI** (24.10 and 25.12): `test_firewall_of_the_default_config` reads the image's default
  config (zones lan and wan, the lan to wan forwarding, the `Allow-*` rules); the lab has no
  `wan` interface, so that zone is incomplete. *Guess*: redirect and `nat` sections on a real
  router (the simulator has them), fw3 releases.

## MAC address table (#160, #378)

Read with `clients`: for every bridge of `network.device status` the kernel's table
`/sys/class/net/<bridge>/brforward` through `file read` with `"base64": true` (16-byte records
of `struct __fdb_entry`: MAC, port number, local flag, age in 1/100 s), and the port numbers
of its members from `/sys/class/net/<member>/brport/port_no`. No extra package and no `exec`
permission, only the ACL paths `/sys/class/net/*/brforward` and, because rpcd checks a path after resolving the `/sys/class/net` symlinks, `/sys/devices/*/net/*/brforward`, `/sys/devices/*/net/*/bridge/*` and `/sys/devices/*/net/*/brport/*` (the spanning-tree reads need the last two as well). Local entries are the device's own
addresses (`self`), the rest `dynamic` with their age. The file has no VLAN: an address learned
in several VLANs is one entry. An ACL of an older setup refuses the file: the clients are read,
the table is an optional gap (`openwrt.fdbRead`, *Fix it*: the ACL update).

Other ways were left out: no rpcd method returns the bridge forwarding database
(`network.device status`, `luci-rpc getHostHints` and `getNetworkDevices` have no per-port
MACs), and `bridge -j fdb` needs the `ip-bridge` package and an `exec` permission.

*Verified in CI* (QEMU, 24.10 and 25.12): the read with the ACL of this page; the bridge's own
addresses on its members. *Guess* (#21): on a DSA switch the file holds what the software bridge
learned (broadcasts and frames to the CPU), not every address the switch chip keeps in
hardware; enough to tell which port leads to which device in a home network. The age is read in
either byte order (big-endian MIPS boards), unconfirmed on such a board.

## Accounts (#175)

`uci get {"config": "rpcd"}`: each `config login` section becomes an account with `username`,
the privilege of its ACLs (`write '*'` is admin, other `write` groups write, `read` groups only
read) and `password_set`: `$p$<user>` refers to the system password in `/etc/shadow`, which is
not readable (unknown); any other value is a hash (set); no `password` option: none
(*guess* that rpcd then accepts any password, #21). The `password` options are dropped the
moment the answer arrives; no hash is kept, logged or exported. The read ACL lists `rpcd` for
this (an older ACL gives an optional gap; *Fix it* updates it).

`default_credentials` is true when the configured login is `root` with an empty password,
compared in memory. The advanced setting **probe_empty_root_password** (off by default) is an
active probe: at every read Signalbox also tries one `session.login` as `root` with an empty
password and destroys the session at once. A success means root still has no password (the
OpenWrt factory state; *guess* that rpcd accepts it, #21). Nothing is changed. The rules are in
[account_checks](../rules/account_checks.md).

## Routes and policy rules (#149)

Read from what `read_interfaces` has already, no new ACL entry: the `route` list of every
interface in `network.interface dump` (the installed routes; the origin comes from the
interface's protocol: `dhcp` and `pppoe` defaults are `dhcp`, `dhcpv6` is `ra`, `wireguard` is
`vpn`, everything else `static`) and the `route`, `route6`, `rule` and `rule6` sections of
`uci get network`. A configured route in the main table that is not in the dump has
`active=false`; a `table` option puts a route in that table; `type` `blackhole`, `unreachable`
and `prohibit` are dropping routes. A rule with `invert`, an unreadable `src` or `dest`, a
`goto`, or an incoming interface (`in`) that is no network of the router is left out. Connected
networks come from the subnets. *CI*: the image's static route and rule (see
tests/integration/test_openwrt_real.py). *Guess:* `rule` options of other actions (#21).

## DNS: DNSSEC and encrypted upstreams (#182, #80)

dnsmasq's `dnssec` option becomes `dnssec`. If `/etc/config/https-dns-proxy` or
`/etc/config/stubby` exists, the DNS service is marked as able to encrypt (dnsmasq then forwards
to `127.0.0.1#port`, a local forwarder). The instances are read (#182): a forwarder to the local
port of an `https-dns-proxy` section (`resolver_url`, older releases `url_prefix`; `listen_addr`
127.0.0.1 and `listen_port`, counted up from 5053 in section order when not set) is shown as the
DNS over HTTPS upstream behind it (`transport` https, `tls_name` the host of the URL); stubby's
`listen_address` (`127.0.0.1@5453`) with the `tls_auth_name` of its first `resolver` section as DNS
over TLS. The port numbering and the old option names are guesses (#21). Domain-specific
`server=/domain/addr` lines are forwarders with `domain`. Typed settings (#182): `rebind_protection`
(`rebind_protection`, on by default), `rebind_allowed_domains` (`rebind_domain`), `cache_size`
(`cachesize`, 150 by default), `local_domain` (`domain`), `recursive` false. 23.05, 24.10 and 25.12
use the same UCI options (guess for 23.05, #21).

## IPv6 router advertisements and DHCPv6 (#151)

Read with `dhcp` from the `dhcp` UCI config (odhcpd), one `RouterAdvert` and one `Dhcp6Server`
per `config dhcp` section of a network Signalbox knows (the `wan` section is skipped):

| UCI option | Meaning |
|---|---|
| `ra` | `server` or `hybrid`: router advertisements are sent (`RaMode`), anything else (also unset): `off` |
| `ra_flags` (list) | `managed-config` is the M flag, `other-config` the O flag (OpenWrt 21.02 and later: 23.05, 24.10, 25.12) |
| `ra_management` | before `ra_flags` (18.06, 19.07): `0` O only, `1` M and O, `2` M only *(guess: the mapping of the old values)* |
| neither of the two | O only (odhcpd's default) |
| `ra_slaac` | `0` clears the A flag of the interface's prefixes (reported as `RaPrefix(autonomous=False)`), else the prefix list stays empty (odhcpd announces the interface's prefixes) |
| `ra_lifetime` | router lifetime, default 1800 s |
| `dns` (list, IPv6 only) | RDNSS of the advertisements and DNS of DHCPv6. A resolver odhcpd adds on its own (its own address) is not read |
| `domain` (list) | DNSSL and DHCPv6 search list |
| `dhcpv6` | `server` or `hybrid`: a `Dhcp6Server` (stateful when the M flag is set, else stateless); `relay` and `disabled`: none. odhcpd has no address range option, so `pools` stay empty |
| `leasetime` | lease time |

Leases: `ubus call dhcp ipv6leases` (odhcpd; `device` -> name -> `leases` with `duid`, `hostname`,
`ipv6-addr` `address` / `valid-lifetime`; the MAC address of a DUID-LL or DUID-LLT is taken from
it), in the read-only ACL as `"dhcp": ["ipv6leases"]` (an older ACL is refused: the DHCPv6 leases
of `luci-rpc getDHCPLeases` are used instead). Not tested against a real device (#21).

### Configuration state (#181)

`ubus uci changes` is read with the system read: when it lists staged (uncommitted) UCI changes,
`config_state.pending` is true (`config.pending`). rpcd keeps staged changes per login session,
so this sees the changes in Signalbox's own session (for example ones a rolled-back apply put
back) and not changes staged in a LuCI or SSH session; an empty answer is reported as unknown,
never as "nothing is pending". The read ACL needs `uci: ["changes"]` (added to the ACL above; an
older ACL leaves the field empty). *(Guess: the cross-session behaviour is from the rpcd
sources, #21.)*

## Mesh and wireless uplinks (#171)

`wifi-iface` sections of mode `mesh` (802.11s) become a `Wlan` with `backhaul` set (the mesh id is
its SSID; SSID rules skip it). For interfaces of mode `mesh` and `sta` that are up,
`iwinfo assoclist` (rpcd-mod-iwinfo) gives the peers: a `MeshPeer` with the MAC address, signal and
the rates (kbit/s in the answer). A `sta` interface is a client bridge, with `wds '1'` a WDS client;
its peer is the access point (role `uplink`), an 802.11s peer has no direction. Core finds the
device behind the MAC address (a port, or the BSSID of an SSID) and draws the link. A device with
such peers has `Device.mesh` (role `repeater` for a station uplink, `agent` for a mesh point).
Without `rpcd-mod-iwinfo` nothing is reported. *Guess (#21): the MAC of a `sta` peer is the BSSID
the access point reports as its `Wlan.bssid`.*

**WDS, access point side (#475).** On an access point interface with `wds '1'`, the stations
that hostapd marks `wds` in `hostapd.<ifname> get_clients` (the 4-address stations) are `MeshPeer`s
of role `downlink` and kind WDS, with signal and rates from `iwinfo assoclist`; ordinary clients of
the interface stay clients. The device gets `Device.mesh` role `agent` (`repeater` if it also has a
`sta` uplink). Both ubus calls are in the read ACL already: no change to the ACL. *Guess (#21):
the field name `wds` of `get_clients` (from hostapd's ubus code); without it nothing is reported.*
The stock `easymesh` package of OpenWrt is 802.11s plus batman-adv and is covered by the mesh
point above.

**EasyMesh / prplMesh: not supported.** prplMesh is part of prplOS, not of stock OpenWrt, and its
data model (BBF `Device.WiFi.DataElements`) is reached through the Ambiorix bus with object names
that are not documented for OpenWrt releases. Nothing is read until a stable, documented ubus or
UCI interface exists (#475).

## Multicast: bridge snooping, `igmpproxy`, Avahi reflector *(optional parts)* (interfaces, #161)

- **Snooping and querier** per bridge (and per VLAN of a filtering bridge): the kernel's running
  values through `file read` of `/sys/class/net/<bridge>/bridge/multicast_snooping`,
  `multicast_querier`, `multicast_igmp_version`, `multicast_mld_version` and, per member,
  `/sys/class/net/<port>/brport/multicast_fast_leave` and `multicast_flood` (both inside the ACL
  entries the spanning tree already needs). Where a file cannot be read, the UCI `device` section
  of the bridge (`igmp_snooping`, `multicast_querier`, `igmp_version`) is used; netifd's defaults
  are not assumed, so an option that is not set stays unknown.
- **IGMP proxy**: `uci get igmpproxy`, one `phyint` section per interface with `network` and
  `direction` (`upstream`, `downstream`, `disabled`); package `igmpproxy` (optional).
- **mDNS reflector**: `[reflector] enable-reflector=yes` and `[server] allow-interfaces` of
  `/etc/avahi/avahi-daemon.conf` through `file read`; package `avahi-dbus-daemon` or similar
  (optional, no file: nothing to report). `umdns` answers for the router and does not reflect.
- ACL additions: UCI config `igmpproxy` and the file `/etc/avahi/avahi-daemon.conf`; an older ACL
  keeps the rest and reports an optional gap naming them.

*(Guess, #21: the option names of the UCI sections and the Avahi paths are from the package
documentation, not yet seen on a device.)* Covered: OpenWrt 23.05, 24.10 and 25.12.

## UPnP, NAT-PMP and mappings of `miniupnpd` *(optional part)* (interfaces, #176)

- **Settings**: `uci get upnpd` (package `miniupnpd`): the section `upnpd` has `enabled`,
  `enable_upnp` and `enable_natpmp` (both on when unset), `secure_mode` (on when unset),
  `internal_iface` (the networks it listens on; `lan` when unset); each `perm_rule` section
  (`action`, `ext_ports`, `int_addr`, `int_ports`) is one permission rule. The service object
  `upnp` and `Device.upnp` come from this. No `upnpd` config: nothing is reported.
- **Mappings**: the lease file `/var/run/miniupnpd.leases` through `file read`, one line per
  mapping `PROTO:external port:internal address:internal port:expiry:description` (expiry is a
  Unix time, `0` never ends; expired lines are left out). Mappings of NAT-PMP and PCP are told by
  the description miniupnpd gives them.
- ACL additions: UCI config `upnpd` and the file `/var/run/miniupnpd.leases`; an older ACL keeps
  the rest and reports an optional gap naming them (mappings then count as not complete).

*(Guess, #21: the option names and the lease file format are from the package documentation, not
yet seen on a device; the `luci.upnp` ubus object is not used because its fields are not
documented.)* Covered: OpenWrt 23.05, 24.10 and 25.12 (miniupnpd 2.3; the file format is the same
in 2.1 and later).
## Access control: MAC filter, RADIUS, dynamic VLAN (wifi, #162)

- Read from the `wifi-iface` sections of `/etc/config/wireless` (no extra permission): `macfilter`
  (`allow`, `deny`) with the *number* of `maclist` entries, and for WPA-Enterprise networks
  `auth_server`, `auth_port`, `acct_server`, `acct_port` and `dynamic_vlan`. The RADIUS servers
  are also listed per device. The shared secrets (`auth_secret`, `acct_secret`) are only tested
  for presence; the MAC addresses are never kept. Same option names on OpenWrt 21.02, 22.03,
  23.05 and later. Wired 802.1X (hostapd `wired` driver) is not read.
