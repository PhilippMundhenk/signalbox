# OpenWrt adapter

Reads an OpenWrt device (21.02 or later; DSA bridge VLANs or plain bridges) over ubus JSON-RPC,
the API that LuCI uses: `rpcd` behind `uhttpd` at `https://<device>/ubus`. Read only; nothing on
the device is changed.

| | |
| --- | --- |
| Adapter id | `openwrt` |
| Roles | `ap`, `switch`, `gateway` |
| Capabilities | interfaces, wireless, DHCP, clients, neighbours (LLDP) |
| Simulator | `signalbox.sim.openwrt` (`uvicorn --factory signalbox.sim.openwrt:create_app`) |

> The answer shapes below follow the OpenWrt documentation and source (netifd, rpcd, hostapd,
> uhttpd-mod-ubus). They are implemented by the simulator but still need to be confirmed on a
> real device (#21). Shapes marked *(guess)* are the least certain.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `url` | | ubus endpoint, for example `https://192.0.2.2/ubus` |
| `username` | `signalbox` | rpcd login (see below) |
| `password` | | its password; stored encrypted, never sent back to the UI |
| `allow_insecure_http` | `false` | accept an `http://` URL; the password then crosses the network in clear text |

## Certificate pinning

OpenWrt ships a self-signed certificate (`px5g`/`uhttpd`), so there is no CA to check. Before
every login Signalbox opens one TLS connection, reads the certificate and compares its SHA-256
fingerprint with the pinned one; if nothing is pinned yet, or the fingerprint differs, the device
is reported as `untrusted-certificate` with the fingerprint to confirm, and the password is not
sent. Every answer is checked against the pin again. Colons and case in a pinned fingerprint
are ignored.

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
| `result [6]` / error `-32002` "Access denied" | not allowed by the ACL, or session expired | logs in once more, then "access denied for `object.method`: add it to the rpcd ACL" |
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

`model` becomes the device model, `release.version` the current firmware. `system info` (uptime,
memory) is allowed by the ACL for later use but not read yet.

### `network.device status` (ports)

```json
{"lan1": {"type": "Network device", "up": true, "carrier": true, "macaddr": "02:…",
          "speed": "1000F", "mtu": 1500},
 "br-lan": {"type": "bridge", "up": true, "bridge-members": ["lan1", …]},
 "br-lan.1": {"type": "VLAN", …}, "lo": {…}, "phy0-ap0": {…}}
```

Every device except `lo` and VLAN devices (`name.vid`) becomes a port; `carrier` is the link
state, `speed` `"<Mbit/s><F|H>"` speed and duplex (`-1F`: no link). `type: bridge` is a bridge
port, `phy*`/`wlan*` (or `"wireless": true`) a wireless one.

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
  (netifd's rule; *to confirm*).
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

- Radio: `band` `2g`/`5g`/`6g` (before 21.02: `hwmode` `11g`/`11a`, else from the channel),
  width from the digits of `htmode` (`NOHT` = 20), `txpower` dBm, `country`. Enabled when not
  `disabled` and `up` in `network.wireless status`. 60 GHz radios are skipped.
- WLAN: only `mode ap`. `encryption` (cipher suffix `+ccmp` ignored): `none` open, `owe`,
  `psk2`/`psk-mixed` WPA2, `psk` other (WPA1), `sae` WPA3, `sae-mixed` WPA2/WPA3, `wpa`/`wpa2`
  WPA2-Enterprise, `wpa3*` WPA3-Enterprise. `ieee80211w` `0`/`1`/`2` is PMF disabled/optional/
  required; unset means hostapd's default (required for `sae`, `owe`, `wpa3`; optional for
  `sae-mixed`; otherwise unknown). `ieee80211r`, `ieee80211k`, `bss_transition` (or `ieee80211v`)
  are the roaming flags, `hidden` the hidden SSID. The segment is that of the first `network`.
- The `key` is read (rpcd cannot hide single options) but only
  `passphrase_fingerprint(ssid, key)` is kept, and only for personal (PSK/SAE) networks.

### `uci get {"config": "dhcp"}` (dnsmasq)

```json
{"values": {
  "lan": {".type": "dhcp", "interface": "lan", "start": "100", "limit": "150",
          "leasetime": "12h", "ignore": "1"},
  "cfg06fe63": {".type": "host", "name": "printer", "mac": "02:00:00:00:10:01", "ip": "192.0.2.50"}}}
```

One DHCP server per `dhcp` section whose interface maps to a segment and has an IPv4 address.
`ignore 1` is disabled (typical for an access point behind a gateway). The pool is
`<network> + start` for `limit` addresses (defaults 100 and 150), the lease time `12h`/`30m`/
`3600`/`infinite`, router and DNS from `dhcp_option` `3,…` and `6,…` (else the interface address).
`host` sections inside the subnet are reservations. odhcpd (DHCPv6, RA) is not modelled yet.

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
{"data": "1700043000 02:00:00:00:20:03 192.0.2.103 laptop 01:02:…\n"}
```

Leases add addresses and host names to the stations (and add wired clients of a DHCP server).
Both are optional: if neither is installed or allowed, clients have no addresses.

### `lldpd show_neighbours` (LLDP) *(guess)*

OpenWrt's `lldpd` package has no standard ubus object; this call expects one that returns
`lldpcli -f json0 show neighbors`:

```json
{"lldp": [{"interface": [{"name": "lan1", "via": "LLDP",
   "chassis": [{"id": [{"type": "mac", "value": "02:00:00:00:30:01"}],
                "name": [{"value": "switch"}], "mgmt-ip": [{"value": "192.0.2.3"}]}],
   "port": [{"id": [{"type": "ifname", "value": "port 8"}]}]}]}]}
```

Without the object the neighbours read fails with "lldpd not installed", which shows as an
incomplete device; the other capabilities are unaffected.

## Read-only user on the device

Packages: `rpcd`, `uhttpd`, `uhttpd-mod-ubus` (all part of a LuCI install); `rpcd-mod-file` for
the lease file and `rpcd-mod-luci` for `luci-rpc` are optional.

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
        "luci-rpc": ["getDHCPLeases"],
        "file": ["read"],
        "lldpd": ["show_neighbours"]
      },
      "uci": ["network", "wireless", "dhcp"],
      "file": {"/tmp/dhcp.leases": ["read"]}
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
