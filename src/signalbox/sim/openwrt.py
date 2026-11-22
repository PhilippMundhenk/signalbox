"""Simulated OpenWrt access point speaking ubus JSON-RPC at ``POST /ubus``.

Neutral sample data: an access point with DSA ports ``lan1``..``lan4`` on bridge ``br-lan``,
VLAN 1 ("lan", untagged on lan1-3) and VLAN 20 ("iot", tagged on lan1), two radios, the SSIDs
"Example" (WPA2/WPA3, 802.11r) and "Example-IoT" (WPA2, VLAN 20, client isolation), three
stations and DHCP switched off (the gateway serves it). With ``router`` set it serves DHCP and
has the uplink ``wan`` (DHCP on ``eth0``, 203.0.113.45/24) and ``wan6`` (DHCPv6 with the
delegated prefix 2001:db8:1::/56). Failure switches on
:class:`OpenWrtSim` change the answers for refused-path tests. Answer shapes follow the OpenWrt
documentation and source; see ``docs/adapters/openwrt.md``.

The UCI configs are state: rpcd's ``uci`` object is simulated with per-session staging
(``set``, ``add``, ``delete``, ``order``, ``revert``), ``apply`` with an optional rollback timer
(the committed configs go back unless ``confirm`` comes in time; the clock is injectable),
``confirm`` and ``rollback``. The running state (``network.device status``,
``network.interface dump``, ``network.wireless status``, ``hostapd.*``) is derived from the
committed configs, so an applied change shows in every read.

Serve it with any ASGI server, for example
``uvicorn --factory signalbox.sim.openwrt:create_app``.
"""

from __future__ import annotations

import asyncio
import copy
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase
from ipaddress import ip_interface
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

NO_SESSION = "0" * 32
MAC = "02:00:00:00:{:02x}:{:02x}"
#: Devices with a DHCP reservation keep their real (universally administered) MAC: the
#: documentation range of RFC 7042, so that `clients.random-mac` stays quiet for them.
FIXED_MAC = "00:00:5e:00:53:{:02x}"
#: UCI configs the simulator knows (and can write)
CONFIGS = ("network", "wireless", "dhcp")
#: UCI configs it only reads (time zone and NTP, #179; SSH and web UI, #173)
READ_ONLY = ("system", "dropbear", "uhttpd")
#: file paths the read ACL of docs/adapters/openwrt.md allows (``*``: any characters)
FILES = (
    "/tmp/dhcp.leases",
    "/sys/class/thermal/thermal_zone*/temp",
    "/sys/class/thermal/thermal_zone*/type",
)

Sections = dict[str, dict[str, Any]]
"""One UCI config: section name -> {".type", ".anonymous", options}, in order."""
Staged = dict[str, list[tuple[str, dict[str, Any]]]]
"""Staged operations of one session: config -> [(method, args)]."""


def _mac(a: int, b: int) -> str:
    return MAC.format(a, b)


def _fixed(n: int) -> str:
    return FIXED_MAC.format(n)


def _uci(*sections: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
    """``uci get`` answer from (type, name, options); names starting with ``cfg`` are anonymous."""
    return _get(
        {
            name: {".anonymous": name.startswith("cfg"), ".type": kind, **options}
            for kind, name, options in sections
        }
    )


def _get(sections: Sections) -> dict[str, Any]:
    """``uci get`` answer of one config."""
    return {
        "values": {
            name: {**s, ".name": name, ".index": i} for i, (name, s) in enumerate(sections.items())
        }
    }


def _sections(answer: dict[str, Any]) -> Sections:
    return {
        name: {k: v for k, v in s.items() if k not in (".name", ".index")}
        for name, s in answer["values"].items()
    }


def _of(config: Sections, kind: str) -> list[tuple[str, dict[str, Any]]]:
    return [(n, s) for n, s in config.items() if s.get(".type") == kind]


def _words(value: Any) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else str(value or "").split()


def _on(value: Any) -> bool:
    return str(value) in ("1", "true", "yes", "on")


def network_config(router: bool = False) -> dict[str, Any]:
    upstream = {} if router else {"gateway": "192.0.2.1", "dns": "192.0.2.1"}
    return _uci(
        (
            "interface",
            "loopback",
            {"device": "lo", "proto": "static", "ipaddr": "127.0.0.1", "netmask": "255.0.0.0"},
        ),
        ("globals", "globals", {"ula_prefix": "fd00:db8::/48"}),
        (
            "device",
            "cfg030f15",
            {"name": "br-lan", "type": "bridge", "ports": ["lan1", "lan2", "lan3", "lan4"]},
        ),
        (
            "bridge-vlan",
            "cfg040f15",
            {"device": "br-lan", "vlan": "1", "ports": ["lan1:u*", "lan2:u*", "lan3"]},
        ),
        ("bridge-vlan", "cfg050f15", {"device": "br-lan", "vlan": "20", "ports": ["lan1:t"]}),
        ("device", "cfg060f15", {"name": "lan4", "enabled": "0"}),
        (
            "interface",
            "lan",
            {
                "device": "br-lan.1",
                "proto": "static",
                "ipaddr": "192.0.2.2/24",
                "ip6addr": "2001:db8::2/64",
                **upstream,
            },
        ),
        ("interface", "iot", {"device": "br-lan.20", "proto": "none"}),
        *(
            (
                ("interface", "wan", {"device": "eth0", "proto": "dhcp"}),
                ("interface", "wan6", {"device": "@wan", "proto": "dhcpv6", "reqprefix": "auto"}),
            )
            if router
            else ()
        ),
    )


#: What the provider hands out to a DHCP / DHCPv6 interface of the router, as netifd reports
#: it in ``network.interface dump`` (documentation addresses).
DHCP_LEASES: dict[str, dict[str, Any]] = {
    "wan": {
        "uptime": 5400,
        "ipv4-address": [{"address": "203.0.113.45", "mask": 24}],
        "route": [
            {"target": "0.0.0.0", "mask": 0, "nexthop": "203.0.113.1", "source": "203.0.113.45/32"}
        ],
        "dns-server": ["203.0.113.53", "203.0.113.54"],
    },
    "wan6": {
        "uptime": 5390,
        "ipv6-address": [
            {"address": "2001:db8:ffff::45", "mask": 64, "preferred": 3500, "valid": 7100}
        ],
        "ipv6-prefix": [
            {
                "address": "2001:db8:1::",
                "mask": 56,
                "preferred": 3500,
                "valid": 7100,
                "class": "wan6",
                "assigned": {"lan": {"address": "2001:db8:1::", "mask": 64}},
            }
        ],
        "route": [
            {"target": "::", "mask": 0, "nexthop": "fe80::1", "source": "2001:db8:ffff::45/64"}
        ],
        "dns-server": ["2001:db8:ffff::53"],
    },
}


def interface_dump(network: Sections) -> dict[str, Any]:
    """Every UCI interface up, with its static addresses; a ``gateway`` is a default route."""
    entries = []
    for name, s in _of(network, "interface"):
        dev = s.get("device") or s.get("ifname")
        v4, v6 = [], []
        for text in _words(s.get("ipaddr")):
            addr = ip_interface(text if "/" in text else f"{text}/{s.get('netmask', '32')}")
            v4.append({"address": str(addr.ip), "mask": addr.network.prefixlen})
        for text in _words(s.get("ip6addr")):
            addr = ip_interface(text)
            v6.append({"address": str(addr.ip), "mask": addr.network.prefixlen})
        gateway = s.get("gateway")
        entry: dict[str, Any] = {
            "interface": name,
            "up": True,
            "proto": s.get("proto", "none"),
            "device": dev,
            "l3_device": dev,
            "ipv4-address": v4,
            "ipv6-address": v6,
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": gateway, "source": "0.0.0.0/0"}]
            if gateway
            else [],
        }
        if s.get("dns"):
            entry["dns-server"] = _words(s["dns"])
        if isinstance(dev, str) and dev.startswith("@"):  # an alias: its parent's device
            parent = next((p for n, p in _of(network, "interface") if n == dev[1:]), {})
            entry["device"] = entry["l3_device"] = parent.get("device")
        if entry["proto"] in ("dhcp", "dhcpv6") and name in DHCP_LEASES:
            entry |= copy.deepcopy(DHCP_LEASES[name])
        entries.append(entry)
    return {"interface": entries}


def running_ifaces(wireless: Sections) -> list[tuple[str, str, str, str]]:
    """(section, radio, ifname, mode) of every wifi-iface that is up: ``phy<n>-<mode><i>``."""
    out = []
    for p, (radio, r) in enumerate(_of(wireless, "wifi-device")):
        if _on(r.get("disabled")):
            continue
        count: dict[str, int] = {}
        for name, s in _of(wireless, "wifi-iface"):
            if s.get("device") != radio or _on(s.get("disabled")):
                continue
            mode = str(s.get("mode", "ap"))
            i = count.get(mode, 0)
            count[mode] = i + 1
            out.append((name, radio, f"phy{p}-{mode}{i}", mode))
    return out


#: What netifd lists for a gigabit copper port (``link-supported``, ``link-advertising``).
GIGABIT = ["10baseT-H", "10baseT-F", "100baseT-H", "100baseT-F", "1000baseT-F"]


def device_status(network: Sections, wireless: Sections) -> dict[str, Any]:
    def eth(carrier: bool) -> dict[str, Any]:
        return {
            "external": False,
            "present": True,
            "type": "Network device",
            "up": True,
            "carrier": carrier,
            "mtu": 1500,
            "macaddr": _mac(0, 1),
            "speed": "1000F" if carrier else "-1F",
            "autoneg": True,
            "link-supported": GIGABIT,
            "link-advertising": GIGABIT,
        }

    status: dict[str, Any] = {f"lan{n}": eth(n < 4) for n in range(1, 5)}
    status["eth0"] = eth(True) | {
        "speed": "2500F",
        "link-supported": [*GIGABIT, "2500baseT-F"],
        "link-advertising": [*GIGABIT, "2500baseT-F"],
    }
    for _, s in _of(network, "device"):
        if s.get("name") in status and str(s.get("enabled", "1")) == "0":
            status[str(s["name"])] |= {"up": False, "carrier": False, "speed": "-1F"}
    wifi = [ifname for _, _, ifname, _ in running_ifaces(wireless)]
    for _, s in _of(network, "device"):
        if s.get("type") == "bridge" and s.get("name"):
            status[str(s["name"])] = {
                "type": "bridge",
                "up": True,
                "carrier": True,
                "macaddr": _mac(0, 1),
                "mtu": 1500,
                "bridge-members": [*_words(s.get("ports")), *wifi],
            }
    for _, s in _of(network, "bridge-vlan"):
        vlan = {"type": "VLAN", "up": True, "carrier": True, "macaddr": _mac(0, 1)}
        status[f"{s.get('device')}.{s.get('vlan')}"] = vlan
    status["lo"] = {"type": "Network device", "up": True, "carrier": True}
    for i, name in enumerate(wifi):
        status[name] = {
            "type": "Network device",
            "up": True,
            "carrier": True,
            "macaddr": _mac(1, i),
        }
    return status


def wireless_config() -> dict[str, Any]:
    common = {"mode": "ap", "ieee80211k": "1", "bss_transition": "1"}
    return _uci(
        (
            "wifi-device",
            "radio0",
            {
                "type": "mac80211",
                "path": "platform/soc/18000000.wifi",
                "band": "2g",
                "channel": "6",
                "htmode": "HE20",
                "txpower": "20",
                "country": "DE",
                "cell_density": "0",
            },
        ),
        (
            "wifi-device",
            "radio1",
            {
                "type": "mac80211",
                "path": "platform/soc/18000000.wifi+1",
                "band": "5g",
                "channel": "36",
                "htmode": "HE80",
                "txpower": "23",
                "country": "DE",
            },
        ),
        (
            "wifi-iface",
            "default_radio0",
            {
                **common,
                "device": "radio0",
                "network": "lan",
                "ssid": "Example",
                "encryption": "sae-mixed",
                "key": "example-passphrase",
                "ieee80211r": "1",
            },
        ),
        (
            "wifi-iface",
            "default_radio1",
            {
                **common,
                "device": "radio1",
                "network": "lan",
                "ssid": "Example",
                "encryption": "sae-mixed",
                "key": "example-passphrase",
                "ieee80211r": "1",
                "ieee80211w": "1",
            },
        ),
        (
            "wifi-iface",
            "iot_radio0",
            {
                "device": "radio0",
                "mode": "ap",
                "network": "iot",
                "ssid": "Example-IoT",
                "encryption": "psk2+ccmp",
                "key": "example-iot-passphrase",
                "hidden": "1",
                "isolate": "1",
            },
        ),
        (
            "wifi-iface",
            "uplink",
            {
                "device": "radio1",
                "mode": "sta",
                "network": "wwan",
                "ssid": "Upstream",
                "encryption": "psk2",
                "key": "upstream-passphrase",
                "disabled": "1",
            },
        ),
    )


#: wifi-iface section -> associated stations
STATIONS = {
    "default_radio0": [_mac(0x20, 1)],
    "iot_radio0": [_mac(0x20, 2)],
    "default_radio1": [_mac(0x20, 3)],
}


def wireless_status(wireless: Sections) -> dict[str, Any]:
    running = running_ifaces(wireless)
    return {
        radio: {
            "up": not _on(r.get("disabled")),
            "pending": False,
            "autostart": True,
            "disabled": _on(r.get("disabled")),
            "retry_setup_failed": False,
            "config": {},
            "interfaces": [
                {"section": s, "ifname": ifname, "config": {}}
                for s, on, ifname, _ in running
                if on == radio
            ],
        }
        for radio, r in _of(wireless, "wifi-device")
    }


def dhcp_config(router: bool) -> dict[str, Any]:
    return _uci(
        ("dnsmasq", "cfg01411c", {"domainneeded": "1", "localise_queries": "1"}),
        (
            "dhcp",
            "lan",
            {
                "interface": "lan",
                "start": "100",
                "limit": "150",
                "leasetime": "12h",
                **(
                    {"dhcp_option": ["6,192.0.2.1,192.0.2.53", "42,192.0.2.1"]}
                    if router
                    else {"ignore": "1"}
                ),
            },
        ),
        ("dhcp", "wan", {"interface": "wan", "ignore": "1"}),
        ("host", "cfg06fe63", {"name": "printer", "mac": _fixed(1), "ip": "192.0.2.50"}),
        ("host", "cfg07fe63", {"name": "faraway", "mac": _fixed(2), "ip": "203.0.113.9"}),
    )


def dropbear_config() -> dict[str, Any]:
    """``/etc/config/dropbear`` as OpenWrt ships it (one instance, SSH in the LAN)."""
    return _uci(
        (
            "dropbear",
            "cfg029944",
            {
                "PasswordAuth": "on",
                "RootPasswordAuth": "on",
                "Port": "22",
                "Interface": "lan",
            },
        )
    )


def uhttpd_config() -> dict[str, Any]:
    """``/etc/config/uhttpd`` as OpenWrt ships it (LuCI on 80 and 443, redirect off)."""
    return _uci(
        (
            "uhttpd",
            "main",
            {
                "listen_http": ["0.0.0.0:80", "[::]:80"],
                "listen_https": ["0.0.0.0:443", "[::]:443"],
                "redirect_https": "0",
                "home": "/www",
                "rfc1918_filter": "1",
                "max_requests": "3",
                "cert": "/etc/uhttpd.crt",
                "key": "/etc/uhttpd.key",
                "cgi_prefix": "/cgi-bin",
                "script_timeout": "60",
                "network_timeout": "30",
                "http_keepalive": "20",
                "tcp_keepalive": "1",
            },
        ),
        ("cert", "defaults", {"days": "730", "key_type": "ec", "country": "ZZ"}),
    )


def system_config(router: bool) -> dict[str, Any]:
    """``/etc/config/system`` as OpenWrt writes it for Europe/Berlin (LuCI's zone table)."""
    ntp: dict[str, Any] = {"enabled": "1", "enable_server": "0", "server": ["192.0.2.1"]}
    if router:
        servers = [f"{n}.openwrt.pool.ntp.org" for n in range(4)]
        ntp = {"enabled": "1", "enable_server": "1", "interface": "lan", "server": servers}
    return _uci(
        (
            "system",
            "cfg01e48a",
            {
                "hostname": "ap",
                "timezone": "CET-1CEST,M3.5.0,M10.5.0/3",
                "zonename": "Europe/Berlin",
                "ttylogin": "0",
                "log_size": "128",
                "urandom_seed": "0",
            },
        ),
        ("timeserver", "ntp", ntp),
    )


def system_info(now: float, zone: str, uptime: int = 273906) -> dict[str, Any]:
    """``system info`` of a 512 MiB filogic AP: memory in bytes, root and tmp in KiB, load
    times 65536, ``localtime`` the wall clock of ``zone`` in seconds since the epoch."""
    try:
        offset = datetime.fromtimestamp(now, ZoneInfo(zone)).utcoffset()
    except (ZoneInfoNotFoundError, ValueError):
        offset = None
    local = int(now + (offset.total_seconds() if offset else 0))
    return {
        "localtime": local,
        "uptime": uptime,
        "load": [6912, 4352, 2880],
        "memory": {
            "total": 515878912,
            "free": 382853120,
            "shared": 1069056,
            "buffered": 0,
            "available": 371363840,
            "cached": 38051840,
        },
        "root": {"total": 104320, "free": 100736, "used": 3584, "avail": 96512},
        "tmp": {"total": 251892, "free": 251488, "used": 404, "avail": 251488},
        "swap": {"total": 0, "free": 0},
    }


def clients(ifname: str, section: str) -> dict[str, Any]:
    return {
        "freq": 2437 if ifname.startswith("phy0") else 5180,
        "clients": {
            mac: {"auth": True, "assoc": True, "authorized": True, "signal": -55, "aid": 1}
            for mac in STATIONS.get(section, [])
        },
    }


LEASE = (_mac(0x20, 3), "192.0.2.103", "laptop")


def board() -> dict[str, Any]:
    return {
        "kernel": "5.15.167",
        "hostname": "ap",
        "system": "ARMv8 Processor rev 4",
        "model": "Example AP",
        "board_name": "example,ap",
        "rootfs_type": "squashfs",
        "release": {
            "distribution": "OpenWrt",
            "version": "23.05.5",
            "revision": "r24106-10cc5fcd00",
            "target": "mediatek/filogic",
            "description": "OpenWrt 23.05.5 r24106-10cc5fcd00",
        },
    }


def lldp_status() -> dict[str, Any]:
    """``luci.lldpd getStatus`` (luci-app-lldpd): ``lldpcli -f json0 show ...`` of each part."""
    return {
        "statistics": {"lldp": [{"interface": []}]},
        "neighbors": lldp_neighbours(),
        "interfaces": {"lldp": [{"interface": []}]},
        "chassis": {"local-chassis": [{"chassis": [{"name": [{"value": "ap"}]}]}]},
    }


def lldp_neighbours() -> dict[str, Any]:
    """lldpcli ``-f json0 show neighbors details`` shape."""
    return {
        "lldp": [
            {
                "interface": [
                    {
                        "name": "lan1",
                        "via": "LLDP",
                        "chassis": [
                            {
                                "id": [{"type": "mac", "value": _mac(0x30, 1)}],
                                "name": [{"value": "switch"}],
                                "mgmt-ip": [{"value": "192.0.2.3"}],
                            }
                        ],
                        "port": [{"id": [{"type": "ifname", "value": "port 8"}]}],
                    },
                    {"name": "lan2", "chassis": [{"name": [{"value": "no id"}]}]},
                ]
            }
        ]
    }


# --- rpcd's uci object ------------------------------------------------------------------------

# ubus status codes
OK, INVALID_ARGUMENT, NOT_FOUND, NO_DATA, DENIED = 0, 2, 4, 5, 6


def _uci_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_uci_value(v) for v in value]
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def uci_op(config: Sections, method: str, args: dict[str, Any], counter: int) -> list[Any]:
    """Run one staged ``uci`` operation on a config (in place); the ubus result (rpcd uci.c)."""
    section = args.get("section")
    if method == "add":
        kind = args.get("type")
        if not isinstance(kind, str) or not kind:
            return [INVALID_ARGUMENT]
        name = args.get("name") or f"cfg{counter:06x}"
        if name in config:  # rpcd: uci_set on the name; an existing section only changes type
            config[name][".type"] = kind
        else:
            config[name] = {".anonymous": not args.get("name"), ".type": kind}
        config[name].update({k: _uci_value(v) for k, v in (args.get("values") or {}).items()})
        return [OK, {"section": name}]
    if method == "order":
        names = list(args.get("sections") or [])
        if any(n not in config for n in names):
            return [NOT_FOUND]  # rpcd saves nothing then
        rest = [n for n in config if n not in names]
        moved = {n: config[n] for n in [*names, *rest]}
        config.clear()
        config.update(moved)
        return [OK]
    if not isinstance(section, str) or section not in config:
        return [NOT_FOUND]
    if method == "set":
        values = args.get("values")
        if not isinstance(values, dict):
            return [INVALID_ARGUMENT]
        config[section].update({k: _uci_value(v) for k, v in values.items()})
        return [OK]
    # delete: rpcd answers "not found" if none of the named options exists
    if "options" in args:
        present = [o for o in args["options"] or [] if o in config[section]]
    elif "option" in args:
        present = [args["option"]] if args["option"] in config[section] else []
    else:
        del config[section]
        return [OK]
    for option in present:
        del config[section][option]
    return [OK] if present else [NOT_FOUND]


def uci_delta(method: str, args: dict[str, Any]) -> list[list[Any]]:
    """A staged operation as rpcd's ``uci changes`` lists it (``uci_delta`` entries)."""
    section = str(args.get("section") or args.get("name") or "")
    out: list[list[Any]] = []
    if method == "add":
        out.append(["add", section, str(args.get("type"))])
    if method in ("add", "set"):
        for option, value in (args.get("values") or {}).items():
            if isinstance(value, list):
                out.append(["remove", section, option])
                out += [["list-add", section, option, _uci_value(v)] for v in value]
            else:
                out.append(["set", section, option, _uci_value(value)])
    if method == "delete":
        options = args.get("options") or ([args["option"]] if args.get("option") else [])
        out += [["remove", section, o] for o in options] or [["remove", section]]
    if method == "order":
        out += [["order", n, i] for i, n in enumerate(args.get("sections") or [])]
    return out


@dataclass
class OpenWrtSim:
    """State and failure switches of the simulator; mutate between requests."""

    username: str = "signalbox"
    password: str = "example-password"
    session_ttl: float = 300.0
    #: ``object``, ``object.method`` or ``uci:<config>`` entries the ACL does not allow
    denied: set[str] = field(default_factory=set)
    #: UCI configs that do not exist (a router without Wi-Fi has no ``wireless``)
    missing: set[str] = field(default_factory=set)
    #: no ``network.wireless`` ubus object (a device without Wi-Fi)
    no_wireless_object: bool = False
    #: UCI configs the ACL lets the user change (``write`` → ``uci`` in the rpcd ACL)
    writable: set[str] = field(default_factory=lambda: set(CONFIGS))
    #: objects answered with broken JSON (``*``: every request)
    malformed: set[str] = field(default_factory=set)
    #: objects answered with valid JSON of the wrong shape
    odd: set[str] = field(default_factory=set)
    #: seconds to wait before answering (``slow`` objects only, or every request if empty)
    delay: float = 0.0
    slow: set[str] = field(default_factory=set)
    #: luci-app-lldpd installed (ubus object ``luci.lldpd``)
    lldpd: bool = True
    luci_rpc: bool = True
    #: OpenWrt 25.12: netifd's ucode wireless object answers "invalid argument" through rpcd
    wireless_ucode: bool = False
    #: DHCP on, no default route on lan: the device acts as the router of 192.0.2.0/24
    router: bool = False
    #: fourth byte of the port MACs (02:00:00:<base>:..), so several simulators differ
    mac_base: int = 0
    #: time source of sessions and the rollback timer (replace it to test the timer)
    clock: Callable[[], float] = time.monotonic
    #: seconds the device's wall clock is ahead of the real time (``system info`` localtime)
    clock_skew: float = 0.0
    #: thermal zones (``type``, milli-degrees Celsius) under /sys/class/thermal
    thermal_zones: list[tuple[str, int]] = field(default_factory=lambda: [("cpu-thermal", 47823)])
    sessions: dict[str, float] = field(default_factory=dict)
    logins: int = 0
    requests: int = 0
    #: committed UCI configs (built on first use, so ``router`` can be set after ``reset``)
    configs: dict[str, Sections] | None = None
    #: session -> config -> staged operations (``uci changes``)
    staged: dict[str, dict[str, list[tuple[str, dict[str, Any]]]]] = field(default_factory=dict)
    #: the ``uci apply`` waiting for ``uci confirm``: session, deadline, configs before it,
    #: the staged changes it applied (rpcd puts them back into the session on a rollback)
    pending: tuple[str, float, dict[str, Sections], Staged] | None = None
    #: uci calls that changed something: ("apply" | "confirm" | "rollback" | "revert", ...)
    history: list[str] = field(default_factory=list)
    _added: int = 0

    def reset(self) -> None:
        fresh = OpenWrtSim()
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(fresh, name))

    def expire_sessions(self) -> None:
        """Every session ends (rpcd drops their staged changes too)."""
        self.sessions.clear()
        self.staged.clear()

    @property
    def state(self) -> dict[str, Sections]:
        if self.configs is None:
            self.configs = {
                "network": _sections(network_config(self.router)),
                "wireless": _sections(wireless_config()),
                "dhcp": _sections(dhcp_config(self.router)),
                "system": _sections(system_config(self.router)),
                "dropbear": _sections(dropbear_config()),
                "uhttpd": _sections(uhttpd_config()),
            }
        return self.configs

    def _roll_back(self) -> None:
        """rpcd's rollback: the configs before the apply come back; if the applying session
        still exists, so do its staged changes (LuCI shows them as unsaved again)."""
        assert self.pending is not None
        sid, _, before, staged = self.pending
        self.configs = before
        self.pending = None
        expires = self.sessions.get(sid)
        if expires is not None and expires >= self.clock():
            self.staged[sid] = staged

    def tick(self) -> None:
        """The rollback timer: past the deadline, the configs before the apply come back."""
        if self.pending is not None and self.clock() >= self.pending[1]:
            self._roll_back()
            self.history.append("timeout-rollback")

    def view(self, sid: str, config: str) -> Sections:
        """A config as one session sees it: committed plus its own staged changes."""
        out = copy.deepcopy(self.state[config])
        for method, args in self.staged.get(sid, {}).get(config, []):
            uci_op(out, method, args, 0)
        return out

    # ubus ---------------------------------------------------------------------------

    def _login(self, args: dict[str, Any]) -> list[Any]:
        if args.get("username") != self.username or args.get("password") != self.password:
            return [6]
        self.logins += 1
        sid = secrets.token_hex(16)
        if self.pending is not None and self.sessions.get(self.pending[0], -1) >= self.clock():
            sid = self.pending[0]  # rpcd reclaims the session of a pending apply (same user)
        self.sessions[sid] = self.clock() + self.session_ttl
        ttl = int(self.session_ttl)
        return [
            0,
            {
                "ubus_rpc_session": sid,
                "timeout": ttl,
                "expires": ttl,
                "acls": {},
                "data": {"username": self.username},
            },
        ]

    def _uci(self, sid: str, method: str, args: dict[str, Any]) -> list[Any] | None:
        config = str(args.get("config"))
        if method == "get":
            if f"uci:{config}" in self.denied:
                return [DENIED]
            if config not in CONFIGS + READ_ONLY or config in self.missing:
                return [NOT_FOUND]
            sections = self.view(sid, config)
            if isinstance(args.get("section"), str):
                s = sections.get(args["section"])
                return [OK, {"values": s}] if s is not None else [NOT_FOUND]
            return [OK, _get(sections)]
        if method in ("set", "add", "delete", "order"):
            if config not in CONFIGS:
                return [NOT_FOUND]
            if config not in self.writable or f"uci:{config}" in self.denied:
                return [DENIED]
            self._added += 1
            view = self.view(sid, config)
            result = uci_op(view, method, args, self._added)
            if result[0] == OK:
                if method == "add" and not args.get("name"):  # replay with the same name
                    args = {**args, "name": result[1]["section"]}
                self.staged.setdefault(sid, {}).setdefault(config, []).append((method, args))
            return result
        if method == "revert":
            if self.pending is not None:
                return [DENIED]  # rpcd: no revert while a change waits for its confirmation
            if config not in self.writable or f"uci:{config}" in self.denied:
                return [DENIED]
            self.staged.get(sid, {}).pop(config, None)
            if not self.staged.get(sid, True):
                del self.staged[sid]
            self.history.append(f"revert {config}")
            return [OK]
        if method == "changes":
            staged = self.staged.get(sid, {})
            changes = {c: [d for m, a in ops for d in uci_delta(m, a)] for c, ops in staged.items()}
            return [OK, {"changes": {c: d for c, d in changes.items() if d}}]
        if method == "apply":
            return self._apply(sid, args)
        if method in ("confirm", "rollback"):
            if self.pending is None:
                return [NO_DATA]
            if self.pending[0] != sid:
                return [DENIED]
            if method == "rollback":
                self._roll_back()
            self.pending = None
            self.history.append(method)
            return [OK]
        return None

    def _apply(self, sid: str, args: dict[str, Any]) -> list[Any]:
        if self.pending is not None:
            # rpcd: another apply waits for its confirmation. With rollback that is refused;
            # without, rpcd answers OK and applies nothing (the changes stay staged).
            return [DENIED] if args.get("rollback") else [OK]
        staged = self.staged.pop(sid, {})
        if not staged:
            return [NO_DATA]
        before = copy.deepcopy(self.state)
        for config, ops in staged.items():
            for method, op_args in ops:
                uci_op(self.state[config], method, op_args, 0)
        if args.get("rollback"):
            timeout = float(args.get("timeout", 30))
            self.pending = (sid, self.clock() + timeout, before, staged)
        self.history.append("apply")
        return [OK]

    def _data(self, sid: str, obj: str, method: str, args: dict[str, Any]) -> list[Any] | None:
        """ubus result list, or None when the object does not exist."""
        if obj == "system" and method == "board":
            return [0, board()]
        if obj == "system" and method == "info":
            zone = next((sec for sec in self.state["system"].values()), {})
            name = str(zone.get("zonename") or "UTC")
            return [0, system_info(time.time() + self.clock_skew, name)]
        if obj == "network.device" and method == "status":
            status = device_status(self.state["network"], self.state["wireless"])
            if self.mac_base:  # a second simulated device needs MACs of its own
                base, own = "02:00:00:00:", f"02:00:00:{self.mac_base:02x}:"
                for entry in status.values():
                    mac = entry.get("macaddr")
                    if isinstance(mac, str) and mac.startswith(base):  # not reserved MACs
                        entry["macaddr"] = own + mac[len(base) :]
            return [0, status]
        if obj == "network.interface" and method == "dump":
            return [0, interface_dump(self.state["network"])]
        if obj == "network.wireless" and method == "status":
            if self.no_wireless_object:  # no Wi-Fi hardware/packages (an OpenWrt switch)
                return [NOT_FOUND]
            if self.wireless_ucode:
                return [INVALID_ARGUMENT]
            return [0, wireless_status(self.state["wireless"])]
        if obj == "uci":
            return self._uci(sid, method, args)
        if obj.startswith("hostapd."):
            running = {ifname: s for s, _, ifname, mode in running_ifaces(self.state["wireless"])}
            if obj[8:] in running:
                ifname = obj[8:]
                return [0, clients(ifname, running[ifname])] if method == "get_clients" else [3]
        if obj == "luci-rpc" and self.luci_rpc:
            if method == "getWirelessDevices":  # network.wireless status plus iwinfo
                status = wireless_status(self.state["wireless"])
                for radio in status.values():
                    radio["iwinfo"] = {"hwmodes": ["n"]}
                return [0, status]
            if method != "getDHCPLeases":
                return [3]
            mac, ip, name = LEASE
            lease = {"expires": 43000, "hostname": name, "macaddr": mac, "ipaddr": ip}
            return [0, {"dhcp_leases": [lease, {"macaddr": "bogus"}], "dhcp6_leases": []}]
        if obj == "file" and method == "read":
            path = str(args.get("path"))
            if not any(fnmatchcase(path, allowed) for allowed in FILES):
                return [DENIED]
            if path.startswith("/sys/class/thermal/thermal_zone"):
                n, _, leaf = path.removeprefix("/sys/class/thermal/thermal_zone").partition("/")
                if not n.isdigit() or int(n) >= len(self.thermal_zones):
                    return [NOT_FOUND]
                kind, milli = self.thermal_zones[int(n)]
                return [0, {"data": f"{milli}\n" if leaf == "temp" else f"{kind}\n"}]
            mac, ip, name = LEASE
            text = f"1700043000 {mac} {ip} {name} 01:{mac}\n1700043000 bogus x * *\nshort\n"
            return [0, {"data": text}]
        if obj == "luci.lldpd" and self.lldpd:
            return [0, lldp_status()] if method == "getStatus" else [3]
        return None

    async def handle(self, body: bytes) -> Response:
        self.requests += 1
        try:
            req = json.loads(body)
            rid, params = req.get("id"), req["params"]
            sid, obj, method = params[0], params[1], params[2]
            args = params[3] if len(params) > 3 else {}
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            return self._error(None, -32700, "Parse error")
        if self.delay and (not self.slow or obj in self.slow):
            await asyncio.sleep(self.delay)
        self.tick()
        if "*" in self.malformed or obj in self.malformed:
            return Response('{"jsonrpc": "2.0", "result": [0, {', media_type="application/json")
        if obj in self.odd:
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": "unexpected"})
        if obj == "session" and method == "login" and sid == NO_SESSION:
            return self._result(rid, self._login(args))
        expires = self.sessions.get(sid)
        if expires is None or expires < self.clock():
            self.sessions.pop(sid, None)
            self.staged.pop(sid, None)
            return self._error(rid, -32002, "Access denied")
        if obj in self.denied or f"{obj}.{method}" in self.denied:
            return self._error(rid, -32002, "Access denied")
        result = self._data(sid, obj, method, args)
        if result is None:
            return self._error(rid, -32000, "Object not found")
        return self._result(rid, result)

    @staticmethod
    def _result(rid: Any, result: list[Any]) -> Response:
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result})

    @staticmethod
    def _error(rid: Any, code: int, message: str) -> Response:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
        )


def create_app(sim: OpenWrtSim | None = None) -> FastAPI:
    state = sim or OpenWrtSim()
    app = FastAPI(title="OpenWrt ubus simulator", docs_url=None, redoc_url=None)
    app.state.sim = state

    @app.post("/ubus")
    async def ubus(request: Request) -> Response:
        return await state.handle(await request.body())

    return app
