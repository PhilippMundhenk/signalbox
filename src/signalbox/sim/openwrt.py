"""Simulated OpenWrt access point speaking ubus JSON-RPC at ``POST /ubus``.

Neutral sample data: an access point with DSA ports ``lan1``..``lan4`` (conduit ``eth1``) on
bridge ``br-lan``,
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
import base64
import copy
import hashlib
import json
import secrets
import time
from collections.abc import Callable, Sequence
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
#: UCI configs the simulator knows (and can write; firewall since #295)
CONFIGS = ("network", "wireless", "dhcp", "firewall")
#: UCI configs it only reads (time zone and NTP, #179; SSH and web UI, #173)
#: Read-only until #327: ``system`` and ``snmpd`` are also written (log target, SNMP agent);
#: ``mwan3`` since #463 (gateway groups), ``upnpd`` since #513
WRITE_ALSO = ("system", "snmpd", "mwan3", "upnpd")
READ_ONLY = (
    "system",
    "dropbear",
    "uhttpd",
    "snmpd",
    "luci_statistics",
    "softflowd",
    "rpcd",
    "mwan3",
    "ddns",
    "https-dns-proxy",
    "usteer",
    "dawn",
    "opennds",
    "nodogsplash",
    "igmpproxy",
    "upnpd",
    "openvpn",
    "sqm",
)
#: Of those, the configs of optional packages (#180): only there when installed
PACKAGES = (
    "snmpd",
    "luci_statistics",
    "softflowd",
    "mwan3",
    "ddns",
    "https-dns-proxy",
    "usteer",
    "dawn",
    "opennds",
    "nodogsplash",
    "igmpproxy",
    "upnpd",
    "openvpn",
    "sqm",
)
#: file paths the read ACL of docs/adapters/openwrt.md allows (``*``: any characters)
FILES = (
    "/tmp/dhcp.leases",
    "/sys/class/thermal/thermal_zone*/temp",
    "/sys/class/thermal/thermal_zone*/type",
    "/sys/class/net/*/bonding/*",
    "/sys/class/net/*/bonding_slave/*",
    "/sys/class/net/*/bridge/*",
    "/sys/class/net/*/brport/*",
    "/sys/class/net/*/brforward",
    "/sys/devices/*/net/*/brforward",
    "/sys/devices/*/net/*/bridge/*",
    "/sys/devices/*/net/*/brport/*",
    "/var/run/ddns/*",
    "/etc/avahi/avahi-daemon.conf",
    "/var/run/miniupnpd.leases",
    "/var/run/openvpn.*.status",
    "/etc/swanctl/swanctl.conf",
)

#: miniupnpd's lease file (#176)
UPNP_LEASES = "/var/run/miniupnpd.leases"

#: Avahi's configuration (#161); the file exists when the package ``avahi`` is installed
AVAHI_CONF = "/etc/avahi/avahi-daemon.conf"
AVAHI_TEXT = """[server]
use-ipv4=yes
allow-interfaces=br-lan.1,br-lan.20

[reflector]
enable-reflector=yes
"""

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


def _wg_key(name: str) -> str:
    """A WireGuard key of the sample: base64 of SHA-256 of a name (valid, nobody's real key;
    computed so that no key-shaped literal is in the source)."""
    return base64.b64encode(hashlib.sha256(name.encode()).digest()).decode()


#: The key helper of the write ACL (#152, docs/adapters/openwrt.md).
WG_KEY_HELPER = "/usr/libexec/signalbox-wg-key"


def wg_private_key(interface: str) -> str:
    """The private key the simulated helper generates for an interface Signalbox created: it
    must never leave the integration (``do-not-leak`` in the seed, #152)."""
    return _wg_key(f"sim-wg-private-do-not-leak-{interface}")


def wg_public_key(interface: str) -> str:
    return _wg_key(f"sim-wg-public-{interface}")


#: the router's own tunnel ``wg0``, its site peer (the OPNsense simulator's ``wg0``) and a phone
WG_KEY = _wg_key("sim-site-b")
WG_SITE_A = _wg_key("sim-opnsense-wg0")
WG_PHONE = _wg_key("sim-openwrt-phone")


def wireguard_sections() -> tuple[tuple[str, str, dict[str, Any]], ...]:
    """``wg0`` as ``uci get network`` returns it: with ``private_key`` and ``preshared_key``,
    which the adapter must drop on arrival (the values are derived samples, not secrets)."""
    return (
        (
            "interface",
            "wg0",
            {
                "proto": "wireguard",
                "private_key": _wg_key("sim-secret-private"),
                "listen_port": "51820",
                "addresses": ["2001:db8:ff::2/64"],
                "mtu": "1420",
            },
        ),
        (
            "wireguard_wg0",
            "cfg0a1b2c",
            {
                "public_key": WG_SITE_A,
                "description": "site-a",
                "preshared_key": _wg_key("sim-secret-psk"),
                "endpoint_host": "203.0.113.10",
                "endpoint_port": "51820",
                "allowed_ips": ["2001:db8:ff::1/128", "192.0.2.0/24"],
                "persistent_keepalive": "25",
                "route_allowed_ips": "1",
            },
        ),
        (
            "wireguard_wg0",
            "cfg0b2c3d",
            {
                "public_key": WG_PHONE,
                "description": "phone",
                "allowed_ips": ["2001:db8:ff::3/128"],
            },
        ),
    )


def network_config(
    router: bool = False, wireguard: bool = False, bond: str | None = None
) -> dict[str, Any]:
    upstream = {} if router else {"gateway": "192.0.2.1", "dns": "192.0.2.1"}
    config = _base_network(upstream, router, wireguard)
    if bond is None:
        return config
    # #157: lan2 and lan3 form bond0 (netifd ``device`` of type bonding), a port of br-lan
    values = config["values"]
    for s in values.values():
        if s.get("name") == "br-lan":
            s["ports"] = ["lan1", "bond0", "lan4"]
        elif s.get(".type") == "bridge-vlan" and s.get("vlan") == "1":
            s["ports"] = ["lan1:u*", "bond0:u*"]
    values["cfg070f15"] = {
        ".type": "device",
        ".name": "cfg070f15",
        ".index": len(values),
        ".anonymous": True,
        "name": "bond0",
        "type": "bonding",
        "ports": ["lan2", "lan3"],
        "policy": bond,
        "xmit_hash_policy": "layer2+3",
        "lacp_rate": "fast",
        "min_links": "1",
    }
    return config


#: What the kernel reports in sysfs for bond0 of ``network_config(bond=...)`` (#157):
#: lan2 aggregated with an LACP partner, lan3 waiting (its far end does not answer).
BOND_SYSFS = {
    "bond0/bonding/xmit_hash_policy": "layer2+3 2",
    "bond0/bonding/lacp_rate": "fast 1",
    "bond0/bonding/lacp_active": "on 1",
    "bond0/bonding/min_links": "1",
    "bond0/bonding/slaves": "lan2 lan3",
    "bond0/bonding/ad_aggregator": "1",
    "bond0/bonding/ad_partner_mac": "02:00:00:00:10:01",
    "lan2/bonding_slave/state": "active",
    "lan2/bonding_slave/ad_aggregator_id": "1",
    "lan2/bonding_slave/ad_actor_oper_port_state": "61",
    "lan3/bonding_slave/state": "backup",
    "lan3/bonding_slave/ad_aggregator_id": "2",
    "lan3/bonding_slave/ad_actor_oper_port_state": "69",
}
_KERNEL_MODES = {
    "balance-rr": 0,
    "active-backup": 1,
    "balance-xor": 2,
    "broadcast": 3,
    "802.3ad": 4,
    "balance-tlb": 5,
    "balance-alb": 6,
}


def _base_network(upstream: dict[str, str], router: bool, wireguard: bool) -> dict[str, Any]:
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
            {
                "name": "br-lan",
                "type": "bridge",
                "ports": ["lan1", "lan2", "lan3", "lan4"],
                "igmp_snooping": "1",
            },
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
        # Static routes and policy routing (#149): a lab network behind a second router (in the
        # running table), a disabled one, one in table 100 and a rule that sends a source
        # network to it. Option names as netifd documents them (*guess*, #21).
        (
            "route",
            "lab",
            {
                "interface": "lan",
                "target": "198.18.20.0",
                "netmask": "255.255.255.0",
                "gateway": "192.0.2.254",
            },
        ),
        (
            "route",
            "oldlab",
            {
                "interface": "lan",
                "target": "198.18.30.0/24",
                "gateway": "192.0.2.254",
                "disabled": "1",
            },
        ),
        (
            "route",
            "lab100",
            {
                "interface": "lan",
                "target": "0.0.0.0/0",
                "gateway": "192.0.2.254",
                "table": "100",
            },
        ),
        ("rule", "labrule", {"src": "192.0.2.128/25", "lookup": "100", "priority": "100"}),
        *(
            (
                ("interface", "wan", {"device": "eth0", "proto": "dhcp"}),
                ("interface", "wan6", {"device": "@wan", "proto": "dhcpv6", "reqprefix": "auto"}),
            )
            if router
            else ()
        ),
        *(wireguard_sections() if wireguard else ()),
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


def _route_entry(section: dict[str, Any]) -> dict[str, Any]:
    """A UCI ``route`` section as netifd lists it in ``network.interface dump``."""
    target = str(section["target"])
    net = ip_interface(
        target if "/" in target else f"{target}/{section.get('netmask', '255.255.255.255')}"
    ).network
    return {
        "target": str(net.network_address),
        "mask": net.prefixlen,
        "nexthop": section["gateway"],
        "source": "0.0.0.0/0",
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
        for text in _words(s.get("addresses")):  # proto wireguard
            addr = ip_interface(text)
            (v4 if addr.version == 4 else v6).append(
                {"address": str(addr.ip), "mask": addr.network.prefixlen}
            )
        gateway = s.get("gateway")
        static = [
            _route_entry(r)
            for _, r in _of(network, "route")
            if r.get("interface") == name
            and r.get("gateway")
            and not _on(r.get("disabled"))
            and "table" not in r
        ]
        entry: dict[str, Any] = {
            "interface": name,
            "up": True,
            "proto": s.get("proto", "none"),
            "device": dev,
            "l3_device": dev,
            "ipv4-address": v4,
            "ipv6-address": v6,
            "route": [
                *(
                    [{"target": "0.0.0.0", "mask": 0, "nexthop": gateway, "source": "0.0.0.0/0"}]
                    if gateway
                    else []
                ),
                *static,
            ],
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


def _stats(busy: bool) -> dict[str, int]:
    """``statistics`` of ``network.device status`` (rtnl_link_stats64), fixed values: a port
    with a link has carried some traffic and a few errors, one without has nothing."""
    if not busy:
        return dict.fromkeys(("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"), 0) | {
            "rx_errors": 0,
            "tx_errors": 0,
            "rx_dropped": 0,
            "tx_dropped": 0,
            "collisions": 0,
            "rx_crc_errors": 0,
        }
    return {
        "rx_bytes": 48_211_904,
        "tx_bytes": 391_220_117,
        "rx_packets": 402_113,
        "tx_packets": 511_902,
        "rx_errors": 3,
        "tx_errors": 0,
        "rx_dropped": 12,
        "tx_dropped": 0,
        "collisions": 0,
        "rx_crc_errors": 3,
    }


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
            "statistics": _stats(carrier),
        }

    status: dict[str, Any] = {f"lan{n}": eth(n < 4) for n in range(1, 5)}
    status["eth0"] = eth(True) | {
        "speed": "2500F",
        "link-supported": [*GIGABIT, "2500baseT-F"],
        "link-advertising": [*GIGABIT, "2500baseT-F"],
    }
    # the DSA conduit: the link of the CPU to the switch chip of lan1..lan4 (fixed speed, #252)
    status[CONDUIT] = eth(True) | {"speed": "1000F", "autoneg": False, "macaddr": _mac(0, 2)}
    for key in ("link-supported", "link-advertising"):
        del status[CONDUIT][key]
    for _, s in _of(network, "device"):
        if s.get("name") in status and str(s.get("enabled", "1")) == "0":
            status[str(s["name"])] |= {"up": False, "carrier": False, "speed": "-1F"}
    for name, s in _of(network, "interface"):
        if s.get("proto") == "wireguard":
            status[name] = eth(True) | {"mtu": int(s.get("mtu", 1420)), "macaddr": None}
            for key in ("speed", "autoneg", "link-supported", "link-advertising", "macaddr"):
                status[name].pop(key, None)
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
                # netifd 22.03+: the bridge's settings (``bridge_dump_info``)
                "bridge-attributes": {
                    "stp": str(s.get("stp", "0")) == "1",
                    "forward_delay": 8,
                    "priority": int(str(s.get("priority", 0x7FFF))),
                    "ageing_time": 30,
                    "hello_time": 2,
                    "max_age": 20,
                },
            }
    for _, s in _of(network, "device"):
        if s.get("type") == "bonding" and s.get("name"):
            status[str(s["name"])] = {
                "type": "bonding",
                "up": True,
                "carrier": True,
                "macaddr": _mac(0, 1),
                "mtu": 1500,
                "speed": "2000F",
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


#: DSA conduit of the simulated switch chip. Which kernel facts LuCI reads for it is taken
#: from the rpcd-mod-luci source, not from a real DSA device (a guess, #21).
CONDUIT = "eth1"


def network_devices(network: Sections, wireless: Sections) -> dict[str, Any]:
    """``luci-rpc getNetworkDevices``: kernel facts per device (rpcd-mod-luci ``luci.c``):
    ``devtype`` from the uevent (``dsa`` for DSA user ports), ``parent`` from ``iflink``."""
    out: dict[str, Any] = {}
    for name, st in device_status(network, wireless).items():
        entry: dict[str, Any] = {
            "name": name,
            "up": bool(st.get("up")),
            "mtu": st.get("mtu", 1500),
            "type": 772 if name == "lo" else 1,
            "devtype": "ethernet",
            "wireless": False,
        }
        if st.get("macaddr"):
            entry["mac"] = st["macaddr"]
        if st.get("type") == "bridge":
            entry |= {"bridge": True, "ports": st.get("bridge-members", []), "devtype": "bridge"}
        elif st.get("type") == "VLAN":
            entry |= {"devtype": "vlan", "parent": name.rsplit(".", 1)[0]}
        elif st.get("type") == "bonding":
            entry |= {"devtype": "bond"}
        elif name.startswith("lan"):
            entry |= {"devtype": "dsa", "parent": CONDUIT}
        elif name.startswith("phy"):
            entry |= {"devtype": "wlan", "wireless": True}
        out[name] = entry
    for bridge in [n for n, e in out.items() if e.get("bridge")]:
        for member in out[bridge]["ports"]:
            if member in out:
                out[member]["master"] = bridge
    return out


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
                "sae_pwe": "2",
                "ieee80211r": "1",
                "mobility_domain": "a1b2",
                "ft_over_ds": "0",
                "ft_psk_generate_local": "1",
                "dtim_period": "2",
                "rssi_reject_assoc_rssi": "-75",
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
                "sae_pwe": "2",
                "ieee80211r": "1",
                "mobility_domain": "a1b2",
                "ft_over_ds": "0",
                "ft_psk_generate_local": "1",
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
                "wps_pushbutton": "1",
                "wpa_group_rekey": "3600",
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


#: shared secret of the simulated RADIUS server: tests assert that it is never read
RADIUS_SECRET = "sim-radius-secret-do-not-leak"
#: the 802.11s peer of the simulator's mesh point (``OpenWrtSim.mesh``)
MESH_PEER = _mac(0x30, 1)
#: the WDS station of the access point interface ``default_radio0`` when it has ``wds '1'``
#: (#475); it is served as a ``wds`` client by hostapd
WDS_PEER = _mac(0x30, 2)
#: wifi-iface section -> associated stations
STATIONS = {
    "mesh0": [MESH_PEER],
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
        (
            "dnsmasq",
            "cfg01411c",
            {
                "domainneeded": "1",
                "localise_queries": "1",
                **(
                    {
                        "noresolv": "1",
                        "server": ["192.0.2.53", "/corp.example/198.51.100.53"],
                    }
                    if router
                    else {}
                ),
                "authoritative": "1",
                "dhcp_boot": "pxelinux.0,,192.0.2.5",
            },
        ),
        (
            "dhcp",
            "lan",
            {
                "interface": "lan",
                "start": "100",
                "limit": "150",
                "leasetime": "12h",
                **(
                    {
                        "ra": "server",
                        "dhcpv6": "server",
                        "ra_slaac": "1",
                        "ra_flags": ["managed-config", "other-config"],
                        "dns": ["2001:db8::53"],
                        "dhcp_option": [
                            "6,192.0.2.1,192.0.2.53",
                            "42,192.0.2.1",
                            "119,home.example,lan.example",
                            "121,203.0.113.0/24,192.0.2.254",
                            "option:wpad,http://192.0.2.1/wpad.dat",
                        ],
                    }
                    if router
                    else {"ignore": "1"}
                ),
            },
        ),
        ("dhcp", "wan", {"interface": "wan", "ignore": "1"}),
        ("host", "cfg06fe63", {"name": "printer", "mac": _fixed(1), "ip": "192.0.2.50"}),
        ("host", "cfg07fe63", {"name": "faraway", "mac": _fixed(2), "ip": "203.0.113.9"}),
        ("domain", "cfg08f37c", {"name": "printer.lan", "ip": "192.0.2.50"}),
        (
            "relay",
            "cfg08fe63",
            {"local_addr": "192.0.2.2", "server_addr": "192.0.2.53", "interface": "iot"},
        ),
    )


def firewall_config(router: bool = False, wireguard: bool = False) -> dict[str, Any]:
    """``/etc/config/firewall`` as OpenWrt 24.10 ships it (zones ``lan`` and ``wan``, one
    forwarding, the ``Allow-*`` rules), plus an ``iot`` zone, a port forward and a rule of the
    owner's (documentation addresses). Without ``router`` (an access point): LAN only."""
    zones: list[tuple[str, str, dict[str, Any]]] = [
        ("defaults", "cfg01e63d", {"input": "REJECT", "output": "ACCEPT", "forward": "REJECT"}),
        (
            "zone",
            "cfg02dc81",
            {
                "name": "lan",
                "network": ["lan"],
                "input": "ACCEPT",
                "output": "ACCEPT",
                "forward": "ACCEPT",
            },
        ),
    ]
    if not router:
        return _uci(*zones)
    wan_networks = ["wan", "wan6"]
    return _uci(
        *zones,
        (
            "zone",
            "cfg03dc81",
            {
                "name": "wan",
                "network": wan_networks,
                "input": "REJECT",
                "output": "ACCEPT",
                "forward": "REJECT",
                "masq": "1",
                "mtu_fix": "1",
            },
        ),
        (
            "zone",
            "iot",
            {
                "name": "iot",
                "network": ["iot"],
                "input": "REJECT",
                "output": "ACCEPT",
                "forward": "REJECT",
            },
        ),
        *(
            (
                (
                    "zone",
                    "vpn",
                    {
                        "name": "vpn",
                        "network": ["wg0"],
                        "input": "REJECT",
                        "output": "ACCEPT",
                        "forward": "REJECT",
                    },
                ),
            )
            if wireguard
            else ()
        ),
        ("forwarding", "cfg04ad58", {"src": "lan", "dest": "wan"}),
        ("forwarding", "cfg05ad58", {"src": "iot", "dest": "wan"}),
        (
            "rule",
            "cfg06dc81",
            {
                "name": "Allow-DHCP-Renew",
                "src": "wan",
                "proto": "udp",
                "dest_port": "68",
                "target": "ACCEPT",
                "family": "ipv4",
            },
        ),
        (
            "rule",
            "cfg07dc81",
            {
                "name": "Allow-Ping",
                "src": "wan",
                "proto": "icmp",
                "icmp_type": "echo-request",
                "family": "ipv4",
                "target": "ACCEPT",
            },
        ),
        (
            "rule",
            "cfg08dc81",
            {
                "name": "Allow-DHCPv6",
                "src": "wan",
                "proto": "udp",
                "dest_ip": "fc00::/6",
                "dest_port": "546",
                "family": "ipv6",
                "target": "ACCEPT",
            },
        ),
        (
            "rule",
            "cfg09dc81",
            {
                "name": "Allow-IPSec-ESP",
                "src": "wan",
                "dest": "lan",
                "proto": "esp",
                "target": "ACCEPT",
            },
        ),
        (
            "rule",
            "iot_dns",
            {
                "name": "Allow-DNS-IoT",
                "src": "iot",
                "proto": ["tcp", "udp"],
                "dest_port": "53",
                "target": "ACCEPT",
            },
        ),
        (
            "redirect",
            "nas",
            {
                "name": "nas-https",
                "target": "DNAT",
                "src": "wan",
                "src_dport": "8443",
                "dest": "lan",
                "dest_ip": "192.0.2.10",
                "dest_port": "443",
                "proto": "tcp",
            },
        ),
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


def snmpd_config() -> dict[str, Any]:
    """``/etc/config/snmpd`` of the snmpd package (shortened): v1/v2c with ``public`` from
    anywhere and ``private`` from localhost, plus a v2c trap target. *Guess* (#21)."""
    return _uci(
        ("agent", "cfg01", {"agentaddress": "UDP:161,UDP6:161"}),
        ("com2sec", "public", {"secname": "ro", "source": "default", "community": "public"}),
        ("com2sec", "private", {"secname": "rw", "source": "localhost", "community": "private"}),
        ("group", "public_v1", {"group": "public", "version": "v1", "secname": "ro"}),
        ("group", "public_v2c", {"group": "public", "version": "v2c", "secname": "ro"}),
        ("group", "private_v2c", {"group": "private", "version": "v2c", "secname": "rw"}),
        ("access", "public_access", {"group": "public", "read": "all", "write": "none"}),
        ("access", "private_access", {"group": "private", "read": "all", "write": "all"}),
        ("system", "cfg02", {"sysLocation": "office", "sysContact": "admin@example.com"}),
        ("trap2sink", "cfg03", {"host": "192.0.2.5", "community": "public", "port": "162"}),
        ("snmpd", "general", {"enabled": "1"}),
    )


def statistics_config() -> dict[str, Any]:
    """``/etc/config/luci_statistics`` (shortened): collectd's network plugin to one server."""
    return _uci(
        ("statistics", "collectd", {"BaseDir": "/var/run/collectd", "Interval": "30"}),
        ("statistics", "collectd_network", {"enable": "1"}),
        ("collectd_network_server", "cfg01", {"host": "192.0.2.5", "port": "25826"}),
    )


def softflowd_config() -> dict[str, Any]:
    """``/etc/config/softflowd`` as the package ships it: off, NetFlow v5 to a collector."""
    return _uci(
        (
            "softflowd",
            "cfg01",
            {
                "enabled": "0",
                "interface": "br-lan",
                "host_port": "192.0.2.5:9995",
                "export_version": "5",
            },
        ),
    )


def rpcd_config(username: str) -> dict[str, Any]:
    """``/etc/config/rpcd`` as OpenWrt ships it (root with the system password, all ACLs)
    plus Signalbox's login with the read-only ACL of the setup guide. The hash is a
    placeholder, not one of a real password."""
    return _uci(
        ("rpcd", "cfg01", {"socket": "/var/run/ubus/ubus.sock", "timeout": "30"}),
        (
            "login",
            "cfg02",
            {"username": "root", "password": "$p$root", "read": ["*"], "write": ["*"]},
        ),
        (
            "login",
            "cfg03",
            {
                "username": username,
                "password": "$1$placehld$notarealhash000000000",
                "read": ["signalbox"],
            },
        ),
    )


def usteer_config() -> dict[str, Any]:
    """``/etc/config/usteer`` (#447, guess: option names): band steering every 2 minutes."""
    return _uci(("usteer", "usteer", {"band_steering_interval": "120000", "network": ["lan"]}))


def dawn_config() -> dict[str, Any]:
    """``/etc/config/dawn`` (#447, guess: option names): 5 GHz ranked above 2.4 GHz."""
    return _uci(("metric", "global", {"kicking": "1", "freq_5": "100", "freq_2": "0"}))


def opennds_config() -> dict[str, Any]:
    """``/etc/config/opennds`` (#460, guess: option names): the built-in splash page on br-lan.1."""
    return _uci(
        (
            "opennds",
            "opennds",
            {
                "enabled": "1",
                "gatewayinterface": "br-lan.1",
                "gatewayname": "Example",
                "sessiontimeout": "480",
            },
        )
    )


def upnpd_config() -> dict[str, Any]:
    """``/etc/config/upnpd`` (#176): miniupnpd on the main network, secure mode on, one rule."""
    return _uci(
        (
            "upnpd",
            "config",
            {
                "enabled": "1",
                "enable_upnp": "1",
                "enable_natpmp": "1",
                "secure_mode": "1",
                "internal_iface": "lan",
                "upnp_lease_file": "/var/run/miniupnpd.leases",
            },
        ),
        (
            "perm_rule",
            "cfg0a1b2c",
            {
                "action": "allow",
                "ext_ports": "1024-65535",
                "int_addr": "192.0.2.0/24",
                "int_ports": "1024-65535",
                "comment": "Allow high ports",
            },
        ),
        (
            "perm_rule",
            "cfg0b1b2c",
            {
                "action": "deny",
                "ext_ports": "0-65535",
                "int_addr": "0.0.0.0/0",
                "int_ports": "0-65535",
            },
        ),
    )


def upnp_leases(now: float) -> str:
    """The lease file of miniupnpd (#176): a game console (UPnP, 2 h left), a NAT-PMP mapping
    and a permanent one; documentation addresses only."""
    soon = int(now) + 7200
    return (
        f"UDP:3074:192.0.2.60:3074:{soon}:Example console\n"
        f"TCP:51413:192.0.2.61:51413:{soon}:Example torrent client: port 51413\n"
        "TCP:2222:192.0.2.62:22:0:NAT-PMP 2222 tcp\n"
        "broken line\n"
        f"UDP:9999:192.0.2.63:9999:{int(now) - 60}:expired\n"
    )


#: static key and key files of the simulated OpenVPN: tests assert they never leak (#153)
OPENVPN_SECRET = "sim-openvpn-static-key-do-not-leak"


def openvpn_config() -> dict[str, Any]:
    """``/etc/config/openvpn`` (#153): a server with tls-crypt and AES-GCM, and a client with
    the old BF-CBC cipher and no tls-auth (documentation addresses)."""
    return _uci(
        (
            "openvpn",
            "road_warrior",
            {
                "enabled": "1",
                "dev": "tun",
                "proto": "udp",
                "port": "1194",
                "server": "198.18.77.0 255.255.255.0",
                "ca": "/etc/openvpn/ca.crt",
                "cert": "/etc/openvpn/server.crt",
                "key": "/etc/openvpn/server.key",
                "tls_crypt": OPENVPN_SECRET,
                "data_ciphers": "AES-256-GCM:AES-128-GCM",
                "push": ["route 192.0.2.0 255.255.255.0"],
            },
        ),
        (
            "openvpn",
            "to_provider",
            {
                "enabled": "1",
                "client": "1",
                "dev": "tun",
                "proto": "tcp-client",
                "remote": "203.0.113.60 443",
                "ca": "/etc/openvpn/provider-ca.crt",
                "cipher": "BF-CBC",
                "secret": OPENVPN_SECRET,
                "auth_user_pass": OPENVPN_SECRET,
            },
        ),
    )


def openvpn_status(now: float) -> str:
    """The status file of the server (``status_version 2``, #527): one client, documentation
    addresses; the client line carries epoch times."""
    t = int(now)
    return (
        "TITLE,OpenVPN 2.6.8 x86_64-pc-linux-gnu\n"
        f"TIME,sim-time,{t}\n"
        "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,"
        "Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,"
        "Client ID,Peer ID,Data Channel Cipher\n"
        "CLIENT_LIST,alice-laptop,203.0.113.77:51000,198.18.77.6,,1234,5678,"
        f"sim-time,{t - 3600},UNDEF,0,0,AES-256-GCM\n"
        "END\n"
    )


#: a pre-shared key and a passphrase of the simulated strongSwan: tests assert they never leak
SWANCTL_SECRET = "sim-ipsec-psk-do-not-leak"
SWANCTL_CONF = f"""# documentation addresses only (#527)
connections {{
    site-b {{
        version = 2
        remote_addrs = 203.0.113.80
        proposals = aes256-sha256-modp2048,aes128-sha1-modp1024
        dpd_delay = 30s
        local {{
            auth = psk
            id = gw.example.invalid
        }}
        remote {{
            auth = psk
        }}
        children {{
            lan {{
                local_ts = 192.0.2.0/24
                remote_ts = 198.51.100.0/24
                esp_proposals = aes256gcm16-modp2048
                rekey_time = 1h
            }}
        }}
    }}
    roadwarrior {{
        version = 1
        aggressive = yes
        local {{
            auth = pubkey
            certs = gw.pem
        }}
        children {{
            net {{
                local_ts = 192.0.2.0/24
                esp_proposals = 3des-md5
            }}
        }}
    }}
}}
secrets {{
    ike-site-b {{
        id = gw.example.invalid
        secret = "{SWANCTL_SECRET}"
    }}
}}
"""


def sqm_config() -> dict[str, Any]:
    """``/etc/config/sqm`` (#166, guess: option names): cake on the WAN, 90 and 18 Mbit/s."""
    return _uci(
        (
            "queue",
            "wan",
            {
                "enabled": "1",
                "interface": "wan",
                "download": "90000",
                "upload": "18000",
                "qdisc": "cake",
                "script": "piece_of_cake.qos",
            },
        ),
    )


def igmpproxy_config() -> dict[str, Any]:
    """``/etc/config/igmpproxy`` (#161): the uplink ``wan`` upstream, the main network down."""
    return _uci(
        ("igmpproxy", "igmpproxy", {"quickleave": "1"}),
        ("phyint", "wan", {"network": "wan", "direction": "upstream", "altnet": "0.0.0.0/0"}),
        ("phyint", "lan", {"network": "lan", "direction": "downstream"}),
        ("phyint", "iot", {"network": "iot", "direction": "disabled"}),
    )


def nodogsplash_config() -> dict[str, Any]:
    """``/etc/config/nodogsplash`` (#460, guess): an external authentication service."""
    return _uci(
        (
            "nodogsplash",
            "cfg020f15",
            {"enabled": "1", "gatewayinterface": "br-lan.1", "fasremoteip": "192.0.2.80"},
        )
    )


def mwan3_config() -> dict[str, Any]:
    """``/etc/config/mwan3`` of a router with a cable line (``wan``, tier 1) and an LTE stick
    (``wanb``, tier 2) as backup (documentation addresses)."""
    return _uci(
        ("interface", "wan", {"enabled": "1", "track_ip": ["192.0.2.53", "198.51.100.53"]}),
        ("interface", "wanb", {"enabled": "1", "track_ip": ["198.51.100.53"], "interval": "10"}),
        ("member", "wan_m1", {"interface": "wan", "metric": "1", "weight": "3"}),
        ("member", "wanb_m2", {"interface": "wanb", "metric": "2", "weight": "1"}),
        ("policy", "failover", {"use_member": ["wan_m1", "wanb_m2"]}),
    )


def ddns_config() -> dict[str, Any]:
    """``/etc/config/ddns`` with one client; the account data is there, and never read."""
    return _uci(
        (
            "service",
            "home",
            {
                "enabled": "1",
                "service_name": "duckdns.org",
                "lookup_host": "home.example.dyndns.invalid",
                "domain": "home.example.dyndns.invalid",
                "username": "sim-user",
                "password": "sim-secret-token",
                "interface": "wan",
                "use_ipv6": "0",
                "use_https": "1",
            },
        ),
    )


#: ``ubus call mwan3 status`` (guess: shape of mwan3 2.x, #21)
MWAN3_STATUS: dict[str, Any] = {
    "interfaces": {
        "wan": {
            "status": "online",
            "up": True,
            "track_ip": [
                {"ip": "192.0.2.53", "status": "up", "latency": 12, "packetloss": 0},
                {"ip": "198.51.100.53", "status": "up", "latency": 15, "packetloss": 0},
            ],
        },
        "wanb": {
            "status": "offline",
            "up": False,
            "track_ip": [
                {"ip": "198.51.100.53", "status": "down", "latency": 0, "packetloss": 100}
            ],
        },
    }
}


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
                "log_ip": "192.0.2.5",
                "log_port": "514",
                "log_proto": "udp",
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


#: What the sample stations report (#170): hostapd ``get_clients`` fields and the
#: ``iwinfo assoclist`` entry (rates in kbit/s, ``inactive`` in ms), by MAC.
STATION_DETAILS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    _mac(0x20, 1): (
        {"signal": -55, "ht": True, "vht": True, "he": True, "mfp": True, "rrm": [113, 0, 0, 0, 0]},
        {
            "signal": -55,
            "noise": -95,
            "inactive": 120,
            "connected_time": 7200,
            "rx": {"rate": 573500, "he": True, "40mhz": False, "packets": 9000},
            "tx": {"rate": 286700, "he": True, "packets": 8000, "retries": 400, "failed": 3},
        },
    ),
    _mac(0x20, 2): (
        {"signal": -82, "ht": False, "vht": False, "he": False},
        {
            "signal": -82,
            "noise": -95,
            "inactive": 4000,
            "connected_time": 300,
            "rx": {"rate": 11000, "packets": 500},
            "tx": {"rate": 11000, "packets": 400, "retries": 200, "failed": 40},
        },
    ),
    MESH_PEER: (
        {"signal": -78},
        {
            "signal": -78,
            "noise": -95,
            "inactive": 30,
            "connected_time": 5000,
            "rx": {"rate": 54000, "packets": 9000},
            "tx": {"rate": 48000, "packets": 8000, "retries": 100, "failed": 2},
        },
    ),
    WDS_PEER: (
        {"signal": -70, "wds": True},
        {
            "signal": -70,
            "noise": -95,
            "inactive": 20,
            "connected_time": 600,
            "rx": {"rate": 144400, "packets": 900},
            "tx": {"rate": 130000, "packets": 800, "retries": 10, "failed": 0},
        },
    ),
    _mac(0x20, 3): (
        {"signal": -61, "ht": True, "vht": True, "he": False, "mfp": True},
        {
            "signal": -61,
            "noise": -92,
            "inactive": 50,
            "connected_time": 86400,
            "rx": {"rate": 866700, "vht": True, "80mhz": True, "packets": 90000},
            "tx": {"rate": 780000, "vht": True, "packets": 80000, "retries": 800, "failed": 5},
        },
    ),
}


def _stations(section: str, wds: bool, extra: Sequence[str] = ()) -> list[str]:
    """Stations of a section; with ``wds '1'`` the access point interface has a WDS station;
    ``extra``: more stations a test gives (``OpenWrtSim.stations``, #529)."""
    return [
        *STATIONS.get(section, []),
        *([WDS_PEER] if wds and section == "default_radio0" else []),
        *extra,
    ]


#: hostapd and iwinfo details of a station a test adds (``OpenWrtSim.stations``, #529)
OTHER_STATION: tuple[dict[str, Any], dict[str, Any]] = (
    {"signal": -64},
    {
        "signal": -64,
        "noise": -95,
        "inactive": 10,
        "connected_time": 3600,
        "rx": {"rate": 390000, "packets": 5000},
        "tx": {"rate": 351000, "packets": 4000, "retries": 20, "failed": 0},
    },
)


def clients(
    ifname: str, section: str, wds: bool = False, extra: Sequence[str] = ()
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for mac in _stations(section, wds, extra):
        base = {"auth": True, "assoc": True, "authorized": True, "signal": -55, "aid": 1}
        hostapd, info = STATION_DETAILS.get(mac, OTHER_STATION if mac in extra else ({}, {}))
        if wds and mac in extra:
            hostapd = {**hostapd, "wds": True}
        rate = {"rx": info["rx"]["rate"], "tx": info["tx"]["rate"]} if info else None
        out[mac] = {**base, **hostapd, **({"rate": rate} if rate else {})}
    return {"freq": 2437 if ifname.startswith("phy0") else 5180, "clients": out}


def assoclist(
    ifname: str, section: str, wds: bool = False, extra: Sequence[str] = ()
) -> dict[str, Any]:
    """``iwinfo assoclist`` of an interface."""
    details = {**STATION_DETAILS, **dict.fromkeys(extra, OTHER_STATION)}
    return {
        "results": [
            {"mac": mac, **details[mac][1]}
            for mac in _stations(section, wds, extra)
            if mac in details
        ]
    }


#: Channels of the sample radios with country DE (5 GHz: 36-140, no 149-165 in the EU).
CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [*range(36, 65, 4), *range(100, 141, 4)]


def _mhz(band: str, channel: int) -> int:
    return 2407 + 5 * channel if band == "2g" else 5000 + 5 * channel


def _width(htmode: str) -> int:
    digits = htmode.lstrip("EHTVN")
    return int(digits) if digits.isdigit() else 20


def iwinfo(method: str, radio: dict[str, Any]) -> dict[str, Any] | None:
    """``iwinfo info/freqlist/txpowerlist/survey`` of a radio's interface (#172), derived from
    its UCI section: an ax radio, quiet channels."""
    band = str(radio.get("band", "2g"))
    channel = int(radio.get("channel", 6 if band == "2g" else 36))
    htmode = str(radio.get("htmode", "HE20"))
    mhz = _mhz(band, channel)
    noise = -92 if band == "2g" else -95
    if method == "info":
        n = _width(htmode) // 20
        start = 36 + 4 * n * ((channel - 36) // (4 * n)) if band != "2g" else channel
        return {
            "phy": "phy0" if band == "2g" else "phy1",
            "mode": "Master",
            "channel": channel,
            "center_chan1": start + 2 * (n - 1) if band != "2g" else channel,
            "frequency": mhz,
            "txpower": int(radio.get("txpower", 20)),
            "quality": 0,
            "quality_max": 70,
            "signal": 0,
            "noise": noise,
            "country": str(radio.get("country", "00")),
            "hwmodes": ["b", "g", "n", "ax"] if band == "2g" else ["a", "n", "ac", "ax"],
            "htmode": htmode,
            "htmodes": ["HT20", "HT40", "HE20", "HE40"]
            if band == "2g"
            else ["HT20", "HT40", "VHT20", "VHT40", "VHT80", "HE20", "HE40", "HE80", "HE160"],
        }
    if method == "freqlist":
        chans = CHANNELS_24 if band == "2g" else CHANNELS_5
        return {
            "results": [
                {"channel": c, "mhz": _mhz(band, c), "restricted": False, "active": c == channel}
                for c in chans
            ]
        }
    if method == "txpowerlist":
        top = 20 if band == "2g" else 23
        return {
            "results": [
                {"dbm": d, "mw": round(10 ** (d / 10)), "active": False} for d in range(top + 1)
            ]
        }
    if method == "survey":
        busy = 31 if band == "2g" else 12  # percent of the time
        active = 1_000_000
        return {
            "results": [
                {
                    "mhz": mhz,
                    "noise": noise,
                    "active_time": active,
                    "busy_time": active * busy // 100,
                    "busy_time_ext": 0,
                    "rx_time": active * busy // 300,
                    "tx_time": active * busy // 300,
                }
            ]
        }
    return None


def _neighbour(
    bssid: str, ssid: str, channel: int, signal: int, wpa: list[int], auth: list[str], width: int
) -> dict[str, Any]:
    band = "2g" if channel <= 14 else "5g"
    row: dict[str, Any] = {
        "ssid": ssid,
        "bssid": bssid.upper(),
        "mode": "Master",
        "band": 2 if band == "2g" else 5,
        "channel": channel,
        "mhz": _mhz(band, channel),
        "signal": signal,
        "quality": max(0, signal + 110),
        "quality_max": 70,
        "ht_operation": {"primary_channel": channel, "channel_width": 2040 if width >= 40 else 20},
        "encryption": {"enabled": bool(auth), "wpa": wpa, "authentication": auth},
    }
    if band == "5g":
        row["vht_operation"] = {"channel_width": width if width >= 80 else 40}
    return row


#: What the simulated radios hear (#169): neighbours' networks with documentation MACs, the
#: answer of ``iwinfo scan`` (filtered by the scanning radio's band).
NEIGHBOURS: list[dict[str, Any]] = [
    _neighbour("02:5e:00:00:01:01", "Neighbour-A", 6, -58, [2], ["psk"], 20),
    _neighbour("02:5e:00:00:01:02", "Neighbour-B", 6, -71, [2, 3], ["psk", "sae"], 20),
    _neighbour("02:5e:00:00:01:03", "", 11, -77, [2], ["psk"], 20),
    _neighbour("02:5e:00:00:01:04", "Cafe-Free", 1, -84, [], [], 20),
    _neighbour("02:5e:00:00:02:01", "Neighbour-A", 44, -67, [2], ["psk"], 80),
    _neighbour("02:5e:00:00:02:02", "Neighbour-C", 149, -80, [3], ["sae"], 80),
]


def hostapd_status(ifname: str, radio: dict[str, Any]) -> dict[str, Any]:
    """``hostapd.<ifname> get_status`` (#172): channel, DFS and air time."""
    band = str(radio.get("band", "2g"))
    channel = int(radio.get("channel", 6 if band == "2g" else 36))
    return {
        "status": "ENABLED",
        "freq": _mhz(band, channel),
        "channel": channel,
        "op_class": 81 if band == "2g" else 128,
        "beacon_interval": 100,
        "phy": ifname.split("-")[0],
        "dfs": {"cac_seconds": 60, "cac_active": False, "cac_seconds_left": 0},
        "airtime": {"time": 0, "time_busy": 0, "utilization": 0},
    }


LEASE = (_mac(0x20, 3), "192.0.2.103", "laptop")


#: Releases the simulator can pose as: revision and kernel per version (#407). 23.05 and 24.10
#: have netifd's shell wireless object and opkg; 25.12 has the ucode one (``wireless_ucode``), apk.
RELEASES: dict[str, tuple[str, str]] = {
    #: only the release string differs: a minimum signal is refused before 22.03 (#489)
    "21.02.7": ("r16847-f8282da11e", "5.4.238"),
    "23.05.5": ("r24106-10cc5fcd00", "5.15.167"),
    "23.05.6": ("r23630-842932a63d", "5.15.194"),
    "24.10.8": ("r28939-ecd2cf8f09", "6.6.119"),
}


def board(version: str = "23.05.5") -> dict[str, Any]:
    revision, kernel = RELEASES[version]
    return {
        "kernel": kernel,
        "hostname": "ap",
        "system": "ARMv8 Processor rev 4",
        "model": "Example AP",
        "board_name": "example,ap",
        "rootfs_type": "squashfs",
        "release": {
            "distribution": "OpenWrt",
            "version": version,
            "revision": revision,
            "target": "mediatek/filogic",
            "description": f"OpenWrt {version} {revision}",
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
                        "age": "0 day, 03:12:44",
                        "chassis": [
                            {
                                "id": [{"type": "mac", "value": _mac(0x30, 1)}],
                                "name": [{"value": "switch"}],
                                "mgmt-ip": [{"value": "192.0.2.3"}],
                                "descr": [{"value": "MikroTik RouterOS 7.15.3 CRS326-24G-2S+"}],
                                "capability": [
                                    {"type": "Bridge", "enabled": True},
                                    {"type": "Router", "enabled": True},
                                    {"type": "Wlan", "enabled": False},
                                    {"type": "Station", "enabled": False},
                                ],
                            }
                        ],
                        "port": [
                            {
                                "id": [{"type": "ifname", "value": "port 8"}],
                                "descr": [{"value": "uplink to router"}],
                                "ttl": [{"value": "120"}],
                                "mfs": [{"value": "1522"}],
                                "vlan": [
                                    {"vlan-id": "1", "pvid": True, "value": "default"},
                                    {"vlan-id": "20", "pvid": False, "value": "iot"},
                                ],
                                "power": [
                                    {
                                        "device-type": "PSE",
                                        "class": "class 4",
                                        "requested": "15400",
                                        "allocated": "15400",
                                    }
                                ],
                            }
                        ],
                        "lldp-med": [{"device-type": [{"value": "Network Connectivity Device"}]}],
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
    #: optional packages installed (#180): ``snmpd``, ``luci_statistics``, ``softflowd``; and
    #: ``mwan3`` (#150), ``ddns`` (ddns-scripts, #154), ``usteer`` and ``dawn`` (#447),
    #: ``opennds`` and ``nodogsplash`` (#460)
    packages: set[str] = field(default_factory=set)
    #: an 802.11s mesh point on radio1 with one mesh peer (#171), ``mesh_peer_mac`` away
    mesh: bool = False
    #: A WPA2-Enterprise SSID with RADIUS server and shared secret (#162); the secret must never
    #: show up in the model, logs or API output.
    enterprise: bool = False
    #: no ``network.wireless`` ubus object (a device without Wi-Fi)
    no_wireless_object: bool = False
    #: answer of ``ubus call poe info`` (realtek-poe); None: the daemon is not installed
    poe_info: dict[str, Any] | None = None
    #: UCI configs the ACL lets the user change (``write`` → ``uci`` in the rpcd ACL)
    writable: set[str] = field(default_factory=lambda: {*CONFIGS, *WRITE_ALSO})
    #: objects answered with broken JSON (``*``: every request)
    malformed: set[str] = field(default_factory=set)
    #: objects answered with valid JSON of the wrong shape
    odd: set[str] = field(default_factory=set)
    #: seconds to wait before answering (``slow`` objects or ``object.method`` only, or every
    #: request if empty)
    delay: float = 0.0
    slow: set[str] = field(default_factory=set)
    #: luci-app-lldpd installed (ubus object ``luci.lldpd``)
    lldpd: bool = True
    luci_rpc: bool = True
    #: a WireGuard interface ``wg0`` with two peers in the network config (#152)
    wireguard: bool = False
    #: ``luci.wireguard`` (luci-proto-wireguard) installed
    luci_wireguard: bool = True
    #: seconds since the site peer's last handshake
    wg_handshake_ago: int = 42
    #: ``/usr/libexec/signalbox-wg-key`` installed with wireguard-tools (#152)
    wg_key_helper: bool = True
    #: rpcd-mod-iwinfo installed (ubus object ``iwinfo``, #172)
    iwinfo: bool = True
    #: access points ``iwinfo scan`` reports (#169), see :data:`NEIGHBOURS`
    neighbours: list[dict[str, Any]] = field(default_factory=lambda: list(NEIGHBOURS))
    #: ``luci getFeatures`` answers (rpcd-mod-luci); off: the adapter reads the wpad package
    luci_features: bool = True
    #: installed hostapd package (``rpc-sys packagelist``); ``wpad-basic-mbedtls``: no SAE, OWE, EAP
    wpad: str = "wpad-mbedtls"
    #: release the simulator reports (``system board``), a key of :data:`RELEASES` (#407)
    release: str = "23.05.5"
    #: OpenWrt 25.12: netifd's ucode wireless object answers "invalid argument" through rpcd
    wireless_ucode: bool = False
    #: DHCP on, no default route on lan: the device acts as the router of 192.0.2.0/24
    router: bool = False
    #: lan2 and lan3 in a bond ``bond0`` with this policy (``802.3ad``, ``balance-xor``; #157)
    bond: str | None = None
    #: sysfs of the bond readable (the ACL of the docs); False: an older ACL
    bond_sysfs: bool = True
    #: fourth byte of the port MACs (02:00:00:<base>:..), so several simulators differ
    mac_base: int = 0
    #: time source of sessions and the rollback timer (replace it to test the timer)
    clock: Callable[[], float] = time.monotonic
    #: seconds the device's wall clock is ahead of the real time (``system info`` localtime)
    clock_skew: float = 0.0
    #: thermal zones (``type``, milli-degrees Celsius) under /sys/class/thermal
    thermal_zones: list[tuple[str, int]] = field(default_factory=lambda: [("cpu-thermal", 47823)])
    #: bridge members without ``/sys/class/net/<port>/brport`` (#155)
    no_brport: set[str] = field(default_factory=set)
    #: the bridge is the IGMP querier (``multicast_querier``, #161)
    querier: bool = True
    #: addresses the bridges learned (#378): (member, MAC, seconds since refreshed); the
    #: members' own MACs are local entries of ``brforward`` besides these
    learned: list[tuple[str, str, int]] = field(default_factory=list)
    #: ``/sys/class/net/*/brforward`` in the ACL (the docs); False: an older ACL
    brforward_acl: bool = True
    #: more stations per wifi-iface section (#529): the access point a station interface is
    #: associated with, the WDS stations of an access point interface with ``wds '1'``
    stations: dict[str, list[str]] = field(default_factory=dict)
    #: the bridge member that is the STP root port of its bridge (#529): another bridge is the
    #: root (a mesh node whose uplink is its Wi-Fi station); None: the bridge is the root
    stp_root_port: str | None = None
    sessions: dict[str, float] = field(default_factory=dict)
    #: more logins, username -> md5-crypt hash (set by the SSH side, ``openwrt_ssh``)
    login_hashes: dict[str, str] = field(default_factory=dict)
    logins: int = 0
    requests: int = 0
    #: root's system password (``""``: none, the factory state); logins tried as root (#175)
    root_password: str = "example-root-password"
    root_attempts: int = 0
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
                "network": _sections(network_config(self.router, self.wireguard, self.bond)),
                "wireless": _sections(wireless_config()),
                "dhcp": _sections(dhcp_config(self.router)),
                "system": _sections(system_config(self.router)),
                "dropbear": _sections(dropbear_config()),
                "uhttpd": _sections(uhttpd_config()),
                "snmpd": _sections(snmpd_config()),
                "luci_statistics": _sections(statistics_config()),
                "softflowd": _sections(softflowd_config()),
                "rpcd": _sections(rpcd_config(self.username)),
                "mwan3": _sections(mwan3_config()),
                "ddns": _sections(ddns_config()),
                "usteer": _sections(usteer_config()),
                "dawn": _sections(dawn_config()),
                "opennds": _sections(opennds_config()),
                "nodogsplash": _sections(nodogsplash_config()),
                "igmpproxy": _sections(igmpproxy_config()),
                "upnpd": _sections(upnpd_config()),
                "openvpn": _sections(openvpn_config()),
                "sqm": _sections(sqm_config()),
                "https-dns-proxy": {},
                "firewall": _sections(firewall_config(self.router, self.wireguard)),
            }
        if self.enterprise and "corp_radio1" not in self.configs["wireless"]:
            self.configs["wireless"]["corp_radio1"] = {
                ".anonymous": False,
                ".type": "wifi-iface",
                "device": "radio1",
                "mode": "ap",
                "network": "lan",
                "ssid": "Example-Corp",
                "encryption": "wpa2+ccmp",
                "auth_server": "192.0.2.53",
                "auth_port": "1812",
                "auth_secret": RADIUS_SECRET,
                "acct_server": "192.0.2.53",
                "acct_port": "1813",
                "acct_secret": RADIUS_SECRET,
                "dynamic_vlan": "1",
                "macfilter": "deny",
                "maclist": ["02:00:00:00:99:01", "02:00:00:00:99:02"],
            }
        if self.mesh and "mesh0" not in self.configs["wireless"]:
            self.configs["wireless"]["mesh0"] = {
                ".anonymous": False,
                ".type": "wifi-iface",
                "device": "radio1",
                "mode": "mesh",
                "network": "lan",
                "mesh_id": "example-mesh",
                "encryption": "sae",
                "key": "example-mesh-passphrase",
                "mesh_fwding": "1",
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

    def _known(self, username: Any, password: Any) -> bool:
        if username == self.username and password == self.password:
            return True
        if username == "root":
            self.root_attempts += 1
            return bool(password == self.root_password)
        stored = self.login_hashes.get(str(username), "")
        if not stored.startswith("$1$") or not isinstance(password, str):
            return False
        from signalbox.adapters.openwrt.provision import md5_crypt

        return md5_crypt(password, stored.split("$")[2]) == stored

    def _login(self, args: dict[str, Any]) -> list[Any]:
        if not self._known(args.get("username"), args.get("password")):
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
                "data": {"username": args.get("username")},
            },
        ]

    def _uci(self, sid: str, method: str, args: dict[str, Any]) -> list[Any] | None:
        config = str(args.get("config"))
        if method == "get":
            if f"uci:{config}" in self.denied:
                return [DENIED]
            if (
                config not in CONFIGS + READ_ONLY
                or config in self.missing
                or (config in PACKAGES and config not in self.packages)
            ):
                return [NOT_FOUND]
            sections = self.view(sid, config)
            if isinstance(args.get("section"), str):
                s = sections.get(args["section"])
                return [OK, {"values": s}] if s is not None else [NOT_FOUND]
            return [OK, _get(sections)]
        if method in ("set", "add", "delete", "order"):
            if config not in CONFIGS + WRITE_ALSO or (
                config in PACKAGES and config not in self.packages
            ):
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

    def _device_status(self) -> dict[str, Any]:
        status = device_status(self.state["network"], self.state["wireless"])
        if self.mac_base:  # a second simulated device needs MACs of its own
            base, own = "02:00:00:00:", f"02:00:00:{self.mac_base:02x}:"
            for entry in status.values():
                mac = entry.get("macaddr")
                if isinstance(mac, str) and mac.startswith(base):  # not reserved MACs
                    entry["macaddr"] = own + mac[len(base) :]
        return status

    def _wds(self, section: str) -> bool:
        """The section is an access point interface with ``wds '1'`` (#475)."""
        return str(self.state["wireless"].get(section, {}).get("wds")) == "1"

    def _radio_of(self, ifname: str) -> dict[str, Any] | None:
        """The UCI wifi-device section of a running interface (``phy0-ap0``) or phy."""
        wireless = self.state["wireless"]
        radios = dict(_of(wireless, "wifi-device"))
        for _, radio, name, _ in running_ifaces(wireless):
            if ifname in (name, name.split("-")[0]):
                return radios.get(radio)
        return None

    def _data(self, sid: str, obj: str, method: str, args: dict[str, Any]) -> list[Any] | None:
        """ubus result list, or None when the object does not exist."""
        if obj == "system" and method == "board":
            return [0, board(self.release)]
        if obj == "system" and method == "info":
            zone = next((sec for sec in self.state["system"].values()), {})
            name = str(zone.get("zonename") or "UTC")
            return [0, system_info(time.time() + self.clock_skew, name)]
        if obj == "poe" and method == "info":  # realtek-poe: only on PoE switches
            return None if self.poe_info is None else [0, self.poe_info]
        if obj == "network.device" and method == "status":
            return [0, self._device_status()]
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
            running = {
                ifname: s
                for s, _, ifname, mode in running_ifaces(self.state["wireless"])
                if mode == "ap"
            }
            if obj[8:] in running:
                ifname = obj[8:]
                if method == "get_status":
                    return [0, hostapd_status(ifname, self._radio_of(ifname) or {})]
                wds = self._wds(running[ifname])
                extra = self.stations.get(running[ifname], [])
                return (
                    [0, clients(ifname, running[ifname], wds, extra)]
                    if method == "get_clients"
                    else [3]
                )
        if obj == "iwinfo" and self.iwinfo:
            radio = self._radio_of(str(args.get("device", "")))
            if radio is None:
                return [INVALID_ARGUMENT]
            device = str(args.get("device", ""))
            if method == "assoclist":
                running = {i: sec for sec, _, i, mode in running_ifaces(self.state["wireless"])}
                section = running.get(device, "")
                extra = self.stations.get(section, [])
                return [0, assoclist(device, section, self._wds(section), extra)]
            if method == "scan":
                band = 2 if str(radio.get("band", "2g")) == "2g" else 5
                return [0, {"results": [n for n in self.neighbours if n["band"] == band]}]
            answer = iwinfo(method, radio)
            if method == "info" and answer is not None:
                mac = self._device_status().get(device, {}).get("macaddr")
                if mac:
                    answer["bssid"] = str(mac).upper()
            return [3] if answer is None else [0, answer]
        if obj == "luci" and self.luci_features and method == "getFeatures":
            full = "-basic" not in self.wpad
            flags = {"adhoc": True, "ieee80211r": True, "ieee80211w": True, "wps": full}
            flags |= {"sae": full, "owe": full, "eap": full, "suiteb192": full}
            return [0, {"hostapd": flags, "dropbear": True}]
        if obj == "rpc-sys" and method == "packagelist":
            return [0, {"packages": {"base-files": "1623-r1", self.wpad: "2024.09.15-1"}}]
        if obj == "luci-rpc" and self.luci_rpc:
            if method == "getWirelessDevices":  # network.wireless status plus iwinfo
                status = wireless_status(self.state["wireless"])
                for radio in status.values():
                    radio["iwinfo"] = {"hwmodes": ["n"]}
                return [0, status]
            if method == "getNetworkDevices":
                return [0, network_devices(self.state["network"], self.state["wireless"])]
            if method != "getDHCPLeases":
                return [3]
            mac, ip, name = LEASE
            lease = {"expires": 43000, "hostname": name, "macaddr": mac, "ipaddr": ip}
            printer = {
                "expires": False,  # a lease that never ends
                "hostname": "printer",
                "macaddr": FIXED_MAC.format(1),
                "ipaddr": "192.0.2.50",
            }
            v6 = {
                "duid": "000100012d1b2c3d02000000200a",
                "ip6addr": "2001:db8::1a2/128",
                "hostname": "laptop",
                "expires": 3000,
            }
            return [
                0,
                {"dhcp_leases": [lease, printer, {"macaddr": "bogus"}], "dhcp6_leases": [v6]},
            ]
        if obj == "file" and method == "exec":
            return self.file_exec(args)
        if obj == "file" and method == "read":
            path = str(args.get("path"))
            if f"file:{path}" in self.denied or not any(
                fnmatchcase(path, allowed) for allowed in FILES
            ):
                return [DENIED]
            if path.startswith("/sys/class/net/"):
                if path.endswith("/brforward"):
                    return self.brforward(path.split("/")[4], bool(args.get("base64")))
                if "/bonding" in path:
                    return self.bond_file(path.removeprefix("/sys/class/net/"))
                value = self.sysfs_net(path)
                return [NOT_FOUND] if value is None else [0, {"data": f"{value}\n"}]
            if path == UPNP_LEASES:
                if "upnpd" not in self.packages:
                    return [NOT_FOUND]
                return [0, {"data": upnp_leases(time.time())}]
            if path.startswith("/var/run/openvpn.") and path.endswith(".status"):
                server = path == "/var/run/openvpn.road_warrior.status"
                if "openvpn" not in self.packages or not server:
                    return [NOT_FOUND]
                return [0, {"data": openvpn_status(time.time())}]
            if path == "/etc/swanctl/swanctl.conf":
                return [0, {"data": SWANCTL_CONF}] if "strongswan" in self.packages else [NOT_FOUND]
            if path == AVAHI_CONF:
                return [0, {"data": AVAHI_TEXT}] if "avahi" in self.packages else [NOT_FOUND]
            if path.startswith("/var/run/ddns/"):
                files = {"home.update": "1795000000\n", "home.ip": "203.0.113.45\n"}
                text = files.get(path.removeprefix("/var/run/ddns/"))
                return (
                    [NOT_FOUND]
                    if text is None or "ddns" not in self.packages
                    else [0, {"data": text}]
                )
            if path.startswith("/sys/class/thermal/thermal_zone"):
                n, _, leaf = path.removeprefix("/sys/class/thermal/thermal_zone").partition("/")
                if not n.isdigit() or int(n) >= len(self.thermal_zones):
                    return [NOT_FOUND]
                kind, milli = self.thermal_zones[int(n)]
                return [0, {"data": f"{milli}\n" if leaf == "temp" else f"{kind}\n"}]
            mac, ip, name = LEASE
            text = f"4102444800 {mac} {ip} {name} 01:{mac}\n0 bogus x * *\nshort\n"
            return [0, {"data": text}]
        if obj == "dhcp" and method == "ipv6leases":
            duid = "00030001" + FIXED_MAC.format(3).replace(":", "")
            lease = {
                "duid": duid,
                "iaid": 1,
                "hostname": "laptop",
                "assigned": 1,
                "flags": ["bound"],
                "ipv6-addr": [
                    {"address": "2001:db8::1a2", "preferred-lifetime": 3000, "valid-lifetime": 3600}
                ],
            }
            return [0, {"device": {"br-lan": {"leases": [lease]}}}]
        if obj == "mwan3" and "mwan3" in self.packages:
            return [0, MWAN3_STATUS] if method == "status" else [3]
        if obj == "luci.wireguard" and self.luci_wireguard:
            return [0, self.wg_instances()] if method == "getWgInstances" else [3]
        if obj == "luci.lldpd" and self.lldpd:
            return [0, lldp_status()] if method == "getStatus" else [3]
        return None

    def brforward(self, bridge: str, b64: bool) -> list[Any]:
        """``/sys/class/net/<bridge>/brforward`` (#378): 16-byte ``struct __fdb_entry`` records
        (little-endian, as on x86), base64 when asked (rpcd's ``file read``)."""
        if not self.brforward_acl:
            return [DENIED]
        status = self._device_status()
        st = status.get(bridge)
        if not isinstance(st, dict) or st.get("type") != "bridge":
            return [NOT_FOUND]
        members = [str(m) for m in st.get("bridge-members", [])]
        rows: list[tuple[str, int, bool, int]] = []
        for no, member in enumerate(members, 1):
            mac = (status.get(member) or {}).get("macaddr")
            if mac:
                rows.append((str(mac), no, True, 0))
        rows += [
            (mac, members.index(m) + 1, False, age) for m, mac, age in self.learned if m in members
        ]
        raw = bytearray()
        for mac, no, local, age in rows:
            rec = bytearray(16)
            rec[:6] = bytes(int(x, 16) for x in mac.split(":"))
            rec[6], rec[7], rec[12] = no & 0xFF, int(local), no >> 8
            rec[8:12] = (age * 100).to_bytes(4, "little")
            raw += rec
        if not raw:
            return [NO_DATA]  # rpcd: an empty file is "no data"
        data = base64.b64encode(bytes(raw)).decode() if b64 else raw.decode("latin-1")
        return [0, {"data": data}]

    def bond_file(self, rel: str) -> list[Any]:
        """``/sys/class/net/<rel>`` of the bond (#157)."""
        if self.bond is None or not self.bond_sysfs:
            return [NOT_FOUND] if self.bond is None else [DENIED]
        if rel == "bond0/bonding/mode":
            return [0, {"data": f"{self.bond} {_KERNEL_MODES.get(self.bond, 0)}\n"}]
        if rel not in BOND_SYSFS:
            return [NOT_FOUND]
        return [0, {"data": BOND_SYSFS[rel] + "\n"}]

    def sysfs_net(self, path: str) -> str | None:
        """``/sys/class/net/<bridge>/bridge/*`` and ``/sys/class/net/<port>/brport/*`` (#155):
        the kernel's STP of a bridge with ``option stp 1``, the bridge the root; None where the
        kernel has no such file (no bridge, a port in none, ``no_brport``)."""
        name, _, rest = path.removeprefix("/sys/class/net/").partition("/")
        group, _, leaf = rest.partition("/")
        status = self._device_status()
        bridges = {n: st for n, st in status.items() if st.get("type") == "bridge"}
        settings = {
            str(sec.get("name")): sec
            for _, sec in _of(self.state["network"], "device")
            if sec.get("type") == "bridge"
        }
        if group == "bridge" and name in bridges:
            prio = int(str(settings.get(name, {}).get("priority", 0x7FFF)))
            own = f"{prio:04x}." + str(bridges[name]["macaddr"]).replace(":", "")
            on = str(settings.get(name, {}).get("stp", "0")) == "1"
            members = list(bridges[name].get("bridge-members", []))
            root_no = members.index(self.stp_root_port) + 1 if self.stp_root_port in members else 0
            values = {
                "bridge_id": own,
                # another bridge is the root when a member is the root port (#529)
                "root_id": "1000.020000ff0001" if root_no else own,
                "root_port": str(root_no),
                "root_path_cost": "100" if root_no else "0",
                "stp_state": "1" if on else "0",
                "priority": str(prio),
                # multicast (#161): snooping on, the bridge is the querier unless the test says not
                "multicast_snooping": "1",
                "multicast_querier": "1" if self.querier else "0",
                "multicast_igmp_version": "2",
                "multicast_mld_version": "1",
            }
            return values.get(leaf)
        for st in bridges.values():
            members = list(st.get("bridge-members", []))
            if group == "brport" and name in members and name not in self.no_brport:
                values = {
                    "state": "3",
                    "port_no": f"0x{members.index(name) + 1:x}",
                    "path_cost": "100" if name.startswith("phy") else "4",
                    "bpdu_guard": "0",
                    "root_block": "0",
                    "multicast_fast_leave": "0",
                    "multicast_flood": "1",
                }
                return values.get(leaf)
        return None

    def file_exec(self, args: dict[str, Any]) -> list[Any]:
        """rpcd ``file exec``: only the WireGuard key helper of the write ACL (#152). It gives
        an interface Signalbox created a private key (marked ``do-not-leak``) in the live
        configuration, as the script's ``uci commit`` does, and prints nothing."""
        if "network" not in self.writable or "file:exec" in self.denied:
            return [DENIED]  # a read-only login, or an ACL from before #152
        if args.get("command") != WG_KEY_HELPER:
            return [DENIED]
        if not self.wg_key_helper:
            return [NOT_FOUND]
        params = [str(p) for p in args.get("params") or []]
        if params == ["--check"]:
            return [0, {"code": 0}]
        if len(params) != 1:
            return [0, {"code": 2}]
        section = self.state["network"].get(params[0])
        if (
            not isinstance(section, dict)
            or section.get("proto") != "wireguard"
            or not section.get("signalbox")
        ):
            return [0, {"code": 3}]
        section.setdefault("private_key", wg_private_key(params[0]))
        self.history.append(f"wg-key {params[0]}")
        return [0, {"code": 0}]

    def wg_instances(self) -> dict[str, Any]:
        """``luci.wireguard getWgInstances``: running state, public data only. Interfaces other
        than the sample's ``wg0`` (created by a deployment) report the public key of the key
        the helper generated, and their peers without a handshake."""
        out: dict[str, Any] = {}
        for name, s in _of(self.state["network"], "interface"):
            if s.get("proto") != "wireguard" or name == "wg0":
                continue
            entry: dict[str, Any] = {"name": name, "peers": []}
            if s.get("private_key"):
                entry["public_key"] = wg_public_key(name)
            if str(s.get("listen_port") or "").isdigit():
                entry["listen_port"] = int(s["listen_port"])
            for _, p in _of(self.state["network"], f"wireguard_{name}"):
                entry["peers"].append(
                    {
                        "public_key": p.get("public_key"),
                        "endpoint": "(none)",
                        "allowed_ips": p.get("allowed_ips") or [],
                        "latest_handshake": 0,
                        "transfer_rx": 0,
                        "transfer_tx": 0,
                        "persistent_keepalive": p.get("persistent_keepalive") or "off",
                    }
                )
            out[name] = entry
        if not any(
            s.get("proto") == "wireguard" and name == "wg0"
            for name, s in _of(self.state["network"], "interface")
        ):
            return out
        return out | {
            "wg0": {
                "name": "wg0",
                "public_key": WG_KEY,
                "listen_port": 51820,
                "peers": [
                    {
                        "public_key": WG_SITE_A,
                        "endpoint": "203.0.113.10:51820",
                        "allowed_ips": ["2001:db8:ff::1/128", "192.0.2.0/24"],
                        "latest_handshake": int(time.time()) - self.wg_handshake_ago,
                        "transfer_rx": 1834567,
                        "transfer_tx": 2934871,
                        "persistent_keepalive": 25,
                    },
                    {
                        "public_key": WG_PHONE,
                        "endpoint": "(none)",
                        "allowed_ips": ["2001:db8:ff::3/128"],
                        "latest_handshake": 0,
                        "transfer_rx": 0,
                        "transfer_tx": 0,
                        "persistent_keepalive": "off",
                    },
                ],
            }
        }

    async def handle(self, body: bytes) -> Response:
        self.requests += 1
        try:
            req = json.loads(body)
            rid, params = req.get("id"), req["params"]
            sid, obj, method = params[0], params[1], params[2]
            args = params[3] if len(params) > 3 else {}
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            return self._error(None, -32700, "Parse error")
        if self.delay and (not self.slow or obj in self.slow or f"{obj}.{method}" in self.slow):
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
        if obj == "session" and method == "destroy":
            self.sessions.pop(sid, None)
            self.staged.pop(sid, None)
            return self._result(rid, [0])
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
