"""Simulated OpenWrt access point speaking ubus JSON-RPC at ``POST /ubus``.

Neutral sample data: an access point with DSA ports ``lan1``..``lan4`` on bridge ``br-lan``,
VLAN 1 ("lan", untagged on lan1-3) and VLAN 20 ("iot", tagged on lan1), two radios, the SSIDs
"Example" (WPA2/WPA3, 802.11r) and "Example-IoT" (WPA2, VLAN 20), three stations and DHCP
switched off (the gateway serves it). Failure switches on :class:`OpenWrtSim` change the
answers for refused-path tests. Answer shapes follow the OpenWrt documentation and source; see
``docs/adapters/openwrt.md``.

Serve it with any ASGI server, for example
``uvicorn --factory signalbox.sim.openwrt:create_app``.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

NO_SESSION = "0" * 32
MAC = "02:00:00:00:{:02x}:{:02x}"


def _mac(a: int, b: int) -> str:
    return MAC.format(a, b)


def _uci(*sections: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
    """``uci get`` answer from (type, name, options); names starting with ``cfg`` are anonymous."""
    return {
        "values": {
            name: {
                ".anonymous": name.startswith("cfg"),
                ".type": kind,
                ".name": name,
                ".index": i,
                **options,
            }
            for i, (kind, name, options) in enumerate(sections)
        }
    }


def network_config() -> dict[str, Any]:
    return _uci(
        ("interface", "loopback", {"device": "lo", "proto": "static", "ipaddr": "127.0.0.1"}),
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
        (
            "interface",
            "lan",
            {
                "device": "br-lan.1",
                "proto": "static",
                "ipaddr": "192.0.2.2/24",
                "gateway": "192.0.2.1",
                "ip6addr": "2001:db8::2/64",
            },
        ),
        ("interface", "iot", {"device": "br-lan.20", "proto": "none"}),
    )


def interface_dump(router: bool) -> dict[str, Any]:
    lan_routes = (
        []
        if router
        else [{"target": "0.0.0.0", "mask": 0, "nexthop": "192.0.2.1", "source": "0.0.0.0/0"}]
    )
    return {
        "interface": [
            {
                "interface": "lan",
                "up": True,
                "proto": "static",
                "device": "br-lan.1",
                "l3_device": "br-lan.1",
                "ipv4-address": [{"address": "192.0.2.2", "mask": 24}],
                "ipv6-address": [{"address": "2001:db8::2", "mask": 64}],
                "route": lan_routes,
                "dns-server": ["192.0.2.1"],
            },
            {
                "interface": "iot",
                "up": True,
                "proto": "none",
                "device": "br-lan.20",
                "l3_device": "br-lan.20",
                "ipv4-address": [],
                "ipv6-address": [],
                "route": [],
            },
            {
                "interface": "loopback",
                "up": True,
                "proto": "static",
                "device": "lo",
                "l3_device": "lo",
                "ipv4-address": [{"address": "127.0.0.1", "mask": 8}],
                "route": [],
            },
        ]
    }


def device_status() -> dict[str, Any]:
    def eth(n: int, carrier: bool) -> dict[str, Any]:
        return {
            "external": False,
            "present": True,
            "type": "Network device",
            "up": True,
            "carrier": carrier,
            "mtu": 1500,
            "macaddr": _mac(0, 1),
            "speed": "1000F" if carrier else "-1F",
        }

    status: dict[str, Any] = {f"lan{n}": eth(n, n < 4) for n in range(1, 5)}
    status["eth0"] = eth(0, True) | {"speed": "2500F"}
    status["br-lan"] = {
        "type": "bridge",
        "up": True,
        "carrier": True,
        "macaddr": _mac(0, 1),
        "mtu": 1500,
        "bridge-members": ["lan1", "lan2", "lan3", "lan4", "phy0-ap0", "phy0-ap1", "phy1-ap0"],
    }
    status["br-lan.1"] = {"type": "VLAN", "up": True, "carrier": True, "macaddr": _mac(0, 1)}
    status["br-lan.20"] = {"type": "VLAN", "up": True, "carrier": True, "macaddr": _mac(0, 1)}
    status["lo"] = {"type": "Network device", "up": True, "carrier": True}
    for i, name in enumerate(("phy0-ap0", "phy0-ap1", "phy1-ap0")):
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


#: wifi-iface section -> ifname of the running interface
IFNAMES = {"default_radio0": "phy0-ap0", "iot_radio0": "phy0-ap1", "default_radio1": "phy1-ap0"}
STATIONS = {
    "phy0-ap0": [_mac(0x20, 1)],
    "phy0-ap1": [_mac(0x20, 2)],
    "phy1-ap0": [_mac(0x20, 3)],
}


def wireless_status() -> dict[str, Any]:
    def radio(sections: list[str]) -> dict[str, Any]:
        return {
            "up": True,
            "pending": False,
            "autostart": True,
            "disabled": False,
            "retry_setup_failed": False,
            "config": {},
            "interfaces": [{"section": s, "ifname": IFNAMES[s], "config": {}} for s in sections],
        }

    return {
        "radio0": radio(["default_radio0", "iot_radio0"]),
        "radio1": radio(["default_radio1"]),
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
                **({"dhcp_option": ["6,192.0.2.1,192.0.2.53"]} if router else {"ignore": "1"}),
            },
        ),
        ("dhcp", "wan", {"interface": "wan", "ignore": "1"}),
        ("host", "cfg06fe63", {"name": "printer", "mac": _mac(0x10, 1), "ip": "192.0.2.50"}),
        ("host", "cfg07fe63", {"name": "faraway", "mac": _mac(0x10, 2), "ip": "203.0.113.9"}),
    )


def clients(ifname: str) -> dict[str, Any]:
    return {
        "freq": 2437 if ifname.startswith("phy0") else 5180,
        "clients": {
            mac: {"auth": True, "assoc": True, "authorized": True, "signal": -55, "aid": 1}
            for mac in STATIONS[ifname]
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


def lldp_neighbours() -> dict[str, Any]:
    """lldpcli ``-f json0`` shape."""
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


@dataclass
class OpenWrtSim:
    """State and failure switches of the simulator; mutate between requests."""

    username: str = "signalbox"
    password: str = "example-password"
    session_ttl: float = 300.0
    #: ``object``, ``object.method`` or ``uci:<config>`` entries the ACL does not allow
    denied: set[str] = field(default_factory=set)
    #: objects answered with broken JSON (``*``: every request)
    malformed: set[str] = field(default_factory=set)
    #: objects answered with valid JSON of the wrong shape
    odd: set[str] = field(default_factory=set)
    #: seconds to wait before answering (``slow`` objects only, or every request if empty)
    delay: float = 0.0
    slow: set[str] = field(default_factory=set)
    lldpd: bool = True
    luci_rpc: bool = True
    #: DHCP on, no default route on lan: the device acts as the router of 192.0.2.0/24
    router: bool = False
    sessions: dict[str, float] = field(default_factory=dict)
    logins: int = 0
    requests: int = 0

    def reset(self) -> None:
        fresh = OpenWrtSim()
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(fresh, name))

    def expire_sessions(self) -> None:
        self.sessions.clear()

    # ubus ---------------------------------------------------------------------------

    def _login(self, args: dict[str, Any]) -> list[Any]:
        if args.get("username") != self.username or args.get("password") != self.password:
            return [6]
        self.logins += 1
        sid = secrets.token_hex(16)
        self.sessions[sid] = time.monotonic() + self.session_ttl
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

    def _data(self, obj: str, method: str, args: dict[str, Any]) -> list[Any] | None:
        """ubus result list, or None when the object does not exist."""
        if obj == "system" and method == "board":
            return [0, board()]
        if obj == "system" and method == "info":
            return [0, {"localtime": 1700000000, "uptime": 86400, "load": [0, 0, 0]}]
        if obj == "network.device" and method == "status":
            return [0, device_status()]
        if obj == "network.interface" and method == "dump":
            return [0, interface_dump(self.router)]
        if obj == "network.wireless" and method == "status":
            return [0, wireless_status()]
        if obj == "uci" and method == "get":
            configs: dict[str, Callable[[], dict[str, Any]]] = {
                "network": network_config,
                "wireless": wireless_config,
                "dhcp": lambda: dhcp_config(self.router),
            }
            config = str(args.get("config"))
            if f"uci:{config}" in self.denied:
                return [6]
            return [0, configs[config]()] if config in configs else [4]
        if obj.startswith("hostapd.") and obj[8:] in STATIONS:
            return [0, clients(obj[8:])] if method == "get_clients" else [3]
        if obj == "luci-rpc" and self.luci_rpc:
            if method != "getDHCPLeases":
                return [3]
            mac, ip, name = LEASE
            lease = {"expires": 43000, "hostname": name, "macaddr": mac, "ipaddr": ip}
            return [0, {"dhcp_leases": [lease, {"macaddr": "bogus"}], "dhcp6_leases": []}]
        if obj == "file" and method == "read":
            if args.get("path") != "/tmp/dhcp.leases":
                return [4]
            mac, ip, name = LEASE
            text = f"1700043000 {mac} {ip} {name} 01:{mac}\n1700043000 bogus x * *\nshort\n"
            return [0, {"data": text}]
        if obj == "lldpd" and self.lldpd:
            return [0, lldp_neighbours()] if method == "show_neighbours" else [3]
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
        if "*" in self.malformed or obj in self.malformed:
            return Response('{"jsonrpc": "2.0", "result": [0, {', media_type="application/json")
        if obj in self.odd:
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": "unexpected"})
        if obj == "session" and method == "login" and sid == NO_SESSION:
            return self._result(rid, self._login(args))
        expires = self.sessions.get(sid)
        if expires is None or expires < time.monotonic():
            self.sessions.pop(sid, None)
            return self._error(rid, -32002, "Access denied")
        if obj in self.denied or f"{obj}.{method}" in self.denied:
            return self._error(rid, -32002, "Access denied")
        result = self._data(obj, method, args)
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
