"""Simulated OpenWrt access point speaking ubus JSON-RPC at ``POST /ubus``.

Neutral sample data: an access point with DSA ports ``lan1``..``lan4`` on bridge ``br-lan``,
VLAN 1 ("lan", untagged on lan1-3) and VLAN 20 ("iot", tagged on lan1), two radios, the SSIDs
"Example" (WPA2/WPA3, 802.11r) and "Example-IoT" (WPA2, VLAN 20), three stations and DHCP
switched off (the gateway serves it). Failure switches on :class:`OpenWrtSim` change the
answers for refused-path tests. Answer shapes follow the OpenWrt documentation and source; see
``docs/adapters/openwrt.md``.

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
from ipaddress import ip_interface
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

NO_SESSION = "0" * 32
MAC = "02:00:00:00:{:02x}:{:02x}"
#: UCI configs the simulator knows
CONFIGS = ("network", "wireless", "dhcp")

Sections = dict[str, dict[str, Any]]
"""One UCI config: section name -> {".type", ".anonymous", options}, in order."""


def _mac(a: int, b: int) -> str:
    return MAC.format(a, b)


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
    )


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
        }

    status: dict[str, Any] = {f"lan{n}": eth(n < 4) for n in range(1, 5)}
    status["eth0"] = eth(True) | {"speed": "2500F"}
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
                **({"dhcp_option": ["6,192.0.2.1,192.0.2.53"]} if router else {"ignore": "1"}),
            },
        ),
        ("dhcp", "wan", {"interface": "wan", "ignore": "1"}),
        ("host", "cfg06fe63", {"name": "printer", "mac": _mac(0x10, 1), "ip": "192.0.2.50"}),
        ("host", "cfg07fe63", {"name": "faraway", "mac": _mac(0x10, 2), "ip": "203.0.113.9"}),
    )


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
    """Run one staged ``uci`` operation on a config (in place); the ubus result."""
    section = args.get("section")
    if method == "add":
        kind = args.get("type")
        if not isinstance(kind, str) or not kind:
            return [INVALID_ARGUMENT]
        name = args.get("name")
        anonymous = not name
        name = name or f"cfg{counter:06x}"
        if name in config:
            return [INVALID_ARGUMENT]
        config[name] = {".anonymous": anonymous, ".type": kind}
        config[name].update({k: _uci_value(v) for k, v in (args.get("values") or {}).items()})
        return [OK, {"section": name}]
    if method == "order":
        names = [n for n in args.get("sections") or [] if n in config]
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
    # delete
    options = list(args.get("options") or []) + ([args["option"]] if args.get("option") else [])
    if options:
        for option in options:
            config[section].pop(option, None)
    else:
        del config[section]
    return [OK]


@dataclass
class OpenWrtSim:
    """State and failure switches of the simulator; mutate between requests."""

    username: str = "signalbox"
    password: str = "example-password"
    session_ttl: float = 300.0
    #: ``object``, ``object.method`` or ``uci:<config>`` entries the ACL does not allow
    denied: set[str] = field(default_factory=set)
    #: UCI configs the ACL lets the user change (``write`` → ``uci`` in the rpcd ACL)
    writable: set[str] = field(default_factory=lambda: set(CONFIGS))
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
    #: time source of sessions and the rollback timer (replace it to test the timer)
    clock: Callable[[], float] = time.monotonic
    sessions: dict[str, float] = field(default_factory=dict)
    logins: int = 0
    requests: int = 0
    #: committed UCI configs (built on first use, so ``router`` can be set after ``reset``)
    configs: dict[str, Sections] | None = None
    #: session -> config -> staged operations (``uci changes``)
    staged: dict[str, dict[str, list[tuple[str, dict[str, Any]]]]] = field(default_factory=dict)
    #: the ``uci apply`` waiting for ``uci confirm``: session, deadline, configs before it
    pending: tuple[str, float, dict[str, Sections]] | None = None
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
            }
        return self.configs

    def tick(self) -> None:
        """The rollback timer: past the deadline, the configs before the apply come back."""
        if self.pending is not None and self.clock() >= self.pending[1]:
            self.configs = self.pending[2]
            self.pending = None
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
            if config not in CONFIGS:
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
            self.staged.get(sid, {}).pop(config, None)
            if not self.staged.get(sid, True):
                del self.staged[sid]
            self.history.append(f"revert {config}")
            return [OK]
        if method == "changes":
            staged = self.staged.get(sid, {})
            return [OK, {"changes": {c: [[m, a] for m, a in ops] for c, ops in staged.items()}}]
        if method == "apply":
            return self._apply(sid, args)
        if method in ("confirm", "rollback"):
            if self.pending is None or self.pending[0] != sid:
                return [DENIED]
            if method == "rollback":
                self.configs = self.pending[2]
            self.pending = None
            self.history.append(method)
            return [OK]
        return None

    def _apply(self, sid: str, args: dict[str, Any]) -> list[Any]:
        if self.pending is not None:
            return [DENIED]  # rpcd: another apply waits for its confirmation
        staged = self.staged.pop(sid, {})
        if not staged:
            return [NO_DATA]
        before = copy.deepcopy(self.state)
        for config, ops in staged.items():
            for method, op_args in ops:
                uci_op(self.state[config], method, op_args, 0)
        if args.get("rollback"):
            timeout = float(args.get("timeout", 30))
            self.pending = (sid, self.clock() + timeout, before)
        self.history.append("apply")
        return [OK]

    def _data(self, sid: str, obj: str, method: str, args: dict[str, Any]) -> list[Any] | None:
        """ubus result list, or None when the object does not exist."""
        if obj == "system" and method == "board":
            return [0, board()]
        if obj == "system" and method == "info":
            return [0, {"localtime": 1700000000, "uptime": 86400, "load": [0, 0, 0]}]
        if obj == "network.device" and method == "status":
            return [0, device_status(self.state["network"], self.state["wireless"])]
        if obj == "network.interface" and method == "dump":
            return [0, interface_dump(self.state["network"])]
        if obj == "network.wireless" and method == "status":
            return [0, wireless_status(self.state["wireless"])]
        if obj == "uci":
            return self._uci(sid, method, args)
        if obj.startswith("hostapd."):
            running = {ifname: s for s, _, ifname, mode in running_ifaces(self.state["wireless"])}
            if obj[8:] in running:
                ifname = obj[8:]
                return [0, clients(ifname, running[ifname])] if method == "get_clients" else [3]
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
