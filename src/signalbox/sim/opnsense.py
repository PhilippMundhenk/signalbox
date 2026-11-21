"""Simulator of the OPNsense REST API endpoints the ``opnsense`` adapter reads.

The answers follow the JSON shapes in ``docs/adapters/opnsense.md`` (from the public API docs,
not yet confirmed on a real device, issue #21). Sample network, documentation addresses only:

- LAN ``igb0`` untagged, 192.0.2.1/24 and 2001:db8:1::1/64, Kea DHCP
- VLAN 20 "IoT" on ``igb0``, 198.51.100.1/24, Kea DHCP with its own options
- VLAN 30 "Guest" on ``igb0``, 203.0.113.1/24, ISC DHCP
- VLAN 40 "Lab" defined but not assigned; WAN ``igb1`` (uplink, 2001:db8:ffff::2/64)
- Unbound with forwarders and host overrides; ARP and NDP entries; DHCP leases

Failure switches on :class:`OpnsenseSimulator`: ``api_enabled=False`` (404 on everything),
``delay`` (seconds before every answer), ``malformed`` (endpoints answering broken JSON),
``fail`` (a status code per endpoint);
a wrong key or secret is answered with 401. ``data`` can be edited by tests.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import secrets
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

KEY = "sim-key"
SECRET = "sim-secret"


def _opt(selected: dict[str, tuple[str, bool]]) -> dict[str, dict[str, Any]]:
    """An OPNsense option field: ``{key: {"value": label, "selected": 0|1}}``."""
    return {k: {"value": v, "selected": int(on)} for k, (v, on) in selected.items()}


def _iface(device: str, ident: str, descr: str, **kw: Any) -> dict[str, Any]:
    return {
        "device": device,
        "identifier": ident,
        "description": descr,
        "enabled": True,
        "status": "up",
        "macaddr": kw.pop("mac", "02:00:00:00:01:00"),
        "media": kw.pop("media", ""),
        "is_physical": kw.pop("physical", False),
        "vlan_tag": kw.pop("vlan", None),
        "ipv4": [{"ipaddr": a} for a in kw.pop("v4", [])],
        "ipv6": [{"ipaddr": a, "link-local": a.startswith("fe80")} for a in kw.pop("v6", [])],
        **kw,
    }


def sample_data() -> dict[str, Any]:
    """Answers by endpoint path (a fresh copy every call)."""
    lan_ifaces = {"lan": ("LAN", True), "opt1": ("IoT", True), "opt2": ("Guest", False)}
    data: dict[str, Any] = {
        "/api/core/firmware/status": {
            "status": "update",
            "status_msg": "There are 3 updates available.",
            "product": {
                "product_name": "OPNsense",
                "product_version": "24.7.1",
                "product_latest": "24.7.2",
                "product_arch": "amd64",
            },
        },
        "/api/interfaces/overview/interfacesInfo": {
            "total": 6,
            "rowCount": 6,
            "current": 1,
            "rows": [
                _iface(
                    "igb0",
                    "lan",
                    "LAN",
                    media="1000baseT <full-duplex>",
                    physical=True,
                    v4=["192.0.2.1/24"],
                    v6=["2001:db8:1::1/64", "fe80::1/64"],
                ),
                _iface(
                    "igb1",
                    "wan",
                    "WAN",
                    mac="02:00:00:00:02:00",
                    media="2500Base-T <full-duplex>",
                    physical=True,
                    v6=["2001:db8:ffff::2/64"],
                ),
                _iface("vlan01", "opt1", "IoT", vlan=20, v4=["198.51.100.1/24"]),
                _iface("vlan02", "opt2", "Guest", vlan=30, v4=["203.0.113.1/24"]),
                _iface(
                    "igb2",
                    "",
                    "",
                    mac="02:00:00:00:03:00",
                    status="no carrier",
                    media="autoselect",
                    physical=True,
                ),
                _iface("lo0", "lo0", "Loopback", mac="", v4=["127.0.0.1/8"], v6=["::1/128"]),
            ],
        },
        "/api/interfaces/vlan_settings/searchItem": {
            "total": 3,
            "rowCount": 3,
            "current": 1,
            "rows": [
                {"uuid": "v-20", "vlanif": "vlan01", "if": "igb0", "tag": "20", "descr": "IoT"},
                {"uuid": "v-30", "vlanif": "vlan02", "if": "igb0", "tag": "30", "descr": "Guest"},
                {"uuid": "v-40", "vlanif": "vlan03", "if": "igb0", "tag": "40", "descr": "Lab"},
            ],
        },
        "/api/kea/dhcpv4/get": {
            "dhcpv4": {
                "general": {
                    "enabled": "1",
                    "interfaces": _opt(lan_ifaces),
                    "valid_lifetime": "4000",
                },
                "subnets": {
                    "subnet4": {
                        "s-lan": {
                            "subnet": "192.0.2.0/24",
                            "pools": "192.0.2.100-192.0.2.199",
                            "option_data_autocollect": "1",
                            "option_data": {"routers": "", "domain_name_servers": ""},
                            "description": "LAN",
                        },
                        "s-iot": {
                            "subnet": "198.51.100.0/24",
                            "pools": "198.51.100.128/26\n198.51.100.200-198.51.100.210",
                            "option_data_autocollect": "0",
                            "option_data": {
                                "routers": "198.51.100.1",
                                "domain_name_servers": "198.51.100.1,192.0.2.1",
                                "domain_name": "iot.example",
                            },
                            "description": "IoT",
                        },
                    }
                },
                "reservations": {
                    "reservation": {
                        "r-1": {
                            "subnet": _opt({"s-lan": ("192.0.2.0/24", True)}),
                            "ip_address": "192.0.2.10",
                            "hw_address": "02:00:00:00:00:10",
                            "hostname": "printer",
                        },
                        "r-2": {
                            "subnet": _opt({"s-iot": ("198.51.100.0/24", True)}),
                            "ip_address": "198.51.100.20",
                            "hw_address": "02:00:00:00:00:20",
                            "hostname": "sensor",
                        },
                    }
                },
            }
        },
        "/api/kea/leases4/search": {
            "total": 1,
            "rows": [
                {
                    "address": "192.0.2.100",
                    "hwaddr": "02:00:00:00:00:21",
                    "hostname": "laptop",
                    "if_name": "lan",
                    "if_descr": "LAN",
                }
            ],
        },
        "/api/dhcpv4/service/status": {"status": "running"},
        "/api/dhcpv4/leases/searchLease": {
            "total": 2,
            "interfaces": {"opt2": "Guest"},
            "rows": [
                {
                    "address": "203.0.113.150",
                    "mac": "02:00:00:00:00:31",
                    "hostname": "guest-phone",
                    "if": "opt2",
                    "if_descr": "Guest",
                    "type": "dynamic",
                    "status": "online",
                    "state": "active",
                },
                {
                    "address": "203.0.113.10",
                    "mac": "02:00:00:00:00:30",
                    "hostname": "kiosk",
                    "if": "opt2",
                    "if_descr": "Guest",
                    "type": "static",
                    "status": "offline",
                    "state": "",
                },
            ],
        },
        "/api/unbound/settings/get": {
            "unbound": {
                "general": {
                    "enabled": "1",
                    "port": "53",
                    "active_interface": _opt(
                        {"lan": ("LAN", True), "opt1": ("IoT", True), "opt2": ("Guest", False)}
                    ),
                },
                "dots": {
                    "dot": {
                        "d-1": {
                            "enabled": "1",
                            "type": "forward",
                            "domain": "",
                            "server": "192.0.2.53",
                            "port": "53",
                        },
                        "d-2": {
                            "enabled": "1",
                            "type": "dot",
                            "domain": "",
                            "server": "2001:db8:53::53",
                            "port": "853",
                        },
                        "d-3": {
                            "enabled": "1",
                            "type": "forward",
                            "domain": "corp.example",
                            "server": "198.51.100.53",
                        },
                        "d-4": {"enabled": "0", "type": "forward", "server": "192.0.2.54"},
                    }
                },
            }
        },
        "/api/unbound/settings/searchHostOverride": {
            "total": 4,
            "rows": [
                {
                    "uuid": "h-1",
                    "enabled": "1",
                    "hostname": "nas",
                    "domain": "home.example",
                    "rr": "A",
                    "server": "192.0.2.10",
                },
                {
                    "uuid": "h-2",
                    "enabled": "1",
                    "hostname": "nas",
                    "domain": "home.example",
                    "rr": "AAAA",
                    "server": "2001:db8:1::10",
                },
                {
                    "uuid": "h-3",
                    "enabled": "0",
                    "hostname": "old",
                    "domain": "home.example",
                    "rr": "A",
                    "server": "192.0.2.11",
                },
                {
                    "uuid": "h-4",
                    "enabled": "1",
                    "hostname": "",
                    "domain": "home.example",
                    "rr": "MX",
                    "mx": "mail.home.example",
                    "server": "",
                },
            ],
        },
        "/api/diagnostics/interface/getArp": [
            {
                "mac": "02:00:00:00:00:10",
                "ip": "192.0.2.10",
                "intf": "igb0",
                "expired": False,
                "expires": 1100,
                "permanent": False,
                "type": "ethernet",
                "manufacturer": "",
                "hostname": "printer.home.example",
                "intf_description": "LAN",
            },
            {
                "mac": "02:00:00:00:00:21",
                "ip": "192.0.2.100",
                "intf": "igb0",
                "permanent": False,
                "hostname": "",
            },
            {"mac": "02:00:00:00:00:20", "ip": "198.51.100.20", "intf": "vlan01", "hostname": ""},
            {"mac": "02:00:00:00:01:00", "ip": "192.0.2.1", "intf": "igb0", "permanent": True},
            {"mac": "(incomplete)", "ip": "192.0.2.99", "intf": "igb0"},
        ],
        "/api/diagnostics/interface/getNdp": [
            {"mac": "02:00:00:00:00:10", "ip": "2001:db8:1::10", "intf": "igb0"},
            {"mac": "02:00:00:00:00:10", "ip": "fe80::10%igb0", "intf": "igb0"},
        ],
    }
    return copy.deepcopy(data)


@dataclass
class OpnsenseSimulator:
    api_key: str = KEY
    api_secret: str = SECRET
    api_enabled: bool = True
    delay: float = 0.0
    malformed: set[str] = field(default_factory=set)
    #: Status code to answer per path instead of the data (403, 500, ...).
    fail: dict[str, int] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=sample_data)
    #: Paths requested so far (to check that nothing is sent before the pin check).
    requests: list[str] = field(default_factory=list)

    def authorised(self, header: str | None) -> bool:
        if not header or not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        return secrets.compare_digest(user, self.api_key) and secrets.compare_digest(
            password, self.api_secret
        )

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

        @app.api_route("/{path:path}", methods=["GET", "POST"])
        async def answer(path: str, request: Request) -> Response:
            path = "/" + path
            self.requests.append(path)
            if not self.api_enabled:
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            if not self.authorised(request.headers.get("authorization")):
                return JSONResponse(
                    {"status": 401, "message": "Authentication Failed"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="api"'},
                )
            if self.delay:
                await asyncio.sleep(self.delay)
            if path in self.fail:
                return JSONResponse({"message": "simulated failure"}, status_code=self.fail[path])
            if path not in self.data:
                return JSONResponse({"errorMessage": "Endpoint not found"}, status_code=404)
            if path in self.malformed:
                return Response('{"rows": [', media_type="application/json")
            return JSONResponse(self.data[path])

        return app
