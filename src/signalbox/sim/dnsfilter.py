"""Simulators of AdGuard Home's REST API and Pi-hole v6's REST API (#304).

The shapes follow the public API descriptions (``docs/adapters/adguardhome.md``,
``docs/adapters/pihole.md``); they are not yet confirmed on a real device (#21). Documentation
addresses only: AdGuard Home at 192.0.2.53 forwards to the router 192.0.2.1 and to DNS over
TLS at 203.0.113.53; Pi-hole at 192.0.2.54 forwards to AdGuard Home (192.0.2.53).

Without credentials the simulators answer what the discovery probes read (#314): AdGuard
Home's 401 with its realm, Pi-hole's ``/api/info/login`` and ``/admin/``.

Pi-hole v5 (#385): with ``version="v5"`` there is no ``/api``; the legacy ``/admin/api.php``
and ``/admin/api_db.php`` answer ``?versions`` and ``?status`` without a token and
``?getForwardDestinations`` and ``?network`` only with ``auth=<token>`` (a wrong token gets an
empty list, as the real one does, guess #21). ``PiholeSim.queries`` lists every request with
its query, so tests can see where the token went.

Switches: ``AdGuardSim.dhcp_enabled``, ``upstream_file``, ``fail`` (path -> HTTP status),
``PiholeSim.version`` (``"v6"``, ``"v5"`` or ``"other"``: nothing answers), ``token`` (v5),
``dhcp_active``, ``max_sessions`` (more: HTTP 429), ``fail``, ``totp`` (a login that needs a
second factor). ``PiholeSim.sessions`` and ``logouts`` show that sessions end.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

AG_USER = "signalbox"
AG_PASSWORD = "adguard-sim-password"
PH_PASSWORD = "pihole-sim-app-password"
#: the v5 API token is a hash of the password: made at runtime, no secret-looking literal
PH_TOKEN = hashlib.sha256(b"signalbox pihole simulator").hexdigest()

MAC_LAPTOP = "02:00:5e:00:53:10"
MAC_NAS = "02:00:5e:00:53:11"
MAC_PHONE = "02:00:5e:00:53:12"


def _adguard_data() -> dict[str, Any]:
    return {
        "/control/status": {
            "dns_addresses": ["127.0.0.1", "192.0.2.53", "2001:db8::53", "fe80::1"],
            "dns_port": 53,
            "http_port": 3000,
            "protection_enabled": True,
            "dhcp_available": True,
            "running": True,
            "version": "v0.107.52",
            "language": "en",
        },
        "/control/dns_info": {
            "upstream_dns": [
                "192.0.2.1",
                "tls://203.0.113.53",
                "https://dns.example.net/dns-query",
                "[/example.lan/]192.0.2.1:5353",
                "# comment",
            ],
            "upstream_dns_file": "",
            "bootstrap_dns": ["203.0.113.9"],
            "upstream_mode": "load_balance",
            "protection_enabled": True,
        },
        "/control/dhcp/status": {
            "interface_name": "eth0",
            "v4": {
                "gateway_ip": "192.0.2.1",
                "subnet_mask": "255.255.255.0",
                "range_start": "192.0.2.100",
                "range_end": "192.0.2.199",
                "lease_duration": 86400,
                "icmp_timeout_msec": 1000,
            },
            "v6": {"range_start": "2001:db8::100", "lease_duration": 86400},
            "leases": [
                {
                    "mac": MAC_LAPTOP,
                    "ip": "192.0.2.101",
                    "hostname": "laptop",
                    "expires": "2030-01-01T10:00:00Z",
                },
                {
                    "mac": MAC_PHONE,
                    "ip": "192.0.2.102",
                    "hostname": "",
                    "expires": "2030-01-01T11:00:00Z",
                },
            ],
            "static_leases": [{"mac": MAC_NAS, "ip": "192.0.2.20", "hostname": "nas"}],
            "enabled": True,
        },
        "/control/clients": {
            "clients": [
                {"name": "Laptop", "ids": [MAC_LAPTOP, "192.0.2.101"]},
                {"name": "Kids", "ids": ["192.0.2.0/28"]},
                {"name": "NAS", "ids": [MAC_NAS.upper()]},
            ],
            "auto_clients": [{"name": "printer", "ip": "192.0.2.77", "source": "ARP"}],
            "supported_tags": [],
        },
        "/control/rewrite/list": [
            {"domain": "nas.example.lan", "answer": "192.0.2.20"},
            {"domain": "alias.example.lan", "answer": "nas.example.lan"},
        ],
    }


@dataclass
class AdGuardSim:
    username: str = AG_USER
    password: str = AG_PASSWORD
    data: dict[str, Any] = field(default_factory=_adguard_data)
    fail: dict[str, int] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)

    def upstream_file(self) -> None:
        self.data["/control/dns_info"]["upstream_dns_file"] = "/etc/upstreams.txt"
        self.data["/control/dns_info"]["upstream_dns"] = []

    def authorised(self, header: str | None) -> bool:
        if not header or not header.lower().startswith("basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except ValueError:
            return False
        return user == self.username and password == self.password

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
        async def answer(path: str, request: Request) -> Response:
            path = "/" + path
            self.requests.append((request.method, path))
            if not self.authorised(request.headers.get("authorization")):
                return Response(
                    "Unauthorized\n",
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="AdGuard Home"'},
                )
            if request.method != "GET":
                return Response("method not allowed\n", status_code=405)
            if path in self.fail:
                return Response("simulated failure\n", status_code=self.fail[path])
            if path not in self.data:
                return Response("404 page not found\n", status_code=404)
            return JSONResponse(copy.deepcopy(self.data[path]))

        return app


def _pihole_data() -> dict[str, Any]:
    return {
        "/api/info/version": {
            "version": {
                "core": {"local": {"branch": "master", "version": "v6.0.1", "hash": "abc"}},
                "ftl": {
                    "local": {"branch": "master", "version": "v6.0.2", "hash": "def"},
                    "remote": {"version": "v6.1", "hash": None},
                },
            },
            "took": 0.001,
        },
        "/api/config": {
            "config": {
                "dns": {
                    "upstreams": ["192.0.2.53", "203.0.113.53#5353", "2001:db8::1"],
                    "interface": "eth0",
                    "listeningMode": "LOCAL",
                    "port": 53,
                    "domain": {"name": "lan", "local": True},
                    "hosts": ["192.0.2.10 printer.lan printer", "192.0.2.11 cam.lan # camera"],
                    "revServers": ["true,192.0.2.0/24,192.0.2.1,lan", "false,198.51.100.0/24,x,y"],
                    "blocking": {"active": True, "mode": "NULL"},
                },
                "dhcp": {
                    "active": True,
                    "start": "192.0.2.150",
                    "end": "192.0.2.199",
                    "router": "192.0.2.1",
                    "netmask": "255.255.255.0",
                    "leaseTime": "24h",
                    "ipv6": False,
                    "hosts": [f"{MAC_NAS},192.0.2.20,nas", "garbage"],
                },
                "misc": {"dnsmasq_lines": ["dhcp-authoritative"]},
            },
            "took": 0.002,
        },
        "/api/network/devices": {
            "devices": [
                {
                    "id": 1,
                    "hwaddr": MAC_LAPTOP,
                    "interface": "eth0",
                    "firstSeen": 1893400000,
                    "lastQuery": 1893490000,
                    "numQueries": 12,
                    "macVendor": "",
                    "ips": [
                        {"ip": "192.0.2.151", "lastSeen": 1893491000, "name": "laptop"},
                        {"ip": "2001:db8::151", "lastSeen": 1893400100, "name": None},
                    ],
                },
                {
                    "id": 2,
                    "hwaddr": MAC_PHONE.upper(),
                    "interface": "eth0",
                    "firstSeen": 1893400000,
                    "lastQuery": None,
                    "numQueries": 0,
                    "macVendor": "",
                    "ips": [{"ip": "192.0.2.152", "lastSeen": 0, "name": ""}],
                },
                {
                    "id": 3,
                    "hwaddr": "ip-192.0.2.99",
                    "interface": "eth0",
                    "firstSeen": 1,
                    "lastQuery": 1,
                    "numQueries": 1,
                    "macVendor": "",
                    "ips": [{"ip": "192.0.2.99", "lastSeen": 1, "name": "x"}],
                },
            ],
            "took": 0.001,
        },
        "/api/info/login": {"dns": True, "https_port": 443, "dhcp": False, "took": 0.0},
        "/api/dhcp/leases": {
            "leases": [
                {
                    "expires": 1893492000,
                    "name": "laptop",
                    "hwaddr": MAC_LAPTOP,
                    "ip": "192.0.2.151",
                    "clientid": "01:02:00:5e:00:53:10",
                },
                {"expires": 0, "name": "*", "hwaddr": MAC_NAS, "ip": "192.0.2.20", "clientid": ""},
                {"expires": 5, "name": "x", "hwaddr": "", "ip": "192.0.2.160", "clientid": ""},
            ],
            "took": 0.001,
        },
    }


def _pihole_v5_data() -> dict[str, Any]:
    return {
        "versions": {
            "core_update": True,
            "web_update": False,
            "FTL_update": False,
            "core_current": "v5.17",
            "web_current": "v5.21",
            "FTL_current": "v5.23",
            "core_latest": "v5.18",
            "web_latest": "v5.21",
            "FTL_latest": "v5.23",
            "core_branch": "master",
            "web_branch": "master",
            "FTL_branch": "master",
        },
        "status": {"status": "enabled"},
        "getForwardDestinations": {
            "forward_destinations": {
                "blocklist|blocklist": 12.5,
                "cache|cache": 30.1,
                "other|other": 0.4,
                "adguard.lan|192.0.2.53": 40.0,
                "dns.example.net|203.0.113.53#5353": 10.0,
                "2001:db8::1|2001:db8::1": 7.0,
            },
            "forwarded_queries": 100,
        },
        "network": {
            "network": [
                {
                    "id": 1,
                    "interface": "eth0",
                    "firstSeen": 1893400000,
                    "lastQuery": 1893490000,
                    "numQueries": 12,
                    "macVendor": "",
                    "ip": ["192.0.2.151", "2001:db8::151"],
                    "name": ["laptop", ""],
                    "hwaddr": MAC_LAPTOP,
                },
                {
                    "id": 2,
                    "interface": "eth0",
                    "firstSeen": 1893400000,
                    "lastQuery": 0,
                    "numQueries": 0,
                    "macVendor": "",
                    "ip": "192.0.2.152",
                    "name": None,
                    "hwaddr": MAC_PHONE.upper(),
                },
                {
                    "id": 3,
                    "interface": "eth0",
                    "firstSeen": 1,
                    "lastQuery": 1,
                    "numQueries": 1,
                    "macVendor": "",
                    "ip": ["192.0.2.99"],
                    "name": ["x"],
                    "hwaddr": "ip-192.0.2.99",
                },
            ]
        },
    }


@dataclass
class PiholeSim:
    password: str = PH_PASSWORD
    token: str = PH_TOKEN
    v5_data: dict[str, Any] = field(default_factory=_pihole_v5_data)
    #: every request as path and query (v5 carries the token there)
    queries: list[str] = field(default_factory=list)
    version: str = "v6"
    max_sessions: int = 16
    totp: bool = False
    data: dict[str, Any] = field(default_factory=_pihole_data)
    fail: dict[str, int] = field(default_factory=dict)
    sessions: set[str] = field(default_factory=set)
    logouts: int = 0
    requests: list[tuple[str, str]] = field(default_factory=list)
    #: the last password and session id seen, so tests can check they are not stored
    last_sid: str = ""

    @property
    def dhcp_active(self) -> bool:
        return bool(self.data["/api/config"]["config"]["dhcp"]["active"])

    @dhcp_active.setter
    def dhcp_active(self, value: bool) -> None:
        self.data["/api/config"]["config"]["dhcp"]["active"] = value

    def _v5(self, path: str, request: Request) -> Response:
        """The legacy API: ``?versions`` and ``?status`` are public, the rest needs ``auth``."""
        if path in self.fail:
            return Response("simulated failure\n", status_code=self.fail[path])
        query = request.query_params
        authed = query.get("auth") == self.token
        if path == "/admin/api.php":
            for key in ("versions", "status"):
                if key in query:
                    return JSONResponse(copy.deepcopy(self.v5_data[key]))
            if "getForwardDestinations" in query and authed:
                return JSONResponse(copy.deepcopy(self.v5_data["getForwardDestinations"]))
        if path == "/admin/api_db.php" and "network" in query and authed:
            return JSONResponse(copy.deepcopy(self.v5_data["network"]))
        return JSONResponse([])

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

        def error(status: int, key: str) -> JSONResponse:
            body = {"error": {"key": key, "message": key, "hint": None}, "took": 0.0}
            return JSONResponse(body, status_code=status)

        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
        async def answer(path: str, request: Request) -> Response:
            path = "/" + path
            self.requests.append((request.method, path))
            self.queries.append(str(request.url.path) + "?" + request.url.query)
            if self.version in ("v5", "other"):
                if self.version == "v5" and path == "/admin/":
                    return Response("<title>Pi-hole admin</title>", media_type="text/html")
                if self.version == "v5" and path in ("/admin/api.php", "/admin/api_db.php"):
                    return self._v5(path, request)
                return Response("not found\n", status_code=404)
            if path == "/admin/" and request.method == "GET":
                return Response("<title>Pi-hole</title>", media_type="text/html")
            if not path.startswith("/api/"):
                return Response("not found\n", status_code=404)
            if path == "/api/info/login" and request.method == "GET":  # public, no session
                return JSONResponse(copy.deepcopy(self.data[path]))
            if path == "/api/auth" and request.method == "POST":
                body = await request.json()
                if len(self.sessions) >= self.max_sessions:
                    return error(429, "rate_limiting")
                if body.get("password") != self.password:
                    return error(401, "unauthorized")
                if self.totp:
                    session: dict[str, Any] = {
                        "valid": False,
                        "totp": True,
                        "sid": None,
                        "message": "2FA needed",
                    }
                    return JSONResponse({"session": session, "took": 0.0})
                sid = secrets.token_urlsafe(16)
                self.sessions.add(sid)
                self.last_sid = sid
                session = {
                    "valid": True,
                    "totp": False,
                    "sid": sid,
                    "csrf": "x",
                    "validity": 300,
                }
                return JSONResponse({"session": session, "took": 0.0})
            sid = request.headers.get("sid", "")
            if sid not in self.sessions:
                return error(401, "unauthorized")
            if path == "/api/auth" and request.method == "DELETE":
                self.sessions.discard(sid)
                self.logouts += 1
                return Response(status_code=204)
            if request.method != "GET":
                return error(405, "bad_request")
            if path in self.fail:
                return error(self.fail[path], "simulated failure")
            if path not in self.data:
                return error(404, "not_found")
            return JSONResponse(copy.deepcopy(self.data[path]))

        return app
