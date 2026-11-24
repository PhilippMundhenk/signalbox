"""Simulator of the UniFi Network application API the ``unifi`` adapter reads.

The shapes follow what the application's web API is known to answer (community API
documentation and the Network application's own UI); they have not been checked against a real
console or controller (issue #21). Every classic answer is wrapped as
``{"meta": {"rc": "ok"}, "data": [...]}``.

Two kinds of installation (``style``):

- ``"unifi_os"`` (console): ``GET /`` answers 200, login at ``POST /api/auth/login``, the
  application below ``/proxy/network``; wrong login: HTTP 401;
- ``"controller"`` (self-hosted): ``GET /`` redirects (302), login at ``POST /api/login``, the
  API at the root; wrong login: HTTP 400 ``api.err.Invalid``.

Three versions (``version``): ``"8.x"`` spells the Wi-Fi bands ``wlan_band``, a custom port
profile as an excluded list and LLDP per port; ``"9.x"`` and ``"10.x"`` use ``wlan_bands``,
tagged lists and the device's own ``lldp_table``.

Logins: ``username`` / ``password`` (a session cookie) or ``api_key`` (``X-API-KEY``). With
``key_classic`` False the key is refused by the classic API (HTTP 401) and only the Integration
API (``/integration/v1``: info, sites, devices, networks, clients) answers it.

Sample site "default" (named "Default"), documentation addresses only: a gateway (UDM) with a
WAN on DHCP and four LAN ports, an 8-port switch (PoE, a LAG on ports 7 and 8, LLDP, MAC
table), two access points (one wired to switch port 3, one a wireless mesh child of it), the
networks LAN (untagged), IoT (VLAN 20) and Guest (VLAN 30), the Wi-Fi networks Home, IoT
(hidden) and Guest (open), and three clients. ``data`` can be edited by tests; ``requests``
records every request path.
"""

from __future__ import annotations

import copy
import secrets
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

USERNAME = "sim-reader"
PASSWORD = "sim-password"
API_KEY = "sim-api-key"
SITE_UUID = "5f0000000000000000000a01"

GATEWAY = "02:00:00:00:0a:01"
SWITCH = "02:00:00:00:0b:01"
AP1 = "02:00:00:00:0c:01"
AP2 = "02:00:00:00:0c:02"

NET_LAN, NET_IOT, NET_GUEST, NET_WAN = "net-lan", "net-iot", "net-guest", "net-wan"
PROF_ALL, PROF_IOT, PROF_OFF = "prof-all", "prof-iot", "prof-off"
WLAN_HOME, WLAN_IOT, WLAN_GUEST = "wlan-home", "wlan-iot", "wlan-guest"


def _port(idx: int, name: str | None = None, **kw: Any) -> dict[str, Any]:
    up = kw.pop("up", False)
    row: dict[str, Any] = {
        "port_idx": idx,
        "name": name or f"Port {idx}",
        "portconf_id": PROF_ALL,
        "enable": True,
        "up": up,
        "speed": kw.pop("speed", 0),
        "full_duplex": up,
        "media": "GE",
    }
    row.update(kw)
    return row


def sample_data(major: int) -> dict[str, Any]:
    """The sample site as the application of this major version answers it."""
    new = major >= 9
    ap_uplink = {
        "type": "wire",
        "uplink_mac": SWITCH,
        "uplink_remote_port": 3,
        "port_idx": 1,
        "speed": 1000,
        "up": True,
    }
    switch_ports = [
        _port(
            1,
            up=True,
            speed=1000,
            port_poe=True,
            poe_enable=True,
            poe_power="4.2",
            poe_mode="auto",
            mac_table=[{"mac": "02:00:00:00:01:01", "vlan": 1, "age": 3}],
        ),
        _port(
            2,
            portconf_id=PROF_IOT,
            up=True,
            speed=100,
            port_poe=True,
            poe_enable=True,
            mac_table=[{"mac": "02:00:00:00:02:01", "vlan": 20, "static": False}],
        ),
        _port(3, up=True, speed=1000, port_poe=True, poe_enable=True),
        _port(4, portconf_id=PROF_OFF, enable=False, port_poe=True, poe_enable=False),
        _port(5, up=True, speed=1000, is_uplink=True),
        _port(6, portconf_id="prof-trunk"),
        _port(7, op_mode="aggregate", up=True, speed=1000),
        _port(8, aggregated_by=7, up=True, speed=1000),
    ]
    lldp = [
        {
            "chassis_id": GATEWAY,
            "port_id": "eth1",
            "chassis_name": "Gateway",
            "chassis_descr": "UniFi Dream Machine",
            "is_wired": True,
        },
    ]
    if new:
        lldp[0]["local_port_idx"] = 5
        switch_lldp: dict[str, Any] = {"lldp_table": lldp}
    else:
        switch_ports[4]["lldp_table"] = lldp
        switch_lldp = {}
    radios = [
        {"name": "wifi0", "radio": "ng", "channel": "auto", "ht": "20", "tx_power": 14},
        {
            "name": "wifi1",
            "radio": "na",
            "channel": 36,
            "ht": "80",
            "tx_power": 20,
            "has_dfs": True,
        },
    ]
    stats = [
        {
            "name": "wifi0",
            "channel": 6,
            "tx_power": 14,
            "num_sta": 1,
            "cu_total": 20,
            "cu_self_rx": 4,
            "cu_self_tx": 6,
        },
        {
            "name": "wifi1",
            "channel": 36,
            "tx_power": 20,
            "num_sta": 2,
            "cu_total": 8,
            "cu_self_rx": 3,
            "cu_self_tx": 2,
        },
    ]
    vaps = [
        {
            "id": WLAN_HOME,
            "essid": "Home",
            "radio": "ng",
            "radio_name": "wifi0",
            "bssid": "02:00:00:00:0c:11",
            "up": True,
        },
        {
            "id": WLAN_HOME,
            "essid": "Home",
            "radio": "na",
            "radio_name": "wifi1",
            "bssid": "02:00:00:00:0c:12",
            "up": True,
        },
        {
            "id": WLAN_IOT,
            "essid": "IoT",
            "radio": "ng",
            "radio_name": "wifi0",
            "bssid": "02:00:00:00:0c:13",
            "up": True,
        },
        {
            "id": WLAN_GUEST,
            "essid": "Guest",
            "radio": "ng",
            "radio_name": "wifi0",
            "bssid": "02:00:00:00:0c:14",
            "up": True,
            "is_guest": True,
        },
    ]

    def band(*codes: str, both: bool = False) -> dict[str, Any]:
        if new:
            return {"wlan_bands": list(codes)}
        return {"wlan_band": "both" if both else codes[0]}

    def custom(tagged: list[str]) -> dict[str, Any]:
        if new:
            return {"forward": "customize", "tagged_networkconf_ids": tagged}
        every = {NET_LAN, NET_IOT, NET_GUEST}
        return {"forward": "customize", "excluded_networkconf_ids": sorted(every - set(tagged))}

    return {
        "sites": [{"_id": "s1", "name": "default", "desc": "Default"}],
        "sysinfo": [
            {
                "version": f"{major}.0.0",
                "timezone": "Europe/Berlin",
                "name": "Network",
            }
        ],
        "stat/device": [
            {
                "_id": "d1",
                "mac": GATEWAY,
                "type": "udm",
                "model": "UDM",
                "name": "Gateway",
                "version": "4.0.6",
                "ip": "192.0.2.1",
                "adopted": True,
                "state": 1,
                "uptime": 864000,
                "system-stats": {"cpu": "7.5", "mem": "41.0", "uptime": "864000"},
                "sys_stats": {
                    "loadavg_1": "0.2",
                    "loadavg_5": "0.3",
                    "loadavg_15": "0.4",
                    "mem_total": 2000000000,
                    "mem_used": 800000000,
                },
                "general_temperature": 52,
                "storage": [
                    {"name": "eMMC", "mount_point": "/data", "size": 8000000000, "used": 2000000000}
                ],
                "port_table": [
                    _port(1, "WAN", network_name="wan", up=True, speed=1000),
                    _port(2, "LAN 1", up=True, speed=1000, op_mode="switch"),
                    _port(3, "LAN 2"),
                ],
                "wan1": {
                    "name": "WAN",
                    "ip": "203.0.113.45",
                    "netmask": "255.255.255.0",
                    "gateway": "203.0.113.1",
                    "dns": ["203.0.113.53"],
                    "up": True,
                },
            },
            {
                "_id": "d2",
                "mac": SWITCH,
                "type": "usw",
                "model": "US8P150",
                "name": "Switch",
                "version": "7.0.50",
                "ip": "192.0.2.11",
                "adopted": True,
                "state": 1,
                "uptime": 7200,
                "system-stats": {"cpu": "3.0", "mem": "30.0"},
                "uplink": {
                    "type": "wire",
                    "uplink_mac": GATEWAY,
                    "uplink_remote_port": 2,
                    "port_idx": 5,
                    "speed": 1000,
                    "up": True,
                },
                "port_table": switch_ports,
                **switch_lldp,
            },
            {
                "_id": "d3",
                "mac": AP1,
                "type": "uap",
                "model": "U6LR",
                "name": "AP One",
                "version": "6.6.77",
                "ip": "192.0.2.21",
                "adopted": True,
                "state": 1,
                "uptime": 3600,
                "uplink": ap_uplink,
                "radio_table": copy.deepcopy(radios),
                "radio_table_stats": copy.deepcopy(stats),
                "vap_table": copy.deepcopy(vaps),
            },
            {
                "_id": "d4",
                "mac": AP2,
                "type": "uap",
                "model": "U6M",
                "name": "AP Two",
                "version": "6.6.77",
                "ip": "192.0.2.22",
                "adopted": True,
                "state": 1,
                "uptime": 1800,
                "uplink": {"type": "wireless", "uplink_mac": AP1, "speed": 866, "up": True},
                "radio_table": copy.deepcopy(radios[:1]),
                "radio_table_stats": copy.deepcopy(stats[:1]),
                "vap_table": [copy.deepcopy(vaps[0])],
            },
            {
                "_id": "d5",
                "mac": "02:00:00:00:0d:01",
                "type": "usw",
                "model": "US8",
                "name": "Pending",
                "adopted": False,
                "state": 5,
            },
        ],
        "rest/networkconf": [
            {
                "_id": NET_LAN,
                "name": "LAN",
                "purpose": "corporate",
                "vlan_enabled": False,
                "ip_subnet": "192.0.2.1/24",
                "dhcpd_enabled": True,
                "dhcpd_start": "192.0.2.100",
                "dhcpd_stop": "192.0.2.200",
                "dhcpd_leasetime": 86400,
                "dhcpd_dns_enabled": True,
                "dhcpd_dns_1": "192.0.2.53",
                "domain_name": "lan.example",
                "enabled": True,
            },
            {
                "_id": NET_IOT,
                "name": "IoT",
                "purpose": "corporate",
                "vlan_enabled": True,
                "vlan": 20,
                "ip_subnet": "198.51.100.1/24",
                "dhcpd_enabled": True,
                "dhcpd_start": "198.51.100.50",
                "dhcpd_stop": "198.51.100.99",
                "dhcpd_leasetime": 3600,
                "enabled": True,
            },
            {
                "_id": NET_GUEST,
                "name": "Guest",
                "purpose": "guest",
                "vlan_enabled": True,
                "vlan": 30,
                "ip_subnet": "203.0.113.129/25",
                "dhcpd_enabled": False,
                "enabled": True,
            },
            {
                "_id": NET_WAN,
                "name": "Internet",
                "purpose": "wan",
                "wan_type": "dhcp",
                "wan_networkgroup": "WAN",
                "enabled": True,
            },
        ],
        "rest/portconf": [
            {"_id": PROF_ALL, "name": "All", "forward": "all"},
            {
                "_id": PROF_IOT,
                "name": "IoT access",
                "native_networkconf_id": NET_IOT,
                "forward": "native",
            },
            {"_id": PROF_OFF, "name": "Disabled", "forward": "disabled"},
            {"_id": "prof-trunk", "name": "Trunk", **custom([NET_IOT])},
        ],
        "rest/wlanconf": [
            {
                "_id": WLAN_HOME,
                "name": "Home",
                "enabled": True,
                "security": "wpapsk",
                "wpa_mode": "wpa2",
                "wpa3_support": True,
                "wpa3_transition": True,
                "wpa_enc": "ccmp",
                "x_passphrase": "example-passphrase",
                "pmf_mode": "optional",
                "networkconf_id": NET_LAN,
                "group_rekey": 3600,
                **band("2g", "5g", both=True),
            },
            {
                "_id": WLAN_IOT,
                "name": "IoT",
                "enabled": True,
                "security": "wpapsk",
                "wpa_mode": "wpa2",
                "wpa_enc": "ccmp",
                "x_passphrase": "example-iot-key",
                "hide_ssid": True,
                "networkconf_id": NET_IOT,
                "l2_isolation": True,
                **band("2g"),
            },
            {
                "_id": WLAN_GUEST,
                "name": "Guest",
                "enabled": True,
                "security": "open",
                "is_guest": True,
                "networkconf_id": NET_GUEST,
                **band("2g"),
            },
        ],
        "rest/apgroups": [],
        "stat/sta": [
            {
                "mac": "02:00:00:00:01:01",
                "ip": "192.0.2.101",
                "hostname": "desk",
                "is_wired": True,
                "sw_mac": SWITCH,
                "sw_port": 1,
                "network_id": NET_LAN,
                "last_seen": 1790000000,
            },
            {
                "mac": "02:00:00:00:02:01",
                "ip": "198.51.100.51",
                "name": "sensor",
                "is_wired": True,
                "sw_mac": SWITCH,
                "sw_port": 2,
                "network_id": NET_IOT,
                "vlan": 20,
                "last_seen": 1790000010,
            },
            {
                "mac": "02:00:00:00:03:01",
                "ip": "192.0.2.102",
                "hostname": "phone",
                "is_wired": False,
                "ap_mac": AP1,
                "essid": "Home",
                "radio": "na",
                "network_id": NET_LAN,
                "last_seen": 1790000020,
            },
        ],
        # the Integration API (what an API key may always read)
        "integration/info": {"applicationVersion": f"{major}.0.0"},
        "integration/sites": [{"id": SITE_UUID, "internalReference": "default", "name": "Default"}],
        "integration/devices": [
            {
                "id": "i-d2",
                "macAddress": SWITCH,
                "name": "Switch",
                "model": "US8P150",
                "state": "ONLINE",
                "features": ["switching"],
                "firmwareVersion": "7.0.50",
            },
            {
                "id": "i-d3",
                "macAddress": AP1,
                "name": "AP One",
                "model": "U6LR",
                "state": "ONLINE",
                "features": ["accessPoint"],
            },
        ],
        "integration/networks": [
            {"id": NET_LAN, "name": "LAN", "vlanId": 1, "enabled": True},
            {"id": NET_IOT, "name": "IoT", "vlanId": 20, "enabled": True},
        ],
        "integration/clients": [
            {
                "id": "c1",
                "type": "WIRED",
                "macAddress": "02:00:00:00:01:01",
                "name": "desk",
                "ipAddress": "192.0.2.101",
                "connectedAt": "2026-11-01T10:00:00Z",
            },
        ],
        "integration/stats": {"uptimeSec": 7200, "cpuUtilizationPct": 3.5},
    }


class UnifiSimulator:
    def __init__(
        self,
        *,
        style: str = "unifi_os",
        version: str = "10.0.26",
        username: str = USERNAME,
        password: str = PASSWORD,
        api_key: str = API_KEY,
        key_classic: bool = True,
    ) -> None:
        self.style = style
        self.version = version
        self.username = username
        self.password = password
        self.api_key = api_key
        self.key_classic = key_classic
        self.major = int(version.split(".")[0])
        self.data = sample_data(self.major)
        self.data["sysinfo"][0]["version"] = version
        self.data["integration/info"]["applicationVersion"] = version
        self.sessions: set[str] = set()
        self.requests: list[str] = []
        #: paths answering an UniFi error (``meta.rc`` ``error`` with this message)
        self.error: dict[str, str] = {}
        #: a missing endpoint per rest path (HTTP 404)
        self.missing: set[str] = set()
        self.expire_next = False
        self.date = "Tue, 24 Nov 2026 10:00:00 GMT"

    @property
    def prefix(self) -> str:
        return "/proxy/network" if self.style == "unifi_os" else ""

    def _ok(self, data: Any) -> JSONResponse:
        return JSONResponse({"meta": {"rc": "ok"}, "data": data}, headers={"date": self.date})

    def _error(self, msg: str, status: int = 200) -> JSONResponse:
        return JSONResponse({"meta": {"rc": "error", "msg": msg}, "data": []}, status_code=status)

    def _authorised(self, request: Request, classic: bool) -> bool:
        key = request.headers.get("x-api-key")
        if key is not None:
            return key == self.api_key and (self.key_classic or not classic)
        return request.cookies.get("sid") in self.sessions

    def app(self) -> FastAPI:
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        login = "/api/auth/login" if self.style == "unifi_os" else "/api/login"

        @app.get("/")
        async def start() -> Response:
            self.requests.append("/")
            if self.style == "unifi_os":
                return Response("<html>UniFi OS</html>", media_type="text/html")
            return RedirectResponse("/manage", status_code=302)

        @app.post(login)
        async def do_login(request: Request) -> Response:
            self.requests.append(login)
            body = await request.json()
            if body.get("username") != self.username or body.get("password") != self.password:
                if self.style == "unifi_os":
                    return JSONResponse({"code": "AUTHENTICATION_FAILED"}, status_code=401)
                return self._error("api.err.Invalid", 400)
            sid = secrets.token_hex(8)
            self.sessions.add(sid)
            response = JSONResponse({"meta": {"rc": "ok"}, "data": []})
            response.set_cookie("sid", sid)
            if self.style == "unifi_os":
                response.headers["x-csrf-token"] = secrets.token_hex(8)
            return response

        @app.get("/{path:path}")
        async def read(path: str, request: Request) -> Response:
            full = "/" + path
            self.requests.append(full)
            wrong_style = (self.style == "unifi_os") != full.startswith("/proxy/network")
            if wrong_style and full != "/status":
                return Response("not found", status_code=404)
            rest = full.removeprefix(self.prefix).lstrip("/")
            if rest == "status" and self.style == "controller":
                return JSONResponse(
                    {"meta": {"rc": "ok", "up": True, "server_version": self.version}}
                )
            integration = rest.startswith("integration/v1/")
            if not self._authorised(request, classic=not integration):
                if self.style == "controller" and not integration:
                    return self._error("api.err.LoginRequired", 401)
                return Response("unauthorized", status_code=401)
            if self.expire_next:
                self.expire_next = False
                self.sessions.clear()
                return self._error("api.err.LoginRequired", 401)
            if integration:
                return self._integration(rest.removeprefix("integration/v1/"), request)
            if rest == "api/self/sites":
                return self._ok(self.data["sites"])
            parts = rest.split("/", 3)  # api, s, <site>, <rest>
            if len(parts) < 4 or parts[:2] != ["api", "s"]:
                return Response("not found", status_code=404)
            if parts[2] != "default":
                return self._error("api.err.NoSiteContext")
            what = parts[3]
            if what in self.error:
                return self._error(self.error[what])
            if what in self.missing or what not in self.data:
                return Response("not found", status_code=404)
            return self._ok(copy.deepcopy(self.data[what]))

        return app

    def _integration(self, what: str, request: Request) -> Response:
        if what == "info":
            return JSONResponse(self.data["integration/info"])
        if what == "sites":
            return self._page(self.data["integration/sites"], request)
        if what.startswith(f"sites/{SITE_UUID}/"):
            tail = what.split("/", 2)[2]
            if tail.startswith("devices/") and tail.endswith("/statistics/latest"):
                return JSONResponse(self.data["integration/stats"])
            if f"integration/{tail}" in self.data:
                return self._page(self.data[f"integration/{tail}"], request)
        return Response("not found", status_code=404)

    @staticmethod
    def _page(rows: list[dict[str, Any]], request: Request) -> JSONResponse:
        limit = int(request.query_params.get("limit", 200))
        offset = int(request.query_params.get("offset", 0))
        page = rows[offset : offset + limit]
        return JSONResponse(
            {
                "offset": offset,
                "limit": limit,
                "count": len(page),
                "totalCount": len(rows),
                "data": page,
            }
        )


def create_app() -> FastAPI:
    """``uvicorn --factory signalbox.sim.unifi:create_app``"""
    return UnifiSimulator().app()
