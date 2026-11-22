"""Simulator of the TP-Link Omada controller Open API endpoints the ``omada`` adapter uses.

The answers follow the JSON shapes in ``docs/adapters/omada.md`` (best effort from the Omada
Open API documentation, not yet confirmed on a real controller, issue #21). Every answer is
wrapped as ``{"errorCode": 0, "msg": "Success.", "result": ...}``; lists are paged
(``page``/``pageSize`` → ``totalRows``, ``currentPage``, ``currentSize``, ``data``).

Sample site "Default" (a second site "Branch" is empty), documentation addresses only:

- gateway (ER605), one 8-port switch, two EAPs; MACs ``02-00-00-00-..``
- LAN, VLAN 1 (native), 192.0.2.1/24 with DHCP; IoT, VLAN 20, 198.51.100.1/24 with DHCP;
  Guest, VLAN 30, VLAN only (no gateway interface)
- port profiles "All" (LAN native, IoT and Guest tagged), "LAN", "IoT access"
- one WLAN group with the SSIDs Home (WPA2, both bands), IoT (hidden, 2.4 GHz, VLAN 20) and
  Guest (open, VLAN 30)
- five clients, wired and wireless

Failure switches on :class:`OmadaSimulator`: ``client_secret`` (what the controller accepts),
``expire_next`` (the next API request answers "token expired" and drops every token),
``error`` (an Omada ``(errorCode, msg)`` per path), ``malformed`` (paths answering broken
JSON), ``delay`` (seconds before every answer), ``page_limit`` (largest page the controller
returns). ``data`` can be edited by tests; ``requests`` and ``token_requests`` record traffic.

Writes (issue #44, shapes as guessed in ``docs/adapters/omada.md``): ``POST`` to a list path
creates a row (LAN networks get an ``id``, SSIDs an ``ssidId``), ``PATCH <list>/<id>`` merges
the body into the row (a ``null`` value removes the key), ``DELETE <list>/<id>`` removes it;
switch ports are addressed by their number. The controller checks what a real one would refuse
(a VLAN used twice, a network still in use, an SSID name used twice in a WLAN group, a WPA
passphrase that is not 8 to 63 characters, a port pointing at an unknown network). Write
switches: ``read_only`` (the client has the viewer role: every write is refused with
``PERMISSION_DENIED``), ``write_error`` (an Omada ``(errorCode, msg)`` per path for writes
only). ``writes`` records ``(method, path, body)``.
"""

from __future__ import annotations

import asyncio
import copy
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

OMADAC_ID = "0123456789abcdef0123456789abcdef"
CLIENT_ID = "sim-client"
CLIENT_SECRET = "sim-secret"
SITE_ID = "5f0000000000000000000001"

GATEWAY = "02-00-00-00-0A-01"
SWITCH = "02-00-00-00-0B-01"
EAP1 = "02-00-00-00-0C-01"
EAP2 = "02-00-00-00-0C-02"

#: Path prefix of the site endpoints.
SITE = f"/openapi/v1/{OMADAC_ID}/sites/{SITE_ID}"

#: Omada error codes the simulator uses (the token codes as documented, the others invented).
TOKEN_EXPIRED = -44112
TOKEN_INVALID = -44113
CLIENT_INVALID = -44106
PERMISSION_DENIED = -1005
INVALID_PARAMS = -1001
IN_USE = -33004
#: Key of the id of a row, per list path suffix.
ROW_IDS = {"lan-networks": "id", "ssids": "ssidId", "ports": "port", "lan-profiles": "id"}


def _port(n: int, profile: str, profile_name: str, **kw: Any) -> dict[str, Any]:
    return {
        "port": n,
        "name": f"Port{n}",
        "profileId": profile,
        "profileName": profile_name,
        "disable": False,
        "linkStatus": kw.pop("link", 1),
        "linkSpeed": kw.pop("speed", 3),
        "duplex": kw.pop("duplex", 2),
        "poe": kw.pop("poe", False),
        **kw,
    }


def sample_data() -> dict[str, Any]:
    """Results by path (a fresh copy every call); lists are paged by the simulator."""
    radios = {
        "radioSetting2g": {
            "radioEnable": True,
            "channel": "6",
            "channelWidth": "20",
            "txPower": 20,
        },
        "radioSetting5g": {
            "radioEnable": True,
            "channel": "36",
            "channelWidth": "80",
            "txPower": 23,
        },
    }
    data: dict[str, Any] = {
        "/api/info": {
            "controllerVer": "5.14.26",
            "apiVer": "3",
            "configured": True,
            "type": 1,
            "omadacId": OMADAC_ID,
        },
        f"/openapi/v1/{OMADAC_ID}/sites": [
            {"siteId": SITE_ID, "name": "Default", "region": "Germany", "timeZone": "UTC"},
            {"siteId": "5f0000000000000000000002", "name": "Branch", "region": "Germany"},
        ],
        f"{SITE}/devices": [
            {
                "mac": GATEWAY,
                "name": "Gateway",
                "type": "gateway",
                "model": "ER605",
                "ip": "192.0.2.1",
                "status": 1,
                "firmwareVersion": "2.2.3 Build 20231201",
                "needUpgrade": False,
            },
            {
                "mac": SWITCH,
                "name": "Switch",
                "type": "switch",
                "model": "TL-SG2008P",
                "ip": "192.0.2.2",
                "status": 1,
                "firmwareVersion": "1.0.5",
                "needUpgrade": True,
            },
            {
                "mac": EAP1,
                "name": "AP 1",
                "type": "ap",
                "model": "EAP650",
                "ip": "192.0.2.3",
                "status": 1,
                "firmwareVersion": "1.1.0",
                "wlanId": "wlan-default",
            },
            {
                "mac": EAP2,
                "name": "AP 2",
                "type": "ap",
                "model": "EAP225",
                "ip": "192.0.2.4",
                "status": 1,
                "firmwareVersion": "5.1.0",
            },
        ],
        f"{SITE}/lan-networks": [
            {
                "id": "net-lan",
                "name": "LAN",
                "purpose": "interface",
                "vlan": 1,
                "gatewaySubnet": "192.0.2.1/24",
                "domain": "lan.example",
                "dhcpSettings": {
                    "enable": True,
                    "ipaddrStart": "192.0.2.100",
                    "ipaddrEnd": "192.0.2.199",
                    "leasetime": 120,
                    "dhcpns": "auto",
                    "gateway": "192.0.2.1",
                },
            },
            {
                "id": "net-iot",
                "name": "IoT",
                "purpose": "interface",
                "vlan": 20,
                "gatewaySubnet": "198.51.100.1/24",
                "dhcpSettings": {
                    "enable": True,
                    "ipaddrStart": "198.51.100.100",
                    "ipaddrEnd": "198.51.100.150",
                    "leasetime": 1440,
                    "dhcpns": "manual",
                    "priDns": "198.51.100.1",
                    "sndDns": "192.0.2.53",
                },
            },
            {"id": "net-guest", "name": "Guest", "purpose": "vlan", "vlan": 30},
        ],
        f"{SITE}/lan-profiles": [
            {
                "id": "prof-all",
                "name": "All",
                "nativeNetworkId": "net-lan",
                "tagNetworkIds": ["net-iot", "net-guest"],
            },
            {"id": "prof-lan", "name": "LAN", "nativeNetworkId": "net-lan", "tagNetworkIds": []},
            {"id": "prof-iot", "name": "IoT access", "nativeNetworkId": "net-iot"},
        ],
        f"{SITE}/switches/{SWITCH}/ports": [
            _port(1, "prof-all", "All", speed=4),
            _port(2, "prof-all", "All", poe=True),
            _port(3, "prof-all", "All", poe=True),
            _port(4, "prof-lan", "LAN", link=0, speed=0, duplex=0),
            _port(5, "prof-lan", "LAN", speed=2, duplex=1),
            _port(6, "prof-lan", "LAN", link=0, speed=0, duplex=0, disable=True),
            _port(7, "prof-iot", "IoT access"),
            # A port-level override of the profile: Guest untagged, nothing tagged.
            _port(8, "prof-all", "All", link=0, nativeNetworkId="net-guest", tagNetworkIds=[]),
        ],
        f"{SITE}/eaps/{EAP1}/radios": copy.deepcopy(radios),
        f"{SITE}/eaps/{EAP2}/radios": {
            **copy.deepcopy(radios),
            "radioSetting5g": {"radioEnable": False, "channel": "0", "channelWidth": "0"},
        },
        f"{SITE}/wireless-network/wlans": [
            {"wlanId": "wlan-default", "name": "Default", "primary": True},
        ],
        f"{SITE}/wireless-network/wlans/wlan-default/ssids": [
            {
                "ssidId": "ssid-home",
                "name": "Home",
                "band": 3,
                "security": 3,
                "broadcast": True,
                "vlanEnable": False,
                "pmfMode": 2,
                "pskSetting": {"versionPsk": 2, "encryptionPsk": 3},
            },
            {
                "ssidId": "ssid-iot",
                "name": "IoT",
                "band": 1,
                "security": 3,
                "broadcast": False,
                "vlanEnable": True,
                "vlanId": 20,
                "pskSetting": {"versionPsk": 2, "securityKey": "example-iot-passphrase"},
            },
            {
                "ssidId": "ssid-guest",
                "name": "Guest",
                "band": 3,
                "security": 0,
                "broadcast": True,
                "vlanEnable": True,
                "vlanId": 30,
            },
        ],
        f"{SITE}/clients": [
            {
                "mac": "02-00-00-00-00-21",
                "name": "laptop",
                "hostName": "laptop",
                "ip": "192.0.2.100",
                "ipv6List": ["2001:db8:1::21"],
                "wireless": True,
                "ssid": "Home",
                "apMac": EAP1,
                "radioId": 1,
                "vid": 1,
                "networkName": "LAN",
                "lastSeen": 1767225600000,
            },
            {
                "mac": "02-00-00-00-00-20",
                "name": "sensor",
                "ip": "198.51.100.20",
                "wireless": True,
                "ssid": "IoT",
                "apMac": EAP2,
                "radioId": 0,
                "vid": 20,
            },
            {
                "mac": "02-00-00-00-00-31",
                "name": "02-00-00-00-00-31",
                "wireless": True,
                "ssid": "Guest",
                "apMac": EAP1,
                "radioId": 0,
                "networkName": "Guest",
            },
            {
                "mac": "02-00-00-00-00-10",
                "name": "printer",
                "hostName": "printer",
                "ip": "192.0.2.10",
                "wireless": False,
                "switchMac": SWITCH,
                "port": 5,
                "vid": 1,
            },
            {
                "mac": "02-00-00-00-00-30",
                "name": "camera",
                "ip": "198.51.100.30",
                "wireless": False,
                "switchMac": SWITCH,
                "port": 7,
                "vid": 20,
            },
        ],
    }
    return copy.deepcopy(data)


def _wrap(result: Any, code: int = 0, msg: str = "Success.") -> JSONResponse:
    body: dict[str, Any] = {"errorCode": code, "msg": msg}
    if code == 0:
        body["result"] = result
    return JSONResponse(body)


@dataclass
class OmadaSimulator:
    omadac_id: str = OMADAC_ID
    client_id: str = CLIENT_ID
    client_secret: str = CLIENT_SECRET
    #: The next authorised API request answers "token expired" and every token is dropped.
    expire_next: bool = False
    #: ``(errorCode, msg)`` to answer per path instead of the data.
    error: dict[str, tuple[int, str]] = field(default_factory=dict)
    malformed: set[str] = field(default_factory=set)
    delay: float = 0.0
    #: Largest page size the controller honours (None: whatever is asked for).
    page_limit: int | None = None
    data: dict[str, Any] = field(default_factory=sample_data)
    #: Paths requested so far (to check that nothing is sent before the pin check).
    requests: list[str] = field(default_factory=list)
    token_requests: int = 0
    tokens: set[str] = field(default_factory=set)
    #: The Open API client has the viewer role: every write is refused.
    read_only: bool = False
    #: ``(errorCode, msg)`` to answer per path for POST, PATCH and DELETE only.
    write_error: dict[str, tuple[int, str]] = field(default_factory=dict)
    writes: list[tuple[str, str, Any]] = field(default_factory=list)
    created: int = 0

    def _token(self, body: Any) -> JSONResponse:
        self.token_requests += 1
        ok = (
            isinstance(body, dict)
            and body.get("omadacId") == self.omadac_id
            and secrets.compare_digest(str(body.get("client_id", "")), self.client_id)
            and secrets.compare_digest(str(body.get("client_secret", "")), self.client_secret)
        )
        if not ok:
            return _wrap(None, CLIENT_INVALID, "Client Id Or Client Secret is Invalid.")
        token = "AT-" + secrets.token_hex(8)
        self.tokens.add(token)
        return _wrap(
            {
                "accessToken": token,
                "tokenType": "bearer",
                "expiresIn": 7200,
                "refreshToken": "RT-" + secrets.token_hex(8),
            }
        )

    def _page(self, value: Any, request: Request) -> Any:
        if not isinstance(value, list):
            return value
        try:
            page = max(1, int(request.query_params.get("page", "1")))
            size = max(1, int(request.query_params.get("pageSize", "10")))
        except ValueError:
            return None
        if self.page_limit:
            size = min(size, self.page_limit)
        rows = value[(page - 1) * size : page * size]
        return {"totalRows": len(value), "currentPage": page, "currentSize": size, "data": rows}

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

        @app.api_route("/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
        async def answer(path: str, request: Request) -> Response:
            path = "/" + path
            self.requests.append(path)
            if self.delay:
                await asyncio.sleep(self.delay)
            if path == "/openapi/authorize/token" and request.method == "POST":
                if request.query_params.get("grant_type") != "client_credentials":
                    return _wrap(None, -44111, "The grant type is Invalid.")
                try:
                    body = json.loads(await request.body())
                except ValueError:
                    body = None
                return self._token(body)
            if path.startswith("/openapi/"):
                auth = request.headers.get("authorization", "")
                token = auth.removeprefix("AccessToken=")
                if not auth.startswith("AccessToken=") or token not in self.tokens:
                    return _wrap(None, TOKEN_INVALID, "The access token is Invalid.")
                if self.expire_next:
                    self.expire_next = False
                    self.tokens.clear()
                    return _wrap(None, TOKEN_EXPIRED, "The access token has expired.")
            if path in self.error:
                code, msg = self.error[path]
                return _wrap(None, code, msg)
            if request.method != "GET":
                try:
                    body = json.loads(await request.body() or b"null")
                except ValueError:
                    return _wrap(None, INVALID_PARAMS, "Invalid JSON.")
                return self._write(request.method, path, body)
            if path not in self.data:
                return JSONResponse({"errorCode": -1, "msg": "Not Found"}, status_code=404)
            if path in self.malformed:
                return Response('{"errorCode": 0, "result": {', media_type="application/json")
            return _wrap(self._page(self.data[path], request))

        return app

    # --- writes --------------------------------------------------------------------------

    def _write(self, method: str, path: str, body: Any) -> JSONResponse:
        self.writes.append((method, path, copy.deepcopy(body)))
        if self.read_only:
            return _wrap(None, PERMISSION_DENIED, "Permission denied.")
        if path in self.write_error:
            code, msg = self.write_error[path]
            return _wrap(None, code, msg)
        if method == "POST":
            rows = self.data.get(path)
            kind = path.rsplit("/", 1)[-1]
            if not isinstance(rows, list) or kind not in ("lan-networks", "ssids"):
                return JSONResponse({"errorCode": -1, "msg": "Not Found"}, status_code=404)
            if not isinstance(body, dict):
                return _wrap(None, INVALID_PARAMS, "Invalid request parameters.")
            self.created += 1
            key = ROW_IDS[kind]
            row = {k: v for k, v in body.items() if v is not None}
            row[key] = f"{'net' if key == 'id' else 'ssid'}-new{self.created}"
            problem = self._invalid(path, row, None)
            if problem:
                return _wrap(None, *problem)
            rows.append(row)
            return _wrap({key: row[key]})
        list_path, _, item = path.rpartition("/")
        rows = self.data.get(list_path)
        kind = list_path.rsplit("/", 1)[-1]
        if not isinstance(rows, list) or kind not in ROW_IDS:
            return JSONResponse({"errorCode": -1, "msg": "Not Found"}, status_code=404)
        key = ROW_IDS[kind]
        index = next((i for i, r in enumerate(rows) if str(r.get(key)) == item), None)
        if index is None:
            return _wrap(None, -33000, "The object does not exist.")
        if method == "DELETE":
            if kind == "ports":
                return _wrap(None, INVALID_PARAMS, "A port cannot be deleted.")
            if kind == "lan-networks" and self._network_used(item):
                return _wrap(None, IN_USE, "The network is in use.")
            del rows[index]
            return _wrap(None)
        if not isinstance(body, dict):
            return _wrap(None, INVALID_PARAMS, "Invalid request parameters.")
        row = {**rows[index], **body}
        row = {k: v for k, v in row.items() if v is not None}
        row[key] = rows[index][key]
        problem = self._invalid(list_path, row, index)
        if problem:
            return _wrap(None, *problem)
        rows[index] = row
        return _wrap(None)

    def _rows(self, suffix: str) -> list[dict[str, Any]]:
        return [r for p, v in self.data.items() if p.endswith(suffix) for r in v]

    def _network_used(self, net_id: str) -> bool:
        ports = self._rows("/ports") + self._rows("/lan-profiles")
        return any(
            r.get("nativeNetworkId") == net_id or net_id in (r.get("tagNetworkIds") or [])
            for r in ports
        )

    def _invalid(
        self, list_path: str, row: dict[str, Any], index: int | None
    ) -> tuple[int, str] | None:
        """What a controller would refuse in a new (``index`` None) or changed row."""
        rows = self.data[list_path]
        others = [r for i, r in enumerate(rows) if i != index]
        kind = list_path.rsplit("/", 1)[-1]
        if kind == "lan-networks":
            vlan = row.get("vlan")
            if not isinstance(row.get("name"), str) or not row["name"]:
                return INVALID_PARAMS, "The network needs a name."
            if not isinstance(vlan, int) or not 1 <= vlan <= 4094:
                return INVALID_PARAMS, "The VLAN must be 1-4094."
            if any(r.get("vlan") == vlan for r in others):
                return -33101, "The VLAN is already used by another network."
        elif kind == "ssids":
            if not isinstance(row.get("name"), str) or not row["name"]:
                return INVALID_PARAMS, "The SSID needs a name."
            if any(r.get("name") == row["name"] for r in others):
                return -33201, "The SSID already exists in this WLAN group."
            key = (row.get("pskSetting") or {}).get("securityKey")
            checked = row.get("security") == 3 and (index is None or key is not None)
            if checked and (not isinstance(key, str) or not 8 <= len(key) <= 63):
                return INVALID_PARAMS, "The password must be 8-63 characters."
        elif kind == "ports":
            nets = {r.get("id") for r in self._rows("/lan-networks")}
            wanted = [row.get("nativeNetworkId"), *(row.get("tagNetworkIds") or [])]
            if any(n is not None and n not in nets for n in wanted):
                return INVALID_PARAMS, "The network does not exist."
            profiles = {r.get("id"): r for r in self._rows("/lan-profiles")}
            if row.get("profileId") not in profiles:
                return INVALID_PARAMS, "The profile does not exist."
            row["profileName"] = profiles[row["profileId"]].get("name", "")
        return None


def create_app() -> FastAPI:
    """``uvicorn --factory signalbox.sim.omada:create_app``"""
    return OmadaSimulator().app()
