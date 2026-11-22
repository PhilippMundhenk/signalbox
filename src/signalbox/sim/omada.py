"""Simulator of the TP-Link Omada controller Open API endpoints the ``omada`` adapter uses.

The answers, error codes and refusals of the controller itself (sites, LAN networks, port
profiles, WLAN groups and SSIDs, the token, the roles) are those of the real Omada Software
Controller 6.3.0.111, recorded in CI (tests/integration/test_omada_real.py, #140); the answers
about managed devices (gateway, switch ports, EAP radios, clients) follow the controller's own
Open API description (``/v3/api-docs``) of that version, which has no device to answer them.
Every answer is wrapped as ``{"errorCode": 0, "msg": "Success.", "result": ...}``; lists are
paged (``page``/``pageSize`` → ``totalRows``, ``currentPage``, ``currentSize``, ``data``).

Sample site "Default" (a second site "Branch" is empty), documentation addresses only:

- gateway (ER605), one 8-port switch, two EAPs; MACs ``02-00-00-00-..``; the gateway's WAN
  port 1 on DHCP (203.0.113.45/24), port 2 a WAN with PPPoE that is down, port 3 in LAN mode
- LAN, VLAN 1 (native, the controller's primary network), 192.0.2.1/24 with DHCP; IoT,
  VLAN 20, 198.51.100.1/24 with DHCP; Guest, VLAN 30, VLAN only (no gateway interface)
- port profiles "All" (LAN native, IoT and Guest tagged), "LAN", "IoT access"
- one WLAN group with the SSIDs Home (WPA2, both bands), IoT (hidden, 2.4 GHz, VLAN 20) and
  Guest (open, VLAN 30)
- five clients, wired and wireless
- uptime, CPU and memory use per device in the device list; the site's time zone

Like the real controller: the SSID list leaves out the security settings (only
``…/ssids/{ssidId}`` has ``pskSetting`` and ``pmfMode``, the passphrase included); the v1 network
list has ``purpose`` as a number (0 VLAN, 1 interface) and the DHCP settings as
``dhcpSettingsVO``; a switch's ports are in ``GET …/switches/{mac}`` (``portList``), an EAP's
radio settings in ``GET …/aps/{mac}/radio-config`` (``channelWidth`` as a code).

Failure switches on :class:`OmadaSimulator`: ``client_secret`` (what the controller accepts),
``expire_next`` (the next API request answers "token expired" and drops every token),
``error`` (an Omada ``(errorCode, msg)`` per path), ``malformed`` (paths answering broken
JSON), ``delay`` (seconds before every answer), ``page_limit`` (largest page the controller
returns). ``data`` can be edited by tests; ``requests`` and ``token_requests`` record traffic.

Writes, as the real controller takes them: ``POST …/lan-networks`` (``{"id": …}``), ``PATCH``
and ``DELETE …/lan-networks/{id}`` (a PATCH carries the whole network: ``name``, ``purpose``
and ``igmpSnoopEnable`` are required, keys left out are gone); ``POST …/wlans/{id}/ssids``
(``{"ssidId": …}``), ``PATCH …/ssids/{id}/update-basic-config`` (the whole basic
configuration), ``PATCH …/wireless-network/ssids/{id}/enable``, ``DELETE …/ssids/{id}``;
``PATCH …/switches/{mac}/ports/{port}``. Refusals with the controller's codes: a missing field
(-1001), a VLAN used twice (-34517), an overlapping subnet (-33502), an interface network
without LAN interfaces (-33515), an unknown network (-33503), an SSID name used twice (-33219),
a bad passphrase (-33223), a port
pointing at an unknown network or profile. Write switches: ``read_only`` (the application has
the viewer role: every write is refused with -1007), ``write_error`` (an Omada
``(errorCode, msg)`` per path for writes only). ``writes`` records ``(method, path, body)``.
"""

from __future__ import annotations

import asyncio
import copy
import json
import secrets
from dataclasses import dataclass, field
from ipaddress import ip_interface
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
#: Where the simulator keeps a switch's ports (the controller answers them in the switch).
PORTS_KEY = "/ports"
#: Where the simulator keeps the rest of a switch's answer (``jumbo``, #156).
SETTINGS_KEY = "/settings"

#: Omada error codes, as the real controller answers them.
TOKEN_EXPIRED = -44112  # also the answer to a token the controller never issued
TOKEN_INVALID = -44113
OPEN_API_AUTH_FAILED = -44116  # no token at all (HTTP 401)
CLIENT_INVALID = -44106
PERMISSION_DENIED = -1007
INVALID_PARAMS = -1001
VLAN_USED = -34517
NO_INTERFACES = -33515
NO_NETWORK = -33503
SUBNET_USED = -33502
SSID_EXISTS = -33219
BAD_KEY = -33223
NO_AP = -39303
NO_DEVICE = -39050
MESSAGES = {
    TOKEN_EXPIRED: "The access token has expired. Please re-initiate the refreshToken process "
    "to obtain the access token.",
    OPEN_API_AUTH_FAILED: "Open API Authorized failed, please check whether the input "
    "parameters are legal.",
    CLIENT_INVALID: "The Client Id Or Client Secret is Invalid.",
    PERMISSION_DENIED: "The current user does not have permissions to access this page.",
    VLAN_USED: "This VLAN ID is already used by the LAN interface.",
    NO_INTERFACES: "LAN interfaces could not be none.",
    NO_NETWORK: "This network does not exist.",
    SUBNET_USED: "This range of IP address already exists.",
    SSID_EXISTS: "This SSID already exists.",
    BAD_KEY: "The security key can only contain 8-63 printable ASCII characters or 8-63 "
    "hexadecimal digits.",
    NO_AP: "AP does not exist.",
    NO_DEVICE: "This device does not exist.",
}
#: The LAN interfaces the controller gives a network (without a gateway: four virtual ones).
INTERFACES = [f"{n}_{secrets.token_hex(16)}" for n in (2, 3, 4, 5)]
#: Fields of an SSID in the list (the rest only in its detail).
SSID_LIST_KEYS = (
    "ssidId", "id", "name", "ssidEnable", "chooseDevices", "band", "guestNetEnable", "security",
    "broadcast", "vlanEnable", "vlanId", "vlanPoolIds",
)  # fmt: skip
#: Required by ``POST …/ssids`` and ``PATCH …/update-basic-config``.
SSID_CREATE = (
    "name", "deviceType", "band", "guestNetEnable", "security", "broadcast", "vlanEnable",
    "mloEnable", "pmfMode", "enable11r", "hidePwd",
)  # fmt: skip
SSID_BASIC = (
    "name", "band", "guestNetEnable", "security", "broadcast", "vlanEnable", "mloEnable",
    "pmfMode", "enable11r",
)  # fmt: skip
NETWORK_REQUIRED = ("name", "purpose", "igmpSnoopEnable")


def _port(n: int, profile: str, profile_name: str, **kw: Any) -> dict[str, Any]:
    return {
        "port": n,
        "name": f"Port{n}",
        "profileId": profile,
        "profileName": profile_name,
        "profileOverrideEnable": False,
        "disable": False,
        "linkStatus": kw.pop("link", 1),
        "linkSpeed": kw.pop("speed", 3),
        "duplex": kw.pop("duplex", 2),
        "poe": kw.pop("poe", False),
        "maxSpeed": kw.pop("max_speed", 3),
        **kw,
    }


def _network(net_id: str, name: str, vlan: int, **kw: Any) -> dict[str, Any]:
    """A LAN network as the v1 list answers it."""
    row = {
        "id": net_id,
        "name": name,
        "purpose": 1 if "gatewaySubnet" in kw else 0,
        "interfaceIds": [] if vlan == 1 else list(INTERFACES),
        "vlanType": 0,
        "vlan": vlan,
        "application": 0,
        **kw,
        "igmpSnoopEnable": False,
        "mldSnoopEnable": False,
        "dhcpL2RelayEnable": False,
        "dhcpGuard": {"enable": False},
        "dhcpv6Guard": {"enable": False},
        "portal": False,
        "accessControlRule": False,
        "rateLimit": False,
        "allLan": True,
        "primary": vlan == 1,
    }
    return row


def _dhcp(start: str, end: str, **kw: Any) -> dict[str, Any]:
    return {"enable": True, "ipaddrStart": start, "ipaddrEnd": end, "dhcpns": "auto", **kw}


def _ssid(sid: str, name: str, band: int, security: int, **kw: Any) -> dict[str, Any]:
    """An SSID as its detail answers it."""
    vlan = kw.pop("vlan", None)
    row: dict[str, Any] = {
        "ssidId": sid,
        "id": sid,
        "name": name,
        "band": band,
        "autoWanAccess": False,
        "guestNetEnable": False,
        "security": security,
        "broadcast": kw.pop("broadcast", True),
        "vlanEnable": vlan is not None,
        "mloEnable": False,
        "enable11r": False,
        "deviceType": 1,
        "ssidEnable": kw.pop("enable", True),
        "chooseDevices": 1,
        "apGroupIds": ["wlan-default"],
        **kw,
    }
    if vlan is not None:
        row["vlanId"] = vlan
        row["vlanSetting"] = {
            "mode": 1,
            "customConfig": {"customMode": 1, "vlanPoolIds": str(vlan)},
        }
        row["vlanPoolIds"] = str(vlan)
    else:
        row["vlanSetting"] = {"mode": 0, "customConfig": {}}
    return row


def _wan(
    port: int, name: str, proto: str, connected: bool, kind: int = 0, mode: int = 0
) -> dict[str, Any]:
    """One port of ``…/gateways/{mac}/wan-status`` (fields of the controller's API description)."""
    up = connected and mode == 0
    v4 = {
        "ip": "203.0.113.45" if up else "",
        "netmask": "255.255.255.0" if up else "",
        "ip2": "",
        "gateway": "203.0.113.1" if up else "",
        "gateway2": "",
        "priDns": "203.0.113.53" if up else "",
        "sndDns": "203.0.113.54" if up else "",
        "priDns2": "",
        "sndDns2": "",
        "mac": f"02:00:00:00:0a:1{port}",
    }
    v6 = {
        "enable": 1 if up else 0,
        "proto": "dhcpv6" if up else "",
        "addr": "2001:db8:ffff::45" if up else "",
        "gateway": "fe80::1" if up else "",
        "priDns": "2001:db8:ffff::53" if up else "",
        "sndDns": "",
        "internetState": 1 if up else 0,
        "mac": f"02:00:00:00:0a:1{port}",
    }
    return {
        "port": port,
        "name": name,
        "mac": f"02-00-00-00-0A-1{port}",
        "portDesc": "",
        "type": kind,
        "physicalType": 0,
        "mode": mode,
        "status": 1 if connected else 0,
        "internetState": 1 if up else 0,
        "ip": v4["ip"],
        "speed": 3 if connected else 0,
        "duplex": 2 if connected else 0,
        "proto": proto,
        "wanPortIpv4Config": v4,
        "wanPortIpv6Config": v6,
        "latency": 9 if up else 0,
        "loss": 0.0,
    }


def sample_data() -> dict[str, Any]:
    """Results by path (a fresh copy every call); lists are paged by the simulator."""
    radios = {
        "radioSetting2g": {
            "radioEnable": True,
            "channel": "6",
            "channelWidth": "2",
            "txPower": 20,
            "txPowerLevel": 3,
        },
        "radioSetting5g": {
            "radioEnable": True,
            "channel": "36",
            "channelWidth": "5",
            "txPower": 23,
            "txPowerLevel": 3,
        },
    }
    data: dict[str, Any] = {
        "/api/info": {
            "controllerVer": "6.3.0.111",
            "apiVer": "3",
            "configured": True,
            "type": 1,
            "supportApp": True,
            "omadacId": OMADAC_ID,
            "registeredRoot": True,
            "omadacCategory": "advanced",
            "mspMode": False,
        },
        f"/openapi/v1/{OMADAC_ID}/sites": [
            {
                "siteId": SITE_ID,
                "name": "Default",
                "region": "Germany",
                "timeZone": "UTC",
                "scenario": "Home",
                "type": 0,
                "supportES": False,
                "supportL2": True,
                "primary": False,
            },
            {"siteId": "5f0000000000000000000002", "name": "Branch", "region": "Germany"},
        ],
        # site-wide device services (field names from a third-party SDK of the Open API; the
        # controller's /v3/api-docs is checked in CI)
        f"{SITE}/ssh": {"sshEnable": True, "sshServerPort": 22, "layer3Access": False},
        f"{SITE}/setting/service/snmp": {
            "snmpV1V2CEnable": True,
            "snmpV3Enable": True,
            "securityLevel": 2,
            "communityString": "public",
            "snmpPort": 161,
        },
        f"{SITE}/gateways/{GATEWAY}/wan-status": [
            _wan(1, "SFP WAN", "DHCP", connected=True),
            _wan(2, "WAN2", "PPPoE", connected=False, kind=1),
            _wan(3, "LAN3", "", connected=True, kind=1, mode=1),
        ],
        f"{SITE}/devices": [
            {
                "mac": GATEWAY,
                "name": "Gateway",
                "type": "gateway",
                "model": "ER605 v2.0",
                "modelName": "ER605",
                "ip": "192.0.2.1",
                "status": 1,
                "firmwareVersion": "2.2.3 Build 20231201",
                "uptime": "12day(s) 3h 4m 5s",
                "cpuUtil": 7,
                "memUtil": 41,
            },
            {
                "mac": SWITCH,
                "name": "Switch",
                "type": "switch",
                "model": "TL-SG2008P",
                "ip": "192.0.2.2",
                "status": 1,
                "firmwareVersion": "1.0.5",
                "uptime": "12day(s) 3h 2m 1s",
                "cpuUtil": 3,
                "memUtil": 55,
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
                "uptime": "3h 4m 5s",
                "cpuUtil": 12,
                "memUtil": 63,
            },
            {
                "mac": EAP2,
                "name": "AP 2",
                "type": "ap",
                "model": "EAP225",
                "ip": "192.0.2.4",
                "status": 1,
                "firmwareVersion": "5.1.0",
                "uptimeLong": 86400,
                "cpuUtil": 5,
                "memUtil": 48,
            },
        ],
        f"{SITE}/lan-networks": [
            _network(
                "net-lan",
                "LAN",
                1,
                gatewaySubnet="192.0.2.1/24",
                dhcpSettingsVO=_dhcp(
                    "192.0.2.100", "192.0.2.199", leasetime=120, gateway="192.0.2.1"
                ),
                domain="lan.example",
            ),
            _network(
                "net-iot",
                "IoT",
                20,
                gatewaySubnet="198.51.100.1/24",
                dhcpSettingsVO=_dhcp(
                    "198.51.100.100",
                    "198.51.100.150",
                    leasetime=1440,
                    dhcpns="manual",
                    priDns="198.51.100.1",
                    sndDns="192.0.2.53",
                ),
            ),
            _network("net-guest", "Guest", 30),
        ],
        f"{SITE}/lan-profiles": [
            {
                "id": "prof-all",
                "flag": 0,
                "name": "All",
                "poe": 2,
                "nativeNetworkId": "net-lan",
                "tagNetworkIds": ["net-iot", "net-guest"],
                "untagNetworkIds": ["net-lan"],
                "type": 0,
            },
            {
                "id": "prof-lan",
                "flag": 2,
                "name": "LAN",
                "poe": 2,
                "nativeNetworkId": "net-lan",
                "tagNetworkIds": [],
                "untagNetworkIds": [],
                "type": 2,
            },
            {
                "id": "prof-iot",
                "flag": 2,
                "name": "IoT access",
                "poe": 2,
                "nativeNetworkId": "net-iot",
                "type": 2,
            },
        ],
        # the switch's own settings: jumbo frames up to 9216 bytes (1518: off)
        f"{SITE}/switches/{SWITCH}{SETTINGS_KEY}": {"jumbo": 9216},
        f"{SITE}/switches/{SWITCH}{PORTS_KEY}": [
            _port(1, "prof-all", "All", speed=4, max_speed=4),
            _port(2, "prof-all", "All", poe=True),
            _port(3, "prof-all", "All", poe=True),
            _port(4, "prof-lan", "LAN", link=0, speed=0, duplex=0),
            _port(5, "prof-lan", "LAN", speed=2, duplex=1),
            _port(6, "prof-lan", "LAN", link=0, speed=0, duplex=0, disable=True),
            _port(7, "prof-iot", "IoT access"),
            # A port-level override of the profile: Guest untagged, nothing tagged.
            _port(
                8,
                "prof-all",
                "All",
                link=0,
                profileOverrideEnable=True,
                nativeNetworkId="net-guest",
                tagNetworkIds=[],
            ),
        ],
        f"{SITE}/aps/{EAP1}/radio-config": copy.deepcopy(radios),
        f"{SITE}/aps/{EAP2}/radio-config": {
            **copy.deepcopy(radios),
            "radioSetting5g": {"radioEnable": False, "channel": "0", "channelWidth": "6"},
        },
        f"{SITE}/wireless-network/wlans": [
            {
                "wlanId": "wlan-default",
                "name": "Default",
                "primary": True,
                "clone": False,
                "site": SITE_ID,
                "resource": 0,
            },
        ],
        f"{SITE}/wireless-network/wlans/wlan-default/ssids": [
            _ssid(
                "ssid-home",
                "Home",
                3,
                3,
                pmfMode=2,
                pskSetting={
                    "securityKey": "example-home-passphrase",
                    "versionPsk": 2,
                    "encryptionPsk": 3,
                    "gikRekeyPskEnable": False,
                },
            ),
            _ssid(
                "ssid-iot",
                "IoT",
                1,
                3,
                broadcast=False,
                vlan=20,
                pmfMode=3,
                pskSetting={
                    "securityKey": "example-iot-passphrase",
                    "versionPsk": 2,
                    "encryptionPsk": 1,
                    "gikRekeyPskEnable": True,
                    "rekeyPskInterval": 3600,
                },
            ),
            _ssid("ssid-guest", "Guest", 3, 0, vlan=30, guestNetEnable=True),
        ],
        f"{SITE}/clients": [
            {
                "mac": "02-00-00-00-00-21",
                "name": "laptop",
                "hostName": "laptop",
                "ip": "192.0.2.100",
                "ipv6List": ["2001:db8:1::21"],
                "wireless": True,
                "connectType": 1,
                "connectDevType": "ap",
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
                "connectType": 2,
                "connectDevType": "switch",
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


def _wrap(result: Any, code: int = 0, msg: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"errorCode": code, "msg": msg or MESSAGES.get(code, "Success.")}
    if code == 0 and result is not None:
        body["result"] = result
    return JSONResponse(body)


def _html(status: int, text: str) -> Response:
    """Tomcat's own error page (unknown paths, methods, unreadable bodies)."""
    page = f"<!doctype html><html><body><h1>HTTP Status {status} - {text}</h1></body></html>"
    return Response(page, status_code=status, media_type="text/html")


def _missing(body: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    gone = [k for k in keys if body.get(k) is None]
    return "".join(f"Parameter [{k}] should not be null.\n" for k in gone) or None


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
    #: The Open API application has the viewer role: every write is refused.
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
            return _wrap(None, CLIENT_INVALID)
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

    def _read(self, path: str, request: Request) -> Response:
        """A GET: the data at the path, or what the controller derives from it."""
        if path.endswith(PORTS_KEY):
            return _html(404, "Not Found")
        if path in self.data and path.endswith("/wan-status"):  # a plain list, not paged
            return _wrap(self.data[path])
        if path in self.data:
            value = self.data[path]
            if path.endswith("/ssids") and isinstance(value, list):
                value = [{k: r[k] for k in SSID_LIST_KEYS if k in r} for r in value]
            if path in self.malformed:
                return Response('{"errorCode": 0, "result": {', media_type="application/json")
            return _wrap(self._page(value, request))
        parent, _, item = path.rpartition("/")
        rows = self.data.get(parent)
        if parent.endswith("/ssids") and isinstance(rows, list):
            row = next((r for r in rows if r.get("ssidId") == item), None)
            if row is None:
                return _wrap(None, -33200, "This SSID does not exist.")
            if row.get("hidePwd") and isinstance(row.get("pskSetting"), dict):
                # "the SSID password will be hidden" (API description; not tried on 6.3)
                psk = {k: v for k, v in row["pskSetting"].items() if k != "securityKey"}
                row = {**row, "pskSetting": psk}
            return _wrap(row)
        if parent.endswith("/lan-networks") and isinstance(rows, list):
            row = next((r for r in rows if r.get("id") == item), None)
            if row is None:
                return _wrap(None, NO_NETWORK)
            detail = {k: v for k, v in row.items() if k != "dhcpSettingsVO"}
            dhcp = row.get("dhcpSettingsVO")
            if isinstance(dhcp, dict):  # the detail has the v3 shape: a list of ranges
                pool = {k: dhcp[k] for k in ("ipaddrStart", "ipaddrEnd") if k in dhcp}
                rest = {k: v for k, v in dhcp.items() if k not in pool}
                detail["dhcpSettings"] = {**rest, "ipRangePool": [pool] if pool else []}
            return _wrap(detail)
        if parent.endswith("/switches"):
            ports = self.data.get(f"{path}{PORTS_KEY}")
            if ports is None:
                return _wrap(None, NO_DEVICE)
            settings = self.data.get(f"{path}{SETTINGS_KEY}") or {}
            return _wrap({"mac": item, **settings, "portList": ports})
        if path.endswith("/radio-config"):
            return _wrap(None, NO_AP)
        return _html(404, "Not Found")

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
                if not auth.startswith("AccessToken="):
                    code = OPEN_API_AUTH_FAILED
                    return JSONResponse({"msg": MESSAGES[code], "errorCode": code}, 401)
                if token not in self.tokens:
                    return _wrap(None, TOKEN_EXPIRED)
                if self.expire_next:
                    self.expire_next = False
                    self.tokens.clear()
                    return _wrap(None, TOKEN_EXPIRED)
            if path in self.error:
                code, msg = self.error[path]
                return _wrap(None, code, msg)
            if request.method != "GET":
                try:
                    body = json.loads(await request.body() or b"null")
                except ValueError:
                    return _html(400, "Bad Request")
                return self._write(request.method, path, body)
            return self._read(path, request)

        return app

    # --- writes --------------------------------------------------------------------------

    def _write(self, method: str, path: str, body: Any) -> Response:
        self.writes.append((method, path, copy.deepcopy(body)))
        if self.read_only:
            return _wrap(None, PERMISSION_DENIED)
        if path in self.write_error:
            code, msg = self.write_error[path]
            return _wrap(None, code, msg)
        if path.endswith("/enable") and "/wireless-network/ssids/" in path:
            return self._ssid_enable(path, body)
        if path.endswith("/update-basic-config"):
            return self._ssid_update(path.removesuffix("/update-basic-config"), body)
        if method == "POST":
            return self._create(path, body)
        list_path, _, item = path.rpartition("/")
        kind = list_path.rsplit("/", 1)[-1]
        if kind == "ports":
            list_path = f"{list_path.removesuffix('/ports')}{PORTS_KEY}"
        rows = self.data.get(list_path)
        if not isinstance(rows, list) or kind not in ("lan-networks", "ssids", "ports"):
            return _html(404, "Not Found")
        if kind == "ssids" and method == "PATCH":
            return _html(405, "Method Not Allowed")
        key = {"lan-networks": "id", "ssids": "ssidId", "ports": "port"}[kind]
        index = next((i for i, r in enumerate(rows) if str(r.get(key)) == item), None)
        if index is None:
            if kind == "lan-networks":
                return _wrap(None, NO_NETWORK)
            return _wrap(None, -33000, "Not found.")
        if method == "DELETE":
            if kind == "ports":
                return _html(405, "Method Not Allowed")
            del rows[index]
            return _wrap(None)
        if not isinstance(body, dict):
            return _wrap(None, INVALID_PARAMS, "Invalid request parameters.")
        if kind == "lan-networks":
            return self._network_update(rows, index, body)
        row = {**rows[index], **body}
        row = {k: v for k, v in row.items() if v is not None}
        row["port"] = rows[index]["port"]
        problem = self._port_invalid(row)
        if problem:
            return _wrap(None, INVALID_PARAMS, problem)
        rows[index] = row
        return _wrap(None)

    def _rows(self, suffix: str) -> list[dict[str, Any]]:
        return [r for p, v in self.data.items() if p.endswith(suffix) for r in v]

    def _create(self, path: str, body: Any) -> Response:
        rows = self.data.get(path)
        kind = path.rsplit("/", 1)[-1]
        if not isinstance(rows, list) or kind not in ("lan-networks", "ssids"):
            return _html(404, "Not Found")
        if not isinstance(body, dict):
            return _wrap(None, INVALID_PARAMS, "Invalid request parameters.")
        self.created += 1
        if kind == "lan-networks":
            if isinstance(body.get("purpose"), str):
                return _html(400, "Bad Request")  # the enum is a number
            missing = _missing(body, NETWORK_REQUIRED)
            if missing:
                return _wrap(None, INVALID_PARAMS, missing)
            row = {k: v for k, v in body.items() if v is not None}
            row["id"] = f"net-new{self.created}"
            if row.get("purpose") == 0:
                row["interfaceIds"] = list(INTERFACES)
            problem = self._network_invalid(rows, row, None)
            if problem:
                return _wrap(None, *problem)
            rows.append({**row, "primary": False})
            return _wrap({"id": row["id"]})
        missing = _missing(body, SSID_CREATE)
        if missing:
            return _wrap(None, INVALID_PARAMS, missing)
        sid = f"ssid-new{self.created}"
        row = {k: v for k, v in body.items() if v is not None}
        row.update(ssidId=sid, id=sid)
        row.setdefault("ssidEnable", True)
        row.setdefault("autoWanAccess", False)
        row.setdefault("chooseDevices", 1)
        row.setdefault("apGroupIds", [path.split("/wlans/")[1].split("/")[0]])
        problem = self._ssid_invalid(rows, row, None)
        if problem:
            return _wrap(None, *problem)
        rows.append(row)
        return _wrap({"ssidId": sid})

    def _network_invalid(
        self, rows: list[dict[str, Any]], row: dict[str, Any], index: int | None
    ) -> tuple[int, str] | None:
        vlan = row.get("vlan")
        if not isinstance(row.get("name"), str) or not row["name"]:
            return INVALID_PARAMS, "Parameter [name] should not be null.\n"
        if not isinstance(vlan, int) or not 1 <= vlan <= 4094:
            return INVALID_PARAMS, "Vlan should be within the range of 1-4094."
        if any(r.get("vlan") == vlan for i, r in enumerate(rows) if i != index):
            return VLAN_USED, MESSAGES[VLAN_USED]
        if row.get("purpose") == 1:
            if not row.get("gatewaySubnet"):
                return INVALID_PARAMS, "Parameter [gatewaySubnet] should not be null.\n"
            if not row.get("interfaceIds") and not row.get("primary"):
                return NO_INTERFACES, MESSAGES[NO_INTERFACES]
            try:
                mine = ip_interface(row["gatewaySubnet"]).network
            except ValueError:
                return INVALID_PARAMS, "Invalid request parameters."
            for i, r in enumerate(rows):
                other = r.get("gatewaySubnet")
                if i != index and other and ip_interface(other).network.overlaps(mine):
                    return SUBNET_USED, MESSAGES[SUBNET_USED]
        return None

    def _network_update(
        self, rows: list[dict[str, Any]], index: int, body: dict[str, Any]
    ) -> Response:
        """A PATCH replaces the network: what it leaves out is gone."""
        if isinstance(body.get("purpose"), str):
            return _html(400, "Bad Request")
        missing = _missing(body, NETWORK_REQUIRED)
        if missing:
            return _wrap(None, INVALID_PARAMS, missing)
        old = rows[index]
        row = {k: v for k, v in body.items() if v is not None}
        row.update(id=old["id"], primary=old.get("primary", False))
        if body.get("dhcpSettingsVO", "") is None and "dhcpSettingsVO" in old:
            row["dhcpSettingsVO"] = {"enable": False}  # what the controller leaves of it
        if row.get("purpose") == 0:
            row.pop("gatewaySubnet", None)
            row.pop("dhcpSettingsVO", None)
        problem = self._network_invalid(rows, row, index)
        if problem:
            return _wrap(None, *problem)
        rows[index] = row
        return _wrap(None)

    def _ssid_invalid(
        self, rows: list[dict[str, Any]], row: dict[str, Any], index: int | None
    ) -> tuple[int, str] | None:
        if not isinstance(row.get("name"), str) or not row["name"]:
            return INVALID_PARAMS, "Parameter [name] should not be null.\n"
        if any(r.get("name") == row["name"] for i, r in enumerate(rows) if i != index):
            return SSID_EXISTS, MESSAGES[SSID_EXISTS]
        if row.get("security") == 3:
            key = (row.get("pskSetting") or {}).get("securityKey")
            if not isinstance(key, str) or not 8 <= len(key) <= 63:
                return BAD_KEY, MESSAGES[BAD_KEY]
        else:  # an open SSID: the controller keeps neither the WPA settings nor the PMF mode
            row.pop("pskSetting", None)
            row.pop("pmfMode", None)
        if not row.get("hidePwd"):
            row.pop("hidePwd", None)  # taken, answered only when set
        if row.get("vlanEnable"):
            vlan = row.get("vlanId")
            row["vlanSetting"] = {
                "mode": 1,
                "customConfig": {"customMode": 1, "vlanPoolIds": str(vlan)},
            }
            row["vlanPoolIds"] = str(vlan)
        else:
            row.pop("vlanId", None)
            row.pop("vlanPoolIds", None)
            row["vlanSetting"] = {"mode": 0, "customConfig": {}}
        return None

    def _ssid_update(self, path: str, body: Any) -> Response:
        list_path, _, sid = path.rpartition("/")
        rows = self.data.get(list_path)
        if not isinstance(rows, list):
            return _html(404, "Not Found")
        index = next((i for i, r in enumerate(rows) if r.get("ssidId") == sid), None)
        if index is None:
            return _wrap(None, -33200, "This SSID does not exist.")
        if not isinstance(body, dict):
            return _wrap(None, INVALID_PARAMS, "Invalid request parameters.")
        missing = _missing(body, SSID_BASIC)
        if missing:
            return _wrap(None, INVALID_PARAMS, missing)
        setting = body.get("vlanSetting")
        if isinstance(setting, dict) and setting.get("mode") == 0 and "customConfig" in setting:
            return _wrap(
                None, INVALID_PARAMS, "Cannot set vlanId and customConfig when the mode of "
                "vlanSetting is 0."
            )  # fmt: skip
        row = {**rows[index], **{k: v for k, v in body.items() if v is not None}}
        if body.get("security") == 3 and "securityKey" not in (body.get("pskSetting") or {}):
            return _wrap(None, INVALID_PARAMS, "Invalid request parameters.")
        problem = self._ssid_invalid(rows, row, index)
        if problem:
            return _wrap(None, *problem)
        rows[index] = row
        return _wrap(None)

    def _ssid_enable(self, path: str, body: Any) -> Response:
        sid = path.removesuffix("/enable").rsplit("/", 1)[-1]
        for row in self._rows("/ssids"):
            if row.get("ssidId") == sid:
                if not isinstance(body, dict) or not isinstance(body.get("ssidEnable"), bool):
                    return _wrap(
                        None, INVALID_PARAMS, "Parameter [ssidEnable] should not be null.\n"
                    )
                row["ssidEnable"] = body["ssidEnable"]
                return _wrap(None)
        return _wrap(None, -33200, "This SSID does not exist.")

    def _port_invalid(self, row: dict[str, Any]) -> str | None:
        nets = {r.get("id") for r in self._rows("/lan-networks")}
        wanted = [row.get("nativeNetworkId"), *(row.get("tagNetworkIds") or [])]
        if any(n is not None and n not in nets for n in wanted):
            return "The network does not exist."
        profiles = {r.get("id"): r for r in self._rows("/lan-profiles")}
        if row.get("profileId") not in profiles:
            return "The profile does not exist."
        row["profileName"] = profiles[row["profileId"]].get("name", "")
        return None


def create_app() -> FastAPI:
    """``uvicorn --factory signalbox.sim.omada:create_app``"""
    return OmadaSimulator().app()
