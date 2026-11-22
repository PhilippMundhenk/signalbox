"""Simulator of the RouterOS 7 REST API (``GET /rest/<menu>``) the ``mikrotik`` adapter reads.

The answers follow the JSON shapes in ``docs/adapters/mikrotik.md`` (from the RouterOS
documentation, not yet confirmed on a real device, issue #21): lists of objects with ``.id``,
every value a string. Sample network, documentation addresses only:

- a hEX-like router with Wi-Fi: ``ether1`` is the uplink (interface list ``WAN``,
  203.0.113.2/24), ``ether2``-``ether5``, ``wifi1`` (2.4 GHz), ``wifi2`` (5 GHz) and the virtual
  ``wifi3`` in ``bridge`` with VLAN filtering
- VLAN 1 (native LAN, 192.0.2.1/24, 2001:db8:1::1/64) untagged on ether2, ether3, wifi1/2;
  VLAN 20 "iot" (198.51.100.1/24) tagged on ether2, untagged on ether4 and wifi3; ether5 disabled
- DHCP on both, with static leases; DNS with static entries; ARP, IPv6 neighbours, bridge hosts,
  Wi-Fi registrations; one LLDP/MNDP neighbour (a switch on ether2)

Failure switches on :class:`MikrotikSimulator`: ``rest_enabled=False`` (404 on everything),
``delay`` (seconds before every answer), ``malformed`` (paths answering broken JSON), ``fail``
(a status code per path), ``wireless`` (``"wifi"``, ``"legacy"`` or ``"none"``: which wireless
package is installed); a wrong user or password is answered with 401. ``data`` can be edited.
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

USER = "signalbox"
PASSWORD = "sim-password"
#: Wi-Fi passphrase of the sample SSID "Example" (to test the fingerprint).
PASSPHRASE = "correct horse battery staple"

MAC = "02:00:00:00:{:02x}:{:02x}"


def _mac(a: int, b: int) -> str:
    return MAC.format(a, b).upper()  # RouterOS writes MACs in upper case


def _ids(*rows: dict[str, Any]) -> list[dict[str, Any]]:
    """A menu answer: every row gets a ``.id`` (``*1``, ``*2``, ...)."""
    return [{".id": f"*{i:X}", **row} for i, row in enumerate(rows, start=1)]


def _iface(name: str, kind: str, mac: str, running: bool = True, **kw: Any) -> dict[str, Any]:
    return {
        "name": name,
        "default-name": name if kind == "ether" else "",
        "type": kind,
        "mtu": "1500",
        "actual-mtu": "1500",
        "mac-address": mac,
        "running": "true" if running else "false",
        "disabled": "false",
        "dynamic": "false",
        "slave": "false",
        **kw,
    }


def _ether(name: str, speed: str) -> dict[str, Any]:
    return {"name": name, "default-name": name, "speed": speed, "auto-negotiation": "true"}


def _port(interface: str, pvid: str = "1", frame_types: str = "admit-all") -> dict[str, Any]:
    return {
        "interface": interface,
        "bridge": "bridge",
        "pvid": pvid,
        "frame-types": frame_types,
        "ingress-filtering": "true",
        "disabled": "false",
        "dynamic": "false",
        "inactive": "false",
    }


def sample_data() -> dict[str, Any]:
    """Answers by path (a fresh copy every call)."""
    bridge_mac = _mac(1, 0)
    data: dict[str, Any] = {
        "/rest/system/resource": {
            "uptime": "3d04:05:06",
            "version": "7.15.3 (stable)",
            "build-time": "2024-07-24 10:39:00",
            "factory-software": "7.0.4",
            "free-memory": "190000000",
            "total-memory": "268435456",
            "cpu": "ARMv7",
            "cpu-count": "4",
            "architecture-name": "arm64",
            "board-name": "hAP ax^2",
            "platform": "MikroTik",
        },
        "/rest/system/routerboard": {
            "routerboard": "true",
            "board-name": "hAP ax^2",
            "model": "C52iG-5HaxD2HaxD",
            "firmware-type": "ipq6000",
            "current-firmware": "7.15.3",
            "upgrade-firmware": "7.15.3",
        },
        "/rest/system/package/update": {
            "channel": "stable",
            "installed-version": "7.15.3",
            "latest-version": "7.16",
            "status": "New version is available",
        },
        "/rest/interface": _ids(
            _iface("ether1", "ether", _mac(0, 1), comment="uplink"),
            _iface("ether2", "ether", _mac(0, 2)),
            _iface("ether3", "ether", _mac(0, 3)),
            _iface("ether4", "ether", _mac(0, 4)),
            _iface("ether5", "ether", _mac(0, 5), running=False, disabled="true"),
            _iface("wifi1", "wifi", _mac(0, 6)),
            _iface("wifi2", "wifi", _mac(0, 7)),
            _iface("wifi3", "wifi", _mac(0, 8)),
            _iface("bridge", "bridge", bridge_mac),
            _iface("iot", "vlan", bridge_mac),
            _iface("lo", "loopback", "00:00:00:00:00:00"),
        ),
        "/rest/interface/ethernet": _ids(
            _ether("ether1", "1G-baseT-full"),
            _ether("ether2", "1Gbps"),
            _ether("ether3", "100M-baseT-half"),
            _ether("ether4", "1G-baseT-full"),
            _ether("ether5", "1G-baseT-full"),
        ),
        "/rest/interface/bridge": _ids(
            {
                "name": "bridge",
                "comment": "LAN",
                "vlan-filtering": "true",
                "pvid": "1",
                "frame-types": "admit-all",
                "protocol-mode": "rstp",
                "mac-address": bridge_mac,
                "disabled": "false",
            }
        ),
        "/rest/interface/bridge/port": _ids(
            _port("ether2"),
            _port("ether3", frame_types="admit-only-untagged-and-priority-tagged"),
            _port("ether4", pvid="20", frame_types="admit-only-untagged-and-priority-tagged"),
            _port("ether5"),
            _port("wifi1"),
            _port("wifi2"),
            _port("wifi3", pvid="20"),
        ),
        "/rest/interface/bridge/vlan": _ids(
            {
                "bridge": "bridge",
                "vlan-ids": "1",
                "tagged": "",
                "untagged": "",
                "current-tagged": "",
                "current-untagged": "bridge,ether2,ether3,wifi1,wifi2",
                "dynamic": "true",
                "disabled": "false",
            },
            {
                "bridge": "bridge",
                "vlan-ids": "20",
                "tagged": "bridge,ether2",
                "untagged": "ether4",
                "current-tagged": "bridge,ether2",
                "current-untagged": "ether4,wifi3",
                "comment": "IoT devices",
                "dynamic": "false",
                "disabled": "false",
            },
        ),
        "/rest/interface/vlan": _ids(
            {
                "name": "iot",
                "vlan-id": "20",
                "interface": "bridge",
                "mtu": "1500",
                "mac-address": bridge_mac,
                "running": "true",
                "disabled": "false",
            }
        ),
        "/rest/interface/list/member": _ids(
            {"list": "WAN", "interface": "ether1", "disabled": "false", "dynamic": "false"},
            {"list": "LAN", "interface": "bridge", "disabled": "false", "dynamic": "false"},
        ),
        "/rest/ip/address": _ids(
            {
                "address": "192.0.2.1/24",
                "network": "192.0.2.0",
                "interface": "bridge",
                "actual-interface": "bridge",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            },
            {
                "address": "198.51.100.1/24",
                "network": "198.51.100.0",
                "interface": "iot",
                "actual-interface": "iot",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
            },
            {
                "address": "203.0.113.2/24",
                "network": "203.0.113.0",
                "interface": "ether1",
                "actual-interface": "ether1",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
            },
        ),
        "/rest/ipv6/address": _ids(
            {
                "address": "2001:db8:1::1/64",
                "interface": "bridge",
                "actual-interface": "bridge",
                "advertise": "true",
                "disabled": "false",
                "dynamic": "false",
                "invalid": "false",
                "link-local": "false",
            },
            {
                "address": "fe80::1/64",
                "interface": "bridge",
                "actual-interface": "bridge",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
                "link-local": "true",
            },
            {
                "address": "2001:db8:ffff::2/64",
                "interface": "ether1",
                "actual-interface": "ether1",
                "disabled": "false",
                "dynamic": "true",
                "invalid": "false",
            },
        ),
        "/rest/ip/dhcp-server": _ids(
            {
                "name": "defconf",
                "interface": "bridge",
                "address-pool": "default-dhcp",
                "lease-time": "30m",
                "disabled": "false",
                "invalid": "false",
                "dynamic": "false",
            },
            {
                "name": "iot-dhcp",
                "interface": "iot",
                "address-pool": "iot-pool",
                "lease-time": "1d00:00:00",
                "disabled": "false",
                "invalid": "false",
                "dynamic": "false",
            },
        ),
        "/rest/ip/dhcp-server/network": _ids(
            {
                "address": "192.0.2.0/24",
                "gateway": "192.0.2.1",
                "dns-server": "192.0.2.1",
                "domain": "home.example",
                "comment": "defconf",
            },
            {
                "address": "198.51.100.0/24",
                "gateway": "198.51.100.1",
                "dns-server": "198.51.100.1,192.0.2.1",
                "domain": "iot.example",
            },
        ),
        "/rest/ip/pool": _ids(
            {"name": "default-dhcp", "ranges": "192.0.2.100-192.0.2.199"},
            {
                "name": "iot-pool",
                "ranges": "198.51.100.100-198.51.100.149,198.51.100.200-198.51.100.210",
            },
        ),
        "/rest/ip/dhcp-server/lease": _ids(
            {
                "address": "192.0.2.10",
                "mac-address": _mac(0, 0x10),
                "server": "defconf",
                "comment": "printer",
                "host-name": "PRN-0010",
                "status": "bound",
                "dynamic": "false",
                "disabled": "false",
                "active-address": "192.0.2.10",
                "active-mac-address": _mac(0, 0x10),
            },
            {
                "address": "198.51.100.20",
                "mac-address": _mac(0, 0x20),
                "server": "iot-dhcp",
                "host-name": "sensor",
                "status": "waiting",
                "dynamic": "false",
                "disabled": "false",
            },
            {
                "address": "192.0.2.100",
                "mac-address": _mac(0, 0x21),
                "server": "defconf",
                "host-name": "laptop",
                "status": "bound",
                "dynamic": "true",
                "disabled": "false",
                "active-address": "192.0.2.100",
                "active-mac-address": _mac(0, 0x21),
                "expires-after": "25m10s",
            },
            {
                "address": "198.51.100.101",
                "mac-address": _mac(0, 0x22),
                "server": "iot-dhcp",
                "host-name": "phone",
                "status": "bound",
                "dynamic": "true",
                "disabled": "false",
            },
        ),
        "/rest/ip/dns": {
            "servers": "192.0.2.53,2001:db8:53::53",
            "dynamic-servers": "203.0.113.1",
            "allow-remote-requests": "true",
            "cache-size": "2048KiB",
            "cache-max-ttl": "1w",
        },
        "/rest/ip/dns/static": _ids(
            {"name": "nas.home.example", "address": "192.0.2.10", "ttl": "1d", "disabled": "false"},
            {
                "name": "nas.home.example",
                "type": "AAAA",
                "address": "2001:db8:1::10",
                "ttl": "1d",
                "disabled": "false",
            },
            {"name": "old.home.example", "address": "192.0.2.11", "disabled": "true"},
            {
                "name": "files.home.example",
                "type": "CNAME",
                "cname": "nas.home.example",
                "disabled": "false",
            },
            {"regexp": ".*\\.ads\\.example", "address": "0.0.0.0", "disabled": "false"},
        ),
        "/rest/ip/arp": _ids(
            {
                "address": "192.0.2.10",
                "mac-address": _mac(0, 0x10),
                "interface": "bridge",
                "status": "reachable",
                "dynamic": "true",
                "complete": "true",
                "DHCP": "true",
            },
            {
                "address": "192.0.2.100",
                "mac-address": _mac(0, 0x21),
                "interface": "bridge",
                "status": "stale",
                "dynamic": "true",
                "complete": "true",
            },
            {
                "address": "198.51.100.20",
                "mac-address": _mac(0, 0x20),
                "interface": "iot",
                "status": "reachable",
                "dynamic": "true",
            },
            {
                "address": "203.0.113.1",
                "mac-address": _mac(9, 1),
                "interface": "ether1",
                "status": "reachable",
                "dynamic": "true",
            },
            {"address": "192.0.2.99", "interface": "bridge", "status": "failed"},
        ),
        "/rest/ipv6/neighbor": _ids(
            {
                "address": "2001:db8:1::10",
                "mac-address": _mac(0, 0x10),
                "interface": "bridge",
                "status": "reachable",
            },
            {
                "address": "fe80::10",
                "mac-address": _mac(0, 0x10),
                "interface": "bridge",
                "status": "stale",
            },
        ),
        "/rest/interface/bridge/host": _ids(
            {
                "mac-address": bridge_mac,
                "on-interface": "bridge",
                "bridge": "bridge",
                "vid": "1",
                "local": "true",
                "dynamic": "false",
            },
            {
                "mac-address": _mac(0, 0x10),
                "on-interface": "ether3",
                "bridge": "bridge",
                "vid": "1",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x21),
                "on-interface": "ether2",
                "bridge": "bridge",
                "vid": "1",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x20),
                "on-interface": "ether4",
                "bridge": "bridge",
                "vid": "20",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x22),
                "on-interface": "wifi3",
                "bridge": "bridge",
                "vid": "20",
                "local": "false",
                "dynamic": "true",
            },
            {
                "mac-address": _mac(0, 0x50),
                "on-interface": "ether2",
                "bridge": "bridge",
                "vid": "1",
                "local": "false",
                "dynamic": "true",
            },
        ),
        "/rest/ip/neighbor": _ids(
            {
                "interface": "ether2,bridge",
                "address": "192.0.2.2",
                "address4": "192.0.2.2",
                "mac-address": _mac(0, 0x50),
                "identity": "switch",
                "platform": "MikroTik",
                "version": "7.15.3 (stable)",
                "board": "CRS326-24G-2S+",
                "interface-name": "ether24",
                "discovered-by": "lldp,mndp",
                "system-caps": "bridge,router",
            },
            {"interface": "ether1", "identity": "isp-modem", "discovered-by": "cdp"},
        ),
        "/rest/interface/wifi": _ids(
            {
                "name": "wifi1",
                "default-name": "wifi1",
                "mac-address": _mac(0, 6),
                "configuration.mode": "ap",
                "configuration.ssid": "Example",
                "configuration.country": "Germany",
                "configuration.tx-power": "17",
                "channel.band": "2ghz-ax",
                "channel.frequency": "2437",
                "channel.width": "20/40mhz",
                "security": "home",
                "steering.rrm": "yes",
                "steering.wnm": "yes",
                "datapath.bridge": "bridge",
                "disabled": "false",
                "running": "true",
            },
            {
                "name": "wifi2",
                "default-name": "wifi2",
                "mac-address": _mac(0, 7),
                "configuration": "home-5g",
                "channel.band": "5ghz-ax",
                "channel.width": "20/40/80mhz",
                "security": "home",
                "datapath.bridge": "bridge",
                "disabled": "false",
                "running": "true",
            },
            {
                "name": "wifi3",
                "master-interface": "wifi1",
                "mac-address": _mac(0, 8),
                "configuration.mode": "ap",
                "configuration.ssid": "Example-IoT",
                "configuration.hide-ssid": "true",
                "security.authentication-types": "wpa2-psk",
                "security.passphrase": "iot-passphrase",
                "datapath.bridge": "bridge",
                "datapath.vlan-id": "20",
                "disabled": "false",
                "running": "true",
            },
        ),
        "/rest/interface/wifi/configuration": _ids(
            {
                "name": "home-5g",
                "mode": "ap",
                "ssid": "Example",
                "country": "Germany",
                "tx-power": "23",
            }
        ),
        "/rest/interface/wifi/security": _ids(
            {
                "name": "home",
                "authentication-types": "wpa2-psk,wpa3-psk",
                "passphrase": PASSPHRASE,
                "management-protection": "allowed",
                "ft": "yes",
                "ft-over-ds": "yes",
            }
        ),
        "/rest/interface/wifi/channel": [],
        "/rest/interface/wifi/registration-table": _ids(
            {
                "interface": "wifi3",
                "ssid": "Example-IoT",
                "mac-address": _mac(0, 0x22),
                "uptime": "1h2m3s",
                "signal": "-61",
                "band": "2ghz-ax",
            }
        ),
    }
    return copy.deepcopy(data | legacy_wireless())


def legacy_wireless() -> dict[str, Any]:
    """Answers of the older ``wireless`` package (served with ``wireless="legacy"``)."""
    return {
        "/rest/interface/wireless": _ids(
            {
                "name": "wlan1",
                "mode": "ap-bridge",
                "ssid": "Example",
                "band": "2ghz-b/g/n",
                "frequency": "2412",
                "channel-width": "20/40mhz-XX",
                "country": "germany",
                "security-profile": "home",
                "hide-ssid": "false",
                "vlan-mode": "no-tag",
                "vlan-id": "1",
                "disabled": "false",
                "running": "true",
                "mac-address": _mac(0, 6),
            },
            {
                "name": "wlan2",
                "mode": "ap-bridge",
                "ssid": "Example",
                "band": "5ghz-a/n/ac",
                "frequency": "auto",
                "channel-width": "20/40/80mhz-XXXX",
                "security-profile": "home",
                "disabled": "true",
                "running": "false",
                "mac-address": _mac(0, 7),
            },
            {
                "name": "wlan3",
                "master-interface": "wlan1",
                "mode": "ap-bridge",
                "ssid": "Example-Guest",
                "security-profile": "default",
                "vlan-mode": "use-tag",
                "vlan-id": "30",
                "disabled": "false",
            },
            {"name": "wlan4", "master-interface": "wlan1", "mode": "station", "ssid": "Upstream"},
        ),
        "/rest/interface/wireless/security-profiles": _ids(
            {
                "name": "default",
                "mode": "none",
                "authentication-types": "",
                "management-protection": "disabled",
            },
            {
                "name": "home",
                "mode": "dynamic-keys",
                "authentication-types": "wpa2-psk",
                "wpa2-pre-shared-key": PASSPHRASE,
                "management-protection": "allowed",
            },
        ),
        "/rest/interface/wireless/registration-table": _ids(
            {"interface": "wlan1", "mac-address": _mac(0, 0x23), "signal-strength": "-55dBm"}
        ),
    }


WIFI_PATHS = (
    "/rest/interface/wifi",
    "/rest/interface/wifi/configuration",
    "/rest/interface/wifi/security",
    "/rest/interface/wifi/channel",
    "/rest/interface/wifi/registration-table",
)
LEGACY_PATHS = (
    "/rest/interface/wireless",
    "/rest/interface/wireless/security-profiles",
    "/rest/interface/wireless/registration-table",
)


@dataclass
class MikrotikSimulator:
    username: str = USER
    password: str = PASSWORD
    rest_enabled: bool = True
    delay: float = 0.0
    malformed: set[str] = field(default_factory=set)
    #: Status code to answer per path instead of the data (403, 500, ...).
    fail: dict[str, int] = field(default_factory=dict)
    #: Installed wireless package: "wifi" (RouterOS 7 wifi), "legacy" (wireless) or "none".
    wireless: str = "wifi"
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
        return secrets.compare_digest(user, self.username) and secrets.compare_digest(
            password, self.password
        )

    def answers(self) -> dict[str, Any]:
        """``data`` without the menus of the wireless packages that are not installed."""
        absent = {
            "wifi": LEGACY_PATHS,
            "legacy": WIFI_PATHS,
        }.get(self.wireless, WIFI_PATHS + LEGACY_PATHS)
        return {k: v for k, v in self.data.items() if k not in absent}

    def app(self) -> FastAPI:
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
        not_found = {"error": 404, "message": "Not Found"}

        @app.api_route("/{path:path}", methods=["GET"])
        async def answer(path: str, request: Request) -> Response:
            path = "/" + path
            self.requests.append(path)
            if not self.rest_enabled:
                return JSONResponse(not_found, status_code=404)
            if not self.authorised(request.headers.get("authorization")):
                return JSONResponse(
                    {"error": 401, "message": "Unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="RouterOS"'},
                )
            if self.delay:
                await asyncio.sleep(self.delay)
            if path in self.fail:
                return JSONResponse(
                    {"error": self.fail[path], "message": "simulated failure"},
                    status_code=self.fail[path],
                )
            data = self.answers()
            if path not in data:
                return JSONResponse(not_found, status_code=404)
            if path in self.malformed:
                return Response('[{".id": "*1", ', media_type="application/json")
            return JSONResponse(data[path])

        return app
