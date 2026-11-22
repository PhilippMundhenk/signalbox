"""Simulated Fritz!Box speaking TR-064 (SOAP) at ``POST /upnp/control/<service>``.

Neutral sample data: a gateway on 192.0.2.1/24 with DHCP 192.0.2.20-192.0.2.200, two radios
(2.4 GHz channel 6, 5 GHz channel 36) with the SSID "Example" (WPA2/WPA3), the guest WLAN
"Example-Guest" (WPA2) as ``WLANConfiguration3``, and four hosts (one of them no longer
active). Every request needs HTTP Digest authentication (MD5, ``qop=auth``), like the real
device. The answer shapes follow AVM's TR-064 documentation; see ``docs/adapters/fritzbox.md``.

The settings the adapter can change (DHCP on/off and range; SSID, beacon type, passphrase,
on/off and beacon advertisement of each WLAN) are state of the :class:`FritzboxSim` instance:
the ``Set...`` actions change it and the getters report it. Failure switches on the instance
change the answers for refused-path tests.

Serve it with any ASGI server, for example
``uvicorn --factory signalbox.sim.fritzbox:create_app``.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from fastapi import FastAPI, Request
from fastapi.responses import Response

REALM = "HTTPS Access"
SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
HOST_LIST = "/devicehostlist.lua"
MAC = "02:00:00:00:{:02x}:{:02x}"
_PARAM = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s,]*))')

#: control URL -> service name used in the answers
CONTROL = {
    "deviceinfo": "DeviceInfo:1",
    "lanhostconfigmgm": "LANHostConfigManagement:1",
    "lanethernetifcfg": "LANEthernetInterfaceConfig:1",
    "hosts": "Hosts:1",
    "wlanconfig1": "WLANConfiguration:1",
    "wlanconfig2": "WLANConfiguration:2",
    "wlanconfig3": "WLANConfiguration:3",
}


def _mac(a: int, b: int) -> str:
    return MAC.format(a, b).upper()  # the Fritz!Box answers upper case


def _md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


LAN = {
    "NewDHCPServerConfigurable": "1",
    "NewDHCPRelay": "0",
    "NewMinAddress": "192.0.2.20",
    "NewMaxAddress": "192.0.2.200",
    "NewReservedAddresses": "",
    "NewDHCPServerEnable": "1",
    "NewDNSServers": "192.0.2.1",
    "NewDomainName": "fritz.box",
    "NewIPRouters": "192.0.2.1",
    "NewSubnetMask": "255.255.255.0",
}

WLANS: dict[int, dict[str, str]] = {
    1: {
        "NewSSID": "Example",
        "NewChannel": "6",
        "NewStandard": "ax",
        "NewBeaconType": "11iandWPA3",
        "NewX_AVM-DE_FrequencyBand": "2400",
        "NewBSSID": _mac(1, 1),
        "NewEnable": "1",
        "NewBeaconAdvertisementEnabled": "1",
    },
    2: {
        "NewSSID": "Example",
        "NewChannel": "36",
        "NewStandard": "ax",
        "NewBeaconType": "11iandWPA3",
        "NewX_AVM-DE_FrequencyBand": "5000",
        "NewBSSID": _mac(1, 2),
        "NewEnable": "1",
        "NewBeaconAdvertisementEnabled": "1",
    },
    3: {
        "NewSSID": "Example-Guest",
        "NewChannel": "6",
        "NewStandard": "ax",
        "NewBeaconType": "11i",
        "NewX_AVM-DE_FrequencyBand": "2400",
        "NewBSSID": _mac(1, 3),
        "NewEnable": "1",
        "NewBeaconAdvertisementEnabled": "1",
    },
}
PASSPHRASES = {1: "example-passphrase", 2: "example-passphrase", 3: "example-guest-passphrase"}
POSSIBLE_BEACON_TYPES = "None,11i,WPAand11i,WPA3,11iandWPA3"

#: WLAN index -> associated stations (MAC, IP)
STATIONS: dict[int, list[tuple[str, str]]] = {
    1: [],
    2: [(_mac(0x20, 1), "192.0.2.101")],
    3: [(_mac(0x20, 2), "0.0.0.0")],
}

#: Host table (Hosts1): MAC, IP, source, interface type, active, host name
HOSTS: list[tuple[str, str, str, str, str, str]] = [
    (_mac(0x20, 1), "192.0.2.101", "DHCP", "802.11", "1", "laptop"),
    (_mac(0x20, 2), "", "DHCP", "802.11", "1", "guest-phone"),
    (_mac(0x10, 1), "192.0.2.50", "DHCP", "Ethernet", "1", "printer"),
    (_mac(0x10, 2), "192.0.2.60", "DHCP", "Ethernet", "0", "gone"),
]


def host_entry(index: int) -> dict[str, str]:
    mac, ip, source, kind, active, name = HOSTS[index]
    return {
        "NewIPAddress": ip,
        "NewAddressSource": source,
        "NewLeaseTimeRemaining": "86400" if active == "1" else "0",
        "NewMACAddress": mac,
        "NewInterfaceType": kind,
        "NewActive": active,
        "NewHostName": name,
    }


def host_list() -> str:
    items = "".join(
        "<Item><Index>{}</Index>{}</Item>".format(
            i + 1,
            "".join(
                f"<{k.removeprefix('New')}>{escape(v)}</{k.removeprefix('New')}>"
                for k, v in host_entry(i).items()
            ),
        )
        for i in range(len(HOSTS))
    )
    return f'<?xml version="1.0" encoding="utf-8"?><List>{items}</List>'


@dataclass
class FritzboxSim:
    """State and failure switches of the simulator; mutate between requests."""

    username: str = "signalbox"
    password: str = "example-password"
    #: actions (``GetSecurityKeys``) the user has no right for: UPnP fault 606
    denied: set[str] = field(default_factory=set)
    #: ``action`` or ``service#action`` -> UPnP error code to answer with
    faults: dict[str, int] = field(default_factory=dict)
    #: actions answered with broken XML (``*``: every request)
    malformed: set[str] = field(default_factory=set)
    #: actions answered with a document type declaration (an entity expansion attempt)
    doctype: set[str] = field(default_factory=set)
    #: seconds to wait before answering (``slow`` actions only, or every request if empty)
    delay: float = 0.0
    slow: set[str] = field(default_factory=set)
    #: report the guest WLAN through X_AVM-DE_GetWLANExtInfo (else: fault 401)
    ext_info: bool = True
    #: answer X_AVM-DE_GetHostListPath (else: fault 401, the adapter reads entry by entry)
    host_list: bool = True
    #: path X_AVM-DE_GetHostListPath points to
    host_list_path: str = ""
    nonces: set[str] = field(default_factory=set)
    #: requests that reached the application (authenticated or not)
    requests: int = 0
    #: requests that carried a valid digest
    authenticated: int = 0
    sid: str = field(default_factory=lambda: secrets.token_hex(8))
    #: the configuration the write actions change (copies of the sample data)
    lan: dict[str, str] = field(default_factory=lambda: dict(LAN))
    wlans: dict[int, dict[str, str]] = field(default_factory=lambda: copy.deepcopy(WLANS))
    passphrases: dict[int, str] = field(default_factory=lambda: dict(PASSPHRASES))
    #: answer X_AVM-DE_GetBeaconAdvertisement (else: fault 401)
    beacon_advertisement: bool = True
    #: write actions answered with success but not applied (a box that ignores a setting)
    ignore: set[str] = field(default_factory=set)
    #: write actions applied, in order, as ``service#action`` (arguments are not kept)
    writes: list[str] = field(default_factory=list)

    def reset(self) -> None:
        fresh = FritzboxSim()
        for name in self.__dataclass_fields__:
            if name not in ("nonces", "sid"):
                setattr(self, name, getattr(fresh, name))

    # digest -------------------------------------------------------------------------

    def challenge(self) -> Response:
        nonce = secrets.token_hex(16)
        self.nonces.add(nonce)
        header = f'Digest realm="{REALM}", nonce="{nonce}", algorithm=MD5, qop="auth"'
        return Response(
            "<html><body>401 Unauthorized</body></html>",
            status_code=401,
            headers={"WWW-Authenticate": header},
            media_type="text/html",
        )

    def authorised(self, method: str, header: str | None) -> bool:
        if not header or not header.lower().startswith("digest "):
            return False
        params = {k: a or b for k, a, b in _PARAM.findall(header[7:])}
        if params.get("username") != self.username or params.get("realm") != REALM:
            return False
        if params.get("nonce") not in self.nonces or params.get("qop") != "auth":
            return False
        ha1 = _md5(f"{self.username}:{REALM}:{self.password}")
        ha2 = _md5(f"{method}:{params.get('uri', '')}")
        expected = _md5(
            f"{ha1}:{params['nonce']}:{params.get('nc', '')}:{params.get('cnonce', '')}:auth:{ha2}"
        )
        return secrets.compare_digest(expected, params.get("response", ""))

    # SOAP ---------------------------------------------------------------------------

    def _data(self, service: str, action: str, args: dict[str, str]) -> dict[str, str] | int:
        """Output arguments, or a UPnP error code."""
        name, _, number = service.partition(":")
        if name == "DeviceInfo" and action == "GetInfo":
            return {
                "NewManufacturerName": "AVM",
                "NewModelName": "FRITZ!Box Example",
                "NewDescription": "FRITZ!Box Example 154.07.57",
                "NewProductClass": "AVMFB",
                "NewSerialNumber": "000000000000",
                "NewSoftwareVersion": "154.07.57",
                "NewHardwareVersion": "FRITZ!Box Example",
                "NewSpecVersion": "1.0",
                "NewUpTime": "86400",
            }
        if name == "LANHostConfigManagement":
            lan = self.lan
            getters: dict[str, Callable[[], dict[str, str]]] = {
                "GetInfo": lambda: dict(lan),
                "GetIPRoutersList": lambda: {"NewIPRouters": lan["NewIPRouters"]},
                "GetSubnetMask": lambda: {"NewSubnetMask": lan["NewSubnetMask"]},
                "GetAddressRange": lambda: {
                    "NewMinAddress": lan["NewMinAddress"],
                    "NewMaxAddress": lan["NewMaxAddress"],
                },
            }
            if action in getters:
                return getters[action]()
            return self._set_lan(action, args)
        if name == "LANEthernetInterfaceConfig":
            if action == "GetInfo":
                return {
                    "NewEnable": "1",
                    "NewStatus": "Up",
                    "NewMACAddress": _mac(0, 1),
                    "NewMaxBitRate": "1000",
                    "NewDuplexMode": "Full",
                }
            if action == "GetStatistics":
                return {
                    "NewBytesSent": "1000",
                    "NewBytesReceived": "2000",
                    "NewPacketsSent": "10",
                    "NewPacketsReceived": "20",
                }
            return 401
        if name == "WLANConfiguration":
            return self._wlan(int(number), action, args)
        if name == "Hosts":
            if action == "GetHostNumberOfEntries":
                return {"NewHostNumberOfEntries": str(len(HOSTS))}
            if action == "GetGenericHostEntry":
                index = int(args.get("NewIndex", "-1"))
                return host_entry(index) if 0 <= index < len(HOSTS) else 713
            if action == "X_AVM-DE_GetHostListPath" and self.host_list:
                return {"NewX_AVM-DE_HostListPath": self.host_list_path or self.list_path}
        return 401

    @property
    def list_path(self) -> str:
        return f"{HOST_LIST}?sid={self.sid}"

    def _set_lan(self, action: str, args: dict[str, str]) -> dict[str, str] | int:
        if action == "SetDHCPServerEnable":
            value = args.get("NewDHCPServerEnable")
            if value not in ("0", "1"):
                return 402
            return self._write("LANHostConfigManagement", action, {"NewDHCPServerEnable": value})
        if action == "SetAddressRange":
            try:
                first = IPv4Address(args.get("NewMinAddress", ""))
                last = IPv4Address(args.get("NewMaxAddress", ""))
            except ValueError:
                return 402
            lan = IPv4Network(
                f"{self.lan['NewIPRouters']}/{self.lan['NewSubnetMask']}", strict=False
            )
            if first not in lan or last not in lan or first > last:
                return 402
            return self._write(
                "LANHostConfigManagement",
                action,
                {"NewMinAddress": str(first), "NewMaxAddress": str(last)},
            )
        return 401

    def _write(
        self, service: str, action: str, values: dict[str, str], index: int | None = None
    ) -> dict[str, str]:
        """Apply a write action (unless ignored) and answer with no output arguments."""
        if action not in self.ignore:
            target = self.lan if index is None else self.wlans[index]
            if "NewKeyPassphrase" in values:
                assert index is not None
                self.passphrases[index] = values["NewKeyPassphrase"]
            else:
                target.update(values)
            self.writes.append(f"{service}{index or ''}#{action}")
        return {}

    def _set_wlan(self, index: int, action: str, args: dict[str, str]) -> dict[str, str] | int:
        service = "WLANConfiguration"
        if action == "SetSSID":
            ssid = args.get("NewSSID", "")
            if not 1 <= len(ssid.encode()) <= 32:
                return 402
            return self._write(service, action, {"NewSSID": ssid}, index)
        if action == "SetBeaconType":
            beacon = args.get("NewBeaconType", "")
            if beacon not in POSSIBLE_BEACON_TYPES.split(","):
                return 402
            return self._write(service, action, {"NewBeaconType": beacon}, index)
        if action == "SetSecurityKeys":
            passphrase = args.get("NewKeyPassphrase", "")
            if not 8 <= len(passphrase) <= 63:
                return 402
            return self._write(service, action, {"NewKeyPassphrase": passphrase}, index)
        if action == "SetEnable":
            value = args.get("NewEnable")
            if value not in ("0", "1"):
                return 402
            return self._write(service, action, {"NewEnable": value}, index)
        if action == "X_AVM-DE_SetBeaconAdvertisement" and self.beacon_advertisement:
            value = args.get("NewBeaconAdvertisementEnabled")
            if value not in ("0", "1"):
                return 402
            return self._write(service, action, {"NewBeaconAdvertisementEnabled": value}, index)
        return 401

    def _wlan(self, index: int, action: str, args: dict[str, str]) -> dict[str, str] | int:
        info = {k: v for k, v in self.wlans[index].items() if k != "NewBeaconAdvertisementEnabled"}
        if action == "GetInfo":
            return {
                "NewStatus": "Up" if info["NewEnable"] == "1" else "Disabled",
                "NewMaxBitRate": "Auto",
                "NewBasicEncryptionModes": "None",
                "NewBasicAuthenticationMode": "None",
                "NewX_AVM-DE_PossibleBeaconTypes": POSSIBLE_BEACON_TYPES,
                "NewMACAddressControlEnabled": "0",
                **info,
            }
        if action == "GetSecurityKeys":
            return {
                "NewWEPKey0": "",
                "NewPreSharedKey": "0" * 64,
                "NewKeyPassphrase": self.passphrases[index],
            }
        if action == "X_AVM-DE_GetBeaconAdvertisement" and self.beacon_advertisement:
            return {
                "NewBeaconAdvertisementEnabled": self.wlans[index]["NewBeaconAdvertisementEnabled"]
            }
        if action == "X_AVM-DE_GetWLANExtInfo" and self.ext_info:
            return {
                "NewX_AVM-DE_APEnabled": "1",
                "NewX_AVM-DE_APType": "guest" if index == 3 else "normal",
            }
        if action == "GetTotalAssociations":
            return {"NewTotalAssociations": str(len(STATIONS[index]))}
        if action == "GetGenericAssociatedDeviceInfo":
            i = int(args.get("NewAssociatedDeviceIndex", "-1"))
            if not 0 <= i < len(STATIONS[index]):
                return 713
            mac, ip = STATIONS[index][i]
            return {
                "NewAssociatedDeviceMACAddress": mac,
                "NewAssociatedDeviceIPAddress": ip,
                "NewAssociatedDeviceAuthState": "1",
                "NewX_AVM-DE_Speed": "866",
                "NewX_AVM-DE_SignalStrength": "70",
            }
        return self._set_wlan(index, action, args)

    async def handle(self, control: str, body: bytes, soap_action: str) -> Response:
        service = CONTROL.get(control)
        if service is None:
            return Response("<html>404 Not Found</html>", status_code=404)
        _, _, action = soap_action.strip('"').partition("#")
        try:
            root = ET.fromstring(body)
            call = next(e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == action)
            args = {c.tag: (c.text or "") for c in call}
        except (ET.ParseError, StopIteration):
            return self._fault(402, "Invalid Args")
        if self.delay and (not self.slow or action in self.slow):
            await asyncio.sleep(self.delay)
        if "*" in self.malformed or action in self.malformed:
            return Response("<s:Envelope><s:Body><u:", media_type="text/xml")
        if action in self.doctype:
            evil = (
                '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]>'
                f'<s:Envelope xmlns:s="{SOAP_ENV}"><s:Body><u:{action}Response>'
                f"<NewModelName>&lol;</NewModelName></u:{action}Response></s:Body></s:Envelope>"
            )
            return Response(evil, media_type="text/xml")
        code = self.faults.get(f"{service.split(':')[0]}#{action}", self.faults.get(action))
        if code is None and action in self.denied:
            code = 606
        if code is None:
            try:
                data = self._data(service, action, args)
            except ValueError:  # an index argument that is not a number
                data = 402
            if isinstance(data, int):
                code = data
            else:
                return self._answer(service, action, data)
        return self._fault(
            code,
            {
                402: "Invalid Args",
                606: "Action Not Authorized",
                713: "SpecifiedArrayIndexInvalid",
            }.get(code, "Invalid Action" if code == 401 else "Action Failed"),
        )

    @staticmethod
    def _answer(service: str, action: str, data: dict[str, str]) -> Response:
        inner = "".join(f"<{k}>{escape(v)}</{k}>" for k, v in data.items())
        body = (
            '<?xml version="1.0"?>'
            f'<s:Envelope xmlns:s="{SOAP_ENV}" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action}Response xmlns:u="urn:dslforum-org:service:{service}">{inner}'
            f"</u:{action}Response></s:Body></s:Envelope>"
        )
        return Response(body, media_type='text/xml; charset="utf-8"')

    @staticmethod
    def _fault(code: int, description: str) -> Response:
        body = (
            '<?xml version="1.0"?>'
            f'<s:Envelope xmlns:s="{SOAP_ENV}" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault>'
            "<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>"
            '<UPnPError xmlns="urn:dslforum-org:control-1-0">'
            f"<errorCode>{code}</errorCode><errorDescription>{description}</errorDescription>"
            "</UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        )
        return Response(body, status_code=500, media_type='text/xml; charset="utf-8"')


def create_app(sim: FritzboxSim | None = None) -> FastAPI:
    state = sim or FritzboxSim()
    app = FastAPI(title="Fritz!Box TR-064 simulator", docs_url=None, redoc_url=None)
    app.state.sim = state

    @app.post("/upnp/control/{control}")
    async def control(control: str, request: Request) -> Response:
        state.requests += 1
        if not state.authorised("POST", request.headers.get("authorization")):
            return state.challenge()
        state.authenticated += 1
        return await state.handle(
            control, await request.body(), request.headers.get("soapaction", "")
        )

    @app.get(HOST_LIST)
    async def hosts(sid: str = "") -> Response:
        state.requests += 1
        if sid != state.sid:
            return Response("<html>403 Forbidden</html>", status_code=403)
        if "HostList" in state.doctype:
            return Response('<!DOCTYPE List [<!ENTITY x "x">]><List/>', media_type="text/xml")
        if "HostList" in state.malformed:
            return Response("<List><Item>", media_type="text/xml")
        return Response(host_list(), media_type="text/xml")

    return app
