"""Simulated Fritz!Box speaking TR-064 (SOAP), built from AVM's service descriptions.

The interface is not hand-written: the simulator loads ``tr64desc.xml`` and the SCPD files of
one FRITZ!OS version (:mod:`signalbox.sim.tr064`, files in ``tests/fixtures/tr064/``), serves
them like a box (``GET /tr64desc.xml``, ``GET /wlanconfigSCPD.xml``..., no authentication) and
answers ``POST <controlURL>`` only for actions that are in the description: an unknown action
is UPnP fault 401, missing or unknown arguments 402, a value of the wrong data type or not in
the allowed values 600 (601 out of range). Every answer carries exactly the ``out`` arguments
of the action, with values of their data types (checked, a simulator bug otherwise).

Neutral sample data: a gateway on 192.0.2.1/24 with DHCP 192.0.2.20-192.0.2.200, two radios
(2.4 GHz channel 6, 5 GHz channel 36) with the SSID "Example" (WPA2/WPA3), the guest WLAN
"Example-Guest" (WPA2) as ``WLANConfiguration3``, and four hosts (one of them no longer
active). Model and FRITZ!OS version come from the description. Every SOAP request needs HTTP
Digest authentication (MD5, ``qop=auth``; realm ``HTTPS Access`` over HTTPS, ``F!Box
SOAP-Auth`` over plain HTTP).

The settings the adapter can change (DHCP on/off and range; SSID, beacon type, passphrase,
on/off and beacon advertisement of each WLAN) are state of the :class:`FritzboxSim` instance:
the ``Set...`` actions change it and the getters report it. Failure switches on the instance
change the answers for refused-path tests.

Serve it with any ASGI server from a checkout, for example
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
from datetime import UTC, datetime, timedelta, tzinfo
from functools import cache
from ipaddress import IPv4Address, IPv4Network
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request
from fastapi.responses import Response

from signalbox.sim import tr064
from signalbox.sim.tr064 import ArgumentError, Description

#: Digest realm of TR-064 over HTTPS (port 49443) and over plain HTTP (port 49000).
REALM_HTTPS = "HTTPS Access"
REALM_HTTP = "F!Box SOAP-Auth"
SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
HOST_LIST = "/devicehostlist.lua"
MAC = "02:00:00:00:{:02x}:{:02x}"
_PARAM = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s,]*))')

#: UPnP error descriptions (UPnP Device Architecture)
ERRORS = {
    401: "Invalid Action",
    402: "Invalid Args",
    501: "Action Failed",
    600: "Argument Value Invalid",
    601: "Argument Value Out of Range",
    606: "Action Not Authorized",
    713: "SpecifiedArrayIndexInvalid",
    714: "NoSuchEntryInArray",
    820: "Internal Error",
}


@cache
def description(version: str = tr064.VERSIONS[0]) -> Description:
    return tr064.load(version)


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
#: Beacon types the sample box offers (spelled as in the description of its FRITZ!OS)
OFFERED_BEACON_TYPES = ("None", "11i", "WPAand11i", "WPA3", "11iandWPA3")
#: Limits the sample box reports in WLANConfiguration GetInfo
SSID_CHARS = (1, 32)
PSK_CHARS = (8, 63)
ALLOWED_CHARS = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

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


def time_info(zone: str, skew: float = 0.0) -> dict[str, str]:
    """``Time:1 GetInfo`` as in AVM's timeSCPD (TR-064 Time:1): NTP servers, the local time
    with its offset and the zone as a POSIX string (*Guess*: AVM fills in the zone fields like
    the TR-064 example; no real Fritz!Box confirms it in CI)."""
    try:
        tz: tzinfo = ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError):
        tz = UTC
    now = (datetime.now(UTC) + timedelta(seconds=skew)).astimezone(tz).replace(microsecond=0)
    return {
        "NewNTPServer1": "ntp.example.net",
        "NewNTPServer2": "",
        "NewCurrentLocalTime": now.isoformat(),
        "NewLocalTimeZone": "CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00",
        "NewLocalTimeZoneName": "CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00",
        "NewDaylightSavingsUsed": "1",
        "NewDaylightSavingsStart": "0001-01-01T00:00:00",
        "NewDaylightSavingsEnd": "0001-01-01T00:00:00",
    }


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


class NotSimulated(Exception):
    """An action of the description that the simulator does not implement (fault 501)."""


@dataclass
class FritzboxSim:
    """State and failure switches of the simulator; mutate between requests."""

    username: str = "signalbox"
    password: str = "example-password"
    #: FRITZ!OS whose descriptions are served (a name from ``tr064.VERSIONS``)
    version: str = tr064.VERSIONS[0]
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
    #: offer X_AVM-DE_GetWLANExtInfo (else: fault 401, as on a FRITZ!OS without it)
    ext_info: bool = True
    #: offer X_AVM-DE_GetHostListPath (else: fault 401, the adapter reads entry by entry)
    host_list: bool = True
    #: path X_AVM-DE_GetHostListPath points to
    host_list_path: str = ""
    nonces: set[str] = field(default_factory=set)
    #: requests that reached the application (authenticated or not)
    requests: int = 0
    #: TR-064 HTTPS port the box reports with GetSecurityPort (asked without credentials).
    security_port: int = 49443
    #: requests that carried a valid digest
    authenticated: int = 0
    sid: str = field(default_factory=lambda: secrets.token_hex(8))
    #: the configuration the write actions change (copies of the sample data)
    lan: dict[str, str] = field(default_factory=lambda: dict(LAN))
    wlans: dict[int, dict[str, str]] = field(default_factory=lambda: copy.deepcopy(WLANS))
    passphrases: dict[int, str] = field(default_factory=lambda: dict(PASSPHRASES))
    #: offer Get/SetBeaconAdvertisement (else: fault 401)
    beacon_advertisement: bool = True
    #: write actions answered with success but not applied (a box that ignores a setting)
    ignore: set[str] = field(default_factory=set)
    #: write actions applied, in order, as ``service#action`` (arguments are not kept)
    writes: list[str] = field(default_factory=list)
    #: every authenticated SOAP call that named an existing service: (service, action, args)
    calls: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    #: seconds since the last start (``DeviceInfo GetInfo`` ``NewUpTime``)
    uptime: int = 1209600
    #: IANA zone of the box's clock (``Time GetInfo``) and how far it is ahead, in seconds
    timezone: str = "Europe/Berlin"
    clock_skew: float = 0.0

    def reset(self) -> None:
        fresh = FritzboxSim()
        for name in self.__dataclass_fields__:
            if name not in ("nonces", "sid", "version"):
                setattr(self, name, getattr(fresh, name))

    @property
    def description(self) -> Description:
        return description(self.version)

    @property
    def absent(self) -> set[str]:
        """Actions switched off (an older FRITZ!OS): answered with fault 401."""
        off = set()
        if not self.ext_info:
            off.add("X_AVM-DE_GetWLANExtInfo")
        if not self.host_list:
            off.add("X_AVM-DE_GetHostListPath")
        if not self.beacon_advertisement:
            off |= {"GetBeaconAdvertisement", "SetBeaconAdvertisement"}
        return off

    def beacon_spelling(self, beacon: str) -> str:
        """A beacon type as the description of this FRITZ!OS spells it (``none``/``None``)."""
        service = self.description.service_by_type("urn:dslforum-org:service:WLANConfiguration:1")
        assert service is not None
        [arg] = service.actions["SetBeaconType"].inputs
        return next((a for a in arg.variable.allowed if a.lower() == beacon.lower()), beacon)

    @property
    def offered_beacon_types(self) -> list[str]:
        return [self.beacon_spelling(b) for b in OFFERED_BEACON_TYPES]

    # digest -------------------------------------------------------------------------

    def challenge(self, realm: str) -> Response:
        nonce = secrets.token_hex(8).upper()
        self.nonces.add(nonce)
        header = f'Digest realm="{realm}",nonce="{nonce}",algorithm=MD5,qop="auth"'
        return Response(
            "<HTML><HEAD><TITLE>401 Unauthorized (ERR_NONE)</TITLE></HEAD>"
            "<BODY><H1>401 Unauthorized</H1><BR>ERR_NONE<HR><B>Webserver</B></BODY></HTML>",
            status_code=401,
            headers={"WWW-Authenticate": header},
            media_type="text/html",
        )

    def authorised(self, method: str, header: str | None, realm: str) -> bool:
        if not header or not header.lower().startswith("digest "):
            return False
        params = {k: a or b for k, a, b in _PARAM.findall(header[7:])}
        if params.get("username") != self.username or params.get("realm") != realm:
            return False
        if params.get("nonce") not in self.nonces or params.get("qop") != "auth":
            return False
        ha1 = _md5(f"{self.username}:{realm}:{self.password}")
        ha2 = _md5(f"{method}:{params.get('uri', '')}")
        expected = _md5(
            f"{ha1}:{params['nonce']}:{params.get('nc', '')}:{params.get('cnonce', '')}:auth:{ha2}"
        )
        return secrets.compare_digest(expected, params.get("response", ""))

    # SOAP ---------------------------------------------------------------------------

    def _data(self, service: str, action: str, args: dict[str, str]) -> dict[str, str] | int:
        """Output arguments, or a UPnP error code; NotSimulated for other described actions."""
        name, _, number = service.partition(":")
        if name == "DeviceInfo" and action == "GetSecurityPort":
            return {"NewSecurityPort": str(self.security_port)}
        if name == "DeviceInfo" and action == "GetInfo":
            desc = self.description
            return {
                "NewManufacturerName": "AVM",
                "NewManufacturerOUI": "00040E",
                "NewModelName": desc.value("modelName"),
                "NewDescription": f"{desc.value('modelName')} {desc.value('Display')}",
                "NewProductClass": "AVMFB",
                "NewSerialNumber": "000000000000",
                "NewSoftwareVersion": desc.value("Display"),
                "NewHardwareVersion": desc.value("modelName"),
                "NewSpecVersion": "1.0",
                "NewProvisioningCode": "",
                "NewUpTime": str(self.uptime),
                "NewDeviceLog": "",
            }
        if name == "Time" and action == "GetInfo":
            return time_info(self.timezone, self.clock_skew)
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
                "GetDNSServers": lambda: {"NewDNSServers": lan["NewDNSServers"]},
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
        if name == "WLANConfiguration":
            return self._wlan(int(number), action, args)
        if name == "Hosts":
            if action == "GetHostNumberOfEntries":
                return {"NewHostNumberOfEntries": str(len(HOSTS))}
            if action == "GetGenericHostEntry":
                index = int(args["NewIndex"])
                return host_entry(index) if index < len(HOSTS) else 713
            if action == "X_AVM-DE_GetHostListPath":
                return {"NewX_AVM-DE_HostListPath": self.host_list_path or self.list_path}
        raise NotSimulated(f"{service} {action}")

    @property
    def list_path(self) -> str:
        return f"{HOST_LIST}?sid={self.sid}"

    def _set_lan(self, action: str, args: dict[str, str]) -> dict[str, str] | int:
        if action == "SetDHCPServerEnable":
            value = _bit(args["NewDHCPServerEnable"])
            return self._write("LANHostConfigManagement", action, {"NewDHCPServerEnable": value})
        if action == "SetAddressRange":
            try:
                first = IPv4Address(args["NewMinAddress"])
                last = IPv4Address(args["NewMaxAddress"])
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
        raise NotSimulated(f"LANHostConfigManagement {action}")

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
            ssid = args["NewSSID"]
            if not SSID_CHARS[0] <= len(ssid.encode()) <= SSID_CHARS[1]:
                return 402
            return self._write(service, action, {"NewSSID": ssid}, index)
        if action == "SetBeaconType":
            beacon = args["NewBeaconType"]
            if beacon not in self.offered_beacon_types:
                return 402
            return self._write(service, action, {"NewBeaconType": beacon}, index)
        if action == "SetSecurityKeys":
            passphrase = args["NewKeyPassphrase"]
            if not PSK_CHARS[0] <= len(passphrase) <= PSK_CHARS[1]:
                return 402
            return self._write(service, action, {"NewKeyPassphrase": passphrase}, index)
        if action == "SetEnable":
            return self._write(service, action, {"NewEnable": _bit(args["NewEnable"])}, index)
        if action == "SetBeaconAdvertisement":
            value = _bit(args["NewBeaconAdvertisementEnabled"])
            return self._write(service, action, {"NewBeaconAdvertisementEnabled": value}, index)
        raise NotSimulated(f"{service}:{index} {action}")

    def _wlan(self, index: int, action: str, args: dict[str, str]) -> dict[str, str] | int:
        info = {k: v for k, v in self.wlans[index].items() if k != "NewBeaconAdvertisementEnabled"}
        if action == "GetInfo":
            return {
                "NewStatus": "Up" if info["NewEnable"] == "1" else "Disabled",
                "NewMaxBitRate": "Auto",
                "NewBasicEncryptionModes": "None",
                "NewBasicAuthenticationMode": "None",
                "NewX_AVM-DE_PossibleBeaconTypes": ",".join(self.offered_beacon_types),
                "NewMACAddressControlEnabled": "0",
                "NewMinCharsSSID": str(SSID_CHARS[0]),
                "NewMaxCharsSSID": str(SSID_CHARS[1]),
                "NewAllowedCharsSSID": ALLOWED_CHARS,
                "NewMinCharsPSK": str(PSK_CHARS[0]),
                "NewMaxCharsPSK": str(PSK_CHARS[1]),
                "NewAllowedCharsPSK": ALLOWED_CHARS,
                "NewX_AVM-DE_WLANGlobalEnable": "1",
                **info,
            }
        if action == "GetSecurityKeys":
            return {
                "NewWEPKey0": "",
                "NewWEPKey1": "",
                "NewWEPKey2": "",
                "NewWEPKey3": "",
                "NewPreSharedKey": "0" * 64,
                "NewKeyPassphrase": self.passphrases[index],
            }
        if action == "GetBeaconAdvertisement":
            return {
                "NewBeaconAdvertisementEnabled": self.wlans[index]["NewBeaconAdvertisementEnabled"]
            }
        if action == "X_AVM-DE_GetWLANExtInfo":
            return {
                "NewX_AVM-DE_APEnabled": "1",
                "NewX_AVM-DE_APType": "guest" if index == 3 else "normal",
                "NewX_AVM-DE_FrequencyBand": info["NewX_AVM-DE_FrequencyBand"],
                "NewX_AVM-DE_TimeoutActive": "0",
                "NewX_AVM-DE_Timeout": "0",
                "NewX_AVM-DE_TimeRemain": "0",
                "NewX_AVM-DE_NoForcedOff": "0",
                "NewX_AVM-DE_UserIsolation": "1" if index == 3 else "0",
                "NewX_AVM-DE_EncryptionMode": "",
                "NewX_AVM-DE_LastChangedStamp": "0",
            }
        if action == "GetTotalAssociations":
            return {"NewTotalAssociations": str(len(STATIONS[index]))}
        if action == "GetGenericAssociatedDeviceInfo":
            i = int(args["NewAssociatedDeviceIndex"])
            if i >= len(STATIONS[index]):
                return 713
            mac, ip = STATIONS[index][i]
            return {
                "NewAssociatedDeviceMACAddress": mac,
                "NewAssociatedDeviceIPAddress": ip,
                "NewAssociatedDeviceAuthState": "1",
                "NewX_AVM-DE_Speed": "866",
                "NewX_AVM-DE_SignalStrength": "70",
                "NewX_AVM-DE_ChannelWidth": "80",
            }
        return self._set_wlan(index, action, args)

    async def handle(self, control: str, body: bytes, soap_action: str) -> Response:
        service = self.description.services.get(control)
        if service is None:
            return Response("<html>404 Not Found</html>", status_code=404)
        service_type, _, action_name = soap_action.strip().strip('"').partition("#")
        action = service.actions.get(action_name)
        if service_type != service.service_type or action is None or action_name in self.absent:
            return self._fault(401)
        try:
            root = ET.fromstring(body)
            call = next(e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == action_name)
            args = {c.tag.rsplit("}", 1)[-1]: (c.text or "") for c in call}
        except (ET.ParseError, StopIteration):
            return self._fault(402)
        self.calls.append((service.name, action_name, dict(args)))
        try:
            action.check_inputs(args)
        except ArgumentError as exc:
            return self._fault(exc.code)
        if self.delay and (not self.slow or action_name in self.slow):
            await asyncio.sleep(self.delay)
        if "*" in self.malformed or action_name in self.malformed:
            return Response("<s:Envelope><s:Body><u:", media_type="text/xml")
        if action_name in self.doctype:
            evil = (
                '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]>'
                f'<s:Envelope xmlns:s="{SOAP_ENV}"><s:Body><u:{action_name}Response>'
                f"<NewModelName>&lol;</NewModelName></u:{action_name}Response></s:Body>"
                "</s:Envelope>"
            )
            return Response(evil, media_type="text/xml")
        base = service.name.split(":")[0]
        code = self.faults.get(f"{base}#{action_name}", self.faults.get(action_name))
        if code is None and action_name in self.denied:
            code = 606
        if code is not None:
            return self._fault(code)
        try:
            data = self._data(service.name, action_name, args)
        except NotSimulated:
            return self._fault(501)
        if isinstance(data, int):
            return self._fault(data)
        action.check_outputs(data)
        return self._answer(service.service_type, action_name, data, action)

    @staticmethod
    def _answer(
        service_type: str, action: str, data: dict[str, str], described: tr064.Action
    ) -> Response:
        inner = "".join(f"<{a.name}>{escape(data[a.name])}</{a.name}>" for a in described.outputs)
        body = (
            '<?xml version="1.0"?>'
            f'<s:Envelope xmlns:s="{SOAP_ENV}" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action}Response xmlns:u="{service_type}">{inner}'
            f"</u:{action}Response></s:Body></s:Envelope>"
        )
        return Response(body, media_type='text/xml; charset="utf-8"')

    @staticmethod
    def _fault(code: int) -> Response:
        body = (
            '<?xml version="1.0"?>'
            f'<s:Envelope xmlns:s="{SOAP_ENV}" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault>'
            "<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>"
            '<UPnPError xmlns="urn:dslforum-org:control-1-0">'
            f"<errorCode>{code}</errorCode>"
            f"<errorDescription>{ERRORS.get(code, 'Action Failed')}</errorDescription>"
            "</UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        )
        return Response(body, status_code=500, media_type='text/xml; charset="utf-8"')


def _bit(value: str) -> str:
    return "1" if value.strip().lower() in ("1", "true", "yes") else "0"


def create_app(sim: FritzboxSim | None = None) -> FastAPI:
    state = sim or FritzboxSim()
    state.description  # noqa: B018 - fail at start when the descriptions are missing
    app = FastAPI(title="Fritz!Box TR-064 simulator", docs_url=None, redoc_url=None)
    app.state.sim = state

    @app.get("/{name}.xml")
    async def described(name: str) -> Response:
        """``tr64desc.xml`` and the SCPD files, without authentication like the box."""
        state.requests += 1
        content = state.description.files.get(f"/{name}.xml")
        if content is None:
            return Response("<html>404 Not Found</html>", status_code=404)
        return Response(content, media_type="text/xml")

    @app.post("/upnp/control/{control}")
    async def control(control: str, request: Request) -> Response:
        state.requests += 1
        realm = REALM_HTTPS if request.url.scheme == "https" else REALM_HTTP
        soap_action = request.headers.get("soapaction", "")
        # like the box: the TR-064 HTTPS port is told to anyone on plain HTTP (port 49000)
        public = request.url.scheme == "http" and soap_action.strip('"').endswith(
            "DeviceInfo:1#GetSecurityPort"
        )
        if not public and not state.authorised("POST", request.headers.get("authorization"), realm):
            return state.challenge(realm)
        state.authenticated += 0 if public else 1
        return await state.handle(
            f"/upnp/control/{control}",
            await request.body(),
            request.headers.get("soapaction", ""),
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
