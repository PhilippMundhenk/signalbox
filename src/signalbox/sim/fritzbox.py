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
"Example-Guest" (WPA2) as ``WLANConfiguration3``, four hosts (one of them no longer active)
and a DSL connection over PPPoE (203.0.113.45; ``wan`` switches to cable behind carrier-grade
NAT, LTE or none). Model and FRITZ!OS version come from the description. Every SOAP request
needs HTTP Digest authentication (MD5, ``qop=auth``; realm ``HTTPS Access`` over HTTPS, ``F!Box
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
import json
import re
import secrets
import string
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from functools import cache
from ipaddress import IPv4Address, IPv4Network
from typing import Any, ClassVar
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
MESH_LIST = "/meshlist.lua"
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


ETHERNET = {
    "NewEnable": "1",
    "NewStatus": "Up",
    "NewMACAddress": _mac(0, 1),
    "NewMaxBitRate": "1000",
    "NewDuplexMode": "Full",
}

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

REMOTE_ACCESS = {
    "NewEnabled": "0",
    "NewPort": "443",
    "NewUsername": "",
    "NewLetsEncryptEnabled": "0",
    "NewLetsEncryptState": "",
}
#: ``X_AVM-DE_RemoteAccess GetDDNSInfo``: a DDNS provider (names invented; the update URL and
#: the account are in the answer and never read, #154)
DDNS = {
    "NewEnabled": "1",
    "NewProviderName": "DynDNS",
    "NewUpdateURL": "https://dyn.example.invalid/update?hostname=<domain>&myip=<ipaddr>",
    "NewDomain": "home.example.dyndns.invalid",
    "NewStatusIPv4": "ok",
    "NewStatusIPv6": "unknown",
    "NewUsername": "sim-user",
    "NewMode": "ddns_v4",
    "NewServerIPv4": "198.51.100.80",
    "NewServerIPv6": "",
}
MYFRITZ = {
    "NewEnabled": "1",
    "NewDeviceRegistered": "1",
    "NewDynDNSName": "example.myfritz.example",
    "NewPort": "443",
    "NewState": "ok",
    "NewEmail": "",
}
STORAGE = {
    "NewFTPEnable": "1",
    "NewFTPStatus": "Started",
    "NewSMBEnable": "0",
    "NewFTPWANEnable": "0",
    "NewFTPWANSSLOnly": "1",
    "NewFTPWANPort": "21",
}
UPNP = {"NewEnable": "1", "NewUPnPMediaServer": "0"}

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
#: ``X_AVM-DE_GetWPSInfo`` of each WLANConfiguration: (mode, status); status ``off``: WPS disabled
WPS = {1: ("stop", "inactive"), 2: ("pbc", "active"), 3: ("stop", "off")}
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


def _mesh_node(
    uid: str, name: str, model: str, mac: str, role: str, ip: str, itfs: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "uid": uid,
        "device_name": name,
        "device_model": model,
        "device_manufacturer": "AVM",
        "device_firmware_version": "7.57",
        "device_mac_address": mac,
        "is_meshed": True,
        "mesh_role": role,
        "node_interfaces": [{"ip": ip, **i} for i in itfs],
    }


def _mesh_link(uid: str, a: str, b: str, ia: str, ib: str, rate: int, rcpi: int) -> dict[str, Any]:
    return {
        "uid": uid,
        "type": "WLAN",
        "state": "CONNECTED",
        "node_1_uid": a,
        "node_2_uid": b,
        "node_interface_1_uid": ia,
        "node_interface_2_uid": ib,
        "cur_data_rate_rx": rate,
        "cur_data_rate_tx": rate,
        "rx_rcpi": rcpi,
        "tx_rcpi": rcpi,
    }


def mesh_topology() -> dict[str, Any]:
    """A mesh in the shape of AVM's mesh topology document (#171): the box (master), a repeater
    on 5 GHz and a second one behind it on 2.4 GHz, plus a client the document lists as a node
    (``is_meshed`` false). Documentation addresses and made-up MACs; the field names are the
    adapter's guess (#21), not a recording."""
    l1 = _mesh_link("SEG-1", "n-box", "n-rep1", "i-box-ap5", "i-rep1-up5", 866_000, 100)
    l2 = _mesh_link("SEG-2", "n-rep1", "n-rep2", "i-rep1-ap2", "i-rep2-up2", 40_000, 56)
    box = _mesh_node(
        "n-box",
        "fritz.box",
        "FRITZ!Box 7590",
        _mac(0, 1),
        "master",
        "192.0.2.1",
        [
            {
                "uid": "i-box-ap5",
                "name": "AP:5G:0",
                "mac_address": _mac(0, 2),
                "current_channel": 36,
                "node_links": [l1],
            }
        ],
    )
    rep1 = _mesh_node(
        "n-rep1",
        "Repeater Hall",
        "FRITZ!Repeater 3000",
        _mac(2, 1),
        "slave",
        "192.0.2.21",
        [
            {
                "uid": "i-rep1-up5",
                "name": "UPLINK:5G:0",
                "mac_address": _mac(2, 2),
                "current_channel": 36,
                "node_links": [l1],
            },
            {
                "uid": "i-rep1-ap2",
                "name": "AP:2G:0",
                "mac_address": _mac(2, 3),
                "current_channel": 6,
                "node_links": [l2],
            },
        ],
    )
    rep2 = _mesh_node(
        "n-rep2",
        "Repeater Garden",
        "FRITZ!Repeater 1200",
        _mac(3, 1),
        "slave",
        "192.0.2.22",
        [
            {
                "uid": "i-rep2-up2",
                "name": "UPLINK:2G:0",
                "mac_address": _mac(3, 2),
                "current_channel": 6,
                "node_links": [l2],
            }
        ],
    )
    client = {"uid": "n-client", "device_name": "phone", "is_meshed": False, "node_interfaces": []}
    return {"schema_version": "1.9", "nodes": [box, rep1, rep2, client]}


_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#: ``wan`` -> (NewWANAccessType, Layer 1 downstream and upstream rate in bit/s)
WAN_ACCESS = {
    "dsl": ("DSL", 116_790_000, 46_719_000),
    "cable": ("X_AVM-DE_Cable", 1_000_000_000, 50_000_000),
    "lte": ("X_AVM-DE_LTE", 150_000_000, 50_000_000),
    "client": ("Ethernet", 0, 0),
}
#: ``wan`` -> (external address, PPP peer, DNS servers as the box lists them)
WAN_ADDRESSES = {
    "dsl": ("203.0.113.45", "203.0.113.1", "203.0.113.53, 203.0.113.54"),
    "cable": ("100.64.12.34", "", "100.64.0.53, 100.64.0.54"),
    "lte": ("100.72.3.4", "", "100.64.0.53"),
}


def wan_info(ppp: bool, active: bool, up: bool, wan: str) -> dict[str, str]:
    """``GetInfo`` of WANPPPConnection:1 (``ppp``) or WANIPConnection:1."""
    connected = active and up
    external, remote, dns = WAN_ADDRESSES.get(wan, ("", "", "")) if connected else ("", "", "")
    info = {
        "NewEnable": "1" if active else "0",
        "NewConnectionStatus": "Connected" if connected else "Disconnected",
        "NewPossibleConnectionTypes": "IP_Routed",
        "NewConnectionType": "IP_Routed",
        "NewName": "internet" if ppp else "mstv",
        "NewUptime": "7200" if connected else "0",
        "NewLastConnectionError": "ERROR_NONE",
        "NewRSIPAvailable": "0",
        "NewNATEnabled": "1",
        "NewExternalIPAddress": external,
        "NewDNSServers": dns,
        "NewMACAddress": _mac(9, 1),
        "NewConnectionTrigger": "AlwaysOn",
        "NewRouteProtocolRx": "Off",
        "NewDNSEnabled": "1",
        "NewDNSOverrideAllowed": "0",
    }
    if ppp:
        info |= {
            "NewUpstreamMaxBitRate": "46719000",
            "NewDownstreamMaxBitRate": "116790000",
            "NewIdleDisconnectTime": "0",
            "NewUserName": "example-user@isp.example",
            "NewLastAuthErrorInfo": "",
            "NewMaxCharsUsername": "128",
            "NewMinCharsUsername": "0",
            "NewAllowedCharsUsername": _CHARS + "@.-_",
            "NewMaxCharsPassword": "128",
            "NewMinCharsPassword": "0",
            "NewAllowedCharsPassword": _CHARS,
            "NewTransportType": "PPPoE",
            "NewPPPoEServiceName": "",
            "NewRemoteIPAddress": remote,
            "NewPPPoEACName": "isp-bras" if connected else "",
        }
    return info


def port_mapping(
    external: int,
    protocol: str,
    internal: int,
    client: str,
    description: str,
    *,
    enabled: bool = True,
    remote: str = "",
    lease: int = 0,
) -> dict[str, str]:
    """``GetGenericPortMappingEntry`` of WANIPConnection:1/WANPPPConnection:1."""
    return {
        "NewRemoteHost": remote,
        "NewExternalPort": str(external),
        "NewProtocol": protocol,
        "NewInternalPort": str(internal),
        "NewInternalClient": client,
        "NewEnabled": "1" if enabled else "0",
        "NewPortMappingDescription": description,
        "NewLeaseDuration": str(lease),
    }


#: Port sharing of the sample box (documentation addresses): a NAS web interface, a game server,
#: a disabled SSH forward, one only for a source network.
PORT_MAPPINGS = [
    port_mapping(8443, "TCP", 443, "192.0.2.20", "NAS"),
    port_mapping(27015, "UDP", 27015, "192.0.2.30", "Game server"),
    port_mapping(2222, "TCP", 22, "192.0.2.21", "SSH (off)", enabled=False),
    port_mapping(5060, "UDP", 5060, "192.0.2.40", "Phone", remote="203.0.113.0/24"),
]


def forwarding_entry(
    destination: str,
    mask: str,
    gateway: str,
    *,
    interface: str = "",
    metric: int = 0,
    enabled: bool = True,
    kind: str = "Network",
) -> dict[str, str]:
    """``GetGenericForwardingEntry`` of Layer3Forwarding:1 (static IPv4 routes, #149)."""
    return {
        "NewEnable": "1" if enabled else "0",
        "NewStatus": "Enabled" if enabled else "Disabled",
        "NewType": kind,
        "NewDestIPAddress": destination,
        "NewDestSubnetMask": mask,
        "NewSourceIPAddress": "0.0.0.0",
        "NewSourceSubnetMask": "0.0.0.0",
        "NewGatewayIPAddress": gateway,
        "NewInterface": interface,
        "NewForwardingMetric": str(metric),
    }


#: Static routes of the sample box (a lab network behind a second router, and a disabled one).
FORWARDING = [
    forwarding_entry("198.18.20.0", "255.255.255.0", "192.0.2.254"),
    forwarding_entry("198.18.30.0", "255.255.255.0", "192.0.2.254", enabled=False),
]


class NotSimulated(Exception):
    """An action of the description that the simulator does not implement (fault 501)."""


@dataclass
class FritzboxSim:
    """State and failure switches of the simulator; mutate between requests."""

    username: str = "signalbox"
    password: str = "example-password"
    #: A box set to log in with its password only (#373): TR-064 wants the user the box made up
    #: (``generated_user``, an empty name gets HTTP 401) and ``/login_sid.lua`` lists it.
    password_only: bool = False
    generated_user: str = "fritz0000"
    #: ``/login_sid.lua`` answers 404 (a FRITZ!OS without it, or the lookup blocked)
    no_login_page: bool = False
    #: FRITZ!OS whose descriptions are served (a directory name, ``tr064.VERSIONS`` or
    #: ``tr064.OLDER``)
    version: str = tr064.VERSIONS[0]
    #: The same by release (#413): ``"6.83"``, ``"7.29"``, ``"7.57"`` or ``"8.02"``; sets
    #: ``version``. An older release serves the descriptions of that release, without the
    #: actions and answer arguments it lacks, and the sample Wi-Fi it can have (no WPA3 before
    #: 7.20); before 7.24 ``/login_sid.lua`` is the version 1 page without a user list.
    release: str = ""
    #: a box before 7.24 that answers ``/login_sid.lua?version=2`` with 404 instead of ignoring
    #: the parameter (adapter fallback test)
    strict_login_version: bool = False
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
    #: FRITZ!Mesh (#171): ``X_AVM-DE_GetMeshListPath`` points to :func:`mesh_topology` (or to
    #: ``mesh_doc``); off: the box has no mesh and answers fault 401 as a FRITZ!OS without it
    mesh: bool = False
    mesh_doc: object = None
    #: path X_AVM-DE_GetMeshListPath points to (empty: this simulator's own)
    mesh_list_path: str = ""
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
    #: internet access to the box (``X_AVM-DE_RemoteAccess GetInfo``, off as shipped)
    remote_access: dict[str, str] = field(default_factory=lambda: dict(REMOTE_ACCESS))
    myfritz: dict[str, str] = field(default_factory=lambda: dict(MYFRITZ))
    #: ``X_AVM-DE_RemoteAccess GetDDNSInfo`` (#154)
    ddns: dict[str, str] = field(default_factory=lambda: dict(DDNS))
    #: ``X_AVM-DE_Storage GetInfo``: FTP in the LAN and from the internet
    storage: dict[str, str] = field(default_factory=lambda: dict(STORAGE))
    upnp: dict[str, str] = field(default_factory=lambda: dict(UPNP))
    #: Layer3Forwarding:1 (#149): static IPv4 routes and the connection the default route uses.
    forwarding: list[dict[str, str]] = field(default_factory=lambda: [dict(e) for e in FORWARDING])
    default_connection: str = (
        "uuid:00000000-0000-4000-8000-000000000149,urn:upnp-org:serviceId:WANIPConn1"
    )
    #: ``LANEthernetInterfaceConfig GetInfo``: NewMaxBitRate is a maximum (or ``Auto``)
    ethernet: dict[str, str] = field(default_factory=lambda: dict(ETHERNET))
    wlans: dict[int, dict[str, str]] = field(default_factory=lambda: copy.deepcopy(WLANS))
    passphrases: dict[int, str] = field(default_factory=lambda: dict(PASSPHRASES))
    wps: dict[int, tuple[str, str]] = field(default_factory=lambda: dict(WPS))
    #: offer Get/SetBeaconAdvertisement (else: fault 401)
    beacon_advertisement: bool = True
    #: write actions answered with success but not applied (a box that ignores a setting)
    ignore: set[str] = field(default_factory=set)
    #: write actions applied, in order, as ``service#action`` (arguments are not kept)
    writes: list[str] = field(default_factory=list)
    #: the internet connection: ``"dsl"`` (PPPoE, public 203.0.113.0/24), ``"cable"`` (DHCP
    #: behind the provider's carrier-grade NAT, 100.64.0.0/10), ``"lte"`` (WANIPConnection on a
    #: mobile access) or ``"client"`` (neither connection enabled: an IP client on LAN 1; with
    #: :meth:`behind`, WANIPConnection:1 reports its LAN 1 address)
    wan: str = "dsl"
    #: the connection is up (else ``Disconnected``, uptime 0)
    wan_up: bool = True
    #: ``wan`` ``"client"`` behind another router (#375, :meth:`behind`): the LAN 1 address
    #: WANIPConnection:1 reports (empty: none), and whether it reports the connection enabled
    lan1_address: str = ""
    lan1_enabled: bool = False
    #: port sharing of the active internet connection (``GetGenericPortMappingEntry``)
    port_mappings: list[dict[str, str]] = field(
        default_factory=lambda: [dict(m) for m in PORT_MAPPINGS]
    )
    #: every authenticated SOAP call that named an existing service: (service, action, args)
    calls: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    #: seconds since the last start (``DeviceInfo GetInfo`` ``NewUpTime``)
    uptime: int = 1209600
    #: IANA zone of the box's clock (``Time GetInfo``) and how far it is ahead, in seconds
    timezone: str = "Europe/Berlin"
    clock_skew: float = 0.0
    #: ``LANConfigSecurity`` (#175): the box still has its printed default password, the
    #: rights of the calling user (``BoxAdmin`` is "FRITZ!Box settings") and the user names
    default_password: bool = False
    user_rights: dict[str, str] = field(
        default_factory=lambda: {"BoxAdmin": "readwrite", "Phone": "none", "NAS": "none"}
    )
    users: list[str] = field(default_factory=lambda: ["fritz0000", "signalbox"])

    def __post_init__(self) -> None:
        if self.release:
            if self.release not in tr064.RELEASES:
                raise ValueError(f"unknown release {self.release!r}: {sorted(tr064.RELEASES)}")
            self.version = tr064.RELEASES[self.release]
        self._adapt()

    def _adapt(self) -> None:
        """The sample data a box of this release can have: no WPA3 before 7.20, and the older
        radios are Wi-Fi 4/5."""
        if self.fritzos < (7, 20):
            for index, standard in ((1, "n"), (2, "ac"), (3, "n")):
                self.wlans[index]["NewStandard"] = standard
                if self.wlans[index]["NewBeaconType"] == "11iandWPA3":
                    self.wlans[index]["NewBeaconType"] = "11i"

    @property
    def fritzos(self) -> tuple[int, int]:
        """(major, minor) of the FRITZ!OS in the description: ``113.06.83`` is (6, 83)."""
        parts = self.description.value("Display").split(".")
        return int(parts[-2]), int(parts[-1])

    def behind(
        self,
        address: str,
        gateway: str,
        lan: str,
        *,
        enabled: bool = False,
        mask: str = "255.255.255.0",
    ) -> None:
        """A box that reaches the internet over LAN 1 through another router (double NAT,
        #375): its LAN 1 *address* in the front router's network, the default route to
        *gateway* and its own LAN *lan* (``x.y.z.1``, DHCP from ``.20`` to ``.200``)."""
        self.wan = "client"
        self.lan1_address = address
        self.lan1_enabled = enabled
        self.forwarding.append(forwarding_entry("0.0.0.0", "0.0.0.0", gateway, kind="Default"))
        prefix = lan.rsplit(".", 1)[0]
        self.lan |= {
            "NewIPRouters": lan,
            "NewDNSServers": lan,
            "NewSubnetMask": mask,
            "NewMinAddress": f"{prefix}.20",
            "NewMaxAddress": f"{prefix}.200",
        }

    def reset(self) -> None:
        fresh = FritzboxSim()
        for name in self.__dataclass_fields__:
            if name not in ("nonces", "sid", "version", "release"):
                setattr(self, name, getattr(fresh, name))
        self._adapt()

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
        if not self.mesh:
            off.add("X_AVM-DE_GetMeshListPath")
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
        service = self.description.service_by_type("urn:dslforum-org:service:WLANConfiguration:1")
        assert service is not None
        [arg] = service.actions["SetBeaconType"].inputs
        allowed = {a.lower() for a in arg.variable.allowed}
        return [self.beacon_spelling(b) for b in OFFERED_BEACON_TYPES if b.lower() in allowed]

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

    @property
    def login_name(self) -> str:
        """The user TR-064 accepts."""
        return self.generated_user if self.password_only else self.username

    @property
    def login_v2(self) -> bool:
        """``/login_sid.lua?version=2`` (the user list) exists from FRITZ!OS 7.24 (#413)."""
        return self.fritzos >= (7, 24)

    def login_page(self, version: int = 2) -> str:
        """``/login_sid.lua?version=2``: no login needed, lists the users (#373). Before 7.24
        the parameter is ignored and the answer is the version 1 page (challenge, no users)."""
        if version == 1 or not self.login_v2:
            return (
                '<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID>'
                "<Challenge>1234abcd</Challenge><BlockTime>0</BlockTime><Rights></Rights>"
                "</SessionInfo>"
            )
        names = [self.generated_user] if self.password_only else [self.username]
        users = "".join(
            f'<User last="{int(i == len(names) - 1)}">{escape(n)}</User>'
            for i, n in enumerate(names)
            if n
        )
        return (
            '<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID>'
            "<Challenge>00000000</Challenge><BlockTime>0</BlockTime>"
            f"<Users>{users}</Users></SessionInfo>"
        )

    def authorised(self, method: str, header: str | None, realm: str) -> bool:
        if not header or not header.lower().startswith("digest "):
            return False
        params = {k: a or b for k, a, b in _PARAM.findall(header[7:])}
        if params.get("username") != self.login_name or params.get("realm") != realm:
            return False
        if params.get("nonce") not in self.nonces or params.get("qop") != "auth":
            return False
        ha1 = _md5(f"{self.login_name}:{realm}:{self.password}")
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
                "NewSerialNumber": "020000000001",  # invented; a real box: its base MAC
                "NewSoftwareVersion": desc.value("Display"),
                "NewHardwareVersion": desc.value("modelName"),
                "NewSpecVersion": "1.0",
                "NewProvisioningCode": "",
                "NewUpTime": str(self.uptime),
                "NewDeviceLog": "",
            }
        if name == "UserInterface" and action == "GetInfo":
            return {
                "NewUpgradeAvailable": "1",
                "NewPasswordRequired": "1",
                "NewPasswordUserSelectable": "1",
                "NewWarrantyDate": "0001-01-01T00:00:00",
                "NewX_AVM-DE_Version": "999.99.99",  # invented newer release
                "NewX_AVM-DE_DownloadURL": "",
                "NewX_AVM-DE_InfoURL": "",
                "NewX_AVM-DE_UpdateState": "UpdateAvailable",
                "NewX_AVM-DE_BuildType": "Release",
                "NewX_AVM-DE_SetupAssistantStatus": "1",
            }
        if name == "UserInterface" and action == "X_AVM-DE_GetInfo":
            return {
                "NewX_AVM-DE_AutoUpdateMode": "important",
                "NewX_AVM-DE_UpdateTime": "2026-01-15T03:12:00",
                "NewX_AVM-DE_LastFwVersion": "",
                "NewX_AVM-DE_LastInfoUrl": "",
                "NewX_AVM-DE_CurrentFwVersion": "",
                "NewX_AVM-DE_UpdateSuccessful": "unknown",
            }
        if name == "X_AVM-DE_RemoteAccess" and action == "GetInfo":
            return dict(self.remote_access)
        if name == "X_AVM-DE_RemoteAccess" and action == "GetDDNSInfo":
            return dict(self.ddns)
        if name == "X_AVM-DE_MyFritz" and action == "GetInfo":
            return dict(self.myfritz)
        if name == "X_AVM-DE_Storage" and action == "GetInfo":
            return dict(self.storage)
        if name == "X_AVM-DE_UPnP" and action == "GetInfo":
            return dict(self.upnp)
        if name == "Time" and action == "GetInfo":
            return time_info(self.timezone, self.clock_skew)
        if name == "LANConfigSecurity":
            return self._security(action)
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
                return dict(self.ethernet)
            if action == "GetStatistics":
                return {
                    "NewBytesSent": "1000",
                    "NewBytesReceived": "2000",
                    "NewPacketsSent": "10",
                    "NewPacketsReceived": "20",
                }
        if name == "WLANConfiguration":
            return self._wlan(int(number), action, args)
        if name in ("WANPPPConnection", "WANIPConnection", "WANCommonInterfaceConfig"):
            return self._wan(name, action, args)
        if name == "Layer3Forwarding":
            if action == "GetDefaultConnectionService":
                return {"NewDefaultConnectionService": self.default_connection}
            if action == "GetForwardNumberOfEntries":
                return {"NewForwardNumberOfEntries": str(len(self.forwarding))}
            if action == "GetGenericForwardingEntry":
                index = int(args["NewForwardingIndex"])
                return dict(self.forwarding[index]) if index < len(self.forwarding) else 713
        if name == "Hosts":
            if action == "GetHostNumberOfEntries":
                return {"NewHostNumberOfEntries": str(len(HOSTS))}
            if action == "GetGenericHostEntry":
                index = int(args["NewIndex"])
                return host_entry(index) if index < len(HOSTS) else 713
            if action == "X_AVM-DE_GetHostListPath":
                return {"NewX_AVM-DE_HostListPath": self.host_list_path or self.list_path}
            if action == "X_AVM-DE_GetMeshListPath":
                return {"NewX_AVM-DE_MeshListPath": self.mesh_list_path or self.mesh_path}
        raise NotSimulated(f"{service} {action}")

    # characters a password and a user name may have (built, not written out: a literal looks
    # like a key to secret scanners)
    ALLOWED_CHARS: ClassVar[str] = (
        string.digits + string.ascii_uppercase + string.ascii_lowercase + string.punctuation + " "
    )

    def _security(self, action: str) -> dict[str, str]:
        """``LANConfigSecurity`` (#175): password rules, the calling user and the user list.
        The rights and list layouts follow AVM's documentation (*guess*, #21)."""
        if action == "GetInfo":
            return {
                "NewMaxCharsPassword": "32",
                "NewMinCharsPassword": "0",
                "NewAllowedCharsPassword": self.ALLOWED_CHARS,
                "NewAllowedCharsUsername": self.ALLOWED_CHARS,
                "NewX_AVM-DE_IsDefaultPasswordActive": "1" if self.default_password else "0",
            }
        if action == "X_AVM-DE_GetCurrentUser":
            rights = "".join(
                f"<path>{p}</path><access>{a}</access>" for p, a in self.user_rights.items()
            )
            return {
                "NewX_AVM-DE_CurrentUsername": self.username,
                "NewX_AVM-DE_CurrentUserRights": f'<?xml version="1.0"?><rights>{rights}</rights>',
            }
        if action == "X_AVM-DE_GetUserList":
            entries = "".join(
                f'<Username last_user="{int(n == self.username)}">{escape(n)}</Username>'
                for n in self.users
            )
            return {"NewX_AVM-DE_UserList": f"<List>{entries}</List>"}
        raise NotSimulated(f"LANConfigSecurity {action}")

    def _wan(self, name: str, action: str, args: dict[str, str]) -> dict[str, str] | int:
        if name == "WANCommonInterfaceConfig":
            totals = {
                "GetTotalBytesSent": ("NewTotalBytesSent", 1_204_117_552),
                "GetTotalBytesReceived": ("NewTotalBytesReceived", 3_881_020_914),
                "GetTotalPacketsSent": ("NewTotalPacketsSent", 7_204_511),
                "GetTotalPacketsReceived": ("NewTotalPacketsReceived", 9_113_207),
            }
            if action in totals:  # fixed values (the 32-bit counters of every FRITZ!OS)
                key, value = totals[action]
                return {key: str(value)}
            if action != "GetCommonLinkProperties":
                raise NotSimulated(f"{name} {action}")
            access, down, upstream = WAN_ACCESS[self.wan]
            return {
                "NewWANAccessType": access,
                "NewLayer1UpstreamMaxBitRate": str(upstream),
                "NewLayer1DownstreamMaxBitRate": str(down),
                "NewPhysicalLinkStatus": "Up" if self.wan_up else "Down",
                "NewX_AVM-DE_DownstreamCurrentUtilization": "",
                "NewX_AVM-DE_UpstreamCurrentUtilization": "",
                "NewX_AVM-DE_DownstreamCurrentMaxSpeed": "0",
                "NewX_AVM-DE_UpstreamCurrentMaxSpeed": "0",
            }
        ppp = name == "WANPPPConnection"
        active = self.wan != "client" and ppp == (self.wan == "dsl")
        info = wan_info(ppp, active, self.wan_up, self.wan)
        if not ppp and self.wan == "client" and self.lan1_address:
            # the LAN 1 address of a box behind another router (what FRITZ!OS reports here
            # is a guess, #21); GetInfo leaves it out, GetExternalIPAddress has it
            up = self.wan_up
            info |= {
                "NewEnable": "1" if self.lan1_enabled else "0",
                "NewConnectionStatus": "Connected" if up else "Disconnected",
                "NewUptime": "3600" if up else "0",
                "NewExternalIPAddress": self.lan1_address if up and self.lan1_enabled else "",
            }
            if action == "GetExternalIPAddress":
                return {"NewExternalIPAddress": self.lan1_address if up else ""}
        if action == "GetInfo":
            return info
        if action == "GetStatusInfo":
            keys = ("NewConnectionStatus", "NewLastConnectionError", "NewUptime")
            return {k: info[k] for k in keys}
        if action == "GetExternalIPAddress":
            return {"NewExternalIPAddress": info["NewExternalIPAddress"]}
        if action == "X_GetDNSServers":
            return {"NewDNSServers": info["NewDNSServers"]}
        if action == "GetGenericPortMappingEntry":
            index = int(args["NewPortMappingIndex"])
            rows = self.port_mappings if active else []
            return dict(rows[index]) if index < len(rows) else 713
        raise NotSimulated(f"{name} {action}")

    @property
    def list_path(self) -> str:
        return f"{HOST_LIST}?sid={self.sid}"

    @property
    def mesh_path(self) -> str:
        return f"{MESH_LIST}?sid={self.sid}"

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
        if action == "X_AVM-DE_GetWPSInfo":
            mode, status = self.wps[index]
            return {"NewX_AVM-DE_WPSMode": mode, "NewX_AVM-DE_WPSStatus": status}
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
        if action == "GetChannelInfo":  # (#172) channels of the band with country DE
            five = info["NewX_AVM-DE_FrequencyBand"] == "5000"
            channels = [*range(36, 65, 4), *range(100, 141, 4)] if five else range(1, 14)
            return {
                "NewChannel": info["NewChannel"],
                "NewPossibleChannels": ",".join(str(c) for c in channels),
                "NewX_AVM-DE_AutoChannelEnabled": "1",
                "NewX_AVM-DE_FrequencyBand": info["NewX_AVM-DE_FrequencyBand"],
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
        if self.version in tr064.OLDER:  # the sample answer has more than this release's box
            wanted = {a.name for a in action.outputs}
            data = {k: v for k, v in data.items() if k in wanted}
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

    @app.get("/login_sid.lua")
    async def login_sid(version: int = 1) -> Response:
        state.requests += 1
        if state.no_login_page or (state.strict_login_version and version == 2):
            return Response("<html>404 Not Found</html>", status_code=404)
        return Response(state.login_page(version), media_type="text/xml")

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

    @app.get(MESH_LIST)
    async def mesh_list(sid: str = "") -> Response:
        state.requests += 1
        if sid != state.sid:
            return Response("<html>403 Forbidden</html>", status_code=403)
        if "MeshList" in state.malformed:
            return Response('{"nodes": [', media_type="application/json")
        doc = state.mesh_doc if state.mesh_doc is not None else mesh_topology()
        return Response(json.dumps(doc), media_type="application/json")

    return app
