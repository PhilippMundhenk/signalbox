"""MikroTik RouterOS 7: reads interfaces, bridge VLANs, DHCP, DNS, Wi-Fi, clients, neighbours.

The write side (router interfaces, DHCP, static leases, bridge VLANs, Wi-Fi) is in
:mod:`signalbox.adapters.mikrotik.write`.

Talks to the RouterOS REST API (``GET /rest/<menu path>``, HTTP basic auth) over HTTPS with a
pinned certificate (:mod:`signalbox.adapters.https`). Every endpoint and the JSON shape assumed
for it is listed in ``docs/adapters/mikrotik.md``; the shapes are taken from the RouterOS
documentation and still need confirmation on a real device (issue #21).

RouterOS answers a menu with a JSON list of objects (``.id`` plus the menu's properties) and a
single-value menu (``/system/resource``, ``/ip/dns``) with one object. Every value is a string:
booleans are ``"true"``/``"false"``, numbers are digits. Parsing is defensive: missing fields
never crash, unknown fields are ignored, an answer of the wrong shape raises
``AdapterError("unexpected answer from <endpoint>: ...")``.

Segments: on a bridge with ``vlan-filtering`` every VLAN id of ``/interface/bridge/vlan`` is
``<site>/segment/<vid>`` (VLAN 1 is the native segment), with the ports from its tagged and
untagged lists (configured and current) plus the access ports whose ``pvid`` it is. A VLAN
interface (``/interface/vlan``) on a plain port makes that port a tagged member. A bridge
without VLAN filtering is one untagged network: the native segment, unless another network
already is; a port of its own with an address (a DMZ) is ``<site>/segment/<port>``. Members of
the interface list ``WAN`` are the uplink: ports only, no segment, no subnets.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Interface, IPv6Network, ip_address, ip_interface, ip_network
from typing import Any

from pydantic import Field, JsonValue, SecretStr, field_validator, model_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterError,
    AdminLogin,
    AuthFailed,
    Capability,
    Manifest,
    Observation,
    SetupPlan,
    SetupRequest,
    SetupResult,
    SystemInfo,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.mikrotik import discovery as _discovery
from signalbox.adapters.mikrotik.write import WRITES, MikrotikWrites
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    SERVICE_PORTS,
    TYPED_OPTION_CODES,
    WIREGUARD_KEY,
    AddressSource,
    Band,
    Cipher,
    Client,
    DeviceHealth,
    DeviceRole,
    DeviceTime,
    DhcpBoot,
    DhcpLease,
    DhcpOption,
    DhcpPool,
    DhcpRelay,
    DhcpRoute,
    DhcpServer,
    DnsForwarder,
    DnsService,
    Fan,
    Firmware,
    FrameTypes,
    HostRecord,
    IPAddress,
    IPInterface,
    IPNetwork,
    LeaseState,
    ManagementService,
    Membership,
    NatClass,
    Neighbour,
    NtpClient,
    NtpServer,
    Pmf,
    Port,
    PortKind,
    PortMembership,
    PortRole,
    PowerSupply,
    Radio,
    Reservation,
    SaePwe,
    SaeSettings,
    Security,
    Segment,
    ServiceKind,
    SnmpSettings,
    SnmpVersion,
    StorageKind,
    StorageUsage,
    Subnet,
    TemperatureSensor,
    Tunnel,
    TunnelPeer,
    Uplink,
    UplinkKind,
    Wlan,
    Wps,
    WpsMethod,
    address_nat_class,
    normalise_mac,
    object_id,
    passphrase_digest,
    passphrase_fingerprint,
    port_id,
    segment_id,
)

RESOURCE = "/rest/system/resource"
ROUTERBOARD = "/rest/system/routerboard"
PACKAGE_UPDATE = "/rest/system/package/update"
INTERFACE = "/rest/interface"
ETHERNET = "/rest/interface/ethernet"
BRIDGE = "/rest/interface/bridge"
BRIDGE_PORT = "/rest/interface/bridge/port"
BRIDGE_VLAN = "/rest/interface/bridge/vlan"
BRIDGE_HOST = "/rest/interface/bridge/host"
VLAN = "/rest/interface/vlan"
BONDING = "/rest/interface/bonding"
ETHERNET_SWITCH_PORT = "/rest/interface/ethernet/switch/port"
LIST_MEMBER = "/rest/interface/list/member"
DHCP_CLIENT = "/rest/ip/dhcp-client"
IPV6_DHCP_CLIENT = "/rest/ipv6/dhcp-client"
PPPOE_CLIENT = "/rest/interface/pppoe-client"
WIREGUARD = "/rest/interface/wireguard"
WIREGUARD_PEERS = "/rest/interface/wireguard/peers"
PPPOE_MONITOR = "/rest/interface/pppoe-client/monitor"
CLOUD = "/rest/ip/cloud"
IP_ADDRESS = "/rest/ip/address"
IPV6_ADDRESS = "/rest/ipv6/address"
DHCP_SERVER = "/rest/ip/dhcp-server"
DHCP_NETWORK = "/rest/ip/dhcp-server/network"
DHCP_LEASE = "/rest/ip/dhcp-server/lease"
DHCP_OPTION = "/rest/ip/dhcp-server/option"
DHCP_RELAY = "/rest/ip/dhcp-relay"
POOL = "/rest/ip/pool"
DNS = "/rest/ip/dns"
DNS_STATIC = "/rest/ip/dns/static"
ARP = "/rest/ip/arp"
IPV6_NEIGHBOR = "/rest/ipv6/neighbor"
NEIGHBOR = "/rest/ip/neighbor"
WIFI = "/rest/interface/wifi"
WIFI_CONFIGURATION = "/rest/interface/wifi/configuration"
WIFI_SECURITY = "/rest/interface/wifi/security"
WIFI_CHANNEL = "/rest/interface/wifi/channel"
WIFI_DATAPATH = "/rest/interface/wifi/datapath"
WIFI_STEERING = "/rest/interface/wifi/steering"
WIFI_REGISTRATION = "/rest/interface/wifi/registration-table"
WIRELESS = "/rest/interface/wireless"
WIRELESS_SECURITY = "/rest/interface/wireless/security-profiles"
WIRELESS_REGISTRATION = "/rest/interface/wireless/registration-table"
HEALTH = "/rest/system/health"
CLOCK = "/rest/system/clock"
NTP_CLIENT = "/rest/system/ntp/client"
NTP_SERVER = "/rest/system/ntp/server"
IP_SERVICE = "/rest/ip/service"
MAC_SERVER = "/rest/tool/mac-server"
MAC_WINBOX = "/rest/tool/mac-server/mac-winbox"
ROMON = "/rest/tool/romon"
IP_SSH = "/rest/ip/ssh"
UPNP = "/rest/ip/upnp"
SNMP = "/rest/snmp"
SNMP_COMMUNITY = "/rest/snmp/community"

#: ``/ip/service`` names -> kind of service.
_IP_SERVICES = {
    "telnet": ServiceKind.TELNET,
    "ftp": ServiceKind.FTP,
    "www": ServiceKind.HTTP,
    "ssh": ServiceKind.SSH,
    "www-ssl": ServiceKind.HTTPS,
    "api": ServiceKind.API,
    "winbox": ServiceKind.WINBOX,
    "api-ssl": ServiceKind.API_SSL,
}

#: Name of the interface list RouterOS' default configuration puts the uplink into.
WAN_LIST = "WAN"

_KINDS = {
    "ether": PortKind.ETHERNET,
    "bridge": PortKind.BRIDGE,
    "bond": PortKind.LAG,
    "wifi": PortKind.WIRELESS,
    "wlan": PortKind.WIRELESS,
    "cap": PortKind.WIRELESS,
}
#: Interface types that are not ports (loopback). VLAN interfaces are ports of role ``vlan``
#: and also become segments.
_NOT_PORTS = {"loopback", "lo"}
#: ``type`` of ``/interface`` rows -> role (#252). ``ether`` covers SFP too. Types that are
#: tunnels in RouterOS 7 (WireGuard is ``wg``).
_ROLES = {
    "ether": PortRole.JACK,
    "bridge": PortRole.BRIDGE,
    "vlan": PortRole.VLAN,
    "bond": PortRole.LAG,
    "wifi": PortRole.WIRELESS,
    "wlan": PortRole.WIRELESS,
    "cap": PortRole.WIRELESS,
}
_TUNNEL_TYPES = frozenset(
    {
        "wg", "wireguard", "eoip", "gre", "gre6", "ipip", "ipipv6", "eoipv6", "vxlan",
        "pppoe-out", "pptp-out", "l2tp-out", "sstp-out", "ovpn-out", "6to4", "ppp-out",
    }
)  # fmt: skip
#: ``frame-types`` of a bridge port that does not accept untagged frames (no pvid membership).
_TAGGED_ONLY = "admit-only-vlan-tagged"
_FRAME_TYPES = {
    "admit-all": FrameTypes.ALL,
    _TAGGED_ONLY: FrameTypes.TAGGED_ONLY,
    "admit-only-untagged-and-priority-tagged": FrameTypes.UNTAGGED_ONLY,
}
_WIFI_PROFILES = {
    "configuration": WIFI_CONFIGURATION,
    "security": WIFI_SECURITY,
    "channel": WIFI_CHANNEL,
    "datapath": WIFI_DATAPATH,
    "steering": WIFI_STEERING,
}
_PMF = {"disabled": Pmf.DISABLED, "allowed": Pmf.OPTIONAL, "required": Pmf.REQUIRED}
_AP_MODES = {"ap", "ap-bridge", "bridge"}


class MikrotikConfig(AdapterConfig):
    url: str = Field(
        description="Address of the router, for example 192.0.2.1; RouterOS answers the REST API "
        "on https (IP > Services: www-ssl must be enabled)",
        examples=["192.0.2.1"],
    )
    username: str = Field(
        default="signalbox",
        description="RouterOS user, best in a group of its own with the policies read, api and "
        "rest-api (add write only to deploy changes)",
    )
    password: SecretStr = Field(description="Password of that user")
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="Allow plain http:// (simulators and tests only: password sent unencrypted)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return device_url(value)

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> MikrotikConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (simulators only)")
        return self


# --- defensive parsing helpers ---------------------------------------------------------------


def _unexpected(endpoint: str, what: str) -> AdapterError:
    return AdapterError(f"unexpected answer from {endpoint}: {what}")


def _rows(data: Any, endpoint: str) -> list[dict[str, Any]]:
    """A menu answer: a list of objects; entries that are not objects are dropped."""
    if not isinstance(data, list):
        raise _unexpected(endpoint, f"{type(data).__name__}, expected a list")
    return [r for r in data if isinstance(r, dict)]


def _object(data: Any, endpoint: str) -> dict[str, Any]:
    """A single-value menu: one object (also accepted as a list holding one object)."""
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        raise _unexpected(endpoint, f"{type(data).__name__}, expected an object")
    return data


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value is True or _text(value).lower() in ("true", "yes", "on")


def _maybe(value: Any) -> bool | None:
    """A flag that may not be set at all (None: RouterOS' default applies, unknown here)."""
    return None if value is None or value == "" else _flag(value)


def _active(row: dict[str, Any]) -> bool:
    return not _flag(row.get("disabled")) and not _flag(row.get("invalid"))


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    match = re.match(r"-?\d+", _text(value))
    return int(match.group()) if match else None


def _names(value: Any) -> list[str]:
    """A RouterOS list value: ``"a,b,c"`` (or a JSON list)."""
    parts = value if isinstance(value, list) else _text(value).split(",")
    return [p.strip() for p in parts if isinstance(p, str) and p.strip()]


def _addr(value: Any) -> IPAddress | None:
    try:
        return ip_address(_text(value).split("%")[0])
    except ValueError:
        return None


def _addrs(value: Any) -> list[IPAddress]:
    return [a for a in (_addr(p) for p in _names(value)) if a is not None]


def _mac(value: Any) -> str | None:
    try:
        return normalise_mac(_text(value))
    except ValueError:
        return None


def vlan_ids(value: Any) -> list[int]:
    """``vlan-ids`` of a bridge VLAN entry: ``"20"``, ``"20,30"``, ``"100-105"``."""
    out: list[int] = []
    for part in _names(value):
        low, _, high = part.partition("-")
        a, b = _int(low), _int(high or low)
        if a is None or b is None or not 1 <= a <= b <= 4094:
            continue
        out += [v for v in range(a, b + 1) if v not in out]
    return out


_DURATION = re.compile(
    r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+):(\d\d):(\d\d))?"
)


def _wire(value: Any) -> bytes | None:
    """An option value written as hex (``0x0c68...``), else None."""
    text = _text(value)
    if not text.lower().startswith("0x"):
        return None
    try:
        return bytes.fromhex(text[2:])
    except ValueError:
        return None


def _search_list(raw: bytes) -> list[str]:
    """Option 119: DNS names as length-prefixed labels, each ended by a zero byte."""
    names: list[str] = []
    labels: list[str] = []
    i = 0
    while i < len(raw):
        n = raw[i]
        if n == 0:
            names.append(".".join(labels))
            labels = []
            i += 1
        elif n >= 0x40 or i + 1 + n > len(raw):  # compression pointers: not decoded
            break
        else:
            labels.append(raw[i + 1 : i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
    return [n for n in names if n]


def _classless_routes(raw: bytes) -> list[DhcpRoute]:
    """Option 121 (RFC 3442): prefix length, the significant destination octets, gateway."""
    routes, i = [], 0
    while i < len(raw):
        bits = raw[i]
        width = (bits + 7) // 8
        if bits > 32 or i + 1 + width + 4 > len(raw):
            break
        dest = raw[i + 1 : i + 1 + width] + bytes(4 - width)
        gateway = raw[i + 1 + width : i + 5 + width]
        routes.append(
            DhcpRoute(
                destination=ip_network(f"{IPv4Address(dest)}/{bits}", strict=False),
                gateway=IPv4Address(gateway),
            )
        )
        i += 5 + width
    return routes


def _lease_state(row: dict[str, Any], static: bool) -> LeaseState:
    status = _text(row.get("status"))
    if status == "bound":
        return LeaseState.ACTIVE
    if status == "offered":
        return LeaseState.OFFERED
    if status in ("busy", "conflict"):  # guess: the address is in use elsewhere
        return LeaseState.DECLINED
    return LeaseState.RESERVED if static else LeaseState.EXPIRED  # waiting, testing, ...


def _lease(row: dict[str, Any], now: datetime) -> DhcpLease | None:
    mac = _mac(row.get("active-mac-address") or row.get("mac-address"))
    client_id = _text(row.get("active-client-id") or row.get("client-id")) or None
    address = _addr(row.get("active-address") or row.get("address"))
    if address is None or (mac is None and client_id is None):
        return None
    static = not _flag(row.get("dynamic"))
    left = duration(row.get("expires-after"))
    return DhcpLease(
        address=address,
        mac=mac,
        client_id=client_id,
        hostname=_text(row.get("host-name")) or _text(row.get("comment")) or None,
        state=_lease_state(row, static),
        reserved=static,
        expires=now + timedelta(seconds=left) if left is not None else None,
        vendor_class=_text(row.get("active-class-id") or row.get("class-id")) or None,
    )


def _segment_key(segment: str) -> str:
    key = segment.rsplit("/", 1)[-1]
    return "lan" if key == "native" else key


def duration(value: Any) -> int | None:
    """RouterOS time: ``30m``, ``1d00:00:00``, ``00:10:00``, ``1w2d3h4m5s`` -> seconds."""
    text = _text(value).replace(" ", "")
    match = _DURATION.fullmatch(text) if text else None
    if not match or not any(match.groups()):
        return None
    w, d, h, m, s, hh, mm, ss = (int(g) if g else 0 for g in match.groups())
    return (((w * 7 + d) * 24 + h + hh) * 60 + m + mm) * 60 + s + ss


def speed(value: Any) -> tuple[int | None, bool | None]:
    """``1Gbps``, ``100Mbps``, ``2.5G-baseT``, ``1G-baseT-full``, ``100M-baseT-half``."""
    match = re.match(r"(\d+(?:\.\d+)?)\s*([MG])", _text(value), re.IGNORECASE)
    mbps = None
    if match:
        mbps = int(float(match.group(1)) * (1000 if match.group(2).upper() == "G" else 1))
    text = _text(value).lower()
    duplex = True if text.endswith("full") else False if text.endswith("half") else None
    return mbps, duplex


def advertised(value: Any) -> list[int]:
    """``10M-baseT-half,100M-baseT-full,1G-baseT-full`` (7.12+) or ``10M-full,1000M-full``."""
    return sorted({m for item in _text(value).split(",") if (m := speed(item)[0])})


def mtu_of(*values: Any) -> int | None:
    """The first value that is an MTU (``auto`` on a bridge: the next one, ``actual-mtu``)."""
    for value in values:
        number = _int(value)
        if number is not None and 68 <= number <= 65535:
            return number
    return None


def flow_control(row: dict[str, Any]) -> bool | None:
    """``rx-``/``tx-flow-control`` ``on``/``off``/``auto`` (auto: negotiated, unknown here)."""
    values = {_text(row.get(k)).lower() for k in ("rx-flow-control", "tx-flow-control")}
    if "on" in values:
        return True
    return False if values == {"off"} else None


def bridge_port_details(row: dict[str, Any]) -> dict[str, Any]:
    """PVID, frame types and ingress filtering of a port in a VLAN-filtering bridge."""
    pvid = _int(row.get("pvid")) or 1
    return {
        "pvid": pvid if 1 <= pvid <= 4094 else None,
        "frame_types": _FRAME_TYPES.get(_text(row.get("frame-types"))),
        "ingress_filter": _maybe(row.get("ingress-filtering")),
    }


def _pool(text: str) -> DhcpPool | None:
    try:
        if "-" in text:
            start, end = (ip_address(x.strip()) for x in text.split("-", 1))
            return DhcpPool(start=start, end=end)
        net = ip_network(text, strict=False)
    except ValueError:
        return None
    return DhcpPool(start=net[0], end=net[-1])


def frequency_channel(mhz: int) -> tuple[Band, int] | None:
    if mhz == 2484:
        return Band.GHZ_2_4, 14
    if 2412 <= mhz < 2484:
        return Band.GHZ_2_4, (mhz - 2407) // 5
    if 5950 <= mhz <= 7125:
        return Band.GHZ_6, (mhz - 5950) // 5
    if 5000 <= mhz < 5950:
        return Band.GHZ_5, (mhz - 5000) // 5
    return None


def band_of(text: Any) -> Band | None:
    """``channel.band`` / ``band``: ``2ghz-ax``, ``5ghz-a/n/ac``, ``6ghz-ax``."""
    prefix = _text(text).lower()[:4]
    return {"2ghz": Band.GHZ_2_4, "5ghz": Band.GHZ_5, "6ghz": Band.GHZ_6}.get(prefix)


def width_of(text: Any) -> int | None:
    """``20/40/80mhz``, ``20/40mhz-Ce``, ``20mhz`` -> the widest."""
    head = _text(text).lower().split("mhz")[0]
    widths = [w for w in (_int(x) for x in head.split("/")) if w in (20, 40, 80, 160, 320)]
    return max(widths) if widths else None


def security_of(types: Any, mode: Any = None) -> Security:
    """``authentication-types`` (``wpa2-psk,wpa3-psk``, ...); legacy ``mode=none`` is open and
    ``static-keys-*`` is WEP. ``wpa-psk`` is WPA1 (mixed with ``wpa2-psk``: WPA/WPA2)."""
    kinds = set(_names(types))
    if _text(mode) == "none":
        return Security.OPEN
    if _text(mode).startswith("static-keys"):
        return Security.WEP
    if not kinds:
        return Security.OPEN
    if "wpa3-eap" in kinds:
        return Security.WPA3_ENTERPRISE
    if "wpa3-eap-192" in kinds:
        return Security.WPA3_ENTERPRISE_192
    if "wpa2-eap" in kinds:
        return Security.WPA_ENTERPRISE if "wpa-eap" in kinds else Security.WPA2_ENTERPRISE
    if "wpa-eap" in kinds:
        return Security.WPA_ENTERPRISE
    if {"wpa2-psk", "wpa3-psk"} <= kinds:
        return Security.WPA2_WPA3
    if "wpa3-psk" in kinds:
        return Security.WPA3
    if {"wpa-psk", "wpa2-psk"} <= kinds:
        return Security.WPA_WPA2
    if "wpa2-psk" in kinds:
        return Security.WPA2
    if "wpa-psk" in kinds:
        return Security.WPA
    if "owe" in kinds:
        return Security.OWE
    return Security.OTHER


_PERSONAL = {
    Security.WPA,
    Security.WPA_WPA2,
    Security.WPA2,
    Security.WPA3,
    Security.WPA2_WPA3,
    Security.OTHER,
}
_SAE = {Security.WPA3, Security.WPA2_WPA3}
_CIPHERS = {
    "ccmp": Cipher.CCMP,
    "aes-ccm": Cipher.CCMP,
    "ccmp-256": Cipher.CCMP_256,
    "gcmp": Cipher.GCMP,
    "gcmp-256": Cipher.GCMP_256,
    "tkip": Cipher.TKIP,
}
_SAE_PWE = {
    "hunting-and-pecking": SaePwe.HUNTING_AND_PECKING,
    "hash-to-element": SaePwe.HASH_TO_ELEMENT,
    "both": SaePwe.BOTH,
}
#: What the ``wifi`` drivers (wifi-qcom, wifi-qcom-ac) offer; the ``wireless`` package has no
#: WPA3 and no OWE but does WEP.
_WIFI_MODES = [
    Security.OPEN,
    Security.OWE,
    Security.WPA,
    Security.WPA_WPA2,
    Security.WPA2,
    Security.WPA3,
    Security.WPA2_WPA3,
    Security.WPA_ENTERPRISE,
    Security.WPA2_ENTERPRISE,
    Security.WPA3_ENTERPRISE,
    Security.WPA3_ENTERPRISE_192,
]
_WIRELESS_MODES = [
    Security.OPEN,
    Security.WEP,
    Security.WPA,
    Security.WPA_WPA2,
    Security.WPA2,
    Security.WPA_ENTERPRISE,
    Security.WPA2_ENTERPRISE,
]


def ciphers_of(value: Any, sec: Security) -> list[Cipher] | None:
    """``encryption`` / ``unicast-ciphers`` as model ciphers; None: not set, open, or a word
    this does not know. WEP networks have the ``wep`` cipher only."""
    if sec is Security.OPEN:
        return None
    if sec is Security.WEP:
        return [Cipher.WEP]
    words = _names(value)
    found = [_CIPHERS[w] for w in words if w in _CIPHERS]
    return list(dict.fromkeys(found)) if words and len(found) == len(words) else None


def cipher_of(value: Any, sec: Security) -> Cipher | None:
    """``group-encryption`` / ``group-ciphers``: the first (strongest listed) cipher."""
    if sec is Security.OPEN:
        return None
    if sec is Security.WEP:
        return Cipher.WEP
    words = [_CIPHERS[w] for w in _names(value) if w in _CIPHERS]
    return words[0] if words else None


def wps_of(value: Any) -> Wps | None:
    """``wps`` (wifi: ``push-button``, ``disable``) or ``wps-mode`` (wireless: ``disabled``,
    ``push-button``, ``push-button-virtual-only``); None: not set."""
    text = _text(value)
    if not text:
        return None
    if text.startswith("disable"):
        return Wps(enabled=False)
    if text.startswith("push-button"):
        return Wps(enabled=True, methods=[WpsMethod.PUSH_BUTTON])
    return None


def _extra(row: dict[str, Any], *keys: str) -> dict[str, JsonValue]:
    return {k: _text(row[k]) for k in keys if _text(row.get(k))}


def ros_error(endpoint: str, response: Any) -> AdapterError:
    """A refused request: RouterOS answers ``{"error", "message", "detail"}``.

    A menu this device does not have (a package that is not installed, ``/system/routerboard``
    on CHR) is HTTP 400 ``no such command or directory (...)`` (or ``no such command prefix``):
    :class:`NotFound`, as an optional menu. A missing policy is HTTP 500 ``not enough
    permissions (9)``: :class:`AuthFailed`. Both as RouterOS 7.25 CHR answers them in CI.
    """
    try:
        data = response.json()
    except ValueError:
        data = {}
    detail = _text(data.get("detail")) if isinstance(data, dict) else ""
    if detail.startswith("no such command"):
        return NotFound(f"{endpoint}: not on this device ({detail})")
    if "not enough permissions" in detail:
        return AuthFailed(f"{endpoint}: access denied ({detail}); check the user's group policies")
    reason = detail or _text(getattr(response, "reason_phrase", ""))
    return AdapterError(f"{endpoint}: HTTP {response.status_code} {reason}".rstrip())


async def get_menu(http: DeviceHttp, endpoint: str) -> Any:
    """``GET`` one menu (errors mapped by :func:`ros_error`)."""
    response = await http.request("GET", endpoint, accept=(400, 500))
    if response.status_code >= 400:
        raise ros_error(endpoint, response)
    try:
        return response.json()
    except ValueError as exc:
        raise AdapterError(f"{endpoint}: answer is not valid JSON") from exc


def _prefix(value: Any) -> IPv6Network | None:
    """``prefix`` of an IPv6 DHCP client: ``"2001:db8:1::/56, 2d23h59m"`` (with lifetime)."""
    try:
        net = ip_network(_text(value).split(",")[0].strip(), strict=False)
    except ValueError:
        return None
    return net if isinstance(net, IPv6Network) else None


# --- interface layout, shared by every capability --------------------------------------------


@dataclass
class _Layout:
    ports: dict[str, Port]
    segments: dict[str, Segment]
    #: Layer-3 interface name -> segment id (bridges, VLAN interfaces, routed ports).
    l3: dict[str, str]
    addresses: list[tuple[str, IPInterface]]
    wan: set[str]
    #: Bridge port -> segment of its pvid (where the bridge filters VLANs, or is untagged).
    port_segment: dict[str, str] = field(default_factory=dict)
    filtering: set[str] = field(default_factory=set)
    own_macs: set[str] = field(default_factory=set)

    def containing(self, address: IPAddress) -> str | None:
        """Segment with the most specific network that contains the address."""
        best: tuple[int, str] | None = None
        for name, a in self.addresses:
            seg = self.l3.get(name)
            if seg and address in a.network and (best is None or a.network.prefixlen > best[0]):
                best = (a.network.prefixlen, seg)
        return best[1] if best else None

    def port(self, name: str) -> str | None:
        return self.ports[name].id if name in self.ports else None


#: Shown in the device form ("Before you add it").
MIKROTIK_STEPS = (
    (
        "Enable the REST API: the service www-ssl needs a certificate; the setup guide has the "
        "five commands (a local CA is enough)."
    ),
    ("Add a group with the policies read, api and rest-api and a user 'signalbox' in it."),
    (
        "Below: the router's address, that user and password. Then Test connection and trust "
        "the certificate."
    ),
)


class MikrotikAdapter(MikrotikWrites, Adapter):
    manifest = Manifest(
        setup_steps=MIKROTIK_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/mikrotik.md#setup",
        id="mikrotik",
        name="MikroTik RouterOS",
        version="0.2.0",
        api_version="1.3",
        vendor="MikroTik",
        roles=frozenset({DeviceRole.GATEWAY, DeviceRole.SWITCH, DeviceRole.AP}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.DHCP,
                Capability.DNS,
                Capability.WIRELESS,
                Capability.CLIENTS,
                Capability.NEIGHBOURS,
                Capability.HEALTH,
                Capability.TIME,
                Capability.VPN,
            }
        ),
        config=MikrotikConfig,
        description="Reads and changes a RouterOS 7 router, switch or access point (REST API).",
        writes=WRITES,
        admin_login=AdminLogin(
            transport="the REST API as admin",
            user_default="admin",
            secret_label="admin password",
            note="The REST API (www-ssl with a certificate, setup guide: HTTPS with a "
            "certificate) must be on already.",
        ),
    )

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """REST API answering 401 with the RouterOS realm, without credentials."""
        return await _discovery.discover(probe)

    @classmethod
    async def plan_setup(cls, request: SetupRequest) -> SetupPlan:
        """User group and user through the REST API as admin (docs: Automatic setup)."""
        from signalbox.adapters.mikrotik.provision import MikrotikSetup

        return await MikrotikSetup(request).plan()

    @classmethod
    async def apply_setup(cls, request: SetupRequest) -> SetupResult:
        from signalbox.adapters.mikrotik.provision import MikrotikSetup

        return await MikrotikSetup(request).apply()

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        assert isinstance(cfg, MikrotikConfig)
        self.http = DeviceHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            auth=(cfg.username, cfg.password.get_secret_value()),
            allow_insecure_http=cfg.allow_insecure_http,
        )
        self._cache: dict[str, Any] = {}
        self._layout_cache: _Layout | None = None

    async def close(self) -> None:
        await self.http.close()

    async def _get(self, endpoint: str) -> Any:
        """GET once per observation (DHCP and clients both need the leases, ...)."""
        if endpoint not in self._cache:
            self._cache[endpoint] = await get_menu(self.http, endpoint)
        return self._cache[endpoint]

    async def _rows(self, endpoint: str) -> list[dict[str, Any]]:
        return _rows(await self._get(endpoint), endpoint)

    async def _optional_rows(self, endpoint: str) -> list[dict[str, Any]]:
        """A menu that may not exist (package not installed, older version): empty then."""
        try:
            return await self._rows(endpoint)
        except NotFound:
            return []

    def _seg(self, vid: int | None) -> str:
        return segment_id(self.context.site_id, vid)

    # --- system -------------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        # A new observation: probe the certificate again and forget the previous answers.
        await self.http.reset()
        self._cache.clear()
        self._layout_cache = None
        resource = _object(await self._get(RESOURCE), RESOURCE)
        current = _text(resource.get("version")).split(" ")[0]
        if not current:
            raise _unexpected(RESOURCE, "no version")
        model = _text(resource.get("board-name")) or None
        try:
            board = _object(await self._get(ROUTERBOARD), ROUTERBOARD)
        except NotFound:  # CHR and x86 have no routerboard menu
            board = {}
        if _flag(board.get("routerboard"), default=True):
            model = _text(board.get("model")) or model
        available = None
        try:
            update = _object(await self._get(PACKAGE_UPDATE), PACKAGE_UPDATE)
        except (NotFound, AdapterError):  # optional: the user may lack the right to see it
            update = {}
        latest = _text(update.get("latest-version"))
        if latest and latest != current:
            available = latest
        return SystemInfo(
            vendor="MikroTik",
            model=model,
            firmware=Firmware(current=current, available=available),
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
        )

    # --- interfaces ---------------------------------------------------------------------------

    async def _layout(self) -> _Layout:
        if self._layout_cache is None:
            self._layout_cache = await self._build_layout()
        return self._layout_cache

    async def _build_layout(self) -> _Layout:
        dev, site = self.context.device_id, self.context.site_id
        interfaces = await self._rows(INTERFACE)
        ethernet = {_text(r.get("name")): r for r in await self._optional_rows(ETHERNET)}
        bridges = {_text(r.get("name")): r for r in await self._rows(BRIDGE)}
        bridge_ports = [r for r in await self._rows(BRIDGE_PORT) if _active(r)]
        bridge_vlans = [r for r in await self._rows(BRIDGE_VLAN) if _active(r)]
        vlan_ifaces = {_text(r.get("name")): r for r in await self._rows(VLAN)}
        bonds = {_text(r.get("name")): r for r in await self._optional_rows(BONDING)}
        chip_ports = await self._optional_rows(ETHERNET_SWITCH_PORT)
        wan = {
            _text(r.get("interface"))
            for r in await self._optional_rows(LIST_MEMBER)
            if _text(r.get("list")) == WAN_LIST and _active(r)
        }

        filtering = {b for b, r in bridges.items() if _flag(r.get("vlan-filtering"))}
        vlan_details = {
            _text(r.get("interface")): bridge_port_details(r)
            for r in bridge_ports
            if _text(r.get("bridge")) in filtering
        }
        vlan_details |= {b: bridge_port_details(bridges[b]) for b in filtering}
        ports: dict[str, Port] = {}
        for row in interfaces:
            name, kind = _text(row.get("name")), _text(row.get("type"))
            if not name or kind in _NOT_PORTS:
                continue
            eth = ethernet.get(name, {})
            mbps, duplex = speed(eth.get("speed"))
            disabled = _flag(row.get("disabled"))
            running = row.get("running")
            ports[name] = Port(
                id=port_id(dev, name),
                device_id=dev,
                name=name,
                kind=_KINDS.get(kind, PortKind.VIRTUAL),
                up=False if disabled else (_flag(running) if running is not None else None),
                speed_mbps=mbps,
                full_duplex=duplex,
                mac=_mac(row.get("mac-address")),
                description=_text(row.get("comment") or bridges.get(name, {}).get("comment")),
                admin_up=not disabled if row.get("disabled") is not None else None,
                mtu=mtu_of(row.get("mtu"), row.get("actual-mtu")),
                l2_mtu=mtu_of(row.get("l2mtu"), eth.get("l2mtu")),
                advertised_speeds_mbps=advertised(eth.get("advertise")),
                autoneg=_maybe(eth.get("auto-negotiation")),
                flow_control=flow_control(eth),
                **vlan_details.get(name, {}),
                role=PortRole.TUNNEL if kind in _TUNNEL_TYPES else _ROLES.get(kind),
                vendor_extra=_extra(row, "type"),
            )
            if kind in _TUNNEL_TYPES:
                ports[name] = ports[name].model_copy(update={"kind": PortKind.VIRTUAL})
        # internal structure (#252): CPU ports of switch chips, then what runs on what
        chip_of: dict[str, str] = {}  # jack -> CPU port of its switch chip
        for row in chip_ports:
            pname = _text(row.get("name"))
            if pname.endswith("-cpu") and pname not in ports:
                cpu = pname
            elif pname in ports:
                chip_of[pname] = f"{_text(row.get('switch'))}-cpu"
                continue
            else:
                continue
            ports[cpu] = Port(
                id=port_id(dev, cpu), device_id=dev, name=cpu, kind=PortKind.VIRTUAL,
                role=PortRole.CPU,
            )  # fmt: skip
        lower: dict[str, list[str]] = {}
        for b in bridges:
            lower[b] = [
                _text(r.get("interface")) for r in bridge_ports if _text(r.get("bridge")) == b
            ]
        for n, vrow in vlan_ifaces.items():
            lower[n] = [_text(vrow.get("interface"))]
        for n, brow in bonds.items():
            lower[n] = _names(brow.get("slaves"))
        for endpoint in (WIFI, WIRELESS):  # virtual APs run on their master interface
            for wrow in await self._optional_rows(endpoint):
                if _text(wrow.get("master-interface")):
                    lower[_text(wrow.get("name"))] = [_text(wrow.get("master-interface"))]
        for n, port in ports.items():
            if port.role is PortRole.JACK and chip_of.get(n) in ports:
                lower[n] = [chip_of[n]]
        for n, names_ in lower.items():
            if n in ports:
                ports[n] = ports[n].model_copy(
                    update={
                        "lower": [
                            ports[x].id for x in dict.fromkeys(names_) if x in ports and x != n
                        ]
                    }
                )

        members: dict[str, dict[str, Membership]] = {}
        names: dict[str, str] = {}
        vids: dict[str, int | None] = {}

        def join(seg: str, vid: int | None, port: str | None, mode: Membership | None) -> None:
            entry = members.setdefault(seg, {})
            vids.setdefault(seg, vid)
            if port is None or port not in ports or port in bridges:
                return  # the bridge itself is the router's own side, not a member
            if entry.get(ports[port].id) is not Membership.UNTAGGED:
                entry[ports[port].id] = mode or Membership.UNTAGGED

        def label(seg: str, text: str) -> None:
            if text and seg not in names:
                names[seg] = text

        l3: dict[str, str] = {}
        port_segment: dict[str, str] = {}
        native_taken = bool(filtering)

        # Filtering bridges: VLAN table plus access ports by pvid.
        for b in sorted(filtering):
            pvid = _int(bridges[b].get("pvid")) or 1
            l3[b] = self._seg(pvid)
            join(l3[b], pvid, None, None)
            label(l3[b], _text(bridges[b].get("comment")))
        for row in bridge_vlans:
            if _text(row.get("bridge")) not in filtering:
                continue
            for vid in vlan_ids(row.get("vlan-ids")):
                seg = self._seg(vid)
                join(seg, vid, None, None)
                for key in ("untagged", "current-untagged"):
                    for p in _names(row.get(key)):
                        join(seg, vid, p, Membership.UNTAGGED)
                for key in ("tagged", "current-tagged"):
                    for p in _names(row.get(key)):
                        join(seg, vid, p, Membership.TAGGED)
                if not _flag(row.get("dynamic")):  # RouterOS: "added by pvid"
                    label(seg, _text(row.get("comment")))
        for row in bridge_ports:
            b, p = _text(row.get("bridge")), _text(row.get("interface"))
            if b in filtering:
                pvid = _int(row.get("pvid")) or 1
                if _text(row.get("frame-types")) != _TAGGED_ONLY:
                    port_segment[p] = self._seg(pvid)
                    join(self._seg(pvid), pvid, p, Membership.UNTAGGED)

        # Untagged networks: bridges without filtering first, then routed ports with an address.
        addresses: list[tuple[str, IPInterface]] = []
        for endpoint, required in ((IP_ADDRESS, True), (IPV6_ADDRESS, False)):
            rows = await (self._rows(endpoint) if required else self._optional_rows(endpoint))
            for row in rows:
                iface = _text(row.get("actual-interface")) or _text(row.get("interface"))
                try:
                    a = ip_interface(_text(row.get("address")).split("%")[0])
                except ValueError:
                    continue
                if _active(row) and not a.ip.is_link_local and not a.ip.is_loopback:
                    addresses.append((iface, a))
        with_address = {n for n, _ in addresses}
        in_bridge = {_text(r.get("interface")) for r in bridge_ports}
        untagged = [b for b in bridges if b not in filtering]
        untagged += [
            p
            for p in ports
            if p in with_address
            and p not in bridges
            and p not in in_bridge
            and p not in wan
            and p not in vlan_ifaces
            and ports[p].role is not PortRole.TUNNEL  # its address is no network of the site
        ]
        for net in untagged:
            seg = f"{site}/segment/{net}" if native_taken else self._seg(None)
            native_taken = True
            l3[net] = seg
            join(seg, None, None, None)
            label(seg, _text(bridges.get(net, {}).get("comment")))
            if net in ports and net not in bridges:
                join(seg, None, net, Membership.UNTAGGED)
            for row in bridge_ports:
                if _text(row.get("bridge")) == net:
                    p = _text(row.get("interface"))
                    port_segment[p] = seg
                    join(seg, None, p, Membership.UNTAGGED)

        # VLAN interfaces: the router's own address in a VLAN.
        for vname, row in vlan_ifaces.items():
            tag, parent = _int(row.get("vlan-id")), _text(row.get("interface"))
            if tag is None or not 1 <= tag <= 4094 or parent in wan:
                continue
            seg = self._seg(tag)
            l3[vname] = seg
            join(seg, tag, None if parent in filtering else parent, Membership.TAGGED)
            # the name RouterOS gives a new VLAN interface is not a name of the network
            label(seg, _text(row.get("comment")) or ("" if vname == f"vlan{tag}" else vname))

        segments = {
            seg: Segment(
                id=seg,
                site_id=site,
                vlan=vids[seg] if vids[seg] is not None and vids[seg] != 1 else None,
                name=names.get(seg),
                members=[PortMembership(port_id=p, mode=m) for p, m in sorted(mem.items())],
            )
            for seg, mem in sorted(members.items())
        }
        return _Layout(
            ports=ports,
            segments=segments,
            l3=l3,
            addresses=addresses,
            wan=wan,
            port_segment=port_segment,
            filtering=filtering,
            own_macs={p.mac for p in ports.values() if p.mac},
        )

    async def read_interfaces(self) -> Observation:
        layout = await self._layout()
        dev = self.context.device_id
        gateway = self.context.role is DeviceRole.GATEWAY
        subnets = [
            Subnet(
                id=object_id(dev, "subnet", f"{name}-{a.ip}"),
                segment_id=layout.l3[name],
                interface=a,
                device_id=dev,
                gateway=gateway,
            )
            for name, a in layout.addresses
            if name in layout.l3
        ]
        return Observation(
            ports=list(layout.ports.values()),
            segments=list(layout.segments.values()),
            subnets=subnets,
            uplinks=await self._uplinks(layout),
            services=await self._services(layout),
        )

    async def _services(self, layout: _Layout) -> list[ManagementService]:
        """Management services (#173): ``/ip/service`` plus MAC server, RoMON, SNMP. Empty
        when ``/ip/service`` cannot be read (not read); a menu the user may not read only
        leaves out its own services."""
        dev = self.context.device_id
        try:
            rows = await self._rows(IP_SERVICE)
        except AdapterError:
            return []
        ssh = await self._optional_object(IP_SSH)
        out: list[ManagementService] = []
        for row in rows:
            name = _text(row.get("name"))
            kind = _IP_SERVICES.get(name)
            # dynamic rows are open connections and the resolver, not services (CHR 7.25.1)
            if kind is None or _flag(row.get("dynamic")):
                continue
            allowed: list[IPNetwork] = []
            for part in _text(row.get("available-from") or row.get("address")).split(","):
                with contextlib.suppress(ValueError):
                    allowed.append(ip_network(part.strip(), strict=False))
            values: dict[str, Any] = {}
            if kind is ServiceKind.SSH:
                # RouterOS 7.25.1: yes, no, or yes-if-no-key (a password only while the user
                # has no key: neither); older versions: always-allow-password-login
                auth = _text(ssh.get("password-authentication")).lower()
                if auth in ("yes", "no"):
                    values["password_login"] = auth == "yes"
                elif _flag(ssh.get("always-allow-password-login")):
                    values["password_login"] = True
            out.append(
                ManagementService(
                    id=object_id(dev, "service", name),
                    device_id=dev,
                    kind=kind,
                    name=name,
                    enabled=not _flag(row.get("disabled")),
                    port=_int(row.get("port")) or SERVICE_PORTS.get(kind),
                    allowed_from=allowed,
                    **values,
                )
            )
        members: dict[str, list[str]] = {}
        for m in await self._optional_rows(LIST_MEMBER):
            members.setdefault(_text(m.get("list")), []).append(_text(m.get("interface")))
        for menu, kind, key in (
            (MAC_SERVER, ServiceKind.MAC_TELNET, "mac-telnet"),
            (MAC_WINBOX, ServiceKind.MAC_WINBOX, "mac-winbox"),
        ):
            conf = await self._optional_object(menu)
            if not conf:
                continue
            wanted = _text(conf.get("allowed-interface-list")) or "all"
            ports = [] if wanted in ("all", "none") else members.get(wanted, [])
            out.append(
                ManagementService(
                    id=object_id(dev, "service", key),
                    device_id=dev,
                    kind=kind,
                    name=key,
                    enabled=wanted != "none",
                    interfaces=[p for n in ports if (p := layout.port(n))],
                )
            )
        romon = await self._optional_object(ROMON)
        if romon:
            out.append(
                ManagementService(
                    id=object_id(dev, "service", "romon"),
                    device_id=dev,
                    kind=ServiceKind.ROMON,
                    name="romon",
                    enabled=_flag(romon.get("enabled")),
                )
            )
        upnp = await self._optional_object(UPNP)
        if upnp:
            out.append(
                ManagementService(
                    id=object_id(dev, "service", "upnp"),
                    device_id=dev,
                    kind=ServiceKind.UPNP,
                    name="upnp",
                    enabled=_flag(upnp.get("enabled")),
                )
            )
        snmp = await self._snmp()
        if snmp is not None:
            out.append(snmp)
        return out

    async def _optional_object(self, endpoint: str) -> dict[str, Any]:
        """A single-value menu that may be missing or refused: empty then."""
        try:
            return _object(await self._get(endpoint), endpoint)
        except AdapterError:
            return {}

    async def _snmp(self) -> ManagementService | None:
        """``/snmp`` with its communities. Names are only compared with ``public``, never kept."""
        conf = await self._optional_object(SNMP)
        if not conf:
            return None
        try:
            rows = await self._rows(SNMP_COMMUNITY)
        except AdapterError:
            rows = []
        versions: set[SnmpVersion] = set()
        v3_plain = False
        for r in rows:
            # security: none (v1/v2c), authorized (authNoPriv) or private (authPriv); the
            # protocol fields are filled whatever the level (DES on the CHR's "public")
            security = _text(r.get("security"))
            if security in ("", "none"):
                versions.add(SnmpVersion.V2C)
            else:
                versions.add(SnmpVersion.V3)
                v3_plain |= security != "private"
        settings = SnmpSettings(
            versions=sorted(versions),
            default_community=any(_text(r.get("name")).lower() == "public" for r in rows),
            v3_privacy=(not v3_plain) if SnmpVersion.V3 in versions else None,
            write_access=any(_flag(r.get("write-access")) for r in rows),
        )
        dev = self.context.device_id
        return ManagementService(
            id=object_id(dev, "service", "snmp"),
            device_id=dev,
            kind=ServiceKind.SNMP,
            name="snmp",
            enabled=_flag(conf.get("enabled")),
            port=SERVICE_PORTS[ServiceKind.SNMP],
            snmp=settings,
        )

    async def _monitor(self, name: str) -> dict[str, Any]:
        """``/interface/pppoe-client/monitor <name> once``; empty when RouterOS refuses it."""
        try:
            answer = await self.http.post_json(PPPOE_MONITOR, {"numbers": name, "once": ""})
        except AdapterError:
            return {}
        if isinstance(answer, list):
            answer = answer[0] if answer else {}
        return answer if isinstance(answer, dict) else {}

    async def _uplinks(self, layout: _Layout) -> list[Uplink]:
        """Members of the interface list ``WAN``, with their DHCP or PPPoE client (#148)."""
        if not layout.wan:
            return []
        dev = self.context.device_id
        types = {_text(r.get("name")): _text(r.get("type")) for r in await self._rows(INTERFACE)}
        dhcp = {
            _text(r.get("interface")): r
            for r in await self._optional_rows(DHCP_CLIENT)
            if _active(r)
        }
        dhcp6 = {
            _text(r.get("interface")): r
            for r in await self._optional_rows(IPV6_DHCP_CLIENT)
            if _active(r)
        }
        pppoe = {
            _text(r.get("name")): r for r in await self._optional_rows(PPPOE_CLIENT) if _active(r)
        }
        # the port under a PPPoE client of the WAN list is not an uplink of its own
        carriers = {_text(r.get("interface")) for n, r in pppoe.items() if n in layout.wan}
        now = datetime.now(UTC).replace(microsecond=0)
        out: list[Uplink] = []
        for name in sorted(layout.wan):
            if name in carriers and name not in dhcp:
                continue
            own = [a for n, a in layout.addresses if n == name]
            since: datetime | None = None
            gateway: IPAddress | None = None
            dns: list[IPAddress] = []
            extra: dict[str, JsonValue] = {}
            port = layout.port(name)
            if name in pppoe:
                kind = UplinkKind.PPPOE
                carrier = _text(pppoe[name].get("interface"))
                port = layout.port(carrier) or port
                monitor = await self._monitor(name)
                status = _text(monitor.get("status"))
                up = status == "connected" if status else _flag(pppoe[name].get("running"))
                uptime = duration(monitor.get("uptime"))
                if up and uptime is not None:
                    since = now - timedelta(seconds=uptime)
                gateway = _addr(monitor.get("remote-address"))
                local = _addr(monitor.get("local-address"))
                if isinstance(local, IPv4Address) and all(a.ip != local for a in own):
                    own.append(IPv4Interface(local))
                extra = _extra(monitor, "status", "service-name", "ac-name", "mtu")
            elif name in dhcp:
                row = dhcp[name]
                kind = UplinkKind.DHCP
                status = _text(row.get("status"))
                up = status == "bound"
                try:
                    lease = ip_interface(_text(row.get("address")))
                except ValueError:
                    lease = None
                if lease is not None and lease not in own:
                    own.insert(0, lease)
                gateway = _addr(row.get("gateway"))
                dns = [
                    a
                    for a in (_addr(row.get(k)) for k in ("primary-dns", "secondary-dns"))
                    if a is not None
                ]
                extra = {"status": status} if status else {}
            else:
                kind = UplinkKind.LTE if types.get(name) == "lte" else UplinkKind.STATIC
                if kind is UplinkKind.STATIC and not own:
                    kind = UplinkKind.OTHER
                running = layout.ports.get(name)
                up = bool(own) and (running.up is not False if running else True)
            prefixes: list[IPv6Network] = []
            v6 = dhcp6.get(name)
            if v6 is not None:
                net = _prefix(v6.get("prefix"))
                if net is not None:
                    prefixes.append(net)
            out.append(
                Uplink(
                    id=object_id(dev, "uplink", name),
                    device_id=dev,
                    port_id=port,
                    name=name,
                    kind=kind,
                    up=up,
                    since=since,
                    addresses=own,
                    delegated_prefixes=prefixes,
                    upstream_gateway=gateway,
                    dns_servers=_unique(dns),
                    vendor_extra=extra,
                )
            )
        return await self._public_address(out)

    async def _public_address(self, uplinks: list[Uplink]) -> list[Uplink]:
        """``/ip/cloud`` ``public-address`` on the first connected uplink, if not its own."""
        try:
            cloud = _object(await self._get(CLOUD), CLOUD)
        except AdapterError:
            return uplinks
        public = _addr(cloud.get("public-address"))
        if not isinstance(public, IPv4Address) or address_nat_class(public) is not NatClass.PUBLIC:
            return uplinks
        for i, uplink in enumerate(uplinks):
            if uplink.up:
                if all(a.ip != public for a in uplink.ipv4()):
                    uplinks[i] = uplink.model_copy(update={"public_ipv4": public})
                break
        return uplinks

    # --- DHCP ---------------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        layout = await self._layout()
        dev = self.context.device_id
        networks = []
        for row in await self._rows(DHCP_NETWORK):
            try:
                networks.append((ip_network(_text(row.get("address")), strict=False), row))
            except ValueError:
                continue
        pools = {_text(r.get("name")): r for r in await self._rows(POOL)}
        leases = await self._rows(DHCP_LEASE)
        options = {_text(r.get("name")): r for r in await self._optional_rows(DHCP_OPTION)}
        now = datetime.now(UTC)
        servers: list[DhcpServer] = []
        for row in await self._rows(DHCP_SERVER):
            sname, iface = _text(row.get("name")), _text(row.get("interface"))
            seg = layout.l3.get(iface)
            if not sname or seg is None:
                continue  # a server on an interface we do not know (or the WAN)
            own = [a for n, a in layout.addresses if n == iface and isinstance(a, IPv4Interface)]
            net_row: dict[str, Any] = {}
            net = None
            for candidate, nrow in networks:  # the most specific network of the server
                if any(a.ip in candidate for a in own) and (
                    net is None or candidate.prefixlen > net.prefixlen
                ):
                    net, net_row = candidate, nrow
            ranges, seen_pools = [], set()
            pool_name = _text(row.get("address-pool"))
            while pool_name and pool_name in pools and pool_name not in seen_pools:
                seen_pools.add(pool_name)  # follow next-pool, once each
                ranges += [p for t in _names(pools[pool_name].get("ranges")) if (p := _pool(t))]
                pool_name = _text(pools[pool_name].get("next-pool"))
            reservations = []
            for lease in leases:
                if _flag(lease.get("dynamic")) or _flag(lease.get("disabled")):
                    continue
                mac, address = _mac(lease.get("mac-address")), _addr(lease.get("address"))
                server = _text(lease.get("server"))
                if mac is None or address is None:
                    continue
                if server == sname or (server in ("", "all") and net and address in net):
                    hostname = _text(lease.get("comment")) or _text(lease.get("host-name"))
                    reservations.append(
                        Reservation(mac=mac, address=address, hostname=hostname or None)
                    )
            router = _addrs(net_row.get("gateway"))
            table = [
                x
                for lease in leases
                if not _flag(lease.get("disabled"))
                and (
                    _text(lease.get("server")) == sname or _text(lease.get("server")) in ("", "all")
                )
                and (x := _lease(lease, now)) is not None
                and (_text(lease.get("server")) == sname or (net is not None and x.address in net))
            ]
            search, routes, boot_name, boot_file, extra = [], [], "", "", []
            named = _names(net_row.get("dhcp-option")) + _names(row.get("dhcp-option"))
            for oname in named:
                opt = options.get(oname)
                code = _int(opt.get("code")) if opt else None
                if opt is None or code is None:
                    continue
                value, raw = _text(opt.get("value")), _wire(opt.get("value"))
                if code == 119 and raw is not None:
                    search += _search_list(raw)
                elif code == 121 and raw is not None:
                    routes += _classless_routes(raw)
                elif code == 66:
                    boot_name = value.strip("'\"")
                elif code == 67:
                    boot_file = value.strip("'\"")
                elif code not in TYPED_OPTION_CODES and 1 <= code <= 254:
                    extra.append(DhcpOption(code=code, name=oname, value=value))
            next_server = _addr(net_row.get("next-server"))
            boot_file = boot_file or _text(net_row.get("boot-file-name"))
            authoritative = _text(row.get("authoritative"))
            servers.append(
                DhcpServer(
                    id=object_id(dev, "dhcp", sname),
                    device_id=dev,
                    segment_id=seg,
                    enabled=_active(row),
                    pools=ranges,
                    lease_seconds=duration(row.get("lease-time")),
                    router=router[0] if router else None,
                    dns_servers=_addrs(net_row.get("dns-server")),
                    domain=_text(net_row.get("domain")) or None,
                    reservations=reservations,
                    ntp_servers=_addrs(net_row.get("ntp-server")),
                    leases=table,
                    search_domains=search,
                    static_routes=routes,
                    boot=DhcpBoot(
                        next_server=next_server,
                        server_name=boot_name or None,
                        filename=boot_file or None,
                    )
                    if next_server or boot_name or boot_file
                    else None,
                    options=extra,
                    authoritative=authoritative != "no" if authoritative else None,
                    vendor_extra=_extra(row, "interface", "address-pool")
                    | ({"network": str(net)} if net else {}),
                )
            )
        return Observation(dhcp_servers=servers, dhcp_relays=await self._relays(layout))

    async def _relays(self, layout: Any) -> list[DhcpRelay]:
        """``/ip/dhcp-relay``: ``interface``, ``dhcp-server`` (comma list), ``disabled``."""
        dev = self.context.device_id
        relays: list[DhcpRelay] = []
        for row in await self._optional_rows(DHCP_RELAY):
            seg = layout.l3.get(_text(row.get("interface")))
            key = _segment_key(seg) if seg else ""
            if not seg or any(r.id.endswith(f"/{key}") for r in relays):
                continue
            relays.append(
                DhcpRelay(
                    id=object_id(dev, "dhcp-relay", key),
                    device_id=dev,
                    segment_id=seg,
                    servers=_addrs(row.get("dhcp-server")),
                    enabled=_active(row),
                )
            )
        return relays

    # --- DNS ----------------------------------------------------------------------------------

    async def read_dns(self) -> Observation:
        layout = await self._layout()
        dns = _object(await self._get(DNS), DNS)
        records = []
        for row in await self._rows(DNS_STATIC):
            kind = _text(row.get("type")).upper() or "A"
            host, address = _text(row.get("name")), _addr(row.get("address"))
            if not _active(row) or kind not in ("A", "AAAA") or not host or address is None:
                continue
            records.append(HostRecord(name=host, address=address))
        remote = _flag(dns.get("allow-remote-requests"))
        listen = _unique(a.ip for n, a in layout.addresses if n in layout.l3) if remote else []
        return Observation(
            dns_services=[
                DnsService(
                    id=object_id(self.context.device_id, "dns", "dns"),
                    device_id=self.context.device_id,
                    enabled=remote,
                    listen=listen,
                    name="dns",
                    forwarders=[
                        DnsForwarder(address=a) for a in _unique(_addrs(dns.get("servers")))
                    ],
                    host_records=records,
                    vendor_extra=_extra(dns, "dynamic-servers", "cache-size"),
                )
            ]
        )

    # --- wireless -----------------------------------------------------------------------------

    async def _wifi_rows(self) -> tuple[str, list[dict[str, Any]]]:
        """("wifi", rows) for RouterOS 7 Wi-Fi, ("wireless", rows) for the legacy package."""
        try:
            return "wifi", await self._rows(WIFI)
        except NotFound:
            pass
        try:
            return "wireless", await self._rows(WIRELESS)
        except NotFound:
            raise AdapterError(
                f"no wireless package: neither {WIFI} nor {WIRELESS} exists on this device"
            ) from None

    async def read_wireless(self) -> Observation:
        layout = await self._layout()
        kind, rows = await self._wifi_rows()
        if kind == "wifi":
            return await self._wifi(layout, rows)
        return await self._wireless(layout, rows)

    def _wlan_segment(self, layout: _Layout, name: str, vid: int | None) -> str | None:
        if name in layout.port_segment:
            return layout.port_segment[name]
        return self._seg(vid) if vid is not None and 1 <= vid <= 4094 else None

    async def _wifi(self, layout: _Layout, rows: list[dict[str, Any]]) -> Observation:
        dev = self.context.device_id
        profiles = {
            section: {_text(r.get("name")): r for r in await self._optional_rows(endpoint)}
            for section, endpoint in _WIFI_PROFILES.items()
        }

        def prop(row: dict[str, Any], section: str, key: str) -> Any:
            inline = row.get(f"{section}.{key}")
            if inline not in (None, ""):
                return inline
            return profiles[section].get(_text(row.get(section)), {}).get(key)

        by_name = {_text(r.get("name")): r for r in rows if _text(r.get("name"))}
        radios: dict[str, Radio] = {}
        for name, row in by_name.items():
            if _text(row.get("master-interface")):
                continue
            freqs = _names(prop(row, "channel", "frequency"))
            freq = _int(freqs[0]) if freqs else None
            fc = frequency_channel(freq) if freq else None
            band = band_of(prop(row, "channel", "band")) or (fc[0] if fc else None)
            if band is None:
                continue
            radios[name] = Radio(
                id=object_id(dev, "radio", name),
                device_id=dev,
                name=name,
                band=band,
                channel=fc[1] if fc else None,
                width_mhz=width_of(prop(row, "channel", "width")),
                tx_power_dbm=_int(prop(row, "configuration", "tx-power")),
                country=_text(prop(row, "configuration", "country")) or None,
                enabled=_active(row),
                supported_security=list(_WIFI_MODES),
                vendor_extra={
                    k: _text(v)
                    for k in ("band", "frequency", "width")
                    if _text(v := prop(row, "channel", k))
                },
            )
        wlans = []
        for name, row in by_name.items():
            master = _text(row.get("master-interface")) or name
            radio = radios.get(master)
            ssid = _text(prop(row, "configuration", "ssid"))
            mode = _text(prop(row, "configuration", "mode")) or "ap"
            if radio is None or not ssid or mode not in _AP_MODES:
                continue
            sec = security_of(prop(row, "security", "authentication-types"))
            passphrase = _text(prop(row, "security", "passphrase"))
            pmf = _PMF.get(_text(prop(row, "security", "management-protection")))
            personal = bool(passphrase) and sec in _PERSONAL
            threshold = _int(prop(row, "security", "sae-anti-clogging-threshold"))
            rekey = duration(prop(row, "security", "group-key-update"))
            wlans.append(
                Wlan(
                    id=object_id(dev, "wlan", name),
                    device_id=dev,
                    ssid=ssid,
                    radio_id=radio.id,
                    port_id=layout.port(name),
                    enabled=radio.enabled and _active(row),
                    security=sec,
                    pmf=pmf,
                    passphrase_fingerprint=(
                        passphrase_fingerprint(ssid, passphrase) if personal else None
                    ),
                    passphrase_digest=passphrase_digest(passphrase) if personal else None,
                    ciphers=ciphers_of(prop(row, "security", "encryption"), sec),
                    group_cipher=cipher_of(prop(row, "security", "group-encryption"), sec),
                    sae=SaeSettings(
                        pwe=_SAE_PWE.get(_text(prop(row, "security", "sae-pwe"))),
                        anti_clogging_threshold=threshold,
                    )
                    if sec in _SAE
                    else None,
                    wps=wps_of(prop(row, "security", "wps")) if sec in _PERSONAL else None,
                    key_rotation_seconds=rekey if sec is not Security.OPEN else None,
                    segment_id=self._wlan_segment(
                        layout, name, _int(prop(row, "datapath", "vlan-id"))
                    ),
                    hidden=_flag(prop(row, "configuration", "hide-ssid")),
                    roaming_80211r=_maybe(prop(row, "security", "ft")),
                    roaming_80211k=_maybe(prop(row, "steering", "rrm")),
                    roaming_80211v=_maybe(prop(row, "steering", "wnm")),
                    vendor_extra={
                        "authentication-types": _text(prop(row, "security", "authentication-types"))
                    },
                )
            )
        return Observation(radios=list(radios.values()), wlans=wlans)

    async def _wireless(self, layout: _Layout, rows: list[dict[str, Any]]) -> Observation:
        dev = self.context.device_id
        profiles = {_text(r.get("name")): r for r in await self._optional_rows(WIRELESS_SECURITY)}
        radios: dict[str, Radio] = {}
        for row in rows:
            name = _text(row.get("name"))
            if not name or _text(row.get("master-interface")):
                continue
            freq = _int(row.get("frequency"))
            fc = frequency_channel(freq) if freq else None
            band = band_of(row.get("band")) or (fc[0] if fc else None)
            if band is None:
                continue
            radios[name] = Radio(
                id=object_id(dev, "radio", name),
                device_id=dev,
                name=name,
                band=band,
                channel=fc[1] if fc else None,
                width_mhz=width_of(row.get("channel-width")),
                tx_power_dbm=_int(row.get("tx-power")),
                country=_text(row.get("country")) or None,
                enabled=_active(row),
                supported_security=list(_WIRELESS_MODES),
                vendor_extra=_extra(row, "band", "frequency", "channel-width"),
            )
        wlans = []
        for row in rows:
            name = _text(row.get("name"))
            radio = radios.get(_text(row.get("master-interface")) or name)
            ssid = _text(row.get("ssid"))
            if radio is None or not ssid or _text(row.get("mode")) not in _AP_MODES:
                continue
            profile = profiles.get(_text(row.get("security-profile")) or "default", {})
            sec = security_of(profile.get("authentication-types"), profile.get("mode"))
            psk = _text(profile.get("wpa2-pre-shared-key")) or _text(
                profile.get("wpa-pre-shared-key")
            )
            vid = _int(row.get("vlan-id")) if _text(row.get("vlan-mode")) == "use-tag" else None
            personal = bool(psk) and sec in _PERSONAL
            rekey = duration(profile.get("group-key-update"))
            wlans.append(
                Wlan(
                    id=object_id(dev, "wlan", name),
                    device_id=dev,
                    ssid=ssid,
                    radio_id=radio.id,
                    port_id=layout.port(name),
                    enabled=radio.enabled and _active(row),
                    security=sec,
                    pmf=_PMF.get(_text(profile.get("management-protection"))),
                    passphrase_fingerprint=passphrase_fingerprint(ssid, psk) if personal else None,
                    passphrase_digest=passphrase_digest(psk) if personal else None,
                    ciphers=ciphers_of(profile.get("unicast-ciphers"), sec),
                    group_cipher=cipher_of(profile.get("group-ciphers"), sec),
                    wps=wps_of(row.get("wps-mode")) if sec in _PERSONAL else None,
                    key_rotation_seconds=rekey if sec is not Security.OPEN else None,
                    segment_id=self._wlan_segment(layout, name, vid),
                    hidden=_flag(row.get("hide-ssid")),
                    vendor_extra=_extra(row, "mode", "security-profile"),
                )
            )
        return Observation(radios=list(radios.values()), wlans=wlans)

    # --- clients ------------------------------------------------------------------------------

    async def read_clients(self) -> Observation:
        layout = await self._layout()
        dev = self.context.device_id
        own = set(layout.own_macs)
        servers = {
            _text(r.get("name")): _text(r.get("interface"))
            for r in await self._rows(DHCP_SERVER)
            if _text(r.get("name"))
        }
        seen: dict[str, dict[str, Any]] = {}

        def add(
            mac: str | None, address: Any = None, source: AddressSource | None = None, **info: Any
        ) -> None:
            if mac is None or mac in own:
                return
            entry = seen.setdefault(
                mac,
                {"addresses": [], "hostname": None, "segment": None, "seen_on": None, "src": {}},
            )
            addr = _addr(address)
            if addr is not None and not addr.is_link_local and addr not in entry["addresses"]:
                entry["addresses"].append(addr)
            if addr is not None and addr in entry["addresses"] and source is not None:
                entry["src"][addr] = source
            for key, value in info.items():
                entry[key] = entry[key] or value or None

        for row in await self._rows(BRIDGE_HOST):
            if _flag(row.get("local")):
                own.add(_mac(row.get("mac-address")) or "")
        for endpoint, required in ((ARP, True), (IPV6_NEIGHBOR, False)):
            rows = await (self._rows(endpoint) if required else self._optional_rows(endpoint))
            for row in rows:
                iface = _text(row.get("interface"))
                status = _text(row.get("status"))
                if iface in layout.wan or status in ("failed", "incomplete", "noarp"):
                    continue  # the uplink's neighbours are not clients of this network
                add(_mac(row.get("mac-address")), row.get("address"), segment=layout.l3.get(iface))
        for row in await self._rows(DHCP_LEASE):
            if _text(row.get("status")) != "bound" or _flag(row.get("disabled")):
                continue  # dynamic leases and static ones in use
            iface = servers.get(_text(row.get("server")), "")
            static = not _flag(row.get("dynamic"))
            add(
                _mac(row.get("active-mac-address") or row.get("mac-address")),
                row.get("active-address") or row.get("address"),
                AddressSource.DHCP_RESERVED if static else AddressSource.DHCP,
                hostname=_text(row.get("host-name")),
                segment=layout.l3.get(iface),
            )
        for row in await self._rows(BRIDGE_HOST):
            if _flag(row.get("local")):
                continue
            on = _text(row.get("on-interface")) or _text(row.get("interface"))
            vid = _int(row.get("vid"))
            bridge = _text(row.get("bridge"))
            seg = self._seg(vid) if bridge in layout.filtering and vid else None
            add(_mac(row.get("mac-address")), seen_on=layout.port(on), segment=seg)
        for endpoint in (WIFI_REGISTRATION, WIRELESS_REGISTRATION):
            for row in await self._optional_rows(endpoint):
                iface = _text(row.get("interface"))
                mac = _mac(row.get("mac-address"))
                if mac is not None and mac not in own and iface:
                    add(mac, segment=layout.port_segment.get(iface))
                    seen[mac]["seen_on"] = object_id(dev, "wlan", iface)

        for entry in seen.values():  # nothing said where: by address
            if entry["segment"] is None:
                entry["segment"] = next(
                    (s for a in entry["addresses"] if (s := layout.containing(a))), None
                )
        clients = [
            Client(
                id=object_id(dev, "client", mac),
                mac=mac,
                addresses=sorted(e["addresses"], key=_sort_key),
                hostname=e["hostname"],
                segment_id=e["segment"],
                seen_on=e["seen_on"],
                address_sources=e["src"],
            )
            for mac, e in sorted(seen.items())
        ]
        return Observation(clients=clients)

    # --- neighbours ---------------------------------------------------------------------------

    async def read_neighbours(self) -> Observation:
        layout = await self._layout()
        dev = self.context.device_id
        neighbours: dict[str, Neighbour] = {}
        for row in await self._rows(NEIGHBOR):
            local = next((p for p in _names(row.get("interface")) if p in layout.ports), None)
            mac = _mac(row.get("mac-address"))
            if local is None or mac is None:
                continue
            nid = object_id(dev, "neighbour", f"{local}-{mac}")
            neighbours[nid] = Neighbour(
                id=nid,
                local_port_id=layout.ports[local].id,
                chassis_id=mac,
                remote_port=_text(row.get("interface-name")) or None,
                system_name=_text(row.get("identity")) or None,
                management_address=(
                    _text(row.get("address4")) or _text(row.get("address")) or None
                ),
                vendor_extra=_extra(row, "platform", "board", "version", "discovered-by"),
            )
        return Observation(neighbours=list(neighbours.values()))

    # --- health and time ----------------------------------------------------------------------

    async def read_health(self) -> Observation:
        resource = _object(await self._get(RESOURCE), RESOURCE)
        try:
            sensors = health_rows(await self._get(HEALTH))
        except NotFound:  # a device without the menu: no sensors
            sensors = []
        value = health_of(resource, sensors)
        return Observation(health={self.context.device_id: value})

    async def read_vpn(self) -> Observation:
        """WireGuard interfaces and peers (#152): ``/interface/wireguard`` and ``.../peers``.

        Both menus return keys: ``private-key`` of an interface (and, from 7.15, of a peer's
        client configuration) and a peer's ``preshared-key``. They are dropped while the answer
        is parsed (:func:`wireguard_rows`), before it is kept or looked at; the pre-shared key
        stays as the flag ``preshared-key-set``. A menu is read without the cache so that the
        keys are not kept in it."""
        d = self.context.device_id
        try:
            interfaces = wireguard_rows(await get_menu(self.http, WIREGUARD), WIREGUARD)
        except NotFound:  # no wireguard package / RouterOS 6
            return Observation(tunnels=[])
        peers = wireguard_rows(await get_menu(self.http, WIREGUARD_PEERS), WIREGUARD_PEERS)
        addresses: dict[str, list[IPInterface]] = {}
        for endpoint in (IP_ADDRESS, IPV6_ADDRESS):
            for row in await self._optional_rows(endpoint):
                try:
                    a = ip_interface(_text(row.get("address")).split("%")[0])
                except ValueError:
                    continue
                if _active(row) and not a.ip.is_link_local and not a.ip.is_loopback:
                    iface = _text(row.get("actual-interface")) or _text(row.get("interface"))
                    addresses.setdefault(iface, []).append(a)
        known = {_text(r.get("name")) for r in await self._rows(INTERFACE)}
        now = datetime.now(UTC)
        tunnels = []
        for row in interfaces:
            name = _text(row.get("name"))
            if not name:
                continue
            listen = _int(row.get("listen-port"))
            mtu = _int(row.get("mtu"))
            disabled = _flag(row.get("disabled"))
            tunnels.append(
                Tunnel(
                    id=object_id(d, "tunnel", name),
                    device_id=d,
                    name=name,
                    description=_text(row.get("comment")) or None,
                    port_id=port_id(d, name) if name in known else None,
                    up=False if disabled else _maybe(row.get("running")),
                    enabled=not disabled,
                    listen_port=listen if listen and 1 <= listen <= 65535 else None,
                    public_key=_wg_key(row.get("public-key")),
                    addresses=addresses.get(name, []),
                    mtu=mtu if mtu is not None and 68 <= mtu <= 65535 else None,
                    peers=wireguard_peers(
                        [p for p in peers if _text(p.get("interface")) == name], now
                    ),
                )
            )
        return Observation(tunnels=tunnels)

    async def read_time(self) -> Observation:
        start = datetime.now(UTC)
        clock = _object(await get_menu(self.http, CLOCK), CLOCK)
        end = datetime.now(UTC)
        client = server = None
        with contextlib.suppress(NotFound):
            client = _object(await self._get(NTP_CLIENT), NTP_CLIENT)
        with contextlib.suppress(NotFound):
            server = _object(await self._get(NTP_SERVER), NTP_SERVER)
        value = time_of(clock, client, server, start, end)
        return Observation(time={self.context.device_id: value})


def _wg_key(value: Any) -> str | None:
    text = _text(value)
    return text if re.fullmatch(WIREGUARD_KEY, text) else None


def wireguard_rows(data: Any, endpoint: str) -> list[dict[str, Any]]:
    """Rows of a WireGuard menu without private and pre-shared keys (#152): ``private-key`` is
    deleted, ``preshared-key`` becomes ``preshared-key-set`` (a flag). RouterOS says ``auto``
    or nothing for a key that is not set; anything else counts as set."""
    out = []
    for row in _rows(data, endpoint):
        clean = {k: v for k, v in row.items() if k not in ("private-key", "preshared-key")}
        psk = _text(row.get("preshared-key"))
        clean["preshared-key-set"] = psk not in ("", "none", "auto")
        out.append(clean)
    return out


def wireguard_peers(rows: list[dict[str, Any]], now: datetime) -> list[TunnelPeer]:
    """Peers of one interface from :func:`wireguard_rows`. The name is the ``comment``, else
    ``name`` (RouterOS numbers peers ``peer1``, ...); ``last-handshake`` is how long ago, absent
    or empty before the first one; ``current-endpoint-*`` is where the peer was seen."""
    out: dict[str, TunnelPeer] = {}
    for row in rows:
        key = _wg_key(row.get("public-key"))
        if key is None or key in out:
            continue
        host = _text(row.get("endpoint-address")) or _text(row.get("current-endpoint-address"))
        port = (
            _int(row.get("endpoint-port"))
            if _text(row.get("endpoint-address"))
            else _int(row.get("current-endpoint-port"))
        )
        ago = duration(row.get("last-handshake"))
        allowed: list[IPNetwork] = []
        for part in _names(row.get("allowed-address")):
            with contextlib.suppress(ValueError):
                allowed.append(ip_network(part, strict=False))
        keepalive = duration(row.get("persistent-keepalive"))
        rx, tx = _int(row.get("rx")), _int(row.get("tx"))
        out[key] = TunnelPeer(
            public_key=key,
            name=_text(row.get("comment")) or _text(row.get("name")) or None,
            endpoint_host=host or None,
            endpoint_port=port if host and port and 1 <= port <= 65535 else None,
            allowed_ips=allowed,
            latest_handshake=now - timedelta(seconds=ago) if ago is not None else None,
            rx_bytes=rx if rx is not None and rx >= 0 else None,
            tx_bytes=tx if tx is not None and tx >= 0 else None,
            keepalive_seconds=keepalive if keepalive is not None and keepalive <= 65535 else 0,
            preshared_key=bool(row.get("preshared-key-set")),
            enabled=not _flag(row.get("disabled")),
        )
    return list(out.values())


def _sort_key(address: IPAddress) -> tuple[int, int]:
    return (address.version, int(address))


def _unique(addresses: Iterable[IPAddress]) -> list[IPAddress]:
    out: list[IPAddress] = []
    for a in addresses:
        if a not in out:
            out.append(a)
    return out


# --- health and time parsing ------------------------------------------------------------------


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    match = re.match(r"-?\d+(?:\.\d+)?", _text(value))
    return float(match.group()) if match else None


def health_rows(data: Any, endpoint: str = HEALTH) -> list[dict[str, Any]]:
    """``/system/health``: RouterOS 7 answers rows ``{name, value, type}``. The single object
    of older versions (``{"temperature": "45", "voltage": "24.1"}``) is turned into such rows;
    CHR 7.25.1 answers ``{"state": "disabled", "state-after-reboot": "enabled"}`` (no sensors),
    rows without a number, which are skipped."""
    if isinstance(data, dict):
        return [{"name": k, "value": v} for k, v in data.items() if not k.startswith(".")]
    return _rows(data, endpoint)


_FAN = re.compile(r"(fan\d*)-speed")
_FAN_STATE = re.compile(r"(fan\d*)-state")
_PSU_STATE = re.compile(r"(psu\d*)-state")


def _ok(value: Any) -> bool:
    return _text(value).lower() == "ok"


def health_of(resource: dict[str, Any], sensors: list[dict[str, Any]]) -> DeviceHealth:
    """``/system/resource`` and the ``/system/health`` rows as :class:`DeviceHealth`.

    Memory used is total minus free (RouterOS counts no page cache as used). The ``hdd`` (the
    flash of a RouterBOARD, the disk of CHR/x86) holds the configuration and the packages:
    storage of kind ``system``. Sensors: type ``C`` (or a name with ``temperature``) is a
    temperature, ``fanN-speed`` (type ``RPM``) and ``fanN-state`` a fan, ``psuN-state`` a power
    supply; ``voltage`` and ``power-consumption`` without power supply rows describe the one
    power input.
    """
    total, free = _int(resource.get("total-memory")), _int(resource.get("free-memory"))
    used = None
    if total and free is not None and 0 <= free <= total:
        used = total - free
    storage = []
    disk, disk_free = _int(resource.get("total-hdd-space")), _int(resource.get("free-hdd-space"))
    if disk:
        disk_used = None
        if disk_free is not None and 0 <= disk_free <= disk:
            disk_used = disk - disk_free
        storage.append(
            StorageUsage(
                name="hdd", kind=StorageKind.SYSTEM, total_bytes=disk, used_bytes=disk_used
            )
        )
    load = _int(resource.get("cpu-load"))
    count = _int(resource.get("cpu-count"))
    temps: list[TemperatureSensor] = []
    fans: dict[str, Fan] = {}
    psus: dict[str, PowerSupply] = {}
    power: dict[str, float] = {}
    for row in sensors:
        name, raw = _text(row.get("name")), row.get("value")
        unit = _text(row.get("type")).upper()
        number = _number(raw)
        if not name:
            continue
        if (m := _PSU_STATE.fullmatch(name)) is not None:
            psus[m.group(1)] = PowerSupply(name=m.group(1), ok=_ok(raw))
        elif (m := _FAN_STATE.fullmatch(name)) is not None:
            key = m.group(1)
            fans[key] = fans.get(key, Fan(name=key)).model_copy(update={"ok": _ok(raw)})
        elif number is None:
            continue
        elif (m := _FAN.fullmatch(name)) is not None or unit == "RPM":
            key = m.group(1) if m else name
            rpm = max(int(number), 0)
            fans[key] = fans.get(key, Fan(name=key)).model_copy(update={"rpm": rpm})
        elif unit == "C" or "temperature" in name:
            temps.append(TemperatureSensor(name=name, value_c=number))
        elif name in ("voltage", "power-consumption") and number >= 0:
            power[name] = number
    supplies = list(psus.values())
    if not supplies and power:
        supplies = [
            PowerSupply(
                name="power",
                input_voltage=power.get("voltage"),
                watts=power.get("power-consumption"),
            )
        ]
    return DeviceHealth(
        uptime_seconds=duration(resource.get("uptime")),
        cpu_load_pct=load if load is not None and 0 <= load <= 100 else None,
        cpu_count=count if count and count > 0 else None,
        memory_total_bytes=total or None,
        memory_used_bytes=used,
        storage=storage,
        temperatures=temps,
        fans=list(fans.values()),
        power_supplies=supplies,
    )


_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
_OFFSET = re.compile(r"([+-])(\d{1,2}):(\d\d)")
_CLOCK = re.compile(r"(\d\d?):(\d\d):(\d\d)")


def clock_date(value: Any) -> date | None:
    """``2026-11-22`` (RouterOS 7.10 and later) or ``nov/22/2026`` (older)."""
    text = _text(value).lower()
    try:
        if "/" in text:
            month, day, year = text.split("/")
            return date(int(year), _MONTHS.index(month) + 1, int(day))
        return date.fromisoformat(text)
    except ValueError:
        return None


def gmt_offset(value: Any) -> int | None:
    """``+01:00``, ``-05:30`` (or seconds, ``3600``) -> minutes east of UTC."""
    text = _text(value) if not isinstance(value, int) else str(value)
    if (m := _OFFSET.fullmatch(text)) is not None:
        minutes = int(m.group(2)) * 60 + int(m.group(3))
        return -minutes if m.group(1) == "-" else minutes
    if re.fullmatch(r"-?\d+", text):
        return int(text) // 60
    return None


def time_of(
    clock: dict[str, Any],
    client: dict[str, Any] | None,
    server: dict[str, Any] | None,
    start: datetime,
    end: datetime,
) -> DeviceTime:
    """``/system/clock`` (read between ``start`` and ``end``) and the NTP client and server.

    The clock has whole seconds: the device's time lies within that second, so ``clock`` is its
    middle and the uncertainty half the round trip plus half a second. ``time-zone-name``
    ``manual`` is no zone (only the offset). NTP ``status`` ``synchronized`` is in sync, any
    other status of an enabled client not (yet).
    """
    offset = gmt_offset(clock.get("gmt-offset"))
    if offset is not None and abs(offset) > 1080:
        offset = None
    day = clock_date(clock.get("date"))
    match = _CLOCK.fullmatch(_text(clock.get("time")))
    stamp = None
    if day is not None and match is not None and offset is not None:
        hh, mm, ss = (int(g) for g in match.groups())
        try:
            stamp = datetime(
                day.year, day.month, day.day, hh, mm, ss, tzinfo=timezone(timedelta(minutes=offset))
            )
        except ValueError:
            stamp = None
    half = (end - start) / 2
    zone = _text(clock.get("time-zone-name"))
    ntp_client = None
    if client is not None:
        servers = _names(client.get("servers")) or [
            s
            for key in ("primary-ntp", "secondary-ntp", "server-dns-names")
            for s in _names(client.get(key))
            if s != "0.0.0.0"
        ]
        enabled = _flag(client.get("enabled"))
        status = _text(client.get("status")).lower()
        stratum = _int(client.get("synced-stratum"))
        ntp_client = NtpClient(
            enabled=enabled,
            servers=servers,
            synchronised=(status == "synchronized") if enabled and status else None,
            stratum=stratum if stratum is not None and 0 <= stratum <= 16 else None,
            current_server=_text(client.get("synced-server")) or None,
        )
    return DeviceTime(
        clock=stamp + timedelta(seconds=0.5) if stamp else None,
        read_at=start + half if stamp else None,
        uncertainty_seconds=half.total_seconds() + 0.5 if stamp else None,
        timezone=zone if zone and zone != "manual" else None,
        utc_offset_minutes=offset,
        ntp_client=ntp_client,
        ntp_server=NtpServer(enabled=_flag(server.get("enabled"))) if server is not None else None,
    )


__all__ = ["MikrotikAdapter", "MikrotikConfig", "get_menu"]
