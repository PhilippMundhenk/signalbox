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
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
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
    Gap,
    Manifest,
    Observation,
    PreviewStep,
    Remedy,
    RemedyRequest,
    SetupPlan,
    SetupRequest,
    SetupResult,
    SystemInfo,
    TraceAnswer,
    TraceSupport,
    bonding,
    known_interfaces,
    unexpected_answer,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.mikrotik import access as _access
from signalbox.adapters.mikrotik import capsman, hotspot, multiwan, wifi_assoc
from signalbox.adapters.mikrotik import discovery as _discovery
from signalbox.adapters.mikrotik import firewall as _firewall
from signalbox.adapters.mikrotik import multicast as _multicast
from signalbox.adapters.mikrotik import poe as mikrotik_poe
from signalbox.adapters.mikrotik import routes as route_reader
from signalbox.adapters.mikrotik import stp as _stp
from signalbox.adapters.mikrotik import trace as _trace
from signalbox.adapters.mikrotik import upnp as _upnp
from signalbox.adapters.mikrotik import vpn as vpn_reader
from signalbox.adapters.mikrotik.certificates import USERS as CERT_USERS
from signalbox.adapters.mikrotik.certificates import attach_users
from signalbox.adapters.mikrotik.certificates import parse as parse_certificate
from signalbox.adapters.mikrotik.write import WRITES, MikrotikWrites
from signalbox.adapters.portcounters import counters_of
from signalbox.discovery import Candidate, HostProbe
from signalbox.factory_defaults import is_factory_default
from signalbox.lldp import protocol_of
from signalbox.model import (
    LOG_PORTS,
    SERVICE_PORTS,
    SPANNING_TREE,
    STANDARD_RANK,
    TYPED_OPTION_CODES,
    WIREGUARD_KEY,
    AccountPrivilege,
    AddressSource,
    Band,
    Blocklist,
    CaptivePortal,
    Certificate,
    CertificateUse,
    Cipher,
    Client,
    ConfigState,
    Device,
    DeviceAccount,
    DeviceHealth,
    DeviceMulticast,
    DeviceRole,
    DeviceTime,
    DeviceUpnp,
    Dhcp6Mode,
    Dhcp6PrefixPool,
    Dhcp6Server,
    DhcpBoot,
    DhcpLease,
    DhcpOption,
    DhcpPool,
    DhcpRelay,
    DhcpRoute,
    DhcpServer,
    DnsForwarder,
    DnsService,
    DnsTransport,
    DynamicDns,
    Fan,
    FastTransition,
    FdbEntry,
    FdbKind,
    Firmware,
    FirmwareChannel,
    FrameTypes,
    HostRecord,
    IPAddress,
    IPInterface,
    IPNetwork,
    LacpRate,
    LagHashPolicy,
    LagMemberState,
    LagMode,
    LeaseState,
    LocalBackups,
    LogKind,
    LogTarget,
    LogTransport,
    ManagementService,
    Membership,
    MeshLinkKind,
    MeshMembership,
    MeshPeer,
    MeshPeerRole,
    MeshRole,
    MeshUplink,
    NatClass,
    Neighbour,
    NtpClient,
    NtpServer,
    Pmf,
    Port,
    PortAccessControl,
    PortCounters,
    PortKind,
    PortMembership,
    PortPoe,
    PortRole,
    PowerSupply,
    Radio,
    RadiusServer,
    RaMode,
    RaPrefix,
    Reservation,
    RouterAdvert,
    SaePwe,
    SaeSettings,
    Security,
    Segment,
    ServerKind,
    ServerOffer,
    ServerSighting,
    ServiceKind,
    SightingSource,
    SnmpSettings,
    SnmpVersion,
    StorageKind,
    StorageUsage,
    StpBridge,
    StpPort,
    StpProtocol,
    Subnet,
    TemperatureSensor,
    Tunnel,
    TunnelPeer,
    Uplink,
    UplinkKind,
    WifiStandard,
    WirelessLinkInfo,
    Wlan,
    Wps,
    WpsMethod,
    address_nat_class,
    fdb_id,
    normalise_capabilities,
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
IDENTITY = "/rest/system/identity"
HISTORY = "/rest/system/history"
FILES = "/rest/file"
INTERFACE = "/rest/interface"
ETHERNET = "/rest/interface/ethernet"
BRIDGE = "/rest/interface/bridge"
BRIDGE_PORT = "/rest/interface/bridge/port"
BRIDGE_VLAN = "/rest/interface/bridge/vlan"
BRIDGE_HOST = "/rest/interface/bridge/host"
VLAN = "/rest/interface/vlan"
BONDING = "/rest/interface/bonding"
BONDING_MONITOR = "/rest/interface/bonding/monitor-slaves"
ETHERNET_SWITCH_PORT = "/rest/interface/ethernet/switch/port"
ETHERNET_POE = "/rest/interface/ethernet/poe"
ETHERNET_POE_MONITOR = "/rest/interface/ethernet/poe/monitor"
LIST_MEMBER = "/rest/interface/list/member"
DHCP_CLIENT = "/rest/ip/dhcp-client"
IPV6_DHCP_CLIENT = "/rest/ipv6/dhcp-client"
IPV6_ND = "/rest/ipv6/nd"
IPV6_ND_PREFIX = "/rest/ipv6/nd/prefix"
IPV6_DHCP_SERVER = "/rest/ipv6/dhcp-server"
IPV6_POOL = "/rest/ipv6/pool"
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
DHCP_ALERT = "/rest/ip/dhcp-server/alert"
POOL = "/rest/ip/pool"
DNS = "/rest/ip/dns"
DNS_STATIC = "/rest/ip/dns/static"
DNS_ADLIST = "/rest/ip/dns/adlist"
ARP = "/rest/ip/arp"
IPV6_NEIGHBOR = "/rest/ipv6/neighbor"
NEIGHBOR = "/rest/ip/neighbor"
WIFI = "/rest/interface/wifi"
WIFI_CONFIGURATION = "/rest/interface/wifi/configuration"
WIFI_SECURITY = "/rest/interface/wifi/security"
WIFI_CHANNEL = "/rest/interface/wifi/channel"
WIFI_DATAPATH = "/rest/interface/wifi/datapath"
WIFI_STEERING = "/rest/interface/wifi/steering"
#: ``configuration.mode`` (``wifi``) or ``mode`` (``wireless``) of a station that bridges a LAN
#: into the Wi-Fi, and what kind of backhaul link it is (#171)
_STATION_KINDS = {
    "station-bridge": MeshLinkKind.CLIENT_BRIDGE,
    "station-pseudobridge": MeshLinkKind.CLIENT_BRIDGE,
    "station-pseudobridge-clone": MeshLinkKind.CLIENT_BRIDGE,
    "station-wds": MeshLinkKind.WDS,
}
WIFI_REGISTRATION = "/rest/interface/wifi/registration-table"
WIFI_ACCESS_LIST = "/rest/interface/wifi/access-list"
WIFI_RADIO = "/rest/interface/wifi/radio"
WIRELESS = "/rest/interface/wireless"
WIRELESS_SECURITY = "/rest/interface/wireless/security-profiles"
WIRELESS_REGISTRATION = "/rest/interface/wireless/registration-table"
WIRELESS_WDS = "/rest/interface/wireless/wds"
HEALTH = "/rest/system/health"
CLOCK = "/rest/system/clock"
NTP_CLIENT = "/rest/system/ntp/client"
NTP_SERVER = "/rest/system/ntp/server"
IP_SERVICE = "/rest/ip/service"
CERTIFICATE = "/rest/certificate"
MAC_SERVER = "/rest/tool/mac-server"
MAC_WINBOX = "/rest/tool/mac-server/mac-winbox"
ROMON = "/rest/tool/romon"
IP_SSH = "/rest/ip/ssh"
UPNP = "/rest/ip/upnp"
SNMP = "/rest/snmp"
SNMP_COMMUNITY = "/rest/snmp/community"
#: Remote log targets, flow export (#180).
LOG_ACTION = "/rest/system/logging/action"
LOG_RULES = "/rest/system/logging"
TRAFFIC_FLOW = "/rest/ip/traffic-flow"
TRAFFIC_FLOW_TARGET = "/rest/ip/traffic-flow/target"
#: Local users, their groups' policies and SSH keys (#175); RouterOS never shows passwords.
USERS = "/rest/user"
USER_GROUPS = "/rest/user/group"
USER_SSH_KEYS = "/rest/user/ssh-keys"
#: The packet filter (#135): filter rules, NAT, raw rules, interface and address lists.
FW_FILTER = "/rest/ip/firewall/filter"
FW_FILTER6 = "/rest/ipv6/firewall/filter"
FW_NAT = "/rest/ip/firewall/nat"
FW_RAW = "/rest/ip/firewall/raw"
IPSEC_POLICY = "/rest/ip/ipsec/policy"
FW_ADDRESS_LIST = "/rest/ip/firewall/address-list"
FW_ADDRESS_LIST6 = "/rest/ipv6/firewall/address-list"
INTERFACE_LIST = "/rest/interface/list"

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


#: ``/interface`` rows (RouterOS 7.1+, the REST API's minimum) carry the traffic counters;
#: ``rx-fcs-error`` and ``tx-collision`` belong to the ethernet statistics (``/interface/ethernet``
#: with stats, RouterOS 7.x; where the REST row lacks them they stay unset: a guess, #21).
_COUNTER_KEYS = {
    "rx_bytes": ("rx-byte", "rx-bytes"),
    "tx_bytes": ("tx-byte", "tx-bytes"),
    "rx_packets": ("rx-packet", "rx-packets"),
    "tx_packets": ("tx-packet", "tx-packets"),
    "rx_errors": ("rx-error", "rx-errors"),
    "tx_errors": ("tx-error", "tx-errors"),
    "rx_crc_errors": ("rx-fcs-error",),
    "rx_drops": ("rx-drop", "rx-drops"),
    "tx_drops": ("tx-drop", "tx-drops"),
    "collisions": ("tx-collision",),
    "link_downs": ("link-downs",),
}


def _counters(row: dict[str, Any], eth: dict[str, Any]) -> PortCounters | None:
    return counters_of({**eth, **row}, _COUNTER_KEYS)


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
    return unexpected_answer(endpoint, what)


def _routeros6() -> AdapterError:
    """The device says it runs RouterOS 6.x (which has no REST API)."""
    return AdapterError(
        f"RouterOS 6 is not supported: {RESOURCE} has no REST API (RouterOS 6 answers 404 or a "
        "web page there). Signalbox needs RouterOS 7.1 or newer",
        fix="Update RouterOS to 7.1 or newer, or read the device through the generic SNMP "
        "integration.",
        fix_id="mikrotik.ros6.fix",
        message_id="mikrotik.ros6",
        params={"endpoint": RESOURCE},
    )


def _no_rest() -> AdapterError:
    """/rest answers 404 or a web page: RouterOS 6, REST disabled, or the wrong address (#425)."""
    return AdapterError(
        "no RouterOS REST API at this address (RouterOS 6, REST disabled, or wrong address/port)",
        fix="Check the address and port, and that the REST API is enabled (RouterOS 7.1 or "
        "newer, service www-ssl). RouterOS 6 has no REST API: update it, or read the device "
        "through the generic SNMP integration.",
        fix_id="mikrotik.noRest.fix",
        message_id="mikrotik.noRest",
    )


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


def _ms(value: Any) -> int | None:
    """A RouterOS time (``20s``, ``500ms``) in milliseconds."""
    text = _text(value)
    if text.endswith("ms") and text[:-2].isdigit():
        return int(text[:-2])
    seconds = duration(text)
    return seconds * 1000 if seconds is not None else None


def _maybe(value: Any) -> bool | None:
    """A flag that may not be set at all (None: RouterOS' default applies, unknown here)."""
    return None if value is None or value == "" else _flag(value)


#: ``/interface/bonding`` values (#157): ``transmit-hash-policy`` and ``lacp-rate``.
_BOND_HASHES = {
    "layer-2": LagHashPolicy.L2,
    "layer-2-and-3": LagHashPolicy.L2_L3,
    "layer-3-and-4": LagHashPolicy.L3_L4,
}
_LACP_RATES = {"30secs": LacpRate.SLOW, "1sec": LacpRate.FAST}


def bond_details(row: dict[str, Any]) -> dict[str, Any]:
    """The LAG fields of a bonding interface: ``mode`` (the Linux names; ``802.3ad`` is LACP,
    ``lacp-mode`` passive where RouterOS has it), ``transmit-hash-policy``, ``lacp-rate``,
    ``min-links``."""
    mode = _text(row.get("mode"))
    out: dict[str, Any] = {}
    if mode == "802.3ad":
        passive = _text(row.get("lacp-mode")) == "passive"
        out["lag_mode"] = LagMode.LACP_PASSIVE if passive else LagMode.LACP_ACTIVE
        if _text(row.get("lacp-rate")) in _LACP_RATES:
            out["lacp_rate"] = _LACP_RATES[_text(row.get("lacp-rate"))]
        if _text(row.get("min-links")).isdigit():
            out["min_links"] = min(64, int(_text(row.get("min-links"))))
    elif mode:
        out["lag_mode"] = bonding.MODES.get(mode, LagMode.OTHER)
    policy = _text(row.get("transmit-hash-policy"))
    if policy and mode in ("802.3ad", "balance-xor", "balance-tlb"):
        out["hash_policy"] = _BOND_HASHES.get(policy, LagHashPolicy.OTHER)
    return out


def member_state(bond: dict[str, Any], row: dict[str, Any] | None) -> LagMemberState | None:
    """A member's state from its ``monitor-slaves`` row (a guess from the RouterOS manual,
    #21): ``active``, the actor flags (``collecting``, ``distributing``) and the partner's
    system id, port and key; for ``active-backup`` whether it is the active member."""
    if row is None:
        return None
    flags = set(_names(row.get("actor-state") or row.get("flags")))
    partner = _text(row.get("partner-sys-id") or row.get("partner-system-id"))
    try:
        partner_mac = normalise_mac(partner) if partner else None
    except ValueError:
        partner_mac = None
    if partner_mac == "00:00:00:00:00:00":
        partner_mac = None
    lacp = _text(bond.get("mode")) == "802.3ad"
    port = _text(row.get("partner-port") or row.get("partner-port-number"))
    key = _text(row.get("partner-key") or row.get("partner-oper-key"))
    return LagMemberState(
        selected=_maybe(row.get("active")),
        collecting_distributing=({"collecting", "distributing"} <= flags)
        if lacp and flags
        else None,
        partner_system_id=partner_mac if lacp else None,
        partner_port=int(port) if lacp and partner_mac and port.isdigit() else None,
        partner_key=int(key) if lacp and partner_mac and key.isdigit() else None,
    )


def _active(row: dict[str, Any]) -> bool:
    return not _flag(row.get("disabled")) and not _flag(row.get("invalid"))


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    match = re.match(r"-?\d+", _text(value))
    return int(match.group()) if match else None


_AGE_PART = re.compile(r"(\d+)([wdhms])")
_UNIT_S = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def _duration_s(value: Any) -> int | None:
    """A RouterOS duration (``1w2d3h4m5s``, ``45s``, or a plain number of seconds) in seconds."""
    text = _text(value)
    if text.isdigit():
        return int(text)
    parts = _AGE_PART.findall(text)
    if not parts:
        return None
    return sum(int(n) * _UNIT_S[u] for n, u in parts)


def _vlan_id(value: Any) -> int | None:
    vid = _int(value)
    return vid if vid is not None and 1 <= vid <= 4094 else None


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


_STANDARD_WORDS = {s.value: s for s in WifiStandard} | {"onlyn": WifiStandard.N}
_STANDARD_WORDS |= {"onlyac": WifiStandard.AC, "onlyg": WifiStandard.G}


def standards_of(text: Any) -> list[WifiStandard]:
    """The standards a band text names: ``2ghz-ax`` -> [ax], ``5ghz-a/n/ac`` -> [a, n, ac],
    ``2ghz-g,2ghz-n,2ghz-ax`` -> [g, n, ax] (#172)."""
    found: set[WifiStandard] = set()
    for part in _names(text):
        words = part.lower().split("-", 1)[1] if "-" in part else ""
        for word in words.replace("/", " ").split():
            if word in _STANDARD_WORDS:
                found.add(_STANDARD_WORDS[word])
    return sorted(found, key=lambda x: STANDARD_RANK[x])


def standard_of(text: Any) -> WifiStandard | None:
    """The newest standard of a configured band (``2ghz-b/g/n`` -> n)."""
    found = standards_of(text)
    return found[-1] if found else None


def channels_of(text: Any, band: Band) -> list[int] | None:
    """``2g-channels``/``5g-channels`` of ``/interface/wifi/radio`` (MHz list) -> channels."""
    out = sorted(
        {
            fc[1]
            for f in _names(text)
            if (mhz := _int(f)) and (fc := frequency_channel(mhz)) and fc[0] is band
        }
    )
    return out or None


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
        return NotFound(
            f"{endpoint}: not on this device ({detail})",
            message_id="mikrotik.notOnDevice",
            params={"endpoint": endpoint, "detail": detail},
        )
    if "not enough permissions" in detail:
        return AuthFailed(
            f"{endpoint}: access denied ({detail}); check the user's group policies",
            message_id="mikrotik.accessDenied",
            params={"endpoint": endpoint, "detail": detail},
            remedy="policies",
        )
    reason = detail or _text(getattr(response, "reason_phrase", ""))
    status = f"{response.status_code} {reason}".rstrip()
    return AdapterError(
        f"{endpoint}: HTTP {status}",
        message_id="transport.httpStatus",
        params={"path": endpoint, "status": status},
    )


async def get_menu(http: DeviceHttp, endpoint: str) -> Any:
    """``GET`` one menu (errors mapped by :func:`ros_error`)."""
    response = await http.request("GET", endpoint, accept=(400, 500))
    if response.status_code >= 400:
        raise ros_error(endpoint, response)
    try:
        return response.json()
    except ValueError as exc:
        raise AdapterError(
            f"{endpoint}: answer is not valid JSON",
            message_id="transport.notJson",
            params={"path": endpoint},
        ) from exc


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


#: *Fix it* (#267, docs/adr/0012); implemented in :mod:`.provision`, declared here so that the
#: adapter module need not import it (the provision module imports this one).
REMEDIES = (
    Remedy(
        id="policies",
        read_side=True,
        preview=[PreviewStep(id="policies", title="Add the missing policies to the group")],
        title="Add the missing policies",
        description="Through the REST API with the admin login: adds the policies of the setup "
        "guide (read, api, rest-api; write and sensitive too when changes are allowed) that the "
        "group of the stored user lacks. Its other policies and members, and the user's "
        "password, stay; nothing else changes.",
    ),
    Remedy(
        id="rest-service",
        title="Turn on the REST service",
        description="Over SSH with the admin login: creates the local CA and the server "
        "certificate of the setup guide if www-ssl has none, enables www-ssl, and adds this "
        "machine's address to its address list when the list excludes it. Other services, "
        "addresses and all network settings stay. A new certificate must be confirmed again "
        "afterwards.",
        transport="SSH as admin",
        port_default=22,
        preview=[
            PreviewStep(id="ca", title="Create the local CA if missing"),
            PreviewStep(id="server-certificate", title="Create the server certificate if missing"),
            PreviewStep(id="certificate", title="Use the certificate www-ssl already has"),
            PreviewStep(id="www-ssl", title="Enable the www-ssl service"),
            PreviewStep(id="check", title="Read www-ssl again"),
        ],
    ),
)


class MikrotikAdapter(MikrotikWrites, Adapter):
    manifest = Manifest(
        setup_steps=MIKROTIK_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/mikrotik.md#setup",
        id="mikrotik",
        least_privilege=AccountPrivilege.READ,
        name="MikroTik RouterOS",
        version="0.2.0",
        api_version="1.4",
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
                Capability.FIREWALL,
            }
        ),
        config=MikrotikConfig,
        description=(
            "Reads and changes a RouterOS 7 router, switch or access point (REST API); firewall "
            "rules, port forwards and zone policies are tagged and protected by a revert timer."
        ),
        writes=WRITES,
        remedies=REMEDIES,
        admin_login=AdminLogin(
            transport="the REST API as admin",
            user_default="admin",
            secret_label="admin password",
            note="The REST API (www-ssl with a certificate, setup guide: HTTPS with a "
            "certificate) must be on already.",
            preview=[
                PreviewStep(id="group", title="Create the user group with the documented policies"),
                PreviewStep(id="user", title="Create the user signalbox with a generated password"),
                PreviewStep(id="user", title="Delete the user signalbox", remove=True),
                PreviewStep(
                    id="group-signalbox-read",
                    title="Delete the user group signalbox-read (if no other user is in it)",
                    remove=True,
                ),
                PreviewStep(
                    id="group-signalbox-write",
                    title="Delete the user group signalbox-write (if no other user is in it)",
                    remove=True,
                ),
            ],
        ),
        traces=TraceSupport(
            permission="the group policy test (RouterOS: ping and traceroute)",
            method="/tool/traceroute through the REST API (one probe per hop)",
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

    @classmethod
    async def plan_remedy(cls, request: RemedyRequest) -> SetupPlan:
        """*Fix it* (#267): group policies (REST) or the REST service (SSH), as admin."""
        from signalbox.adapters.mikrotik.provision import MikrotikFix

        return await MikrotikFix(request).plan()

    @classmethod
    async def apply_remedy(cls, request: RemedyRequest) -> SetupResult:
        from signalbox.adapters.mikrotik.provision import MikrotikFix

        return await MikrotikFix(request).apply()

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
            unreachable_remedy="rest-service",
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

    async def _readable(self, endpoint: str) -> list[dict[str, Any]] | None:
        """A menu that may be missing (empty) or refused to this user (``None``)."""
        try:
            return await self._optional_rows(endpoint)
        except AdapterError:
            return None

    def _seg(self, vid: int | None) -> str:
        return segment_id(self.context.site_id, vid)

    # --- system -------------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        # A new observation: probe the certificate again and forget the previous answers.
        await self.http.reset()
        self._cache.clear()
        self._layout_cache = None
        try:
            resource = _object(await self._get(RESOURCE), RESOURCE)
        except NotFound as exc:  # RouterOS 6, REST disabled or another service: version unknown
            raise _no_rest() from exc
        except AdapterError as exc:
            if exc.message_id == "transport.notJson":  # a web page instead of JSON
                raise _no_rest() from exc
            raise
        current = _text(resource.get("version")).split(" ")[0]
        if not current:
            raise _unexpected(RESOURCE, "no version")
        if current.startswith("6."):
            raise _routeros6()
        model = _text(resource.get("board-name")) or None
        try:
            board = _object(await self._get(ROUTERBOARD), ROUTERBOARD)
        except NotFound:  # CHR and x86 have no routerboard menu
            board = {}
        is_board = _flag(board.get("routerboard"), default=True)
        if is_board:
            model = _text(board.get("model")) or model
        available = None
        try:
            update = _object(await self._get(PACKAGE_UPDATE), PACKAGE_UPDATE)
        except (NotFound, AdapterError):  # optional: the user may lack the right to see it
            update = {}
        latest = _text(update.get("latest-version"))
        if latest and latest != current:
            available = latest
        # Identity (#177): optional, a user without the right to see a menu gets fewer fields.
        try:
            identity = _object(await self._get(IDENTITY), IDENTITY)
        except (NotFound, AdapterError):
            identity = {}
        ports = await self._readable(INTERFACE) or []
        # The base MAC is the first Ethernet port's (RouterOS has no chassis MAC) (heuristic).
        base_mac = next(
            (
                m
                for r in ports
                if _text(r.get("type")) == "ether"
                for m in [_mac(r.get("orig-mac-address") or r.get("mac-address"))]
                if m
            ),
            None,
        )
        return SystemInfo(
            vendor="MikroTik",
            model=model,
            firmware=Firmware(
                current=current,
                available=available,
                channel=_CHANNELS.get(_text(update.get("channel"))),
            ),
            config_state=await self._config_state(),
            local_backups=await self._local_backups(),
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
            mac=base_mac,
            # RouterOS 7 and 6.4x name the serial ``serial-number``; CHR and x86 have none.
            serial=(_text(board.get("serial-number")) or None) if is_board else None,
            board=_text(resource.get("board-name")) or None,
            architecture=_text(resource.get("architecture-name")) or None,
            # The boot loader: RouterBOOT version as installed (``current-firmware``).
            bootloader=(_text(board.get("current-firmware")) or None) if is_board else None,
            # ``upgrade-firmware`` is the RouterBOOT version bundled with the installed RouterOS
            # (#444); it differs from ``current-firmware`` until ``/system routerboard upgrade``
            # ran and the router restarted. Same fields on RouterOS 6.4x and 7.
            bootloader_available=(
                (_text(board.get("upgrade-firmware")) or None) if is_board else None
            ),
            hostname=_text(identity.get("name")) or None,
            os="RouterOS",
            os_version=current,
        )

    async def _config_state(self) -> ConfigState:
        """The last change from ``/system/history`` (#181). RouterOS applies and saves every
        change at once, so nothing is ever unsaved or pending (``False``, from RouterOS 6
        on: there is no startup configuration to differ from). ``/system/history`` lives in
        memory (undoable actions since the boot), so no row means "none since the restart",
        not "never changed"."""
        rows = await self._readable(HISTORY) or []
        stamped: list[tuple[datetime, str | None]] = []
        for r in rows:
            at = login_time(r.get("time"))
            if at is not None:
                stamped.append((at, _text(r.get("by")) or None))
        last = max(stamped, key=lambda x: x[0], default=None)
        when, by = last if last else (None, None)
        return ConfigState(unsaved=False, pending=False, last_changed=when, changed_by=by)

    async def _local_backups(self) -> LocalBackups | None:
        """Binary backups and exports in the device's file list (#181); ``None`` where the
        login may not list files (the list is empty then, as for a router without any)."""
        rows = await self._readable(FILES)
        if rows is None:
            return None
        found = [
            r
            for r in rows
            if _text(r.get("type")) == "backup"
            or _text(r.get("name")).lower().endswith((".backup", ".rsc"))
        ]
        times = [t for r in found if (t := login_time(r.get("creation-time"))) is not None]
        return LocalBackups(count=len(found), newest=max(times, default=None))

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
                counters=_counters(row, eth),
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
        for n, brow in bonds.items():
            if n not in ports:
                continue
            ports[n] = ports[n].model_copy(update=bond_details(brow))
            states = await self._bond_members(n) if _text(brow.get("mode")) else {}
            for slave in _names(brow.get("slaves")):
                if slave in ports and slave != n:
                    ports[slave] = ports[slave].model_copy(
                        update={"lag": n, "lag_member_state": member_state(brow, states.get(slave))}
                    )
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
        targets, gaps = await self._log_targets()
        gateway = self.context.role is DeviceRole.GATEWAY
        subnets = [
            Subnet(
                id=object_id(dev, "subnet", f"{name}-{a.ip}"),
                segment_id=layout.l3[name],
                interface=a,
                interface_name=name,
                device_id=dev,
                gateway=gateway,
            )
            for name, a in layout.addresses
            if name in layout.l3
        ]
        accounts, privilege, account_gaps = await self._accounts()
        cfg = self.context.config
        assert isinstance(cfg, MikrotikConfig)
        default = is_factory_default("mikrotik", cfg.password.get_secret_value(), cfg.username)
        bridges, port_stp, stp_gaps = await self._stp(layout)
        multicast, multicast_gaps = await self._multicast(layout)
        upnp = await self._upnp(layout)
        services = await self._services(layout)
        if upnp and services:  # services are not read when /ip/service is refused
            services.append(upnp[0])
        port_poe, poe_gaps = await self._poe()
        control, radius, radius_gaps = await self._access_control()
        ports = [
            p.model_copy(update={"stp": port_stp[n]} if n in port_stp else {})
            .model_copy(update={"poe": port_poe[n]} if n in port_poe else {})
            .model_copy(update={"access_control": control[n]} if n in control else {})
            for n, p in layout.ports.items()
        ]
        route_rows = [
            await self._readable(e) for e in (route_reader.IP_ROUTE, route_reader.IPV6_ROUTE)
        ]
        rule_rows = await self._readable(route_reader.ROUTING_RULE)
        if None in route_rows:
            gaps = [
                *gaps,
                Gap(
                    message="routes: the routing table (/ip/route) could not be read",
                    fix="Optional: give the Signalbox user a group with the read policy.",
                    optional=True,
                    message_id="routing.readGap",
                    fix_id="routing.readGap.fix",
                    params={"what": "/ip/route"},
                ),
            ]
        routes = [r for rows in route_rows if rows for r in route_reader.read_routes(dev, rows)]
        uplinks = await self._uplinks(layout)
        wan_groups = multiwan.groups(
            dev, route_rows[0] or [], uplinks, await self._readable(multiwan.NETWATCH) or []
        )
        uplinks = multiwan.with_members(uplinks, wan_groups)
        return Observation(
            routes=known_interfaces(routes, [p.id for p in layout.ports.values()])
            if None not in route_rows
            else [],
            routing_rules=route_reader.read_rules(dev, rule_rows or [], layout.l3.get),
            ports=ports,
            segments=list(layout.segments.values()),
            subnets=subnets,
            uplinks=uplinks,
            gateway_groups=wan_groups,
            ddns=await self._cloud_ddns(uplinks),
            portals=await self._portals(layout),
            services=services,
            certificates=await self._certificates(),
            log_targets={} if targets is None else {dev: targets},
            accounts={} if accounts is None else {dev: accounts},
            stp_bridges={dev: bridges},
            multicast={dev: multicast},
            upnp={dev: upnp[1]} if upnp else {},
            radius_servers={} if radius is None else {dev: radius},
            default_credentials={dev: default},
            signalbox_privilege={} if privilege is None else {dev: privilege},
            incomplete=gaps + account_gaps + stp_gaps + poe_gaps + multicast_gaps + radius_gaps,
        )

    async def _radius_rows(self) -> list[dict[str, Any]] | None:
        return await self._readable(_access.RADIUS)

    async def _access_control(
        self,
    ) -> tuple[dict[str, PortAccessControl], list[RadiusServer] | None, list[Gap]]:
        """802.1X servers per interface, ports that do not learn addresses (#162) and the
        ``/radius`` entries (never the secrets: only whether one is set). ``/radius`` that this
        login may not read is an optional gap; the 802.1X menu exists from RouterOS 7.1."""
        control: dict[str, PortAccessControl] = {}
        for row in await self._rows(BRIDGE_PORT):
            found = _access.learning_off(row) if _active(row) else None
            if found is not None:
                control[_text(row.get("interface"))] = found
        control.update(_access.dot1x_ports(await self._readable(_access.DOT1X_SERVER) or []))
        rows = await self._radius_rows()
        if rows is None:
            gap = Gap(
                message="RADIUS servers: not readable with this login",
                fix="Give Signalbox's group on the router the policies of the setup guide.",
                optional=True,
                message_id="mikrotik.radius",
                fix_id="mikrotik.radius.fix",
            )
            return control, None, [gap]
        return control, _access.radius_servers(rows), []

    async def _portals(self, layout: _Layout) -> list[CaptivePortal]:
        """``/ip/hotspot`` servers (#460). A menu that is missing (no hotspot, older package) or
        refused to this user reports nothing."""
        rows = await self._readable(hotspot.HOTSPOT)
        if not rows:
            return []
        return hotspot.hotspots(
            self.context.device_id,
            rows,
            await self._readable(hotspot.PROFILE) or [],
            await self._readable(hotspot.USER_PROFILE) or [],
            layout.l3,
            duration,
        )

    async def _poe(self) -> tuple[dict[str, PortPoe], list[Gap]]:
        """PoE-out of the ethernet ports (``/interface/ethernet/poe``: ``poe-out`` auto-on,
        forced-on or off, ``poe-priority``; RouterOS 7 has the menu on boards with PoE
        out, elsewhere it is missing) with the state from its ``monitor once``
        (``poe-out-status``, ``poe-out-voltage``, ``poe-out-current`` in mA, ``poe-out-power``
        in W). The monitor is optional: without it only the settings are read."""
        rows = await self._optional_rows(ETHERNET_POE)
        if not rows:
            return {}, []
        names = [_text(r.get("name")) for r in rows if _text(r.get("name"))]
        seen: dict[str, dict[str, Any]] = {}
        refused: AdapterError | None = None
        try:
            answer = await self.http.post_json(
                ETHERNET_POE_MONITOR, {"numbers": ",".join(names), "once": ""}
            )
        except AdapterError as exc:
            refused = exc
        else:
            rows_seen = _stp.monitor_rows(answer)
            for i, m in enumerate(rows_seen):
                name = _text(m.get("name"))
                if not name and len(rows_seen) == len(names):
                    name = names[i]
                seen[name] = m
        out = {
            _text(r.get("name")): mikrotik_poe.port(r, seen.get(_text(r.get("name")), {}))
            for r in rows
            if _text(r.get("name"))
        }
        gaps: list[Gap] = []
        if refused is not None:
            gaps.append(
                Gap(
                    message=f"PoE state (status and power per port): {refused}",
                    fix="Give Signalbox's group on the router the policies of the setup guide "
                    "so it may run the PoE monitor; without it only the PoE settings are read.",
                    optional=True,
                    message_id="mikrotik.poeMonitor",
                    fix_id="mikrotik.poeMonitor.fix",
                    params={"cause": str(refused)},
                )
            )
        return out, gaps

    async def _multicast(self, layout: _Layout) -> tuple[DeviceMulticast, list[Gap]]:
        """Snooping and querier per bridge, the mDNS repeater (RouterOS 7.16 and later) and the
        IGMP proxy (#161). A menu the user may not read is an optional gap; the bridges are
        read with the layout and never missing."""
        rows = [r for r in await self._rows(BRIDGE) if _active(r)]
        port_rows = await self._rows(BRIDGE_PORT)
        out = DeviceMulticast()
        for row in rows:
            name = _text(row.get("name"))
            members = [r for r in port_rows if _text(r.get("bridge")) == name and _active(r)]
            out.settings.append(_multicast.settings(row, members, layout.l3.get(name)))
        gaps: list[Gap] = []
        try:
            dns = _object(await self._get(DNS), DNS)
            if (mdns := _multicast.mdns_repeater(dns, layout.l3)) is not None:
                out.reflectors.append(mdns)
        except AdapterError:
            pass  # DNS has its own gap in its capability
        proxy = await self._readable(_multicast.IGMP_PROXY_INTERFACE)
        if proxy is None:
            gaps.append(
                Gap(
                    message="IGMP proxy settings: not readable with this login",
                    fix="Give Signalbox's group on the router the policies of the setup guide.",
                    optional=True,
                    message_id="mikrotik.igmpProxy",
                    fix_id="mikrotik.igmpProxy.fix",
                )
            )
        elif (igmp := _multicast.igmp_proxy(proxy, layout.l3)) is not None:
            out.reflectors.append(igmp)
        return out, gaps

    async def _stp(self, layout: _Layout) -> tuple[list[StpBridge], dict[str, StpPort], list[Gap]]:
        """Spanning tree per bridge and bridge port (#155). The running state comes from the
        print of the bridge ports (RouterOS 7) or the read-only ``monitor ... once``; when
        RouterOS refuses the monitor, the configuration is kept with an optional gap."""
        ids = {n: p.id for n, p in layout.ports.items()}
        rows = [r for r in await self._rows(BRIDGE) if _active(r)]
        bport_rows = [r for r in await self._rows(BRIDGE_PORT) if _active(r)]
        ethernet = {_text(r.get("name")): r for r in await self._optional_rows(ETHERNET)}
        refused: AdapterError | None = None

        async def monitor(path: str, numbers: str) -> list[dict[str, Any]]:
            nonlocal refused
            try:
                answer = await self.http.post_json(path, {"numbers": numbers, "once": ""})
            except AdapterError as exc:
                refused = refused or exc
                return []
            return _stp.monitor_rows(answer)

        bridges: list[StpBridge] = []
        protocols: dict[str, StpProtocol] = {}
        for row in rows:
            proto = _stp.protocol(row)
            name = _text(row.get("name"))
            seen: dict[str, Any] = {}
            if proto in SPANNING_TREE:
                answer = await monitor(_stp.BRIDGE_MONITOR, _text(row.get(".id")) or name)
                seen = answer[0] if answer else {}
            b = _stp.bridge(row, seen, ids)
            if b is not None:
                bridges.append(b)
                protocols[b.name] = b.protocol
        in_tree = [r for r in bport_rows if protocols.get(_text(r.get("bridge"))) is not None]
        monitors: dict[str, dict[str, Any]] = {}
        spanning = [r for r in in_tree if protocols[_text(r.get("bridge"))] in SPANNING_TREE]
        if _stp.needs_monitor(spanning):
            numbers = ",".join(_text(r.get(".id")) or _text(r.get("interface")) for r in spanning)
            answer = await monitor(_stp.BRIDGE_PORT_MONITOR, numbers)
            for i, m in enumerate(answer):
                name = _text(m.get("interface"))
                if not name and len(answer) == len(spanning):
                    name = _text(spanning[i].get("interface"))
                monitors[name] = m
        out: dict[str, StpPort] = {}
        for r in in_tree:
            name = _text(r.get("interface"))
            if name in layout.ports:
                proto = protocols[_text(r.get("bridge"))]
                out[name] = _stp.port(r, monitors.get(name, {}), proto, ethernet.get(name))
        gaps: list[Gap] = []
        if refused is not None:
            gaps.append(
                Gap(
                    message=f"spanning tree state (root bridge, port roles): {refused}",
                    fix="Give Signalbox's group on the router the policies of the setup guide "
                    "so it may run the bridge monitor; without it only the settings of the "
                    "bridges are read.",
                    optional=True,
                    message_id="mikrotik.stpMonitor",
                    fix_id="mikrotik.stpMonitor.fix",
                    params={"cause": str(refused)},
                )
            )
        return bridges, out, gaps

    async def _accounts(
        self,
    ) -> tuple[list[DeviceAccount] | None, AccountPrivilege | None, list[Gap]]:
        """Local users with their group's privilege (#175). ``/user`` never shows a password,
        so ``password_set`` stays unknown; SSH keys from ``/user/ssh-keys``. ``None`` with an
        optional gap when the users cannot be read (a group without the ``read`` policy)."""
        try:
            users = await self._rows(USERS)
            groups = await self._rows(USER_GROUPS)
        except AdapterError as exc:
            gap = Gap(
                message=f"accounts: {exc}",
                optional=True,
                message_id="mikrotik.accounts",
                params={"cause": str(exc)},
            )
            return None, None, [gap]
        policy = {_text(g.get("name")): user_privilege(g.get("policy")) for g in groups}
        keys = await self._readable(USER_SSH_KEYS)
        with_key = {_text(k.get("user")) for k in keys or []}
        cfg = self.context.config
        assert isinstance(cfg, MikrotikConfig)
        out: list[DeviceAccount] = []
        for u in users:
            name = _text(u.get("name"))
            if not name:
                continue
            allowed: list[IPv4Network | IPv6Network] = []
            for part in _names(u.get("address")):
                with contextlib.suppress(ValueError):
                    allowed.append(ip_network(part, strict=False))
            out.append(
                DeviceAccount(
                    name=name,
                    privilege=policy.get(_text(u.get("group")), AccountPrivilege.OTHER),
                    enabled=not _flag(u.get("disabled")),
                    key_auth=None if keys is None else name in with_key,
                    logins_tracked=True,
                    last_login=login_time(u.get("last-logged-in")),
                    is_signalbox=name == cfg.username,
                    allowed_from=[n for n in allowed if n.prefixlen > 0],
                )
            )
        own = next((a for a in out if a.is_signalbox), None)
        return out, own.privilege if own else None, []

    async def _log_targets(self) -> tuple[list[LogTarget] | None, list[Gap]]:
        """Remote logging actions with the topics of the rules using them, traffic-flow
        (NetFlow/IPFIX) targets and SNMP trap targets (#180). ``None`` with a gap when the
        logging actions cannot be read; a missing flow or SNMP menu only leaves those out."""
        try:
            actions = await self._optional_rows(LOG_ACTION)
            rules = await self._optional_rows(LOG_RULES)
        except AdapterError as exc:
            return None, [
                Gap(
                    message=f"log targets: {exc}",
                    optional=True,
                    message_id="mikrotik.logTargets",
                    params={"cause": str(exc)},
                )
            ]
        topics: dict[str, list[str]] = {}
        for r in rules:
            if _flag(r.get("disabled")) or _flag(r.get("invalid")):
                continue
            used = topics.setdefault(_text(r.get("action")), [])
            used += [t for t in _text(r.get("topics")).split(",") if t and t not in used]
        out: list[LogTarget] = []
        for a in actions:
            address = _text(a.get("remote"))
            if _text(a.get("target")) != "remote" or address in ("", "0.0.0.0", "::"):
                continue
            name = _text(a.get("name"))
            proto = _text(a.get("remote-protocol")).lower()
            out.append(
                LogTarget(
                    kind=LogKind.SYSLOG,
                    address=address,
                    port=_int(a.get("remote-port")) or LOG_PORTS[LogKind.SYSLOG],
                    transport=LogTransport.TCP if proto == "tcp" else LogTransport.UDP,
                    enabled=name in topics,
                    name=name or None,
                    topics=topics.get(name, []),
                    managed=name.startswith("signalbox"),
                )
            )
        flow = await self._optional_object(TRAFFIC_FLOW)
        for t in await self._readable(TRAFFIC_FLOW_TARGET) or []:
            address = _text(t.get("dst-address"))
            if not address:
                continue
            version = _text(t.get("version")) or "9"
            kind = LogKind.IPFIX if version == "ipfix" else LogKind.NETFLOW
            out.append(
                LogTarget(
                    kind=kind,
                    address=address,
                    port=_int(t.get("port")) or LOG_PORTS[LogKind.NETFLOW],
                    transport=LogTransport.UDP,
                    enabled=_flag(flow.get("enabled")) and not _flag(t.get("disabled")),
                    name="traffic-flow",
                    topics=[] if kind is LogKind.IPFIX else [f"v{version}"],
                )
            )
        snmp = await self._optional_object(SNMP)
        generators = [g for g in _text(snmp.get("trap-generators")).split(",") if g]
        for address in _text(snmp.get("trap-target")).split(","):
            if address.strip() in ("", "0.0.0.0", "::"):
                continue
            out.append(
                LogTarget(
                    kind=LogKind.SNMP_TRAP,
                    address=address,
                    port=LOG_PORTS[LogKind.SNMP_TRAP],
                    transport=LogTransport.UDP,
                    enabled=_flag(snmp.get("enabled")) and bool(generators),
                    name="snmp",
                    topics=generators,
                )
            )
        return out, []

    async def _certificates(self) -> list[Certificate]:
        """Certificates stored on the router (#330): ``/certificate`` (public data only, see
        :mod:`.certificates`) and the services, VPN and RADIUS servers that name them. Empty
        when the menu cannot be read (not read)."""
        dev = self.context.device_id
        rows = await self._readable(CERTIFICATE)
        if not rows:
            return []
        certs = [c for r in rows if (c := parse_certificate(dev, r)) is not None]
        services = await self._readable(IP_SERVICE) or []
        named: list[tuple[str, CertificateUse]] = []
        for endpoint, use, single in CERT_USERS:
            if single:
                values = [await self._optional_object(endpoint)]
            else:
                values = await self._readable(endpoint) or []
            named += [(_text(v.get("certificate")), use) for v in values]
        return attach_users(certs, dev, services, named)

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
        snmp = await self._snmp()
        if snmp is not None:
            out.append(snmp)
        if (cloud := await self._cloud_service()) is not None:
            out.append(cloud)
        return out

    async def _upnp(self, layout: _Layout) -> tuple[ManagementService, DeviceUpnp] | None:
        """``/ip/upnp``, its interfaces and the dynamic NAT rules it created (#176, ADR 0029)."""
        settings = await self._optional_object(UPNP)
        if not settings:
            return None
        nat = await self._readable(FW_NAT)
        return _upnp.state(
            self.context.device_id,
            settings,
            await self._optional_rows(_upnp.UPNP_INTERFACES),
            nat,
            layout.l3,
        )

    async def _cloud_service(self) -> ManagementService | None:
        """MikroTik Cloud (``/ip/cloud``, #327): on when DDNS is ``yes`` (RouterOS 7.x), when
        ``auto`` has reached the cloud (``status`` ``updated``), or with Back to Home VPN.
        GUESS (needs a real router, #21): the meaning of ``auto`` and the field names
        ``back-to-home-vpn`` and ``status`` on the installed versions."""
        conf = await self._optional_object(CLOUD)
        if not conf:
            return None
        ddns = _text(conf.get("ddns-enabled")).lower()
        status = _text(conf.get("status")).lower()
        on = (
            _flag(ddns)
            or (ddns == "auto" and status == "updated")
            or _text(conf.get("back-to-home-vpn")).lower() == "enabled"
        )
        dev = self.context.device_id
        return ManagementService(
            id=object_id(dev, "service", "mikrotik-cloud"),
            device_id=dev,
            kind=ServiceKind.CLOUD,
            name="mikrotik-cloud",
            enabled=on,
        )

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
            default_community=any(
                _text(r.get("name")).lower() in ("public", "private") for r in rows
            ),
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

    async def _bond_members(self, bond: str) -> dict[str, dict[str, Any]]:
        """``/interface/bonding/monitor-slaves bond=<bond> once`` (#157): the LACP state per
        member. Empty when RouterOS refuses it (an older version, the policy) or has none."""
        try:
            answer = await self.http.post_json(BONDING_MONITOR, {"bond": bond, "once": ""})
        except AdapterError:
            return {}
        rows = answer if isinstance(answer, list) else [answer]
        out: dict[str, dict[str, Any]] = {}
        for row in rows:
            if isinstance(row, dict):
                name = _text(row.get("interface") or row.get("port") or row.get("slave"))
                if name:
                    out[name] = row
        return out

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

    async def _cloud_ddns(self, uplinks: list[Uplink]) -> list[DynamicDns]:
        """The MikroTik Cloud name (``/ip/cloud``, #154); a router without it has none."""
        try:
            cloud = _object(await self._get(CLOUD), CLOUD)
        except AdapterError:
            return []
        own = next((u for u in uplinks if u.public_ipv4), next((u for u in uplinks if u.up), None))
        return multiwan.cloud_ddns(self.context.device_id, cloud, own)

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
        adverts, servers6 = await self._ipv6(layout)
        return Observation(
            dhcp_servers=servers,
            dhcp_relays=await self._relays(layout),
            server_sightings=await self._sightings(layout),
            router_adverts=adverts,
            dhcp6_servers=servers6,
        )

    async def _ipv6(self, layout: Any) -> tuple[list[RouterAdvert], list[Dhcp6Server]]:
        """Router advertisements (``/ipv6/nd``, with ``/ipv6/nd/prefix``) and DHCPv6 servers
        (``/ipv6/dhcp-server``, prefix delegation from ``/ipv6/pool``) (#151). Without the
        ``ipv6`` package the menus are missing and nothing is reported. RouterOS' DHCPv6 server
        only delegates prefixes (it hands out no addresses): it is reported as a stateless
        server with prefix pools. ``/ipv6/nd`` ``interface=all`` is the default for every
        interface without a row of its own."""
        dev = self.context.device_id
        nd_rows = await self._optional_rows(IPV6_ND)
        nd = {_text(r.get("interface")): r for r in nd_rows if not _flag(r.get("dynamic"))}
        prefix_rows = await self._optional_rows(IPV6_ND_PREFIX)
        adverts: list[RouterAdvert] = []
        for iface, seg in sorted(layout.l3.items()):
            row = nd.get(iface) or nd.get("all")
            if row is None or iface in layout.wan or any(a.segment_id == seg for a in adverts):
                continue
            off = _flag(row.get("disabled"))
            managed = _flag(row.get("managed-address-configuration"))
            other = _flag(row.get("other-configuration"))
            mode = (
                RaMode.OFF
                if off
                else RaMode.STATEFUL
                if managed
                else RaMode.STATELESS
                if other
                else RaMode.SLAAC
            )
            prefixes = []
            for prow in prefix_rows:
                if _text(prow.get("interface")) not in (iface, "all") or _flag(
                    prow.get("disabled")
                ):
                    continue
                try:
                    pnet = IPv6Network(_text(prow.get("prefix")).split(",")[0], strict=False)
                except ValueError:
                    continue
                prefixes.append(
                    RaPrefix(
                        prefix=pnet,
                        autonomous=_maybe(prow.get("autonomous")),
                        on_link=_maybe(prow.get("on-link")),
                    )
                )
            dns = [a for a in _addrs(row.get("dns")) if isinstance(a, IPv6Address)]
            adverts.append(
                RouterAdvert(
                    id=object_id(dev, "ra", _segment_key(seg)),
                    device_id=dev,
                    segment_id=seg,
                    mode=mode,
                    managed=None if off else managed,
                    other=None if off else other,
                    prefixes=prefixes,
                    rdnss=dns if _flag(row.get("advertise-dns"), True) else [],
                    router_lifetime=duration(row.get("ra-lifetime")),
                    vendor_extra=_extra(row, "interface"),
                )
            )
        pools = {_text(r.get("name")): r for r in await self._optional_rows(IPV6_POOL)}
        servers: list[Dhcp6Server] = []
        for row in await self._optional_rows(IPV6_DHCP_SERVER):
            sname, seg = _text(row.get("name")), layout.l3.get(_text(row.get("interface")))
            if not sname or seg is None:
                continue
            pool = pools.get(_text(row.get("address-pool")))
            length = _int(pool.get("prefix-length")) if pool else None
            prefix_pools = []
            if pool is not None and length:
                with contextlib.suppress(ValueError):
                    prefix_pools.append(
                        Dhcp6PrefixPool(
                            prefix=IPv6Network(_text(pool.get("prefix")), strict=False),
                            length=length,
                        )
                    )
            servers.append(
                Dhcp6Server(
                    id=object_id(dev, "dhcp6", sname),
                    device_id=dev,
                    segment_id=seg,
                    enabled=_active(row),
                    mode=Dhcp6Mode.STATELESS,
                    prefix_pools=prefix_pools,
                    lease_seconds=duration(row.get("lease-time")),
                    vendor_extra=_extra(row, "interface", "address-pool"),
                )
            )
        return adverts, servers

    async def _sightings(self, layout: Any) -> list[ServerSighting]:
        """DHCP servers the router saw answer (#184): the server of its own DHCP client on a
        network that is not the WAN (``/ip/dhcp-client`` ``dhcp-server``), and the unknown
        servers of the rogue DHCP detector (``/ip/dhcp-server/alert`` ``unknown-server``, the
        MAC addresses it saw answer that are not in ``valid-server``)."""
        dev = self.context.device_id
        out: dict[str, ServerSighting] = {}
        for row in await self._optional_rows(DHCP_CLIENT):
            iface = _text(row.get("interface"))
            seg = layout.l3.get(iface)
            server = _addr(row.get("dhcp-server"))
            if iface in layout.wan or seg is None or server is None or not _active(row):
                continue
            if _text(row.get("status")) != "bound":
                continue
            try:
                lease = ip_interface(_text(row.get("address")))
            except ValueError:
                lease = None
            dns = [a for a in (_addr(row.get(k)) for k in ("primary-dns", "secondary-dns")) if a]
            gateway = _addr(row.get("gateway"))
            key = f"lease-{iface}-{server}"
            out[key] = ServerSighting(
                id=object_id(dev, "server-seen", key),
                device_id=dev,
                segment_id=seg,
                kind=ServerKind.DHCPV4,
                server_address=server,
                offered=ServerOffer(
                    address=lease.ip if lease else None,
                    routers=[gateway] if gateway else [],
                    dns_servers=dns,
                    prefixes=[lease.network] if lease else [],
                ),
                origin=SightingSource.CLIENT_LEASE,
            )
        for row in await self._optional_rows(DHCP_ALERT):
            iface = _text(row.get("interface"))
            seg = layout.l3.get(iface)
            if seg is None or _flag(row.get("disabled")):
                continue
            for token in _names(row.get("unknown-server")):
                mac = _mac(token.split("/")[0].strip())
                if mac is None:
                    continue
                key = f"alert-{iface}-{mac}"
                out[key] = ServerSighting(
                    id=object_id(dev, "server-seen", key),
                    device_id=dev,
                    segment_id=seg,
                    kind=ServerKind.DHCPV4,
                    server_mac=mac,
                    origin=SightingSource.DEVICE_ALERT,
                )
        return sorted(out.values(), key=lambda x: x.id)

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
        domain_forwards: list[tuple[str, IPAddress]] = []
        dynamic = False
        for row in await self._rows(DNS_STATIC):
            dynamic = dynamic or _flag(row.get("dynamic"))
            kind = _text(row.get("type")).upper() or "A"
            if kind == "FWD":
                # RouterOS 7.? static entry ``type=FWD``: names under ``name`` go to ``forward-to``
                # (a guess for the field names, #21)
                target = _addr(row.get("forward-to"))
                if _active(row) and target is not None and _text(row.get("name")):
                    domain_forwards.append((_text(row.get("name")).lower(), target))
                continue
            host, address = _text(row.get("name")), _addr(row.get("address"))
            if not _active(row) or kind not in ("A", "AAAA") or not host or address is None:
                continue
            records.append(HostRecord(name=host, address=address))
        # ``use-doh-server``: with a DoH server set (RouterOS 7.x), every lookup goes there over
        # HTTPS; ``servers`` then only resolve its name. The name is the host of the URL.
        doh = _text(dns.get("use-doh-server")).split("://", 1)[-1].split("/", 1)[0]
        # ``adlist`` (RouterOS 7.15 and later; a guess for ``match-count``, #21): not on older
        # releases, where there are no block lists
        blocklists = [
            Blocklist(
                name=_text(row.get("url")).split("://", 1)[-1].split("/", 1)[0].split("@")[-1],
                entries=_int(row.get("match-count")) if row.get("match-count") else None,
                enabled=_active(row),
            )
            for row in await self._readable(DNS_ADLIST) or []
            if _text(row.get("url"))
        ]
        remote = _flag(dns.get("allow-remote-requests"))
        listen = _unique(a.ip for n, a in layout.addresses if n in layout.l3) if remote else []
        # RouterOS has no switch that puts lease names into DNS: it takes a ``lease-script`` on
        # the DHCP server that adds ``/ip dns static`` entries. A script that mentions "dns" is
        # read as registering (a guess, #21); servers without one: not registering. Entries the
        # script made (or any other ``dynamic`` row) show as ``dynamic`` in the static table.
        servers = [r for r in await self._optional_rows(DHCP_SERVER) if _active(r)]
        register = (
            any("dns" in _text(r.get("lease-script")).lower() for r in servers) if servers else None
        )
        # only the layer-3 interfaces that carry an address are answered on (not an interface
        # list: ``allow-remote-requests`` has none)
        segments = (
            sorted({layout.l3[n] for n, _ in layout.addresses if n in layout.l3}) if remote else []
        )
        return Observation(
            dns_services=[
                DnsService(
                    id=object_id(self.context.device_id, "dns", "dns"),
                    device_id=self.context.device_id,
                    enabled=remote,
                    listen=listen,
                    name="dns",
                    forwarders=[
                        DnsForwarder(
                            address=a,
                            transport=DnsTransport.HTTPS if doh else DnsTransport.UDP,
                            tls_name=doh or None,
                        )
                        for a in _unique(_addrs(dns.get("servers")))
                    ]
                    + [DnsForwarder(address=a, domain=name) for name, a in domain_forwards],
                    recursive=False,
                    # ``cache-size`` in kiB
                    cache_size=_int(dns.get("cache-size")) if dns.get("cache-size") else None,
                    blocklists=blocklists,
                    supports_encrypted_dns=True,
                    host_records=records,
                    register_dhcp=register,
                    dynamic_records=True if dynamic else (register or None),
                    listen_segments=segments,
                    # RouterOS 7 has no rebinding protection setting (none in /ip/dns): None
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
                f"no wireless package: neither {WIFI} nor {WIRELESS} exists on this device",
                message_id="mikrotik.noWireless",
                params={"wifi": WIFI, "wireless": WIRELESS},
            ) from None

    async def read_wireless(self) -> Observation:
        layout = await self._layout()
        kind, rows = await self._wifi_rows()
        if kind == "wifi":
            obs = await self._wifi(layout, rows)
        else:
            obs = await self._wireless(layout, rows)
        return await self._with_capsman(obs)

    async def _with_capsman(self, obs: Observation) -> Observation:
        """The access points a CAPsMAN controller manages (#475) as devices of this one, from
        ``remote-cap`` of both generations (a menu that does not exist: nothing). They are
        agents of this device, which is the controller unless it is a repeater itself."""
        dev = self.context.device_id
        rows = [
            *(await self._readable(capsman.REMOTE_CAP_V7) or []),
            *(await self._readable(capsman.REMOTE_CAP_LEGACY) or []),
        ]
        caps = capsman.cap_devices(
            rows, controller_id=dev, site_id=self.context.site_id, adapter_id=self.manifest.id
        )
        if not caps:
            return obs
        obs = await self._cap_radios(obs, await self._cap_owners(caps))
        layout = await self._layout()
        raw = {capsman.cap_id(r, dev): _text(r.get("address")) for r in rows}
        arp = await self._optional_rows(ARP)
        hosts = await self._optional_rows(BRIDGE_HOST)
        wireless = {n for n, p in layout.ports.items() if p.kind is PortKind.WIRELESS}
        mesh: dict[str, MeshMembership] = {}
        found: list[Device] = []
        for cap in caps:
            extra, member = capsman.uplink_of(
                cap,
                arp=arp,
                hosts=hosts,
                wireless_ports=wireless,
                segment_of_interface=layout.l3,
                segment_of_address=lambda a: layout.containing(ip_address(a)),
                cap_address_text=raw.get(cap.id, ""),
            )
            member = member.model_copy(update={"controller_id": dev})
            port = layout.port(extra.get("capsman_port", ""))
            if port is None:  # a table row of an interface that is no port: not claimed
                extra.pop("capsman_port", None)
                member = member.model_copy(update={"uplink": None})
            else:
                extra["capsman_port"] = port
            found.append(cap.model_copy(update={"vendor_extra": {**cap.vendor_extra, **extra}}))
            mesh[cap.id] = member
        mesh = mesh | obs.mesh
        mesh.setdefault(dev, capsman.controller_membership())
        return obs.model_copy(update={"devices": [*obs.devices, *found], "mesh": mesh})

    async def _cap_owners(self, caps: list[Device] | None = None) -> dict[str, str]:
        """Interface name -> id of the CAP it runs on (#481); empty without CAPs."""
        if caps is None:
            rows = [
                *(await self._readable(capsman.REMOTE_CAP_V7) or []),
                *(await self._readable(capsman.REMOTE_CAP_LEGACY) or []),
            ]
            caps = capsman.cap_devices(
                rows,
                controller_id=self.context.device_id,
                site_id=self.context.site_id,
                adapter_id=self.manifest.id,
            )
        if not caps:
            return {}
        radios = [
            *(await self._readable(capsman.CAP_RADIO_V7) or []),
            *(await self._readable(capsman.CAP_RADIO_LEGACY) or []),
        ]
        interfaces = [
            *(await self._readable(WIFI) or []),
            *(await self._readable(capsman.CAP_INTERFACE_LEGACY) or []),
        ]
        return capsman.interface_owners(caps, radios, interfaces)

    async def _cap_radios(self, obs: Observation, owners: dict[str, str]) -> Observation:
        """Radios and SSIDs of the CAPs (#481) as those of the CAP device. ``wifi``: the
        controller's own ``/interface/wifi`` list holds the CAP interfaces; what was read for
        them moves to the CAP. ``/caps-man/interface`` (legacy) is read here: band and channel
        from ``current-channel`` (``5180/20-eeCe/ac``) or the channel settings, SSID and VLAN
        from the configuration, the client count from the registration table *(guess, #21:
        the dotted column names of the REST API)*."""
        if not owners:
            return obs
        layout = await self._layout()
        moved = {r.id: r for r in obs.radios if r.name in owners}
        radios: list[Radio] = [r for r in obs.radios if r.id not in moved]
        wlans: list[Wlan] = []
        new_radio: dict[str, str] = {}
        for old in moved.values():
            cap = owners[old.name]
            fresh = old.model_copy(
                update={"id": object_id(cap, "radio", old.name), "device_id": cap}
            )
            new_radio[old.id] = fresh.id
            radios.append(fresh)
        for w in obs.wlans:
            name = w.id.rsplit("/", 1)[-1]
            if name in owners or w.radio_id in moved:
                cap = owners.get(name) or owners[moved[w.radio_id].name]
                w = w.model_copy(
                    update={
                        "id": object_id(cap, "wlan", name),
                        "device_id": cap,
                        "radio_id": new_radio.get(w.radio_id, w.radio_id),
                        "port_id": None,
                    }
                )
            wlans.append(w)
        by_name = {
            _text(r.get("name")): r
            for r in await self._readable(capsman.CAP_INTERFACE_LEGACY) or []
            if _text(r.get("name")) in owners
        }
        counts: dict[str, int] = {}
        for row in await self._readable(capsman.CAP_REGISTRATION_LEGACY) or []:
            iface = _text(row.get("interface"))
            master = _text(by_name.get(iface, {}).get("master-interface"))
            key = master if master not in ("", "none") else iface
            counts[key] = counts.get(key, 0) + 1
        masters: dict[str, Radio] = {}
        for name, row in by_name.items():
            if _text(row.get("master-interface")) not in ("", "none"):
                continue
            channel = capsman.current_channel(row)
            fc = frequency_channel(channel[0]) if channel else None
            band = band_of(row.get("channel.band")) or (fc[0] if fc else None)
            if band is None:
                continue
            cap = owners[name]
            masters[name] = Radio(
                id=object_id(cap, "radio", name),
                device_id=cap,
                name=name,
                band=band,
                channel=fc[1] if fc else None,
                width_mhz=(channel[1] if channel else None) or width_of(row.get("channel.width")),
                enabled=_active(row),
                standard=standard_of(row.get("channel.band")),
                channel_auto=not _text(row.get("channel.frequency")),
                client_count=counts.get(name, 0),
                vendor_extra=_extra(row, "channel.band", "current-channel"),
            )
        radios.extend(masters.values())
        for name, row in by_name.items():
            master = _text(row.get("master-interface"))
            radio = masters.get(name if master in ("", "none") else master)
            ssid = _text(row.get("configuration.ssid")) or _text(row.get("ssid"))
            if radio is None or not ssid:
                continue
            vid = _int(row.get("datapath.vlan-id")) if _text(row.get("datapath.vlan-id")) else None
            wlans.append(
                Wlan(
                    id=object_id(owners[name], "wlan", name),
                    device_id=owners[name],
                    ssid=ssid,
                    radio_id=radio.id,
                    bssid=_mac(row.get("mac-address")),
                    enabled=radio.enabled and _active(row),
                    security=security_of(row.get("security.authentication-types")),
                    segment_id=self._wlan_segment(layout, name, vid),
                    hidden=_flag(row.get("configuration.hide-ssid")),
                    vendor_extra=_extra(row, "configuration", "security"),
                )
            )
        return obs.model_copy(update={"radios": radios, "wlans": wlans})

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

        access_list = await self._optional_rows(WIFI_ACCESS_LIST)
        radius = _access.radius_servers(await self._readable(_access.RADIUS) or [])
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
                standard=standard_of(prop(row, "channel", "band")),
                channel_auto=len(freqs) != 1,
                vendor_extra={
                    k: _text(v)
                    for k in ("band", "frequency", "width")
                    if _text(v := prop(row, "channel", k))
                },
            )
        masters = {n: _text(r.get("master-interface")) or n for n, r in by_name.items()}
        await self._client_counts(radios, masters, WIFI_REGISTRATION)
        await self._wifi_capabilities(radios, by_name)
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
                    bssid=_mac(row.get("mac-address")),
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
                    **self._roaming(row, prop, access_list, name),
                    mac_filter=_access.mac_filter(access_list, name),
                    radius=_access.wlan_radius(radius) if "enterprise" in sec.value else None,
                    vendor_extra={
                        "authentication-types": _text(prop(row, "security", "authentication-types"))
                    },
                )
            )
        stations = [
            (name, masters[name], _text(prop(row, "configuration", "mode")))
            for name, row in by_name.items()
        ]
        peers, member = await self._station_peers(layout, stations, radios, WIFI_REGISTRATION)
        return Observation(radios=list(radios.values()), wlans=wlans, mesh_peers=peers, mesh=member)

    async def _station_peers(
        self,
        layout: _Layout,
        stations: list[tuple[str, str, str]],
        radios: dict[str, Radio],
        endpoint: str,
    ) -> tuple[list[MeshPeer], dict[str, MeshMembership]]:
        """Wireless backhaul peers (#171): the access point a station interface is connected
        to, from the registration table (``interface``, ``mac-address`` of the access point,
        ``signal``, ``tx-rate``, ``rx-rate``). Only modes that carry a LAN: ``station-bridge``
        and ``station-pseudobridge`` (client bridge), ``station-wds`` (WDS). A plain ``station``
        is an uplink of a router, not a mesh node. Not readable: nothing is reported."""
        dev = self.context.device_id
        modes = {
            name: (master, _STATION_KINDS[mode])
            for name, master, mode in stations
            if mode in _STATION_KINDS
        }
        if not modes:
            return [], {}
        table = await self._readable(endpoint)
        peers: list[MeshPeer] = []
        for row in table or []:
            name = _text(row.get("interface"))
            mac, port = _mac(row.get("mac-address")), layout.port(name)
            if name not in modes or mac is None or port is None:
                continue
            master, kind = modes[name]
            radio = radios.get(master)
            tx, rx = wifi_assoc.rate(row.get("tx-rate"))[0], wifi_assoc.rate(row.get("rx-rate"))[0]
            peers.append(
                MeshPeer(
                    id=object_id(dev, "meshpeer", f"{name}-{mac}"),
                    device_id=dev,
                    port_id=port,
                    peer_mac=mac,
                    role=MeshPeerRole.UPLINK,
                    wireless=WirelessLinkInfo(
                        band=radio.band if radio else None,
                        channel=radio.channel if radio else None,
                        signal_dbm=wifi_assoc.signal(row.get("signal", row.get("signal-strength"))),
                        tx_rate_mbps=tx,
                        rx_rate_mbps=rx,
                        kind=kind,
                    ),
                )
            )
        if not peers:
            return [], {}
        member = MeshMembership(role=MeshRole.REPEATER, uplink=MeshUplink.WIRELESS)
        return peers, {dev: member}

    @staticmethod
    def _roaming(
        row: dict[str, Any], prop: Any, access_list: list[dict[str, Any]], name: str
    ) -> dict[str, Any]:
        """Roaming fields (#168) of a ``wifi`` interface; what is not set stays None."""
        out: dict[str, Any] = {}
        if _maybe(prop(row, "security", "ft")):
            out["ft"] = FastTransition(
                mobility_domain=wifi_assoc.mobility_domain(
                    prop(row, "security", "ft-mobility-domain")
                ),
                over_ds=_maybe(prop(row, "security", "ft-over-ds")),
                key_holder=wifi_assoc.key_holder(prop(row, "security", "ft-nas-identifier")),
                reassociation_deadline_ms=_ms(prop(row, "security", "ft-reassociation-deadline")),
            )
        dtim = _int(prop(row, "configuration", "dtim-period"))
        if dtim is not None and 1 <= dtim <= 255:
            out["dtim_period"] = dtim
        beacon = _int(prop(row, "configuration", "beacon-interval"))
        if beacon is not None and beacon > 0:
            out["beacon_interval_ms"] = beacon
        limit = _int(prop(row, "configuration", "max-clients"))  # (guess)
        if limit is not None and limit >= 0:
            out["max_clients"] = limit
        low = wifi_assoc.min_signal(access_list, name)
        if low is not None:
            out["min_rssi_dbm"] = low
        return out

    async def _client_counts(
        self, radios: dict[str, Radio], masters: dict[str, str], endpoint: str
    ) -> None:
        """``client_count`` of every radio from the registration table (#172): the stations
        of its interfaces and their virtual ones. Not readable: not reported."""
        table = await self._readable(endpoint)
        if table is None:
            return
        counts = dict.fromkeys(radios, 0)
        for row in table:
            radio = masters.get(_text(row.get("interface")))
            if radio in counts:
                counts[radio] += 1
        for name, count in counts.items():
            radios[name] = radios[name].model_copy(update={"client_count": count})

    async def _wifi_capabilities(
        self, radios: dict[str, Radio], by_name: dict[str, dict[str, Any]]
    ) -> None:
        """What each radio supports, from ``/interface/wifi/radio`` (#172): ``bands``,
        ``2g-channels``/``5g-channels``, ``tx-chains``/``rx-chains``; matched by ``interface``
        or by the radio's MAC address *(guess: field names)*. Missing or refused: unreported."""
        table = await self._readable(WIFI_RADIO)
        if not table:
            return
        by_mac = {_text(r.get("mac-address")).lower(): n for n, r in by_name.items()}
        for row in table:
            name = _text(row.get("interface")) or by_mac.get(_text(row.get("radio-mac")).lower())
            radio = radios.get(name or "")
            if radio is None:
                continue
            key = {Band.GHZ_2_4: "2g-channels", Band.GHZ_5: "5g-channels"}.get(radio.band, "")
            prefix = {Band.GHZ_2_4: "2ghz", Band.GHZ_5: "5ghz", Band.GHZ_6: "6ghz"}[radio.band]
            bands = [b for b in _names(row.get("bands")) if b.lower().startswith(prefix)]
            channels = channels_of(row.get(key), radio.band) if key else None
            tx, rx = _names(row.get("tx-chains")), _names(row.get("rx-chains"))
            update: dict[str, Any] = {
                "standards": standards_of(",".join(bands)) or None,
                "supported_channels": channels,
                "antennas": f"{len(tx)}x{len(rx)}" if tx and rx else None,
            }
            if radio.band is Band.GHZ_5 and channels is not None:
                update["dfs_capable"] = any(52 <= c <= 144 for c in channels)
            radios[radio.name] = radio.model_copy(
                update={k: v for k, v in update.items() if v is not None}
            )

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
                standard=standard_of(row.get("band")),
                channel_auto=_text(row.get("frequency")) in ("", "auto"),
                vendor_extra=_extra(row, "band", "frequency", "channel-width"),
            )
        masters = {
            _text(r.get("name")): _text(r.get("master-interface")) or _text(r.get("name"))
            for r in rows
        }
        await self._client_counts(radios, masters, WIRELESS_REGISTRATION)
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
                    bssid=_mac(row.get("mac-address")),
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
        stations = [
            (_text(r.get("name")), masters[_text(r.get("name"))], _text(r.get("mode")))
            for r in rows
            if _text(r.get("name"))
        ]
        peers, member = await self._station_peers(layout, stations, radios, WIRELESS_REGISTRATION)
        wds = await self._wds_peers(layout, masters, radios)
        if wds:
            peers = [*peers, *wds]
            member = member or {dev: MeshMembership(role=MeshRole.AGENT)}
        return Observation(radios=list(radios.values()), wlans=wlans, mesh_peers=peers, mesh=member)

    async def _wds_peers(
        self, layout: _Layout, masters: dict[str, str], radios: dict[str, Radio]
    ) -> list[MeshPeer]:
        """The WDS stations of an access point (#475, ``wireless`` package; the ``wifi`` package
        has no WDS): registration rows marked ``wds`` or whose address is the ``wds-address`` of
        an entry of ``/interface/wireless/wds`` (dynamic or static). Signal and rates are the
        row's. The port is the access point interface the WDS interface belongs to
        (``master-interface``). *(Guess, #21: the ``wds`` column of the registration table.)*"""
        dev = self.context.device_id
        entries = {
            addr: _text(r.get("master-interface")) or _text(r.get("name"))
            for r in await self._optional_rows(WIRELESS_WDS)
            if (addr := _mac(r.get("wds-address"))) is not None
        }
        peers: list[MeshPeer] = []
        for row in await self._readable(WIRELESS_REGISTRATION) or []:
            mac = _mac(row.get("mac-address"))
            if mac is None or not (_flag(row.get("wds")) or mac in entries):
                continue
            name = entries.get(mac) or _text(row.get("interface"))
            port = layout.port(name) or layout.port(_text(row.get("interface")))
            if port is None:
                continue
            radio = radios.get(masters.get(name, name))
            tx, rx = wifi_assoc.rate(row.get("tx-rate"))[0], wifi_assoc.rate(row.get("rx-rate"))[0]
            peers.append(
                MeshPeer(
                    id=object_id(dev, "meshpeer", f"{name}-{mac}"),
                    device_id=dev,
                    port_id=port,
                    peer_mac=mac,
                    role=MeshPeerRole.DOWNLINK,
                    wireless=WirelessLinkInfo(
                        band=radio.band if radio else None,
                        channel=radio.channel if radio else None,
                        signal_dbm=wifi_assoc.signal(row.get("signal", row.get("signal-strength"))),
                        tx_rate_mbps=tx,
                        rx_rate_mbps=rx,
                        kind=MeshLinkKind.WDS,
                    ),
                )
            )
        return peers

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
        fdb: dict[str, FdbEntry] = {}
        for row in await self._rows(BRIDGE_HOST):
            on = _text(row.get("on-interface")) or _text(row.get("interface"))
            vid = _int(row.get("vid"))
            bridge = _text(row.get("bridge"))
            filtering = bridge in layout.filtering
            seg = self._seg(vid) if filtering and vid else None
            mac, port = _mac(row.get("mac-address")), layout.port(on)
            if mac is not None and port is not None and not int(mac[:2], 16) & 1:
                vlan = vid if filtering else None
                kind = (
                    FdbKind.SELF
                    if _flag(row.get("local"))
                    else FdbKind.DYNAMIC
                    if _flag(row.get("dynamic"))
                    else FdbKind.STATIC
                )
                entry_seg = seg if filtering else layout.l3.get(bridge)
                fid = fdb_id(dev, on, mac, vlan)
                fdb[fid] = FdbEntry(
                    id=fid,
                    device_id=dev,
                    port_id=port,
                    mac=mac,
                    vlan=vlan,
                    segment_id=entry_seg if entry_seg in layout.segments else None,
                    kind=kind,
                    age_seconds=duration(row.get("age")),
                )
            if not _flag(row.get("local")):
                add(mac, seen_on=port, segment=seg)
        owners = await self._cap_owners()  # CAPsMAN: clients of a CAP's interface (#481)
        masters = {
            _text(r.get("name")): _text(r.get("master-interface"))
            for r in [
                *(await self._readable(WIFI) or []),
                *(await self._readable(capsman.CAP_INTERFACE_LEGACY) or []),
            ]
            if _text(r.get("master-interface")) not in ("", "none")
        }
        for endpoint in (WIFI_REGISTRATION, WIRELESS_REGISTRATION, capsman.CAP_REGISTRATION_LEGACY):
            for row in await self._optional_rows(endpoint):
                iface = _text(row.get("interface"))
                mac = _mac(row.get("mac-address"))
                if mac is not None and mac not in own and iface:
                    ap = owners.get(iface, dev)
                    add(mac, segment=layout.port_segment.get(iface) if ap == dev else None)
                    seen[mac]["seen_on"] = object_id(ap, "wlan", iface)
                    seen[mac]["wireless"] = wifi_assoc.association(
                        row,
                        radio_id=(
                            object_id(ap, "radio", masters.get(iface, iface)) if ap != dev else None
                        ),
                        wlan_id=object_id(ap, "wlan", iface),
                        band=band_of(row.get("band")),
                        standard=standard_of(row.get("band")),
                    )

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
                wireless=e.get("wireless"),
            )
            for mac, e in sorted(seen.items())
        ]
        return Observation(clients=clients, fdb=[fdb[k] for k in sorted(fdb)])

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
            age = _duration_s(row.get("age"))
            neighbours[nid] = Neighbour(
                id=nid,
                local_port_id=layout.ports[local].id,
                chassis_id=mac,
                remote_port=_text(row.get("interface-name")) or None,
                system_name=_text(row.get("identity")) or None,
                management_address=(
                    _text(row.get("address4")) or _text(row.get("address")) or None
                ),
                capabilities=normalise_capabilities(
                    _text(row.get("system-caps-enabled")).split(",")
                ),
                description=_text(row.get("system-description")) or None,
                protocol=protocol_of(_text(row.get("discovered-by"))),
                chassis_id_kind="mac",
                age_seconds=age,
                # RouterOS counts the age from the last update (#448)
                last_seen=(
                    None
                    if age is None
                    else datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=age)
                ),
                port_vlan=_vlan_id(row.get("vlan-id")),
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
            more, gaps = await self._ipsec_openvpn()
            return Observation(tunnels=more, incomplete=gaps)
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
        more, gaps = await self._ipsec_openvpn()
        return Observation(tunnels=[*tunnels, *more], incomplete=gaps)

    async def _vpn_menu(
        self, endpoint: str, gaps: list[Gap], optional: bool = True
    ) -> list[dict[str, Any]] | None:
        """A VPN menu without anything that can hold a secret (:func:`vpn_reader.clean`); read
        without the cache so that none is kept. None: the menu does not exist (404; package or
        version) or the group may not read it (an optional gap, #153)."""
        try:
            data = await get_menu(self.http, endpoint)
            if isinstance(data, dict):
                data = [data]
            return vpn_reader.clean(_rows(data, endpoint))
        except NotFound:
            return None
        except AdapterError as exc:
            gaps.append(
                Gap(
                    message=f"VPN ({endpoint}): {exc}",
                    fix="Give the API user's group the read policy, or ignore: IPsec and "
                    "OpenVPN are then not checked.",
                    optional=optional,
                    message_id="mikrotik.vpnGap",
                    fix_id="mikrotik.vpnGap.fix",
                    params={"path": endpoint, "cause": str(exc)},
                )
            )
            return None

    async def _ipsec_openvpn(self) -> tuple[list[Tunnel], list[Gap]]:
        """IPsec peers (identity, profile, proposals, policies, active peers) and the OpenVPN
        server and clients (#153), see :mod:`vpn`."""
        d = self.context.device_id
        gaps: list[Gap] = []
        out: list[Tunnel] = []
        peers = await self._vpn_menu(vpn_reader.PEERS, gaps)
        if peers is not None:
            identities = await self._vpn_menu(vpn_reader.IDENTITIES, gaps) or []
            profiles = await self._vpn_menu(vpn_reader.PROFILES, gaps) or []
            proposals = await self._vpn_menu(vpn_reader.PROPOSALS, gaps) or []
            policies = await self._vpn_menu(vpn_reader.POLICIES, gaps) or []
            active = await self._vpn_menu(vpn_reader.ACTIVE, gaps)
            out += vpn_reader.ipsec_tunnels(
                d, peers, identities, profiles, proposals, policies, active, datetime.now(UTC)
            )
        server = await self._vpn_menu(vpn_reader.OVPN_SERVER, gaps)
        clients = await self._vpn_menu(vpn_reader.OVPN_CLIENTS, gaps)
        if server or clients:
            sessions = await self._vpn_menu(vpn_reader.OVPN_SESSIONS, gaps) or []
            out += vpn_reader.openvpn_tunnels(
                d, server[0] if server else None, sessions, clients or []
            )
        return out, list({g.message: g for g in gaps}.values())

    async def trace(self, target: Any, max_hops: int, wait: float) -> TraceAnswer:
        """``/tool/traceroute`` once (#253); needs the group policy ``test``."""
        body = _trace.request_body(target, max_hops, wait)
        response = await self.http.request("POST", _trace.TRACEROUTE, json=body, accept=(400, 500))
        if response.status_code >= 400:
            exc = ros_error(_trace.TRACEROUTE, response)
            if isinstance(exc, AuthFailed):
                raise AuthFailed(
                    f"{_trace.TRACEROUTE}: the user's group may not run traceroutes, it needs the "
                    f"policy test ({exc})",
                    fix="Give the group of Signalbox's user the policy test (System > Users > "
                    "Groups), or use Fix it on the device page while path traces are on.",
                    remedy="policies",
                    message_id="mikrotik.traceDenied",
                    fix_id="mikrotik.traceDenied.fix",
                    params={"path": _trace.TRACEROUTE, "cause": str(exc)},
                ) from None
            raise exc
        try:
            answer = response.json()
        except ValueError as e:
            raise AdapterError(
                f"{_trace.TRACEROUTE}: answer is not valid JSON",
                message_id="transport.notJson",
                params={"path": _trace.TRACEROUTE},
            ) from e
        return _trace.parse(answer, target, max_hops)

    async def read_firewall(self) -> Observation:
        """Packet filter and NAT (#135): ``/ip/firewall/filter`` and ``nat``,
        ``/ipv6/firewall/filter``, ``raw`` (a drop there makes the list incomplete), interface
        lists as zones and address lists, with the read-only group of the setup guide."""
        layout = await self._layout()
        dev = self.context.device_id
        filter4 = await self._rows(FW_FILTER)
        filter6 = await self._optional_rows(FW_FILTER6)  # no ipv6 package
        nat_rows = await self._optional_rows(FW_NAT)
        # a menu the group may not read (``ipsec``, ``raw`` can need more than ``read``) is
        # not known: raw rules then count as a drop, IPsec policies as present
        raw = await self._readable(FW_RAW)
        if raw is None:
            raw = [{"action": "drop"}]
        entries = [
            *await self._optional_rows(FW_ADDRESS_LIST),
            *await self._optional_rows(FW_ADDRESS_LIST6),
        ]
        lists = _firewall.Lists.build(
            await self._optional_rows(INTERFACE_LIST),
            await self._optional_rows(LIST_MEMBER),
            entries,
        )
        # a template policy is no IPsec traffic; without a real one ``ipsec-policy`` rules
        # (the defaults of RouterOS have some) can never match
        policies = await self._readable(IPSEC_POLICY)
        lists.ipsec = policies is None or any(
            _active(p) and not _flag(p.get("template")) and not _flag(p.get("dynamic"))
            for p in policies
        )
        uplinks = {u.name: u.id for u in await self._uplinks(layout) if u.name}

        def mapper(name: str) -> _firewall.Mapped | None:
            seg = layout.l3.get(name) or layout.port_segment.get(name)
            port = layout.ports.get(name)
            tunnel = (
                [object_id(dev, "tunnel", name)]
                if port is not None and port.vendor_extra.get("type") in ("wg", "wireguard")
                else []
            )
            up = [uplinks[name]] if name in uplinks else []
            bare = [port.id] if port is not None and not (seg or up or tunnel) else []
            if not (seg or up or tunnel or bare):
                return None
            return ([seg] if seg else []), up, tunnel, bare

        built = _firewall.build(dev, lists, mapper, filter4, filter6, nat_rows, raw)
        return Observation(firewalls=[built])

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


#: ``/system/package/update`` ``channel`` (RouterOS 7; older 7.x name it the same way).
_CHANNELS = {
    "stable": FirmwareChannel.STABLE,
    "long-term": FirmwareChannel.LONG_TERM,
    "testing": FirmwareChannel.TESTING,
    "development": FirmwareChannel.DEVELOPMENT,
}
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


def user_privilege(policy: Any) -> AccountPrivilege:
    """The privilege of a ``/user/group`` policy list: ``policy`` (manage users) with
    ``write`` is admin, ``write`` alone write, ``read`` alone read. ``!write`` is a policy
    the group does not have (older RouterOS lists them)."""
    have = {p for p in _names(policy) if not p.startswith("!")}
    if "write" in have and "policy" in have:
        return AccountPrivilege.ADMIN
    if "write" in have:
        return AccountPrivilege.WRITE
    if "read" in have:
        return AccountPrivilege.READ
    return AccountPrivilege.OTHER


def login_time(value: Any) -> datetime | None:
    """``last-logged-in`` of a user: ``2026-11-20 10:11:12`` (RouterOS 7.10 and later) or
    ``nov/20/2026 10:11:12``, the device's local time (taken as UTC: a day's precision is
    enough for ``account.stale``); absent or empty: never."""
    day, _, clock = _text(value).partition(" ")
    when = clock_date(day)
    m = _CLOCK.fullmatch(clock.strip())
    if when is None or m is None:
        return None
    hour, minute, second = map(int, m.groups())
    return datetime(when.year, when.month, when.day, hour, minute, second, tzinfo=UTC)


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
