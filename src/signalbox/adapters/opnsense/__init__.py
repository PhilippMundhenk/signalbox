"""OPNsense: reads interfaces and VLANs, DHCP (Kea and ISC), Unbound DNS, ARP/NDP clients,
WireGuard tunnels; writes router interfaces, VLANs on ports, Kea DHCP subnets and reservations.

Talks to the OPNsense REST API with an API key and secret (HTTP basic auth) over HTTPS with a
pinned certificate (:mod:`signalbox.adapters.https`). Endpoint paths and the JSON shapes assumed
for them are listed in ``docs/adapters/opnsense.md``; they are taken from the public API
documentation and still need confirmation on a real device.

Parsing is defensive: missing fields never crash, unknown fields are ignored, and an answer of
the wrong shape raises ``AdapterError("unexpected answer from <endpoint>: ...")``.

Writing (:mod:`signalbox.adapters.opnsense.write` plans the calls): the API has no
confirm-or-revert timer, so ``apply`` returns no deadline; the backup is the newest revision of
the configuration history (``config.xml``) and ``restore`` reverts to that revision.

Segments: an assigned VLAN interface is segment ``<site>/segment/<tag>`` (its parent port
tagged), the untagged LAN is the native segment, any other untagged assigned interface (a DMZ
on its own port) is ``<site>/segment/<identifier>``. The WAN interface is the uplink, not a
segment of the site: it appears as a port only.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv6Network, ip_address, ip_interface, ip_network
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from pydantic import Field, SecretStr, field_validator, model_validator

from signalbox.adapters import Adapter as _Adapter
from signalbox.adapters import (
    AdapterConfig,
    AdapterContext,
    AdapterError,
    AdminLogin,
    ApplyResult,
    AuthFailed,
    Backup,
    Capability,
    Described,
    Gap,
    Manifest,
    Observation,
    PreviewStep,
    RemedyRequest,
    SetupExtra,
    SetupPlan,
    SetupRequest,
    SetupResult,
    SshOption,
    SystemInfo,
    TraceAnswer,
    TraceSupport,
    VendorCall,
    unexpected_answer,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.opnsense import compat, provision, vitals
from signalbox.adapters.opnsense import discovery as _discovery
from signalbox.adapters.opnsense import firewall as fw
from signalbox.adapters.opnsense import routes as route_reader
from signalbox.adapters.opnsense import trace as _trace
from signalbox.adapters.opnsense import write as w
from signalbox.adapters.opnsense.certificates import CA_PRIVILEGE, CERT_PRIVILEGE, issuer_names
from signalbox.adapters.opnsense.certificates import parse as parse_certificates
from signalbox.adapters.ssh import PinnedSsh
from signalbox.changes import FIREWALL_KINDS, Change, ChangeKind
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
    DNS_PORT,
    LOG_PORTS,
    SERVICE_PORTS,
    WIREGUARD_KEY,
    AccountPrivilege,
    AddressSource,
    Certificate,
    Client,
    DeviceAccount,
    DeviceRole,
    DhcpBoot,
    DhcpLease,
    DhcpOption,
    DhcpPool,
    DhcpRelay,
    DhcpRoute,
    DhcpServer,
    DnsForwarder,
    DnsService,
    Firmware,
    HostRecord,
    IPAddress,
    IPInterface,
    IPNetwork,
    LeaseState,
    LogKind,
    LogTarget,
    LogTransport,
    ManagementService,
    Membership,
    Port,
    PortKind,
    PortMedia,
    PortMembership,
    PortRole,
    Reservation,
    Route,
    Segment,
    ServiceKind,
    SnmpSettings,
    SnmpVersion,
    Subnet,
    Tunnel,
    TunnelPeer,
    Uplink,
    UplinkKind,
    normalise_mac,
    object_id,
    port_id,
    segment_id,
)

log = logging.getLogger(__name__)


def _listen_values(value: Any) -> list[str]:
    """A list field of the model API: ``"a,b"``, or ``{"a": {"value": "a", "selected": 1}}``."""
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, dict):
        return [str(k) for k, v in value.items() if not isinstance(v, dict) or v.get("selected")]
    return []


FIRMWARE = "/api/core/firmware/status"
INTERFACES = "/api/interfaces/overview/interfaces_info"
VLANS = "/api/interfaces/vlan_settings/search_item"
KEA = "/api/kea/dhcpv4/get"
KEA_SUBNETS = "/api/kea/dhcpv4/search_subnet"
KEA_RESERVATIONS = "/api/kea/dhcpv4/search_reservation"
KEA_LEASES = "/api/kea/leases4/search"
KEA_PEERS = "/api/kea/dhcpv4/search_peer"
DHCRELAY = "/api/dhcrelay/settings/search_relay"
DHCRELAY_DEST = "/api/dhcrelay/settings/search_dest"
ISC_STATUS = "/api/dhcpv4/service/status"
ISC_LEASES = "/api/dhcpv4/leases/search_lease"
#: The helper script of #242 (docs/adapters/opnsense.md, "ISC DHCP settings") and its path.
ISC_SCRIPT = "/usr/local/sbin/signalbox-isc-dhcp"
UNBOUND = "/api/unbound/settings/get"
HOST_OVERRIDES = "/api/unbound/settings/search_host_override"
#: The camelCase spelling of older releases (25.1 and before; later ones accept both).
HOST_OVERRIDES_CAMEL = "/api/unbound/settings/searchHostOverride"
HOST_ALIASES = "/api/unbound/settings/search_host_alias"
HOST_ALIASES_CAMEL = "/api/unbound/settings/searchHostAlias"
#: Domain overrides (split DNS) of releases that list them in a grid of their own.
DOMAIN_OVERRIDES = "/api/unbound/settings/search_domain_override"
DOMAIN_OVERRIDES_CAMEL = "/api/unbound/settings/searchDomainOverride"
#: A long grid is read page by page when the answer is shorter than its ``total``.
MAX_GRID_PAGES = 500
#: Privilege of the Unbound API (#386; a guess for the grids, the page covers ``/api/unbound/*``).
UNBOUND_PRIVILEGE = "Services: Unbound DNS (page-services-unbound)"
DNSMASQ = "/api/dnsmasq/settings/get"
ARP = "/api/diagnostics/interface/get_arp"
NDP = "/api/diagnostics/interface/get_ndp"
SYSTEM_TIME = "/api/diagnostics/system/system_time"
SYSTEM_RESOURCES = "/api/diagnostics/system/system_resources"
SYSTEM_DISK = "/api/diagnostics/system/system_disk"
SYSTEM_TEMPERATURE = "/api/diagnostics/system/system_temperature"
CPU_TYPE = "/api/diagnostics/cpu_usage/get_cpu_type"
NTP_STATUS = "/api/ntpd/service/status"
NETSNMP = "/api/netsnmp/general/get"
#: Certificates and certificate authorities stored on the firewall (#330).
CERT_SEARCH = "/api/trust/cert/search"
CA_SEARCH = "/api/trust/ca/search"
#: Remote syslog destinations and NetFlow export (#180).
SYSLOG_DESTINATIONS = "/api/syslog/settings/search_destinations"
NETFLOW = "/api/diagnostics/netflow/getconfig"
#: The user manager (#175): no read-only privilege exists for it.
USERS = "/api/auth/user/search"
USER_KEYS = "/api/auth/user/search_api_key"
USER_GET = "/api/auth/user/get"
#: Users read in detail per observation (one request each).
MAX_ACCOUNTS = 50
#: Privileges of those two pages (core ACL), for the fix text of a refused read.
SYSLOG_PRIVILEGE = "System: Settings: Logging (page-diagnostics-logs-settings-targets)"
NETFLOW_PRIVILEGE = "Diagnostics: Netflow configuration (page-diagnostics-netflow)"
#: The user manager (#349): no read-only variant, whoever may read it may change every account.
ACCOUNTS_PRIVILEGE = "System: Access: Users (page-system-usermanager)"
#: ``wg show all dump`` as records, private and pre-shared keys left out by OPNsense itself
#: (privilege *VPN: WireGuard: Status*). No query string: the grid takes paging from POST only.
WG_SHOW = "/api/wireguard/service/show"
#: The packet filter (#135): rules (MVC, legacy and automatic ones in evaluation order),
#: aliases, interface groups, destination NAT, source NAT and one-to-one NAT.
FILTER_RULES = "/api/firewall/filter/search_rule"
ALIASES = "/api/firewall/alias/search_item"
IFACE_GROUPS = "/api/firewall/group/search_item"
DNAT_RULES = "/api/firewall/d_nat/search_rule"
SNAT_RULES = "/api/firewall/source_nat/search_rule"
ONE_TO_ONE = "/api/firewall/one_to_one/search_rule"

#: Grid endpoints page their answer; ask for everything at once.
ALL_ROWS = {"current": 1, "rowCount": -1}

_SKIP_DEVICES = ("lo", "enc", "pflog", "pfsync")
#: names OPNsense gives VLAN devices (vlan0.20, vlan01, qinq01; before 21.1 igb0_vlan20)
_VLAN_DEVICE = re.compile(r"^(vlan|qinq)\d|_vlan\d+$")
_KINDS = (
    ("bridge", PortKind.BRIDGE),
    ("lagg", PortKind.LAG),
    ("wg", PortKind.VIRTUAL),
    ("ovpn", PortKind.VIRTUAL),
    ("tun", PortKind.VIRTUAL),
    ("gif", PortKind.VIRTUAL),
    ("gre", PortKind.VIRTUAL),
    ("pppoe", PortKind.VIRTUAL),
)
#: device name prefixes of tunnels (role ``tunnel``, #252)
_TUNNEL_PREFIXES = ("wg", "ovpn", "tun", "tap", "gif", "gre", "pppoe", "ipsec")
#: keys of an interface row that may list the members of a lagg or bridge
_MEMBER_KEYS = ("members", "laggport", "bridge_members")


def _members(row: dict[str, Any]) -> list[str]:
    for key in _MEMBER_KEYS:
        value = row.get(key)
        if isinstance(value, str):
            value = re.split(r"[,\s]+", value)
        if isinstance(value, list):
            return [str(v) for v in value if isinstance(v, str) and v]
    return []


def _endpoint(value: Any) -> tuple[str | None, int | None]:
    """``203.0.113.5:51820``, ``[2001:db8::1]:51820`` or ``(none)``: host and port."""
    text = _text(value)
    if not text or text == "(none)":
        return None, None
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
        return text.strip("[]") or None, None
    return host.strip("[]") or None, int(port)


def _networks(value: Any) -> list[IPNetwork]:
    """``allowed-ips``: ``2001:db8:ff::2/128,203.0.113.0/24`` (``(none)``: none)."""
    out: list[IPNetwork] = []
    for part in re.split(r"[,\s]+", _text(value)):
        with contextlib.suppress(ValueError):
            out.append(ip_network(part, strict=False))
    return out


def _wg_key(value: Any) -> str | None:
    text = _text(value)
    return text if re.fullmatch(WIREGUARD_KEY, text) else None


def wireguard_tunnels(
    rows: list[dict[str, Any]],
    device_id: str,
    interfaces: dict[str, dict[str, Any]],
) -> list[Tunnel]:
    """Tunnels from the records of ``/api/wireguard/service/show`` (#239).

    One ``interface`` record per running instance (``if``, ``public-key``, ``listen-port``,
    ``status`` up/down from ifconfig, ``name`` the instance name) and one ``peer`` record per
    peer (``public-key``, ``endpoint``, ``allowed-ips``, ``latest-handshake`` as epoch seconds,
    0 for none, ``transfer-rx``/``-tx``, ``persistent-keepalive`` seconds or ``off``, ``name``).
    Addresses and MTU come from the interface overview row of the same device (``interfaces``).
    """
    by_if: dict[str, dict[str, Any]] = {}
    peers: dict[str, list[TunnelPeer]] = {}
    for row in rows:
        ifname = _text(row.get("if"))
        kind = _text(row.get("type"))
        if not ifname:
            continue
        if kind == "interface":
            by_if.setdefault(ifname, row)
        elif kind == "peer":
            key = _wg_key(row.get("public-key"))
            if key is None or any(p.public_key == key for p in peers.get(ifname, [])):
                continue
            host, port = _endpoint(row.get("endpoint"))
            stamp = _int(row.get("latest-handshake"))
            keepalive = _text(row.get("persistent-keepalive"))
            peers.setdefault(ifname, []).append(
                TunnelPeer(
                    public_key=key,
                    name=_text(row.get("name")) or None,
                    endpoint_host=host,
                    endpoint_port=port if host else None,
                    allowed_ips=_networks(row.get("allowed-ips")),
                    latest_handshake=datetime.fromtimestamp(stamp, UTC) if stamp else None,
                    rx_bytes=_int(row.get("transfer-rx")),
                    tx_bytes=_int(row.get("transfer-tx")),
                    keepalive_seconds=0 if keepalive == "off" else _int(keepalive),
                )
            )
    out = []
    for ifname in sorted(set(by_if) | set(peers)):
        row = by_if.get(ifname, {})
        overview = interfaces.get(ifname, {})
        status = _text(row.get("status")) or _text(overview.get("status")).lower()
        mtu = _int(overview.get("mtu"))
        listen = _int(row.get("listen-port"))
        out.append(
            Tunnel(
                id=object_id(device_id, "tunnel", ifname),
                device_id=device_id,
                name=ifname,
                description=_text(row.get("ifname")) or _text(row.get("name")) or None,
                port_id=port_id(device_id, ifname) if overview else None,
                up=(status == "up") if status else None,
                listen_port=listen if listen and 1 <= listen <= 65535 else None,
                public_key=_wg_key(row.get("public-key")),
                addresses=_iface_addresses(overview),
                mtu=mtu if mtu is not None and 68 <= mtu <= 65535 else None,
                peers=peers.get(ifname, []),
            )
        )
    return out


class OpnsenseConfig(AdapterConfig):
    url: str = Field(
        description="Address of the web interface, for example 192.0.2.1 or "
        "https://opnsense.lan:8443 (no scheme: https)",
        examples=["192.0.2.1"],
    )
    api_key: SecretStr = Field(
        description="API key of a dedicated API user (read-only unless writes are allowed)"
    )
    api_secret: SecretStr = Field(description="API secret belonging to the key")
    allow_insecure_http: bool = Field(
        json_schema_extra={"advanced": True},
        default=False,
        description="Allow plain http:// (simulators and tests only: sends the key unencrypted)",
    )
    isc_ssh_key: SecretStr | None = Field(
        json_schema_extra={"advanced": True},
        default=None,
        description="Optional: private SSH key whose authorized_keys entry on the firewall forces "
        "the helper script signalbox-isc-dhcp (ISC DHCP settings have no API; see the setup "
        "guide). Without it only the ISC leases are read.",
    )
    isc_ssh_host_key: str | None = Field(
        json_schema_extra={"advanced": True},
        default=None,
        description="SSH host key fingerprint of the firewall (SHA256:...): the key is only used "
        "for a firewall that presents it (without it nothing is read over SSH)",
    )
    isc_ssh_port: int = Field(
        json_schema_extra={"advanced": True}, default=22, ge=1, le=65535, description="SSH port"
    )
    isc_ssh_user: str = Field(
        json_schema_extra={"advanced": True},
        default="root",
        pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$",
        description="User whose authorized_keys holds the forced command",
    )

    @field_validator("isc_ssh_key")
    @classmethod
    def _key_text(cls, value: SecretStr | None) -> SecretStr | None:
        """A PEM key pasted into a one-line field has lost its line breaks: restore them."""
        if value is None or not value.get_secret_value().strip():
            return None
        m = re.match(
            r"^\s*(-----BEGIN [A-Z ]+-----)(.*?)(-----END [A-Z ]+-----)\s*$",
            value.get_secret_value(),
            re.S,
        )
        if m is None:  # not checked here (the setup validates the form with a placeholder)
            return value
        body = "".join(m.group(2).split())
        lines = [body[i : i + 70] for i in range(0, len(body), 70)]
        return SecretStr("\n".join([m.group(1), *lines, m.group(3)]) + "\n")

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return device_url(value)

    @model_validator(mode="after")
    def _http_needs_opt_in(self) -> OpnsenseConfig:
        if self.url.startswith("http://") and not self.allow_insecure_http:
            raise ValueError("plain http:// needs allow_insecure_http (simulators only)")
        return self


# --- defensive parsing helpers ---------------------------------------------------------------


def _unexpected(endpoint: str, what: str) -> AdapterError:
    return unexpected_answer(endpoint, what)


def _dict(value: Any, endpoint: str, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _unexpected(endpoint, f"{what} is {type(value).__name__}, expected an object")
    return value


def _rows(data: Any, endpoint: str) -> list[dict[str, Any]]:
    """Rows of a grid answer (``{"rows": [...]}``) or a plain list; non-objects are dropped."""
    rows = data.get("rows") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise _unexpected(endpoint, "no list of rows")
    return [r for r in rows if isinstance(r, dict)]


def _items(value: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """Entries of an OPNsense array field: ``{uuid: {...}}`` (or a list)."""
    if isinstance(value, dict):
        yield from ((str(k), v) for k, v in value.items() if isinstance(v, dict))
    elif isinstance(value, list):
        yield from ((str(i), v) for i, v in enumerate(value) if isinstance(v, dict))


def _sub(parent: dict[str, Any], key: str) -> dict[str, Any]:
    """A nested object, or an empty one when it is missing or not an object."""
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


def _flag(value: Any) -> bool:
    return value in (True, 1, "1", "true", "yes", "on", "enabled")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _privilege_gap(what: str, exc: AdapterError, privilege: str) -> Gap:
    return Gap(
        message=f"{what}: {exc}",
        fix=f"Give the API user the privilege {privilege}, or use Fix it on the device page.",
        remedy="privileges",
        optional=True,
        message_id="opnsense.privilegeGap",
        fix_id="opnsense.privilegeGap.fix",
        params={"what": what, "cause": str(exc), "privilege": privilege},
    )


#: OPNsense API reference of the firewall (the filter pages and what they list).
RULES_DOC = "https://docs.opnsense.org/development/api/core/firewall.html"


def _rules_gap() -> Gap:
    """The rule list is empty or has no ``sort_order`` (#379): this release's filter API lists
    only the rules of *Firewall: Automation: Filter*, not those of the classic *Firewall: Rules*
    pages (guess for 25.x, 26.7 lists them) or the automatic ones. Optional: no privilege is
    missing; the zone matrix and the reachability stay "unknown"."""
    return Gap(
        message="firewall rules: the filter API of this OPNsense lists no rules of the classic "
        "Firewall: Rules pages (legacy rules), so reachability is not checked exactly",
        fix="Optional: no privilege is missing (Firewall: Rules [new], page-filter-api, is "
        "enough). Create the rules on Firewall: Automation: Filter, or use a release that "
        f"lists the legacy rules (26.7 does); see {RULES_DOC}.",
        optional=True,
        message_id="opnsense.rulesIncomplete",
        fix_id="opnsense.rulesIncomplete.fix",
        params={"doc": RULES_DOC},
    )


def _forwards_gap(version: compat.Version | None) -> Gap:
    """The destination NAT page has no API (404): OPNsense before 26.1 keeps port forwards on
    the classic page (#390). Optional: the forwards stay unread, the rest of the firewall is."""
    where = f"OPNsense {compat.release(version)}" if version else "this OPNsense"
    return Gap(
        message=f"port forwards: not readable on {where}, its API has no destination NAT "
        "(the page is classic; 26.1 and newer have it)",
        fix="Optional: nothing to grant. Port forwards are shown once OPNsense is updated to "
        "26.1 or newer.",
        optional=True,
        message_id="opnsense.forwardsUnread",
        fix_id="opnsense.forwardsUnread.fix",
        params={"where": where},
    )


def _fqdn(host: Any, domain: Any) -> str:
    """``host.domain``; a wildcard host (``*``) is the domain itself."""
    h = _text(host)
    return ".".join(x for x in (h if h != "*" else "", _text(domain)) if x)


def _accounts_gap(exc: AdapterError) -> Gap:
    """The user manager could not be read (#349): optional, naming the privilege and what it
    allows (it has no read-only variant)."""
    return Gap(
        message=f"accounts: {exc}",
        fix="Optional, only if Signalbox should list the accounts: give the API user the "
        f"privilege {ACCOUNTS_PRIVILEGE} (or tick the accounts extra of the automatic "
        "setup). OPNsense has no read-only variant: that user can then also change every "
        "account.",
        optional=True,
        message_id="opnsense.accounts",
        fix_id="opnsense.accounts.fix",
        params={"cause": str(exc), "privilege": ACCOUNTS_PRIVILEGE},
    )


def _selected(value: Any) -> list[str]:
    """Selected keys of an option field ``{key: {"value": ..., "selected": 1}}`` (or a CSV)."""
    if isinstance(value, dict):
        return [k for k, v in value.items() if isinstance(v, dict) and _flag(v.get("selected"))]
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []


def _addr(value: Any) -> IPAddress | None:
    text = _text(value).split("%")[0]
    try:
        return ip_address(text)
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    """A port field: None when empty, zero or out of range."""
    port = _int(value)
    return port if port and port <= 65535 else None


def _addrs(value: Any) -> list[IPAddress]:
    parts = value if isinstance(value, list) else re.split(r"[,\s]+", _text(value))
    return [a for a in (_addr(p) for p in parts) if a is not None]


def _mac(value: Any) -> str | None:
    try:
        return normalise_mac(_text(value))
    except ValueError:
        return None


_ISC_STATES = {
    "active": LeaseState.ACTIVE,
    "expired": LeaseState.EXPIRED,
    "free": LeaseState.EXPIRED,
    "backup": LeaseState.EXPIRED,
    "abandoned": LeaseState.DECLINED,
}
_ROUTE = re.compile(r"(\d+\.\d+\.\d+\.\d+/\d+)\D+?(\d+\.\d+\.\d+\.\d+)")


def _when(value: Any) -> datetime | None:
    """An epoch (number or text) or an ISC date (``2026/11/22 10:00:00``, UTC) as UTC time."""
    number = _int(value)
    if number is not None:
        return datetime.fromtimestamp(number, UTC) if number > 0 else None
    text = _text(value)
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _valid_route(destination: str, gateway: str) -> bool:
    try:
        return (
            ip_network(destination, strict=False).version == 4 and ip_address(gateway).version == 4
        )
    except ValueError:
        return False


def _segment_key(segment: str) -> str:
    key = segment.rsplit("/", 1)[-1]
    return "lan" if key == "native" else key


def _kea_lease(row: dict[str, Any]) -> DhcpLease | None:
    address = _addr(row.get("address"))
    mac, client_id = _mac(row.get("hwaddr")), _text(row.get("client_id")) or None
    if address is None or (mac is None and client_id is None):
        return None
    expires = _when(row.get("expire"))
    lifetime = _int(row.get("valid_lifetime"))
    state = {0: LeaseState.ACTIVE, 1: LeaseState.DECLINED, 2: LeaseState.EXPIRED}.get(
        _int(row.get("state")) or 0, LeaseState.ACTIVE
    )
    return DhcpLease(
        address=address,
        mac=mac,
        client_id=client_id,
        hostname=_text(row.get("hostname")) or None,
        state=state,
        starts=expires - timedelta(seconds=lifetime) if expires and lifetime else None,
        expires=expires,
    )


def _isc_lease(row: dict[str, Any]) -> DhcpLease | None:
    address, mac = _addr(row.get("address")), _mac(row.get("mac"))
    if address is None or mac is None:
        return None
    static = _text(row.get("type")) == "static"
    raw = _text(row.get("state")).lower()
    state = _ISC_STATES.get(raw, LeaseState.RESERVED if static else LeaseState.ACTIVE)
    return DhcpLease(
        address=address,
        mac=mac,
        hostname=_text(row.get("hostname")) or None,
        state=state,
        reserved=static,
        starts=_when(row.get("starts")),
        expires=_when(row.get("ends")),
    )


def _vlanif(value: Any) -> str:
    """The VLAN device name; the VLAN list appends ``[<interface>]`` once it is assigned."""
    return re.sub(r"\s*\[.*\]$", "", _text(value))


def _nest(row: dict[str, Any]) -> dict[str, Any]:
    """A grid row with dotted names (``option_data.routers``) as nested objects."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        *parents, last = str(key).split(".")
        target = out
        for part in parents:
            target = target.setdefault(part, {})
            if not isinstance(target, dict):
                break
        else:
            target[last] = value
    return out


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = _text(value)
    return int(text) if text.isdigit() else None


def _iface_addresses(row: dict[str, Any]) -> list[IPInterface]:
    out: list[IPInterface] = []
    for key in ("ipv4", "ipv6"):
        entries = row.get(key)
        for entry in entries if isinstance(entries, list) else []:
            text = entry.get("ipaddr") if isinstance(entry, dict) else entry
            try:
                addr = ip_interface(_text(text).split("%")[0])
            except ValueError:
                continue
            if addr.ip.is_link_local or addr.ip.is_loopback:
                continue
            out.append(addr)
    return out


def _speed(media: str) -> tuple[int | None, bool | None]:
    match = re.search(r"(\d+)(G?)base", media, re.IGNORECASE)
    speed = None
    if match:
        speed = int(match.group(1)) * (1000 if match.group(2) else 1)
    duplex = True if "full-duplex" in media else False if "half-duplex" in media else None
    return speed, duplex


def max_speed(supported: Any) -> int | None:
    """Fastest entry of ``supported_media`` (``["autoselect", "1000baseT <full-duplex>"]``)."""
    if not isinstance(supported, list):
        return None
    speeds = [_speed(m)[0] for m in supported if isinstance(m, str)]
    return max((s for s in speeds if s), default=None)


#: FreeBSD media words of fibre and direct-attach cages (``1000baseSX``, ``10Gbase-SR``, ...).
_OPTICAL = re.compile(r"base-?(SX|LX|LH|ZX|BX|SR|LR|ER|LRM|CX|Twinax|DAC|AOC)", re.IGNORECASE)


def media_of(row: dict[str, Any]) -> PortMedia | None:
    """Medium of a physical port from its media words: ``baseT`` copper, optics a cage."""
    words = [_text(row.get("media")), *(m for m in row.get("supported_media") or [] if m)]
    words = [w for w in words if isinstance(w, str) and "base" in w.lower()]
    if not words or row.get("is_physical") is not True:
        return None
    if any(re.search(r"base-?T(?:X|\b)", w, re.IGNORECASE) for w in words):
        return PortMedia.COPPER
    optical = [w for w in words if _OPTICAL.search(w)]
    if not optical:
        return None
    return PortMedia.SFP_PLUS if max(_speed(w)[0] or 0 for w in optical) >= 10000 else PortMedia.SFP


def autoneg_of(media_raw: Any) -> bool | None:
    """``Ethernet autoselect (1000baseT <full-duplex>)``: auto; ``Ethernet 100baseTX``: forced."""
    text = _text(media_raw)
    if not text:
        return None
    return "autoselect" in text.lower()


def _pool(text: str) -> DhcpPool | None:
    try:
        if "-" in text:
            start, end = (ip_address(x.strip()) for x in text.split("-", 1))
            return DhcpPool(start=start, end=end)
        net = ip_network(text, strict=False)
    except ValueError:
        return None
    if net.num_addresses > 2:  # without network and broadcast address
        return DhcpPool(start=net[1], end=net[-2])
    return DhcpPool(start=net[0], end=net[-1])


#: ``link_type`` of the interface overview (the IPv4 type of config.xml) -> uplink kind
_LINK_KINDS = {"dhcp": UplinkKind.DHCP, "static": UplinkKind.STATIC, "pppoe": UplinkKind.PPPOE}


def _ifctl(row: dict[str, Any], key: str) -> list[str]:
    """Values the WAN received (``ifctl.nameserver``...): file contents, one value per line."""
    value = row.get(f"ifctl.{key}")
    lines = value if isinstance(value, list) else [value]
    return [part for text in lines for part in _text(text).split()]


def _prefixes(values: Iterable[str]) -> list[IPv6Network]:
    out: list[IPv6Network] = []
    for text in values:
        try:
            net = ip_network(text, strict=False)
        except ValueError:
            continue
        if isinstance(net, IPv6Network) and net not in out:
            out.append(net)
    return out


def wan_uplink(row: dict[str, Any], device_id: str, port: str | None) -> Uplink:
    """The ``wan`` row of the interface overview as an uplink (OPNsense reports no uptime)."""
    addresses = _iface_addresses(row)
    gateways = _addrs(row.get("gateways")) or _addrs(_ifctl(row, "router"))
    status = _text(row.get("status")).lower()
    link = _text(row.get("link_type")).lower()
    kind = _LINK_KINDS.get(link, UplinkKind.OTHER)
    dns: list[IPAddress] = []
    for a in _addrs(_ifctl(row, "nameserver")):
        if a not in dns:
            dns.append(a)
    return Uplink(
        id=object_id(device_id, "uplink", "wan"),
        device_id=device_id,
        port_id=port,
        name=_text(row.get("description")) or "WAN",
        kind=kind,
        up=(status == "up" and bool(addresses)) if status else None,
        addresses=addresses,
        delegated_prefixes=_prefixes(_ifctl(row, "prefix")),
        upstream_gateway=gateways[0] if gateways else None,
        dns_servers=dns,
        vendor_extra={
            k: _text(row.get(k)) for k in ("link_type", "link_typev6") if _text(row.get(k))
        },
    )


# --- interface layout, shared by every capability --------------------------------------------


@dataclass
class _Iface:
    identifier: str
    device: str
    description: str
    port: str | None  # port id of the physical device (the parent for a VLAN)
    vlan: int | None
    segment: str | None  # None: WAN / not a site segment
    addresses: list[IPInterface] = field(default_factory=list)


@dataclass
class _Layout:
    ports: list[Port]
    segments: dict[str, Segment]
    ifaces: list[_Iface]

    def by_identifier(self, identifier: str) -> _Iface | None:
        return next((i for i in self.ifaces if i.identifier == identifier), None)

    def by_device(self, device: str) -> _Iface | None:
        return next((i for i in self.ifaces if i.device == device), None)

    def containing(self, address: IPAddress) -> _Iface | None:
        """Interface with the most specific network that contains the address."""
        best: tuple[int, _Iface] | None = None
        for i in self.ifaces:
            for a in i.addresses:
                if address in a.network and (best is None or a.network.prefixlen > best[0]):
                    best = (a.network.prefixlen, i)
        return best[1] if best else None

    def own_macs(self) -> set[str]:
        return {p.mac for p in self.ports if p.mac}


#: Shown in the device form ("Before you add it").
OPNSENSE_STEPS = (
    (
        "System > Access > Users: add a user 'signalbox' with a scrambled password and no "
        "groups; give it the privileges listed in the setup guide."
    ),
    (
        "In that user, under API keys, create a key: the browser downloads a file with key and "
        "secret."
    ),
    (
        "Below: the firewall's address, the key and the secret. Then Test connection and trust "
        "the certificate (compare it with System > Trust > Certificates)."
    ),
)


class _ApiHttp(DeviceHttp):
    """Every request uses the action spelling of the release's ACL and, on a 404, the other one
    once more (#390). 26.7 and 25.7 want ``snake_case`` (also while the release is not known),
    up to 25.1 the privileges name the actions in camelCase and refuse the other spelling with
    a 403 (:data:`compat.SNAKE_ACL`)."""

    camel_first = False

    async def request(
        self, method: str, path: str, *, accept: Collection[int] = (), **kw: Any
    ) -> httpx.Response:
        camel = compat.camel_path(path)
        first, second = (camel, path) if self.camel_first else (path, camel)
        try:
            return await super().request(method, first, accept=accept, **kw)
        except NotFound:
            if second == first:
                raise
            return await super().request(method, second, accept=accept, **kw)


class OpnsenseAdapter(_Adapter):
    manifest = Manifest(
        setup_steps=OPNSENSE_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/opnsense.md#setup",
        id="opnsense",
        least_privilege=AccountPrivilege.WRITE,
        name="OPNsense",
        version="0.2.0",
        api_version="1.4",
        vendor="Deciso",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset(
            {
                Capability.INTERFACES,
                Capability.DHCP,
                Capability.DNS,
                Capability.CLIENTS,
                Capability.HEALTH,
                Capability.TIME,
                Capability.VPN,
                Capability.FIREWALL,
            }
        ),
        config=OpnsenseConfig,
        description=(
            "Reads an OPNsense firewall through its REST API; writes router interfaces, VLANs "
            "on ports, Kea DHCP (subnets, reservations) and firewall rules, port forwards and "
            "zone policies (tagged; without a rollback timer, which 26.7 does not have)."
        ),
        writes=frozenset(
            {
                ChangeKind.ROUTER,
                ChangeKind.DHCP,
                ChangeKind.RESERVATION,
                ChangeKind.PORT,
                ChangeKind.ZONE_POLICY,
                ChangeKind.FIREWALL_RULE,
                ChangeKind.PORT_FORWARD,
            }
        ),
        admin_login=AdminLogin(
            transport="the API with an API key of root",
            user_label="API key of root",
            user_default="",
            secret_label="API secret",
            note="System > Access > Users > root > API keys: + downloads a file with key and "
            "secret. Signalbox uses them once and keeps neither; delete that key afterwards.",
            ssh_option=SshOption(
                label="Also read the ISC DHCP settings (optional)",
                note="The ISC DHCP plugin's API has only leases. This installs a small "
                "read-only script, /usr/local/sbin/signalbox-isc-dhcp, that prints only the "
                "DHCP sections of config.xml (no secrets), and an SSH key that can run nothing "
                "else. Needs SSH on the firewall (System > Settings > Administration, "
                "root login). Off unless you tick it; Remove deletes both.",
            ),
            extras=[
                SetupExtra(
                    id="accounts",
                    label="Also let Signalbox list the accounts (optional)",
                    note="Gives the user the privilege System: Access: Users "
                    "(page-system-usermanager). OPNsense has no read-only variant: with it the "
                    "user, and so anyone holding its API key, can also change every account "
                    "and privilege. Off unless you tick it; without it the device page says "
                    "that the accounts are not readable.",
                )
            ],
            preview=[
                PreviewStep(id="user", title="Create the user signalbox (scrambled password)"),
                PreviewStep(id="privileges", title="Give it the privileges of the setup guide"),
                PreviewStep(id="key", title="Create a new API key for it"),
                PreviewStep(
                    id="isc-script", title="Install the read-only DHCP script", extra="ssh"
                ),
                PreviewStep(
                    id="isc-key", title="Authorize an SSH key that can run only it", extra="ssh"
                ),
                PreviewStep(
                    id="user", title="Delete the user signalbox and its API keys", remove=True
                ),
                PreviewStep(
                    id="isc-script", title="Delete the DHCP script", remove=True, extra="ssh"
                ),
                PreviewStep(
                    id="isc-key", title="Delete Signalbox's SSH key", remove=True, extra="ssh"
                ),
            ],
        ),
        remedies=provision.REMEDIES,
        traces=TraceSupport(
            permission="the privilege Diagnostics: Traceroute (page-diagnostics-traceroute)",
            method="the diagnostics API (traceroute, one ICMP probe per hop)",
        ),
    )

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """The web interface's login page, without credentials."""
        return await _discovery.discover(probe)

    @classmethod
    async def plan_setup(cls, request: SetupRequest) -> SetupPlan:
        """User, privileges and API key through the API with root's key (docs: Automatic
        setup)."""
        return await provision.OpnsenseSetup(request).plan()

    @classmethod
    async def apply_setup(cls, request: SetupRequest) -> SetupResult:
        return await provision.OpnsenseSetup(request).apply()

    @classmethod
    async def plan_remedy(cls, request: RemedyRequest) -> SetupPlan:
        """*Fix it* (#215): add the documented privileges the stored key's user lacks."""
        return await provision.OpnsenseFix(request).plan()

    @classmethod
    async def apply_remedy(cls, request: RemedyRequest) -> SetupResult:
        return await provision.OpnsenseFix(request).apply()

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        assert isinstance(cfg, OpnsenseConfig)
        self.config = cfg
        self.http = _ApiHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            auth=(cfg.api_key.get_secret_value(), cfg.api_secret.get_secret_value()),
            allow_insecure_http=cfg.allow_insecure_http,
            denied_remedy="privileges",
        )
        self._cache: dict[str, Any] = {}
        self._layout_cache: _Layout | None = None
        #: The release read from ``core/firmware/status`` (None: not read yet or unparsable).
        self._version: compat.Version | None = None

    async def close(self) -> None:
        await self.http.close()

    async def _get(self, endpoint: str, grid: bool = False) -> Any:
        """GET once per observation (DHCP and clients both need the leases, ...)."""
        if endpoint not in self._cache:
            self._cache[endpoint] = await self.http.get_json(
                endpoint, params=ALL_ROWS if grid else None
            )
        return self._cache[endpoint]

    async def _optional(self, endpoint: str, grid: bool = False) -> Any:
        """Like _get, but an endpoint that does not exist (component not installed) is None."""
        try:
            return await self._get(endpoint, grid)
        except NotFound:
            return None

    # --- system -------------------------------------------------------------------------------

    async def read_system(self) -> SystemInfo:
        # A new observation: probe the certificate again and forget the previous answers.
        await self.http.reset()
        self._cache.clear()
        self._layout_cache = None
        data = _dict(await self._get(FIRMWARE), FIRMWARE, "the answer")
        product = _sub(data, "product") or data
        current = _text(product.get("product_version"))
        if not current:
            raise _unexpected(FIRMWARE, "no product_version")
        latest = _text(product.get("product_latest"))
        # product_version carries the package revision (26.7.9_3), product_latest does not
        newer = latest and latest not in (current, current.split("_", 1)[0])
        self._set_version(compat.parse_version(current))
        return SystemInfo(
            vendor="Deciso",
            model=_text(product.get("product_name")) or "OPNsense",
            firmware=Firmware(current=current, available=latest if newer else None),
            management_address=self.http.host,
            transport_encrypted=self.http.secure,
        )

    async def _release(self) -> compat.Version | None:
        """The firmware version, read once per observation (None: not readable)."""
        if self._version is None:
            data = _dict(await self._get(FIRMWARE), FIRMWARE, "the answer")
            product = _sub(data, "product") or data
            self._set_version(compat.parse_version(_text(product.get("product_version"))))
        return self._version

    def _set_version(self, version: compat.Version | None) -> None:
        self._version = version
        self.http.camel_first = version is not None and version < compat.SNAKE_ACL

    # --- interfaces ---------------------------------------------------------------------------

    async def _layout(self) -> _Layout:
        if self._layout_cache is None:
            self._layout_cache = self._parse_layout(
                _rows(await self._get(INTERFACES, grid=True), INTERFACES),
                _rows(await self._get(VLANS, grid=True), VLANS),
            )
        return self._layout_cache

    def _parse_layout(self, rows: list[dict[str, Any]], vlan_rows: list[dict[str, Any]]) -> _Layout:
        dev, site = self.context.device_id, self.context.site_id
        vlans: dict[str, tuple[str, int, str]] = {}
        for v in vlan_rows:
            name, parent, tag = _vlanif(v.get("vlanif")), _text(v.get("if")), _int(v.get("tag"))
            if name and parent and tag is not None and 1 <= tag <= 4094:
                vlans[name] = (parent, tag, _text(v.get("descr")))

        ports: dict[str, Port] = {}
        lower_names: dict[str, list[str]] = {}
        for row in rows:
            device = _text(row.get("device"))
            if not device or device.startswith(_SKIP_DEVICES):
                continue
            if device not in vlans and row.get("vlan_tag") not in (None, "", 0, "0"):
                continue  # a VLAN the VLAN table did not list: its parent is unknown
            if not _text(row.get("identifier")) and _VLAN_DEVICE.match(device):
                # a VLAN device that is no longer configured: reverting the configuration
                # history leaves it in the kernel until the next reboot
                continue
            speed, duplex = _speed(_text(row.get("media")))
            status = _text(row.get("status")).lower()
            kind = next((k for p, k in _KINDS if device.startswith(p)), PortKind.ETHERNET)
            assigned = bool(_text(row.get("identifier")))
            enabled = row.get("enabled")
            mtu = _int(row.get("mtu"))
            role: PortRole | None = None
            if device in vlans:
                role, kind = PortRole.VLAN, PortKind.VIRTUAL
            elif kind is PortKind.BRIDGE:
                role = PortRole.BRIDGE
            elif kind is PortKind.LAG:
                role = PortRole.LAG
            elif device.startswith(_TUNNEL_PREFIXES):
                role, kind = PortRole.TUNNEL, PortKind.VIRTUAL
            elif row.get("is_physical") is True:
                role = PortRole.JACK
            ports[device] = Port(
                id=port_id(dev, device),
                device_id=dev,
                name=device,
                kind=kind,
                up=(status == "up") if status else None,
                speed_mbps=speed,
                full_duplex=duplex,
                mac=_mac(row.get("macaddr")),
                # unassigned devices have no description and no enable setting of their own;
                # a disabled interface whose device is up still carries VLANs: unknown
                description=_text(row.get("description")) if assigned else None,
                admin_up=enabled
                if assigned and isinstance(enabled, bool) and (enabled or status != "up")
                else None,
                mtu=mtu if mtu is not None and 68 <= mtu <= 65535 else None,
                max_speed_mbps=max_speed(row.get("supported_media")),
                autoneg=autoneg_of(row.get("media_raw")),
                media=media_of(row) if kind is PortKind.ETHERNET else None,
                role=role,
                vendor_extra={"identifier": _text(row["identifier"])} if assigned else {},
            )
            lower_names[device] = [vlans[device][0]] if device in vlans else _members(row)
        for device, names in lower_names.items():
            ports[device] = ports[device].model_copy(
                update={
                    "lower": [
                        port_id(dev, n) for n in dict.fromkeys(names) if n in ports and n != device
                    ]
                }
            )
        segments: dict[str, Segment] = {}

        def join(seg: str, vlan: int | None, name: str, parent: str, mode: Membership) -> None:
            members = []
            if parent in ports:
                members.append(PortMembership(port_id=port_id(dev, parent), mode=mode))
            old = segments.get(seg)
            if old is not None:
                members = [*old.members, *(m for m in members if m not in old.members)]
                name = old.name or name
            segments[seg] = Segment(
                id=seg, site_id=site, vlan=vlan, name=name or None, members=members
            )

        ifaces: list[_Iface] = []
        assigned_vlans: set[str] = set()
        for row in rows:
            device, identifier = _text(row.get("device")), _text(row.get("identifier"))
            if not device or not identifier or device.startswith(_SKIP_DEVICES):
                continue
            descr = _text(row.get("description")) or identifier.upper()
            vlan = vlans.get(device)
            if vlan is None and device not in ports:
                continue
            parent = vlan[0] if vlan else device
            seg: str | None = None
            if identifier != "wan":
                if vlan:
                    seg = segment_id(site, vlan[1])
                    join(seg, vlan[1], descr, parent, Membership.TAGGED)
                    assigned_vlans.add(device)
                else:
                    seg = (
                        segment_id(site, None)
                        if identifier == "lan"
                        else f"{site}/segment/{identifier}"
                    )
                    join(seg, None, descr, parent, Membership.UNTAGGED)
            ifaces.append(
                _Iface(
                    identifier=identifier,
                    device=device,
                    description=descr,
                    port=port_id(dev, parent) if parent in ports else None,
                    vlan=vlan[1] if vlan else None,
                    segment=seg,
                    addresses=_iface_addresses(row),
                )
            )
        for name, (parent, tag, descr) in vlans.items():
            if name not in assigned_vlans:  # defined but not assigned: still a VLAN on the port
                join(segment_id(site, tag), tag, descr, parent, Membership.TAGGED)
        return _Layout(ports=list(ports.values()), segments=segments, ifaces=ifaces)

    async def read_interfaces(self) -> Observation:
        targets, gaps = await self._log_targets()
        accounts, account_gaps = await self._accounts(self.context.device_id)
        layout = await self._layout()
        dev = self.context.device_id
        subnets = [
            Subnet(
                id=object_id(dev, "subnet", f"{i.identifier}-{a.ip}"),
                segment_id=i.segment,
                interface=a,
                device_id=dev,
                gateway=True,
            )
            for i in layout.ifaces
            if i.segment is not None
            for a in i.addresses
        ]
        wan = layout.by_identifier("wan")
        row = next(
            (
                r
                for r in _rows(await self._get(INTERFACES, grid=True), INTERFACES)
                if _text(r.get("identifier")) == "wan"
            ),
            None,
        )
        uplinks = [] if wan is None or row is None else [wan_uplink(row, dev, wan.port)]
        certificates, cert_gaps = await self._certificates()
        route_list, route_gaps = await self._routes(uplinks[0] if uplinks else None)
        gaps = [*gaps, *cert_gaps, *route_gaps]
        return Observation(
            routes=route_list,
            ports=layout.ports,
            segments=list(layout.segments.values()),
            subnets=subnets,
            uplinks=uplinks,
            services=await self._services(),
            certificates=certificates,
            log_targets={} if targets is None else {dev: targets},
            **accounts,
            incomplete=[*gaps, *account_gaps],
        )

    async def _routes(self, uplink: Uplink | None) -> tuple[list[Route], list[Gap]]:
        """Static routes, the WAN default route and the gateway status (#149). A grid the API
        user may not read is an optional gap naming its privilege. Policy routing (firewall rules
        with a gateway) is not read: documented, not a gap on every read."""
        dev = self.context.device_id
        gaps: list[Gap] = []
        known: dict[str, tuple[IPAddress | None, bool | None]] = {}
        try:
            data = await self._get(route_reader.GATEWAY_STATUS)
            items = data.get("items", []) if isinstance(data, dict) else data
            known = route_reader.gateways(_rows(items, route_reader.GATEWAY_STATUS))
        except NotFound:
            pass
        except AdapterError as exc:
            gaps.append(_privilege_gap("gateways", exc, route_reader.GATEWAY_PRIVILEGE))
        try:
            rows = _rows(await self._get(route_reader.ROUTES_SEARCH, grid=True), "routes")
        except NotFound:
            rows = []
        except AdapterError as exc:
            gaps.append(_privilege_gap("static routes", exc, route_reader.ROUTES_PRIVILEGE))
            return [], gaps
        found = route_reader.static_routes(dev, rows, known)
        default = route_reader.default_route(dev, uplink)
        return ([default] if default else []) + found, gaps

    async def _accounts(self, dev: str) -> tuple[dict[str, Any], list[Gap]]:
        """Local users (#175) through the user manager API, with the user of Signalbox's key
        marked. The user manager has no read-only privilege (whoever may read it may change
        every account), so Signalbox's documented user cannot read it unless it is given the
        privilege on purpose (#349): then the accounts stay unread (None, not an empty list)
        with an optional gap naming the privilege. An OPNsense without the API (404, before
        25.1) has nothing to report. A key that can read it is an administrator's."""
        try:
            rows = _rows(await self.http.post_json(USERS, ALL_ROWS), USERS)
            keys = _rows(await self.http.post_json(USER_KEYS, ALL_ROWS), USER_KEYS)
        except NotFound:
            return {}, []
        except AdapterError as exc:
            return {}, [_accounts_gap(exc)]
        cfg = self.context.config
        assert isinstance(cfg, OpnsenseConfig)
        mine = cfg.api_key.get_secret_value()
        own = next(
            (
                _text(k.get("username"))
                for k in keys
                if hmac.compare_digest(_text(k.get("key")).encode(), mine.encode())
            ),
            None,
        )
        out: list[DeviceAccount] = []
        for row in rows[:MAX_ACCOUNTS]:
            name = _text(row.get("name"))
            uuid = _text(row.get("uuid"))
            if not name:
                continue
            user: dict[str, Any] = {}
            if uuid:
                with contextlib.suppress(AdapterError):
                    answer = await self.http.get_json(f"{USER_GET}/{quote(uuid)}")
                    user = _sub(answer, "user") if isinstance(answer, dict) else {}
            groups = _selected(user.get("group_memberships"))
            privs = _selected(user.get("priv"))
            if "admins" in groups or "page-all" in privs or _flag(row.get("is_admin")):
                privilege = AccountPrivilege.ADMIN
            else:
                privilege = AccountPrivilege.WRITE if privs or groups else AccountPrivilege.OTHER
            keys_text = user.get("authorizedkeys")
            out.append(
                DeviceAccount(
                    name=name,
                    privilege=privilege,
                    enabled=not _flag(row.get("disabled", user.get("disabled"))),
                    key_auth=bool(_text(keys_text)) if isinstance(keys_text, str) else None,
                    is_signalbox=name == own,
                )
            )
        # the key could read the user manager: it may change every account
        return {"accounts": {dev: out}, "signalbox_privilege": {dev: AccountPrivilege.ADMIN}}, []

    async def _certificates(self) -> tuple[list[Certificate], list[Gap]]:
        """Certificates and authorities stored on the firewall (#330), public data only (see
        :mod:`.certificates`). A grid the API user may not read is an optional gap naming its
        privilege; what could be read is still reported."""
        dev = self.context.device_id
        gaps: list[Gap] = []
        grids: dict[str, list[dict[str, Any]]] = {}
        for key, endpoint, privilege in (
            ("ca", CA_SEARCH, CA_PRIVILEGE),
            ("cert", CERT_SEARCH, CERT_PRIVILEGE),
        ):
            try:
                grids[key] = _rows(await self._get(endpoint, grid=True), endpoint)
            except NotFound:
                grids[key] = []
            except AdapterError as exc:
                gaps.append(_privilege_gap("certificates", exc, privilege))
                grids[key] = []
        issuers = issuer_names(grids["ca"])
        found = [
            *parse_certificates(dev, grids["ca"], ca=True, issuers=issuers),
            *parse_certificates(dev, grids["cert"], ca=False, issuers=issuers),
        ]
        unique: dict[str, Certificate] = {}
        for c in found:  # an authority and a certificate may share a description: first wins
            unique.setdefault(c.id, c)
        return list(unique.values()), gaps

    async def _log_targets(self) -> tuple[list[LogTarget] | None, list[Gap]]:
        """Remote syslog destinations and the NetFlow export (#180). A page the API user may
        not read is an optional gap naming its privilege; without the syslog page the targets
        stay unread (None), without the NetFlow page they are the syslog ones only."""
        gaps: list[Gap] = []
        out: list[LogTarget] = []
        try:
            rows = _rows(await self._get(SYSLOG_DESTINATIONS, grid=True), SYSLOG_DESTINATIONS)
        except NotFound:
            rows = []
        except AdapterError as exc:
            return None, [_privilege_gap("log targets", exc, SYSLOG_PRIVILEGE)]
        for r in rows:
            host = _text(r.get("hostname"))
            if not host:
                continue
            transport = _text(r.get("transport")).lower()
            out.append(
                LogTarget(
                    kind=LogKind.SYSLOG,
                    address=host,
                    port=_port(r.get("port")) or LOG_PORTS[LogKind.SYSLOG],
                    transport=LogTransport.TLS
                    if "tls" in transport
                    else LogTransport.TCP
                    if "tcp" in transport
                    else LogTransport.UDP,
                    enabled=_text(r.get("enabled")) != "0",
                    name=_text(r.get("description")) or None,
                    topics=[
                        *_listen_values(r.get("facility")),
                        *_listen_values(r.get("level")),
                    ],
                )
            )
        try:
            data = await self._optional(NETFLOW)
        except AdapterError as exc:
            gaps.append(_privilege_gap("NetFlow export", exc, NETFLOW_PRIVILEGE))
            data = None
        capture = _sub(_sub(data, "netflow"), "capture") if isinstance(data, dict) else {}
        exporting = bool(_listen_values(capture.get("interfaces")))
        version = next(iter(_selected(capture.get("version"))), "v9")
        for value in _listen_values(capture.get("targets")):
            host, _, port = value.rpartition(":")
            host = host.strip("[]")
            if not host or host.startswith("127."):  # the local Insight collector
                continue
            out.append(
                LogTarget(
                    kind=LogKind.NETFLOW,
                    address=host,
                    port=_port(port) or LOG_PORTS[LogKind.NETFLOW],
                    transport=LogTransport.UDP,
                    enabled=exporting,
                    name="netflow",
                    topics=[version],
                )
            )
        return out, gaps

    async def _services(self) -> list[ManagementService]:
        """Management services (#173), as far as a narrow API tells.

        The web interface and SSH settings (``system/webgui``, ``system/ssh``) have no API of
        their own, and the configuration backup that holds them also holds every secret of the
        firewall: it is not downloaded. What is read: the web interface Signalbox itself talks
        to (scheme and port of the address it uses) and, when the ``os-net-snmp`` plugin is
        installed, ``/api/netsnmp/general/get``.
        """
        dev = self.context.device_id
        https = self.http.secure
        out = [
            ManagementService(
                id=object_id(dev, "service", "webgui"),
                device_id=dev,
                kind=ServiceKind.HTTPS if https else ServiceKind.HTTP,
                name="webgui",
                enabled=True,
                port=self.http.port,
            )
        ]
        try:
            data = await self._optional(NETSNMP)
        except AdapterError:  # no privilege for the plugin's page: not read
            return out
        general = _dict(data, NETSNMP, "the answer").get("general") if data is not None else None
        if not isinstance(general, dict):
            return out
        community = _text(general.get("community"))
        listen: list[IPAddress] = []
        for part in _listen_values(general.get("listen")):
            with contextlib.suppress(ValueError):
                listen.append(ip_address(part))
        out.append(
            ManagementService(
                id=object_id(dev, "service", "snmp"),
                device_id=dev,
                kind=ServiceKind.SNMP,
                name="net-snmp",
                enabled=_text(general.get("enabled")) == "1",
                port=SERVICE_PORTS[ServiceKind.SNMP],
                listen=listen,
                snmp=SnmpSettings(
                    versions=[SnmpVersion.V2C] if community else [],
                    default_community=community.lower() in ("public", "private")
                    if community
                    else None,
                ),
            )
        )
        return out

    # --- DHCP ---------------------------------------------------------------------------------

    async def _kea_config(self) -> dict[str, Any] | None:
        """Kea DHCPv4: ``general`` plus subnets and reservations by uuid (None: no Kea).

        ``/api/kea/dhcpv4/get`` answers only the general settings (OPNsense 26.7); subnets and
        reservations are grids whose rows name nested fields with dots
        (``option_data.routers``). They are put back into the nested form of the model.
        """
        data = await self._optional(KEA)
        if data is None:
            return None
        root = dict(_dict(_dict(data, KEA, "the answer").get("dhcpv4"), KEA, "dhcpv4"))
        if "subnets" not in root:
            subnets = _rows(await self._get(KEA_SUBNETS, grid=True), KEA_SUBNETS)
            reservations = _rows(await self._get(KEA_RESERVATIONS, grid=True), KEA_RESERVATIONS)
            root["subnets"] = {"subnet4": {_text(r.get("uuid")): _nest(r) for r in subnets}}
            root["reservations"] = {
                "reservation": {_text(r.get("uuid")): _nest(r) for r in reservations}
            }
        ha = _sub(root, "ha")
        if _flag(ha.get("enabled")):  # peers: field names are a guess
            me = _text(ha.get("this_server_name"))
            peers = [
                _text(r.get("name"))
                for r in _rows(await self._optional(KEA_PEERS, grid=True), KEA_PEERS)
                if _text(r.get("name")) not in ("", me)
            ]
            root["_peer"] = peers[0] if peers else None
        return root

    async def read_dhcp(self) -> Observation:
        layout = await self._layout()
        servers = self._kea(layout, await self._kea_config())
        servers = await self._kea_leases(servers)
        # Kea first: ISC only where no enabled Kea server serves the interface (Kea off or not
        # configured: ISC alone; both: each on its own interfaces).
        served = {s.segment_id for s in servers if s.enabled}
        servers += [s for s in await self._isc(layout) if s.segment_id not in served]
        return Observation(dhcp_servers=servers, dhcp_relays=await self._relays(layout))

    async def _kea_leases(self, servers: list[DhcpServer]) -> list[DhcpServer]:
        """Kea leases (all states) onto the server whose subnet holds the address."""
        data = await self._optional(KEA_LEASES, grid=True)
        if data is None or not servers:
            return servers
        nets = [ip_network(str(s.vendor_extra["subnet"])) for s in servers]
        found: list[list[DhcpLease]] = [[] for _ in servers]
        for row in _rows(data, KEA_LEASES):
            lease = _kea_lease(row)
            if lease is None:
                continue
            for i, net in enumerate(nets):
                if lease.address in net:
                    mac = {r.address: r.mac for r in servers[i].reservations}.get(lease.address)
                    found[i].append(lease.model_copy(update={"reserved": mac == lease.mac}))
                    break
        return [s.model_copy(update={"leases": x}) for s, x in zip(servers, found, strict=True)]

    async def _relays(self, layout: _Layout) -> list[DhcpRelay]:
        """dhcrelay (core since 24.1; field names are a guess): one relay per interface row."""
        data = await self._optional(DHCRELAY, grid=True)
        if data is None:
            return []
        dest = {
            _text(r.get("uuid")): _addr(r.get("server"))
            for r in _rows(await self._optional(DHCRELAY_DEST, grid=True), DHCRELAY_DEST)
        }
        relays: list[DhcpRelay] = []
        for row in _rows(data, DHCRELAY):
            iface = layout.by_identifier(_text(row.get("interface")))
            if iface is None or iface.segment is None:
                continue
            servers = [a for u in _selected(row.get("destination")) if (a := dest.get(u))]
            servers = servers or _addrs(row.get("destination"))
            name = _segment_key(iface.segment)
            if any(r.id.endswith(f"/{name}") for r in relays):
                continue
            relays.append(
                DhcpRelay(
                    id=object_id(self.context.device_id, "dhcp-relay", name),
                    device_id=self.context.device_id,
                    segment_id=iface.segment,
                    servers=servers,
                    enabled=_flag(row.get("enabled", "1")),
                )
            )
        return relays

    def _kea(self, layout: _Layout, root: dict[str, Any] | None) -> list[DhcpServer]:
        if root is None:
            return []
        general = _sub(root, "general")
        enabled = _flag(general.get("enabled"))
        listen = set(_selected(general.get("interfaces")))
        lease = _int(general.get("valid_lifetime"))
        subnets = dict(_items(_sub(root, "subnets").get("subnet4")))
        peer = root.get("_peer") or None

        reservations: dict[str, list[Reservation]] = {}
        for _, r in _items(_sub(root, "reservations").get("reservation")):
            mac, address = _mac(r.get("hw_address")), _addr(r.get("ip_address"))
            if mac is None or address is None:
                continue
            refs = set(_selected(r.get("subnet"))) | {_text(r.get("%subnet"))} - {""}
            if isinstance(r.get("subnet"), dict):  # option values carry the CIDR text
                refs |= {_text(v.get("value")) for v in r["subnet"].values() if isinstance(v, dict)}
            for uuid, s in subnets.items():
                if uuid in refs or _text(s.get("subnet")) in refs:
                    reservations.setdefault(uuid, []).append(
                        Reservation(
                            mac=mac, address=address, hostname=_text(r.get("hostname")) or None
                        )
                    )

        servers: list[DhcpServer] = []
        for uuid, s in subnets.items():
            try:
                net = ip_network(_text(s.get("subnet")), strict=False)
            except ValueError:
                continue
            iface = layout.containing(net[1] if net.num_addresses > 1 else net[0])
            if iface is None or iface.segment is None:
                continue  # a subnet on no interface we know: nothing to attach it to
            own = next(a.ip for a in iface.addresses if a.ip in net)
            name = f"kea-{iface.identifier}"
            if any(x.id.endswith(f"/{name}") for x in servers):  # a second subnet there
                name = f"{name}-{net.network_address}"
            lifetime = _int(s.get("valid_lifetime")) or lease
            options = _sub(s, "option_data")
            routers = _addrs(options.get("routers"))
            dns = _addrs(options.get("domain_name_servers"))
            ntp = _addrs(options.get("ntp_servers"))
            if _flag(s.get("option_data_autocollect")):
                # OPNsense fills all three with the interface address on every Kea save
                # (KeaDhcpv4::setNodes, 26.7); seen in CI after a deployment
                routers, dns, ntp = routers or [own], dns or [own], ntp or [own]
            domain_search = [
                d for d in re.split(r"[,\s]+", _text(options.get("domain_search"))) if d
            ]
            routes = [
                DhcpRoute(destination=ip_network(d, strict=False), gateway=ip_address(g))
                for d, g in _ROUTE.findall(_text(options.get("static_routes")))
                if _valid_route(d, g)
            ]
            next_server = _addr(s.get("next_server"))
            tftp, boot_file = (
                _text(options.get("tftp_server_name")),
                _text(options.get("boot_file_name")),
            )
            extra_options = (
                [DhcpOption(code=4, name="time-servers", value=_text(options.get("time_servers")))]
                if _text(options.get("time_servers"))
                else []
            )
            pools = [
                p
                for t in re.split(r"[\n,]+", _text(s.get("pools")))
                if t.strip() and (p := _pool(t.strip()))
            ]
            servers.append(
                DhcpServer(
                    id=object_id(self.context.device_id, "dhcp", name),
                    device_id=self.context.device_id,
                    segment_id=iface.segment,
                    enabled=enabled and iface.identifier in listen,
                    pools=pools,
                    lease_seconds=lifetime,
                    router=routers[0] if routers else None,
                    dns_servers=dns,
                    domain=_text(options.get("domain_name")) or None,
                    reservations=reservations.get(uuid, []),
                    ntp_servers=ntp,
                    search_domains=domain_search,
                    static_routes=routes,
                    boot=DhcpBoot(
                        next_server=next_server,
                        server_name=tftp or None,
                        filename=boot_file or None,
                    )
                    if next_server or tftp or boot_file
                    else None,
                    options=extra_options,
                    failover_peer=peer,
                    vendor_extra={"server": "kea", "subnet": str(net)},
                )
            )
        return servers

    def _ssh(self) -> PinnedSsh:
        cfg = self.config
        assert cfg.isc_ssh_key is not None
        return PinnedSsh(
            urlsplit(cfg.url).hostname or "",
            cfg.isc_ssh_port,
            cfg.isc_ssh_user,
            "",
            cfg.isc_ssh_host_key,
            self.context.timeout,
            private_key=cfg.isc_ssh_key.get_secret_value(),
        )

    async def _isc_settings(self) -> tuple[dict[str, Any], str]:
        """Per-interface ISC settings from the helper script (#242), or ``({}, why not)``.

        Only with an SSH key and its host key configured. The script's output is untrusted
        input like any answer: a failure never breaks the observation, the leases are read
        as before and the reason is shown on the server.
        """
        if self.config.isc_ssh_key is None:
            return {}, ""
        try:
            async with self._ssh() as ssh:
                res = await ssh.command(ISC_SCRIPT)
            if res.code != 0:
                raise AdapterError(f"the script exited with status {res.code}: {res.err[:200]}")
            data = json.loads(res.text)
            if not isinstance(data, dict) or data.get("version") != 1:
                raise AdapterError("unexpected output (version)")
            section = data.get("dhcpd")
            if not isinstance(section, dict):
                raise AdapterError("unexpected output (no dhcpd section)")
        except (AdapterError, ValueError) as exc:
            log.warning("%s: ISC settings not read: %s", self.context.device_id, exc)
            return {}, f"the ISC settings could not be read over SSH: {exc}"[:300]
        return {k: v for k, v in section.items() if isinstance(v, dict)}, ""

    async def _isc(self, layout: _Layout) -> list[DhcpServer]:
        try:
            status = await self._optional(ISC_STATUS)
        except AuthFailed:
            # core's ISC DHCP has no privilege for its status before 26 (root only): the leases
            # (Status: DHCP leases) are read without it
            status = {"status": "running"}
        if status is None:
            return []
        state = _text(_dict(status, ISC_STATUS, "the answer").get("status"))
        if state == "disabled":
            return []
        try:
            leases = _rows(await self._get(ISC_LEASES, grid=True), ISC_LEASES)
        except AuthFailed:  # no *Status: DHCP leases* either: ISC is not read (optional)
            return []
        by_iface: dict[str, list[dict[str, Any]]] = {}
        for lease in leases:
            by_iface.setdefault(_text(lease.get("if")), []).append(lease)
        settings, problem = await self._isc_settings()
        # an interface the script reports as not served has no ISC server, whatever leases remain
        for identifier, conf in settings.items():
            if conf.get("enable"):
                by_iface.setdefault(identifier, [])
            else:
                by_iface.pop(identifier, None)
        servers = []
        for identifier, rows in by_iface.items():
            iface = layout.by_identifier(identifier)
            if iface is None or iface.segment is None:
                continue
            reservations = [
                Reservation(mac=mac, address=address, hostname=_text(r.get("hostname")) or None)
                for r in rows
                if _text(r.get("type")) == "static"
                and (mac := _mac(r.get("mac"))) is not None
                and (address := _addr(r.get("address"))) is not None
            ]
            extra: dict[str, Any] = {"server": "isc"}
            fields: dict[str, Any] = {}
            conf = settings.get(identifier)
            if conf is not None:
                fields, reservations = self._isc_fields(conf), self._isc_maps(conf)
                extra["settings"] = "signalbox-isc-dhcp"
            else:
                extra["note"] = problem or (
                    "the os-isc-dhcp plugin's API has only the lease list and the service "
                    "state: ranges, options and failover are in config.xml, which Signalbox "
                    "reads only through the optional helper script (docs/adapters/opnsense.md, "
                    "ISC DHCP settings)"
                )
            servers.append(
                DhcpServer(
                    id=object_id(self.context.device_id, "dhcp", f"isc-{identifier}"),
                    device_id=self.context.device_id,
                    segment_id=iface.segment,
                    enabled=state == "running",
                    reservations=reservations,
                    leases=[x for r in rows if (x := _isc_lease(r)) is not None],
                    vendor_extra=extra,
                    **fields,
                )
            )
        return servers

    @staticmethod
    def _isc_fields(conf: dict[str, Any]) -> dict[str, Any]:
        """Pool, router, DNS, NTP, domain, lease time and failover peer of the script's output."""

        def addrs(value: Any) -> list[IPAddress]:
            return [a for v in value if (a := _addr(v))] if isinstance(value, list) else []

        rng = conf.get("range")
        pool = (
            _pool(f"{rng.get('from')}-{rng.get('to')}")
            if isinstance(rng, dict) and rng.get("from") and rng.get("to")
            else None
        )
        lease = _int(conf.get("defaultleasetime"))
        return {
            "pools": [pool] if pool else [],
            "router": _addr(conf.get("gateway")),
            "dns_servers": addrs(conf.get("dnsserver")),
            "ntp_servers": addrs(conf.get("ntpserver")),
            "domain": _text(conf.get("domain")) or None,
            # ISC's own default is 7200 s when the interface sets none
            "lease_seconds": lease if lease else 7200,
            "failover_peer": _text(conf.get("failover_peerip")) or None,
        }

    @staticmethod
    def _isc_maps(conf: dict[str, Any]) -> list[Reservation]:
        rows = conf.get("staticmap")
        return [
            Reservation(mac=mac, address=address, hostname=_text(r.get("hostname")) or None)
            for r in (rows if isinstance(rows, list) else [])
            if isinstance(r, dict)
            and (mac := _mac(r.get("mac"))) is not None
            and (address := _addr(r.get("ipaddr"))) is not None
        ]

    # --- DNS ----------------------------------------------------------------------------------

    async def read_dns(self) -> Observation:
        """Unbound, dnsmasq when its DNS is on, and a DNS server Signalbox does not read (#241).

        Unbound and dnsmasq each have their port. When neither answers on port 53 although one
        of them is on, something else does (AdGuard Home, a plugin whose API needs its own
        login): it is reported as an unread service ``<device>/dns/port-53``.
        """
        layout = await self._layout()
        dev = self.context.device_id
        data = _dict(await self._get(UNBOUND), UNBOUND, "the answer")
        root = _dict(data.get("unbound"), UNBOUND, "unbound")
        general = _sub(root, "general")
        active = _selected(general.get("active_interface"))
        listen_on = [i for i in layout.ifaces if not active or i.identifier in active]
        forwarders: list[DnsForwarder] = []
        domain_forwards: dict[str, str] = {}
        for _, f in _items(_sub(root, "dots").get("dot")):
            server = _addr(f.get("server"))
            if not _flag(f.get("enabled")) or server is None:
                continue
            # an empty port: 853 for DNS over TLS, 53 for a plain forward (Unbound's defaults)
            default = 853 if _text(f.get("type")) in ("", "dot") else DNS_PORT
            fwd = DnsForwarder(address=server, port=_port(f.get("port")) or default)
            domain = _text(f.get("domain"))
            if domain:
                domain_forwards[domain] = str(fwd)
            elif fwd not in forwarders:
                forwarders.append(fwd)
        records, gaps, read = await self._unbound_records(root, general, layout)
        try:
            for row in await self._grid_named(DOMAIN_OVERRIDES, DOMAIN_OVERRIDES_CAMEL):
                server, domain = _addr(row.get("server")), _text(row.get("domain"))
                if server is not None and domain and _flag(row.get("enabled", "1")):
                    port = _port(row.get("port"))
                    fwd = DnsForwarder(address=server, port=port or DNS_PORT)
                    domain_forwards.setdefault(domain, str(fwd))
        except AdapterError as exc:
            # no such grid on this release (26.7 answers 200 with an empty body; the forwards are
            # in the general settings): optional extra, never a gap
            log.debug("%s: no domain override grid: %s", dev, exc)
        extra: dict[str, Any] = {"domain_forwards": domain_forwards} if domain_forwards else {}
        services = [
            DnsService(
                id=object_id(dev, "dns", "unbound"),
                device_id=dev,
                name="unbound",
                enabled=_flag(general.get("enabled")),
                listen=_unique(a.ip for i in listen_on for a in i.addresses),
                port=_port(general.get("port")) or DNS_PORT,
                forwarders=forwarders,
                host_records=records,
                host_records_read=read,
                vendor_extra=extra,
            )
        ]
        if (dnsmasq := await self._dnsmasq(layout)) is not None:
            services.append(dnsmasq)
        on = [d for d in services if d.enabled]
        if on and not any(d.port == DNS_PORT for d in on):
            ports = ", ".join(f"{d.name} on {d.port}" for d in on)
            services.append(
                DnsService(
                    id=object_id(dev, "dns", f"port-{DNS_PORT}"),
                    device_id=dev,
                    config_read=False,
                    vendor_extra={
                        "note": f"{ports}: another DNS server (AdGuard Home, a plugin) answers "
                        "on port 53; its settings are not read"
                    },
                )
            )
        return Observation(dns_services=services, incomplete=gaps)

    async def _grid_named(self, *endpoints: str) -> list[dict[str, Any]]:
        """A grid under its first spelling that exists (``search_x``, then ``searchX``: 25.1 and
        older know only the latter), read completely: ``rowCount=-1`` asks for everything, and
        when the answer holds fewer rows than its ``total`` the next pages are read, too.
        Refusals and malformed answers are raised at once."""
        missing: NotFound | None = None
        for endpoint in endpoints:
            try:
                data = await self._get(endpoint, grid=True)
                rows = _rows(data, endpoint)
            except NotFound as exc:
                missing = exc
                continue
            total = _int(data.get("total")) if isinstance(data, dict) else None
            page = 1
            while rows and total is not None and len(rows) < total and page < MAX_GRID_PAGES:
                page += 1
                size = max(len(rows) // (page - 1), 1)
                more = await self.http.get_json(
                    endpoint, params={"current": page, "rowCount": size}
                )
                extra = _rows(more, endpoint)
                if not extra:
                    break
                rows = rows + extra
            return rows
        assert missing is not None
        raise missing

    async def _unbound_records(
        self, root: dict[str, Any], general: dict[str, Any], layout: _Layout
    ) -> tuple[list[HostRecord], list[Gap], bool]:
        """Host records of Unbound (#386): host overrides, their aliases, and the DHCP static
        mappings and leases it registers. A grid that cannot be read is an optional gap and
        ``read`` is False (an empty list then means "unknown", not "none configured")."""
        records: list[HostRecord] = []
        gaps: list[Gap] = []
        read = True
        by_target: dict[str, list[IPAddress]] = {}
        try:
            for row in await self._grid_named(HOST_OVERRIDES, HOST_OVERRIDES_CAMEL):
                address = _addr(row.get("server") or row.get("address") or row.get("ip"))
                # "A", or a label like "A (IPv4 address)" on some releases
                rr = (_text(row.get("rr")).upper().split() or ["A"])[0]
                if not _flag(row.get("enabled", "1")) or address is None or rr not in ("A", "AAAA"):
                    continue
                name = _fqdn(row.get("hostname"), row.get("domain"))
                if name:
                    source = "alias" if row.get("isAlias") is True else "host-override"
                    records.append(HostRecord(name=name, address=address, source=source))
                    for key in (_text(row.get("uuid")), name):
                        if key:
                            by_target.setdefault(key, []).append(address)
                # 26.7 nests the aliases of an override as ``_children`` (also in the alias grid)
                for child in (c for c in row.get("_children") or [] if isinstance(c, dict)):
                    alias = _fqdn(child.get("hostname"), child.get("domain"))
                    if alias and _flag(child.get("enabled", "1")):
                        records.append(HostRecord(name=alias, address=address, source="alias"))
        except AdapterError as exc:
            read = False
            gaps.append(_privilege_gap("DNS host overrides", exc, UNBOUND_PRIVILEGE))
        if read:
            try:
                for row in await self._grid_named(HOST_ALIASES, HOST_ALIASES_CAMEL):
                    name = _fqdn(row.get("hostname"), row.get("domain"))
                    if not name or not _flag(row.get("enabled", "1")):
                        continue
                    own = _addr(row.get("server") or row.get("address") or row.get("ip"))
                    targets = [own] if own else by_target.get(_text(row.get("host")), [])
                    for address in dict.fromkeys(targets):
                        records.append(HostRecord(name=name, address=address, source="alias"))
            except NotFound:
                pass  # no alias API on this release: there are none
            except AdapterError as exc:
                read = False
                gaps.append(_privilege_gap("DNS host aliases", exc, UNBOUND_PRIVILEGE))
        records += await self._registered(root, general)
        unique = {(r.name.lower(), str(r.address)): r for r in reversed(records)}
        return [r for r in records if unique[(r.name.lower(), str(r.address))] is r], gaps, read

    async def _registered(self, root: dict[str, Any], general: dict[str, Any]) -> list[HostRecord]:
        """Names of DHCP static mappings and leases that Unbound registers ("Register DHCP
        leases" / "Register DHCP static mappings"). *Guess*: the setting names ``regdhcp``,
        ``regdhcpstatic``, ``regdhcpdomain`` (the ``dhcp`` node as a second shape)."""
        dhcp = _sub(root, "dhcp")
        leases = _flag(general.get("regdhcp")) or _flag(dhcp.get("enable"))
        static = _flag(general.get("regdhcpstatic")) or _flag(dhcp.get("static"))
        if not leases and not static:
            return []
        domain = _text(general.get("regdhcpdomain")) or _text(dhcp.get("domain"))
        try:
            servers = (await self.read_dhcp()).dhcp_servers
        except AdapterError as exc:  # shown by the dhcp capability itself
            log.warning("%s: DHCP names not registered: %s", self.context.device_id, exc)
            return []
        found: dict[tuple[str, str], HostRecord] = {}

        def add(
            host: str | None, address: IPAddress, source: str, server_domain: str | None
        ) -> None:
            name = _fqdn(host, domain or server_domain)
            if name and (name.lower(), str(address)) not in found:
                found[(name.lower(), str(address))] = HostRecord(
                    name=name, address=address, source=source
                )

        for srv in (x for x in servers if x.enabled):
            if static:
                for r in srv.reservations:
                    add(r.hostname, r.address, "dhcp-static", srv.domain)
            if leases:
                for lease in srv.leases or []:
                    if lease.state is LeaseState.ACTIVE and not lease.reserved:
                        add(lease.hostname, lease.address, "dhcp-lease", srv.domain)
        return list(found.values())

    async def _dnsmasq(self, layout: _Layout) -> DnsService | None:
        """Dnsmasq's DNS (OPNsense 25.1+), None when not installed or its DNS is off
        (``port`` 0: DHCP only). Its upstream servers are the system's DNS servers, which
        this API does not show: forwarders stay empty."""
        try:
            data = await self._optional(DNSMASQ)
        except AdapterError:  # no privilege for dnsmasq: not read
            return None
        root = _dict(data, DNSMASQ, "the answer").get("dnsmasq") if data is not None else None
        if not isinstance(root, dict) or not _flag(root.get("enable")):
            return None
        port = _int(root.get("port"))
        if port == 0:
            return None
        selected = _selected(root.get("interface"))
        listen_on = [i for i in layout.ifaces if not selected or i.identifier in selected]
        records = []
        for _, h in _items(root.get("hosts")):
            host, domain = _text(h.get("host")), _text(h.get("domain"))
            name = ".".join(x for x in (host if host != "*" else "", domain) if x)
            for address in _addrs(_listen_values(h.get("ip"))):
                if name:
                    records.append(HostRecord(name=name, address=address))
        return DnsService(
            id=object_id(self.context.device_id, "dns", "dnsmasq"),
            device_id=self.context.device_id,
            name="dnsmasq",
            listen=_unique(a.ip for i in listen_on for a in i.addresses),
            port=_port(port) or DNS_PORT,
            host_records=records,
            vendor_extra={"upstream": "the system's DNS servers (not read)"},
        )

    # --- clients ------------------------------------------------------------------------------

    async def read_clients(self) -> Observation:
        layout = await self._layout()
        own = layout.own_macs()
        seen: dict[str, dict[str, Any]] = {}

        def add(
            mac: str | None,
            address: Any,
            iface: _Iface | None,
            hostname: Any,
            source: AddressSource | None = None,
        ) -> None:
            if mac is None or mac in own:
                return
            entry = seen.setdefault(
                mac, {"addresses": [], "hostname": None, "iface": None, "sources": {}}
            )
            addr = _addr(address)
            if addr is not None and not addr.is_link_local and addr not in entry["addresses"]:
                entry["addresses"].append(addr)
            if addr is not None and addr in entry["addresses"] and source is not None:
                entry["sources"][addr] = source
            entry["hostname"] = entry["hostname"] or _text(hostname) or None
            entry["iface"] = entry["iface"] or iface

        for endpoint in (ARP, NDP):
            for row in _rows(await self._get(endpoint), endpoint):
                if _flag(row.get("permanent")):
                    continue  # the firewall's own address
                iface = layout.by_device(_text(row.get("intf")))
                add(_mac(row.get("mac")), row.get("ip"), iface, row.get("hostname"))
        try:
            isc = await self._optional(ISC_LEASES, grid=True)
        except AuthFailed:  # core's ISC leases need *Status: DHCP leases*, not in the read set
            isc = None
        for row in _rows(isc, ISC_LEASES) if isc is not None else []:
            iface = layout.by_identifier(_text(row.get("if")))
            static = _text(row.get("type")) == "static"
            src = AddressSource.DHCP_RESERVED if static else AddressSource.DHCP
            add(_mac(row.get("mac")), row.get("address"), iface, row.get("hostname"), src)
        kea = await self._optional(KEA_LEASES, grid=True)
        for row in _rows(kea, KEA_LEASES) if kea is not None else []:
            iface = layout.by_identifier(_text(row.get("if_name") or row.get("if")))
            add(
                _mac(row.get("hwaddr")),
                row.get("address"),
                iface,
                row.get("hostname"),
                AddressSource.DHCP,
            )

        for entry in seen.values():  # a lease or neighbour without an interface: by address
            if entry["iface"] is None:
                entry["iface"] = next(
                    (i for a in entry["addresses"] if (i := layout.containing(a))), None
                )
        dev = self.context.device_id
        clients = [
            Client(
                id=object_id(dev, "client", mac),
                mac=mac,
                addresses=sorted(e["addresses"], key=_sort_key),
                hostname=e["hostname"],
                segment_id=e["iface"].segment if e["iface"] else None,
                seen_on=e["iface"].port if e["iface"] else None,
                address_sources=e["sources"],
            )
            for mac, e in sorted(seen.items())
        ]
        return Observation(clients=clients)

    # --- writing ------------------------------------------------------------------------------

    # --- health and time ------------------------------------------------------------------

    async def read_health(self) -> Observation:
        def obj(value: Any, endpoint: str) -> dict[str, Any]:
            return _dict(value, endpoint, "the answer")

        time = obj(await self._get(SYSTEM_TIME), SYSTEM_TIME)
        resources = obj(await self._get(SYSTEM_RESOURCES), SYSTEM_RESOURCES)
        disks = await self._get(SYSTEM_DISK)
        temperatures = await self._get(SYSTEM_TEMPERATURE)
        if not isinstance(temperatures, list):
            raise _unexpected(SYSTEM_TEMPERATURE, f"{type(temperatures).__name__}, not a list")
        cpu = await self._optional(CPU_TYPE)
        value = vitals.health_of(
            time, resources, disks if isinstance(disks, dict | list) else {}, temperatures, cpu
        )
        return Observation(health={self.context.device_id: value})

    async def read_vpn(self) -> Observation:
        """WireGuard instances and peers as running (#239): ``/api/wireguard/service/show``.

        The configuration endpoints (``server/search_server``, ``client/search_client``) need
        *VPN: WireGuard: Configuration*, which also returns the private keys: not used. So a
        disabled instance or peer, which is not running, is not seen.
        """
        rows = _rows(await self._get(WG_SHOW), WG_SHOW)
        try:
            overview = _rows(await self._get(INTERFACES, grid=True), INTERFACES)
        except AdapterError:  # no Status: Interfaces: no addresses, the tunnels still
            overview = []
        interfaces = {_text(r.get("device")): r for r in overview if _text(r.get("device"))}
        tunnels = wireguard_tunnels(rows, self.context.device_id, interfaces)
        return Observation(tunnels=tunnels)

    async def trace(self, target: Any, max_hops: int, wait: float) -> TraceAnswer:
        """Traceroute through Diagnostics: Traceroute (#253); the firewall waits 2 s per hop
        and stops after 20 s, whatever ``wait`` says."""
        await self._release()
        try:
            answer = await self.http.post_json(_trace.TRACEROUTE, _trace.request_body(target))
        except AuthFailed as exc:
            if "403" not in str(exc):
                raise
            raise AuthFailed(
                f"{_trace.TRACEROUTE}: the API user may not run traceroutes (HTTP 403)",
                fix="Give the API user the privilege Diagnostics: Traceroute "
                f"({_trace.PRIVILEGE}), or use Fix it on the device page while path traces "
                "are on.",
                remedy="privileges",
                message_id="opnsense.traceDenied",
                fix_id="opnsense.traceDenied.fix",
                params={"path": _trace.TRACEROUTE, "privilege": _trace.PRIVILEGE},
            ) from None
        return _trace.parse(answer, target, max_hops)

    async def read_firewall(self) -> Observation:
        """Packet filter and NAT (#135): ``filter/search_rule`` with aliases and interface
        groups, ``d_nat``, ``source_nat`` and ``one_to_one``. Each page needs its own privilege
        (docs/adapters/opnsense.md); a refused one is an error with the fix. A release without
        the MVC NAT pages (404) leaves the port forwards unread."""
        layout = await self._layout()
        dev = self.context.device_id
        rows = _rows(await self._get(FILTER_RULES, grid=True), FILTER_RULES)
        aliases = _rows(await self._get(ALIASES, grid=True), ALIASES)
        groups = _rows(await self._get(IFACE_GROUPS, grid=True), IFACE_GROUPS)

        async def grid(endpoint: str) -> list[dict[str, Any]] | None:
            data = await self._optional(endpoint, grid=True)
            return None if data is None else _rows(data, endpoint)

        forwards = await grid(DNAT_RULES)
        snat = await grid(SNAT_RULES)
        binat = await grid(ONE_TO_ONE)
        try:
            wg = _rows(await self._get(WG_SHOW), WG_SHOW)
        except AdapterError:  # no privilege for WireGuard: its zones carry no tunnel
            wg = []
        tunnels = {_text(r.get("if")) for r in wg if _text(r.get("type")) == "interface"}
        ifaces: list[fw.Iface] = []
        for i in layout.ifaces:
            tunnel = [object_id(dev, "tunnel", i.device)] if i.device in tunnels else []
            uplink = [object_id(dev, "uplink", "wan")] if i.identifier == "wan" else []
            ifaces.append(
                fw.Iface(
                    identifier=i.identifier,
                    description=i.description,
                    segments=[i.segment] if i.segment else [],
                    uplinks=uplink,
                    tunnels=tunnel,
                    addresses=i.addresses,
                    mapped=bool(i.segment or uplink or tunnel),
                )
            )
        taken = {i.identifier for i in ifaces} | {_text(g.get("ifname")) for g in groups}
        if "wireguard" not in taken and tunnels:
            # the interface group every WireGuard instance belongs to (Firewall: Rules: WireGuard)
            ifaces.append(
                fw.Iface(
                    identifier="wireguard",
                    description="WireGuard (Group)",
                    tunnels=[object_id(dev, "tunnel", t) for t in sorted(tunnels)],
                    mapped=True,
                )
            )
        ctx = fw.Context(ifaces, groups, aliases)
        built = fw.build(dev, ctx, rows, forwards, snat, binat)
        gaps = [] if built.rules_complete else [_rules_gap()]
        if forwards is None:
            gaps.append(_forwards_gap(await self._release()))
        return Observation(firewalls=[built], incomplete=gaps)

    async def read_time(self) -> Observation:
        start = datetime.now(UTC)
        response = await self.http.request("GET", SYSTEM_TIME)
        end = datetime.now(UTC)
        try:
            answer = response.json()
        except ValueError as exc:
            raise AdapterError(
                f"{SYSTEM_TIME}: answer is not valid JSON",
                message_id="transport.notJson",
                params={"path": SYSTEM_TIME},
            ) from exc
        time = _dict(answer, SYSTEM_TIME, "the answer")
        # no query string: the privilege's pattern is the bare path (26.7 refuses ?current=1)
        status = await self._optional(NTP_STATUS)  # NotFound: ntpd not there
        rows = _rows(status, NTP_STATUS) if status is not None else None
        value = vitals.time_of(time, response.headers.get("date"), rows, start, end)
        return Observation(time={self.context.device_id: value})

    async def _write_state(self) -> w.WriteState:
        """A fresh read of what the write planner needs."""
        self._cache.clear()
        self._layout_cache = None
        layout = await self._layout()
        vlans = [
            {k: _text(v.get(k)) for k in ("uuid", "if", "tag", "descr")}
            | {"vlanif": _vlanif(v.get("vlanif"))}
            for v in _rows(await self._get(VLANS, grid=True), VLANS)
        ]
        root = await self._kea_config()
        isc = {s.segment_id for s in await self._isc(layout)}
        st = w.WriteState(site=self.context.site_id, layout=layout, vlans=vlans, kea=None, isc=isc)
        version = await self._release()
        st.interface_not = version is None or version >= compat.INTERFACE_NOT
        st.release = compat.release(version) if version else ""
        if root is not None:
            general = _sub(root, "general")
            st.kea = root
            st.kea_enabled = _flag(general.get("enabled"))
            st.listen = _selected(general.get("interfaces"))
            st.lifetime = _int(general.get("valid_lifetime"))
            st.subnets = dict(_items(_sub(root, "subnets").get("subnet4")))
            st.reservations = dict(_items(_sub(root, "reservations").get("reservation")))
        return st

    async def _firewall_state(self, st: w.WriteState, changes: list[Change]) -> None:
        """What the firewall changes need besides the layout: the rows of the new rules page
        (and of the destination NAT page for port forwards) and the names of the zones."""
        rows = _rows(await self._get(FILTER_RULES, grid=True), FILTER_RULES)
        st.filter_rows = [r for r in rows if not r.get("is_automatic")]
        if any(c.kind is ChangeKind.PORT_FORWARD for c in changes):
            nat = await self._optional(DNAT_RULES, grid=True)
            if nat is None:
                raise AdapterError(
                    f"{DNAT_RULES}: not available on this firewall (HTTP 404); OPNsense before "
                    "26.1 has no API for port forwards",
                    message_id="opnsense.noForwardApi",
                    params={"path": DNAT_RULES},
                )
            st.dnat_rows = [r for r in _rows(nat, DNAT_RULES) if not r.get("is_automatic")]
        groups = _rows(await self._get(IFACE_GROUPS, grid=True), IFACE_GROUPS)
        st.interfaces = {i.identifier for i in st.layout.ifaces}
        st.zones = st.interfaces | {
            _text(g.get("ifname")) for g in groups if _text(g.get("ifname"))
        }

    async def _needs_assignments(self, changes: list[Change]) -> None:
        if not any(c.kind is ChangeKind.ROUTER for c in changes):
            return
        too_old = AdapterError(
            "this OPNsense version has no interface assignment API with addresses (OPNsense "
            "26.7.6 or newer is needed to change router interfaces)",
            message_id="opnsense.noAssignmentApi",
        )
        try:
            rows = _rows(
                await self.http.get_json(w.ASSIGN_SEARCH, params=ALL_ROWS), w.ASSIGN_SEARCH
            )
        except NotFound as exc:
            raise too_old from exc
        if rows and not any("ipaddr" in r for r in rows):
            # 26.7 up to 26.7.5: the assignment API only knows device, description and lock
            raise too_old

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        await self._release()  # the action spelling of the release's ACL
        await self._needs_assignments(changes)
        st = await self._write_state()
        if any(c.kind in FIREWALL_KINDS for c in changes):
            await self._firewall_state(st, changes)
        calls = [call for c in changes for call in w.calls_for(c, st)]
        calls += self._applies(calls)
        return [call.vendor() for call in calls]

    @staticmethod
    def _applies(calls: list[w.Call]) -> list[w.Call]:
        """The calls that make the saved configuration run: Kea, the packet filter."""
        out = []
        if any(call.kea for call in calls):
            text = Described("apply the Kea DHCP configuration", "plan.opnsense.applyKea")
            out.append(w.Call(text, w.KEA_APPLY))
        if any(call.filter for call in calls):
            text = Described("apply the packet filter rules", "plan.opnsense.applyFilter")
            out.append(w.Call(text, w.FILTER_APPLY))
        if any(call.dnat for call in calls):
            text = Described("apply the port forwards", "plan.opnsense.applyForwards")
            out.append(w.Call(text, w.DNAT_APPLY))
        return out

    async def _send(self, call: w.Call) -> dict[str, Any]:
        try:
            answer = await self.http.post_json(call.path, call.payload)
        except NotFound as exc:
            raise AdapterError(
                f"{call.path}: not available on this firewall (HTTP 404)",
                message_id="opnsense.notAvailable",
                params={"path": call.path},
            ) from exc
        if not isinstance(answer, dict):
            raise _unexpected(call.path, "not an object")
        if answer.get("errorMessage"):
            raise AdapterError(
                f"{call.path}: {_text(answer.get('errorMessage'))}",
                message_id="opnsense.errorMessage",
                params={"request": call.path, "detail": _text(answer.get("errorMessage"))},
            )
        validations = answer.get("validations")
        if answer.get("result") == "failed" or validations:
            found = validations if isinstance(validations, dict) else {}
            detail = "; ".join(f"{k}: {_text(v) or v}" for k, v in found.items())
            raise AdapterError(
                f"{call.path}: the firewall refused the change"
                + (f" ({detail})" if detail else ""),
                message_id="opnsense.refusedChange" if detail else "opnsense.refusedChangeBare",
                params={"path": call.path, "detail": detail} if detail else {"path": call.path},
            )
        result = answer.get("result", answer.get("status"))
        if _text(result).lower() not in ("saved", "deleted", "ok", "done"):
            raise _unexpected(call.path, f"result {result!r}")
        return answer

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult:
        """Send the calls change by change, each planned on a fresh read.

        OPNsense has no confirm-or-revert for API changes (26.7 has no savepoint and rollback
        timer for the packet filter either): no deadline is returned, and the deployment
        restores the backup when the verification fails.
        """
        await self._release()
        await self._needs_assignments(changes)
        sent: list[w.Call] = []
        for change in changes:
            st = await self._write_state()
            if change.kind in FIREWALL_KINDS:
                await self._firewall_state(st, [change])
            for call in w.calls_for(change, st):
                await self._send(call)
                sent.append(call)
        for final in self._applies(sent):
            await self._send(final)
            sent.append(final)
        self._cache.clear()
        self._layout_cache = None
        return ApplyResult(confirm_deadline=None, calls=[c.vendor() for c in sent])

    async def confirm(self) -> None:
        """Nothing to confirm: OPNsense applies API changes at once."""

    async def _history(self) -> list[dict[str, Any]]:
        data = _dict(await self.http.get_json(w.BACKUPS), w.BACKUPS, "the answer")
        items = data.get("items")
        if not isinstance(items, list):
            raise _unexpected(w.BACKUPS, "no list of items")
        rows = [i for i in items if isinstance(i, dict) and _text(i.get("id"))]
        return sorted(rows, key=lambda i: _text(i.get("time")), reverse=True)

    async def _download(self, revision: str) -> str:
        path = w.DOWNLOAD + revision
        text = (await self.http.request("GET", path)).text
        _revision_time(text, path)
        return text

    async def backup(self) -> Backup:
        """The newest revision of the configuration history: the configuration in use."""
        await self._release()
        history = await self._history()
        if not history:
            raise AdapterError(
                "the configuration history is empty; set System > Configuration > History to "
                "keep backups",
                message_id="opnsense.historyEmpty",
            )
        return Backup(
            device_id=self.context.device_id,
            taken_at=datetime.now(UTC),
            format="opnsense-config-xml",
            content=await self._download(_text(history[0]["id"])),
        )

    async def restore(self, backup: Backup) -> None:
        """Revert to the backed-up revision of the configuration history, then apply it.

        Idempotent: reverting twice to the same revision leaves the same configuration.
        """
        await self._release()
        if backup.format != "opnsense-config-xml":
            raise AdapterError(
                f"not an OPNsense backup (format {backup.format})",
                message_id="opnsense.notBackup",
                params={"format": backup.format},
            )
        when = _revision_time(backup.content, "the backup")
        same_time = [i for i in await self._history() if _text(i.get("time")) == when]
        revision = None
        for item in same_time:
            if await self._download(_text(item["id"])) == backup.content:
                revision = _text(item["id"])
                break
        if revision is None and len(same_time) == 1:
            revision = _text(same_time[0]["id"])
        if revision is None:
            raise AdapterError(
                "the backed-up revision is no longer in the configuration history; restore "
                "the stored config.xml in System > Configuration > Backups",
                message_id="opnsense.revisionGone",
            )
        answer = _dict(await self.http.post_json(w.REVERT + revision, {}), w.REVERT, "the answer")
        if _text(answer.get("status")) != "reverted":
            raise AdapterError(
                f"{w.REVERT}{revision}: revert refused ({answer.get('status')!r})",
                message_id="opnsense.revertRefused",
                params={"path": f"{w.REVERT}{revision}", "status": repr(answer.get("status"))},
            )
        for path in (w.VLAN_APPLY, w.ASSIGN_APPLY, w.KEA_APPLY, w.FILTER_APPLY):
            try:
                text = Described("apply the restored configuration", "plan.opnsense.applyRestored")
                await self._send(w.Call(text, path))
            except AdapterError as exc:
                if "HTTP 404" not in str(exc):
                    raise
        self._cache.clear()
        self._layout_cache = None


def _revision_time(text: str, where: str) -> str:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise AdapterError(
            f"{where}: not a config.xml ({exc})",
            message_id="opnsense.notConfigXml",
            params={"where": where, "detail": str(exc)},
        ) from exc
    when = root.findtext("revision/time")
    if root.tag != "opnsense" or not when:
        raise AdapterError(
            f"{where}: not an OPNsense config.xml (no revision time)",
            message_id="opnsense.noRevisionTime",
            params={"where": where},
        )
    return when.strip()


def _sort_key(address: IPAddress) -> tuple[int, int]:
    return (address.version, int(address))


def _unique(addresses: Iterable[IPAddress]) -> list[IPAddress]:
    out: list[IPAddress] = []
    for a in addresses:
        if a not in out:
            out.append(a)
    return out


__all__ = ["OpnsenseAdapter", "OpnsenseConfig"]
