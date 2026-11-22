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

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, ip_address, ip_interface, ip_network
from typing import Any

from pydantic import Field, JsonValue, SecretStr, field_validator, model_validator

from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterContext,
    AdapterError,
    AuthFailed,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.mikrotik.write import WRITES, MikrotikWrites
from signalbox.model import (
    Band,
    Client,
    DeviceRole,
    DhcpPool,
    DhcpServer,
    DnsService,
    Firmware,
    HostRecord,
    IPAddress,
    IPInterface,
    Membership,
    Neighbour,
    Pmf,
    Port,
    PortKind,
    PortMembership,
    Radio,
    Reservation,
    Security,
    Segment,
    Subnet,
    Wlan,
    normalise_mac,
    object_id,
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
LIST_MEMBER = "/rest/interface/list/member"
IP_ADDRESS = "/rest/ip/address"
IPV6_ADDRESS = "/rest/ipv6/address"
DHCP_SERVER = "/rest/ip/dhcp-server"
DHCP_NETWORK = "/rest/ip/dhcp-server/network"
DHCP_LEASE = "/rest/ip/dhcp-server/lease"
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
#: Interface types that are not ports: VLAN interfaces become segments, loopback nothing.
_NOT_PORTS = {"vlan", "loopback", "lo"}
#: ``frame-types`` of a bridge port that does not accept untagged frames (no pvid membership).
_TAGGED_ONLY = "admit-only-vlan-tagged"
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
    """``authentication-types`` (``wpa2-psk,wpa3-psk``, ...); legacy ``mode=none`` is open."""
    kinds = set(_names(types))
    if _text(mode) == "none" or not kinds:
        return Security.OPEN
    if "wpa3-eap" in kinds or "wpa3-eap-192" in kinds:
        return Security.WPA3_ENTERPRISE
    if kinds & {"wpa2-eap", "wpa-eap"}:
        return Security.WPA2_ENTERPRISE
    if {"wpa2-psk", "wpa3-psk"} <= kinds:
        return Security.WPA2_WPA3
    if "wpa3-psk" in kinds:
        return Security.WPA3
    if "wpa2-psk" in kinds:
        return Security.WPA2
    if "owe" in kinds:
        return Security.OWE
    return Security.OTHER


_PERSONAL = {Security.WPA2, Security.WPA3, Security.WPA2_WPA3, Security.OTHER}


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
        api_version="1.0",
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
            }
        ),
        config=MikrotikConfig,
        description="Reads and changes a RouterOS 7 router, switch or access point (REST API).",
        writes=WRITES,
    )

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
        wan = {
            _text(r.get("interface"))
            for r in await self._optional_rows(LIST_MEMBER)
            if _text(r.get("list")) == WAN_LIST and _active(r)
        }

        ports: dict[str, Port] = {}
        for row in interfaces:
            name, kind = _text(row.get("name")), _text(row.get("type"))
            if not name or kind in _NOT_PORTS or name in vlan_ifaces:
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
                vendor_extra=_extra(row, "type", "comment", "mtu")
                | ({"disabled": True} if disabled else {}),
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
        filtering = {b for b, r in bridges.items() if _flag(r.get("vlan-filtering"))}
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
            if p in with_address and p not in bridges and p not in in_bridge and p not in wan
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
        )

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
                    vendor_extra=_extra(row, "interface", "address-pool")
                    | ({"network": str(net)} if net else {}),
                )
            )
        return Observation(dhcp_servers=servers)

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
                    forwarders=_unique(_addrs(dns.get("servers"))),
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
            wlans.append(
                Wlan(
                    id=object_id(dev, "wlan", name),
                    device_id=dev,
                    ssid=ssid,
                    radio_id=radio.id,
                    enabled=radio.enabled and _active(row),
                    security=sec,
                    pmf=pmf,
                    passphrase_fingerprint=(
                        passphrase_fingerprint(ssid, passphrase)
                        if passphrase and sec in _PERSONAL
                        else None
                    ),
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
            wlans.append(
                Wlan(
                    id=object_id(dev, "wlan", name),
                    device_id=dev,
                    ssid=ssid,
                    radio_id=radio.id,
                    enabled=radio.enabled and _active(row),
                    security=sec,
                    pmf=_PMF.get(_text(profile.get("management-protection"))),
                    passphrase_fingerprint=(
                        passphrase_fingerprint(ssid, psk) if psk and sec in _PERSONAL else None
                    ),
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

        def add(mac: str | None, address: Any = None, **info: Any) -> None:
            if mac is None or mac in own:
                return
            entry = seen.setdefault(
                mac, {"addresses": [], "hostname": None, "segment": None, "seen_on": None}
            )
            addr = _addr(address)
            if addr is not None and not addr.is_link_local and addr not in entry["addresses"]:
                entry["addresses"].append(addr)
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
            add(
                _mac(row.get("active-mac-address") or row.get("mac-address")),
                row.get("active-address") or row.get("address"),
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


def _sort_key(address: IPAddress) -> tuple[int, int]:
    return (address.version, int(address))


def _unique(addresses: Iterable[IPAddress]) -> list[IPAddress]:
    out: list[IPAddress] = []
    for a in addresses:
        if a not in out:
            out.append(a)
    return out


__all__ = ["MikrotikAdapter", "MikrotikConfig", "get_menu"]
