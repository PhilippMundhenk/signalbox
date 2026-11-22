"""OPNsense: reads interfaces and VLANs, DHCP (Kea and ISC), Unbound DNS, ARP/NDP clients;
writes router interfaces, VLANs on ports, Kea DHCP subnets and reservations.

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

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv6Network, ip_address, ip_interface, ip_network
from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator

from signalbox.adapters import Adapter as _Adapter
from signalbox.adapters import (
    AdapterConfig,
    AdapterContext,
    AdapterError,
    ApplyResult,
    Backup,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
    VendorCall,
)
from signalbox.adapters.https import DeviceHttp, NotFound, device_url
from signalbox.adapters.opnsense import discovery as _discovery
from signalbox.adapters.opnsense import vitals
from signalbox.adapters.opnsense import write as w
from signalbox.changes import Change, ChangeKind
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import (
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
    Port,
    PortKind,
    PortMedia,
    PortMembership,
    Reservation,
    Segment,
    Subnet,
    Uplink,
    UplinkKind,
    normalise_mac,
    object_id,
    port_id,
    segment_id,
)

FIRMWARE = "/api/core/firmware/status"
INTERFACES = "/api/interfaces/overview/interfaces_info"
VLANS = "/api/interfaces/vlan_settings/search_item"
KEA = "/api/kea/dhcpv4/get"
KEA_SUBNETS = "/api/kea/dhcpv4/search_subnet"
KEA_RESERVATIONS = "/api/kea/dhcpv4/search_reservation"
KEA_LEASES = "/api/kea/leases4/search"
ISC_STATUS = "/api/dhcpv4/service/status"
ISC_LEASES = "/api/dhcpv4/leases/search_lease"
UNBOUND = "/api/unbound/settings/get"
HOST_OVERRIDES = "/api/unbound/settings/search_host_override"
ARP = "/api/diagnostics/interface/get_arp"
NDP = "/api/diagnostics/interface/get_ndp"
SYSTEM_TIME = "/api/diagnostics/system/system_time"
SYSTEM_RESOURCES = "/api/diagnostics/system/system_resources"
SYSTEM_DISK = "/api/diagnostics/system/system_disk"
SYSTEM_TEMPERATURE = "/api/diagnostics/system/system_temperature"
CPU_TYPE = "/api/diagnostics/cpu_usage/get_cpu_type"
NTP_STATUS = "/api/ntpd/service/status"

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
    return AdapterError(f"unexpected answer from {endpoint}: {what}")


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


def _addrs(value: Any) -> list[IPAddress]:
    parts = value if isinstance(value, list) else re.split(r"[,\s]+", _text(value))
    return [a for a in (_addr(p) for p in parts) if a is not None]


def _mac(value: Any) -> str | None:
    try:
        return normalise_mac(_text(value))
    except ValueError:
        return None


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


class OpnsenseAdapter(_Adapter):
    manifest = Manifest(
        setup_steps=OPNSENSE_STEPS,
        setup_url="https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/opnsense.md#setup",
        id="opnsense",
        name="OPNsense",
        version="0.2.0",
        api_version="1.2",
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
            }
        ),
        config=OpnsenseConfig,
        description=(
            "Reads an OPNsense firewall through its REST API; writes router interfaces, VLANs "
            "on ports and Kea DHCP (subnets, reservations)."
        ),
        writes=frozenset(
            {ChangeKind.ROUTER, ChangeKind.DHCP, ChangeKind.RESERVATION, ChangeKind.PORT}
        ),
    )

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        """The web interface's login page, without credentials."""
        return await _discovery.discover(probe)

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        cfg = context.config
        assert isinstance(cfg, OpnsenseConfig)
        self.config = cfg
        self.http = DeviceHttp(
            cfg.url,
            pinned_fingerprint=context.pinned_fingerprint,
            timeout=context.timeout,
            auth=(cfg.api_key.get_secret_value(), cfg.api_secret.get_secret_value()),
            allow_insecure_http=cfg.allow_insecure_http,
        )
        self._cache: dict[str, Any] = {}
        self._layout_cache: _Layout | None = None

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
        return SystemInfo(
            vendor="Deciso",
            model=_text(product.get("product_name")) or "OPNsense",
            firmware=Firmware(current=current, available=latest if newer else None),
            management_address=self.http.host,
        )

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
        for row in rows:
            device = _text(row.get("device"))
            if not device or device.startswith(_SKIP_DEVICES) or device in vlans:
                continue
            if row.get("vlan_tag") not in (None, "", 0, "0"):
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
                vendor_extra={"identifier": _text(row["identifier"])} if assigned else {},
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
        return Observation(
            ports=layout.ports,
            segments=list(layout.segments.values()),
            subnets=subnets,
            uplinks=uplinks,
        )

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
        return root

    async def read_dhcp(self) -> Observation:
        layout = await self._layout()
        servers = self._kea(layout, await self._kea_config())
        servers += await self._isc(layout)
        return Observation(dhcp_servers=servers)

    def _kea(self, layout: _Layout, root: dict[str, Any] | None) -> list[DhcpServer]:
        if root is None:
            return []
        general = _sub(root, "general")
        enabled = _flag(general.get("enabled"))
        listen = set(_selected(general.get("interfaces")))
        lease = _int(general.get("valid_lifetime"))
        subnets = dict(_items(_sub(root, "subnets").get("subnet4")))

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
                    vendor_extra={"server": "kea", "subnet": str(net)},
                )
            )
        return servers

    async def _isc(self, layout: _Layout) -> list[DhcpServer]:
        status = await self._optional(ISC_STATUS)
        if status is None:
            return []
        state = _text(_dict(status, ISC_STATUS, "the answer").get("status"))
        if state == "disabled":
            return []
        leases = _rows(await self._get(ISC_LEASES, grid=True), ISC_LEASES)
        by_iface: dict[str, list[dict[str, Any]]] = {}
        for lease in leases:
            by_iface.setdefault(_text(lease.get("if")), []).append(lease)
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
            servers.append(
                DhcpServer(
                    id=object_id(self.context.device_id, "dhcp", f"isc-{identifier}"),
                    device_id=self.context.device_id,
                    segment_id=iface.segment,
                    enabled=state == "running",
                    reservations=reservations,
                    vendor_extra={
                        "server": "isc",
                        "note": "the OPNsense API does not expose ISC ranges and options",
                    },
                )
            )
        return servers

    # --- DNS ----------------------------------------------------------------------------------

    async def read_dns(self) -> Observation:
        layout = await self._layout()
        data = _dict(await self._get(UNBOUND), UNBOUND, "the answer")
        root = _dict(data.get("unbound"), UNBOUND, "unbound")
        general = _sub(root, "general")
        active = _selected(general.get("active_interface"))
        listen_on = [i for i in layout.ifaces if not active or i.identifier in active]
        forwarders: list[IPAddress] = []
        domain_forwards: dict[str, str] = {}
        for _, f in _items(_sub(root, "dots").get("dot")):
            server = _addr(f.get("server"))
            if not _flag(f.get("enabled")) or server is None:
                continue
            domain = _text(f.get("domain"))
            if domain:
                domain_forwards[domain] = str(server)
            elif server not in forwarders:
                forwarders.append(server)
        records = []
        for row in _rows(await self._get(HOST_OVERRIDES, grid=True), HOST_OVERRIDES):
            address = _addr(row.get("server") or row.get("address"))
            rr = _text(row.get("rr")).upper() or "A"
            if not _flag(row.get("enabled", "1")) or address is None or rr not in ("A", "AAAA"):
                continue
            host, domain = _text(row.get("hostname")), _text(row.get("domain"))
            name = ".".join(x for x in (host if host != "*" else "", domain) if x)
            if name:
                records.append(HostRecord(name=name, address=address))
        extra: dict[str, Any] = {"port": port} if (port := _int(general.get("port"))) else {}
        if domain_forwards:
            extra["domain_forwards"] = domain_forwards
        return Observation(
            dns_services=[
                DnsService(
                    id=object_id(self.context.device_id, "dns", "unbound"),
                    device_id=self.context.device_id,
                    enabled=_flag(general.get("enabled")),
                    listen=_unique(a.ip for i in listen_on for a in i.addresses),
                    forwarders=forwarders,
                    host_records=records,
                    vendor_extra=extra,
                )
            ]
        )

    # --- clients ------------------------------------------------------------------------------

    async def read_clients(self) -> Observation:
        layout = await self._layout()
        own = layout.own_macs()
        seen: dict[str, dict[str, Any]] = {}

        def add(mac: str | None, address: Any, iface: _Iface | None, hostname: Any) -> None:
            if mac is None or mac in own:
                return
            entry = seen.setdefault(mac, {"addresses": [], "hostname": None, "iface": None})
            addr = _addr(address)
            if addr is not None and not addr.is_link_local and addr not in entry["addresses"]:
                entry["addresses"].append(addr)
            entry["hostname"] = entry["hostname"] or _text(hostname) or None
            entry["iface"] = entry["iface"] or iface

        for endpoint in (ARP, NDP):
            for row in _rows(await self._get(endpoint), endpoint):
                if _flag(row.get("permanent")):
                    continue  # the firewall's own address
                iface = layout.by_device(_text(row.get("intf")))
                add(_mac(row.get("mac")), row.get("ip"), iface, row.get("hostname"))
        isc = await self._optional(ISC_LEASES, grid=True)
        for row in _rows(isc, ISC_LEASES) if isc is not None else []:
            iface = layout.by_identifier(_text(row.get("if")))
            add(_mac(row.get("mac")), row.get("address"), iface, row.get("hostname"))
        kea = await self._optional(KEA_LEASES, grid=True)
        for row in _rows(kea, KEA_LEASES) if kea is not None else []:
            iface = layout.by_identifier(_text(row.get("if_name") or row.get("if")))
            add(_mac(row.get("hwaddr")), row.get("address"), iface, row.get("hostname"))

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

    async def read_time(self) -> Observation:
        start = datetime.now(UTC)
        response = await self.http.request("GET", SYSTEM_TIME)
        end = datetime.now(UTC)
        try:
            answer = response.json()
        except ValueError as exc:
            raise AdapterError(f"{SYSTEM_TIME}: answer is not valid JSON") from exc
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
        if root is not None:
            general = _sub(root, "general")
            st.kea = root
            st.kea_enabled = _flag(general.get("enabled"))
            st.listen = _selected(general.get("interfaces"))
            st.lifetime = _int(general.get("valid_lifetime"))
            st.subnets = dict(_items(_sub(root, "subnets").get("subnet4")))
            st.reservations = dict(_items(_sub(root, "reservations").get("reservation")))
        return st

    async def _needs_assignments(self, changes: list[Change]) -> None:
        if not any(c.kind is ChangeKind.ROUTER for c in changes):
            return
        too_old = AdapterError(
            "this OPNsense version has no interface assignment API with addresses (OPNsense "
            "26.7.6 or newer is needed to change router interfaces)"
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
        await self._needs_assignments(changes)
        st = await self._write_state()
        calls = [call for c in changes for call in w.calls_for(c, st)]
        if any(call.kea for call in calls):
            calls.append(w.Call("apply the Kea DHCP configuration", w.KEA_APPLY))
        return [call.vendor() for call in calls]

    async def _send(self, call: w.Call) -> dict[str, Any]:
        try:
            answer = await self.http.post_json(call.path, call.payload)
        except NotFound as exc:
            raise AdapterError(f"{call.path}: not available on this firewall (HTTP 404)") from exc
        if not isinstance(answer, dict):
            raise _unexpected(call.path, "not an object")
        if answer.get("errorMessage"):
            raise AdapterError(f"{call.path}: {_text(answer.get('errorMessage'))}")
        validations = answer.get("validations")
        if answer.get("result") == "failed" or validations:
            found = validations if isinstance(validations, dict) else {}
            detail = "; ".join(f"{k}: {_text(v) or v}" for k, v in found.items())
            raise AdapterError(
                f"{call.path}: the firewall refused the change" + (f" ({detail})" if detail else "")
            )
        result = answer.get("result", answer.get("status"))
        if _text(result).lower() not in ("saved", "deleted", "ok", "done"):
            raise _unexpected(call.path, f"result {result!r}")
        return answer

    async def apply(
        self, changes: list[Change], secrets: Mapping[str, str], rollback_seconds: int
    ) -> ApplyResult:
        """Send the calls change by change, each planned on a fresh read.

        OPNsense has no confirm-or-revert for API changes: no deadline is returned, and the
        deployment restores the backup when the verification fails.
        """
        await self._needs_assignments(changes)
        sent: list[w.Call] = []
        for change in changes:
            st = await self._write_state()
            for call in w.calls_for(change, st):
                await self._send(call)
                sent.append(call)
        if any(call.kea for call in sent):
            final = w.Call("apply the Kea DHCP configuration", w.KEA_APPLY)
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
        history = await self._history()
        if not history:
            raise AdapterError(
                "the configuration history is empty; set System > Configuration > History to "
                "keep backups"
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
        if backup.format != "opnsense-config-xml":
            raise AdapterError(f"not an OPNsense backup (format {backup.format})")
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
                "the stored config.xml in System > Configuration > Backups"
            )
        answer = _dict(await self.http.post_json(w.REVERT + revision, {}), w.REVERT, "the answer")
        if _text(answer.get("status")) != "reverted":
            raise AdapterError(f"{w.REVERT}{revision}: revert refused ({answer.get('status')!r})")
        for path in (w.VLAN_APPLY, w.ASSIGN_APPLY, w.KEA_APPLY):
            try:
                await self._send(w.Call("apply the restored configuration", path))
            except AdapterError as exc:
                if "HTTP 404" not in str(exc):
                    raise
        self._cache.clear()
        self._layout_cache = None


def _revision_time(text: str, where: str) -> str:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise AdapterError(f"{where}: not a config.xml ({exc})") from exc
    when = root.findtext("revision/time")
    if root.tag != "opnsense" or not when:
        raise AdapterError(f"{where}: not an OPNsense config.xml (no revision time)")
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
