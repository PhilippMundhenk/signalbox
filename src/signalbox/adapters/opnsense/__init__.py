"""OPNsense (read): interfaces and VLANs, DHCP (Kea and ISC), Unbound DNS, ARP/NDP clients.

Talks to the OPNsense REST API with an API key and secret (HTTP basic auth) over HTTPS with a
pinned certificate (:mod:`signalbox.adapters.https`). Endpoint paths and the JSON shapes assumed
for them are listed in ``docs/adapters/opnsense.md``; they are taken from the public API
documentation and still need confirmation on a real device.

Parsing is defensive: missing fields never crash, unknown fields are ignored, and an answer of
the wrong shape raises ``AdapterError("unexpected answer from <endpoint>: ...")``.

Segments: an assigned VLAN interface is segment ``<site>/segment/<tag>`` (its parent port
tagged), the untagged LAN is the native segment, any other untagged assigned interface (a DMZ
on its own port) is ``<site>/segment/<identifier>``. The WAN interface is the uplink, not a
segment of the site: it appears as a port only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator

from signalbox.adapters import Adapter as _Adapter
from signalbox.adapters import (
    AdapterConfig,
    AdapterContext,
    AdapterError,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
)
from signalbox.adapters.https import DeviceHttp, NotFound
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
    PortMembership,
    Reservation,
    Segment,
    Subnet,
    normalise_mac,
    object_id,
    port_id,
    segment_id,
)

FIRMWARE = "/api/core/firmware/status"
INTERFACES = "/api/interfaces/overview/interfacesInfo"
VLANS = "/api/interfaces/vlan_settings/searchItem"
KEA = "/api/kea/dhcpv4/get"
KEA_LEASES = "/api/kea/leases4/search"
ISC_STATUS = "/api/dhcpv4/service/status"
ISC_LEASES = "/api/dhcpv4/leases/searchLease"
UNBOUND = "/api/unbound/settings/get"
HOST_OVERRIDES = "/api/unbound/settings/searchHostOverride"
ARP = "/api/diagnostics/interface/getArp"
NDP = "/api/diagnostics/interface/getNdp"

#: Grid endpoints page their answer; ask for everything at once.
ALL_ROWS = {"current": 1, "rowCount": -1}

_SKIP_DEVICES = ("lo", "enc", "pflog", "pfsync")
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
    url: str = Field(description="Address of the web interface, https://host[:port]")
    api_key: SecretStr = Field(description="API key of a dedicated, read-only API user")
    api_secret: SecretStr = Field(description="API secret belonging to the key")
    allow_insecure_http: bool = Field(
        default=False,
        description="Allow plain http:// (simulators and tests only: sends the key unencrypted)",
    )

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("must be https://host[:port]")
        return value.rstrip("/")

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


class OpnsenseAdapter(_Adapter):
    manifest = Manifest(
        id="opnsense",
        name="OPNsense",
        version="0.1.0",
        api_version="1.0",
        vendor="Deciso",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset(
            {Capability.INTERFACES, Capability.DHCP, Capability.DNS, Capability.CLIENTS}
        ),
        config=OpnsenseConfig,
        description="Reads an OPNsense firewall through its REST API (read-only).",
    )

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
        return SystemInfo(
            vendor="Deciso",
            model=_text(product.get("product_name")) or "OPNsense",
            firmware=Firmware(current=current, available=latest if latest != current else None),
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
            name, parent, tag = _text(v.get("vlanif")), _text(v.get("if")), _int(v.get("tag"))
            if name and parent and tag is not None and 1 <= tag <= 4094:
                vlans[name] = (parent, tag, _text(v.get("descr")))

        ports: dict[str, Port] = {}
        for row in rows:
            device = _text(row.get("device"))
            if not device or device.startswith(_SKIP_DEVICES) or device in vlans:
                continue
            if row.get("vlan_tag") not in (None, "", 0, "0"):
                continue  # a VLAN the VLAN table did not list: its parent is unknown
            speed, duplex = _speed(_text(row.get("media")))
            status = _text(row.get("status")).lower()
            ports[device] = Port(
                id=port_id(dev, device),
                device_id=dev,
                name=device,
                kind=next((k for p, k in _KINDS if device.startswith(p)), PortKind.ETHERNET),
                up=(status == "up") if status else None,
                speed_mbps=speed,
                full_duplex=duplex,
                mac=_mac(row.get("macaddr")),
                vendor_extra={
                    k: _text(row.get(k)) for k in ("identifier", "description") if row.get(k)
                },
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
        return Observation(
            ports=layout.ports, segments=list(layout.segments.values()), subnets=subnets
        )

    # --- DHCP ---------------------------------------------------------------------------------

    async def read_dhcp(self) -> Observation:
        layout = await self._layout()
        servers = self._kea(layout, await self._optional(KEA))
        servers += await self._isc(layout)
        return Observation(dhcp_servers=servers)

    def _kea(self, layout: _Layout, data: Any) -> list[DhcpServer]:
        if data is None:
            return []
        root = _dict(_dict(data, KEA, "the answer").get("dhcpv4"), KEA, "dhcpv4")
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
            refs = set(_selected(r.get("subnet")))
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
            options = _sub(s, "option_data")
            routers = _addrs(options.get("routers"))
            dns = _addrs(options.get("domain_name_servers"))
            if _flag(s.get("option_data_autocollect")):
                routers, dns = routers or [own], dns or [own]
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
                    lease_seconds=lease,
                    router=routers[0] if routers else None,
                    dns_servers=dns,
                    domain=_text(options.get("domain_name")) or None,
                    reservations=reservations.get(uuid, []),
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


def _sort_key(address: IPAddress) -> tuple[int, int]:
    return (address.version, int(address))


def _unique(addresses: Iterable[IPAddress]) -> list[IPAddress]:
    out: list[IPAddress] = []
    for a in addresses:
        if a not in out:
            out.append(a)
    return out


__all__ = ["OpnsenseAdapter", "OpnsenseConfig"]
