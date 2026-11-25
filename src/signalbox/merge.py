"""Join device snapshots into one :class:`~signalbox.model.Network`.

Purposes: a segment's purpose comes from the first device (by id) that reports one; segments and
SSIDs without a reported purpose get a name guess (``heuristic``, :mod:`signalbox.purpose`).
Declared purposes from the desired state are applied afterwards by the runner.

Untagged networks (#205): every device reports its plain LAN as ``<site>/segment/native``. When
routers of a site have untagged networks that are separate layer-2 networks (an ISP router with
a firewall behind it, each with its own LAN), :func:`_native_split` gives every further network
a segment of its own (:func:`~signalbox.model.native_segment_id`) before the segments are
joined. A site with one router is not touched.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from ipaddress import IPv4Network, IPv6Network, ip_address

from signalbox.fdb import place_clients
from signalbox.model import (
    AddressSource,
    Client,
    ClientSighting,
    Device,
    DeviceRole,
    IPAddress,
    Link,
    Membership,
    MeshMembership,
    Network,
    Port,
    PortMembership,
    PortRole,
    PrefixSource,
    Segment,
    SegmentRole,
    SegmentView,
    Site,
    Snapshot,
    Subnet,
    is_native_segment,
    native_segment_id,
    segment_id,
)
from signalbox.purpose import with_heuristics

IPNetwork = IPv4Network | IPv6Network


def _overlap(a: Iterable[IPNetwork], b: Iterable[IPNetwork]) -> bool:
    nets = list(b)
    return any(x.version == y.version and x.overlaps(y) for x in a for y in nets)


def _inside(address: str | None, nets: Iterable[IPNetwork]) -> bool:
    try:
        addr = ip_address((address or "").strip("[]"))
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _owner(port: str, devices: dict[str, Device]) -> str | None:
    """Device id of a port id (``<device>/port/<name>``) when it is one of ``devices``."""
    device = port.split("/port/", 1)[0]
    return device if device in devices and device != port else None


class _Groups:
    """Union-find over router ids; the representative is the lowest id."""

    def __init__(self, ids: Iterable[str]) -> None:
        self.parent = {i: i for i in ids}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.parent[max(ra, rb)] = min(ra, rb)
        return True


def _native_split(snaps: list[Snapshot], links: list[Link]) -> dict[str, str]:
    """Device id -> native segment id for the devices of sites with more than one separate
    untagged network; empty when there is none, so single-router sites stay as they are.

    1. Every router (a subnet on the native segment that is marked as gateway or belongs to a
       device with the gateway role) has a network; routers with overlapping subnets (the same
       LAN, a redundant pair, a router in access-point mode) share one.
    2. Other devices join the network whose subnet holds their management address.
    3. A link between two ports that both send the native network untagged joins the networks
       of its ends (a switch or access point that carries both); an end whose device has no
       network yet takes the other one's.
    4. With more than one network left at a site, the main one keeps ``<site>/segment/native``:
       the one that is not in front of another router (no other router's uplink address in
       it), then the one most switches and access points are managed in, then the one of the
       lowest router id. The others are named after their lowest router id.
    """
    devices = {d.id: d for s in snaps for d in (s.device, *s.extra_devices)}
    routers: dict[str, list[IPNetwork]] = {}
    for snap in snaps:
        for sub in snap.subnets:
            dev = devices.get(sub.device_id)
            if dev is None or sub.segment_id != segment_id(dev.site_id, None):
                continue
            if not sub.interface.ip.is_link_local and (
                sub.gateway or dev.role is DeviceRole.GATEWAY
            ):
                routers.setdefault(dev.id, []).append(sub.interface.network)
    per_site: dict[str, list[str]] = {}
    for r in sorted(routers):
        per_site.setdefault(devices[r].site_id, []).append(r)
    if all(len(rs) < 2 for rs in per_site.values()):
        return {}
    groups = _Groups(routers)
    for rs in per_site.values():
        for i, a in enumerate(rs):
            for b in rs[i + 1 :]:
                if _overlap(routers[a], routers[b]):
                    groups.union(a, b)
    member: dict[str, str] = {r: r for r in routers}  # device -> a router of its network
    managed: dict[str, str] = {}
    for dev in sorted(devices.values(), key=lambda d: d.id):
        if dev.id in routers:
            continue
        first = next(
            (
                c
                for c in per_site.get(dev.site_id, [])
                if _inside(dev.management_address, routers[c])
            ),
            None,
        )
        if first is not None:
            member[dev.id] = managed[dev.id] = first
    native_ports = {
        m.port_id
        for snap in snaps
        for seg in snap.segments
        if seg.id == segment_id(seg.site_id, None)
        for m in seg.members
        if m.mode is Membership.UNTAGGED
    }
    changed = True
    while changed:
        changed = False
        for link in links:
            if link.a not in native_ports or link.b not in native_ports:
                continue
            end_a, end_b = _owner(link.a, devices), _owner(link.b, devices)
            if end_a is None or end_b is None or devices[end_a].site_id != devices[end_b].site_id:
                continue
            ga, gb = member.get(end_a), member.get(end_b)
            if ga is not None and gb is not None:
                changed |= groups.union(ga, gb)
            elif ga is not None:
                member[end_b] = ga
                changed = True
            elif gb is not None:
                member[end_a] = gb
                changed = True
    out: dict[str, str] = {}
    for site, rs in sorted(per_site.items()):
        roots = sorted({groups.find(r) for r in rs})
        if len(roots) < 2:
            continue
        nets = {g: [n for r in rs if groups.find(r) == g for n in routers[r]] for g in roots}
        in_front = {
            g
            for snap in snaps
            for u in snap.uplinks
            if u.device_id in routers and devices[u.device_id].site_id == site
            for g in roots
            if groups.find(u.device_id) != g and _overlap([a.network for a in u.addresses], nets[g])
        }
        count = {g: sum(groups.find(r) == g for r in managed.values()) for g in roots}
        main = min(roots, key=lambda g: (g in in_front, -count[g], g))
        for dev_id, r in member.items():
            if devices[dev_id].site_id == site:
                g = groups.find(r)
                out[dev_id] = native_segment_id(site, None if g == main else g)
    return out


def _split_snapshot(snap: Snapshot, native: dict[str, str]) -> Snapshot:
    """The snapshot with its native references moved to the network of the device they
    belong to: memberships by the port's device, subnets, DHCP servers and SSIDs by their
    device, clients by their addresses (else where they were seen, else the reporting device).
    """
    devices = {d.id: d for d in (snap.device, *snap.extra_devices)}
    home = snap.device.id

    def main(dev: Device) -> str:
        return segment_id(dev.site_id, None)

    def of(device_id: str, sid: str | None) -> str | None:
        dev = devices.get(device_id, snap.device)
        return native.get(dev.id, sid) if sid == main(dev) else sid

    segments: list[Segment] = []
    for seg in snap.segments:
        if seg.id != segment_id(seg.site_id, None):
            segments.append(seg)
            continue
        own = native.get(home, seg.id)
        parts: dict[str, list[PortMembership]] = {own: []}
        for m in seg.members:
            parts.setdefault(native.get(_owner(m.port_id, devices) or home, seg.id), []).append(m)
        segments += [
            seg.model_copy(update={"id": sid, "members": members})
            for sid, members in parts.items()
            if members or sid == own
        ]
    subnets = [
        s.model_copy(update={"segment_id": of(s.device_id, s.segment_id)}) for s in snap.subnets
    ]
    networks: dict[str, list[IPNetwork]] = {}
    for sub in subnets:
        if is_native_segment(sub.segment_id):
            networks.setdefault(sub.segment_id, []).append(sub.interface.network)

    def client(c: Client) -> Client:
        if c.segment_id is None or c.segment_id != main(snap.device):
            return c
        for sid in sorted(networks):
            if any(_inside(str(a), networks[sid]) for a in c.addresses):
                return c.model_copy(update={"segment_id": sid})
        seen = _owner(c.seen_on or "", devices) or home
        return c.model_copy(update={"segment_id": native.get(seen, c.segment_id)})

    def device(d: Device) -> Device:
        ntp = d.time.ntp_server if d.time else None
        if d.time is None or ntp is None or not ntp.segments:
            return d
        moved = ntp.model_copy(update={"segments": [of(d.id, s) or s for s in ntp.segments]})
        return d.model_copy(update={"time": d.time.model_copy(update={"ntp_server": moved})})

    return snap.model_copy(
        update={
            "device": device(snap.device),
            "extra_devices": [device(d) for d in snap.extra_devices],
            "segments": segments,
            "subnets": subnets,
            "dhcp_servers": [
                s.model_copy(update={"segment_id": of(s.device_id, s.segment_id)})
                for s in snap.dhcp_servers
            ],
            "portals": [
                p.model_copy(update={"segments": [of(p.device_id, s) or s for s in p.segments]})
                for p in snap.portals
            ],
            "dhcp_relays": [
                r.model_copy(update={"segment_id": of(r.device_id, r.segment_id)})
                for r in snap.dhcp_relays
            ],
            "dhcp6_servers": [
                s.model_copy(update={"segment_id": of(s.device_id, s.segment_id)})
                for s in snap.dhcp6_servers
            ],
            "router_adverts": [
                r.model_copy(update={"segment_id": of(r.device_id, r.segment_id)})
                for r in snap.router_adverts
            ],
            "server_sightings": [
                x.model_copy(update={"segment_id": of(x.device_id, x.segment_id)})
                for x in snap.server_sightings
            ],
            "wlans": [
                w.model_copy(update={"segment_id": of(w.device_id, w.segment_id)})
                for w in snap.wlans
            ],
            "services": [
                s.model_copy(update={"segments": [of(s.device_id, x) or x for x in s.segments]})
                for s in snap.services
            ],
            "firewalls": [
                f.model_copy(
                    update={
                        "zones": [
                            z.model_copy(
                                update={"segments": [of(f.device_id, x) or x for x in z.segments]}
                            )
                            for z in f.zones
                        ]
                    }
                )
                for f in snap.firewalls
            ],
            "clients": [client(c) for c in snap.clients],
            "routing_rules": [
                r.model_copy(update={"segment_id": of(r.device_id, r.segment_id)})
                for r in snap.routing_rules
            ],
            "fdb": [
                e.model_copy(update={"segment_id": of(e.device_id, e.segment_id)}) for e in snap.fdb
            ],
        }
    )


def _name_natives(segments: list[Segment], snaps: list[Snapshot]) -> list[Segment]:
    """Further native segments get their router's name: ``lan (fw)``, ``fw`` without a name."""
    names = {
        native_segment_id(d.site_id, d.id): d.name
        for s in snaps
        for d in (s.device, *s.extra_devices)
    }
    out = []
    for seg in segments:
        if is_native_segment(seg.id) and seg.id != segment_id(seg.site_id, None):
            router = names.get(seg.id)
            if router:
                seg = seg.model_copy(
                    update={"name": f"{seg.name} ({router})" if seg.name else router}
                )
        out.append(seg)
    return out


def _view(snap: Snapshot, seg: Segment) -> SegmentView:
    """What the device of ``snap`` says about ``seg`` (#165)."""
    dev = snap.device
    own = [m for m in seg.members if m.port_id.startswith(f"{dev.id}/")]
    if dev.role is DeviceRole.GATEWAY:
        role = SegmentRole.GATEWAY
    elif dev.role is DeviceRole.AP:
        role = SegmentRole.WIRELESS
    elif any(m.mode is Membership.TAGGED for m in own):
        role = SegmentRole.TRUNK
    else:
        role = SegmentRole.ACCESS
    ports = {p.id: p for p in snap.ports}
    layered = sorted(
        ports[m.port_id].name
        for m in own
        if m.port_id in ports and ports[m.port_id].role in (PortRole.VLAN, PortRole.BRIDGE)
    )
    name = seg.name.strip() if seg.name and seg.name.strip() else None
    return SegmentView(
        device_id=dev.id,
        name=name,
        interface=layered[0] if len(layered) == 1 else None,
        role=role,
    )


def _display_name(views: list[SegmentView], first: str | None) -> str | None:
    """The merged name: the first gateway's, else the first by device id (#165)."""
    for view in views:
        if view.role is SegmentRole.GATEWAY and view.name:
            return view.name
    return first


def _merge_segments(snaps: list[Snapshot]) -> list[Segment]:
    """One segment per id; a port's membership is taken from the device that owns the port.

    Other devices may report foreign ports (for example a controller that knows its switches);
    their view only fills gaps.
    """
    merged: dict[str, Segment] = {}
    members: dict[str, dict[str, tuple[bool, PortMembership]]] = {}
    for snap in snaps:
        own = f"{snap.device.id}/"
        for seg in snap.segments:
            old = merged.get(seg.id)
            names = dict(old.names_by_device) if old else {}
            views = [*old.views, _view(snap, seg)] if old else [_view(snap, seg)]
            if seg.name and seg.name.strip():
                names.setdefault(snap.device.id, seg.name)
            merged[seg.id] = (
                seg.model_copy(
                    update={
                        "source": None,
                        "vendor_extra": {},
                        "names_by_device": names,
                        "views": views,
                    }
                )
                if old is None
                else old.model_copy(
                    update={
                        "name": old.name or seg.name,
                        "names_by_device": names,
                        "views": views,
                        # the first device that reports a purpose (or isolation) wins
                        "purpose": old.purpose or seg.purpose,
                        "purpose_source": old.purpose_source if old.purpose else seg.purpose_source,
                        "isolated": old.isolated if old.isolated is not None else seg.isolated,
                    }
                )
            )
            known = members.setdefault(seg.id, {})
            for m in seg.members:
                owned = m.port_id.startswith(own)
                if m.port_id not in known or (owned and not known[m.port_id][0]):
                    known[m.port_id] = (owned, m)
    result = []
    for sid in sorted(merged):
        by_port = members[sid]
        seg = merged[sid]
        result.append(
            seg.model_copy(
                update={
                    "name": _display_name(seg.views, seg.name),
                    "members": [by_port[p][1] for p in sorted(by_port)],
                }
            )
        )
    return result


def _merge_sources(old: Client, new: Client) -> dict[IPAddress, AddressSource]:
    """Address sources of both; the more specific device's wins unless it says ``unknown``."""
    out = dict(new.address_sources)
    for addr, src in old.address_sources.items():
        if src is not AddressSource.UNKNOWN or addr not in out:
            out[addr] = src
    return out


def _sighting(snap: Snapshot, c: Client) -> ClientSighting:
    return ClientSighting(
        device_id=snap.device.id,
        segment_id=c.segment_id,
        seen_on=c.seen_on,
        addresses=list(c.addresses),
        observed_at=c.observed_at or snap.observed_at,
    )


def _merge_clients(snapshots: list[Snapshot]) -> list[Client]:
    """One client per MAC address.

    Addresses are joined. Where it was seen comes from the most specific device: an access point
    or switch knows the port, a gateway only knows the client exists. A wired client's port is
    then taken from the forwarding databases where they know it (#160,
    :func:`signalbox.fdb.place_clients`).
    """
    rank = {DeviceRole.AP: 0, DeviceRole.SWITCH: 1, DeviceRole.OTHER: 2, DeviceRole.GATEWAY: 3}
    ordered = sorted(snapshots, key=lambda s: (rank[s.device.role], s.device.id))
    merged: dict[str, Client] = {}
    for snap in ordered:
        for c in snap.clients:
            old = merged.get(c.mac)
            seen = _sighting(snap, c)
            if old is None:
                merged[c.mac] = c.model_copy(update={"id": f"client/{c.mac}", "sightings": [seen]})
                continue
            addresses = list(dict.fromkeys([*old.addresses, *c.addresses]))
            last_seen = max(
                (t for t in (old.last_seen, c.last_seen) if t is not None), default=None
            )
            merged[c.mac] = old.model_copy(
                update={
                    "addresses": addresses,
                    "hostname": old.hostname or c.hostname,
                    "segment_id": old.segment_id or c.segment_id,
                    "seen_on": old.seen_on or c.seen_on,
                    "wireless": old.wireless or c.wireless,
                    "last_seen": last_seen,
                    "address_sources": _merge_sources(old, c),
                    "sightings": [*old.sightings, seen],
                }
            )
    return sorted(merged.values(), key=lambda c: c.mac)


def _address_key(address: str | None) -> str | None:
    text = (address or "").strip().strip("[]").lower()
    if not text:
        return None
    try:
        return str(ip_address(text))
    except ValueError:
        return text


def hosting(
    devices: list[Device], ported: set[str], declared: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Device id -> id of the device it runs on (#387).

    A device without ports of its own whose management address is the address of exactly one
    device that has ports (an AdGuard Home on the router, another port) runs on that device;
    two services on the same port are one device. ``declared`` (from the device settings) wins
    over this guess. A host is never hosted itself."""
    own = [d for d in devices if d.managed_by is None]
    known = {d.id for d in own}
    by_address: dict[str, list[Device]] = {}
    for d in own:
        key = _address_key(d.management_address)
        if key:
            by_address.setdefault(key, []).append(d)
    out: dict[str, str] = {}
    for d in own:
        want = (declared or {}).get(d.id)
        if want:
            if want != d.id and want in known:
                out[d.id] = want
            continue
        key = _address_key(d.management_address)
        if key is None or d.id in ported:
            continue
        hosts = [
            h
            for h in by_address[key]
            if h.id != d.id
            and h.id in ported
            and not (h.management_port and h.management_port == d.management_port)
        ]
        if len(hosts) == 1:
            out[d.id] = hosts[0].id
    return {k: v for k, v in out.items() if v not in out}


_ULA = IPv6Network("fc00::/7")


def prefix_sources(snaps: Iterable[Snapshot]) -> list[Subnet]:
    """The subnets of all snapshots with ``prefix_source`` filled in where a device did not say
    (#151): an IPv6 subnet inside a delegated prefix of an uplink of the same site is
    ``delegated``, one in fc00::/7 is ``ula``; every other stays unknown (not guessed)."""
    snaps = list(snaps)
    delegated: dict[str, list[IPv6Network]] = {}
    for snap in snaps:
        for up in snap.uplinks:
            delegated.setdefault(snap.device.site_id, []).extend(up.delegated_prefixes)
    out: list[Subnet] = []
    for snap in snaps:
        for sub in snap.subnets:
            net = sub.interface.network
            if sub.prefix_source is None and isinstance(net, IPv6Network):
                if net.subnet_of(_ULA):
                    sub = sub.model_copy(update={"prefix_source": PrefixSource.ULA})
                elif any(net.subnet_of(p) for p in delegated.get(snap.device.site_id, [])):
                    sub = sub.model_copy(update={"prefix_source": PrefixSource.DELEGATED})
            out.append(sub)
    return out


def _device_macs(dev: Device, ports: Iterable[Port]) -> set[str]:
    return {m for m in (dev.mac, *(p.mac for p in ports if p.device_id == dev.id)) if m}


def _merge_mesh_nodes(snaps: list[Snapshot]) -> list[Snapshot]:
    """A mesh node a controller reports (``extra_devices``) that is also a device of its own
    (its own snapshot) is one device (#459, a FRITZ!Box repeater set up in Signalbox): found by
    a shared MAC address (device or port). The device's own record wins; the node adds
    ``Device.mesh`` and its ports (the backhaul link ends), moved under the own device's id."""
    own = {s.device.id: _device_macs(s.device, s.ports) for s in snaps}
    remap: dict[str, str] = {}
    for s in snaps:
        for extra in s.extra_devices:
            if extra.id in own:
                continue
            macs = _device_macs(extra, s.ports)
            for did, other in sorted(own.items()):
                if did != s.device.id and macs & other:
                    remap[extra.id] = did
                    break
    if not remap:
        return snaps

    def fix(text: str) -> str:
        for old, new in remap.items():
            text = text.replace(f"{old}/port/", f"{new}/port/")
        return text

    def membership(m: MeshMembership | None) -> MeshMembership | None:
        if m is not None and m.controller_id in remap:
            return m.model_copy(update={"controller_id": remap[m.controller_id]})
        return m

    nodes = {remap[e.id]: e for s in snaps for e in s.extra_devices if e.id in remap}
    out: list[Snapshot] = []
    for s in snaps:
        extras = [
            e.model_copy(update={"mesh": membership(e.mesh)})
            for e in s.extra_devices
            if e.id not in remap
        ]
        dev = s.device
        node = nodes.get(dev.id)
        mesh = dev.mesh or (node.mesh if node else None)
        dev = dev.model_copy(update={"mesh": membership(mesh)})
        have = {p.id for p in s.ports}
        ports: list[Port] = []
        for p in s.ports:
            if p.device_id in remap:
                p = p.model_copy(update={"id": fix(p.id), "device_id": remap[p.device_id]})
                if p.id in have:
                    continue
            ports.append(p)
        links = [
            x.model_copy(update={"id": fix(x.id), "a": fix(x.a), "b": fix(x.b)})
            for x in s.wireless_links
        ]
        status = {k: v for k, v in s.extra_status.items() if k not in remap}
        out.append(
            s.model_copy(
                update={
                    "device": dev,
                    "extra_devices": extras,
                    "extra_status": status,
                    "ports": ports,
                    "wireless_links": links,
                }
            )
        )
    return out


def _with_mesh_links(links: Iterable[Link], snaps: list[Snapshot]) -> list[Link]:
    """The known links plus the wireless backhaul links the devices report (#171); a manual
    link between the same two ports wins, then the first report."""
    out = list(links)
    ids = {x.id for x in out}
    pairs = {frozenset((x.a, x.b)) for x in out}
    for s in snaps:
        for link in s.wireless_links:
            pair = frozenset((link.a, link.b))
            if link.id in ids or pair in pairs:
                continue
            ids.add(link.id)
            pairs.add(pair)
            out.append(link)
    return out


def merge(
    sites: Iterable[Site],
    snapshots: Iterable[Snapshot],
    links: Iterable[Link] = (),
    hosted_on: Mapping[str, str] | None = None,
) -> Network:
    """Merge snapshots (one per device) and the known links into a network. ``hosted_on``:
    devices declared to run on another device (device settings, #387)."""
    snaps = sorted(snapshots, key=lambda s: s.device.id)
    ids = [s.device.id for s in snaps]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"more than one snapshot for device(s) {', '.join(duplicates)}")
    snaps = _merge_mesh_nodes(snaps)
    links = _with_mesh_links(links, snaps)
    native = _native_split(snaps, links)
    segments = []
    if native:
        snaps = [_split_snapshot(s, native) for s in snaps]
        segments = _name_natives(_merge_segments(snaps), snaps)
    else:
        segments = _merge_segments(snaps)

    def every(attr: str) -> list[object]:
        return [item for s in snaps for item in getattr(s, attr)]

    all_devices = [d for s in snaps for d in (s.device, *s.extra_devices)]
    host_of = hosting(all_devices, {p.device_id for s in snaps for p in s.ports}, hosted_on)
    all_devices = [
        d.model_copy(update={"hosted_on": host_of[d.id]}) if d.id in host_of else d
        for d in all_devices
    ]

    net = Network.model_validate(
        {
            "sites": sorted(sites, key=lambda s: s.id),
            "devices": all_devices,
            "statuses": {
                d.id: s.extra_status.get(d.id, s.status) if d is not s.device else s.status
                for s in snaps
                for d in (s.device, *s.extra_devices)
            },
            "ports": every("ports"),
            "segments": segments,
            "subnets": prefix_sources(snaps),
            "uplinks": every("uplinks"),
            "gateway_groups": every("gateway_groups"),
            "ddns": every("ddns"),
            "portals": every("portals"),
            "services": every("services"),
            "certificates": every("certificates"),
            "dhcp_servers": every("dhcp_servers"),
            "dhcp_relays": every("dhcp_relays"),
            "dhcp6_servers": every("dhcp6_servers"),
            "router_adverts": every("router_adverts"),
            "dns_services": every("dns_services"),
            "radios": every("radios"),
            "wlans": every("wlans"),
            "clients": _merge_clients(snaps),
            "neighbours": every("neighbours"),
            "mesh_peers": every("mesh_peers"),
            "fdb": every("fdb"),
            "routes": every("routes"),
            "routing_rules": every("routing_rules"),
            "wifi_scan": every("wifi_scan"),
            "tunnels": every("tunnels"),
            "firewalls": every("firewalls"),
            "server_sightings": every("server_sightings"),
            "links": sorted(links, key=lambda link: link.id),
            "errors": every("errors"),
        }
    )
    return with_heuristics(place_clients(net))
