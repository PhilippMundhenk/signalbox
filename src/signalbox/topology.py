"""Topology: links discovered from LLDP, MAC tables and VPN tunnels, and the view model for
the UI."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any

from signalbox.fdb import adjacencies
from signalbox.model import (
    Device,
    Link,
    LinkKind,
    LinkOrigin,
    Membership,
    Network,
    Port,
    Tunnel,
    TunnelPeer,
    normalise_mac,
)
from signalbox.rules import Result, Severity, found, rule


def link_id(origin: LinkOrigin, a: str, b: str) -> str:
    x, y = sorted((a, b))
    return f"{origin.value}:{x}~{y}"


def _mac(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return normalise_mac(value)
    except ValueError:
        return None


def _device_index(net: Network) -> tuple[dict[str, Device], dict[str, Device]]:
    """Lookups: chassis/MAC → device, name → device."""
    by_mac: dict[str, Device] = {}
    for p in net.ports:
        dev = net.device(p.device_id)
        if p.mac and dev:
            by_mac.setdefault(p.mac, dev)
    by_name = {d.name.lower(): d for d in net.devices}
    return by_mac, by_name


def _remote_port(net: Network, device: Device, name: str | None) -> Port | None:
    if not name:
        return None
    ports = [p for p in net.ports if p.device_id == device.id]
    wanted = name.lower()
    return next((p for p in ports if p.name.lower() == wanted), None) or next(
        (p for p in ports if p.mac and p.mac == _mac(name)), None
    )


def lldp_links(net: Network) -> Iterator[Link]:
    """A link for every LLDP neighbour that is a known device with a known port."""
    by_mac, by_name = _device_index(net)
    for nb in net.neighbours:
        local = net.port(nb.local_port_id)
        if local is None:
            continue
        dev = by_mac.get(_mac(nb.chassis_id) or "") or by_name.get((nb.system_name or "").lower())
        if dev is None or dev.id == local.device_id:
            continue
        remote = _remote_port(net, dev, nb.remote_port)
        if remote is None:
            continue
        yield Link(
            id=link_id(LinkOrigin.LLDP, local.id, remote.id),
            a=local.id,
            b=remote.id,
            kind=LinkKind.WIRELESS if nb.wireless else LinkKind.CABLE,
            origin=LinkOrigin.LLDP,
        )


def mac_links(net: Network) -> Iterator[Link]:
    """A link where a port of one device learns another managed device's address in its
    forwarding database (#160, :mod:`signalbox.fdb`): also through switches that are not read,
    the nearest device only. Devices without a table count their clients' ``seen_on``."""
    for adj in adjacencies(net):
        yield Link(
            id=link_id(LinkOrigin.MAC, adj.local, adj.remote),
            a=adj.local,
            b=adj.remote,
            kind=LinkKind.WIRELESS if adj.wireless else LinkKind.CABLE,
            origin=LinkOrigin.MAC,
        )


def tunnel_links(net: Network) -> Iterator[Link]:
    """A ``vpn`` link between two read tunnels whose peers name each other's public keys
    (#239), within a site or across sites. Its ends are the tunnel ids."""
    for tunnel in net.tunnels:
        for peer in tunnel.peers:
            other = net.tunnel_end(tunnel, peer)
            if other is None or other.id < tunnel.id:
                continue  # not read, disagreeing, or found from the other end
            yield Link(
                id=link_id(LinkOrigin.TUNNEL, tunnel.id, other.id),
                a=tunnel.id,
                b=other.id,
                kind=LinkKind.VPN,
                origin=LinkOrigin.TUNNEL,
            )


def discovered_links(net: Network) -> list[Link]:
    """LLDP first; a MAC-table link only where LLDP has nothing for either port; VPN links
    between tunnels (they join tunnels, never ports)."""
    out: dict[frozenset[str], Link] = {}
    for link in lldp_links(net):
        out.setdefault(frozenset((link.a, link.b)), link)
    used = {p for pair in out for p in pair}
    for link in mac_links(net):
        pair = frozenset((link.a, link.b))
        if pair not in out and not pair & used:
            out[pair] = link
    for link in tunnel_links(net):
        out.setdefault(frozenset((link.a, link.b)), link)
    return sorted(out.values(), key=lambda link: link.id)


def _at(net: Network, tunnel: Tunnel) -> datetime | None:
    """When the tunnel was read (handshake ages are relative to the reading, not to now)."""
    if tunnel.observed_at is not None:
        return tunnel.observed_at
    device = net.device(tunnel.device_id)
    return device.observed_at if device else None


def _peer_view(net: Network, tunnel: Tunnel, peer: TunnelPeer) -> dict[str, Any]:
    """What the topology shows of one end's peer: handshake, traffic, networks behind it."""
    at = _at(net, tunnel)
    return {
        "name": peer.name,
        "latest_handshake": peer.latest_handshake.isoformat() if peer.latest_handshake else None,
        "handshake_age": peer.handshake_age(at) if at else None,
        "rx_bytes": peer.rx_bytes,
        "tx_bytes": peer.tx_bytes,
        "networks": [str(n) for n in tunnel.remote_networks(peer)],
    }


def remote_id(tunnel: Tunnel, peer: TunnelPeer) -> str:
    """Id of the unmanaged site behind a peer: the tunnel id and the start of the key."""
    key = "".join(c for c in peer.public_key if c.isalnum())[:12]
    return f"{tunnel.id}/remote/{key}"


def _vpn_edge(net: Network, link: Link, end: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    """A ``vpn`` link: each end's view of the other (handshake, traffic, networks)."""
    a, b = net.tunnel(link.a), net.tunnel(link.b)
    views: dict[str, Any] = {"a": None, "b": None}
    for side, here, there in (("a", a, b), ("b", b, a)):
        if here is None or there is None or there.public_key is None:
            continue
        peer = here.peer(there.public_key)
        if peer is not None:
            views[side] = _peer_view(net, here, peer)
    return {
        "id": link.id,
        "kind": link.kind.value,
        "origin": link.origin.value,
        "a": end(link.a),
        "b": end(link.b),
        "segments": [],
        "vpn": views,
    }


def view(net: Network) -> dict[str, Any]:
    """Nodes, edges with VLANs per end, and clients per port, for the topology page."""
    modes: dict[str, dict[str, str]] = {}  # port id -> segment id -> mode
    for seg in net.segments:
        for m in seg.members:
            modes.setdefault(m.port_id, {})[seg.id] = m.mode.value
    seg_names = {
        s.id: (s.name or (f"VLAN {s.vlan}" if s.vlan else "untagged")) for s in net.segments
    }

    tunnels = {t.id: t for t in net.tunnels}

    def end(port_id: str) -> dict[str, Any]:
        tunnel = tunnels.get(port_id)
        if tunnel is not None:
            return {
                "port_id": port_id,
                "device_id": tunnel.device_id,
                "port": tunnel.name,
                "known": True,
                "tunnel": True,
                "speed_mbps": None,
                "max_speed_mbps": None,
                "mtu": tunnel.mtu,
                "up": tunnel.up,
                "uplink": False,
            }
        port = net.port(port_id)
        return {
            "port_id": port_id,
            "device_id": port.device_id if port else port_id.split("/")[0],
            "port": port.name if port else port_id.rsplit("/", 1)[-1],
            "known": port is not None,
            "speed_mbps": port.speed_mbps if port else None,
            "max_speed_mbps": port.max_speed_mbps if port else None,
            "mtu": port.mtu if port else None,
            "up": port.up if port else None,
            "uplink": net.uplink_at(port_id) is not None,
        }

    def carried(port_id: str) -> dict[str, str]:
        """Memberships of a port; a gateway's uplink port carries the network of the router in
        front of it untagged (#148, #205), so that cable shows as consistent."""
        if port_id in modes:
            return modes[port_id]
        uplink = net.uplink_at(port_id)
        upstream = net.upstream_router(uplink) if uplink else None
        return {upstream.segment_id: Membership.UNTAGGED.value} if upstream else {}

    edges = []
    for link in net.links:
        if link.kind is LinkKind.VPN:
            edges.append(_vpn_edge(net, link, end))
            continue
        a, b = carried(link.a), carried(link.b)
        segments = [
            {
                "segment_id": sid,
                "name": seg_names.get(sid, sid),
                "a": a.get(sid),
                "b": b.get(sid),
                "consistent": a.get(sid) == b.get(sid),
            }
            for sid in sorted(set(a) | set(b))
        ]
        edges.append(
            {
                "id": link.id,
                "kind": link.kind.value,
                "origin": link.origin.value,
                "a": end(link.a),
                "b": end(link.b),
                "segments": segments,
            }
        )
    clients: dict[str, list[dict[str, Any]]] = {}
    for c in net.clients:
        if c.seen_on:
            clients.setdefault(c.seen_on, []).append(
                {"mac": c.mac, "hostname": c.hostname, "segment_id": c.segment_id}
            )
    nodes = [
        {
            "id": d.id,
            "name": d.name,
            "role": d.role.value,
            "site_id": d.site_id,
            "status": net.statuses.get(d.id, "ok"),
            "ports": [
                {
                    "id": p.id,
                    "name": p.name,
                    "kind": p.kind.value,
                    "up": p.up,
                    "description": p.description,
                    "admin_up": p.admin_up,
                    "speed_mbps": p.speed_mbps,
                    "max_speed_mbps": p.max_speed_mbps,
                    "pvid": p.pvid,
                    "pvid_segment": net.pvid_segment(p.id),
                    "mtu": p.mtu,
                    "jumbo": p.jumbo_frames(),
                    "profile": p.profile,
                    "role": p.role.value if p.role else None,
                    "external": p.external,
                    "lower": p.lower,
                    "untagged": [s for s, m in modes.get(p.id, {}).items() if m == "untagged"],
                    "tagged": [s for s, m in modes.get(p.id, {}).items() if m == "tagged"],
                }
                for p in net.ports
                if p.device_id == d.id
            ],
        }
        for d in net.devices
    ]
    remotes = []
    for tunnel, peer in net.remote_sites():
        device = net.device(tunnel.device_id)
        rid = remote_id(tunnel, peer)
        remotes.append(
            {
                "id": rid,
                "name": peer.name or f"behind {tunnel.description or tunnel.name}",
                "site_id": device.site_id if device else None,
                "device_id": tunnel.device_id,
                "tunnel_id": tunnel.id,
                "networks": [str(n) for n in tunnel.remote_networks(peer)],
            }
        )
        edges.append(
            {
                "id": link_id(LinkOrigin.TUNNEL, tunnel.id, rid),
                "kind": LinkKind.VPN.value,
                "origin": LinkOrigin.TUNNEL.value,
                "a": end(tunnel.id),
                "b": {
                    "port_id": rid,
                    "device_id": rid,
                    "port": peer.name or "peer",
                    "known": False,
                    "remote": True,
                },
                "segments": [],
                "vpn": {"a": _peer_view(net, tunnel, peer), "b": None},
            }
        )
    return {
        "nodes": nodes,
        "edges": edges,
        "clients": clients,
        "segments": seg_names,
        "remotes": remotes,
    }


@rule(
    "topology.manual-conflict",
    "Entered cable differs from what the devices report",
    Severity.WARNING,
    "A cable entered by hand connects two ports, but the devices themselves (LLDP or MAC "
    "tables) report that one of these ports is connected somewhere else. Either the cable was "
    "moved or the entry is wrong.",
)
def manual_conflict(net: Network) -> Iterator[Result]:
    discovered = [link for link in net.links if link.origin is not LinkOrigin.MANUAL]
    for manual in (link for link in net.links if link.origin is LinkOrigin.MANUAL):
        for port_id, other in ((manual.a, manual.b), (manual.b, manual.a)):
            for d in discovered:
                if port_id not in (d.a, d.b):
                    continue
                peer = d.b if d.a == port_id else d.a
                if peer != other:
                    yield found(
                        f"Entered: {port_id} ↔ {other}; {d.origin.value.upper()} sees "
                        f"{port_id} ↔ {peer}",
                        [manual.id, d.id, port_id],
                        fix="Move the cable, or update the entered link to match.",
                    )


@rule(
    "topology.untagged-only-link",
    "Link carries only the untagged network",
    Severity.INFO,
    "A link between two managed devices carries no tagged VLANs. That is fine for a network "
    "without VLANs; with VLANs it usually means a trunk was configured as an access port.",
)
def untagged_only(net: Network) -> Iterator[Result]:
    has_vlans = any(s.vlan is not None for s in net.segments)
    if not has_vlans:
        return
    tagged = {m.port_id for s in net.segments for m in s.members if m.mode is Membership.TAGGED}
    known = {m.port_id for s in net.segments for m in s.members}
    for link in net.links:
        if link.kind is LinkKind.WIRELESS:
            continue
        if {link.a, link.b} <= known and not ({link.a, link.b} & tagged):
            yield found(
                f"{link.a} ↔ {link.b} carries no tagged VLAN",
                [link.id],
                fix="If VLANs should pass here, tag them on both ports.",
            )


RULES = [manual_conflict, untagged_only]
