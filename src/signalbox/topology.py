"""Topology: links discovered from LLDP, MAC tables and VPN tunnels, and the view model for
the UI. The view also draws a router behind another one (double NAT, #375) as a link inferred
from addresses, without making it a :class:`Link`: the checks only see what devices report."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from signalbox.fdb import adjacencies
from signalbox.model import (
    Device,
    GatewayGroupMember,
    GroupMode,
    Link,
    LinkKind,
    LinkOrigin,
    Membership,
    MeshPeerRole,
    NatClass,
    Network,
    Port,
    Subnet,
    Tunnel,
    TunnelPeer,
    Uplink,
    UplinkState,
    address_nat_class,
    normalise_mac,
)
from signalbox.rules import Result, RuleSettings, Severity, found, rule


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
    the nearest device only. Devices without a table count their clients' ``seen_on``; a link
    whose far port is a guess, or that no table confirms, is ``inferred`` (#378)."""
    for adj in adjacencies(net):
        yield Link(
            id=link_id(LinkOrigin.MAC, adj.local, adj.remote),
            a=adj.local,
            b=adj.remote,
            kind=LinkKind.WIRELESS if adj.wireless else LinkKind.CABLE,
            origin=LinkOrigin.MAC,
            inferred=adj.inferred,
            evidence=list(adj.evidence),
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


def _port_of_mac(net: Network, mac: str) -> Port | None:
    """The port a MAC address belongs to: a port with that address, else the Wi-Fi port of the
    SSID that sends it (its BSSID)."""
    port = next((p for p in net.ports if p.mac == mac), None)
    if port is not None:
        return port
    wlan = next((w for w in net.wlans if w.bssid == mac and w.port_id), None)
    return net.port(wlan.port_id) if wlan is not None and wlan.port_id else None


def mesh_peer_links(net: Network) -> Iterator[Link]:
    """A ``mesh`` link for every wireless peer a node reports by MAC address whose device is
    known (#171). ``a`` is the upstream end (the peer of an ``uplink``, the node for a
    ``downlink``); equal peers (802.11s) are ordered by port id."""
    for peer in sorted(net.mesh_peers, key=lambda x: x.id):
        local, remote = net.port(peer.port_id), _port_of_mac(net, peer.peer_mac)
        if local is None or remote is None or remote.device_id == local.device_id:
            continue
        if peer.role is MeshPeerRole.UPLINK:
            up, down = remote, local
        elif peer.role is MeshPeerRole.DOWNLINK:
            up, down = local, remote
        else:
            up, down = sorted((local, remote), key=lambda p: p.id)
        yield Link(
            id=link_id(LinkOrigin.MESH, up.id, down.id),
            a=up.id,
            b=down.id,
            kind=LinkKind.WIRELESS,
            origin=LinkOrigin.MESH,
            wireless=peer.wireless,
        )


def discovered_links(net: Network) -> list[Link]:
    """LLDP first; a MAC-table link only where LLDP has nothing for either port; VPN links
    between tunnels (they join tunnels, never ports)."""
    out: dict[frozenset[str], Link] = {}
    # ports the devices report as ends of a wireless backhaul (#171): nothing else is guessed there
    for link in mesh_peer_links(net):
        out.setdefault(frozenset((link.a, link.b)), link)
    meshed = {p for link in net.links if link.origin is LinkOrigin.MESH for p in (link.a, link.b)}
    meshed |= {p for pair in out for p in pair}
    for link in lldp_links(net):
        if {link.a, link.b} & meshed:
            continue
        out.setdefault(frozenset((link.a, link.b)), link)
    used = {p for pair in out for p in pair}
    for link in mac_links(net):
        pair = frozenset((link.a, link.b))
        if pair & used or pair & meshed:
            continue
        seen = out.get(pair)
        if seen is None:
            out[pair] = link
        else:  # found from both ends: one link with the evidence of both (#378)
            evidence = list(dict.fromkeys([*seen.evidence, *link.evidence]))
            inferred = seen.inferred and link.inferred
            out[pair] = seen.model_copy(update={"evidence": evidence, "inferred": inferred})
    for link in tunnel_links(net):
        out.setdefault(frozenset((link.a, link.b)), link)
    return sorted(out.values(), key=lambda link: link.id)


#: ``origin`` of a view edge from a gateway's uplink to the router in front of it (#375).
ADDRESS_ORIGIN = "address"


@dataclass(frozen=True)
class FrontLink:
    """A gateway behind another known router, found by addresses (``upstream_router``): its
    uplink, the front router's gateway subnet and the front router's port where LLDP, a MAC
    table or a host table names it (None: the link ends at the device)."""

    uplink: Uplink
    front: Subnet
    port_id: str | None


def _components(net: Network) -> dict[str, int]:
    """Device -> number of the group of devices the known (non-VPN) links connect."""
    owner = {p.id: p.device_id for p in net.ports}
    parent = {d.id: d.id for d in net.devices}

    def root(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for link in net.links:
        if link.kind is LinkKind.VPN:
            continue
        a, b = owner.get(link.a), owner.get(link.b)
        if a in parent and b in parent:
            parent[root(a)] = root(b)
    roots = sorted({root(d) for d in parent})
    return {d: roots.index(root(d)) for d in parent}


def _front_port(net: Network, uplink: Uplink, front: str) -> str | None:
    """The front router's port the inner gateway is on: its LLDP neighbour, then its MAC
    address in the front router's table, then its host entry (MAC or uplink address)."""
    inner = uplink.device_id
    macs = {p.mac for p in net.ports if p.device_id == inner and p.mac}
    by_mac, by_name = _device_index(net)
    for nb in net.neighbours:
        local = net.port(nb.local_port_id)
        if local is None or local.device_id != front:
            continue
        dev = by_mac.get(_mac(nb.chassis_id) or "") or by_name.get((nb.system_name or "").lower())
        if dev is not None and dev.id == inner:
            return local.id
    for entry in net.fdb:
        port = net.port(entry.port_id)
        if entry.mac in macs and port is not None and port.device_id == front:
            return port.id
    addresses = {a.ip for a in uplink.addresses}
    for client in net.clients:
        port = net.port(client.seen_on or "")
        if port is None or port.device_id != front:
            continue
        if client.mac in macs or addresses & set(client.addresses):
            return port.id
    return None


def front_links(net: Network) -> list[FrontLink]:
    """Every gateway uplink with an address in another known router's gateway subnet (double
    NAT), whatever the integration, where no link the devices report joins the two already."""
    groups = _components(net)
    out = []
    for uplink in sorted(net.uplinks, key=lambda u: u.id):
        front = net.upstream_router(uplink)
        if front is None:
            continue
        inner, outer = uplink.device_id, front.device_id
        if inner not in groups or outer not in groups:
            continue
        if groups[inner] == groups[outer]:
            continue  # LLDP or MAC tables already connect them (directly or through switches)
        out.append(FrontLink(uplink, front, _front_port(net, uplink, outer)))
    return out


#: Id of the one Internet cloud of the whole topology (#534): not a device.
INTERNET_ID = "internet"
#: ``origin`` and ``kind`` of the edges from a border router's uplink to the cloud.
WAN_ORIGIN = "wan"


def _uplink_state(uplink: Uplink, member: GatewayGroupMember | None) -> UplinkState | None:
    """What the monitor of the router says (group member first, then the uplink's own health),
    else ``down`` / ``online`` from the connection state; None: not known."""
    if member is not None and member.state is not None:
        return member.state
    if uplink.health is not None:
        return uplink.health.state
    if uplink.up is None:
        return None
    return UplinkState.ONLINE if uplink.up else UplinkState.DOWN


def _uplink_roles(net: Network) -> dict[str, tuple[str, str | None, GatewayGroupMember | None]]:
    """Uplink id -> (``active`` or ``backup``, group name, member) in its gateway group (#150,
    #455). Failover: the reported active member, else the first tier; balancing: every member
    that is not on standby. An uplink in no group is not here (a single line)."""
    out: dict[str, tuple[str, str | None, GatewayGroupMember | None]] = {}
    for group in sorted(net.gateway_groups, key=lambda g: g.id):
        first = min((m.tier for m in group.members), default=1)
        for m in group.members:
            if not m.uplink_id:
                continue
            if group.active is not None:
                role = "active" if m.name == group.active else "backup"
            elif group.mode is GroupMode.BALANCE:
                role = "backup" if m.state is UplinkState.STANDBY else "active"
            else:
                role = "active" if m.tier == first else "backup"
            if m.uplink_id not in out or role == "active":
                out[m.uplink_id] = (role, group.name, m)
    return out


def internet_view(
    net: Network, nodes: set[str], end: Callable[[str], dict[str, Any]]
) -> dict[str, Any] | None:
    """The Internet cloud and its edges (#534): one cloud for the whole topology, one edge per
    uplink of a device in ``nodes`` that has no known router in front of it (``upstream_router``;
    a double-NAT router is drawn to that router by ``front_links`` instead). None without edges.
    The edge starts at the uplink's port and carries state, kind, NAT class and public address."""
    roles = _uplink_roles(net)
    edges = []
    for up in sorted(net.uplinks, key=lambda u: u.id):
        if up.device_id not in nodes or net.upstream_router(up) is not None:
            continue
        role, group, member = roles.get(up.id, ("single", None, None))
        state = _uplink_state(up, member)
        own = net.port(up.port_id) if up.port_id else None
        if own is not None:
            inner = end(own.id) | {"uplink": True}
        else:  # no port for the uplink (Fritz!Box): the wire starts at the device box
            inner = _unknown_end(up.id, up.device_id, up.name or "uplink", up=up.up, uplink=True)
        nat = up.nat_class()
        public = next((a.ip for a in up.ipv4() if address_nat_class(a.ip) is NatClass.PUBLIC), None)
        if public is None and nat is NatClass.PUBLIC:
            public = up.public_ipv4
        edges.append(
            {
                "id": f"{WAN_ORIGIN}:{up.id}",
                "kind": WAN_ORIGIN,
                "origin": WAN_ORIGIN,
                "a": inner,
                "b": {
                    "port_id": INTERNET_ID,
                    "device_id": INTERNET_ID,
                    "port": INTERNET_ID,
                    "known": False,
                    "cloud": True,
                },
                "segments": [],
                "wan": {
                    "uplink_id": up.id,
                    "name": up.name,
                    "kind": up.kind.value,
                    "state": state.value if state else None,
                    "down": state is UplinkState.DOWN,
                    "role": role,
                    "group": group,
                    "nat": nat.value if nat else None,
                    "address": str(public) if public else None,
                },
            }
        )
    return {"id": INTERNET_ID, "edges": edges} if edges else None


def _unknown_end(
    port_id: str, device_id: str, name: str, *, up: bool | None, uplink: bool
) -> dict[str, Any]:
    """An end of an inferred edge without a known port: the wire ends at the device box."""
    return {
        "port_id": port_id,
        "device_id": device_id,
        "port": name,
        "known": False,
        "speed_mbps": None,
        "max_speed_mbps": None,
        "mtu": None,
        "up": up,
        "uplink": uplink,
        "lag": None,
    }


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


def _weak_backhaul(
    net: Network, settings: Mapping[str, RuleSettings] | None
) -> Callable[[Link], bool]:
    """Whether a wireless backhaul link is weak by the thresholds of ``mesh.weak-backhaul``
    (rule parameters of the node's scope, #459); never, while that rule is switched off."""
    from signalbox.rules._params import Resolver
    from signalbox.rules.mesh_checks import WeakBackhaulParams, is_weak

    settings = settings or {}
    own = settings.get(WeakBackhaulParams.rule_id)
    resolver = Resolver(net, settings, {WeakBackhaulParams.rule_id: WeakBackhaulParams})

    def weak(link: Link) -> bool:
        if link.wireless is None or link.origin is not LinkOrigin.MESH:
            return False
        if own is not None and own.enabled is False:
            return False
        port = net.port(link.b)
        node = port.device_id if port else None
        return is_weak(link.wireless, resolver.params(WeakBackhaulParams, node))

    return weak


def view(net: Network, settings: Mapping[str, RuleSettings] | None = None) -> dict[str, Any]:
    """Nodes, edges with VLANs per end, and clients per port, for the topology page.
    ``settings``: the rule settings (the thresholds that colour a weak wireless backhaul)."""
    weak = _weak_backhaul(net, settings)
    modes: dict[str, dict[str, str]] = {}  # port id -> segment id -> mode
    for seg in net.segments:
        for m in seg.members:
            modes.setdefault(m.port_id, {})[seg.id] = m.mode.value
    seg_names = {
        s.id: (s.name or (f"VLAN {s.vlan}" if s.vlan else "untagged")) for s in net.segments
    }

    tunnels = {t.id: t for t in net.tunnels}
    # LAG membership (#157): a cable of a LAG member is drawn as part of one bundled link
    lags = {m.id: g for g in net.lag_groups().values() for m in g.members}

    def lag_view(port_id: str) -> dict[str, Any] | None:
        group = lags.get(port_id)
        if group is None:
            return None
        return {
            "name": group.name,
            "port_id": group.port.id if group.port is not None else None,
            "mode": group.mode.value if group.mode is not None else None,
        }

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
                "lag": None,
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
            "lag": lag_view(port_id),
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
                "inferred": link.inferred,
                "evidence": [e.model_dump(mode="json") for e in link.evidence],
                # radio details of a wireless backhaul link (#171)
                "wireless": link.wireless.model_dump(mode="json") if link.wireless else None,
                "weak": weak(link),
            }
        )
    for fl in front_links(net):
        up = fl.uplink
        own = net.port(up.port_id) if up.port_id else None
        if own is not None:
            inner = end(own.id) | {"uplink": True}
        else:  # no port for the uplink (Fritz!Box): the wire ends at the device box
            inner = _unknown_end(up.id, up.device_id, up.name or "uplink", up=up.up, uplink=True)
        front_id = fl.front.device_id
        lan = {fl.front.segment_id: Membership.UNTAGGED.value}
        if fl.port_id is not None:
            outer, theirs = end(fl.port_id), modes.get(fl.port_id, {})
        else:
            device = net.device(front_id)
            name = device.name if device else front_id
            outer, theirs = _unknown_end(front_id, front_id, name, up=None, uplink=False), lan
        edges.append(
            {
                "id": f"{ADDRESS_ORIGIN}:{up.id}",
                "kind": LinkKind.CABLE.value,
                "origin": ADDRESS_ORIGIN,
                "a": inner,
                "b": outer,
                "segments": [
                    {
                        "segment_id": sid,
                        "name": seg_names.get(sid, sid),
                        "a": lan.get(sid),
                        "b": theirs.get(sid),
                        "consistent": lan.get(sid) == theirs.get(sid),
                    }
                    for sid in sorted(set(lan) | set(theirs))
                ],
                # the uplink address in the front router's network: what the link is inferred from
                "addresses": [str(a.ip) for a in up.ipv4() if a.ip in fl.front.interface.network],
            }
        )
    clients: dict[str, list[dict[str, Any]]] = {}
    for c in net.clients:
        if c.seen_on:
            clients.setdefault(c.seen_on, []).append(
                {"mac": c.mac, "hostname": c.hostname, "segment_id": c.segment_id}
            )
    from signalbox.rules.stp_checks import root_bridges  # the rules import this module

    stp_roots = {dev for dev, _ in root_bridges(net)}
    ported = {p.device_id for p in net.ports}

    def hosted_view(host: Device) -> list[dict[str, Any]]:
        """The services drawn inside a device's box (#387): what runs on it and has no ports."""
        return [
            {
                "id": h.id,
                "name": h.name,
                "role": h.role.value,
                "kind": h.model or h.adapter,
                "port": h.management_port,
                "status": net.statuses.get(h.id, "ok"),
            }
            for h in net.hosted_here(host.id)
            if h.id not in ported
        ]

    nodes = [
        {
            "id": d.id,
            "name": d.name,
            "role": d.role.value,
            "site_id": d.site_id,
            "status": net.statuses.get(d.id, "ok"),
            "hosted": hosted_view(d),
            # the root bridge of a spanning tree (#155)
            "stp_root": d.id in stp_roots,
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
                    "lag": lags[p.id].name if p.id in lags else None,
                    "stp_state": p.stp.state.value if p.stp and p.stp.state else None,
                    "untagged": [s for s, m in modes.get(p.id, {}).items() if m == "untagged"],
                    "tagged": [s for s, m in modes.get(p.id, {}).items() if m == "tagged"],
                }
                for p in net.ports
                if p.device_id == d.id
            ],
        }
        for d in net.devices
        if d.id in ported or d.hosted_on is None
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
        # the one Internet cloud with an edge per uplink without a known router in front (#534)
        "internet": internet_view(net, {str(n["id"]) for n in nodes}, end),
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
