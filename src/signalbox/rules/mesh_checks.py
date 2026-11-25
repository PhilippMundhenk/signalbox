"""Wi-Fi mesh and wireless backhaul (#171): weak or slow backhaul links, 2.4 GHz backhaul,
long wireless chains, nodes that could use a cable, and a mesh locked to one channel.

A backhaul link is a ``Link`` of origin ``mesh`` whose ``a`` end is the upstream node's port and
whose ``b`` end is the node that uses it as its uplink. Values a device did not report are never
judged. Read-only: Signalbox observes the mesh, the vendor's controller manages it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import Band, Link, LinkKind, LinkOrigin, MeshUplink, Network
from signalbox.rules import Result, RuleParams, Severity, ctx, found, param, rule
from signalbox.rules._names import device_name

#: Defaults of the parameters below.
WEAK_SIGNAL_DBM = -75
WEAK_RATE_MBPS = 100
MAX_WIRELESS_HOPS = 2


class WeakBackhaulParams(RuleParams):
    signal_dbm: int = param(
        WEAK_SIGNAL_DBM,
        unit="dBm",
        ge=-120,
        le=-30,
        description="Backhaul signal below which a link is weak.",
    )
    rate_mbps: float = param(
        WEAK_RATE_MBPS,
        unit="Mbit/s",
        ge=1,
        le=100000,
        description="Backhaul link rate below which a link is slow.",
    )


class ChainParams(RuleParams):
    max_hops: int = param(
        MAX_WIRELESS_HOPS,
        unit="count",
        ge=1,
        le=20,
        description="Most wireless hops between a node and the wired network.",
    )


def _device(net: Network, port_id: str) -> str | None:
    port = net.port(port_id)
    return port.device_id if port else None


def _mesh_links(net: Network) -> list[Link]:
    """Backhaul links with radio details, in id order."""
    return sorted(
        (x for x in net.links if x.origin is LinkOrigin.MESH and x.wireless is not None),
        key=lambda x: x.id,
    )


def _ends(net: Network, link: Link) -> tuple[str, str] | None:
    """(upstream device, node device) of a backhaul link."""
    a, b = _device(net, link.a), _device(net, link.b)
    return (a, b) if a and b and a != b else None


# mesh.weak-backhaul ---------------------------------------------------------------------------


@rule(
    "mesh.weak-backhaul",
    "A mesh node has a weak or slow wireless backhaul",
    Severity.WARNING,
    "A repeater or mesh node reaches the network over a wireless link, and everything behind "
    "it shares that link. At a weak signal (below -75 dBm by default) or a low rate the link "
    "slows every device on that node, and wireless clients of the node pay twice. Readings "
    "the device did not report are not judged; a reading is one moment, not a trend.",
    params=WeakBackhaulParams,
)
def weak_backhaul(net: Network) -> Iterator[Result]:
    for link in _mesh_links(net):
        ends, w = _ends(net, link), link.wireless
        if ends is None or w is None:
            continue
        up, node = ends
        p = ctx.params(WeakBackhaulParams, net.device(node))
        rates = [r for r in (w.tx_rate_mbps, w.rx_rate_mbps) if r is not None]
        weak_signal = w.signal_dbm is not None and w.signal_dbm < p.signal_dbm
        slow = bool(rates) and min(rates) < p.rate_mbps
        if not (weak_signal or slow):
            continue
        parts = []
        if w.signal_dbm is not None:
            parts.append(f"{w.signal_dbm} dBm")
        if rates:
            parts.append(f"{min(rates):g} Mbit/s")
        detail = ", ".join(parts)
        name, parent = device_name(net, node), device_name(net, up)
        yield found(
            f"{name} reaches {parent} over a weak wireless backhaul ({detail})",
            [node, link.id],
            fix=f"Move {name} closer to {parent} or to another node, or connect it with a cable.",
            mid="mesh.weakBackhaul",
            fix_id="mesh.weakBackhaul.fix",
            params={"node": name, "parent": parent, "detail": detail},
        )


# mesh.backhaul-2-4 ----------------------------------------------------------------------------


@rule(
    "mesh.backhaul-2-4",
    "A mesh backhaul uses 2.4 GHz although 5 GHz is available",
    Severity.WARNING,
    "The 2.4 GHz band is slow, crowded and reaches through walls only at low rates. A wireless "
    "backhaul on it limits the whole node; if both nodes have a 5 GHz (or 6 GHz) radio, the "
    "link should use it. Only links whose band is reported and nodes whose radios are read "
    "are judged.",
)
def backhaul_2_4(net: Network) -> Iterator[Result]:
    fast: dict[str, bool] = defaultdict(bool)
    for r in net.radios:
        if r.enabled and r.band is not Band.GHZ_2_4:
            fast[r.device_id] = True
    for link in _mesh_links(net):
        ends, w = _ends(net, link), link.wireless
        if ends is None or w is None or w.band is not Band.GHZ_2_4:
            continue
        up, node = ends
        if not (fast[up] and fast[node]):
            continue
        name, parent = device_name(net, node), device_name(net, up)
        yield found(
            f"{name} reaches {parent} over 2.4 GHz although both have a 5 GHz radio",
            [node, link.id],
            fix=f"Let {name} use the 5 GHz band for its uplink, or move it closer to {parent}.",
            mid="mesh.backhaul24",
            fix_id="mesh.backhaul24.fix",
            params={"node": name, "parent": parent},
        )


# mesh.chain-too-long --------------------------------------------------------------------------


def _hops(net: Network) -> dict[str, int]:
    """Wireless hops from every mesh node to the wired network: the number the node reports
    (``Device.mesh.hop``) or, where it does not, counted along the backhaul links."""
    parent: dict[str, str] = {}
    for link in _mesh_links(net):
        ends = _ends(net, link)
        if ends is not None:
            parent.setdefault(ends[1], ends[0])
    out: dict[str, int] = {}
    for node in parent:
        seen, cur, n = {node}, node, 0
        while cur in parent and parent[cur] not in seen:
            cur = parent[cur]
            seen.add(cur)
            n += 1
        out[node] = n
    for dev in net.devices:
        if dev.mesh is not None and dev.mesh.hop is not None:
            out[dev.id] = max(out.get(dev.id, 0), dev.mesh.hop)
    return out


@rule(
    "mesh.chain-too-long",
    "A mesh node is more than two wireless hops from the wired network",
    Severity.WARNING,
    "Every wireless hop shares the air with the hop before it, so the rate roughly halves per "
    "hop, and the node fails with any node in front of it. More than two hops (by default) "
    "is rarely worth it.",
    params=ChainParams,
)
def chain_too_long(net: Network) -> Iterator[Result]:
    for node, hops in sorted(_hops(net).items()):
        dev = net.device(node)
        if dev is None:
            continue
        if hops > ctx.params(ChainParams, dev).max_hops:
            yield found(
                f"{dev.name} is {hops} wireless hops from the wired network",
                [node],
                fix=f"Connect {dev.name} or a node in front of it with a cable, so that every "
                "node is at most two hops away.",
                mid="mesh.chainTooLong",
                fix_id="mesh.chainTooLong.fix",
                params={"node": dev.name, "hops": hops},
            )


# mesh.wired-possible --------------------------------------------------------------------------


@rule(
    "mesh.wired-possible",
    "A mesh node has a cable but uses a wireless backhaul",
    Severity.INFO,
    "A node that reaches the mesh wirelessly and also has an Ethernet link to another device "
    "could use the cable as backhaul, which is faster and keeps the radio free for clients. "
    "Only nodes with a link found by LLDP, MAC tables or entered by hand are judged.",
)
def wired_possible(net: Network) -> Iterator[Result]:
    nodes: dict[str, str] = {}
    for link in _mesh_links(net):
        ends = _ends(net, link)
        if ends is not None:
            nodes.setdefault(ends[1], link.id)
    for member in net.devices:
        if member.mesh is not None and member.mesh.uplink is MeshUplink.WIRELESS:
            nodes.setdefault(member.id, "")
    for node, link_id in sorted(nodes.items()):
        cabled = [
            x
            for x in net.links
            if x.kind is LinkKind.CABLE
            and x.origin is not LinkOrigin.MESH
            and node in (_device(net, x.a), _device(net, x.b))
        ]
        dev = net.device(node)
        if not cabled or dev is None:
            continue
        yield found(
            f"{dev.name} has a cable to another device but uses a wireless backhaul",
            [node, *([link_id] if link_id else [])],
            fix=f"Make the cable the uplink of {dev.name} in the mesh settings (Ethernet "
            "backhaul), or remove the cable if it is not meant to be used.",
            mid="mesh.wiredPossible",
            fix_id="mesh.wiredPossible.fix",
            params={"node": dev.name},
        )


# mesh.channel-locked --------------------------------------------------------------------------


@rule(
    "mesh.channel-locked",
    "All nodes of a mesh use one channel",
    Severity.INFO,
    "Mesh systems put the backhaul of all nodes on one channel, so the nodes cannot pick the "
    "quietest channel each. That is how they work, not a fault; with interference on that "
    "channel, a cable backhaul is the way out. Reported once per mesh of at least three nodes "
    "whose backhaul links all report the same band and channel.",
)
def channel_locked(net: Network) -> Iterator[Result]:
    parent: dict[str, str] = {}

    def root(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    links = []
    for link in _mesh_links(net):
        ends = _ends(net, link)
        if ends is not None:
            links.append((link, ends))
            parent[root(ends[0])] = root(ends[1])
    groups: dict[str, list[Link]] = defaultdict(list)
    members: dict[str, set[str]] = defaultdict(set)
    for link, ends in links:
        groups[root(ends[0])].append(link)
        members[root(ends[0])] |= set(ends)
    for key, group in sorted(groups.items()):
        radios = {(x.wireless.band, x.wireless.channel) for x in group if x.wireless is not None}
        reported = [x for x in group if x.wireless and x.wireless.channel]
        if len(members[key]) < 3 or len(reported) != len(group) or len(radios) != 1:
            continue
        band, channel = next(iter(radios))
        band_text = f"{band.value} GHz" if band else "unknown band"
        names = ", ".join(sorted(device_name(net, d) for d in members[key]))
        yield found(
            f"The mesh of {names} uses channel {channel} ({band_text}) on all backhaul links",
            sorted(x.id for x in group),
            fix="Nothing to fix. If that channel is busy, connect nodes with a cable.",
            key=key,
            mid="mesh.channelLocked",
            fix_id="mesh.channelLocked.fix",
            params={"nodes": names, "channel": channel, "band": band_text},
        )


RULES = [weak_backhaul, backhaul_2_4, chain_too_long, wired_possible, channel_locked]
