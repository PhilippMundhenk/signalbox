"""Spanning tree and loop protection (issue #155, ADR 0023).

The checks use what the bridges report about themselves (``Device.stp_bridges``,
``Port.stp``) and the cables Signalbox knows (LLDP, MAC tables, entered by hand). Two bridges
are in one layer-2 network when a known cable joins a port of one to a port of the other.
Everything stays quiet where a device does not report its spanning tree.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from signalbox.model import (
    Device,
    DeviceRole,
    LinkKind,
    Network,
    Port,
    PortRole,
    StpBridge,
    StpPortRole,
    StpPortState,
    StpProtocol,
)
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name

#: Topology changes per hour (averaged over the uptime) from which a bridge counts as
#: flapping, and the least number of changes before that is judged.
TC_PER_HOUR = 6.0
TC_MIN = 20
#: Roles of devices whose bridges should be the root of a home network, best first.
CORE_ROLES = (DeviceRole.GATEWAY, DeviceRole.SWITCH)


@dataclass(frozen=True)
class _Bridge:
    device: Device
    stp: StpBridge
    #: port ids of the device that belong to this bridge (its own port and its members)
    ports: frozenset[str]

    @property
    def key(self) -> tuple[str, str]:
        return self.device.id, self.stp.name

    @property
    def label(self) -> str:
        if self.stp.port_id is None or len(self.device.stp_bridges or []) == 1:
            return self.device.name
        return f"{self.device.name} {self.stp.name}"


@dataclass
class _Domain:
    """Bridges joined by known cables (one layer-2 network as far as Signalbox sees)."""

    bridges: list[_Bridge] = field(default_factory=list)

    def spanning(self) -> list[_Bridge]:
        return [b for b in self.bridges if b.stp.spanning_tree]

    def roots(self) -> dict[str, list[_Bridge]]:
        """Root bridge id -> the bridges that see it."""
        out: dict[str, list[_Bridge]] = {}
        for b in self.spanning():
            if b.stp.root_bridge_id is not None:
                out.setdefault(b.stp.root_bridge_id, []).append(b)
        return out

    def by_id(self, bridge_id: str) -> _Bridge | None:
        return next((b for b in self.bridges if b.stp.bridge_id == bridge_id), None)


def _members(net: Network, port_id: str, seen: set[str] | None = None) -> set[str]:
    """A port and everything below it (a bridge's members, a LAG's jacks)."""
    seen = seen if seen is not None else set()
    if port_id in seen:
        return seen
    seen.add(port_id)
    port = net.port(port_id)
    for low in port.lower if port else []:
        _members(net, low, seen)
    return seen


def bridges(net: Network) -> list[_Bridge]:
    """Every reported bridge with the ports that belong to it. A bridge without a port of its
    own (a whole switch) owns all ports of the device that no other bridge owns."""
    out: list[_Bridge] = []
    for d in net.devices:
        own: list[tuple[StpBridge, set[str]]] = []
        for b in d.stp_bridges or []:
            own.append((b, _members(net, b.port_id) if b.port_id else set()))
        taken = {p for _, ports in own for p in ports}
        rest = {p.id for p in net.ports_of(d.id)} - taken
        for b, ports in own:
            if b.port_id is None:
                ports |= rest
            out.append(_Bridge(d, b, frozenset(ports)))
    return out


def _owner(all_bridges: list[_Bridge]) -> dict[str, _Bridge]:
    return {p: b for b in all_bridges for p in b.ports}


def _cables(net: Network) -> Iterator[tuple[str, str]]:
    for link in net.links:
        if link.kind is not LinkKind.VPN:
            yield link.a, link.b


def domains(net: Network) -> list[_Domain]:
    """The bridges grouped by the cables between them (union-find over bridge keys)."""
    all_bridges = bridges(net)
    owner = _owner(all_bridges)
    parent = {b.key: b.key for b in all_bridges}

    def find(k: tuple[str, str]) -> tuple[str, str]:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    for end_a, end_b in _cables(net):
        x, y = owner.get(end_a), owner.get(end_b)
        if x is not None and y is not None and x.key != y.key:
            parent[find(x.key)] = find(y.key)
    groups: dict[tuple[str, str], _Domain] = {}
    for b in all_bridges:
        groups.setdefault(find(b.key), _Domain()).bridges.append(b)
    return [groups[k] for k in sorted(groups)]


def _names(items: Iterable[str]) -> str:
    return ", ".join(sorted(set(items)))


def _root_label(domain: _Domain, root_id: str) -> str:
    b = domain.by_id(root_id)
    return b.label if b else root_id


def root_bridges(net: Network) -> set[tuple[str, str]]:
    """(device id, bridge name) of every bridge that is the root of its tree: reported by the
    bridge itself or by the others of its network. For the topology view."""
    out: set[tuple[str, str]] = set()
    for dom in domains(net):
        for root_id in dom.roots():
            b = dom.by_id(root_id)
            if b is not None:
                out.add(b.key)
    return out


# --- stp.several-roots ----------------------------------------------------------------------


@rule(
    "stp.several-roots",
    "More than one spanning tree root in one network",
    Severity.WARNING,
    "Switches and bridges that are connected by cables should form one spanning tree with one "
    "root bridge. When the bridges of one network name different root bridges, the spanning "
    "tree messages (BPDUs) do not get from one part to the other: a switch or bridge between "
    "them has spanning tree off and drops them, or a port filters them. A loop through both "
    "parts is then not blocked by anyone. Only bridges that report their root are compared.",
)
def several_roots(net: Network) -> Iterator[Result]:
    for dom in domains(net):
        roots = dom.roots()
        if len(roots) < 2:
            continue
        labels = _names(_root_label(dom, r) for r in roots)
        objects = sorted({b.device.id for bs in roots.values() for b in bs})
        yield found(
            f"The bridges of one network see {len(roots)} different root bridges: {labels}.",
            objects,
            fix="Turn on the same spanning tree protocol (RSTP) on every switch and bridge "
            "of this network, and look for a device between them with spanning tree off or "
            "BPDU filtering on.",
            mid="stp.severalRoots",
            fix_id="stp.severalRoots.fix",
            params={"count": len(roots), "roots": labels},
        )


# --- stp.root-not-core ----------------------------------------------------------------------


def _degree(net: Network, b: _Bridge, owner: dict[str, _Bridge]) -> int:
    """Cables from this bridge to other bridges."""
    n = 0
    for x, y in _cables(net):
        for here, there in ((x, y), (y, x)):
            far = owner.get(there)
            if here in b.ports and far is not None and far.key != b.key:
                n += 1
    return n


@rule(
    "stp.root-not-core",
    "Spanning tree root is not the core of the network",
    Severity.INFO,
    "The root bridge of a spanning tree should be the central device (the router's switch or "
    "the core switch): all traffic flows towards the root, and the links that are blocked "
    "follow from where it is. The root is the bridge with the lowest priority, and on a tie "
    "the lowest MAC address, so a cheap switch with the factory priority 32768 often wins "
    "by chance. Reported when the root is another device although a gateway or the most "
    "connected switch of the network takes part in the spanning tree.",
)
def root_not_core(net: Network) -> Iterator[Result]:
    owner = _owner(bridges(net))
    for dom in domains(net):
        roots = dom.roots()
        spanning = dom.spanning()
        if len(roots) != 1 or len(spanning) < 2:
            continue
        (root_id,) = roots
        root = dom.by_id(root_id)
        if root is not None and root.device.role is DeviceRole.GATEWAY:
            continue
        candidates: list[_Bridge] = []
        for role in CORE_ROLES:
            of_role = [b for b in spanning if b.device.role is role]
            if of_role and role is DeviceRole.SWITCH:
                best = max(_degree(net, b, owner) for b in of_role)
                of_role = [b for b in of_role if _degree(net, b, owner) == best]
            if of_role:
                candidates = of_role
                break
        if not candidates or (root is not None and root in candidates):
            continue
        core = min(candidates, key=lambda b: b.key)
        root_label = root.label if root else root_id
        prio = root.stp.priority if root and root.stp.priority is not None else None
        objects = sorted({core.device.id, *([root.device.id] if root else [])})
        if prio is not None:
            text = f"The spanning tree root is {root_label} (priority {prio}), not {core.label}."
            mid = "stp.rootNotCorePriority"
        else:
            text = f"The spanning tree root is {root_label}, not {core.label}."
            mid = "stp.rootNotCore"
        yield found(
            text,
            objects,
            fix=f"Give {core.label} a lower bridge priority (for example 4096) so that it "
            "becomes the root; the network reconverges for a few seconds.",
            mid=mid,
            fix_id="stp.rootNotCore.fix",
            params={"root": root_label, "core": core.label, "priority": prio},
        )


# --- stp.disabled-with-redundancy -------------------------------------------------------------


def _blocking(net: Network, devices: set[str]) -> bool:
    """Some port of these devices is blocked by spanning tree or loop protection."""
    return any(
        p.stp is not None
        and (
            p.stp.state in (StpPortState.BLOCKING, StpPortState.DISCARDING)
            or p.stp.role in (StpPortRole.ALTERNATE, StpPortRole.BACKUP)
        )
        for p in net.ports
        if p.device_id in devices
    )


def _lag_of(net: Network, port: Port | None) -> str | None:
    if port is None:
        return None
    if port.lag:
        return f"{port.device_id}\x00{port.lag}"
    lag = next((u for u in net.upper_ports(port.id) if u.role is PortRole.LAG), None)
    return lag.id if lag else None


def _device_graph(net: Network, without: str) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {}
    for a, b in _cables(net):
        pa, pb = net.port(a), net.port(b)
        da = pa.device_id if pa else a.split("/")[0]
        db = pb.device_id if pb else b.split("/")[0]
        if da == db or without in (da, db):
            continue
        edges.setdefault(da, set()).add(db)
        edges.setdefault(db, set()).add(da)
    return edges


def _reach(edges: dict[str, set[str]], start: str) -> set[str]:
    seen, todo = {start}, [start]
    while todo:
        for nxt in edges.get(todo.pop(), set()) - seen:
            seen.add(nxt)
            todo.append(nxt)
    return seen


@rule(
    "stp.disabled-with-redundancy",
    "Spanning tree off on a bridge in a loop",
    Severity.WARNING,
    "A bridge or switch without spanning tree forwards everything, so two paths between the "
    "same switches (two cables without a link aggregation, or a ring over several switches) "
    "form a loop: broadcasts circle forever and the network stops within seconds. Reported "
    "when the known cables of a bridge with spanning tree off lead to the same device twice, "
    "or to switches that are connected to each other another way, and no device on that loop "
    "blocks a port. Loop detection of simple switches counts as protection.",
)
def disabled_with_redundancy(net: Network) -> Iterator[Result]:
    all_bridges = bridges(net)
    for b in all_bridges:
        if b.stp.protocol is not StpProtocol.NONE:
            continue
        far: dict[str, set[str]] = {}  # remote device -> distinct local paths (port or LAG)
        for x, y in _cables(net):
            for here, there in ((x, y), (y, x)):
                if here not in b.ports:
                    continue
                remote = net.port(there)
                rdev = net.device(remote.device_id) if remote else None
                if rdev is None or rdev.id == b.device.id or rdev.role not in CORE_ROLES:
                    continue
                path = _lag_of(net, net.port(here)) or here
                far.setdefault(rdev.id, set()).add(path)
        loop: set[str] = set()
        for rid, paths in far.items():
            if len(paths) > 1:
                loop |= {rid}
        if not loop and len(far) > 1:
            edges = _device_graph(net, b.device.id)
            remotes = sorted(far)
            for i, rid in enumerate(remotes):
                reach = _reach(edges, rid)
                joined = {r for r in remotes[i + 1 :] if r in reach}
                if joined:
                    loop |= {rid, *joined} | (reach & set(edges))
                    break
        if (
            not loop
            or _blocking(net, loop | {b.device.id})
            or any(
                owner_b.stp.protocol is StpProtocol.LOOP_DETECT
                for owner_b in all_bridges
                if owner_b.device.id in loop
            )
        ):
            continue
        others = _names(device_name(net, r) for r in loop if r in far)
        yield found(
            f"{b.label} has spanning tree off, but its cables to {others} form a loop.",
            sorted({b.device.id, *(r for r in loop if r in far)}),
            fix=f"Turn on RSTP on {b.label} (and the other switches), or remove the second "
            "path, or combine parallel cables into a link aggregation.",
            mid="stp.disabledLoop",
            fix_id="stp.disabledLoop.fix",
            params={"bridge": b.label, "devices": others},
            key=b.stp.name,
        )


# --- stp.topology-changes ---------------------------------------------------------------------


@rule(
    "stp.topology-changes",
    "Frequent spanning tree topology changes",
    Severity.WARNING,
    "Every topology change makes the switches of the network forget their MAC address tables "
    "and flood traffic until they have learnt them again; frequent changes come from a port "
    "that goes up and down (a bad cable, a client that sleeps, a port that is not an edge "
    f"port). Reported from {TC_MIN} changes when they average more than "
    f"{TC_PER_HOUR:.0f} per hour since the device started.",
)
def topology_changes(net: Network) -> Iterator[Result]:
    for b in bridges(net):
        count = b.stp.topology_changes
        uptime = b.device.health.uptime_seconds if b.device.health else None
        if count is None or count < TC_MIN or not uptime or not b.stp.spanning_tree:
            continue
        rate = count / (uptime / 3600)
        if rate < TC_PER_HOUR:
            continue
        yield found(
            f"{b.label} counted {count} spanning tree topology changes, {rate:.0f} per hour.",
            [b.device.id],
            fix="Find the port that goes up and down (its link changes, or the device's log), "
            "and make ports to clients edge ports.",
            mid="stp.topologyChanges",
            fix_id="stp.topologyChanges.fix",
            params={"bridge": b.label, "count": count, "rate": round(rate)},
            key=b.stp.name,
        )


# --- stp.client-port-not-edge -----------------------------------------------------------------


@rule(
    "stp.client-port-not-edge",
    "Port to a client is not an edge port",
    Severity.INFO,
    "A port that only has a client behind it (a PC, a printer, an access point without its "
    "own bridge in the tree) should be an edge port (PortFast): it then forwards as soon as "
    "the link comes up, and its link changes do not count as topology changes. A port that "
    "is not an edge port waits up to 30 seconds after every link change (classic STP) and "
    "makes the switches flush their address tables. Reported for ports of a bridge with "
    "spanning tree that say they are not edge ports, have clients and no known switch "
    "behind them.",
)
def client_port_not_edge(net: Network) -> Iterator[Result]:
    linked = {p for pair in _cables(net) for p in pair}
    clients: dict[str, int] = {}
    for c in net.clients:
        if c.seen_on:
            clients[c.seen_on] = clients.get(c.seen_on, 0) + 1
    for b in bridges(net):
        if not b.stp.spanning_tree:
            continue
        for pid in sorted(b.ports):
            port = net.port(pid)
            if port is None or port.stp is None or port.stp.edge is not False:
                continue
            if port.external is False or pid in linked or not clients.get(pid):
                continue
            if port.stp.role in (StpPortRole.ROOT, StpPortRole.ALTERNATE, StpPortRole.BACKUP):
                continue  # a bridge is behind it after all
            yield found(
                f"{b.device.name} {port.label()} has clients but is not an edge port.",
                [pid],
                fix="Make the port an edge port (PortFast); turn on BPDU guard too if only "
                "clients may be connected there.",
                mid="stp.clientNotEdge",
                fix_id="stp.clientNotEdge.fix",
                params={"device": b.device.name, "port": port.label()},
            )


RULES: list[Rule] = [
    several_roots,
    root_not_core,
    disabled_with_redundancy,
    topology_changes,
    client_port_not_edge,
]
