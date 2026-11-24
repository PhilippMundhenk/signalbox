"""Spanning tree rules (#155)."""

from __future__ import annotations

from typing import Any

from factories import SITE, client, device, health, port
from signalbox.model import (
    DeviceRole,
    Link,
    LinkKind,
    LinkOrigin,
    Network,
    Port,
    PortRole,
    StpBridge,
    StpPort,
    StpPortRole,
    StpPortState,
    StpProtocol,
    stp_bridge_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.stp_checks import (
    client_port_not_edge,
    disabled_with_redundancy,
    domains,
    root_bridges,
    root_not_core,
    several_roots,
    topology_changes,
)

SW, GW, AP = DeviceRole.SWITCH, DeviceRole.GATEWAY, DeviceRole.AP


def bid(n: int, prio: int = 0x8000) -> str:
    return stp_bridge_id(prio, f"02:00:00:00:00:{n:02x}")


class Lab:
    """A small network: devices with one bridge ``br`` over jacks ``p1``..``pN``."""

    def __init__(self) -> None:
        self.devices: list[Any] = []
        self.ports: list[Port] = []
        self.links: list[Link] = []
        self.clients: list[Any] = []

    def add(
        self,
        dev: str,
        role: DeviceRole,
        n: int,
        protocol: StpProtocol | None = StpProtocol.RSTP,
        jacks: int = 4,
        root: int | None = None,
        prio: int = 0x8000,
        whole_switch: bool = False,
        stp: dict[str, StpPort] | None = None,
        **kw: Any,
    ) -> None:
        names = [f"p{i}" for i in range(1, jacks + 1)]
        bridges = None
        if protocol is not None:
            spanning = protocol in (StpProtocol.STP, StpProtocol.RSTP, StpProtocol.MSTP)
            bridges = [
                StpBridge(
                    name="switch" if whole_switch else "br",
                    port_id=None if whole_switch else f"{dev}/port/br",
                    protocol=protocol,
                    priority=prio,
                    bridge_id=bid(n, prio),
                    root_bridge_id=(bid(root) if root and root != n else bid(n, prio))
                    if spanning
                    else None,
                    **kw,
                )
            ]
        self.devices.append(device(dev, role, name=dev.upper(), stp_bridges=bridges))
        for name in names:
            self.ports.append(
                port(dev, name, role=PortRole.JACK, stp=(stp or {}).get(name), up=True)
            )
        if not whole_switch:
            self.ports.append(
                port(dev, "br", role=PortRole.BRIDGE, lower=[f"{dev}/port/{x}" for x in names])
            )

    def cable(self, a: str, b: str) -> None:
        self.links.append(
            Link(id=f"lldp:{a}~{b}", a=a, b=b, kind=LinkKind.CABLE, origin=LinkOrigin.LLDP)
        )

    def net(self) -> Network:
        return Network(
            sites=[SITE],
            devices=self.devices,
            ports=self.ports,
            links=self.links,
            clients=self.clients,
        )


def run(r: Rule, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def chain(protocols: tuple[StpProtocol | None, ...], roots: tuple[int, ...]) -> Lab:
    lab = Lab()
    for i, (proto, root) in enumerate(zip(protocols, roots, strict=True), start=1):
        lab.add(f"s{i}", SW, i, proto, root=root)
    for i in range(1, len(protocols)):
        lab.cable(f"s{i}/port/p2", f"s{i + 1}/port/p1")
    return lab


# stp.several-roots ---------------------------------------------------------------------------


def test_several_roots_behind_a_bridge_without_stp() -> None:
    lab = chain((StpProtocol.RSTP, StpProtocol.NONE, StpProtocol.RSTP), (1, 0, 3))
    (f,) = run(several_roots, lab.net())
    assert f.message == "The bridges of one network see 2 different root bridges: S1, S3."
    assert f.objects == ["s1", "s3"] and f.message_id == "stp.severalRoots"
    assert f.params == {"count": 2, "roots": "S1, S3"}


def test_one_root_and_separate_networks_are_fine() -> None:
    assert not run(several_roots, chain((StpProtocol.RSTP,) * 3, (1, 1, 1)).net())
    lab = chain((StpProtocol.RSTP, StpProtocol.RSTP), (1, 2))
    lab.links = []  # two networks that are not cabled to each other
    assert not run(several_roots, lab.net())
    assert len(domains(lab.net())) == 2


def test_unknown_root_is_named_by_its_id() -> None:
    lab = chain((StpProtocol.RSTP, StpProtocol.RSTP), (9, 2))
    (f,) = run(several_roots, lab.net())
    assert bid(9) in f.message and "S2" in f.message


# stp.root-not-core -------------------------------------------------------------------------


def test_root_on_an_access_point_not_the_gateway() -> None:
    lab = Lab()
    lab.add("gw", GW, 1, root=2)
    lab.add("ap", AP, 2, prio=0x8000)
    lab.cable("gw/port/p1", "ap/port/p1")
    (f,) = run(root_not_core, lab.net())
    assert f.message == "The spanning tree root is AP (priority 32768), not GW."
    assert f.message_id == "stp.rootNotCorePriority" and f.objects == ["ap", "gw"]
    assert root_bridges(lab.net()) == {("ap", "br")}


def test_root_unknown_device_not_the_core_switch() -> None:
    lab = Lab()
    lab.add("core", SW, 1, root=9)
    lab.add("edge", SW, 2, root=9)
    lab.add("edge2", SW, 3, root=9)
    lab.cable("core/port/p1", "edge/port/p1")
    lab.cable("core/port/p2", "edge2/port/p1")
    (f,) = run(root_not_core, lab.net())
    assert f.message == f"The spanning tree root is {bid(9)}, not CORE."
    assert f.message_id == "stp.rootNotCore"


def test_root_on_the_core_or_gateway_is_quiet() -> None:
    lab = Lab()
    lab.add("gw", GW, 1)
    lab.add("sw", SW, 2, root=1)
    lab.cable("gw/port/p1", "sw/port/p1")
    assert not run(root_not_core, lab.net())
    lab = Lab()
    lab.add("core", SW, 1)
    lab.add("ap", AP, 2, root=1)
    lab.cable("core/port/p1", "ap/port/p1")
    assert not run(root_not_core, lab.net())
    # a gateway without spanning tree is no candidate: the AP is the only bridge in the tree
    lab = Lab()
    lab.add("gw", GW, 1, protocol=None)
    lab.add("ap", AP, 2)
    lab.add("ap2", AP, 3, root=2)
    lab.cable("gw/port/p1", "ap/port/p1")
    lab.cable("ap/port/p2", "ap2/port/p1")
    assert not run(root_not_core, lab.net())


# stp.disabled-with-redundancy ----------------------------------------------------------------


def ring(protocol: StpProtocol | None, blocked: bool = False) -> Lab:
    lab = Lab()
    lab.add("a", SW, 1, StpProtocol.NONE)
    state = StpPort(state=StpPortState.DISCARDING) if blocked else None
    lab.add("b", SW, 2, protocol, stp={"p2": state} if state else None)
    lab.add("c", SW, 3, protocol)
    lab.cable("a/port/p1", "b/port/p1")
    lab.cable("a/port/p2", "c/port/p1")
    lab.cable("b/port/p2", "c/port/p2")
    return lab


def test_ring_through_a_bridge_without_stp() -> None:
    (f,) = run(disabled_with_redundancy, ring(None).net())
    assert f.message == "A has spanning tree off, but its cables to B, C form a loop."
    assert f.objects == ["a", "b", "c"] and f.message_id == "stp.disabledLoop"


def test_two_cables_to_one_switch_without_lag() -> None:
    lab = Lab()
    lab.add("a", SW, 1, StpProtocol.NONE)
    lab.add("b", SW, 2, None)
    lab.cable("a/port/p1", "b/port/p1")
    lab.cable("a/port/p2", "b/port/p2")
    (f,) = run(disabled_with_redundancy, lab.net())
    assert f.objects == ["a", "b"]
    # the same two cables in a LAG on this side are one path
    lab.ports = [
        p.model_copy(update={"lag": "1"}) if p.device_id == "a" and p.name in ("p1", "p2") else p
        for p in lab.ports
    ]
    assert not run(disabled_with_redundancy, lab.net())


def test_lag_port_counts_once() -> None:
    lab = Lab()
    lab.add("a", SW, 1, StpProtocol.NONE)
    lab.add("b", SW, 2, None)
    lab.ports.append(port("a", "bond0", role=PortRole.LAG, lower=["a/port/p1", "a/port/p2"]))
    lab.cable("a/port/p1", "b/port/p1")
    lab.cable("a/port/p2", "b/port/p2")
    assert not run(disabled_with_redundancy, lab.net())


def test_star_blocked_ring_and_loop_detection_are_quiet() -> None:
    lab = Lab()
    lab.add("a", SW, 1, StpProtocol.NONE)
    lab.add("b", SW, 2, None)
    lab.add("c", SW, 3, None)
    lab.add("ap", AP, 4, None)
    lab.cable("a/port/p1", "b/port/p1")
    lab.cable("a/port/p2", "c/port/p1")
    lab.cable("a/port/p3", "ap/port/p1")
    assert not run(disabled_with_redundancy, lab.net())  # a star: no loop
    assert not run(disabled_with_redundancy, ring(StpProtocol.RSTP, blocked=True).net())
    assert not run(disabled_with_redundancy, ring(StpProtocol.LOOP_DETECT).net())


# stp.topology-changes ------------------------------------------------------------------------


def test_topology_changes() -> None:
    lab = Lab()
    lab.add("sw", SW, 1, topology_changes=200)
    lab.devices[0] = lab.devices[0].model_copy(update={"health": health(uptime_seconds=7200)})
    (f,) = run(topology_changes, lab.net())
    assert f.message == "SW counted 200 spanning tree topology changes, 100 per hour."
    assert f.params == {"bridge": "SW", "count": 200, "rate": 100}


def test_few_topology_changes_or_no_uptime_are_quiet() -> None:
    lab = Lab()
    lab.add("sw", SW, 1, topology_changes=200)
    assert not run(topology_changes, lab.net())  # no uptime
    lab.devices[0] = lab.devices[0].model_copy(
        update={"health": health(uptime_seconds=3600 * 24 * 30)}
    )
    assert not run(topology_changes, lab.net())  # a few a day
    lab = Lab()
    lab.add("sw", SW, 1, topology_changes=5)
    lab.devices[0] = lab.devices[0].model_copy(update={"health": health(uptime_seconds=60)})
    assert not run(topology_changes, lab.net())


# stp.client-port-not-edge --------------------------------------------------------------------


def test_client_port_not_edge() -> None:
    lab = Lab()
    lab.add(
        "sw",
        SW,
        1,
        stp={
            "p1": StpPort(edge=False, role=StpPortRole.DESIGNATED),
            "p2": StpPort(edge=True),
            "p3": StpPort(edge=False, role=StpPortRole.ROOT),
            "p4": StpPort(edge=False),
        },
    )
    lab.clients = [client(f"02:00:00:00:01:0{i}", seen_on=f"sw/port/p{i}") for i in (1, 2, 3, 4)]
    lab.add("up", SW, 2)
    lab.cable("sw/port/p4", "up/port/p1")
    (f,) = run(client_port_not_edge, lab.net())
    assert f.message == "SW p1 has clients but is not an edge port."
    assert f.objects == ["sw/port/p1"] and f.message_id == "stp.clientNotEdge"


def test_client_port_without_spanning_tree_or_edge_info_is_quiet() -> None:
    lab = Lab()
    lab.add("sw", SW, 1, StpProtocol.NONE, stp={"p1": StpPort(edge=False)})
    lab.add("k", SW, 2, StpProtocol.STP, stp={"p1": StpPort(state=StpPortState.FORWARDING)})
    lab.clients = [client("02:00:00:00:01:01", seen_on="sw/port/p1")]
    lab.clients.append(client("02:00:00:00:01:02", seen_on="k/port/p1"))
    assert not run(client_port_not_edge, lab.net())


def test_whole_switch_bridge_owns_its_ports() -> None:
    lab = Lab()
    lab.add("s1", SW, 1, whole_switch=True)
    lab.add("s2", SW, 2, root=9)
    lab.cable("s1/port/p1", "s2/port/p1")
    (dom,) = domains(lab.net())
    assert {b.label for b in dom.bridges} == {"S1", "S2"}
    assert run(several_roots, lab.net())
