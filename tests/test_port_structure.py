"""The internal port structure of a device (#252, ADR 0008): model, helpers, contract."""

from __future__ import annotations

from factories import port
from signalbox.model import (
    Band,
    Network,
    Port,
    PortKind,
    PortRole,
    Radio,
    Security,
    Wlan,
    natural_key,
    port_id,
)
from signalbox.testing import structure_problems

D = "r1"


def pid(name: str) -> str:
    return port_id(D, name)


def dsa_router() -> Network:
    """eth0 (CPU) → lan1, lan2, lan10; br-lan over lan1, lan2 and phy0-ap0; br-lan.10 on top."""
    ports = [
        port(D, "eth0", role=PortRole.CPU),
        *(port(D, f"lan{n}", role=PortRole.JACK, lower=[pid("eth0")]) for n in (10, 2, 1)),
        port(D, "wan", role=PortRole.JACK),
        port(
            D,
            "br-lan",
            kind=PortKind.BRIDGE,
            role=PortRole.BRIDGE,
            lower=[pid("lan1"), pid("lan2"), pid("phy0-ap0")],
        ),
        port(D, "br-lan.10", kind=PortKind.VIRTUAL, role=PortRole.VLAN, lower=[pid("br-lan")]),
        port(D, "phy0-ap0", kind=PortKind.WIRELESS, role=PortRole.WIRELESS),
        port(D, "phy0-mesh0", kind=PortKind.WIRELESS, role=PortRole.WIRELESS),
        port(D, "old"),  # an adapter that does not report roles
        port("other", "lan1", role=PortRole.JACK),
    ]
    radio = Radio(id=f"{D}/radio/radio0", device_id=D, name="radio0", band=Band.GHZ_2_4)
    wlans = [
        Wlan(
            id=f"{D}/wlan/main",
            device_id=D,
            ssid="Example",
            radio_id=radio.id,
            security=Security.WPA2,
            port_id=pid("phy0-ap0"),
        ),
        Wlan(
            id=f"{D}/wlan/guest",
            device_id=D,
            ssid="Guest",
            radio_id=radio.id,
            security=Security.OPEN,
        ),
    ]
    return Network(ports=ports, radios=[radio], wlans=wlans)


def test_external_from_the_role() -> None:
    assert port(D, "a", role=PortRole.JACK).external is True
    assert port(D, "a", kind=PortKind.LAG, role=PortRole.LAG).external is True
    assert port(D, "a", role=PortRole.CPU).external is False
    assert port(D, "a", role=PortRole.VLAN).external is False
    assert port(D, "a", role=PortRole.SWITCH_PORT).external is None
    assert port(D, "a").external is None  # old data: unknown, never "internal"


def test_old_data_stays_valid() -> None:
    p = Port.model_validate({"id": pid("x"), "device_id": D, "name": "x"})
    assert (p.role, p.lower) == (None, [])


def test_helpers() -> None:
    net = dsa_router()
    assert [p.name for p in net.external_ports(D)] == ["lan10", "lan2", "lan1", "wan", "old"]
    assert [p.name for p in net.external_ports(D, unknown=False)] == [
        "lan10",
        "lan2",
        "lan1",
        "wan",
    ]
    assert [p.name for p in net.lower_ports(pid("br-lan"))] == ["lan1", "lan2", "phy0-ap0"]
    assert net.lower_ports("nope") == []
    assert [p.name for p in net.upper_ports(pid("br-lan"))] == ["br-lan.10"]
    assert sorted(["lan10", "lan2", "lan1"], key=natural_key) == ["lan1", "lan2", "lan10"]


def test_port_tree() -> None:
    tree = dsa_router().port_tree(D)
    assert [n.id for n in tree] == [
        pid("eth0"),
        pid("wan"),
        pid("old"),
        pid("br-lan"),
        pid("phy0-mesh0"),  # a Wi-Fi interface without SSID: no radio known
        f"{D}/radio/radio0",
    ]
    cpu, *_, bridge, mesh, radio = tree
    assert [c.id for c in cpu.children] == [pid("lan1"), pid("lan2"), pid("lan10")]
    assert bridge.members == [pid("lan1"), pid("lan2"), pid("phy0-ap0")]
    assert [c.id for c in bridge.children] == [pid("br-lan.10")]
    assert mesh.wlans == []
    assert radio.node == "radio" and [c.id for c in radio.children] == [pid("phy0-ap0")]
    assert radio.children[0].wlans == [f"{D}/wlan/main"]
    assert radio.wlans == [f"{D}/wlan/guest"]  # its interface is not reported
    assert Network().port_tree(D) == []


def test_port_tree_survives_bad_data() -> None:
    """Unknown lower ports and cycles (an adapter error) do not lose a port."""
    net = Network(
        ports=[
            port(D, "a", lower=[pid("b")]),
            port(D, "b", lower=[pid("a")]),
            port(D, "c", lower=[pid("c"), pid("missing")]),
        ]
    )
    tree = net.port_tree(D)
    assert [n.id for n in tree] == [pid("c"), pid("a")]
    assert [c.id for c in tree[1].children] == [pid("b")]


def test_contract_accepts_a_good_structure() -> None:
    net = dsa_router()
    assert structure_problems([p for p in net.ports if p.device_id == D], net.wlans) == []


def test_contract_problems() -> None:
    ports = [
        port(D, "a", lower=[pid("b"), pid("b")]),
        port(D, "b", lower=[pid("a")]),
        port(D, "c", lower=[pid("gone"), port_id("other", "x")]),
        port("other", "x"),
        port(D, "br", role=PortRole.BRIDGE),
        port(D, "v", kind=PortKind.VIRTUAL, role=PortRole.VLAN, lower=[pid("a"), pid("c")]),
        port(D, "eth", role=PortRole.JACK),
    ]
    wlans = [
        Wlan(
            id=f"{D}/wlan/{n}",
            device_id=D,
            ssid="x",
            radio_id=f"{D}/radio/r",
            security=Security.OPEN,
            port_id=p,
        )
        for n, p in (("1", pid("eth")), ("2", port_id("other", "x")), ("3", pid("later")))
    ]
    found = structure_problems(ports, [*wlans, wlans[0].model_copy(update={"port_id": None})])
    assert found == [
        f"port {pid('a')}: lower lists a port twice",
        f"port {pid('c')}: lower port {pid('gone')} is not reported",
        f"port {pid('c')}: lower port other/port/x belongs to another device",
        f"port {pid('br')}: role bridge with kind ethernet",
        f"port {pid('v')}: a VLAN interface runs on one port, not 2",
        f"port {pid('a')}: lower ports form a cycle",
        f"wlan {D}/wlan/1: port {pid('eth')} is not a Wi-Fi interface",
        f"wlan {D}/wlan/2: port other/port/x is not a port of its device",
    ]
