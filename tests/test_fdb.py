"""MAC address tables (forwarding databases, #160): model, cap, contract, merge, client
placement, links through unread switches, the readers and the API."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from factories import SITE, device, port, snapshot
from signalbox.adapters import _cap_fdb
from signalbox.adapters.linux import parse
from signalbox.adapters.linux.collect import split
from signalbox.fdb import index, place_clients, placement
from signalbox.merge import merge
from signalbox.model import (
    FDB_LIMIT,
    Client,
    DeviceRole,
    FdbEntry,
    FdbKind,
    Link,
    LinkOrigin,
    Network,
    PortKind,
    PortRole,
    Snapshot,
    fdb_id,
    port_id,
)
from signalbox.testing import fdb_problems
from signalbox.topology import discovered_links, mac_links

sys.path.insert(0, str(Path(__file__).parent))

GW, SW1, SW2, AP = (
    "02:00:00:00:01:01",
    "02:00:00:00:02:01",
    "02:00:00:00:03:01",
    "02:00:00:00:04:01",
)
TV, NAS = "02:00:00:00:09:01", "02:00:00:00:09:02"


def entry(dev: str, port: str, mac: str, kind: FdbKind = FdbKind.DYNAMIC, **kw: Any) -> FdbEntry:
    return FdbEntry(
        id=fdb_id(dev, port, mac, kw.get("vlan")),
        device_id=dev,
        port_id=port_id(dev, port),
        mac=mac,
        kind=kind,
        **kw,
    )


def lab(sw2_table: bool = False, links: list[Link] = ()) -> Network:  # type: ignore[assignment]
    """gw:lan1 - an unmanaged switch - sw1:1 and sw2:1; tv on sw1:5, nas on sw2:3.

    gw and sw1 report tables; sw2 only when asked (else its clients' seen_on)."""
    gw = snapshot(
        device("gw", DeviceRole.GATEWAY),
        ports=[
            port("gw", "lan1", mac=GW, role=PortRole.JACK),
            port("gw", "cpu", role=PortRole.CPU),
        ],
        fdb=[
            entry("gw", "lan1", SW1),
            entry("gw", "lan1", SW2),
            entry("gw", "lan1", TV),
            entry("gw", "lan1", NAS),
            entry("gw", "lan1", GW, FdbKind.SELF),
            entry("gw", "cpu", TV),  # internal: never a sighting
        ],
        clients=[Client(id="gw/client/tv", mac=TV, seen_on="gw/port/lan1")],
    )
    sw1 = snapshot(
        device("sw1", DeviceRole.SWITCH),
        ports=[port("sw1", "1", mac=SW1), port("sw1", "5")],
        fdb=[
            entry("sw1", "1", GW, age_seconds=3),
            entry("sw1", "1", SW2),
            entry("sw1", "1", NAS),
            entry("sw1", "5", TV, vlan=20),
        ],
    )
    sw2_fdb = [entry("sw2", "1", GW), entry("sw2", "1", SW1), entry("sw2", "1", TV)]
    sw2 = snapshot(
        device("sw2", DeviceRole.SWITCH),
        ports=[port("sw2", "1", mac=SW2), port("sw2", "3")],
        fdb=[*sw2_fdb, entry("sw2", "3", NAS)] if sw2_table else [],
        clients=[] if sw2_table else [Client(id="sw2/client/nas", mac=NAS, seen_on="sw2/port/3")],
    )
    return merge([SITE], [gw, sw1, sw2], links)


def test_network_keeps_entries_and_helpers() -> None:
    net = lab()
    assert len(net.fdb) == 10
    assert {e.port_id for e in net.fdb_of(TV)} == {"gw/port/lan1", "gw/port/cpu", "sw1/port/5"}
    assert [e.mac for e in net.fdb_on("sw1/port/5")] == [TV]
    assert net.knows(fdb_id("sw1", "5", TV, 20))


def test_clients_are_placed_on_the_access_port() -> None:
    net = lab()
    by_mac = {c.mac: c for c in net.clients}
    # the gateway saw the tv on its uplink; sw1's access port is more specific
    assert by_mac[TV].seen_on == "sw1/port/5"
    # sw2 has no table: its own seen_on stays (gw and sw1 only see the nas on uplinks)
    assert by_mac[NAS].seen_on == "sw2/port/3"
    ix = index(net)
    assert {"gw/port/lan1", "sw1/port/1"} <= ix.uplinks and "sw1/port/5" not in ix.uplinks


def test_placement_rules() -> None:
    net = lab()
    ix = index(net)
    wifi = Client(id="c", mac=TV, seen_on="ap/wlan/home")
    assert placement(net, ix, wifi) == "ap/wlan/home"  # the AP knows better
    unknown = Client(id="c", mac="02:00:00:00:09:99", seen_on=None)
    assert placement(net, ix, unknown) is None
    # only uplinks know it, and a device without a table said a port: keep that
    other = Client(id="c", mac=NAS, seen_on="sw2/port/3")
    assert placement(net, ix, other) == "sw2/port/3"
    # nothing said by the client itself: sw2's report (no table) counts as a sighting
    assert placement(net, ix, Client(id="c", mac=NAS)) == "sw2/port/3"
    # only uplinks: the one with the fewest addresses
    assert placement(net, ix, Client(id="c", mac=SW2)) == "sw1/port/1"
    assert place_clients(Network()) == Network()


def test_links_through_an_unread_switch() -> None:
    found = {(link.a, link.b) for link in mac_links(lab(sw2_table=True))}
    # gw learns sw1 and sw2 on lan1; sw1 learns gw and sw2 on port 1, sw2 learns gw and sw1
    # on port 1: an unmanaged switch joins all three, every pair is "nearest"
    assert ("gw/port/lan1", "sw1/port/1") in found
    assert ("sw1/port/1", "gw/port/lan1") in found
    assert ("gw/port/lan1", "sw2/port/1") in found
    net = lab(sw2_table=True)
    links = discovered_links(net)
    assert all(link.origin is LinkOrigin.MAC for link in links)
    assert {frozenset((link.a, link.b)) for link in links} == {
        frozenset(("gw/port/lan1", "sw1/port/1")),
        frozenset(("gw/port/lan1", "sw2/port/1")),
        frozenset(("sw1/port/1", "sw2/port/1")),
    }


def test_chain_keeps_the_nearest_device() -> None:
    """gw:lan1 - sw1:1, sw1:2 - sw2:1: gw learns both on lan1, but sw2 learns sw1 and gw on
    the same port, so sw1 sits between: gw links to sw1 only."""
    gw = snapshot(
        device("gw", DeviceRole.GATEWAY),
        ports=[port("gw", "lan1", mac=GW)],
        fdb=[entry("gw", "lan1", SW1), entry("gw", "lan1", SW2)],
    )
    sw1 = snapshot(
        device("sw1", DeviceRole.SWITCH),
        ports=[port("sw1", "1", mac=SW1), port("sw1", "2")],
        fdb=[entry("sw1", "1", GW), entry("sw1", "2", SW2)],
    )
    sw2 = snapshot(
        device("sw2", DeviceRole.SWITCH),
        ports=[port("sw2", "1", mac=SW2)],
        fdb=[entry("sw2", "1", GW), entry("sw2", "1", SW1)],
    )
    net = merge([SITE], [gw, sw1, sw2])
    assert {frozenset((link.a, link.b)) for link in discovered_links(net)} == {
        frozenset(("gw/port/lan1", "sw1/port/1")),
        frozenset(("sw1/port/2", "sw2/port/1")),
    }


def test_wireless_port_makes_a_wireless_link() -> None:
    ap = snapshot(
        device("ap", DeviceRole.AP),
        ports=[port("ap", "wlan0", kind=PortKind.WIRELESS, mac=AP)],
        fdb=[entry("ap", "wlan0", SW1)],
    )
    sw = snapshot(device("sw1", DeviceRole.SWITCH), ports=[port("sw1", "1", mac=SW1)])
    links = list(mac_links(merge([SITE], [ap, sw])))
    assert [(link.a, link.b, link.kind.value) for link in links] == [
        ("ap/port/wlan0", "sw1/port/1", "wireless")
    ]


def test_cap_keeps_own_and_static_then_newest() -> None:
    many = [
        entry(
            "sw",
            "1",
            f"02:00:00:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}",
            age_seconds=i,
        )
        for i in range(FDB_LIMIT + 5)
    ]
    own = entry("sw", "1", "02:ff:00:00:00:01", FdbKind.SELF, age_seconds=99999)
    kept, dropped = _cap_fdb([*many, own, entry("ap", "1", TV)])
    assert dropped == 6 and len(kept) == FDB_LIMIT + 1
    assert own in kept and many[0] in kept and many[-1] not in kept
    assert _cap_fdb(many[:3]) == (many[:3], 0)


def test_contract_problems() -> None:
    ok = entry("sw", "1", TV, segment_id="home/segment/native")
    assert fdb_problems([ok], {"sw"}, {"sw/port/1"}, {"home/segment/native"}) == []
    bad = [
        ok,
        ok,
        entry("other", "1", NAS),
        entry("sw", "9", SW1),
        entry("sw", "1", "03:00:00:00:00:01"),
        entry("sw", "1", SW2, segment_id="home/segment/99"),
        FdbEntry(id="sw/x/1", device_id="sw", port_id="ap/port/1", mac=AP),
    ]
    found = fdb_problems(bad, {"sw"}, {"sw/port/1", "ap/port/1"}, {"home/segment/native"})
    assert any("reported twice" in p for p in found)
    assert any("has device_id other" in p for p in found)
    assert any("unknown port sw/port/9" in p for p in found)
    assert any("multicast" in p for p in found)
    assert any("unknown segment" in p for p in found)
    assert any("does not start with sw/fdb/" in p for p in found)
    assert any("of another device" in p for p in found)
    full = [
        entry("sw", "1", f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}") for i in range(FDB_LIMIT + 1)
    ]
    assert any("over" in p for p in fdb_problems(full, {"sw"}, {"sw/port/1"}, set()))


def test_native_split_moves_entry_segments() -> None:
    """Two routers with separate untagged networks (#205): an entry on the further
    router's native segment follows it."""
    from test_double_nat import router_lan

    isp = snapshot(
        device("isp", DeviceRole.GATEWAY),
        ports=[port("isp", "lan")],
        subnets=[router_lan("isp", "192.0.2.1/24")],
        fdb=[entry("isp", "lan", TV, segment_id="home/segment/native")],
    )
    fw = snapshot(
        device("fw", DeviceRole.GATEWAY),
        ports=[port("fw", "lan")],
        subnets=[router_lan("fw", "198.51.100.1/24")],
    )
    net = merge([SITE], [isp, fw])
    assert [e.segment_id for e in net.fdb] == ["home/segment/native-isp"]


def test_linux_bridge_fdb_parsing() -> None:
    answer = split(
        "@@fdb\n"
        '[{"mac":"02:00:00:00:00:10","ifname":"lan1","master":"br0","vlan":10,"updated":7},'
        '{"mac":"02:00:00:00:00:11","ifname":"lan1","master":"br0","flags":["static"]},'
        '{"mac":"02:00:00:00:00:12","ifname":"lan1","master":"br0","vlan":0,"updated":-1},'
        '{"mac":"bad","ifname":"lan1","master":"br0"},'
        '{"mac":"01:00:5e:00:00:01","ifname":"lan1","master":"br0"},'
        '"junk"]\n@@end\n'
    )
    rows = parse.bridge_fdb(answer)
    assert [(r.mac, r.vlan, r.state, r.age) for r in rows] == [
        ("02:00:00:00:00:10", 10, "dynamic", 7),
        ("02:00:00:00:00:11", None, "static", None),
        ("02:00:00:00:00:12", None, "dynamic", None),
    ]
    assert parse.bridge_fdb(split("@@fdb\nnot json\n@@end\n")) == []


def snap_with(entries: list[FdbEntry]) -> Snapshot:
    return snapshot(device("sw", DeviceRole.SWITCH), ports=[port("sw", "1")], fdb=entries)


def test_api_fdb_filters_and_network_leaves_it_out(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from signalbox.service import build
    from signalbox.web.app import create_app, public_network
    from test_runner import Dev

    net = merge(
        [SITE],
        [
            snap_with([entry("sw", "1", TV), entry("sw", "1", NAS)]).model_copy(
                update={"clients": [Client(id="sw/client/tv", mac=TV, seen_on="sw/port/1")]}
            )
        ],
    )
    assert "fdb" not in public_network(net)
    tmp = Path(__import__("tempfile").mkdtemp())
    svc = build(
        tmp, env={"SIGNALBOX_AUTH_PASSWORD": "correct-horse-battery"}, adapters={"dev": Dev}
    )
    try:
        monkeypatch.setattr(svc.runner, "network", lambda: net)
        with TestClient(create_app(svc, run_background=False)) as c:
            assert (
                c.post("/api/login", json={"password": "correct-horse-battery"}).status_code == 200
            )
            every = c.get("/api/fdb").json()
            assert len(every) == 2
            tv = c.get(f"/api/fdb?mac={TV.upper()}").json()
            assert [(e["port_id"], e["client"]) for e in tv] == [("sw/port/1", f"client/{TV}")]
            assert c.get(f"/api/fdb?mac={NAS}").json()[0]["client"] is None
            assert c.get("/api/fdb?device=other").json() == []
            assert len(c.get("/api/fdb?device=sw").json()) == 2
            assert c.get("/api/fdb?mac=nope").status_code == 422
    finally:
        svc.close()
