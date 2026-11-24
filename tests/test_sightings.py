"""Observation history (#185): store, runner, engine and the rules that use it."""

import sqlite3
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE, T0, annotated, annotation, device, ip, port, snapshot
from signalbox.adapters import Capability
from signalbox.config import Config, HistoryConfig
from signalbox.merge import merge
from signalbox.model import (
    Client,
    DeviceRole,
    DeviceStatus,
    DhcpServer,
    Link,
    LinkOrigin,
    Network,
    PortKind,
    ReadError,
    Reservation,
    Segment,
    Snapshot,
    segment_id,
)
from signalbox.rules import Result, Severity, evaluate, history_rule
from signalbox.rules.history_checks import (
    device_flapping,
    down_long,
    network_changed,
    port_flapping,
    stale_reservation,
)
from signalbox.runner import Runner
from signalbox.secrets import load_vault
from signalbox.sightings import (
    ClientHistory,
    DeviceHistory,
    History,
    LinkChange,
    PortHistory,
    SegmentChange,
    StatusChange,
)
from signalbox.store import SCHEMA, Store

LAN = segment_id("home", None)
GUEST = segment_id("home", 20)
MAC = "00:11:22:33:44:55"  # universally administered: a real device that does not rotate
RANDOM = "02:00:00:00:00:51"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def client(mac: str = MAC, seg: str | None = LAN, **kw: Any) -> Client:
    return Client(id=f"x/{mac}", mac=mac, segment_id=seg, **kw)


def gateway(
    status: DeviceStatus = DeviceStatus.OK,
    clients: tuple[Client, ...] = (),
    up: bool | None = True,
    **kw: Any,
) -> Snapshot:
    dev = device("gw", capabilities=[Capability.CLIENTS, Capability.DHCP])
    kw.setdefault("segments", [Segment(id=LAN, site_id="home", name="LAN")])
    return snapshot(
        dev,
        status=status,
        clients=list(clients),
        ports=[
            port("gw", "lan1", up=up),
            port("gw", "wlan0", kind=PortKind.WIRELESS, up=up),
        ],
        **kw,
    )


def net_of(*snaps: Snapshot, links: tuple[Link, ...] = ()) -> Network:
    return merge([SITE], snaps, links)


# store ----------------------------------------------------------------------------------


def test_migration_from_schema_2_keeps_data(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    db = sqlite3.connect(path)
    db.executescript(f"BEGIN; {SCHEMA[0]}; {SCHEMA[1]}; PRAGMA user_version = 2; COMMIT;")
    db.execute("INSERT INTO sites (id, name) VALUES ('home', 'Home')")
    db.commit()
    db.close()
    s = Store(path, load_vault(tmp_path, env={}))
    try:
        assert s._db.execute("PRAGMA user_version").fetchone()[0] == len(SCHEMA) == 7
        assert s.sites() == [SITE]
        assert s.history(T0, 30) == History(now=T0, days=30)
        s.record_history(net_of(gateway()), T0)
        assert set(s.history(T0, 30).devices) == {"gw"}
    finally:
        s.close()


def test_first_round(store: Store) -> None:
    store.record_history(net_of(gateway(clients=(client(),))), T0)
    h = store.history(T0, 30)
    assert h.since == T0 and h.observations == 1 and h.now == T0
    dev = h.devices["gw"]
    assert (dev.first_seen, dev.last_seen, dev.last_ok, dev.status_since) == (T0, T0, T0, T0)
    assert dev.status is DeviceStatus.OK and dev.changes == []
    assert set(h.ports) == {"gw/port/lan1"}  # wireless interfaces are not links
    assert h.ports["gw/port/lan1"].up and h.ports["gw/port/lan1"].since == T0
    c = h.clients[MAC]
    assert c.segment_id == LAN and c.moves == [] and [s.segment_id for s in c.segments] == [LAN]


def test_changes_are_recorded(store: Store) -> None:
    t1, t2, t3 = (T0 + timedelta(minutes=5 * i) for i in (1, 2, 3))
    store.record_history(net_of(gateway(clients=(client(),))), T0)
    store.record_history(net_of(gateway(DeviceStatus.UNREACHABLE)), t1)
    store.record_history(net_of(gateway(up=False, clients=(client(seg=GUEST),))), t2)
    store.record_history(net_of(gateway(up=None, clients=(client(seg=None),))), t3)
    h = store.history(t3, 30)
    assert h.observations == 4 and h.since == T0
    dev = h.devices["gw"]
    assert dev.last_ok == t3 and dev.last_seen == t3 and dev.status_since == t2
    assert dev.changes == [
        StatusChange(at=t1, old=DeviceStatus.OK, new=DeviceStatus.UNREACHABLE),
        StatusChange(at=t2, old=DeviceStatus.UNREACHABLE, new=DeviceStatus.OK),
    ]
    assert dev.outages(T0) == 1 and dev.outages(t2) == 0
    link = h.ports["gw/port/lan1"]
    # not seen at t1 (device down) nor at t3 (state unknown): one change, at t2
    assert not link.up and link.since == t2 and link.last_seen == t2
    assert link.changes == [LinkChange(at=t2, up=False)] and link.downs(T0) == 1
    c = h.clients[MAC]
    assert c.segment_id == GUEST and c.last_seen == t3 and c.first_seen == T0
    assert c.moves == [SegmentChange(at=t2, old=LAN, new=GUEST)]
    assert [(s.segment_id, s.first_seen, s.last_seen) for s in c.segments] == [
        (LAN, T0, T0),
        (GUEST, t2, t2),
    ]


def test_client_networks_not_trusted_while_a_device_is_missing(store: Store) -> None:
    ap = snapshot(device("ap", DeviceRole.AP), status=DeviceStatus.UNREACHABLE)
    store.record_history(net_of(gateway(clients=(client(),))), T0)
    store.record_history(net_of(gateway(clients=(client(seg=GUEST),)), ap), T0 + timedelta(1))
    err = ReadError(device_id="gw", capability="clients", message="timeout")
    store.record_history(
        net_of(gateway(clients=(client(seg=GUEST),), errors=[err])), T0 + timedelta(2)
    )
    c = store.history(T0 + timedelta(2), 30).clients[MAC]
    assert c.segment_id == LAN and c.moves == [] and len(c.segments) == 2


def test_device_that_never_answered(store: Store) -> None:
    store.record_history(net_of(gateway(DeviceStatus.AUTH_FAILED)), T0)
    dev = store.history(T0, 30).devices["gw"]
    assert dev.last_ok is None and dev.status is DeviceStatus.AUTH_FAILED


def test_prune_and_delete(store: Store) -> None:
    later = T0 + timedelta(days=40)
    store.record_history(net_of(gateway(clients=(client(),))), T0)
    store.record_history(net_of(gateway(up=False)), T0 + timedelta(minutes=5))
    store.record_history(net_of(gateway(up=True)), later)
    assert store.prune_history(later - timedelta(days=30)) == 2  # the client and its network
    h = store.history(later, 30)
    assert h.clients == {} and h.ports["gw/port/lan1"].changes == [LinkChange(at=later, up=True)]
    assert h.devices["gw"].first_seen == T0 and h.since == T0
    other = snapshot(device("gw2"), ports=[port("gw2", "lan1", up=True)])
    store.record_history(net_of(gateway(up=False), other), later)
    store.delete_device("gw")
    h = store.history(later, 30)
    assert set(h.devices) == {"gw2"} and set(h.ports) == {"gw2/port/lan1"}
    assert store._all("SELECT * FROM sighting_changes") == []


def test_history_coverage() -> None:
    assert History.empty().covered_since is None and not History.empty().covers(timedelta(0))
    h = History(now=T0, since=T0 - timedelta(days=50), days=30)
    assert h.covered_since == T0 - timedelta(days=30)
    assert h.covers(timedelta(days=30)) and not h.covers(timedelta(days=31))
    young = History(now=T0, since=T0 - timedelta(days=3), days=30)
    assert young.covered_since == young.since and not young.covers(timedelta(days=30))


# engine ---------------------------------------------------------------------------------


@history_rule("test.history", "History", Severity.INFO, "Reports the number of rounds.")
def rounds(net: Network, history: History) -> Iterator[Result]:
    if history.observations:
        yield Result(f"{history.observations} rounds", ())


def test_history_rules_get_history_or_nothing() -> None:
    net = net_of(gateway())
    assert list(rounds.check(net)) == []  # the plain call sees an empty history
    assert evaluate(net, [rounds]) == []  # desired or predicted state
    (f,) = evaluate(net, [rounds], None, History(now=T0, since=T0, observations=4))
    assert f.message == "4 rounds" and f.rule_id == "test.history"


# runner and API -------------------------------------------------------------------------


async def test_runner_records_rounds_only(store: Store) -> None:
    from test_runner import Dev, add, per_device

    add(store, "gw")
    cfg = Config(history=HistoryConfig(days=7))
    r = Runner(store=store, adapters={"dev": Dev}, rules=[per_device], config=cfg)
    await r.observe_all()
    r.evaluate()  # a re-check (desired state saved, deployment done) is not a new round
    h = r.history()
    assert h.observations == 1 and h.days == 7 and set(h.devices) == {"gw"}
    assert h.devices["gw"].last_ok is not None


def test_api_history_and_device_times(tmp_path: Path) -> None:
    from signalbox.service import build
    from test_runner import Dev, per_device
    from test_web import PW, device_body

    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"dev": Dev},
        rules=[per_device],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    from signalbox.web.app import create_app

    try:
        with TestClient(create_app(svc, run_background=False)) as c:
            assert c.post("/api/login", json={"password": PW}).status_code == 200
            made = c.post("/api/devices", json=device_body()).json()
            assert made["first_seen"] is None and made["last_ok"] is None
            mid = made["id"]
            svc.store.record_history(
                Network(statuses={mid: DeviceStatus.OK}, clients=[client()]), T0
            )
            svc.store.record_history(
                Network(statuses={mid: DeviceStatus.UNREACHABLE}), T0 + timedelta(1)
            )
            (dev,) = c.get("/api/devices").json()
            assert dev["first_seen"] == T0.isoformat() and dev["last_ok"] == T0.isoformat()
            assert dev["last_seen"] == (T0 + timedelta(1)).isoformat()
            one = c.get(f"/api/devices/{made['id']}").json()
            assert one["first_seen"] == dev["first_seen"]
            body = c.get("/api/history").json()
            assert body["observations"] == 2 and body["clients"][MAC]["segment_id"] == LAN
            assert body["devices"][mid]["status"] == "unreachable"
    finally:
        svc.close()


# rules ----------------------------------------------------------------------------------

NOW = T0 + timedelta(days=60)


def past(**kw: Any) -> History:
    return History(now=NOW, since=T0, observations=1000, days=30, **kw)


def dev_hist(**kw: Any) -> DeviceHistory:
    base: dict[str, Any] = {
        "first_seen": T0,
        "last_seen": NOW,
        "status": DeviceStatus.UNREACHABLE,
        "status_since": NOW,
    }
    return DeviceHistory.model_validate(base | kw)


def test_down_long() -> None:
    net = net_of(gateway(DeviceStatus.UNREACHABLE))
    assert list(down_long.check(net)) == []
    assert list(down_long.history_check(net, past()) or []) == []  # type: ignore[misc]
    for ago, sev, text in [
        (timedelta(minutes=30), None, None),
        (timedelta(minutes=90), Severity.WARNING, "for 90 min"),
        (timedelta(hours=30), Severity.ERROR, "for 30 h"),
        (timedelta(days=3), Severity.ERROR, "for 3 d"),
    ]:
        out = evaluate(net, [down_long], None, past(devices={"gw": dev_hist(last_ok=NOW - ago)}))
        if text is None:
            assert out == []
            continue
        (f,) = out
        assert f.severity is sev and text in f.message and f.objects == ["gw"]
    (f,) = evaluate(net, [down_long], None, past(devices={"gw": dev_hist()}))
    assert "since Signalbox first saw it (2026-01-15 12:00 UTC)" in f.message
    ok = net_of(gateway())
    assert evaluate(ok, [down_long], None, past(devices={"gw": dev_hist()})) == []


def test_device_flapping() -> None:
    net = net_of(gateway())
    flaps = [
        StatusChange(at=NOW - timedelta(hours=h), old=DeviceStatus.OK, new=DeviceStatus.UNREACHABLE)
        for h in (1, 2, 3)
    ]
    (f,) = evaluate(net, [device_flapping], None, past(devices={"gw": dev_hist(changes=flaps)}))
    assert f.message == "gw stopped answering 3 times in the last 24 hours"
    old = [c.model_copy(update={"at": c.at - timedelta(days=2)}) for c in flaps]
    assert evaluate(net, [device_flapping], None, past(devices={"gw": dev_hist(changes=old)})) == []
    assert evaluate(net, [device_flapping], None, History.empty()) == []


def test_port_flapping() -> None:
    sw = snapshot(device("sw", DeviceRole.SWITCH), ports=[port("sw", "1", up=True)])
    link = Link(id="l1", a="gw/port/lan1", b="sw/port/1", origin=LinkOrigin.MANUAL)
    downs = [LinkChange(at=NOW - timedelta(hours=h), up=h % 2 == 0) for h in range(1, 7)]
    ports = {
        "gw/port/lan1": PortHistory(first_seen=T0, last_seen=NOW, up=True, since=NOW, changes=downs)
    }
    (f,) = evaluate(net_of(gateway(), sw, links=(link,)), [port_flapping], None, past(ports=ports))
    assert f.severity is Severity.WARNING
    assert f.message == "gw port lan1 (to sw) lost its link 3 times in the last 24 hours"
    (f,) = evaluate(net_of(gateway()), [port_flapping], None, past(ports=ports))
    assert f.severity is Severity.INFO and "(to" not in f.message
    dangling = Link(id="l2", a="gw/port/lan1", b="far/port/9", origin=LinkOrigin.MANUAL)
    (f,) = evaluate(net_of(gateway(), links=(dangling,)), [port_flapping], None, past(ports=ports))
    assert "(to far/port/9)" in f.message
    few = {k: v.model_copy(update={"changes": downs[:4]}) for k, v in ports.items()}
    assert evaluate(net_of(gateway()), [port_flapping], None, past(ports=few)) == []
    wireless = {"gw/port/wlan0": ports["gw/port/lan1"]}
    assert evaluate(net_of(gateway()), [port_flapping], None, past(ports=wireless)) == []
    assert evaluate(net_of(gateway()), [port_flapping], None, History.empty()) == []


def dhcp_net(*clients: Client, **kw: Any) -> Network:
    srv = DhcpServer(
        id="gw/dhcp/lan",
        device_id="gw",
        segment_id=LAN,
        enabled=True,
        reservations=[
            Reservation(mac=MAC, address=ip("192.0.2.30"), hostname="printer"),
            Reservation(mac="00:11:22:33:44:66", address=ip("192.0.2.31")),
        ],
    )
    return net_of(gateway(clients=clients, dhcp_servers=[srv], **kw))


def client_hist(mac: str = MAC, **kw: Any) -> ClientHistory:
    return ClientHistory(mac=mac, first_seen=T0, last_seen=NOW, **kw)


def test_stale_reservation() -> None:
    out = evaluate(dhcp_net(), [stale_reservation], None, past())
    assert [f.message for f in out] == [
        "The reservation 192.0.2.30 (printer) on LAN (untagged network) is for "
        "00:11:22:33:44:55, which has not been seen for more than 30 days",
        "The reservation 192.0.2.31 on LAN (untagged network) is for 00:11:22:33:44:66, which "
        "has not been seen for more than 30 days",
    ]
    assert out[0].severity is Severity.INFO and out[0].objects == ["gw/dhcp/lan"]
    # seen now, or within the history period
    (f,) = evaluate(dhcp_net(client()), [stale_reservation], None, past())
    assert "00:11:22:33:44:66" in f.message
    (f,) = evaluate(dhcp_net(), [stale_reservation], None, past(clients={MAC: client_hist()}))
    assert "00:11:22:33:44:66" in f.message
    # silent: too little history, or no device reported clients this round
    young = History(now=NOW, since=NOW - timedelta(days=29), observations=9, days=30)
    assert evaluate(dhcp_net(), [stale_reservation], None, young) == []
    err = ReadError(device_id="gw", capability="clients", message="timeout")
    out = evaluate(dhcp_net(errors=[err]), [stale_reservation], None, past())
    assert [f.rule_id for f in out] == ["signalbox.read"]
    assert evaluate(dhcp_net(), [stale_reservation]) == []


def test_network_changed() -> None:
    segs = [Segment(id=LAN, site_id="home", name="LAN"), Segment(id=GUEST, site_id="home", vlan=20)]
    net = net_of(gateway(clients=(client(seg=GUEST, hostname="nas"),), segments=segs))
    move = SegmentChange(at=NOW - timedelta(hours=2), old=LAN, new=GUEST)
    h = past(clients={MAC: client_hist(moves=[move])})
    (f,) = evaluate(net, [network_changed], None, h)
    assert f.message == (
        "nas (00:11:22:33:44:55) moved from LAN (untagged network) to VLAN 20 at "
        f"{move.at:%Y-%m-%d %H:%M} UTC"
    )
    assert f.objects == [f"client/{MAC}", LAN, GUEST]

    def silent(net: Network, *moves: SegmentChange) -> bool:
        hist = past(clients={MAC: client_hist(moves=list(moves))})
        return evaluate(net, [network_changed], None, hist) == []

    assert silent(net)  # never moved
    assert silent(net, move.model_copy(update={"at": NOW - timedelta(days=8)}))  # long ago
    back = SegmentChange(at=NOW - timedelta(hours=1), old=GUEST, new=LAN)
    assert silent(net, move, back)  # the last move went elsewhere
    assert silent(net, move, back, move.model_copy(update={"at": NOW}))  # roams by design
    assert silent(net_of(gateway(clients=(client(seg=None),))), move)
    rnd = net_of(gateway(clients=(client(RANDOM, seg=GUEST),)))
    hist = past(clients={RANDOM: client_hist(RANDOM, moves=[move])})
    assert evaluate(rnd, [network_changed], None, hist) == []
    assert evaluate(net, [network_changed], None, History.empty()) == []


def test_expectations_quiet_history_rules() -> None:
    off = annotation(f"client/{MAC}", expected={"may_be_unreachable": True})
    out = evaluate(annotated(dhcp_net(), off), [stale_reservation], None, past())
    assert len(out) == 1 and MAC not in out[0].message
    dev_off = annotation("gw", expected={"may_be_unreachable": True})
    h = past(devices={"gw": dev_hist(last_ok=NOW - timedelta(days=3))})
    down = annotated(net_of(gateway(DeviceStatus.UNREACHABLE)), dev_off)
    assert evaluate(down, [down_long], None, h) == []
    # a refused login is a real problem, whatever the user expects
    denied = annotated(net_of(gateway(DeviceStatus.AUTH_FAILED)), dev_off)
    assert len(evaluate(denied, [down_long], None, h)) == 1
    segs = [Segment(id=LAN, site_id="home", name="LAN"), Segment(id=GUEST, site_id="home", vlan=20)]
    net = net_of(gateway(clients=(client(seg=GUEST),), segments=segs))
    move = SegmentChange(at=NOW - timedelta(hours=2), old=LAN, new=GUEST)
    hist = past(clients={MAC: client_hist(moves=[move])})
    assert len(evaluate(net, [network_changed], None, hist)) == 1
    want = annotation(f"client/{MAC}", expected={"segment": LAN})
    assert evaluate(annotated(net, want), [network_changed], None, hist) == []
