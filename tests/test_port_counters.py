"""Port counters (#158) and the port.errors check (#115): deltas, resets, wraps, the store."""

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE, T0, device, port, snapshot
from signalbox.adapters.linux import parse
from signalbox.adapters.opnsense import counters_by_interface
from signalbox.adapters.portcounters import count, counters_of
from signalbox.config import Config
from signalbox.counters import CounterDelta, CounterRecord, counter_delta, counter_value
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    FrameTypes,
    Membership,
    Network,
    PortCounters,
    PortKind,
    PortMembership,
    PortRole,
    Segment,
)
from signalbox.rules import Rule, RuleScope, RuleSettings, ScopeMatch, Severity, evaluate
from signalbox.rules.port_counters import (
    port_collisions,
    port_drops,
    port_errors,
    port_idle_trunk,
    port_utilisation,
    reboot_by_counters,
)
from signalbox.secrets import load_vault
from signalbox.sightings import History, ValueHistory
from signalbox.store import Store

STEP = timedelta(minutes=10)


def pc(at: int, **kw: Any) -> PortCounters:
    """Counters read ``at`` rounds after T0."""
    return PortCounters(read_at=T0 + STEP * at, **kw)


def net_with(*ports: Any) -> Network:
    return merge([SITE], [snapshot(device("sw", DeviceRole.SWITCH), ports=list(ports))], [])


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


# delta ----------------------------------------------------------------------------------


def test_delta_between_two_reads() -> None:
    d = counter_delta(
        pc(0, rx_packets=100, rx_errors=1, rx_drops=2),
        pc(1, rx_packets=1100, rx_errors=11, rx_drops=2, tx_packets=5),
    )
    assert d is not None and not d.reset and d.seconds == 600
    assert (d.rx_packets, d.rx_errors, d.rx_drops, d.tx_packets) == (1000, 10, 0, None)
    assert d.packets == 1000 and d.errors == 10 and d.drops == 0


def test_errors_fall_back_to_crc_and_nothing() -> None:
    d = counter_delta(pc(0, rx_crc_errors=1), pc(1, rx_crc_errors=4))
    assert d is not None and d.errors == 3 and d.drops is None and d.packets is None
    d = counter_delta(pc(0, rx_bytes=1), pc(1, rx_bytes=2))
    assert d is not None and d.errors is None


def test_counter_that_goes_down_is_a_reset() -> None:
    d = counter_delta(pc(0, rx_packets=5000, rx_errors=9), pc(1, rx_packets=40, rx_errors=0))
    assert d is not None and d.reset and d.rx_packets is None and d.errors is None


def test_counters_since_that_moves_is_a_reset() -> None:
    old = pc(0, rx_packets=5, counters_since=T0)
    new = pc(1, rx_packets=9, counters_since=T0 + timedelta(minutes=7))
    d = counter_delta(old, new)
    assert d is not None and d.reset
    same = counter_delta(old, pc(1, rx_packets=9, counters_since=T0 + timedelta(seconds=5)))
    assert same is not None and not same.reset and same.rx_packets == 4


def test_32_bit_wrap_is_counted_through() -> None:
    top = 2**32 - 100
    d = counter_delta(pc(0, rx_packets=top), pc(1, rx_packets=50))
    assert d is not None and not d.reset and d.rx_packets == 150
    d = counter_delta(pc(0, rx_packets=2**40), pc(1, rx_packets=50))
    assert d is not None and d.reset  # a 64-bit counter does not wrap: it was reset


def test_no_time_base_no_delta() -> None:
    assert counter_delta(PortCounters(rx_bytes=1), pc(1, rx_bytes=2)) is None
    assert counter_delta(pc(1, rx_bytes=1), pc(1, rx_bytes=2)) is None  # the same read
    assert counter_delta(pc(1, rx_bytes=1), pc(0, rx_bytes=2)) is None
    assert counter_delta(pc(0, rx_bytes=1), pc(200, rx_bytes=2)) is None  # a day apart


def test_counter_value_keeps_the_last_delta_for_the_same_read() -> None:
    first = counter_value(None, pc(0, rx_packets=1))
    assert first is not None
    second = counter_value(first, pc(1, rx_packets=11))
    assert second is not None and '"rx_packets":10' in second
    assert counter_value(second, pc(1, rx_packets=11)) is None  # the same read again
    assert counter_value(second, PortCounters(rx_packets=11)) is None  # never stamped
    third = counter_value("not json", pc(2, rx_packets=1))
    assert third is not None and "delta" not in third


# store ----------------------------------------------------------------------------------


def test_store_keeps_last_value_and_delta_without_a_change_log(store: Store) -> None:
    def read(n: int, **kw: Any) -> Network:
        return net_with(port("sw", "1", up=True, counters=pc(n, **kw)))

    store.record_history(read(0, rx_packets=1000, rx_errors=0), T0)
    h = store.history(T0, 30)
    assert h.counters["sw/port/1"].delta is None
    store.record_history(read(1, rx_packets=3000, rx_errors=8), T0 + STEP)
    store.record_history(read(1, rx_packets=3000, rx_errors=8), T0 + 2 * STEP)  # same read
    h = store.history(T0 + 2 * STEP, 30)
    delta = h.counters["sw/port/1"].delta
    assert delta is not None and delta.rx_packets == 2000 and delta.rx_errors == 8
    assert h.counters["sw/port/1"].last.rx_packets == 3000
    assert store._db.execute("SELECT count(*) FROM sighting_changes").fetchone()[0] == 0
    store.record_history(read(3, rx_packets=10, rx_errors=0), T0 + 3 * STEP)  # a reboot
    reset = store.history(T0, 30).counters["sw/port/1"].delta
    assert reset is not None and reset.reset
    store.delete_device("sw")
    assert store.history(T0, 30).counters == {}


def test_store_ignores_a_stored_value_of_another_version(store: Store) -> None:
    store.record_history(net_with(port("sw", "1", counters=pc(0, rx_bytes=1))), T0)
    store._db.execute("UPDATE sightings SET value = 'x' WHERE kind = 'counters'")
    assert store.history(T0, 30).counters == {}


def test_deprecated_counters_settings_become_rule_parameters(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert Config().rules == {}  # defaults set nothing
    cfg = Config(counters={"min_errors": 9, "error_ratio": 0.001})  # the default is not applied
    assert cfg.rules["port.errors"].params == {"min_errors": 9}
    assert "counters.min_errors is deprecated" in caplog.text
    assert "error_ratio" not in caplog.text
    # the rule's own parameter wins over the deprecated setting
    both = Config(counters={"min_errors": 9}, rules={"port.errors": {"params": {"min_errors": 3}}})
    assert both.rules["port.errors"].params == {"min_errors": 3}


# rule -----------------------------------------------------------------------------------


def history_of(net: Network, old: PortCounters, new: PortCounters) -> History:
    pid = net.ports[0].id
    record = CounterRecord(last=new, delta=counter_delta(old, new))
    return History(
        now=T0 + STEP,
        since=T0,
        counters={pid: record},
    )


def check(old: PortCounters, new: PortCounters, **port_kw: Any) -> tuple[Network, list[Any]]:
    net = net_with(port("sw", "3", **({"up": True} | port_kw)))
    return net, evaluate(net, [port_errors], None, history_of(net, old, new))


def test_crc_errors_warn() -> None:
    _, found = check(
        pc(0, rx_packets=0, tx_packets=0, rx_crc_errors=0, rx_errors=0),
        pc(1, rx_packets=20_000, tx_packets=20_000, rx_crc_errors=40, rx_errors=40),
    )
    (f,) = found
    assert f.severity is Severity.WARNING and f.objects == ["sw/port/3"]
    assert f.message == (
        "sw port 3 received 40 frames with a bad checksum (CRC) in the last 10 min "
        "(0.20% of 20000 packets)"
    )
    assert f.message_id == "counters.portCrc" and f.params["count"] == 40


def test_other_errors_are_info() -> None:
    _, found = check(
        pc(0, rx_packets=0, tx_packets=0, tx_errors=0),
        pc(1, rx_packets=5000, tx_packets=5000, tx_errors=30),
    )
    (f,) = found
    assert f.severity is Severity.INFO and f.message_id == "counters.portErrors"


def test_quiet_cases() -> None:
    few_errors = pc(1, rx_packets=50_000, rx_errors=3, rx_crc_errors=3)
    low_share = pc(1, rx_packets=5_000_000, rx_errors=500, rx_crc_errors=100)
    for old, new in (
        (pc(0, rx_packets=0, rx_errors=0, rx_crc_errors=0), few_errors),  # below min_errors
        (pc(0, rx_packets=0, rx_errors=0, rx_crc_errors=0), low_share),  # tiny share
        (pc(0, rx_packets=0, rx_errors=0), pc(1, rx_packets=500, rx_errors=100)),  # few packets
        (pc(0, rx_packets=0), pc(1, rx_packets=9000)),  # no error counters
        (pc(0, rx_packets=9000, rx_errors=900), pc(1, rx_packets=10, rx_errors=0)),  # reset
        (pc(0, rx_errors=0), pc(1, rx_errors=900)),  # no packets
    ):
        assert check(old, new)[1] == []


def test_down_disabled_and_internal_ports_are_ignored() -> None:
    old = pc(0, rx_packets=0, rx_errors=0, rx_crc_errors=0)
    new = pc(1, rx_packets=20_000, rx_errors=400, rx_crc_errors=400)
    assert check(old, new, up=False)[1] == []
    assert check(old, new, admin_up=False)[1] == []
    assert check(old, new, kind=PortKind.WIRELESS)[1] == []
    assert check(old, new, role=PortRole.BRIDGE)[1] == []
    assert len(check(old, new)[1]) == 1


def test_quiet_without_history() -> None:
    net = net_with(port("sw", "3", up=True))
    assert evaluate(net, [port_errors], None, History.empty()) == []
    assert list(port_errors.check(net)) == []


def test_thresholds_are_configurable() -> None:
    net = net_with(port("sw", "3", up=True))
    old = pc(0, rx_packets=0, rx_errors=0)
    new = pc(1, rx_packets=2000, rx_errors=6)
    history = history_of(net, old, new)
    quiet = {"port.errors": RuleSettings(params={"error_ratio": 0.01})}
    assert evaluate(net, [port_errors], quiet, history) == []
    assert len(evaluate(net, [port_errors], None, history)) == 1
    # a scope changes it for the ports of one device only
    scoped = {
        "port.errors": RuleSettings(
            scopes=[RuleScope(match=ScopeMatch(device="sw"), params={"error_ratio": 0.01})]
        )
    }
    assert evaluate(net, [port_errors], scoped, history) == []
    other = {
        "port.errors": RuleSettings(
            scopes=[RuleScope(match=ScopeMatch(device="other"), params={"error_ratio": 0.01})]
        )
    }
    assert len(evaluate(net, [port_errors], other, history)) == 1


# readers --------------------------------------------------------------------------------


def test_count_and_counters_of() -> None:
    assert count(5) == 5 and count("7") == 7 and count(" 8 ") == 8 and count(2.0) == 2
    assert count(-1) is None and count(-1.5) is None and count(True) is None
    assert count("x") is None and count(None) is None
    got = counters_of({"a": "3", "c": 4}, {"rx_bytes": ("b", "a"), "tx_bytes": "c"})
    assert got == PortCounters(rx_bytes=3, tx_bytes=4)
    assert counters_of({}, {"rx_bytes": "a"}) is None
    with pytest.raises(ValueError):
        counters_of({}, {"bogus": "a"})


def test_linux_ip_link_counters() -> None:
    row = {
        "stats64": {
            "rx": {"bytes": 10, "packets": 5, "errors": 1, "dropped": 2, "crc_errors": 1},
            "tx": {"bytes": 20, "packets": 6, "errors": 0, "dropped": 0, "collisions": 0},
        }
    }
    assert parse.link_counters(row) == PortCounters(
        rx_bytes=10,
        rx_packets=5,
        rx_errors=1,
        rx_crc_errors=1,
        rx_drops=2,
        tx_bytes=20,
        tx_packets=6,
        tx_errors=0,
        tx_drops=0,
        collisions=0,
    )
    old = {"stats": {"rx": {"bytes": 1}, "tx": "no"}}  # iproute2 without stats64
    assert parse.link_counters(old) == PortCounters(rx_bytes=1)
    assert parse.link_counters({}) is None
    assert parse.link_counters({"stats64": {"rx": {}}}) is None


def test_opnsense_interface_statistics() -> None:
    answer = {
        "statistics": {
            "igb0 / 02:00:00:00:01:00": {
                "name": "igb0",
                "received-packets": "10",
                "received-errors": "2",
                "dropped-packets": "1",
                "received-bytes": "100",
                "sent-packets": 20,
                "send-errors": "0",
                "sent-bytes": "200",
                "collisions": "0",
            },
            "igb0 / 192.0.2.0/24": {"name": "igb0", "received-packets": "1"},
            "junk": "x",
        }
    }
    got = counters_by_interface(answer)
    assert got["igb0"].rx_packets == 10 and got["igb0"].tx_errors == 0
    assert got["igb0"].rx_drops == 1 and got["igb0"].collisions == 0
    assert counters_by_interface([{"name": "em0", "sent-bytes": "5"}])["em0"].tx_bytes == 5
    assert counters_by_interface("nothing") == {}


def test_port_counters_api(tmp_path: Path) -> None:
    from signalbox.service import build
    from signalbox.web.app import create_app
    from test_runner import Dev, per_device
    from test_web import PW

    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"dev": Dev},
        rules=[per_device],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    try:
        with TestClient(create_app(svc, run_background=False)) as c:
            assert c.post("/api/login", json={"password": PW}).status_code == 200
            assert c.get("/api/devices/sw/port-counters").json() == {}
            for n, errors in ((0, 0), (1, 7)):
                net = net_with(
                    port("sw", "1", counters=pc(n, rx_packets=n * 900, rx_errors=errors))
                )
                svc.store.record_history(net, T0 + STEP * n)
            got = c.get("/api/devices/sw/port-counters").json()
            assert got == {
                "sw/port/1": {"seconds": 600.0, "reset": False, "errors": 7, "drops": None}
            }
            assert c.get("/api/devices/other/port-counters").json() == {}
    finally:
        svc.close()


# --- follow-ups of #434 ---------------------------------------------------------------------


def check_rule(rule: Rule, old: PortCounters, new: PortCounters, **port_kw: Any) -> list[Any]:
    net = net_with(port("sw", "3", **({"up": True} | port_kw)))
    return evaluate(net, [rule], None, history_of(net, old, new))


def test_drops_found_and_quiet() -> None:
    old = pc(0, rx_packets=0, tx_packets=0, rx_drops=0, tx_drops=0)
    (f,) = check_rule(
        port_drops, old, pc(1, rx_packets=5000, tx_packets=5000, rx_drops=10, tx_drops=190)
    )
    assert f.severity is Severity.INFO and f.message_id == "counters.portDrops"
    assert f.params["count"] == 200 and f.params["share"] == "2.00%"
    for new in (
        pc(1, rx_packets=5000, tx_packets=5000, rx_drops=5, tx_drops=5),  # too few drops
        pc(1, rx_packets=500_000, tx_packets=500_000, tx_drops=500),  # tiny share
        pc(1, rx_packets=300, tx_packets=300, tx_drops=100),  # too few packets
        pc(1, rx_packets=9000),  # no drop counters
    ):
        assert not check_rule(port_drops, old, new)
    assert not check_rule(port_drops, old, pc(1, rx_packets=5000, tx_drops=900), up=False)


def test_utilisation() -> None:
    old = pc(0, rx_bytes=0, tx_bytes=0)
    # 10 min = 600 s: 700 MB is 9.3 Mbit/s of a 10 Mbit/s link
    (f,) = check_rule(port_utilisation, old, pc(1, rx_bytes=700_000_000, tx_bytes=0), speed_mbps=10)
    assert f.message_id == "counters.portUtilisationRx" and f.params["percent"] == 93
    (g,) = check_rule(
        port_utilisation, old, pc(1, rx_bytes=0, tx_bytes=7_500_000_000), speed_mbps=100
    )
    assert g.message_id == "counters.portUtilisationTx" and g.params["rate"] == 100
    assert not check_rule(port_utilisation, old, pc(1, rx_bytes=700_000_000), speed_mbps=1000)
    assert not check_rule(port_utilisation, old, pc(1, rx_bytes=700_000_000))  # speed unknown
    assert not check_rule(port_utilisation, old, pc(1, rx_packets=5), speed_mbps=10)


def test_idle_trunk() -> None:
    old = pc(0, rx_bytes=0, tx_bytes=0)
    quiet = pc(1, rx_bytes=2000, tx_bytes=3000)
    busy = pc(1, rx_bytes=50_000_000, tx_bytes=3000)
    (f,) = check_rule(port_idle_trunk, old, quiet, frame_types=FrameTypes.TAGGED_ONLY)
    assert f.message_id == "counters.idleTrunk" and f.objects == ["sw/port/3"]
    assert not check_rule(port_idle_trunk, old, busy, frame_types=FrameTypes.TAGGED_ONLY)
    assert not check_rule(port_idle_trunk, old, quiet)  # an access port may be quiet
    assert not check_rule(port_idle_trunk, old, pc(1), frame_types=FrameTypes.TAGGED_ONLY)
    assert not check_rule(port_idle_trunk, old, quiet, frame_types=FrameTypes.TAGGED_ONLY, up=False)


def test_idle_trunk_from_a_tagged_membership() -> None:
    net = net_with(port("sw", "3", up=True))
    pid = net.ports[0].id
    segment = Segment(
        id="home/segment/v20",
        site_id=SITE.id,
        vlan=20,
        members=[PortMembership(port_id=pid, mode=Membership.TAGGED)],
    )
    net = net.model_copy(update={"segments": [segment]})
    old, new = pc(0, rx_bytes=0, tx_bytes=0), pc(1, rx_bytes=10, tx_bytes=10)
    assert len(evaluate(net, [port_idle_trunk], None, history_of(net, old, new))) == 1


def test_collisions() -> None:
    old = pc(0, collisions=0)
    (f,) = check_rule(port_collisions, old, pc(1, collisions=40), full_duplex=True)
    assert f.severity is Severity.WARNING and f.params["count"] == 40
    assert check_rule(port_collisions, old, pc(1, collisions=40), speed_mbps=1000)
    assert not check_rule(port_collisions, old, pc(1, collisions=40), full_duplex=False)
    assert not check_rule(port_collisions, old, pc(1, collisions=40))  # duplex unknown
    assert not check_rule(port_collisions, old, pc(1, collisions=3), full_duplex=True)
    assert not check_rule(port_collisions, old, pc(1, collisions=0), full_duplex=True)


def _reset_history(net: Network, resets: list[bool]) -> History:
    counters = {}
    for p, reset in zip(net.ports, resets, strict=True):
        delta = CounterDelta(seconds=600, reset=True) if reset else CounterDelta(seconds=600)
        counters[p.id] = CounterRecord(last=pc(1, rx_bytes=1), delta=delta)
    return History(now=T0 + STEP, since=T0, counters=counters)


def test_reboot_by_counters() -> None:
    net = net_with(*(port("sw", str(i), up=True) for i in range(1, 5)))
    (f,) = evaluate(net, [reboot_by_counters], None, _reset_history(net, [True] * 4))
    assert f.message_id == "counters.deviceReset" and f.params["count"] == 4
    # one port that did not reset: someone cleared a single port
    assert not evaluate(net, [reboot_by_counters], None, _reset_history(net, [True] * 3 + [False]))
    small = net_with(port("sw", "1", up=True), port("sw", "2", up=True))
    assert not evaluate(small, [reboot_by_counters], None, _reset_history(small, [True] * 2))
    # a device with a known boot time is left to device.reboot
    known = _reset_history(net, [True] * 4).model_copy(
        update={"boots": {"sw": ValueHistory(first_seen=T0, last_seen=T0, value="x", since=T0)}}
    )
    assert not evaluate(net, [reboot_by_counters], None, known)
    assert not evaluate(net, [reboot_by_counters], None, History.empty())


# --- the per-port series (#471) -----------------------------------------------------------


def _record_traffic(store: Store, rounds: int, rx_per_round: int, tx_per_round: int = 0) -> None:
    """``rounds`` + 1 reads, 10 minutes apart, with the given bytes added each round."""
    for n in range(rounds + 1):
        net = net_with(
            port(
                "sw",
                "1",
                up=True,
                speed_mbps=100,
                counters=pc(n, rx_bytes=n * rx_per_round, tx_bytes=n * tx_per_round),
            )
        )
        store.record_history(net, T0 + STEP * n)


def test_schema_9_migration_adds_the_series_table(tmp_path: Path) -> None:
    import sqlite3

    from signalbox.store import SCHEMA

    path = tmp_path / "db.sqlite"
    db = sqlite3.connect(path)
    script = "; ".join(SCHEMA[:8])
    db.executescript(f"BEGIN; {script}; PRAGMA user_version = 8; COMMIT;")
    db.execute("INSERT INTO sites (id, name) VALUES ('home', 'Home')")
    db.commit()
    db.close()
    s = Store(path, load_vault(tmp_path, env={}))
    try:
        assert s._db.execute("PRAGMA user_version").fetchone()[0] == 9
        assert s.sites() == [SITE]
        assert s.history(T0, 30).series == {}
        _record_traffic(s, 1, 1000)
        assert s.history(T0, 30).series["sw/port/1"][0].rx_bytes == 1000
    finally:
        s.close()


def test_store_sums_the_deltas_into_hourly_buckets(store: Store) -> None:
    _record_traffic(store, 8, 6_000_000, 3_000_000)
    series = store.history(T0 + 8 * STEP, 30).series["sw/port/1"]
    assert sum(b.seconds for b in series) == 8 * 600
    assert sum(b.rx_bytes for b in series) == 8 * 6_000_000
    assert sum(b.tx_bytes for b in series) == 8 * 3_000_000
    assert 1 <= len(series) <= 2 and [b.at for b in series] == sorted(b.at for b in series)
    assert all(b.at.minute == 0 for b in series)
    assert series[0].rx_bps == pytest.approx(80_000.0)
    assert series[0].tx_bps == pytest.approx(40_000.0)


def test_series_skips_resets_unchanged_reads_and_byteless_ports(store: Store) -> None:
    def read(n: int, **kw: Any) -> Network:
        return net_with(port("sw", "1", counters=pc(n, **kw)))

    store.record_history(read(0, rx_bytes=100), T0)
    store.record_history(read(1, rx_bytes=1100), T0 + STEP)
    store.record_history(read(1, rx_bytes=1100), T0 + 2 * STEP)  # the same read again
    store.record_history(read(2, rx_bytes=5), T0 + 3 * STEP)  # a reset
    (bucket,) = store.history(T0, 30).series["sw/port/1"]
    assert bucket.rx_bytes == 1000 and bucket.seconds == 600
    store.record_history(net_with(port("sw", "2", counters=pc(0, rx_packets=1))), T0)
    store.record_history(net_with(port("sw", "2", counters=pc(1, rx_packets=9))), T0 + STEP)
    assert "sw/port/2" not in store.history(T0, 30).series


def test_series_is_pruned_with_the_history_and_with_the_device(store: Store) -> None:
    _record_traffic(store, 2, 1000)
    assert store.history(T0, 30).series
    store.prune_history(T0 + timedelta(days=2))
    assert store.history(T0, 30).series == {}
    _record_traffic(store, 2, 1000)
    store.delete_device("sw")
    assert store.history(T0, 30).series == {}


def test_port_series_api_and_history_without_the_series(tmp_path: Path) -> None:
    from signalbox.service import build
    from signalbox.web.app import create_app
    from test_runner import Dev, per_device
    from test_web import PW

    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"dev": Dev},
        rules=[per_device],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    try:
        with TestClient(create_app(svc, run_background=False)) as c:
            assert c.post("/api/login", json={"password": PW}).status_code == 200
            assert c.get("/api/devices/sw/port-series").json() == {}
            _record_traffic(svc.store, 1, 75_000_000)
            got = c.get("/api/devices/sw/port-series").json()
            (bucket,) = got["sw/port/1"]
            assert bucket["seconds"] == 600.0 and bucket["rx_bps"] == 1_000_000
            assert bucket["tx_bps"] == 0
            assert c.get("/api/devices/other/port-series").json() == {}
            assert "series" not in c.get("/api/history").json()
    finally:
        svc.close()


def series_history(net: Network, rates_mbps: list[float]) -> History:
    """Hourly buckets ending at ``now``: one per given rate (Mbit/s received), 3600 s each,
    and a quiet last read interval."""
    from signalbox.counters import CounterBucket

    pid = net.ports[0].id
    now = T0.replace(minute=0, second=0, microsecond=0) + timedelta(hours=6)
    buckets = [
        CounterBucket(
            at=now - timedelta(hours=len(rates_mbps) - i),
            seconds=3600,
            rx_bytes=int(r * 1e6 / 8 * 3600),
        )
        for i, r in enumerate(rates_mbps)
    ]
    old, new = pc(0, rx_bytes=0, tx_bytes=0), pc(1, rx_bytes=0, tx_bytes=0)
    record = CounterRecord(last=new, delta=counter_delta(old, new))
    return History(now=now, since=T0, counters={pid: record}, series={pid: buckets})


def test_utilisation_judges_a_percentile_over_the_window() -> None:
    net = net_with(port("sw", "3", up=True, speed_mbps=100))
    (f,) = evaluate(net, [port_utilisation], None, series_history(net, [95, 96, 97, 98, 99, 99]))
    assert f.message_id == "counters.portUtilisationRx"
    assert f.params["minutes"] == 360 and f.params["rate"] == 99
    one_busy = series_history(net, [1, 1, 1, 1, 1, 99])
    # the 90th percentile of six hours is the busiest hour; a lower percentile ignores it
    assert evaluate(net, [port_utilisation], None, one_busy)
    median = {"port.utilisation": RuleSettings(params={"percentile": 50})}
    assert not evaluate(net, [port_utilisation], median, one_busy)
    # the quiet last interval does not matter when the window is covered
    assert not evaluate(net, [port_utilisation], None, series_history(net, [10] * 6))
    off = {"port.utilisation": RuleSettings(params={"window_hours": 0})}
    assert not evaluate(net, [port_utilisation], off, series_history(net, [99] * 6))


def test_utilisation_falls_back_to_the_last_interval_without_enough_series() -> None:
    net = net_with(port("sw", "3", up=True, speed_mbps=10))
    pid = net.ports[0].id
    old, new = pc(0, rx_bytes=0), pc(1, rx_bytes=700_000_000)
    history = series_history(net, [99]).model_copy(  # one hour of six: below the coverage
        update={"counters": {pid: CounterRecord(last=new, delta=counter_delta(old, new))}}
    )
    (f,) = evaluate(net, [port_utilisation], None, history)
    assert f.params["minutes"] == 10 and f.params["percent"] == 93


def test_idle_trunk_needs_a_sustained_period() -> None:
    net = net_with(port("sw", "3", up=True, frame_types=FrameTypes.TAGGED_ONLY))
    (f,) = evaluate(net, [port_idle_trunk], None, series_history(net, [0.0] * 6))
    assert f.message_id == "counters.idleTrunk" and f.params["minutes"] == 360
    # one busy hour in the period: not idle, although the last interval was quiet
    assert not evaluate(net, [port_idle_trunk], None, series_history(net, [0, 0, 5, 0, 0, 0]))
