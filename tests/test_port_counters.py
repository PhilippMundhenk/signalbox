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
from signalbox.counters import CounterLimits, CounterRecord, counter_delta, counter_value
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, PortCounters, PortKind, PortRole
from signalbox.rules import Severity, evaluate
from signalbox.rules.port_counters import port_errors
from signalbox.secrets import load_vault
from signalbox.sightings import History
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


def test_limits_come_from_the_configuration() -> None:
    limits = Config().counters.limits()
    assert limits == CounterLimits()
    assert Config(counters={"min_errors": 9}).counters.limits().min_errors == 9


# rule -----------------------------------------------------------------------------------


def history_of(net: Network, old: PortCounters, new: PortCounters, **limits: Any) -> History:
    pid = net.ports[0].id
    record = CounterRecord(last=new, delta=counter_delta(old, new))
    return History(
        now=T0 + STEP,
        since=T0,
        counters={pid: record},
        counter_limits=CounterLimits(**limits),
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
    quiet = history_of(net, old, new, error_ratio=0.01)
    assert evaluate(net, [port_errors], None, quiet) == []
    loud = history_of(net, old, new, error_ratio=0.001)
    assert len(evaluate(net, [port_errors], None, loud)) == 1


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
