"""Wi-Fi settings and clients over time (#447)."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from factories import SITE, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Band,
    Client,
    FastTransition,
    MeshPeer,
    Snapshot,
    WifiStandard,
    WirelessAssociation,
    WirelessLinkInfo,
)
from signalbox.rules import Finding, Rule, RuleSettings, evaluate
from signalbox.rules.wifi_clients import (
    RULES,
    OverloadParams,
    StickyParams,
    client_2_4_only,
    client_sticky,
    dtim_high,
    ft_over_ds,
    max_clients_low,
    radio_overloaded,
)
from signalbox.rules.wifi_roaming import client_weak_signal
from signalbox.secrets import load_vault
from signalbox.sightings import (
    History,
    ValueChange,
    ValueHistory,
    observed_values,
    parse_wifi,
    weak_run,
    wifi_spans,
    wifi_value,
)
from signalbox.store import Store
from test_rules_wireless import ap, radio, wlan

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
MAC = "02:00:00:00:00:61"


def run(r: Rule, *snaps: Snapshot, history: History | None = None, **params: int) -> list[Finding]:
    net = merge([SITE], snaps)
    settings = {r.id: RuleSettings(params=params)} if params else None
    return [f for f in evaluate(net, [r], settings, history) if f.rule_id == r.id]


def station(dev: str = "ap1", radio_name: str = "radio0", mac: str = MAC, **kw: Any) -> Client:
    wlan_id = f"{dev}/wlan/Example/{radio_name}"
    return Client(
        id=f"{dev}/client/{mac}",
        mac=mac,
        hostname="laptop",
        seen_on=wlan_id,
        wireless=WirelessAssociation(wlan_id=wlan_id, **kw),
    )


def with_clients(*clients: Client, dev: str = "ap1", **kw: Any) -> Snapshot:
    base = ap(dev, **kw)
    return snapshot(base.device, radios=base.radios, wlans=base.wlans, clients=list(clients))


def test_rules_are_exported() -> None:
    assert [r.id for r in RULES] == [
        "wifi.ft-over-ds",
        "wifi.dtim-high",
        "wifi.max-clients-low",
        "wifi.client-2-4-only",
        "wifi.radio-overloaded",
        "wifi.client-sticky",
    ]


# wifi.ft-over-ds ------------------------------------------------------------------------------


def test_ft_over_ds_is_found() -> None:
    ft = FastTransition(mobility_domain="a1b2", over_ds=True)
    (f,) = run(ft_over_ds, ap("ap1", wlans=[wlan("ap1", ft=ft)]))
    assert f.message_id == "wifi.ftOverDs" and f.fix_id == "wifi.ftOverDs.fix"
    assert f.params == {"ssid": "'Example'", "ap": "ap1"}


def test_ft_over_ds_quiet() -> None:
    for kw in (
        {"ft": FastTransition(over_ds=False)},
        {"ft": FastTransition(mobility_domain="a1b2")},  # not reported
        {"ft": FastTransition(over_ds=True), "roaming_80211r": False},
        {"ft": FastTransition(over_ds=True), "backhaul": True},
        {"ft": FastTransition(over_ds=True), "enabled": False},
        {},
    ):
        assert run(ft_over_ds, ap("ap1", wlans=[wlan("ap1", **kw)])) == []


# wifi.dtim-high -------------------------------------------------------------------------------


def test_dtim_high_is_found_and_scoped_by_parameter() -> None:
    (f,) = run(dtim_high, ap("ap1", wlans=[wlan("ap1", dtim_period=5)]))
    assert f.params == {"ssid": "'Example'", "ap": "ap1", "period": 5}
    assert f.message_id == "wifi.dtimHigh"
    assert run(dtim_high, ap("ap1", wlans=[wlan("ap1", dtim_period=5)]), max_period=5) == []


def test_dtim_high_quiet() -> None:
    for kw in ({"dtim_period": 3}, {"dtim_period": 1}, {}, {"dtim_period": 9, "backhaul": True}):
        assert run(dtim_high, ap("ap1", wlans=[wlan("ap1", **kw)])) == []


# wifi.max-clients-low -------------------------------------------------------------------------


def test_max_clients_reached_is_found() -> None:
    second = station(mac="02:00:00:00:00:62")
    snap = with_clients(station(), second, wlans=[wlan("ap1", max_clients=2)])
    (f,) = run(max_clients_low, snap)
    assert f.params == {"ssid": "'Example'", "ap": "ap1", "limit": 2, "clients": 2}
    assert f.message_id == "wifi.maxClientsLow"


def test_max_clients_quiet() -> None:
    mesh = station(mac="02:00:00:00:00:62")
    for limit in (3, 0, None):
        snap = with_clients(station(), mesh, wlans=[wlan("ap1", max_clients=limit)])
        assert run(max_clients_low, snap) == []
    backhaul = with_clients(station(), wlans=[wlan("ap1", max_clients=1, backhaul=True)])
    assert run(max_clients_low, backhaul) == []


def test_mesh_peers_do_not_count_as_clients() -> None:
    base = with_clients(station(), wlans=[wlan("ap1", max_clients=1)])
    peer = MeshPeer(
        id="ap1/meshpeer/1",
        device_id="ap1",
        port_id="ap1/port/wlan0",
        peer_mac=MAC,
        wireless=WirelessLinkInfo(),
    )
    assert len(run(max_clients_low, base)) == 1
    with_peer = base.model_copy(update={"mesh_peers": [peer]})
    assert run(max_clients_low, with_peer) == []


# wifi.client-2-4-only -------------------------------------------------------------------------


def dual_band(**kw: Any) -> dict[str, Any]:
    return {
        "radios": [radio("ap1", "radio0", Band.GHZ_2_4), radio("ap1", "radio1", Band.GHZ_5)],
        "wlans": [wlan("ap1", radio_name="radio0"), wlan("ap1", radio_name="radio1")],
        **kw,
    }


def test_client_2_4_only_is_found() -> None:
    sta = station(standard=WifiStandard.AX)
    (f,) = run(client_2_4_only, with_clients(sta, **dual_band()))
    assert f.params == {"client": f"laptop ({MAC})", "ap": "ap1", "ssid": "'Example'"}
    assert f.message_id == "wifi.client24Only"
    # the band the access point reports wins over the radio's
    other = station(band=Band.GHZ_2_4, standard=WifiStandard.AC)
    assert len(run(client_2_4_only, with_clients(other, **dual_band()))) == 1


def test_client_2_4_only_quiet() -> None:
    cases = [
        station(standard=WifiStandard.N),
        station(),
        station(radio_name="radio1", standard=WifiStandard.AX),
        station(band=Band.GHZ_5, standard=WifiStandard.AX),
    ]
    for sta in cases:
        assert run(client_2_4_only, with_clients(sta, **dual_band())) == []
    single = with_clients(
        station(standard=WifiStandard.AX), radios=[radio("ap1", "radio0", Band.GHZ_2_4)]
    )
    assert run(client_2_4_only, single) == []  # nothing faster to move to
    off = dual_band()
    off["wlans"][1] = wlan("ap1", radio_name="radio1", enabled=False)
    assert run(client_2_4_only, with_clients(station(standard=WifiStandard.AX), **off)) == []


# wifi.radio-overloaded ------------------------------------------------------------------------


def crowd(n: int, radio_name: str = "radio0") -> list[Client]:
    return [station(radio_name=radio_name, mac=f"02:00:00:00:01:{i:02x}") for i in range(n)]


def test_radio_overloaded_is_found() -> None:
    snap = with_clients(*crowd(31), **dual_band())
    (f,) = run(radio_overloaded, snap)
    assert f.message_id == "wifi.radioOverloaded"
    assert f.params == {
        "radio": "radio0",
        "ap": "ap1",
        "clients": 31,
        "other": "radio1",
        "other_ap": "ap1",
        "other_clients": 0,
    }
    assert OverloadParams().max_clients == 30
    assert len(run(radio_overloaded, with_clients(*crowd(6), **dual_band()), max_clients=5)) == 1


def test_radio_overloaded_quiet() -> None:
    assert run(radio_overloaded, with_clients(*crowd(30), **dual_band())) == []
    busy_other = [*crowd(31), *crowd(10, "radio1")]
    assert run(radio_overloaded, with_clients(*busy_other, **dual_band())) == []
    alone = with_clients(*crowd(31))
    assert run(radio_overloaded, alone) == []  # no other radio with the SSID
    backhaul = dual_band()
    backhaul["wlans"][1] = wlan("ap1", radio_name="radio1", backhaul=True)
    assert run(radio_overloaded, with_clients(*crowd(31), **backhaul)) == []


# history: values, spans and weak runs ---------------------------------------------------------


def hours(n: float) -> datetime:
    return NOW - timedelta(hours=n)


def past(*steps: tuple[float, str]) -> ValueHistory:
    """A client's history from ``(hours ago, value)`` steps, oldest first, seen until now."""
    changes = [
        ValueChange(at=hours(h), old=steps[i][1], new=value)
        for i, (h, value) in enumerate(steps[1:])
    ]
    return ValueHistory(
        first_seen=hours(steps[0][0]),
        last_seen=NOW,
        value=steps[-1][1],
        since=hours(steps[-1][0]),
        changes=changes,
    )


def test_wifi_value_rounds_down_to_five() -> None:
    assert wifi_value("ap1", -73) == "ap1 -75"
    assert wifi_value("ap1", -75) == "ap1 -75"
    assert wifi_value("ap1", -76) == "ap1 -80"
    assert parse_wifi("ap1 -75") == ("ap1", -75)
    assert parse_wifi("garbage") is None
    assert parse_wifi("") is None


def test_observed_values_record_the_access_point_and_signal() -> None:
    snap = with_clients(station(signal_dbm=-82), station(mac="02:00:00:00:00:62"))
    seen = observed_values(merge([SITE], [snap]))
    assert seen[("wifi", MAC)] == "ap1 -85"
    assert ("wifi", "02:00:00:00:00:62") not in seen  # no signal reported


def test_spans_and_weak_run() -> None:
    p = past((5, "ap2 -60"), (3, "ap1 -80"), (2, "ap1 -85"))
    spans = wifi_spans(p)
    assert [(s.device_id, s.bucket_dbm) for s in spans] == [
        ("ap2", -60),
        ("ap1", -80),
        ("ap1", -85),
    ]
    run_ = weak_run(p, -75)
    assert [s.bucket_dbm for s in run_] == [-80, -85]
    assert run_[0].start == hours(3) and run_[-1].end == NOW
    assert weak_run(p, -90) == []  # not weak now
    single = ValueHistory(first_seen=hours(1), last_seen=NOW, value="ap1 -80", since=hours(1))
    assert len(weak_run(single, -75)) == 1
    junk = ValueHistory(first_seen=hours(1), last_seen=NOW, value="x", since=hours(1))
    assert wifi_spans(junk) == []


# wifi.client-weak-signal over history ---------------------------------------------------------


def hist(**wifi: ValueHistory) -> History:
    return History(now=NOW, since=hours(100), observations=100, wifi=wifi)


def test_weak_signal_needs_to_be_sustained_with_history() -> None:
    sta = with_clients(station(signal_dbm=-82))
    long = past((2, "ap1 -85"))
    assert len(run(client_weak_signal, sta, history=hist(**{MAC: long}))) == 1
    short = ValueHistory(first_seen=hours(0.1), last_seen=NOW, value="ap1 -85", since=hours(0.1))
    assert run(client_weak_signal, sta, history=hist(**{MAC: short})) == []
    # an earlier strong stretch does not count
    flip = past((3, "ap1 -60"), (0.2, "ap1 -85"))
    assert run(client_weak_signal, sta, history=hist(**{MAC: flip})) == []
    # another access point before: weak there only for a short time
    moved = past((3, "ap2 -85"), (0.2, "ap1 -85"))
    assert run(client_weak_signal, sta, history=hist(**{MAC: moved})) == []
    assert len(run(client_weak_signal, sta, history=hist(), sustained_minutes=1)) == 1
    assert len(run(client_weak_signal, sta, history=hist(**{MAC: flip}), sustained_minutes=5)) == 1


def test_weak_signal_skips_mesh_nodes_and_backhaul() -> None:
    sta = with_clients(station(signal_dbm=-82), wlans=[wlan("ap1", backhaul=True)])
    assert run(client_weak_signal, sta) == []


# wifi.client-sticky ---------------------------------------------------------------------------


def two_aps(*clients: Client) -> list[Snapshot]:
    return [with_clients(*clients), ap("ap2")]


def test_sticky_client_is_found() -> None:
    p = past((6, "ap2 -55"), (2, "ap1 -85"))
    (f,) = run(client_sticky, *two_aps(station(signal_dbm=-82)), history=hist(**{MAC: p}))
    assert f.message_id == "wifi.clientSticky" and f.fix_id == "wifi.clientSticky.fix"
    assert f.params == {
        "client": f"laptop ({MAC})",
        "ap": "ap1",
        "dbm": -82,
        "minutes": 120,
        "other": "ap2",
        "other_dbm": -55,
    }
    assert StickyParams().sustained_minutes == 30


def test_sticky_client_quiet() -> None:
    sta = two_aps(station(signal_dbm=-82))

    def found_with(p: ValueHistory | None, **kw: int) -> int:
        h = hist(**{MAC: p}) if p else hist()
        return len(run(client_sticky, *sta, history=h, **kw))

    assert found_with(None) == 0  # no history of the client
    assert run(client_sticky, *sta) == []  # no history at all
    assert found_with(past((2, "ap1 -85"))) == 0  # never anywhere else
    assert found_with(past((6, "ap2 -80"), (2, "ap1 -85"))) == 0  # not stronger by the margin
    assert found_with(past((6, "ap2 -55"), (0.1, "ap1 -85"))) == 0  # not long enough
    assert found_with(past((6, "ap2 -55"), (2, "ap1 -60"))) == 0  # not weak
    assert found_with(past((6, "ap2 -55"), (2, "ap1 -85")), min_dbm=-90) == 0
    assert found_with(past((6, "ap2 -55"), (2, "ap1 -85")), margin_db=40) == 0
    assert found_with(past((6, "ap2 -55"), (2, "ap1 -85")), sustained_minutes=240) == 0
    other_ssid = [with_clients(station(signal_dbm=-82)), ap("ap2", wlans=[wlan("ap2", "Other")])]
    p = past((6, "ap2 -55"), (2, "ap1 -85"))
    assert run(client_sticky, *other_ssid, history=hist(**{MAC: p})) == []
    # the previous access point is no peer of the SSID
    assert run(client_sticky, with_clients(station(signal_dbm=-82)), history=hist(**{MAC: p})) == []


# store ----------------------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def test_store_keeps_the_signal_history_of_a_client(store: Store) -> None:
    start = NOW - timedelta(hours=3)

    def record(hours_in: int, dev: str, dbm: int) -> None:
        net = merge([SITE], [with_clients(station(dev, signal_dbm=dbm), dev=dev)])
        store.record_history(net, start + timedelta(hours=hours_in))

    record(0, "ap2", -55)
    record(1, "ap1", -85)
    record(2, "ap1", -83)  # same bucket: no change
    record(3, "ap1", -84)
    h = store.history(NOW, 30)
    p = h.wifi[MAC]
    assert p.value == "ap1 -85" and len(p.changes) == 1
    assert [(s.device_id, s.bucket_dbm) for s in wifi_spans(p)] == [("ap2", -55), ("ap1", -85)]
    assert weak_run(p, -75)[0].start == start + timedelta(hours=1)
