"""Traffic shaping rules (#166): passing, failing and silent cases."""

from typing import Any

from factories import SITE, device, snapshot, uplink
from signalbox.model import Network, Shaper, ShaperKind, UplinkKind
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.qos import (
    RULES,
    above_line,
    far_below_line,
    no_shaper,
    on_down_uplink,
)
from signalbox.testing import shaper_problems


def shaper(name: str = "sqm", **kw: Any) -> Shaper:
    kw.setdefault("uplink_id", "gw/uplink/wan")
    kw.setdefault("kind", ShaperKind.CAKE)
    return Shaper(id=f"gw/shaper/{name}", device_id="gw", name=name, **kw)


def net(*, adapter: str = "openwrt", up: dict[str, Any] | None = None, **kw: Any) -> Network:
    kw.setdefault("sites", [SITE])
    kw.setdefault(
        "devices", [device("gw", adapter=adapter, capabilities=["interfaces"]), device("ap")]
    )
    kw.setdefault("uplinks", [uplink("gw", **(up or {}))])
    return Network(**kw)


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def test_rules_are_registered() -> None:
    assert {r.id for r in RULES} == {
        "qos.shaper-above-line",
        "qos.shaper-far-below-line",
        "qos.shaper-on-down-uplink",
        "qos.no-shaper",
    }
    assert {r.id for r in RULES} <= {r.id for r in BUILTIN}


def test_rate_above_the_line_is_reported_per_direction() -> None:
    n = net(
        up={"downstream_kbps": 50_000, "upstream_kbps": 10_000},
        shapers=[shaper(download_kbps=60_000, upload_kbps=9_500)],
    )
    (f,) = run(above_line, n)
    assert "download" in f.message and "60 Mbit/s" in f.message


def test_rate_within_the_tolerance_or_below_is_fine() -> None:
    n = net(
        up={"downstream_kbps": 50_000, "upstream_kbps": 10_000},
        shapers=[shaper(download_kbps=52_000, upload_kbps=9_000)],
    )
    assert not run(above_line, n)


def test_unknown_rates_and_disabled_shapers_are_not_judged() -> None:
    shapers = [shaper(download_kbps=60_000, enabled=False), shaper("b", upload_kbps=99_999)]
    assert not run(above_line, net(up={"downstream_kbps": 50_000}, shapers=shapers))
    assert not run(far_below_line, net(up={"downstream_kbps": 50_000}, shapers=shapers))


def test_rate_far_below_the_line() -> None:
    n = net(up={"downstream_kbps": 100_000}, shapers=[shaper(download_kbps=20_000)])
    (f,) = run(far_below_line, n)
    assert f.severity.value == "info"
    ok = net(up={"downstream_kbps": 100_000}, shapers=[shaper(download_kbps=90_000)])
    assert not run(far_below_line, ok)


def test_shaper_on_a_down_uplink() -> None:
    n = net(up={"up": False, "since": None}, shapers=[shaper(download_kbps=1000)])
    assert len(run(on_down_uplink, n)) == 1
    assert not run(on_down_uplink, net(shapers=[shaper(download_kbps=1000)]))
    assert not run(on_down_uplink, net(up={"up": None}, shapers=[shaper()]))


def test_no_shaper_on_a_prone_line() -> None:
    (f,) = run(no_shaper, net(up={"kind": UplinkKind.PPPOE}))
    assert "no smart queue" in f.message
    assert run(no_shaper, net(up={"kind": UplinkKind.LTE}))
    assert run(no_shaper, net(up={"downstream_kbps": 50_000}))


def test_no_shaper_stays_quiet() -> None:
    prone = {"kind": UplinkKind.PPPOE}
    assert not run(no_shaper, net(up={"kind": UplinkKind.DHCP}))  # fibre or cable, rate unknown
    assert not run(no_shaper, net(adapter="fritzbox", up=prone))  # integration reads no shapers
    assert not run(no_shaper, net(up=prone | {"up": False, "since": None}))
    assert not run(no_shaper, net(up=prone, shapers=[shaper(download_kbps=1000)]))
    assert not run(no_shaper, net(up=prone, shapers=[shaper(uplink_id=None)]))
    # a disabled shaper does not cover the line
    assert run(no_shaper, net(up=prone, shapers=[shaper(enabled=False)]))


def test_contract_checks_of_shapers() -> None:
    snap = snapshot(device("gw"), shapers=[shaper(uplink_id="gw/uplink/x"), shaper()])
    assert any("unknown uplink" in p for p in shaper_problems(snap))
    dup = snapshot(device("gw"), shapers=[shaper(uplink_id=None), shaper(uplink_id=None)])
    assert any("reported twice" in p for p in shaper_problems(dup))
