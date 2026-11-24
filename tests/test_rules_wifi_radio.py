"""Radio state rules and capability-aware Wi-Fi suggestions (#172)."""

from datetime import UTC, datetime, timedelta

import pytest

from factories import SITE
from signalbox.merge import merge
from signalbox.model import Band, DfsState, Site, Snapshot, WifiStandard
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.wifi_hygiene import channel_plan_24, channel_width, dfs
from signalbox.rules.wifi_radio import channel_busy, legacy_standard, radar_hit
from signalbox.rules.wireless import channel_overlap, channel_ranges, quiet_channels
from signalbox.sightings import History
from test_rules_wireless import ap, radio

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
EU_5 = [*range(36, 65, 4), *range(100, 141, 4)]


def run(r: Rule, *snaps: Snapshot, now: datetime | None = NOW) -> list[Finding]:
    net = merge([SITE, Site(id="cabin", name="Cabin")], snaps, [])
    return [f for f in evaluate(net, [r], history=History(now=now)) if f.rule_id == r.id]


# wifi.channel-busy ----------------------------------------------------------------------------


@pytest.mark.parametrize(("busy", "severity"), [(60.0, Severity.INFO), (85.4, Severity.WARNING)])
def test_busy_channel(busy: float, severity: Severity) -> None:
    (f,) = run(
        channel_busy, ap("ap1", radios=[radio("ap1", channel=36, channel_utilisation_pct=busy)])
    )
    assert f.severity is severity
    assert f.message == f"The channel of ap1 (5 GHz) was busy {busy:.0f} % of the time"
    assert f.message_id == "wifiRadio.busy" and f.fix_id == "wifiRadio.busy.fix"
    assert f.params["busy"] == round(busy)


def test_busy_channel_mostly_others() -> None:
    r = radio("ap1", channel=36, channel_utilisation_pct=70, interference_pct=50)
    (f,) = run(channel_busy, ap("ap1", radios=[r]))
    assert f.message.endswith("(50 % neighbours and interference)")
    assert f.message_id == "wifiRadio.busyInterference"
    assert f.fix_id == "wifiRadio.busy.fixOthers" and "automatic channel selection" in (f.fix or "")
    auto = radio(
        "ap1", channel=36, channel_auto=True, channel_utilisation_pct=70, interference_pct=50
    )
    (g,) = run(channel_busy, ap("ap1", radios=[auto]))
    assert g.fix_id == "wifiRadio.busy.fixAuto"
    own = radio("ap1", channel=36, channel_utilisation_pct=70, interference_pct=10)
    (h,) = run(channel_busy, ap("ap1", radios=[own]))
    assert h.fix_id == "wifiRadio.busy.fix"


def test_busy_channel_stays_quiet() -> None:
    radios = [
        radio("ap1", "r0", channel=36, channel_utilisation_pct=59.9),
        radio("ap1", "r1", channel=100),  # not reported
        radio("ap1", "r2", channel=149, channel_utilisation_pct=95, enabled=False),
    ]
    assert run(channel_busy, ap("ap1", radios=radios)) == []


# wifi.radar-hit -------------------------------------------------------------------------------


def test_recent_radar() -> None:
    r = radio("ap1", channel=100, last_radar=NOW - timedelta(hours=3), supported_channels=EU_5)
    (f,) = run(radar_hit, ap("ap1", radios=[r]))
    assert f.severity is Severity.INFO
    assert f.message == "ap1 (5 GHz) detected radar at 2026-11-24 09:00 UTC"
    assert f.fix_id == "wifi.dfs.fixSupported" and f.params["channels"] == "36-48"


def test_radar_state_without_time() -> None:
    r = radio("ap1", channel=52, dfs_state=DfsState.RADAR_DETECTED)
    (f,) = run(radar_hit, ap("ap1", radios=[r]), now=None)
    assert f.message == "ap1 (5 GHz) left channel 52 because radar was detected"
    assert f.fix_id == "wifi.dfs.fix"


def test_radar_stays_quiet() -> None:
    radios = [
        radio("ap1", "r0", channel=100, last_radar=NOW - timedelta(hours=25)),
        radio("ap1", "r1", channel=52, dfs_state=DfsState.AVAILABLE),
        radio("ap1", "r2", channel=100, dfs_state=DfsState.RADAR_DETECTED, enabled=False),
        radio("ap1", "r3", Band.GHZ_6, channel=37, dfs_state=DfsState.RADAR_DETECTED),
    ]
    assert run(radar_hit, ap("ap1", radios=radios)) == []
    # without a time, an old timestamp alone says nothing
    recent = radio("ap1", channel=100, last_radar=NOW)
    assert run(radar_hit, ap("ap1", radios=[recent]), now=None) == []


# wifi.legacy-standard -------------------------------------------------------------------------

AX_5 = [WifiStandard.A, WifiStandard.N, WifiStandard.AC, WifiStandard.AX]


@pytest.mark.parametrize(
    ("standard", "standards", "newest", "severity"),
    [
        (WifiStandard.N, AX_5, "802.11ax", Severity.INFO),
        (WifiStandard.A, AX_5, "802.11ax", Severity.WARNING),
        (WifiStandard.AC, [*AX_5, WifiStandard.BE], "802.11ax", Severity.INFO),
        (
            WifiStandard.N,
            [WifiStandard.A, WifiStandard.N, WifiStandard.AC],
            "802.11ac",
            Severity.INFO,
        ),
    ],
)
def test_legacy_standard(
    standard: WifiStandard, standards: list[WifiStandard], newest: str, severity: Severity
) -> None:
    r = radio("ap1", channel=36, standard=standard, standards=standards)
    (f,) = run(legacy_standard, ap("ap1", radios=[r]))
    assert f.severity is severity
    assert (
        f.message == f"ap1 (5 GHz) is set to 802.11{standard.value} although it supports {newest}"
    )
    assert f.params == {
        "radio": "ap1 (5 GHz)",
        "standard": f"802.11{standard.value}",
        "newest": newest,
    }


def test_legacy_standard_stays_quiet() -> None:
    radios = [
        radio("ap1", "r0", standard=WifiStandard.AX, standards=AX_5),
        radio("ap1", "r1", standard=WifiStandard.AX, standards=[*AX_5, WifiStandard.BE]),
        radio("ap1", "r2", standard=WifiStandard.N),  # capabilities not reported
        radio("ap1", "r3", standards=AX_5),  # mode not reported
        radio("ap1", "r4", standard=WifiStandard.N, standards=AX_5, enabled=False),
        radio("ap1", "r5", standard=WifiStandard.N, standards=[]),
    ]
    assert run(legacy_standard, ap("ap1", radios=radios)) == []


# capability-aware suggestions -----------------------------------------------------------------


def test_dfs_suggests_supported_channels() -> None:
    (f,) = run(dfs, ap("ap1", radios=[radio("ap1", channel=100, supported_channels=EU_5)]))
    assert f.fix == "If clients lose Wi-Fi now and then, try channels 36-48."
    assert f.fix_id == "wifi.dfs.fixSupported" and f.params["channels"] == "36-48"
    only_dfs = radio("ap1", channel=100, supported_channels=[100, 104])
    (g,) = run(dfs, ap("ap1", radios=[only_dfs]))
    assert g.fix_id == "wifi.dfs.fixNone" and "channels" not in g.params
    (h,) = run(dfs, ap("ap1", radios=[radio("ap1", channel=100)]))
    assert h.fix_id == "wifi.dfs.fix" and "channels" not in h.params


def test_channel_plan_suggests_supported_channels() -> None:
    r = radio("ap1", "r0", Band.GHZ_2_4, channel=3, country="US", supported_channels=[1, 2, 3, 6])
    (f,) = run(channel_plan_24, ap("ap1", radios=[r]))
    assert (f.fix, f.fix_id, f.params["channels"]) == (
        "Use channel 1, 6.",
        "wifi.channelPlan.fixSupported",
        "1, 6",
    )
    full = radio("ap1", "r0", Band.GHZ_2_4, channel=3, supported_channels=list(range(1, 14)))
    (g,) = run(channel_plan_24, ap("ap1", radios=[full]))
    assert g.fix_id == "wifi.channelPlan.fixEu" and "channels" not in g.params
    none = radio("ap1", "r0", Band.GHZ_2_4, channel=3, supported_channels=[2, 3, 4])
    assert run(channel_plan_24, ap("ap1", radios=[none])) == []


def test_channel_plan_skips_automatic_channel() -> None:
    r = radio("ap1", "r0", Band.GHZ_2_4, channel=3, channel_auto=True)
    assert run(channel_plan_24, ap("ap1", radios=[r])) == []


def test_channel_width_suggests_supported_width() -> None:
    a = radio("ap1", channel=36, width_mhz=160, supported_widths_mhz=[20, 40, 160])
    b = ap("ap2", radios=[radio("ap2", channel=100, width_mhz=80)])
    (f,) = run(channel_width, ap("ap1", radios=[a]), b)
    assert f.fix_id == "wifi.widthWide.fixWidth" and f.params["narrower"] == 40
    assert f.fix == "Use 40 MHz so that the access points can use channels that do not overlap."
    usual = radio("ap1", channel=36, width_mhz=160, supported_widths_mhz=[20, 40, 80, 160])
    (g,) = run(channel_width, ap("ap1", radios=[usual]), b)
    assert g.fix_id == "wifi.widthWide.fix5" and "narrower" not in g.params
    only_wide = radio("ap1", channel=36, width_mhz=160, supported_widths_mhz=[160])
    assert run(channel_width, ap("ap1", radios=[only_wide]), b) == []


def test_overlap_uses_reported_centre_channel() -> None:
    # 40 MHz on 40 with the centre 38: occupies 36+40 (as the aligned block does) ...
    a = radio("ap1", channel=40, width_mhz=40, center_channel=38)
    b = radio("ap2", channel=36, width_mhz=20)
    assert len(run(channel_overlap, ap("ap1", radios=[a]), ap("ap2", radios=[b]))) == 1
    # ... an 80 MHz centre 58 on channel 52 occupies 52-64, not 36-48
    c = radio("ap1", channel=52, width_mhz=80, center_channel=58)
    d = radio("ap2", channel=48, width_mhz=20)
    assert run(channel_overlap, ap("ap1", radios=[c]), ap("ap2", radios=[d])) == []
    # a centre that does not fit the channel is ignored: the aligned block counts
    e = radio("ap1", channel=36, width_mhz=80, center_channel=58)
    assert len(run(channel_overlap, ap("ap1", radios=[e]), ap("ap2", radios=[d]))) == 1


def test_channel_helpers() -> None:
    assert channel_ranges([149, 36, 40, 44, 48, 153, 165], Band.GHZ_5) == "36-48, 149-153, 165"
    assert channel_ranges([1, 2, 3, 6], Band.GHZ_2_4) == "1-3, 6"
    assert quiet_channels(radio("ap1")) is None
    assert quiet_channels(radio("ap1", supported_channels=EU_5)) == [36, 40, 44, 48]


def test_contract_radio_capability_problems() -> None:
    from signalbox.testing import radio_problems

    good = radio(
        "ap1",
        width_mhz=80,
        standard=WifiStandard.AX,
        standards=[WifiStandard.AC, WifiStandard.AX],
        supported_widths_mhz=[20, 40, 80],
        channel_utilisation_pct=40,
        interference_pct=10,
        dfs_state=DfsState.AVAILABLE,
    )
    assert radio_problems(good) == []
    bad = [
        radio("ap1", "a", standards=[]),
        radio("ap1", "b", supported_channels=[36, 36]),
        radio("ap1", "c", standard=WifiStandard.BE, standards=[WifiStandard.AX]),
        radio("ap1", "d", width_mhz=160, supported_widths_mhz=[20, 40, 80]),
        radio("ap1", "e", channel_utilisation_pct=10, interference_pct=20),
        radio("ap1", "f", Band.GHZ_2_4, dfs_state=DfsState.CAC),
    ]
    found = [p for r in bad for p in radio_problems(r)]
    assert len(found) == len(bad)
    for needle in [
        "standards empty",
        "supported_channels empty or with duplicates",
        "standard be is not in its standards",
        "width 160 MHz is not a supported width",
        "interference_pct above",
        "dfs_state outside 5 GHz",
    ]:
        assert any(needle in p for p in found), needle
