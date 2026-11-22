"""Wi-Fi hygiene rules (#87, #88, #91, #92, #93, #94, #95, #97, #98, #100, #103)."""

from typing import Any

import pytest

from factories import SITE
from signalbox.merge import merge
from signalbox.model import (
    Band,
    Link,
    LinkKind,
    LinkOrigin,
    Pmf,
    Security,
    Site,
    Snapshot,
    passphrase_fingerprint,
    segment_id,
)
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.wifi_hygiene import (
    channel_plan_24,
    channel_width,
    default_ssid,
    dfs,
    hidden,
    pmf,
    segment_weakest_link,
    six_ghz_security,
    ssid_count,
    ssid_coverage,
    tx_power,
)
from test_rules_wireless import ap, radio, wlan

LAN = segment_id(SITE.id, 10)
GUEST = segment_id(SITE.id, 30)
OTHER_FP = passphrase_fingerprint("Example", "another passphrase")


def run(r: Rule, *snaps: Snapshot, links: list[Link] | None = None) -> list[Finding]:
    net = merge([SITE, Site(id="cabin", name="Cabin")], snaps, links or [])
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def dual(dev: str, ssids: tuple[str, ...] = ("Example",), **kw: Any) -> Snapshot:
    """An access point with a 2.4 and a 5 GHz radio that both broadcast the SSIDs."""
    radios = [
        radio(dev, "radio0", Band.GHZ_2_4, channel=1, width_mhz=20, tx_power_dbm=17),
        radio(dev, "radio1", Band.GHZ_5, channel=36, width_mhz=80, tx_power_dbm=20),
    ]
    wlans = [wlan(dev, s, r) for s in ssids for r in ("radio0", "radio1")]
    return ap(dev, radios=kw.pop("radios", radios), wlans=kw.pop("wlans", wlans), **kw)


# wifi.6ghz-security ---------------------------------------------------------------------------


def wlan6(dev: str, **kw: Any) -> Any:
    return wlan(dev, radio_name="radio2", **kw)


def six(dev: str = "ap1", **kw: Any) -> Snapshot:
    kw.setdefault("pmf", Pmf.REQUIRED)
    return ap(dev, radios=[radio(dev, "radio2", Band.GHZ_6)], wlans=[wlan6(dev, **kw)])


@pytest.mark.parametrize("security", [Security.WPA3, Security.WPA3_ENTERPRISE, Security.OWE])
def test_6ghz_allows_wpa3_and_owe(security: Security) -> None:
    assert run(six_ghz_security, six(security=security)) == []


@pytest.mark.parametrize(
    ("security", "text"),
    [
        (Security.WPA2_WPA3, "WPA2/WPA3"),
        (Security.WPA2, "WPA2"),
        (Security.OPEN, "no password (open)"),
    ],
)
def test_6ghz_rejects_wpa2_transition_and_open(security: Security, text: str) -> None:
    (f,) = run(six_ghz_security, six(security=security))
    assert f.severity is Severity.ERROR
    assert f.message == (
        f"SSID 'Example' on the 6 GHz radio of ap1 uses {text}, which 6 GHz does not allow"
    )
    assert f.fix and "WPA3 only" in f.fix


def test_6ghz_ignores_other_bands_and_disabled_wlans() -> None:
    snap = ap(
        "ap1",
        radios=[radio("ap1"), radio("ap1", "radio2", Band.GHZ_6)],
        wlans=[wlan("ap1", security=Security.WPA2), wlan6("ap1", enabled=False)],
    )
    assert run(six_ghz_security, snap) == []


# wifi.pmf -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("security", "pmf_", "severity"),
    [
        (Security.WPA3, Pmf.DISABLED, Severity.ERROR),
        (Security.WPA3, Pmf.OPTIONAL, Severity.ERROR),
        (Security.OWE, Pmf.OPTIONAL, Severity.ERROR),
        (Security.WPA3_ENTERPRISE, Pmf.DISABLED, Severity.ERROR),
        (Security.WPA2_WPA3, Pmf.DISABLED, Severity.WARNING),
    ],
)
def test_pmf_mismatch(security: Security, pmf_: Pmf, severity: Severity) -> None:
    (f,) = run(pmf, dual("ap1", wlans=[wlan("ap1", security=security, pmf=pmf_)]))
    assert f.severity is severity
    assert f.message.startswith("SSID 'Example' on ap1 uses ")
    assert f"protected management frames (PMF) {pmf_.value}" in f.message


@pytest.mark.parametrize(
    ("security", "pmf_"),
    [
        (Security.WPA3, Pmf.REQUIRED),
        (Security.OWE, Pmf.REQUIRED),
        (Security.WPA2_WPA3, Pmf.OPTIONAL),
        (Security.WPA2_WPA3, Pmf.REQUIRED),
        (Security.WPA2, Pmf.DISABLED),
        (Security.WPA2, None),
        (Security.OPEN, None),
    ],
)
def test_pmf_matches(security: Security, pmf_: Pmf | None) -> None:
    assert run(pmf, dual("ap1", wlans=[wlan("ap1", security=security, pmf=pmf_)])) == []


def test_pmf_unknown_is_incomplete_once_per_ap_and_ssid() -> None:
    wlans = [
        wlan("ap1", radio_name=r, security=Security.WPA3, pmf=None) for r in ("radio0", "radio1")
    ]
    (f,) = run(pmf, dual("ap1", wlans=wlans))
    assert f.incomplete and "did not report" in f.message
    assert f.objects == ["ap1/wlan/Example/radio0", "ap1/wlan/Example/radio1"]


# wifi.hidden ----------------------------------------------------------------------------------


def test_hidden_ssid_is_reported_once_per_site() -> None:
    a = ap("ap1", wlans=[wlan("ap1", hidden=True)])
    b = ap("ap2", wlans=[wlan("ap2", hidden=True)])
    (f,) = run(hidden, a, b)
    assert f.severity is Severity.INFO
    assert f.message == "SSID 'Example' is hidden (on ap1, ap2)"
    assert run(hidden, ap("ap1"), ap("ap2")) == []
    assert run(hidden, ap("ap1", wlans=[wlan("ap1", hidden=True, enabled=False)])) == []


def test_hidden_backhaul_ssid_is_skipped() -> None:
    a = ap("ap1", wlans=[wlan("ap1", "Mesh", hidden=True)])
    b = ap("ap2", wlans=[wlan("ap2", "Mesh", hidden=True)])
    mesh = Link(
        id="m", a="ap1/port/mesh0", b="ap2/port/mesh0", kind=LinkKind.WIRELESS, origin="lldp"
    )
    cable = Link(id="c", a="ap1/port/lan", b="ap2/port/lan", origin=LinkOrigin.MANUAL)
    assert run(hidden, a, b, links=[mesh]) == []
    assert len(run(hidden, a, b, links=[cable])) == 1


# wifi.ssid-count ------------------------------------------------------------------------------


def test_ssid_count() -> None:
    ssids = ("A", "B", "C", "D")
    (f,) = run(ssid_count, dual("ap1", ssids))  # four is fine on 5 GHz, too many on 2.4 GHz
    assert f.severity is Severity.WARNING
    assert f.message == (
        "The 2.4 GHz radio of ap1 broadcasts 4 SSIDs ('A', 'B', 'C', 'D'); more than 3 cost "
        "noticeable airtime"
    )
    assert f.objects[0] == "ap1/radio/radio0"
    found = run(ssid_count, dual("ap1", (*ssids, "E")))
    assert [f.objects[0] for f in found] == ["ap1/radio/radio0", "ap1/radio/radio1"]


def test_ssid_count_stays_quiet() -> None:
    assert run(ssid_count, dual("ap1", ("A", "B", "C"))) == []
    snap = dual("ap1", ("A", "B", "C", "D"))
    radios = [r.model_copy(update={"enabled": False}) for r in snap.radios]
    assert run(ssid_count, snap.model_copy(update={"radios": radios})) == []


# wifi.channel-width ---------------------------------------------------------------------------


def test_24ghz_wider_than_20_mhz() -> None:
    radios = [radio("ap1", band=Band.GHZ_2_4, channel=1, width_mhz=40)]
    (f,) = run(channel_width, ap("ap1", radios=radios))
    assert f.severity is Severity.WARNING
    assert f.message == "The 2.4 GHz radio of ap1 uses 40 MHz"
    assert f.fix == "Use 20 MHz on 2.4 GHz."


@pytest.mark.parametrize(("band", "width"), [(Band.GHZ_5, 160), (Band.GHZ_6, 320)])
def test_wide_channels_with_several_aps(band: Band, width: int) -> None:
    a = ap("ap1", radios=[radio("ap1", band=band, channel=36, width_mhz=width)])
    b = ap("ap2", radios=[radio("ap2", band=band, channel=100, width_mhz=80)])
    (f,) = run(channel_width, a, b)
    assert f.severity is Severity.INFO
    assert f.message == (
        f"The {band.value} GHz radio of ap1 uses {width} MHz at a site with 2 {band.value} GHz "
        "access points"
    )
    # one access point: no neighbours to collide with
    assert run(channel_width, a) == []
    # an access point at another site does not count
    c = ap("ap3", site_id="cabin", radios=[radio("ap3", band=band, channel=36, width_mhz=80)])
    assert run(channel_width, a, c) == []


def test_channel_width_stays_quiet() -> None:
    radios = [
        radio("ap1", "r0", Band.GHZ_2_4, channel=1, width_mhz=20),
        radio("ap1", "r1", Band.GHZ_2_4, channel=6),  # unknown width
        radio("ap1", "r2", Band.GHZ_2_4, channel=11, width_mhz=40, enabled=False),
        radio("ap1", "r3", Band.GHZ_5, channel=36, width_mhz=80),
    ]
    b = ap("ap2", radios=[radio("ap2", channel=100, width_mhz=80)])
    assert run(channel_width, ap("ap1", radios=radios), b) == []


# wifi.24-channel-plan -------------------------------------------------------------------------


def test_24ghz_channel_between_the_standard_ones() -> None:
    (f,) = run(channel_plan_24, ap("ap1", radios=[radio("ap1", band=Band.GHZ_2_4, channel=3)]))
    assert f.severity is Severity.INFO
    assert f.message == "The 2.4 GHz radio of ap1 uses channel 3"
    assert f.fix == "Use channel 1, 6 or 11 (or 1, 5, 9 and 13 on all access points)."
    us = radio("ap1", band=Band.GHZ_2_4, channel=9, country="us")
    (f,) = run(channel_plan_24, ap("ap1", radios=[us]))
    assert f.fix == "Use channel 1, 6 or 11."
    unknown = radio("ap1", band=Band.GHZ_2_4, channel=13, country=None)
    assert len(run(channel_plan_24, ap("ap1", radios=[unknown]))) == 1


@pytest.mark.parametrize(("channel", "country"), [(1, "DE"), (6, "US"), (11, None), (13, "DE")])
def test_24ghz_standard_channels(channel: int, country: str | None) -> None:
    r = radio("ap1", band=Band.GHZ_2_4, channel=channel, country=country)
    assert run(channel_plan_24, ap("ap1", radios=[r])) == []


def test_24ghz_channel_plan_skips_auto_disabled_and_5ghz() -> None:
    radios = [
        radio("ap1", "r0", Band.GHZ_2_4, channel=None),
        radio("ap1", "r1", Band.GHZ_2_4, channel=3, enabled=False),
        radio("ap1", "r2", Band.GHZ_5, channel=40),
    ]
    assert run(channel_plan_24, ap("ap1", radios=radios)) == []


# wifi.dfs -------------------------------------------------------------------------------------


def test_dfs_channel() -> None:
    (f,) = run(dfs, ap("ap1", radios=[radio("ap1", channel=100, width_mhz=80)]))
    assert f.severity is Severity.INFO
    assert f.message == "The 5 GHz radio of ap1 uses channel 100 (DFS)"
    assert f.fix and "36-48 or 149-165" in f.fix


def test_wide_channel_reaching_dfs() -> None:
    (f,) = run(dfs, ap("ap1", radios=[radio("ap1", channel=36, width_mhz=160)]))
    assert f.message == (
        "The 5 GHz radio of ap1 uses channel 36 at 160 MHz, which reaches the DFS channels 52-64"
    )


@pytest.mark.parametrize(
    ("channel", "width", "band"),
    [
        (36, 80, Band.GHZ_5),
        (149, 80, Band.GHZ_5),
        (None, 80, Band.GHZ_5),
        (100, 80, Band.GHZ_6),
        (6, 20, Band.GHZ_2_4),
    ],
)
def test_no_dfs(channel: int | None, width: int, band: Band) -> None:
    r = radio("ap1", band=band, channel=channel, width_mhz=width)
    assert run(dfs, ap("ap1", radios=[r])) == []
    off = radio("ap1", channel=100, enabled=False)
    assert run(dfs, ap("ap1", radios=[off])) == []


# wifi.tx-power --------------------------------------------------------------------------------


def power(dev: str, p24: int | None, p5: int | None, **kw: Any) -> Snapshot:
    radios = [
        radio(dev, "radio0", Band.GHZ_2_4, channel=1, tx_power_dbm=p24),
        radio(dev, "radio1", Band.GHZ_5, channel=36, tx_power_dbm=p5),
    ]
    return dual(dev, radios=radios, **kw)


def test_24ghz_louder_than_5ghz() -> None:
    (f,) = run(tx_power, power("ap1", 20, 14))
    assert f.severity is Severity.INFO
    assert f.message == "The 2.4 GHz radio of ap1 sends at 20 dBm, its 5 GHz radio at 14 dBm"
    assert f.objects == ["ap1/radio/radio0", "ap1/radio/radio1"]


def test_access_points_differ_in_power() -> None:
    (f,) = run(tx_power, power("ap1", 14, 23), power("ap2", 14, 16))
    assert f.message == "On 5 GHz at site home, ap1 sends at 23 dBm and ap2 at 16 dBm"
    assert f.objects == ["ap1/radio/radio1", "ap2/radio/radio1"]


def test_tx_power_stays_quiet() -> None:
    assert run(tx_power, power("ap1", 17, 14), power("ap2", 14, 20)) == []  # 3 dB, 6 dB
    assert run(tx_power, power("ap1", None, 14), power("ap2", 20, None)) == []
    # different SSIDs on the two bands: not the same network
    wlans = [wlan("ap1", "A", "radio0"), wlan("ap1", "B", "radio1")]
    assert run(tx_power, power("ap1", 20, 10, wlans=wlans)) == []
    # access points at different sites are not compared
    assert run(tx_power, power("ap1", 14, 23), power("ap2", 12, 10, site_id="cabin")) == []


# wifi.ssid-coverage ---------------------------------------------------------------------------


def test_ssid_missing_on_an_access_point() -> None:
    findings = run(
        ssid_coverage,
        dual("ap1", ("Example", "Guest")),
        dual("ap2", ("Example", "Guest")),
        dual("ap3"),
    )
    (f,) = findings
    assert f.severity is Severity.INFO
    assert f.message == "SSID 'Guest' is broadcast by ap1, ap2 but not by ap3"
    assert f.fix and f.fix.startswith("Add 'Guest' to ap3")


def test_ssid_only_on_24ghz_at_one_access_point() -> None:
    b = dual("ap2", wlans=[wlan("ap2", "Example", "radio0")])
    (f,) = run(ssid_coverage, dual("ap1"), b)
    assert f.message == (
        "SSID 'Example' is on 5 GHz at ap1 but not at ap2, although they have a 5 GHz radio"
    )


def test_ssid_coverage_stays_quiet() -> None:
    # one access point at the site
    assert run(ssid_coverage, dual("ap1", ("Example", "Guest"))) == []
    # the same SSIDs everywhere; another site is compared on its own
    assert (
        run(ssid_coverage, dual("ap1"), dual("ap2"), dual("ap3", ("Cabin",), site_id="cabin")) == []
    )
    # a 2.4 GHz-only access point cannot offer a 5 GHz SSID
    small = ap(
        "ap2",
        radios=[radio("ap2", "radio0", Band.GHZ_2_4)],
        wlans=[wlan("ap2", "Example", "radio0")],
    )
    five = dual("ap1", wlans=[wlan("ap1", "Example", "radio0"), wlan("ap1", "Fast", "radio1")])
    assert run(ssid_coverage, five, small) == []


# wifi.segment-weakest-link --------------------------------------------------------------------


def test_open_ssid_in_the_private_network() -> None:
    wlans = [wlan("ap1"), wlan("ap1", "Guest", security=Security.OPEN, pmf=None)]
    (f,) = run(segment_weakest_link, ap("ap1", wlans=wlans))
    assert f.severity is Severity.ERROR
    assert f.message == (
        "'Guest' (no password (open)) and 'Example' (WPA2/WPA3) both put clients into "
        "home/segment/10"
    )
    assert f.fix == "Move 'Guest' to its own network (VLAN), for example a guest network."


def test_different_passwords_on_one_network() -> None:
    wlans = [
        wlan("ap1"),
        wlan("ap1", "IoT", security=Security.WPA2, passphrase_fingerprint=OTHER_FP),
    ]
    (f,) = run(segment_weakest_link, ap("ap1", wlans=wlans))
    assert f.severity is Severity.INFO
    assert "SSIDs 'Example', 'IoT' use different passwords" in f.message


def test_segment_weakest_link_stays_quiet() -> None:
    same = [wlan("ap1"), wlan("ap1", "IoT", security=Security.WPA2)]  # same password
    assert run(segment_weakest_link, ap("ap1", wlans=same)) == []
    apart = [wlan("ap1"), wlan("ap1", "Guest", security=Security.OPEN, segment_id=GUEST)]
    assert run(segment_weakest_link, ap("ap1", wlans=apart)) == []
    only_open = [
        wlan("ap1", "Guest", security=Security.OPEN),
        wlan("ap1", "Cafe", security=Security.OWE),
    ]
    assert run(segment_weakest_link, ap("ap1", wlans=only_open)) == []
    # an SSID with two passwords is wifi.ssid-consistent's finding
    two = [wlan("ap1"), wlan("ap2", passphrase_fingerprint=OTHER_FP)]
    assert run(segment_weakest_link, ap("ap1", wlans=two[:1]), ap("ap2", wlans=two[1:])) == []
    unknown_fp = [wlan("ap1"), wlan("ap1", "IoT", passphrase_fingerprint=None)]
    assert run(segment_weakest_link, ap("ap1", wlans=unknown_fp)) == []


def test_unprotected_ssid_without_network_is_incomplete() -> None:
    wlans = [wlan("ap1"), wlan("ap1", "Guest", security=Security.OPEN, segment_id=None)]
    (f,) = run(segment_weakest_link, ap("ap1", wlans=wlans))
    assert f.incomplete and "'Guest'" in f.message
    # nothing protected at the site: nothing to leak into
    alone = [wlan("ap1", "Guest", security=Security.OPEN, segment_id=None)]
    assert run(segment_weakest_link, ap("ap1", wlans=alone)) == []


# wifi.default-ssid ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ssid",
    [
        "OpenWrt",
        "MikroTik-1A2B3C",
        "FRITZ!Box 7590 XY",
        "TP-Link_A1B2",
        "TP-Link_A1B2_5G",
        "NETGEAR42",
        "Omada_1A2B3C",
    ],
)
def test_factory_ssid(ssid: str) -> None:
    (f,) = run(default_ssid, ap("ap1", wlans=[wlan("ap1", ssid)]))
    assert f.severity is Severity.WARNING
    assert f.message == f"ap1 broadcasts the factory SSID {ssid!r}"


def test_open_factory_ssid_is_an_error() -> None:
    (f,) = run(default_ssid, ap("ap1", wlans=[wlan("ap1", "OpenWrt", security=Security.OPEN)]))
    assert f.severity is Severity.ERROR
    assert f.message == "ap1 broadcasts the factory SSID 'OpenWrt' without a password (open)"


@pytest.mark.parametrize("ssid", ["Example", "OpenWrt Lab", "My FRITZ", "NETGEAR-home"])
def test_own_ssid(ssid: str) -> None:
    assert run(default_ssid, ap("ap1", wlans=[wlan("ap1", ssid)])) == []
    assert run(default_ssid, ap("ap1", wlans=[wlan("ap1", "OpenWrt", enabled=False)])) == []
