from typing import Any

import pytest

from factories import SITE, device, iface, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Band,
    DeviceRole,
    Network,
    Pmf,
    Radio,
    Security,
    Segment,
    Site,
    Snapshot,
    Subnet,
    Wlan,
    passphrase_fingerprint,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.wireless import channel_overlap, country, segment_at_gateway, ssid_consistent

LAN = segment_id(SITE.id, 10)
GUEST = segment_id(SITE.id, 30)
FP = passphrase_fingerprint("Example", "correct horse battery staple")


def radio(dev: str, name: str = "radio0", band: Band = Band.GHZ_5, **kw: Any) -> Radio:
    kw.setdefault("country", "DE")
    return Radio(id=f"{dev}/radio/{name}", device_id=dev, name=name, band=band, **kw)


def wlan(dev: str, ssid: str = "Example", radio_name: str = "radio0", **kw: Any) -> Wlan:
    kw.setdefault("security", Security.WPA2_WPA3)
    kw.setdefault("pmf", Pmf.OPTIONAL)
    kw.setdefault("passphrase_fingerprint", FP)
    kw.setdefault("segment_id", LAN)
    kw.setdefault("roaming_80211r", True)
    kw.setdefault("roaming_80211k", True)
    kw.setdefault("roaming_80211v", True)
    return Wlan(
        id=f"{dev}/wlan/{ssid}/{radio_name}",
        device_id=dev,
        ssid=ssid,
        radio_id=f"{dev}/radio/{radio_name}",
        **kw,
    )


def ap(
    dev: str, radios: list[Radio] | None = None, wlans: list[Wlan] | None = None, **kw: Any
) -> Snapshot:
    return snapshot(
        device(dev, DeviceRole.AP, site_id=kw.pop("site_id", SITE.id)),
        radios=[radio(dev)] if radios is None else radios,
        wlans=[wlan(dev)] if wlans is None else wlans,
        **kw,
    )


def gateway(*segs: str) -> Snapshot:
    subnets = [
        Subnet(
            id=f"gw/subnet/{s}",
            segment_id=s,
            interface=iface(f"192.0.2.{i + 1}/28"),
            device_id="gw",
            gateway=True,
        )
        for i, s in enumerate(segs)
    ]
    segments = [Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN")]
    return snapshot(device("gw"), subnets=subnets, segments=segments)


def run(r: Rule, *snaps: Snapshot, sites: list[Site] | None = None) -> list[Finding]:
    net = merge(sites or [SITE], snaps)
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def test_identical_ssid_passes() -> None:
    # Unknown values (None) and disabled WLANs are not compared.
    a = ap("ap1", wlans=[wlan("ap1"), wlan("ap1", "Off", enabled=False, security=Security.OPEN)])
    b = ap("ap2", wlans=[wlan("ap2", pmf=None), wlan("ap2", "Off", security=Security.WPA2)])
    assert run(ssid_consistent, a, b) == []


@pytest.mark.parametrize(
    ("change", "severity", "text"),
    [
        (
            {"security": Security.WPA2},
            "error",
            "security mode differs (ap1: wpa2-wpa3; ap2: wpa2-psk)",
        ),
        ({"pmf": Pmf.DISABLED}, "warning", "protected management frames (PMF) differs"),
        (
            {"segment_id": GUEST},
            "error",
            f"network (VLAN) differs (ap1: LAN (VLAN 10); ap2: {GUEST})",
        ),
        ({"hidden": True}, "warning", "hidden setting differs (ap1: off; ap2: on)"),
        ({"roaming_80211r": False}, "warning", "fast roaming (802.11r) differs"),
        ({"roaming_80211k": False, "roaming_80211v": False}, "warning", "(802.11k) differs"),
    ],
)
def test_ssid_attribute_differs(change: dict[str, Any], severity: str, text: str) -> None:
    findings = run(
        ssid_consistent, gateway(LAN), ap("ap1"), ap("ap2", wlans=[wlan("ap2", **change)])
    )
    assert len(findings) == len(change)
    f = next(f for f in findings if text in f.message)
    assert f.severity == severity
    assert f.message.startswith("SSID 'Example' at site home: ")
    assert f.objects == ["ap1/wlan/Example/radio0", "ap2/wlan/Example/radio0"]


def test_passphrase_differs_without_showing_it() -> None:
    other = passphrase_fingerprint("Example", "something else")
    b = ap("ap2", wlans=[wlan("ap2", passphrase_fingerprint=other)])
    c = ap("ap3", wlans=[wlan("ap3", passphrase_fingerprint=other)])
    (f,) = run(ssid_consistent, ap("ap1"), b, c)
    assert f.message == "SSID 'Example' at site home: passphrase differs (ap1 / ap2, ap3)"
    assert f.severity == "error"
    assert FP not in f.message + (f.fix or "") and other not in f.message + (f.fix or "")


def test_same_ssid_at_other_site_is_compared_separately() -> None:
    cabin = Site(id="cabin", name="Cabin")
    remote = ap("ap2", site_id="cabin", wlans=[wlan("ap2", segment_id=segment_id("cabin", 10))])
    assert run(ssid_consistent, ap("ap1"), remote, sites=[SITE, cabin]) == []


def test_country_code() -> None:
    assert run(country, ap("ap1"), ap("ap2", radios=[radio("ap2", country="de")])) == []
    missing = ap(
        "ap2", radios=[radio("ap2", country=None), radio("ap2", "off", enabled=False, country=None)]
    )
    (f,) = run(country, ap("ap1"), missing)
    assert f.message == "ap2 radio0 (5 GHz) has no country code set (or did not report it)"
    assert f.severity == "warning" and f.objects == ["ap2/radio/radio0"]
    other = ap("ap2", radios=[radio("ap2", country="FR")])
    (g,) = run(country, ap("ap1"), other)
    assert g.message == "Radios at site home use different country codes (DE: ap1; FR: ap2)"
    cabin = Site(id="cabin", name="Cabin")
    assert (
        run(
            country,
            ap("ap1"),
            ap("ap2", site_id="cabin", radios=[radio("ap2", country="FR")]),
            sites=[SITE, cabin],
        )
        == []
    )


@pytest.mark.parametrize(
    ("band", "a", "b", "overlap"),
    [
        (Band.GHZ_2_4, (1, 20), (6, 20), False),
        (Band.GHZ_2_4, (1, 20), (11, 40), False),
        (Band.GHZ_2_4, (1, 20), (4, 20), True),
        (Band.GHZ_2_4, (6, 20), (6, 20), True),
        (Band.GHZ_5, (36, 20), (40, 20), False),
        (Band.GHZ_5, (36, 80), (48, 20), True),
        (Band.GHZ_5, (36, 80), (52, 80), False),
        (Band.GHZ_5, (36, 160), (64, None), True),
        (Band.GHZ_5, (100, 80), (112, 40), True),
        (Band.GHZ_5, (149, 80), (161, 20), True),
        (Band.GHZ_5, (149, 80), (165, 20), False),
        (Band.GHZ_5, (144, 20), (149, 20), False),
        (Band.GHZ_6, (1, 160), (29, 20), True),
        (Band.GHZ_6, (1, 160), (33, 20), False),
        (Band.GHZ_6, (37, 40), (37, 0), True),
    ],
)
def test_channel_overlap(
    band: Band, a: tuple[int, int | None], b: tuple[int, int | None], overlap: bool
) -> None:
    ra = radio("ap1", band=band, channel=a[0], width_mhz=a[1])
    rb = radio("ap2", band=band, channel=b[0], width_mhz=b[1])
    findings = run(channel_overlap, ap("ap1", radios=[ra]), ap("ap2", radios=[rb]))
    assert bool(findings) is overlap
    if findings:
        (f,) = findings
        assert f.severity == "warning" and f.objects == [ra.id, rb.id]
        assert f"channel {a[0]} overlaps" in f.message
        assert ("1, 6 or 11" in (f.fix or "")) is (band is Band.GHZ_2_4)


def test_channel_overlap_ignores_same_device_other_band_and_other_site() -> None:
    cabin = Site(id="cabin", name="Cabin")
    one = ap("ap1", radios=[radio("ap1", "r0", channel=36), radio("ap1", "r1", channel=36)])
    other_band = ap(
        "ap2", radios=[radio("ap2", band=Band.GHZ_6, channel=37), radio("ap2", "r1", channel=None)]
    )
    far = ap("ap3", site_id="cabin", radios=[radio("ap3", channel=36)])
    off = ap("ap4", radios=[radio("ap4", channel=36, enabled=False)])
    assert run(channel_overlap, one, other_band, far, off, sites=[SITE, cabin]) == []


def test_ssid_segment_at_gateway() -> None:
    open_wlan = wlan("ap1", "Untagged", segment_id=None)
    off = wlan("ap1", "Off", segment_id=GUEST, enabled=False)
    assert (
        run(segment_at_gateway, gateway(LAN), ap("ap1", wlans=[wlan("ap1"), open_wlan, off])) == []
    )
    guest = ap("ap2", wlans=[wlan("ap2", "Guests", segment_id=GUEST)])
    (f,) = run(segment_at_gateway, gateway(LAN), guest)
    assert f.severity == "error"
    assert f.message == f"SSID 'Guests' on ap2 uses {GUEST}, which has no subnet on the router"
    assert f.objects == ["ap2/wlan/Guests/radio0", GUEST]


def test_ssid_segment_without_any_router_is_incomplete() -> None:
    guest = ap("ap2", wlans=[wlan("ap2", "Guests", segment_id=GUEST), wlan("ap2", "Example", "r1")])
    (f,) = run(segment_at_gateway, guest)
    assert f.incomplete and f.objects == ["home"]
    assert "'Example', 'Guests'" in f.message


def test_router_without_gateway_flag_still_counts_as_router() -> None:
    def lan(dev: str) -> list[Subnet]:
        return [
            Subnet(id=f"{dev}/s", segment_id=LAN, interface=iface("192.0.2.1/24"), device_id=dev)
        ]

    gw = snapshot(device("gw"), subnets=lan("gw"))
    assert run(segment_at_gateway, gw, ap("ap1")) == []
    # A switch with an address on the network is not a router.
    sw = snapshot(device("sw", DeviceRole.SWITCH), subnets=lan("sw"))
    (f,) = run(segment_at_gateway, sw, ap("ap1"))
    assert f.incomplete


def test_empty_network_is_clean() -> None:
    assert (
        evaluate(Network(), [ssid_consistent, country, channel_overlap, segment_at_gateway]) == []
    )
