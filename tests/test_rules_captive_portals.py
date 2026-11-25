"""Captive portal rules (#460): passing, failing and silent cases."""

from datetime import UTC, datetime
from typing import Any

from factories import SITE, device
from signalbox.model import (
    CaptivePortal,
    Network,
    PortalAuth,
    PurposeSource,
    Security,
    Segment,
    SegmentPurpose,
    Snapshot,
    Wlan,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.captive_portals import (
    RULES,
    click_through_open,
    guest_unprotected,
    non_guest_network,
)
from signalbox.testing import portal_problems

SITE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
LAN = segment_id(SITE.id, None)
GUEST = segment_id(SITE.id, 30)
IOT = segment_id(SITE.id, 20)


def seg(sid: str, vlan: int | None, purpose: SegmentPurpose | None, **kw: Any) -> Segment:
    return Segment(
        id=sid,
        site_id=SITE.id,
        vlan=vlan,
        name=kw.pop("name", None),
        purpose=purpose,
        purpose_source=kw.pop("source", PurposeSource.DECLARED) if purpose else None,
        **kw,
    )


def wlan(dev: str, ssid: str, segment: str | None, **kw: Any) -> Wlan:
    return Wlan(
        id=f"{dev}/wlan/{ssid}-0",
        device_id=dev,
        ssid=ssid,
        radio_id=f"{dev}/radio/0",
        security=Security.WPA2,
        segment_id=segment,
        **kw,
    )


def guest_wlan(dev: str = "ap", segment: str | None = GUEST, **kw: Any) -> Wlan:
    kw.setdefault("purpose", SegmentPurpose.GUEST)
    kw.setdefault("purpose_source", PurposeSource.DECLARED)
    return wlan(dev, kw.pop("ssid", "Visitors"), segment, **kw)


def portal(name: str = "gp", device_id: str = "gw", **kw: Any) -> CaptivePortal:
    return CaptivePortal(id=f"{device_id}/portal/{name}", device_id=device_id, name=name, **kw)


def net(**kw: Any) -> Network:
    kw.setdefault("sites", [SITE])
    kw.setdefault("devices", [device("gw"), device("ap")])
    kw.setdefault(
        "segments",
        [
            seg(LAN, None, SegmentPurpose.MAIN, name="LAN"),
            seg(IOT, 20, SegmentPurpose.IOT, name="Things"),
            seg(GUEST, 30, SegmentPurpose.GUEST, name="Visitors"),
        ],
    )
    return Network(**kw)


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def test_rules_are_registered() -> None:
    ids = {r.id for r in BUILTIN}
    assert {r.id for r in RULES} == {
        "portal.guest-unprotected",
        "portal.non-guest-network",
        "portal.click-through-open",
    }
    assert {r.id for r in RULES} <= ids


# --- portal.guest-unprotected ------------------------------------------------------------------


def test_guest_ssid_without_portal_or_isolation() -> None:
    (f,) = run(guest_unprotected, net(wlans=[guest_wlan(client_isolation=False)]))
    assert "'Visitors'" in f.message and "no captive portal" in f.message
    assert f.severity.value == "info"


def test_guest_ssid_with_isolation_is_fine() -> None:
    assert not run(guest_unprotected, net(wlans=[guest_wlan(client_isolation=True)]))


def test_guest_ssid_with_unknown_isolation_is_not_judged() -> None:
    assert not run(guest_unprotected, net(wlans=[guest_wlan()]))


def test_guest_ssid_on_an_isolated_network_is_fine() -> None:
    segs = [seg(GUEST, 30, SegmentPurpose.GUEST, isolated=True)]
    assert not run(
        guest_unprotected, net(segments=segs, wlans=[guest_wlan(client_isolation=False)])
    )


def test_guest_ssid_with_a_portal_by_ssid_or_network_is_fine() -> None:
    w = guest_wlan(client_isolation=False)
    assert not run(guest_unprotected, net(wlans=[w], portals=[portal(wlans=[w.id])]))
    assert not run(guest_unprotected, net(wlans=[w], portals=[portal(segments=[GUEST])]))


def test_disabled_portal_does_not_count() -> None:
    w = guest_wlan(client_isolation=False)
    n = net(wlans=[w], portals=[portal(wlans=[w.id], enabled=False)])
    assert len(run(guest_unprotected, n)) == 1


def test_guest_network_reported_by_the_device_is_left_alone() -> None:
    w = guest_wlan(
        client_isolation=False, purpose=SegmentPurpose.GUEST, purpose_source=PurposeSource.REPORTED
    )
    assert not run(guest_unprotected, net(wlans=[w]))


def test_wired_guest_network_without_portal() -> None:
    (f,) = run(guest_unprotected, net())
    assert "Visitors (VLAN 30)" in f.message
    assert not run(guest_unprotected, net(portals=[portal(segments=[GUEST])]))
    isolated = [seg(GUEST, 30, SegmentPurpose.GUEST, isolated=True)]
    assert not run(guest_unprotected, net(segments=isolated))


def test_guest_network_with_an_ssid_is_reported_once_through_the_ssid() -> None:
    n = net(wlans=[guest_wlan(client_isolation=False)])
    assert [f.message for f in run(guest_unprotected, n)] == [
        "The guest Wi-Fi 'Visitors' on ap has no captive portal and no client isolation"
    ]


# --- portal.non-guest-network ------------------------------------------------------------------


def test_portal_on_a_non_guest_network() -> None:
    (f,) = run(non_guest_network, net(portals=[portal(segments=[IOT])]))
    assert "Things (VLAN 20) (iot)" in f.message and f.severity.value == "warning"


def test_portal_on_a_non_guest_ssid() -> None:
    w = wlan("ap", "Home", LAN, purpose=SegmentPurpose.MAIN, purpose_source=PurposeSource.DECLARED)
    (f,) = run(non_guest_network, net(wlans=[w], portals=[portal(wlans=[w.id])]))
    assert "SSID 'Home' (main)" in f.message


def test_portal_on_the_guest_network_is_fine() -> None:
    w = guest_wlan()
    assert not run(non_guest_network, net(wlans=[w], portals=[portal(segments=[GUEST])]))
    assert not run(non_guest_network, net(wlans=[w], portals=[portal(wlans=[w.id])]))


def test_portal_on_an_unknown_or_other_purpose_is_not_judged() -> None:
    segs = [seg(LAN, None, None), seg(IOT, 20, SegmentPurpose.OTHER)]
    assert not run(non_guest_network, net(segments=segs, portals=[portal(segments=[LAN, IOT])]))


def test_disabled_portal_on_a_non_guest_network_is_quiet() -> None:
    assert not run(non_guest_network, net(portals=[portal(segments=[IOT], enabled=False)]))


# --- portal.click-through-open -----------------------------------------------------------------


def test_click_through_without_isolation() -> None:
    w = guest_wlan(client_isolation=False)
    (f,) = run(
        click_through_open,
        net(wlans=[w], portals=[portal(wlans=[w.id], auth=PortalAuth.CLICK_THROUGH)]),
    )
    assert "SSID 'Visitors'" in f.message and f.severity.value == "warning"


def test_click_through_on_a_network_that_is_not_isolated() -> None:
    segs = [seg(GUEST, 30, SegmentPurpose.GUEST, isolated=False, name="Visitors")]
    n = net(segments=segs, portals=[portal(segments=[GUEST], auth=PortalAuth.CLICK_THROUGH)])
    (f,) = run(click_through_open, n)
    assert "Visitors (VLAN 30)" in f.message


def test_click_through_stays_quiet_when_isolated_unknown_or_another_login() -> None:
    w = guest_wlan(client_isolation=True)
    click = portal(wlans=[w.id], auth=PortalAuth.CLICK_THROUGH)
    assert not run(click_through_open, net(wlans=[w], portals=[click]))
    unknown = guest_wlan()
    assert not run(
        click_through_open,
        net(wlans=[unknown], portals=[portal(wlans=[unknown.id], auth=PortalAuth.CLICK_THROUGH)]),
    )
    open_wlan = guest_wlan(client_isolation=False)
    for auth in (PortalAuth.VOUCHER, PortalAuth.PASSWORD, PortalAuth.RADIUS, None):
        assert not run(
            click_through_open,
            net(wlans=[open_wlan], portals=[portal(wlans=[open_wlan.id], auth=auth)]),
        )
    off = portal(wlans=[open_wlan.id], auth=PortalAuth.CLICK_THROUGH, enabled=False)
    assert not run(click_through_open, net(wlans=[open_wlan], portals=[off]))


def test_click_through_on_an_isolated_network_is_fine() -> None:
    segs = [seg(GUEST, 30, SegmentPurpose.GUEST, isolated=True)]
    w = guest_wlan(client_isolation=False)
    click = portal(wlans=[w.id], auth=PortalAuth.CLICK_THROUGH)
    assert not run(click_through_open, net(segments=segs, wlans=[w], portals=[click]))


# --- model and contract helpers ----------------------------------------------------------------


def test_portal_lookups() -> None:
    w = guest_wlan()
    p = portal(segments=[GUEST])
    n = net(wlans=[w], portals=[p, portal("off", segments=[GUEST], enabled=False)])
    assert n.portals_on(GUEST) == [p]
    assert n.portals_for(w) == [p]
    assert n.portals_of("gw") == sorted(n.portals, key=lambda x: x.id)
    assert n.knows(p.id)


def test_portal_problems() -> None:
    dev = device("gw")
    good = portal(segments=[GUEST])
    snap = Snapshot(
        device=dev,
        observed_at=SITE_TIME,
        segments=[seg(GUEST, 30, None)],
        portals=[good],
    )
    assert portal_problems(snap) == []
    bad = Snapshot(
        device=dev,
        observed_at=SITE_TIME,
        portals=[
            portal(segments=["nowhere"], wlans=["gw/wlan/none"]),
            CaptivePortal(id="gw/other/x", device_id="gw", name="x"),
        ],
    )
    problems = portal_problems(bad)
    assert any("unknown segment" in p for p in problems)
    assert any("unknown wlan" in p for p in problems)
    assert any("is not gw/portal/" in p for p in problems)
