"""Rules about network purposes (#164, #99, #120 level 1)."""

from typing import Any

from factories import SITE, device, iface
from signalbox.model import (
    Band,
    DeviceRole,
    Network,
    PurposeSource,
    Radio,
    Security,
    Segment,
    SegmentPurpose,
    Subnet,
    Wlan,
    segment_id,
)
from signalbox.purpose import with_heuristics
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.builtin import RULES
from signalbox.rules.networks import (
    guest_isolation,
    guest_no_isolation,
    iot_5ghz_only,
    management_exposure,
    purpose_missing,
)
from signalbox.rules.wireless import segment_at_gateway, ssid_consistent

LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)
MGMT = segment_id(SITE.id, 99)
DECLARED = PurposeSource.DECLARED


def seg(sid: str, vlan: int | None, name: str | None = None, **kw: Any) -> Segment:
    return Segment(id=sid, site_id=SITE.id, vlan=vlan, name=name, **kw)


def purposed(s: Segment, p: SegmentPurpose, source: PurposeSource = DECLARED) -> Segment:
    return s.model_copy(update={"purpose": p, "purpose_source": source})


def wlan(dev: str, ssid: str, segment: str | None, radio: str = "0", **kw: Any) -> Wlan:
    return Wlan(
        id=f"{dev}/wlan/{ssid}-{radio}",
        device_id=dev,
        ssid=ssid,
        radio_id=f"{dev}/radio/{radio}",
        security=kw.pop("security", Security.WPA2),
        segment_id=segment,
        **kw,
    )


def guest_wlan(dev: str, segment: str | None, **kw: Any) -> Wlan:
    kw.setdefault("purpose", SegmentPurpose.GUEST)
    kw.setdefault("purpose_source", DECLARED)
    return wlan(dev, kw.pop("ssid", "Visitors"), segment, **kw)


def subnet(dev: str, sid: str, cidr: str, gateway: bool = True) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{sid}",
        segment_id=sid,
        interface=iface(cidr),
        device_id=dev,
        gateway=gateway,
    )


SEGS = [seg(LAN, None, "LAN"), seg(IOT, 20, "Things"), seg(GUEST, 30, "Visitors")]


def net(**kw: Any) -> Network:
    kw.setdefault("sites", [SITE])
    kw.setdefault(
        "devices", [device("gw"), device("ap", DeviceRole.AP), device("ap2", DeviceRole.AP)]
    )
    kw.setdefault("segments", SEGS)
    return Network(**kw)


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def test_rules_are_registered() -> None:
    ids = {r.id for r in RULES}
    assert {
        "wifi.guest-isolation",
        "segment.guest-no-isolation",
        "security.management-exposure",
        "segment.purpose-missing",
        "segment.iot-on-5ghz-only",
    } <= ids


# --- wifi.guest-isolation (#99) ----------------------------------------------------------------


def test_guest_wifi_next_to_main_ssid() -> None:
    wl = [guest_wlan("ap", IOT), guest_wlan("ap2", IOT), wlan("ap", "Home", IOT)]
    (f,) = run(guest_isolation, net(wlans=wl))
    assert f.severity == "error"
    assert f.message == (
        "The guest Wi-Fi 'Visitors' on ap and ap2 is in Things (VLAN 20), "
        "the same network as 'Home'"
    )
    assert f.objects == ["ap/wlan/Visitors-0", "ap2/wlan/Visitors-0", IOT]
    assert "separate guest VLAN" in (f.fix or "")


def test_guest_wifi_in_main_or_purposed_network() -> None:
    (f,) = run(guest_isolation, net(wlans=[guest_wlan("ap", LAN)]))
    assert f.message.endswith("is in LAN (untagged network), the untagged main network")
    segs = [purposed(SEGS[1], SegmentPurpose.IOT)]
    (g,) = run(guest_isolation, net(segments=segs, wlans=[guest_wlan("ap", IOT)]))
    assert g.message.endswith("which is the IoT network Things (VLAN 20)")
    # a segment that is unknown to the model counts as the main network
    (h,) = run(guest_isolation, net(segments=[], wlans=[guest_wlan("ap", IOT)]))
    assert "untagged main network" in h.message


def test_guest_wifi_guessed_from_its_name_is_a_warning() -> None:
    n = with_heuristics(net(wlans=[wlan("ap", "Example-Guest", LAN), wlan("ap", "Home", LAN)]))
    (f,) = run(guest_isolation, n)
    assert f.severity == "warning"
    assert "'Example-Guest' (guessed from its name)" in f.message
    assert "purpose: main" in (f.fix or "")


def test_guest_wifi_stays_quiet() -> None:
    guest_seg = purposed(SEGS[2], SegmentPurpose.GUEST)
    isolated = SEGS[2].model_copy(update={"isolated": True})
    reported = guest_wlan("ap", LAN, purpose_source=PurposeSource.REPORTED)
    for n in (
        net(segments=[guest_seg], wlans=[guest_wlan("ap", GUEST), wlan("ap", "Other", GUEST)]),
        net(segments=[isolated], wlans=[guest_wlan("ap", GUEST), wlan("ap", "Home", GUEST)]),
        net(wlans=[guest_wlan("ap", GUEST)]),  # its own VLAN, purpose unknown
        net(wlans=[reported, wlan("ap", "Home", LAN)]),  # the device keeps it apart
        net(wlans=[guest_wlan("ap", None)]),
        net(wlans=[guest_wlan("ap", LAN, enabled=False)]),
        # declared as main: not a guest network even though it is named like one
        net(wlans=[wlan("ap", "Guest", LAN, purpose=SegmentPurpose.MAIN, purpose_source=DECLARED)]),
    ):
        assert run(guest_isolation, n) == []
    # two guest SSIDs in one guest-only VLAN without a purpose are fine
    two = net(wlans=[guest_wlan("ap", GUEST), guest_wlan("ap", GUEST, ssid="Visitors-5G")])
    assert run(guest_isolation, two) == []


# --- segment.guest-no-isolation ----------------------------------------------------------------


def test_guest_without_client_isolation() -> None:
    segs = [purposed(SEGS[2], SegmentPurpose.GUEST)]
    wl = [wlan("ap", "Visitors", GUEST, client_isolation=False), wlan("ap2", "Visitors", GUEST)]
    (f,) = run(guest_no_isolation, net(segments=segs, wlans=wl))
    assert f.severity == "warning"
    assert f.message == "The guest Wi-Fi 'Visitors' on ap lets its clients reach each other"
    assert "client_isolation: true" in (f.fix or "")
    guessed = with_heuristics(net(wlans=[wlan("ap", "Guest", LAN, client_isolation=False)]))
    (g,) = run(guest_no_isolation, guessed)
    assert "(guessed from its name)" in g.message


def test_guest_isolation_quiet() -> None:
    segs = [purposed(SEGS[2], SegmentPurpose.GUEST)]
    iso = [SEGS[2].model_copy(update={"isolated": True, "purpose": SegmentPurpose.GUEST})]
    for n in (
        net(segments=segs, wlans=[wlan("ap", "V", GUEST, client_isolation=True)]),
        net(segments=segs, wlans=[wlan("ap", "V", GUEST)]),  # unknown
        net(segments=iso, wlans=[wlan("ap", "V", GUEST, client_isolation=False)]),
        net(wlans=[wlan("ap", "Home", LAN, client_isolation=False)]),
    ):
        assert run(guest_no_isolation, n) == []


# --- security.management-exposure (#120 level 1) -----------------------------------------------


def exposure_net(**kw: Any) -> Network:
    segs = [SEGS[0], purposed(SEGS[1], SegmentPurpose.IOT), seg(GUEST, 30, "Visitors")]
    return net(
        devices=kw.pop(
            "devices",
            [
                device("gw", management_address="192.0.2.1"),
                device("sw", DeviceRole.SWITCH, management_address="198.51.100.2"),
                device("ap", DeviceRole.AP, management_address="192.0.2.3"),
                device("pc", DeviceRole.OTHER, management_address="198.51.100.9"),
            ],
        ),
        segments=kw.pop("segments", segs),
        subnets=kw.pop(
            "subnets",
            [
                subnet("gw", LAN, "192.0.2.1/24"),
                subnet("gw", IOT, "198.51.100.1/24"),
                subnet("ap", IOT, "198.51.100.3/24", gateway=False),
            ],
        ),
        **kw,
    )


def test_management_exposure() -> None:
    findings = run(management_exposure, exposure_net())
    by_msg = {f.message: f for f in findings}
    sw = by_msg["sw is managed at 198.51.100.2 in the IoT network Things (VLAN 20)"]
    assert sw.severity == "error" and sw.objects == ["sw", IOT]
    assert "management VLAN" in (sw.fix or "")
    ap = by_msg["ap has the address 198.51.100.3 in the IoT network Things (VLAN 20)"]
    assert ap.severity == "error" and not ap.incomplete
    router = next(f for f in findings if f.incomplete)
    assert router.message.startswith("gw is reachable at 198.51.100.1 in the IoT network")
    assert "without firewall rules" in router.message
    assert len(findings) == 3


def test_management_exposure_router_managed_there_and_quiet_cases() -> None:
    gw = device("gw", management_address="198.51.100.1")
    (f,) = run(management_exposure, exposure_net(devices=[gw]))
    assert f.incomplete and f.objects == ["gw", IOT]
    # a guessed purpose is named as a guess
    guessed = with_heuristics(
        exposure_net(
            devices=[device("sw", DeviceRole.SWITCH, management_address="203.0.113.2")],
            subnets=[subnet("gw", GUEST, "203.0.113.1/24")],
        )
    )
    (g,) = run(management_exposure, guessed)
    assert g.message.endswith("in the guest network Visitors (VLAN 30) (guessed from its name)")
    # no purpose, no finding; unknown devices and addresses outside any subnet are skipped
    plain = exposure_net(segments=SEGS)
    assert run(management_exposure, plain) == []
    stray = exposure_net(
        devices=[device("sw", DeviceRole.SWITCH, management_address="203.0.113.50")],
        subnets=[subnet("ghost", IOT, "198.51.100.7/24", gateway=False)],
    )
    assert run(management_exposure, stray) == []


# --- segment.purpose-missing -------------------------------------------------------------------


def test_purpose_missing() -> None:
    n = with_heuristics(net())
    (f,) = run(purpose_missing, n)
    assert f.severity == "info" and f.objects == [SITE.id]
    assert f.message == (
        "It is not declared what these networks at site home are for: "
        "Things (VLAN 20); Visitors (VLAN 30), guessed: guest; LAN (untagged network)"
    )
    assert "purpose: iot" in (f.fix or "")
    done = net(segments=[purposed(s, SegmentPurpose.MAIN) for s in SEGS])
    assert run(purpose_missing, done) == []
    assert run(purpose_missing, net(segments=[SEGS[0]])) == []


# --- segment.iot-on-5ghz-only ------------------------------------------------------------------


def test_iot_on_5ghz_only() -> None:
    radios = [
        Radio(id="ap/radio/0", device_id="ap", name="r0", band=Band.GHZ_2_4),
        Radio(id="ap/radio/1", device_id="ap", name="r1", band=Band.GHZ_5),
        Radio(id="ap/radio/2", device_id="ap", name="r2", band=Band.GHZ_6),
    ]
    segs = [purposed(SEGS[1], SegmentPurpose.IOT)]
    five = [wlan("ap", "Things", IOT, "1"), wlan("ap", "Things", IOT, "2")]
    (f,) = run(iot_5ghz_only, net(segments=segs, radios=radios, wlans=five))
    assert f.message == "The IoT SSID 'Things' at site home is only on 5 and 6 GHz"
    both = [*five, wlan("ap", "Things", IOT, "0")]
    assert run(iot_5ghz_only, net(segments=segs, radios=radios, wlans=both)) == []
    unknown = [wlan("ap", "Things", IOT, "9")]
    assert run(iot_5ghz_only, net(segments=segs, radios=radios, wlans=unknown)) == []
    lan = [wlan("ap", "Home", LAN, "1")]
    assert run(iot_5ghz_only, net(segments=segs, radios=radios, wlans=lan)) == []


# --- changes to existing rules -----------------------------------------------------------------


def test_segment_at_gateway_accepts_a_router_internal_guest_network() -> None:
    internal = f"{SITE.id}/segment/guest"
    guest = Segment(
        id=internal,
        site_id=SITE.id,
        name="Guest network",
        purpose=SegmentPurpose.GUEST,
        purpose_source=PurposeSource.REPORTED,
        isolated=True,
    )
    n = net(
        devices=[device("fb")],
        segments=[SEGS[0], guest],
        subnets=[subnet("fb", LAN, "192.0.2.1/24")],
        wlans=[wlan("fb", "Home", LAN), wlan("fb", "Home-Guest", internal)],
    )
    assert run(segment_at_gateway, n) == []
    # the same network on an access point is not served by it
    ap = n.model_copy(
        update={
            "devices": [device("fb"), device("ap", DeviceRole.AP)],
            "wlans": [wlan("ap", "Home-Guest", internal)],
        }
    )
    (f,) = run(segment_at_gateway, ap)
    assert "has no subnet on the router" in f.message


def test_ssid_consistent_compares_client_isolation() -> None:
    wl = [
        wlan("ap", "Home", LAN, client_isolation=True),
        wlan("ap2", "Home", LAN, client_isolation=False),
        wlan("gw", "Home", LAN),
    ]
    (f,) = [x for x in run(ssid_consistent, net(wlans=wl)) if x.message.find("isolation") >= 0]
    assert f.severity == "warning"
    assert "client isolation differs (ap: on; ap2: off)" in f.message
