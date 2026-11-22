"""Network purpose and client isolation (#164): heuristics, merge, desired state, runner, plans."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from factories import SITE, device, iface, snapshot
from signalbox import desired
from signalbox.adapters import AdapterConfig
from signalbox.changes import ChangeKind, WlanValue, apply_change, changes_for, observed_wlan
from signalbox.config import Config
from signalbox.deploy import matches
from signalbox.desired import DesiredError, apply_declared, drift_rules, from_network, parse
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    Network,
    PurposeSource,
    Security,
    Segment,
    SegmentPurpose,
    Subnet,
    Wlan,
    json_schema,
    segment_id,
)
from signalbox.purpose import device_internal, guess, with_heuristics, wlan_purpose, wlan_source
from signalbox.rules import evaluate
from signalbox.runner import Runner
from signalbox.secrets import load_vault
from signalbox.store import DeviceRecord, Store

LAN = segment_id(SITE.id, None)
GUEST = segment_id(SITE.id, 30)
IOT = segment_id(SITE.id, 20)
GUEST_INTERNAL = f"{SITE.id}/segment/guest"


def seg(sid: str, vlan: int | None = None, **kw: Any) -> Segment:
    return Segment(id=sid, site_id=SITE.id, vlan=vlan, **kw)


def wlan(dev: str, ssid: str, segment: str | None, **kw: Any) -> Wlan:
    return Wlan(
        id=f"{dev}/wlan/{ssid}",
        device_id=dev,
        ssid=ssid,
        radio_id=f"{dev}/radio/0",
        security=Security.WPA2,
        segment_id=segment,
        **kw,
    )


# --- heuristics --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "purpose"),
    [
        ("Guest", SegmentPurpose.GUEST),
        ("Example-Guest", SegmentPurpose.GUEST),
        ("MyGuest", SegmentPurpose.GUEST),
        ("Gastzugang", SegmentPurpose.GUEST),
        ("Visitors 5G", SegmentPurpose.GUEST),
        ("IoT", SegmentPurpose.IOT),
        ("Example-IoT", SegmentPurpose.IOT),
        ("iot2g", SegmentPurpose.IOT),
        ("SmartIoT", SegmentPurpose.IOT),
        ("iota", None),
        ("LAN", None),
        ("guest-iot", None),  # two different guesses: no guess
        ("", None),
        (None, None),
    ],
)
def test_guess(name: str | None, purpose: SegmentPurpose | None) -> None:
    assert guess(name) is purpose


def test_merge_takes_reported_purposes_and_guesses_the_rest() -> None:
    a = device("a", DeviceRole.AP)
    b = device("b", DeviceRole.AP)
    snaps = [
        snapshot(a, segments=[seg(LAN), seg(GUEST, 30, name="Guest")]),
        snapshot(
            b,
            segments=[
                seg(
                    GUEST,
                    30,
                    purpose=SegmentPurpose.IOT,
                    purpose_source=PurposeSource.REPORTED,
                    isolated=True,
                ),
                seg(IOT, 20, name="IoT"),
            ],
            wlans=[
                wlan("b", "Visitor", GUEST),
                wlan(
                    "b",
                    "Plain",
                    LAN,
                    purpose=SegmentPurpose.GUEST,
                    purpose_source=PurposeSource.REPORTED,
                ),
            ],
        ),
    ]
    net = merge([SITE], snaps)
    guest, iot, lan = (net.segment(x) for x in (GUEST, IOT, LAN))
    assert guest is not None and iot is not None and lan is not None
    # a reported purpose beats the name; isolation is taken from the device that knows it
    assert (guest.purpose, guest.purpose_source, guest.isolated) == (
        SegmentPurpose.IOT,
        PurposeSource.REPORTED,
        True,
    )
    assert (iot.purpose, iot.purpose_source) == (SegmentPurpose.IOT, PurposeSource.HEURISTIC)
    assert lan.purpose is None and lan.isolated is None
    visitor, plain = sorted(net.wlans, key=lambda w: w.ssid, reverse=True)
    assert (visitor.purpose, visitor.purpose_source) == (
        SegmentPurpose.GUEST,
        PurposeSource.HEURISTIC,
    )
    assert plain.purpose_source is PurposeSource.REPORTED
    # an SSID without a purpose inherits that of its segment
    other = wlan("b", "Other", IOT)
    assert wlan_purpose(net, other) is SegmentPurpose.IOT
    assert wlan_source(net, other) is PurposeSource.HEURISTIC
    assert wlan_purpose(net, wlan("b", "x", None)) is None
    assert wlan_source(net, wlan("b", "x", None)) is None
    assert wlan_source(net, plain) is PurposeSource.REPORTED


def test_device_internal_network() -> None:
    gw = device("fb")
    ap = device("ap", DeviceRole.AP)
    internal = seg(GUEST_INTERNAL, purpose=SegmentPurpose.GUEST, isolated=True)
    net = Network(
        sites=[SITE],
        devices=[gw, ap],
        segments=[internal, seg(LAN)],
        wlans=[wlan("fb", "Guest", GUEST_INTERNAL)],
    )
    assert device_internal(net, GUEST_INTERNAL)
    assert not device_internal(net, LAN)  # not isolated
    assert not device_internal(net, "home/segment/99")  # unknown
    on_ap = net.model_copy(update={"wlans": [wlan("ap", "Guest", GUEST_INTERNAL)]})
    assert not device_internal(on_ap, GUEST_INTERNAL)
    assert not device_internal(net.model_copy(update={"wlans": []}), GUEST_INTERNAL)
    sub = Subnet(
        id="fb/subnet/g",
        segment_id=GUEST_INTERNAL,
        interface=iface("203.0.113.1/24"),
        device_id="fb",
    )
    assert not device_internal(net.model_copy(update={"subnets": [sub]}), GUEST_INTERNAL)


def test_schema_has_purpose_fields() -> None:
    defs = json_schema()["$defs"]
    assert {"purpose", "purpose_source", "reported_purpose", "isolated"} <= set(
        defs["Segment"]["properties"]
    )
    assert {"purpose", "client_isolation"} <= set(defs["Wlan"]["properties"])
    assert "guest" in defs["SegmentPurpose"]["enum"]


# --- desired state -------------------------------------------------------------------------------

STATE = """
sites:
  home:
    segments:
      - {vlan: 30, purpose: guest}
      - {vlan: native, purpose: main}
      - {vlan: 99, purpose: management}
    wlans:
      - {ssid: Visitor, security: wpa2-psk, segment: 30, purpose: guest, client_isolation: true}
      - {ssid: Home, security: wpa2-psk, purpose: main, devices: [a]}
"""


def observed() -> Network:
    return merge(
        [SITE],
        [
            snapshot(
                device("a", DeviceRole.AP),
                segments=[
                    seg(LAN),
                    seg(
                        GUEST,
                        30,
                        purpose=SegmentPurpose.IOT,
                        purpose_source=PurposeSource.REPORTED,
                    ),
                ],
                wlans=[
                    wlan("a", "Visitor", GUEST, client_isolation=False),
                    wlan(
                        "a",
                        "Home",
                        LAN,
                        purpose=SegmentPurpose.GUEST,
                        purpose_source=PurposeSource.REPORTED,
                    ),
                ],
            ),
            snapshot(
                device("b", DeviceRole.AP),
                wlans=[wlan("b", "Home", LAN), wlan("b", "Visitor", GUEST)],
            ),
        ],
    )


def test_declared_purposes_beat_reported_ones() -> None:
    state = parse(STATE)
    assert apply_declared(observed(), None) == observed()
    assert apply_declared(observed(), parse("sites: {home: {}}")) == observed()
    net = apply_declared(observed(), state)
    guest, lan = net.segment(GUEST), net.segment(LAN)
    assert guest is not None and lan is not None
    assert (guest.purpose, guest.purpose_source, guest.reported_purpose) == (
        SegmentPurpose.GUEST,
        PurposeSource.DECLARED,
        SegmentPurpose.IOT,
    )
    assert (lan.purpose, lan.reported_purpose) == (SegmentPurpose.MAIN, None)
    by = {w.id: w for w in net.wlans}
    assert by["a/wlan/Home"].purpose is SegmentPurpose.MAIN
    assert by["a/wlan/Home"].reported_purpose is SegmentPurpose.GUEST
    assert by["b/wlan/Home"].purpose is None  # declared for device a only
    assert by["b/wlan/Visitor"].purpose_source is PurposeSource.DECLARED
    # the same purpose as reported: nothing to keep
    same = parse("sites: {home: {segments: [{vlan: 30, purpose: iot}]}}")
    g = apply_declared(observed(), same).segment(GUEST)
    assert g is not None and g.reported_purpose is None


def test_drift_for_purpose_and_isolation() -> None:
    state = parse(STATE)
    net = apply_declared(observed(), state)
    findings = [
        f for f in evaluate(net, drift_rules(state)) if f.rule_id in ("drift.segment", "drift.wlan")
    ]
    messages = {f.message: f for f in findings}
    seg_purpose = messages["Segment 30 is declared as guest, but the device reports it as iot"]
    assert seg_purpose.severity == "info"
    wlan_purpose_f = messages[
        "SSID Home on a is declared as main, but the device reports it as guest"
    ]
    assert wlan_purpose_f.severity == "info"
    assert "SSID Visitor on a client isolation: should be on, is off" in messages
    unknown = messages["SSID Visitor on b: the device does not report client isolation"]
    assert unknown.incomplete
    assert any("Segment 99" in m and "does not exist" in m for m in messages)


def test_from_network_exports_known_purposes_only() -> None:
    net = apply_declared(
        observed(), parse("sites: {home: {segments: [{vlan: native, purpose: main}]}}")
    )
    net = net.model_copy(update={"segments": [*net.segments, seg(IOT, 20, name="IoT")]})

    net = with_heuristics(net)
    spec = from_network(net, "home").sites["home"]
    purposes = {str(s.vlan): s.purpose for s in spec.segments}
    assert purposes == {
        "native": SegmentPurpose.MAIN,
        "30": SegmentPurpose.IOT,  # reported
        "20": None,  # only a guess
    }
    wl = {w.ssid: w for w in spec.wlans}
    assert wl["Home"].purpose is SegmentPurpose.GUEST
    assert wl["Visitor"].client_isolation is False
    text = desired.dump(from_network(net, "home"))
    assert "purpose: main" in text and parse(text).sites["home"].segments


def test_desired_purpose_validation() -> None:
    with pytest.raises(DesiredError, match="purpose"):
        parse("sites: {home: {segments: [{vlan: 30, purpose: party}]}}")


# --- runner --------------------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def test_runner_applies_declared_purposes(store: Store) -> None:
    rec = DeviceRecord(id="a", site_id="home", name="A", role=DeviceRole.AP, adapter="none")
    store.put_device(rec, {}, AdapterConfig)
    store.save_snapshot(snapshot(device("a", DeviceRole.AP), segments=[seg(GUEST, 30)]))
    sources: list[Any] = [lambda: parse("sites: {home: {segments: [{vlan: 30, purpose: guest}]}}")]

    def source() -> desired.DesiredState | None:
        value = sources[0]()
        assert value is None or isinstance(value, desired.DesiredState)
        return value

    r = Runner(store=store, adapters={}, rules=[], config=Config(), desired_source=source)
    g = r.network().segment(GUEST)
    assert g is not None and g.purpose is SegmentPurpose.GUEST
    assert g.purpose_source is PurposeSource.DECLARED

    def broken() -> None:
        raise DesiredError("bad file")

    sources[0] = broken
    g = r.network().segment(GUEST)
    assert g is not None and g.purpose is None  # an invalid desired state declares nothing
    assert any(x.id == "desired.invalid" for x in r.active_rules())
    plain = Runner(store=store, adapters={}, rules=[], config=Config())
    assert plain.network().segment(GUEST) is not None


# --- plans ---------------------------------------------------------------------------------------


def test_planner_and_prediction_carry_client_isolation() -> None:
    net = observed()
    state = parse(
        "sites: {home: {wlans: [{ssid: Visitor, security: wpa2-psk, segment: 30, "
        "client_isolation: true, devices: [a]}]}}"
    )
    (c,) = changes_for(state, net)
    assert c.kind is ChangeKind.WLAN
    assert isinstance(c.old, WlanValue) and c.old.client_isolation is False
    assert isinstance(c.new, WlanValue) and c.new.client_isolation is True
    after = apply_change(net, c)
    w = observed_wlan(after, "a", "Visitor")
    assert w is not None and w.client_isolation is True
    assert matches(after, c, c.new, {})
    # not declared: the device's value is kept, so there is nothing to change
    keep = parse(
        "sites: {home: {wlans: [{ssid: Visitor, security: wpa2-psk, segment: 30, devices: [a]}]}}"
    )
    assert changes_for(keep, net) == []
    # verification leaves an unspecified isolation to the device
    loose = c.new.model_copy(update={"client_isolation": None})
    assert matches(after, c, loose, {})
