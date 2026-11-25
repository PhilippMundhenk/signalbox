"""Per-device views of segments and client sightings (#165) and the rules built on them."""

from __future__ import annotations

from factories import SITE, client, device, snapshot
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    Membership,
    Network,
    PortMembership,
    Segment,
    SegmentRole,
    segment_id,
)
from signalbox.rules import Finding, evaluate
from signalbox.rules.segment_views import name_missing, segment_disagreement

MAC = "02:00:00:00:00:51"


def seg(vlan: int | None, name: str | None, *members: PortMembership) -> Segment:
    return Segment(
        id=segment_id(SITE.id, vlan),
        site_id=SITE.id,
        vlan=vlan,
        name=name,
        members=list(members),
    )


def sees(sid: str | None, seen_on: str | None = None) -> object:
    return client(MAC, "192.0.2.50", segment_id=sid, seen_on=seen_on)


def clients_net(gw_sid: str | None, sw_sid: str | None) -> Network:
    return merge(
        [SITE],
        [
            snapshot(device("gw", DeviceRole.GATEWAY), clients=[sees(gw_sid)]),
            snapshot(device("sw", DeviceRole.SWITCH), clients=[sees(sw_sid, "sw/port/5")]),
        ],
        (),
    )


def run(n: Network, *rules: object) -> list[Finding]:
    return evaluate(n, list(rules))  # type: ignore[arg-type]


def test_views_have_name_role_and_interface() -> None:
    n = merge(
        [SITE],
        [
            snapshot(device("gw", DeviceRole.GATEWAY), segments=[seg(20, "IoT")]),
            snapshot(
                device("sw", DeviceRole.SWITCH),
                segments=[
                    seg(20, "Smart", PortMembership(port_id="sw/port/1", mode=Membership.TAGGED))
                ],
            ),
            snapshot(device("ap", DeviceRole.AP), segments=[seg(20, None)]),
        ],
        (),
    )
    (s,) = n.segments
    views = {v.device_id: v for v in s.views}
    assert views["gw"].role is SegmentRole.GATEWAY and views["gw"].name == "IoT"
    assert views["sw"].role is SegmentRole.TRUNK and views["sw"].name == "Smart"
    assert views["ap"].role is SegmentRole.WIRELESS and views["ap"].name is None
    assert s.names_by_device == {"gw": "IoT", "sw": "Smart"}


def test_display_name_prefers_the_gateway_over_the_first_device() -> None:
    n = merge(
        [SITE],
        [
            snapshot(device("a-sw", DeviceRole.SWITCH), segments=[seg(20, "Smart")]),
            snapshot(device("z-gw", DeviceRole.GATEWAY), segments=[seg(20, "IoT")]),
        ],
        (),
    )
    assert n.segments[0].name == "IoT"


def test_display_name_falls_back_to_the_first_name() -> None:
    n = merge(
        [SITE],
        [
            snapshot(device("a-sw", DeviceRole.SWITCH), segments=[seg(20, "Smart")]),
            snapshot(device("z-gw", DeviceRole.GATEWAY), segments=[seg(20, None)]),
        ],
        (),
    )
    assert n.segments[0].name == "Smart"


def test_sightings_are_kept_per_device_next_to_the_merged_value() -> None:
    n = clients_net(segment_id(SITE.id, None), segment_id(SITE.id, 10))
    (c,) = n.clients
    assert {s.device_id: s.segment_id for s in c.sightings} == {
        "gw": segment_id(SITE.id, None),
        "sw": segment_id(SITE.id, 10),
    }
    assert c.segment_id == segment_id(SITE.id, 10)  # the switch is the more specific device
    assert all(s.observed_at is not None for s in c.sightings)


def test_disagreement_is_reported() -> None:
    n = clients_net(segment_id(SITE.id, None), segment_id(SITE.id, 10))
    (f,) = run(n, segment_disagreement)
    assert f.rule_id == "clients.segment-disagreement"
    assert "gw" in f.message and "sw" in f.message


def test_agreement_is_quiet() -> None:
    sid = segment_id(SITE.id, 10)
    assert run(clients_net(sid, sid), segment_disagreement) == []


def test_unknown_segment_is_quiet() -> None:
    assert run(clients_net(None, segment_id(SITE.id, 10)), segment_disagreement) == []


def test_single_source_is_quiet() -> None:
    n = merge(
        [SITE],
        [snapshot(device("gw", DeviceRole.GATEWAY), clients=[sees(segment_id(SITE.id, 10))])],
        (),
    )
    assert run(n, segment_disagreement) == []


def test_missing_name_is_reported() -> None:
    n = merge([SITE], [snapshot(device("sw", DeviceRole.SWITCH), segments=[seg(30, None)])], ())
    (f,) = run(n, name_missing)
    assert f.rule_id == "segment.name-missing"


def test_named_vlan_untagged_network_and_blank_name_stay_quiet() -> None:
    named = merge([SITE], [snapshot(device("gw"), segments=[seg(30, "Lab")])], ())
    assert run(named, name_missing) == []
    native = merge([SITE], [snapshot(device("gw"), segments=[seg(None, None)])], ())
    assert run(native, name_missing) == []
    one_names = merge(
        [SITE],
        [
            snapshot(device("gw"), segments=[seg(30, None)]),
            snapshot(device("sw", DeviceRole.SWITCH), segments=[seg(30, "Lab")]),
        ],
        (),
    )
    assert run(one_names, name_missing) == []
