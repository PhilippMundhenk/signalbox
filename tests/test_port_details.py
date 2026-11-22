"""Port configuration details (#156): model, helpers, contract, topology view."""

import pytest
from pydantic import ValidationError

from factories import SITE, configured_port, device, port, snapshot
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    FrameTypes,
    Membership,
    Port,
    PortKind,
    PortMedia,
    PortMembership,
    Segment,
    json_schema,
    segment_id,
)
from signalbox.testing import port_problems
from signalbox.topology import view


def test_all_details_are_optional_and_default_to_unknown() -> None:
    p = port("sw", "1")
    for field in (
        "description",
        "admin_up",
        "pvid",
        "frame_types",
        "ingress_filter",
        "mtu",
        "l2_mtu",
        "jumbo",
        "max_speed_mbps",
        "autoneg",
        "media",
        "profile",
        "flow_control",
        "eee",
    ):
        assert getattr(p, field) is None, field
    assert p.advertised_speeds_mbps == []
    assert p.jumbo_frames() is None
    assert p.label() == "1"


def test_factory_reports_every_detail() -> None:
    p = configured_port("sw", "5", description="office desk", pvid=20)
    assert (p.admin_up, p.pvid, p.mtu, p.max_speed_mbps, p.media) == (
        True,
        20,
        1500,
        1000,
        PortMedia.COPPER,
    )
    assert p.label() == "5 (office desk)"
    assert port_problems(p) == []


def test_normalisation_and_bounds() -> None:
    p = port("sw", "1", advertised_speeds_mbps=[1000, 100, 1000], description="  ", profile=" x ")
    assert p.advertised_speeds_mbps == [100, 1000]
    assert p.description is None
    assert p.profile == "x"
    assert port("sw", "lan", description="lan").label() == "lan"
    for bad in ({"pvid": 0}, {"pvid": 4095}, {"mtu": 9}, {"max_speed_mbps": 0}):
        with pytest.raises(ValidationError):
            port("sw", "1", **bad)
    with pytest.raises(ValidationError):
        port("sw", "1", frame_types="sometimes")


def test_jumbo_from_flag_or_mtu() -> None:
    assert port("sw", "1", jumbo=True).jumbo_frames() is True
    assert port("sw", "1", jumbo=False, mtu=9000).jumbo_frames() is False  # the flag wins
    assert port("sw", "1", mtu=9000).jumbo_frames() is True
    assert port("sw", "1", mtu=1500).jumbo_frames() is False


def test_contract_finds_inconsistent_details() -> None:
    text = "\n".join(
        port_problems(configured_port("sw", "1", speed_mbps=2500))
        + port_problems(configured_port("sw", "2", advertised_speeds_mbps=[100, 10000]))
        + port_problems(configured_port("sw", "3", admin_up=False))
        + port_problems(configured_port("ap", "wlan0", kind=PortKind.WIRELESS))
    )
    for needle in [
        "speed 2500 > max speed 1000",
        "advertises a speed above its max speed 1000",
        "link up on a disabled port",
        "wireless port with a wired medium",
    ]:
        assert needle in text, needle
    assert port_problems(configured_port("sw", "4", admin_up=False, up=False)) == []


def net_with_pvid(pvid: int | None, frame_types: FrameTypes | None = None):  # type: ignore[no-untyped-def]
    ports = [
        configured_port("sw", "1", pvid=pvid, frame_types=frame_types),
        port("sw", "2"),
    ]
    members = [PortMembership(port_id="sw/port/1", mode=Membership.UNTAGGED)]
    seg = Segment(id=segment_id("home", 10), site_id="home", vlan=10, members=members)
    snap = snapshot(device("sw", DeviceRole.SWITCH), ports=ports, segments=[seg])
    return merge([SITE], [snap])


def test_pvid_segment_and_untagged_segments() -> None:
    net = net_with_pvid(20)
    assert net.pvid_segment("sw/port/1") == "home/segment/20"
    assert net.untagged_segments("sw/port/1") == ["home/segment/10"]
    assert net_with_pvid(1).pvid_segment("sw/port/1") == "home/segment/native"
    assert net.pvid_segment("sw/port/2") is None  # no PVID reported
    assert net.pvid_segment("sw/port/9") is None  # no such port
    assert net_with_pvid(20, FrameTypes.TAGGED_ONLY).pvid_segment("sw/port/1") is None
    orphan = net.model_copy(update={"devices": []})
    assert orphan.pvid_segment("sw/port/1") is None


def test_topology_view_carries_the_details() -> None:
    v = view(net_with_pvid(20))
    p1 = next(p for p in v["nodes"][0]["ports"] if p["id"] == "sw/port/1")
    expected = {
        "description": None,
        "admin_up": True,
        "speed_mbps": 1000,
        "max_speed_mbps": 1000,
        "pvid": 20,
        "pvid_segment": "home/segment/20",
        "mtu": 1500,
        "jumbo": False,
        "profile": None,
    }
    assert {k: p1[k] for k in expected} == expected


def test_round_trip_and_schema() -> None:
    p = configured_port(
        "sw",
        "1",
        frame_types=FrameTypes.UNTAGGED_ONLY,
        ingress_filter=True,
        l2_mtu=1598,
        jumbo=False,
        media=PortMedia.SFP_PLUS,
        profile="All",
    )
    assert Port.model_validate_json(p.model_dump_json()) == p
    props = json_schema()["$defs"]["Port"]["properties"]
    for name in ("pvid", "admin_up", "mtu", "max_speed_mbps", "description", "profile", "eee"):
        assert name in props, name
