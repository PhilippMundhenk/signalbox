"""vlan.name-consistent (#111) and the per-device names kept by the merge (#165)."""

from __future__ import annotations

from factories import SITE, device, snapshot
from signalbox.merge import merge
from signalbox.model import DeviceRole, Network, Segment, segment_id
from signalbox.rules import Finding, evaluate
from signalbox.rules.vlan import name_consistent


def seg(vlan: int | None, name: str | None) -> Segment:
    return Segment(id=segment_id(SITE.id, vlan), site_id=SITE.id, vlan=vlan, name=name)


def net(**names: str | None) -> Network:
    """One snapshot per device (``gw=...``, ``sw=...``), each naming VLAN 20."""
    snaps = [
        snapshot(
            device(d, DeviceRole.GATEWAY if d == "gw" else DeviceRole.SWITCH),
            segments=[seg(20, n)],
        )
        for d, n in names.items()
    ]
    return merge([SITE], snaps, ())


def run(n: Network) -> list[Finding]:
    return evaluate(n, [name_consistent])


def test_merge_keeps_every_devices_name() -> None:
    n = net(gw="IoT", sw="Guest", ap=None)
    (s,) = n.segments
    assert s.names_by_device == {"gw": "IoT", "sw": "Guest"}
    assert s.name == "IoT"


def test_different_names_are_reported_with_a_suggestion() -> None:
    (f,) = run(net(gw="IoT", sw="Guest"))
    assert f.severity.value == "info"
    assert "IoT (gw)" in f.message and "Guest (sw)" in f.message
    assert f.fix is not None and "for example" in f.fix


def test_majority_name_is_suggested() -> None:
    (f,) = run(net(gw="IoT", sw="Smart", ap="smart"))
    assert str(f.params["suggestion"]).lower() == "smart"


def test_case_and_whitespace_are_ignored() -> None:
    assert run(net(gw="IoT", sw=" iot ", ap="IOT")) == []
    assert run(net(gw="Smart Home", sw="smart  home ")) == []


def test_devices_without_a_name_are_ignored() -> None:
    assert run(net(gw="IoT", sw=None, ap="  ")) == []


def test_names_derived_from_the_id_are_ignored() -> None:
    assert run(net(gw="IoT", sw="vlan20", ap="ether1.20")) == []
    assert run(net(gw="IoT", sw="VLAN 20", ap="br-lan.20")) == []


def test_untagged_network_is_not_checked() -> None:
    snaps = [
        snapshot(device("gw"), segments=[seg(None, "LAN")]),
        snapshot(device("sw", DeviceRole.SWITCH), segments=[seg(None, "Home")]),
    ]
    assert run(merge([SITE], snaps, ())) == []
