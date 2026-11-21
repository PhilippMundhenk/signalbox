import json
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from factories import SITE, T0, device, ip, port, snapshot
from signalbox.__main__ import main
from signalbox.merge import merge
from signalbox.model import (
    Client,
    DeviceRole,
    Link,
    LinkOrigin,
    Membership,
    PortMembership,
    ReadError,
    Segment,
    Site,
    json_schema,
    normalise_mac,
    object_id,
    passphrase_fingerprint,
    port_id,
    segment_id,
)

ROOT = Path(__file__).resolve().parent.parent


def test_ids() -> None:
    assert port_id("gw", "lan1") == "gw/port/lan1"
    assert segment_id("home", 10) == "home/segment/10"
    assert segment_id("home", None) == "home/segment/native"
    assert object_id("ap", "wlan", "x") == "ap/wlan/x"


@pytest.mark.parametrize(
    ("raw", "want"),
    [("02-00-00-AA-BB-CC", "02:00:00:aa:bb:cc"), ("0200.00aa.bbcc", "02:00:00:aa:bb:cc")],
)
def test_normalise_mac(raw: str, want: str) -> None:
    assert normalise_mac(raw) == want


@pytest.mark.parametrize("raw", ["02:00:00:aa:bb", "not a mac", "02:00:00:aa:bb:cc:dd"])
def test_normalise_mac_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        normalise_mac(raw)


def test_passphrase_fingerprint_compares_without_revealing() -> None:
    a = passphrase_fingerprint("Example", "correct horse")
    assert a == passphrase_fingerprint("Example", "correct horse")
    assert a != passphrase_fingerprint("Example", "correct horsf")
    assert a != passphrase_fingerprint("Other", "correct horse")
    assert "horse" not in a and len(a) == 16


def test_models_forbid_unknown_fields_and_are_frozen() -> None:
    with pytest.raises(ValidationError):
        Site(id="x", name="x", colour="red")  # type: ignore[call-arg]
    site = Site(id="x", name="x")
    with pytest.raises(ValidationError):
        site.name = "y"  # type: ignore[misc]


def test_vlan_range() -> None:
    with pytest.raises(ValidationError):
        Segment(id="s", site_id="home", vlan=4095)


def test_mac_pattern() -> None:
    with pytest.raises(ValidationError):
        Client(id="c", mac="02:00:00:AA:BB:CC")


def test_merge_joins_segments_clients_and_keeps_errors() -> None:
    gw = device("gw", DeviceRole.GATEWAY)
    ap = device("ap", DeviceRole.AP)
    seg = segment_id("home", 10)
    gw_snap = snapshot(
        gw,
        ports=[port("gw", "lan")],
        segments=[
            Segment(
                id=seg,
                site_id="home",
                vlan=10,
                members=[PortMembership(port_id=port_id("gw", "lan"), mode=Membership.TAGGED)],
            )
        ],
        clients=[
            Client(
                id="gw/client/1",
                mac="02:00:00:00:00:01",
                addresses=[ip("192.0.2.10")],
                hostname="laptop",
                last_seen=T0,
            )
        ],
        errors=[ReadError(device_id="gw", capability="dns", message="timeout")],
    )
    ap_snap = snapshot(
        ap,
        ports=[port("ap", "lan")],
        segments=[
            Segment(
                id=seg,
                site_id="home",
                vlan=10,
                name="IoT",
                members=[
                    PortMembership(port_id=port_id("ap", "lan"), mode=Membership.TAGGED),
                    PortMembership(port_id=port_id("gw", "lan"), mode=Membership.UNTAGGED),
                ],
            )
        ],
        clients=[
            Client(
                id="ap/client/1",
                mac="02:00:00:00:00:01",
                addresses=[ip("192.0.2.10"), ip("2001:db8::10")],
                seen_on="ap/wlan/iot",
                last_seen=T0 + timedelta(minutes=1),
            )
        ],
    )
    link = Link(id="l1", a="gw/port/lan", b="ap/port/lan", origin=LinkOrigin.MANUAL)
    net = merge([SITE], [gw_snap, ap_snap], [link])

    assert [d.id for d in net.devices] == ["ap", "gw"]
    assert net.device("gw") == gw and net.device("nope") is None
    assert net.port("ap/port/lan") is not None and net.port("x") is None
    (merged_seg,) = net.segments
    assert net.segment(seg) == merged_seg and net.segment("x") is None
    assert merged_seg.name == "IoT"
    assert merged_seg.source is None
    # the gateway's own view of its port wins over what the AP reports about it
    modes = {m.port_id: m.mode for m in merged_seg.members}
    assert modes == {"ap/port/lan": Membership.TAGGED, "gw/port/lan": Membership.TAGGED}

    (client,) = net.clients
    assert client.id == "client/02:00:00:00:00:01"
    assert client.seen_on == "ap/wlan/iot"  # the AP knows where, the gateway does not
    assert client.hostname == "laptop"
    assert [str(a) for a in client.addresses] == ["192.0.2.10", "2001:db8::10"]
    assert client.last_seen == T0 + timedelta(minutes=1)
    assert net.links == [link]
    assert [e.capability for e in net.errors] == ["dns"]
    assert net.statuses == {"ap": "ok", "gw": "ok"}


def test_merge_client_without_times() -> None:
    a = snapshot(device("a"), clients=[Client(id="1", mac="02:00:00:00:00:02")])
    b = snapshot(device("b"), clients=[Client(id="2", mac="02:00:00:00:00:02")])
    (client,) = merge([SITE], [a, b]).clients
    assert client.last_seen is None


def test_merge_rejects_two_snapshots_of_one_device() -> None:
    gw = device("gw")
    with pytest.raises(ValueError, match="gw"):
        merge([SITE], [snapshot(gw), snapshot(gw)])


def test_committed_schema_is_current() -> None:
    committed = json.loads((ROOT / "docs" / "schema.json").read_text())
    assert committed == json_schema(), "run `make schema` and commit docs/schema.json"


def test_schema_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert "Snapshot" in schema["$defs"] and "Network" in schema["$defs"]
