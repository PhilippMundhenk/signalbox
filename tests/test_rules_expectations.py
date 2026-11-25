"""Rules that use the expectations of client annotations (#84, #85)."""

from typing import Any

from factories import SITE, annotated, annotation
from signalbox.model import (
    Acknowledgement,
    Client,
    Network,
    PurposeSource,
    Segment,
    SegmentPurpose,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.expectations import (
    RULES,
    category_network,
    unexpected_network,
    vendor_network,
)

LAN = segment_id(SITE.id, 10)
IOT = segment_id(SITE.id, 20)
CAM = "02:00:00:00:00:41"
PC = "02:00:00:00:00:42"


def client(mac: str, seg: str | None, **kw: Any) -> Client:
    return Client(id=f"gw/client/{mac}", mac=mac, segment_id=seg, **kw)


def net_of(*clients: Client, source: PurposeSource = PurposeSource.DECLARED) -> Network:
    return Network(
        sites=[SITE],
        segments=[
            Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN"),
            Segment(
                id=IOT,
                site_id=SITE.id,
                vlan=20,
                name="IoT",
                purpose=SegmentPurpose.IOT,
                purpose_source=source,
            ),
        ],
        clients=list(clients),
    )


def run(net: Network, r: Rule) -> list[Finding]:
    return evaluate(net, [r])


def test_registered() -> None:
    assert {r.id for r in RULES} == {
        "clients.unexpected-network",
        "clients.category-network",
        "clients.vendor-network",
    }


def test_unexpected_network() -> None:
    net = net_of(client(CAM, LAN, hostname="camera"))
    assert run(net, unexpected_network) == []  # nothing said
    note = annotation(CAM, expected={"segment": IOT})
    (f,) = run(annotated(net, note), unexpected_network)
    assert f.message == f"camera ({CAM}) is on LAN (VLAN 10) but belongs in IoT (VLAN 20)"
    assert f.severity == "info" and f.objects[0] == f"gw/client/{CAM}"
    assert run(annotated(net_of(client(CAM, IOT)), note), unexpected_network) == []
    assert run(annotated(net_of(client(CAM, None)), note), unexpected_network) == []


def test_category_network_iot_outside() -> None:
    cam = annotation(CAM, expected={"category": "camera"})
    net = annotated(net_of(client(CAM, LAN, hostname="cam")), cam)
    (f,) = run(net, category_network)
    assert f.message == (
        f"1 IoT device (cam ({CAM})) is on LAN (VLAN 10) although IoT (VLAN 20) exists"
    )
    assert f.severity == "info" and "Move them" in (f.fix or "")
    two = annotated(
        net_of(client(CAM, LAN), client(PC, LAN)),
        cam,
        annotation(PC, expected={"category": "iot"}),
    )
    (f,) = run(two, category_network)
    assert f.message.startswith("2 IoT devices (") and " are on " in f.message


def test_category_network_computer_in_iot() -> None:
    net = annotated(net_of(client(PC, IOT)), annotation(PC, expected={"category": "computer"}))
    (f,) = run(net, category_network)
    assert "is in the IoT network IoT (VLAN 20)" in f.message and "main network" in (f.fix or "")
    pcs = annotated(
        net_of(client(PC, IOT), client(CAM, IOT)),
        annotation(PC, expected={"category": "phone"}),
        annotation(CAM, expected={"category": "server"}),
    )
    (f,) = run(pcs, category_network)
    assert (
        "2 computers, phones or servers (" in f.message and " are in the IoT network" in f.message
    )


def test_category_network_stays_quiet() -> None:
    cam = annotation(CAM, expected={"category": "camera"})
    # in the IoT network already
    assert run(annotated(net_of(client(CAM, IOT)), cam), category_network) == []
    # no category, no network, only a guessed IoT network, no IoT network at all
    assert run(net_of(client(CAM, LAN)), category_network) == []
    assert run(annotated(net_of(client(CAM, None)), cam), category_network) == []
    guessed = net_of(client(CAM, LAN), source=PurposeSource.HEURISTIC)
    assert run(annotated(guessed, cam), category_network) == []
    plain = net_of(client(CAM, LAN)).model_copy(
        update={"segments": [Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN")]}
    )
    assert run(annotated(plain, cam), category_network) == []
    # an IoT device in the guest or camera network
    for purpose in (SegmentPurpose.GUEST, SegmentPurpose.CAMERAS):
        net = net_of(client(CAM, LAN))
        segs = [
            s.model_copy(update={"purpose": purpose}) if s.id == LAN else s for s in net.segments
        ]
        assert (
            run(annotated(net.model_copy(update={"segments": segs}), cam), category_network) == []
        )
    # an expected network is for clients.unexpected-network
    both = annotation(CAM, expected={"category": "camera", "segment": IOT})
    assert run(annotated(net_of(client(CAM, LAN)), both), category_network) == []
    # another category in the IoT network, or a computer on the main network
    other = annotation(CAM, expected={"category": "printer"})
    assert run(annotated(net_of(client(CAM, IOT)), other), category_network) == []
    pc = annotation(PC, expected={"category": "computer"})
    assert run(annotated(net_of(client(PC, LAN)), pc), category_network) == []


# Prefixes from the public IEEE registry: Espressif (IoT), Hikvision (camera), Apple (unmapped).
ESP = "d4:8a:fc:00:00:01"
HIK = "0c:75:d2:00:00:02"
APPLE = "3c:22:fb:00:00:03"
RANDOM = "d6:8a:fc:00:00:04"


def main_net(*clients: Client) -> Network:
    net = net_of(*clients)
    segments = [
        s.model_copy(update={"purpose": SegmentPurpose.MAIN}) if s.id == LAN else s
        for s in net.segments
    ]
    return net.model_copy(update={"segments": segments})


def test_vendor_network_flags_iot_and_camera_vendors() -> None:
    net = main_net(client(ESP, LAN, hostname="plug"), client(HIK, LAN))
    found = run(net, vendor_network)
    assert len(found) == 2
    assert all(f.severity == "info" and "IoT (VLAN 20)" in f.message for f in found)
    assert any("vendor Espressif" in f.message and "plug" in f.message for f in found)
    assert any("Hikvision" in f.message for f in found)
    assert "acknowledge" in (found[0].fix or "")


def test_vendor_network_can_be_acknowledged() -> None:
    merged = Client(id=f"client/{ESP}", mac=ESP, segment_id=LAN)  # as the merge names clients
    net = main_net(merged, client(HIK, LAN))
    ack = Acknowledgement(id="a1", rule_id="clients.vendor-network", target=f"client/{ESP}")
    done = run(net.model_copy(update={"acknowledgements": [ack]}), vendor_network)
    by_mac = {ESP in f.message: f.acknowledged is not None for f in done}
    assert by_mac == {True: True, False: False}


def test_vendor_network_stays_quiet() -> None:
    # unknown vendor mapping, randomised address, already in the IoT network
    assert (
        run(main_net(client(APPLE, LAN), client(RANDOM, LAN), client(ESP, IOT)), vendor_network)
        == []
    )
    # no purpose known for the network, or only a guessed IoT network, or none
    assert run(net_of(client(ESP, LAN)), vendor_network) == []
    guessed = main_net(client(ESP, LAN)).model_copy(update={})
    segs = [
        s.model_copy(update={"purpose_source": PurposeSource.HEURISTIC}) for s in guessed.segments
    ]
    assert run(guessed.model_copy(update={"segments": segs}), vendor_network) == []
    # a declared category or expected network belongs to the other two rules
    cat = annotation(ESP, expected={"category": "computer"})
    assert run(annotated(main_net(client(ESP, LAN)), cat), vendor_network) == []
    seg = annotation(HIK, expected={"segment": LAN})
    assert run(annotated(main_net(client(HIK, LAN)), seg), vendor_network) == []
    assert run(main_net(client(ESP, None)), vendor_network) == []
