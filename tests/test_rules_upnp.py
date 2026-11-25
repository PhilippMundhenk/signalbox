"""Rules about the dynamic port mappings of UPnP, NAT-PMP and PCP (#176, ADR 0029)."""

from __future__ import annotations

from typing import Any

from factories import SITE, client, device, iface, service
from signalbox.model import (
    Device,
    DeviceRole,
    DeviceUpnp,
    DynamicPortMapping,
    Network,
    Segment,
    SegmentPurpose,
    ServiceKind,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.upnp_checks import (
    insecure_mode,
    management_port,
    many_mappings,
    mapping_untrusted,
)

LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)


def mapping(address: str = "192.0.2.60", internal: int = 3074, **kw: Any) -> DynamicPortMapping:
    values: dict[str, Any] = {
        "protocol": "udp",
        "external_port": 3074,
        "internal_address": address,
        "internal_port": internal,
    }
    return DynamicPortMapping(**(values | kw))


def gw(*mappings: DynamicPortMapping, **kw: Any) -> Device:
    return device("gw", DeviceRole.GATEWAY, upnp=DeviceUpnp(mappings=list(mappings), **kw))


def net(*devices: Device, clients: Any = (), services: Any = ()) -> Network:
    def sub(sid: str, addr: str) -> Subnet:
        return Subnet(id=f"gw/subnet/{sid}", segment_id=sid, interface=iface(addr), device_id="gw")

    return Network(
        sites=[SITE],
        devices=list(devices),
        segments=[
            Segment(id=LAN, site_id=SITE.id, vlan=None, purpose=SegmentPurpose.MAIN),
            Segment(id=IOT, site_id=SITE.id, vlan=20, purpose=SegmentPurpose.IOT),
            Segment(id=GUEST, site_id=SITE.id, vlan=30, purpose=SegmentPurpose.GUEST),
        ],
        subnets=[
            sub(LAN, "192.0.2.1/25"),
            sub(IOT, "192.0.2.129/26"),
            sub(GUEST, "198.51.100.1/24"),
        ],
        clients=list(clients),
        services=list(services),
    )


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


# upnp.mapping-untrusted ----------------------------------------------------------------------


def test_a_mapping_into_an_iot_network_is_reported() -> None:
    cam = client("02:00:00:00:00:21", "192.0.2.140", segment_id=IOT, hostname="camera")
    (f,) = run(mapping_untrusted, net(gw(mapping("192.0.2.140", 554)), clients=[cam]))
    assert f.message_id == "upnp.mappingUntrusted"
    assert f.objects == ["gw", IOT, cam.id]
    assert f.params["client"] == "camera" and f.params["mapping"] == "UDP 3074"


def test_the_network_comes_from_the_subnet_without_a_client() -> None:
    (f,) = run(mapping_untrusted, net(gw(mapping("198.51.100.7"))))
    assert f.objects == ["gw", GUEST] and f.params["client"] == "198.51.100.7"


def test_each_mapping_is_its_own_finding() -> None:
    n = net(gw(mapping("198.51.100.7"), mapping("198.51.100.7", external_port=3075)))
    assert len({f.id for f in run(mapping_untrusted, n)}) == 2


def test_untrusted_stays_quiet_for_the_main_network_unknown_and_off() -> None:
    assert not run(mapping_untrusted, net(gw(mapping("192.0.2.60"))))
    assert not run(mapping_untrusted, net(gw(mapping("203.0.113.9"))))  # in no network
    assert not run(mapping_untrusted, net(gw(mapping("198.51.100.7", enabled=False))))
    assert not run(mapping_untrusted, net(device("gw", DeviceRole.GATEWAY)))  # not read
    off = service("gw", ServiceKind.UPNP, enabled=False)
    assert not run(mapping_untrusted, net(gw(mapping("198.51.100.7")), services=[off]))


# upnp.management-port ------------------------------------------------------------------------


def test_a_mapping_to_ssh_is_reported_by_either_port() -> None:
    (f,) = run(management_port, net(gw(mapping("192.0.2.60", 22, external_port=2222))))
    assert f.message_id == "upnp.managementPort"
    assert f.params["service"] == "SSH" and f.params["port"] == 22
    (g,) = run(management_port, net(gw(mapping("192.0.2.60", 8080, external_port=3389))))
    assert g.params["service"] == "remote desktop"


def test_ordinary_mappings_are_not_management_ports() -> None:
    assert not run(management_port, net(gw(mapping("192.0.2.60", 3074))))
    assert not run(management_port, net(gw(mapping("192.0.2.60", 22, enabled=False))))


# upnp.insecure-mode --------------------------------------------------------------------------


def test_secure_mode_off_is_reported() -> None:
    (f,) = run(insecure_mode, net(gw(secure_mode=False)))
    assert f.message_id == "upnp.insecureMode" and f.objects == ["gw"]


def test_secure_mode_on_unknown_or_upnp_off_is_quiet() -> None:
    assert not run(insecure_mode, net(gw(secure_mode=True)))
    assert not run(insecure_mode, net(gw()))
    off = service("gw", ServiceKind.UPNP, enabled=False)
    assert not run(insecure_mode, net(gw(secure_mode=False), services=[off]))


# upnp.many-mappings --------------------------------------------------------------------------


def many(count: int, **kw: Any) -> Device:
    return gw(*(mapping(external_port=2000 + n, **kw) for n in range(count)))


def test_more_than_the_limit_is_reported() -> None:
    (f,) = run(many_mappings, net(many(21, lease_seconds=0)))
    assert f.message_id == "upnp.manyMappings"
    assert f.params["count"] == 21 and f.params["permanent"] == 21


def test_the_limit_itself_and_unread_gateways_are_quiet() -> None:
    assert not run(many_mappings, net(many(20)))
    assert not run(many_mappings, net(device("gw", DeviceRole.GATEWAY)))
