"""Rules about the dynamic port mappings of UPnP, NAT-PMP and PCP (#176, ADR 0029)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from factories import SITE, T0, client, device, iface, service, uplink
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
    cgnat_useless,
    insecure_mode,
    management_port,
    many_mappings,
    mapping_to_unknown,
    mapping_untrusted,
    stale_mapping,
)
from signalbox.sightings import ClientHistory, History

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


# upnp.mapping-to-unknown ---------------------------------------------------------------------


def test_a_mapping_to_an_address_nobody_has_is_reported() -> None:
    known = client("02:00:00:00:00:31", "192.0.2.50")
    n = net(gw(mapping("192.0.2.99"), mapping("192.0.2.50", 80)), clients=[known])
    (f,) = run(mapping_to_unknown, n)
    assert f.message_id == "upnp.mappingToUnknown"
    assert f.params["address"] == "192.0.2.99"


def test_unknown_stays_quiet_for_known_addresses_without_clients_and_off() -> None:
    known = client("02:00:00:00:00:31", "192.0.2.50")
    assert not run(mapping_to_unknown, net(gw(mapping("192.0.2.50")), clients=[known]))
    # the gateway's own address in a network, and no client list at all
    assert not run(mapping_to_unknown, net(gw(mapping("192.0.2.1")), clients=[known]))
    assert not run(mapping_to_unknown, net(gw(mapping("192.0.2.99"))))
    off = service("gw", ServiceKind.UPNP, enabled=False)
    n = net(gw(mapping("192.0.2.99")), clients=[known], services=[off])
    assert not run(mapping_to_unknown, n)


def test_a_management_address_counts_as_known() -> None:
    known = client("02:00:00:00:00:31", "192.0.2.50")
    ap = device("ap", DeviceRole.ACCESS_POINT, management_address="192.0.2.77")
    assert not run(mapping_to_unknown, net(gw(mapping("192.0.2.77")), ap, clients=[known]))
    named = device("nas", DeviceRole.ACCESS_POINT, management_address="nas.example.test")
    assert run(mapping_to_unknown, net(gw(mapping("192.0.2.99")), named, clients=[known]))


# upnp.cgnat-useless --------------------------------------------------------------------------


def wan(*addresses: str, **kw: Any) -> Network:
    n = net(gw())
    up = uplink("gw", addresses=[iface(a) for a in addresses], **kw)
    return n.model_copy(update={"uplinks": [up]})


def test_upnp_behind_cgnat_or_another_router_is_reported() -> None:
    (f,) = run(cgnat_useless, wan("100.64.0.23/10"))
    assert f.message_id == "upnp.cgnatUseless"
    (f,) = run(cgnat_useless, wan("10.1.2.3/24"))
    assert f.message_id == "upnp.behindRouterUseless"


def test_cgnat_useless_stays_quiet_where_it_may_work() -> None:
    assert not run(cgnat_useless, wan("198.51.100.23/24"))
    assert not run(cgnat_useless, net(gw()))  # no uplink known
    assert not run(cgnat_useless, wan("100.64.0.23/10", up=False))
    both = net(gw()).model_copy(
        update={
            "uplinks": [
                uplink("gw", "a", addresses=[iface("100.64.0.23/10")]),
                uplink("gw", "b", addresses=[iface("198.51.100.23/24")]),
            ]
        }
    )
    assert not run(cgnat_useless, both)
    off = service("gw", ServiceKind.UPNP, enabled=False)
    assert not run(cgnat_useless, wan("100.64.0.23/10").model_copy(update={"services": [off]}))
    plain = wan("100.64.0.23/10").model_copy(update={"devices": [device("gw", DeviceRole.GATEWAY)]})
    assert not run(cgnat_useless, plain)  # UPnP not reported at all


# upnp.stale-mapping --------------------------------------------------------------------------


def stale(
    seen_days: int | None, *, past_days: int | None = None, now: bool = True
) -> list[Finding]:
    when = T0 - timedelta(days=seen_days) if seen_days is not None else None
    c = client("02:00:00:00:00:41", "192.0.2.60", hostname="console", last_seen=when)
    n = net(gw(mapping("192.0.2.60")), clients=[c])
    hist = History(now=T0 if now else None)
    if past_days is not None:
        past = T0 - timedelta(days=past_days)
        hist.clients[c.mac] = ClientHistory(mac=c.mac, first_seen=past, last_seen=past)
    return [f for f in evaluate(n, [stale_mapping], history=hist) if f.rule_id == stale_mapping.id]


def test_a_mapping_of_a_long_gone_device_is_reported() -> None:
    (f,) = stale(30)
    assert f.message_id == "upnp.staleMapping"
    assert f.params["days"] == 30


def test_recent_unknown_and_timeless_cases_are_quiet() -> None:
    assert not stale(3)
    assert not stale(None)
    assert not stale(30, now=False)
    assert not stale(30, past_days=1)  # the history saw it yesterday
    assert not run(stale_mapping, net(gw(mapping("192.0.2.60"))))  # called without history
