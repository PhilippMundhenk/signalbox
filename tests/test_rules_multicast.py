"""Multicast rules (#161, ADR 0028)."""

from __future__ import annotations

from typing import Any

from factories import SITE, client, device, uplink
from signalbox.model import (
    DeviceMulticast,
    DeviceRole,
    MulticastSettings,
    Network,
    PurposeSource,
    ReflectorKind,
    Segment,
    SegmentPurpose,
    ServiceReflector,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.multicast_checks import (
    iptv_proxy,
    reflector_guest,
    reflector_missing,
    snooping_no_querier,
)

NATIVE = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)


def seg(
    sid: str, vlan: int | None, name: str, purpose: SegmentPurpose | None, **kw: Any
) -> Segment:
    return Segment(id=sid, site_id=SITE.id, vlan=vlan, name=name, purpose=purpose, **kw)


SEGMENTS = [
    seg(NATIVE, None, "Main", SegmentPurpose.MAIN),
    seg(IOT, 20, "IoT", SegmentPurpose.IOT, purpose_source=PurposeSource.DECLARED),
    seg(GUEST, 30, "Guest", SegmentPurpose.GUEST),
]


def net(*devices: Any, **kw: Any) -> Network:
    return Network(sites=[SITE], devices=list(devices), segments=SEGMENTS, **kw)


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def gw(multicast: DeviceMulticast | None, name: str = "gw") -> Any:
    return device(name, DeviceRole.GATEWAY, multicast=multicast)


def snoop(segment: str | None = NATIVE, **kw: Any) -> DeviceMulticast:
    values: dict[str, Any] = {"name": "br", "segment_id": segment, "igmp_snooping": True}
    return DeviceMulticast(settings=[MulticastSettings(**(values | kw))])


# multicast.snooping-no-querier ---------------------------------------------------------------


def test_snooping_without_a_querier_is_reported() -> None:
    (f,) = run(snooping_no_querier, net(gw(snoop(querier=False))))
    assert f.message_id == "multicast.snoopingNoQuerier"
    assert f.objects == [NATIVE, "gw"]
    assert f.params["devices"] == "gw br"
    assert "no device is the querier" in f.message


def test_a_querier_anywhere_in_the_network_satisfies_every_bridge() -> None:
    sw = device("sw", DeviceRole.SWITCH, multicast=snoop(querier=True))
    assert not run(snooping_no_querier, net(gw(snoop(querier=False)), sw))


def test_an_observed_querier_satisfies_the_bridge() -> None:
    seen = snoop(querier=False, observed_querier="192.0.2.1")
    assert not run(snooping_no_querier, net(gw(seen)))


def test_snooping_stays_quiet_when_unsure_or_off() -> None:
    assert not run(snooping_no_querier, net(gw(snoop())))  # the querier is not said
    assert not run(snooping_no_querier, net(gw(snoop(querier=False, igmp_snooping=False))))
    assert not run(snooping_no_querier, net(gw(snoop(None, querier=False))))  # network unknown
    assert not run(snooping_no_querier, net(gw(None)))
    unsure = device("sw", DeviceRole.SWITCH, multicast=snoop())
    assert not run(snooping_no_querier, net(gw(snoop(querier=False)), unsure))


def test_networks_are_judged_separately() -> None:
    both = DeviceMulticast(
        settings=[
            MulticastSettings(name="br", segment_id=NATIVE, igmp_snooping=True, querier=True),
            MulticastSettings(name="br", segment_id=IOT, igmp_snooping=True, querier=False),
        ]
    )
    (f,) = run(snooping_no_querier, net(gw(both)))
    assert IOT in f.objects and NATIVE not in f.objects


# multicast.reflector-guest -------------------------------------------------------------------


def reflecting(*segments: str, kind: ReflectorKind = ReflectorKind.MDNS, **kw: Any) -> Any:
    return gw(
        DeviceMulticast(reflectors=[ServiceReflector(kind=kind, segments=list(segments), **kw)])
    )


def test_a_reflector_into_the_guest_network_is_reported() -> None:
    (f,) = run(reflector_guest, net(reflecting(NATIVE, GUEST)))
    assert f.message_id == "multicast.reflectorGuest"
    assert f.objects == ["gw", GUEST]
    assert f.params["kind"] == "mDNS" and f.params["count"] == 2


def test_ssdp_and_relays_count_too_and_get_a_finding_each() -> None:
    both = gw(
        DeviceMulticast(
            reflectors=[
                ServiceReflector(kind=ReflectorKind.MDNS, segments=[NATIVE, GUEST]),
                ServiceReflector(kind=ReflectorKind.SSDP, segments=[IOT, GUEST]),
            ]
        )
    )
    found = run(reflector_guest, net(both))
    assert sorted(f.params["kind"] for f in found) == ["SSDP", "mDNS"]
    assert len({f.id for f in found}) == 2


def test_reflectors_without_a_guest_network_are_fine() -> None:
    assert not run(reflector_guest, net(reflecting(NATIVE, IOT)))
    assert not run(reflector_guest, net(reflecting(GUEST)))  # one network: nothing reflected
    assert not run(reflector_guest, net(reflecting(NATIVE, GUEST, enabled=False)))
    proxy = reflecting(NATIVE, GUEST, kind=ReflectorKind.IGMP_PROXY)
    assert not run(reflector_guest, net(proxy))  # streams, not names


# multicast.reflector-missing -----------------------------------------------------------------


def with_clients(n: Network) -> Network:
    return n.model_copy(
        update={
            "clients": [
                client("02:00:00:00:00:01", "192.0.2.10"),
                client("02:00:00:00:00:02", "198.51.100.10", segment_id=IOT),
            ]
        }
    )


def test_iot_devices_without_a_reflector_are_reported() -> None:
    (f,) = run(reflector_missing, with_clients(net(gw(DeviceMulticast()))))
    assert f.message_id == "multicast.reflectorMissing"
    assert f.objects == [IOT, NATIVE]
    assert f.severity.value == "info"


def test_a_reflector_joining_both_networks_satisfies_it() -> None:
    assert not run(reflector_missing, with_clients(net(reflecting(NATIVE, IOT))))


def test_a_reflector_of_other_networks_does_not() -> None:
    assert run(reflector_missing, with_clients(net(reflecting(NATIVE, GUEST))))


def test_missing_reflector_stays_quiet_without_data() -> None:
    assert not run(reflector_missing, with_clients(net(gw(None))))  # nothing read
    unknown = reflecting()  # a reflector that cannot say which networks it joins
    assert not run(reflector_missing, with_clients(net(unknown)))
    assert not run(reflector_missing, net(gw(DeviceMulticast())))  # no clients
    guessed = with_clients(net(gw(DeviceMulticast())))
    guessed = guessed.model_copy(
        update={
            "segments": [
                s.model_copy(update={"purpose_source": PurposeSource.HEURISTIC})
                if s.id == IOT
                else s
                for s in guessed.segments
            ]
        }
    )
    assert not run(reflector_missing, guessed)


# multicast.iptv-proxy ------------------------------------------------------------------------


def proxy_net(upstream: str | None, **kw: Any) -> Network:
    d = gw(
        DeviceMulticast(
            reflectors=[
                ServiceReflector(
                    kind=ReflectorKind.IGMP_PROXY,
                    interfaces=["ether1", "bridge"],
                    upstream_interface=upstream,
                    **kw,
                )
            ]
        )
    )
    return net(d, uplinks=[uplink("gw", "pppoe-out1")])


def test_a_proxy_upstream_other_than_the_uplink_is_reported() -> None:
    (f,) = run(iptv_proxy, proxy_net("bridge"))
    assert f.message_id == "multicast.iptvProxy"
    assert f.params == {"device": "gw", "upstream": "bridge", "uplink": "pppoe-out1"}


def test_a_proxy_on_the_uplink_is_fine() -> None:
    assert not run(iptv_proxy, proxy_net("pppoe-out1"))
    assert not run(iptv_proxy, proxy_net("PPPoE-Out1"))


def test_the_proxy_check_stays_quiet_without_data() -> None:
    assert not run(iptv_proxy, proxy_net(None))
    assert not run(iptv_proxy, proxy_net("bridge", enabled=False))
    no_uplink = proxy_net("bridge").model_copy(update={"uplinks": []})
    assert not run(iptv_proxy, no_uplink)
