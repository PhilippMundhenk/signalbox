"""Log and monitoring target rules (#180)."""

from typing import Any

from factories import SITE, client, device, iface, peer, tunnel
from signalbox.adapters import Capability
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    LogKind,
    LogTarget,
    LogTransport,
    Network,
    Segment,
    SegmentPurpose,
    Site,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.logging_checks import RULES, inconsistent, plain_transport, target_unknown

LAN = segment_id(SITE.id, None)


def syslog(address: str, **kw: Any) -> LogTarget:
    return LogTarget(kind=LogKind.SYSLOG, address=address, **({"port": 514} | kw))


def lan(dev: str = "gw", cidr: str = "192.0.2.1/24") -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/lan", segment_id=LAN, interface=iface(cidr), device_id=dev, gateway=True
    )


def make(*targets: LogTarget, read_clients: bool = True, **kw: Any) -> Network:
    caps = [Capability.CLIENTS.value] if read_clients else []
    kw.setdefault("sites", [SITE])
    kw.setdefault("devices", [device("gw", log_targets=list(targets), capabilities=caps)])
    kw.setdefault("subnets", [lan()])
    kw.setdefault("segments", [Segment(id=LAN, site_id=SITE.id)])
    return Network(**kw)


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def test_registered() -> None:
    assert {r.id for r in RULES} == {
        "log.target-unknown",
        "log.inconsistent",
        "log.plain-transport",
    }


# --- log.target-unknown ----------------------------------------------------------------------


def test_target_used_by_a_client_is_fine() -> None:
    n = make(syslog("192.0.2.5"), clients=[client("02:00:00:00:00:05", "192.0.2.5")])
    assert run(target_unknown, n) == []


def test_target_nobody_uses_in_a_known_network() -> None:
    (f,) = run(target_unknown, make(syslog("192.0.2.5")))
    assert f.severity == "warning" and f.objects == ["gw"]
    assert f.message == (
        "gw sends syslog to 192.0.2.5:514, but no device on untagged network uses that address"
    )
    assert f.message_id == "log.targetUnused" and f.fix_id == "log.target.fix"
    assert f.params["segment"] == "untagged network"


def test_target_of_a_device_is_fine() -> None:
    n = make(LogTarget(kind=LogKind.SNMP_TRAP, address="192.0.2.1"))
    assert run(target_unknown, n) == []


def test_unused_address_without_client_data_stays_quiet() -> None:
    assert run(target_unknown, make(syslog("192.0.2.5"), read_clients=False)) == []


def test_private_target_outside_every_network() -> None:
    flow = LogTarget(kind=LogKind.NETFLOW, address="192.168.1.5", port=2055)
    (f,) = run(target_unknown, make(flow))
    assert f.message == "gw sends NetFlow to 192.168.1.5:2055, which is in no known network"
    assert f.message_id == "log.targetOutside" and not f.incomplete


def test_private_target_outside_with_an_unread_device_is_not_checked() -> None:
    n = make(
        syslog("192.168.1.5"),
        devices=[device("gw", log_targets=[syslog("192.168.1.5")]), device("sw")],
        statuses={"sw": DeviceStatus.UNREACHABLE},
    )
    (f,) = run(target_unknown, n)
    assert f.incomplete and f.message_id == "log.targetUnchecked"


def test_quiet_for_public_names_loopback_disabled_tunnels_and_metrics() -> None:
    targets = [
        syslog("203.0.113.9"),  # a public collector
        syslog("logs.home.example"),
        syslog("127.0.0.1"),
        syslog("192.0.2.77", enabled=False),
        LogTarget(kind=LogKind.METRICS, address="192.0.2.78"),
        syslog("10.20.0.5"),  # behind the tunnel
    ]
    t = tunnel("gw", peer("office", "10.20.0.0/16", "10.99.0.2/32"))
    assert run(target_unknown, make(*targets, tunnels=[t])) == []


def test_unread_targets_are_not_checked() -> None:
    n = make(devices=[device("gw", capabilities=[Capability.CLIENTS.value])])
    assert run(target_unknown, n) == []


# --- log.inconsistent ------------------------------------------------------------------------


def site_net(*devices: Any) -> Network:
    return Network(sites=[SITE, Site(id="b", name="B")], devices=list(devices))


def test_same_targets_everywhere_is_fine() -> None:
    n = site_net(
        device("gw", log_targets=[syslog("192.0.2.5")]),
        device("ap", DeviceRole.AP, log_targets=[syslog("192.0.2.5", port=1514)]),
        device("sw", DeviceRole.SWITCH),  # not read: left out
    )
    assert run(inconsistent, n) == []


def test_different_and_missing_targets() -> None:
    n = site_net(
        device("gw", log_targets=[syslog("192.0.2.5")]),
        device("ap", DeviceRole.AP, log_targets=[syslog("192.0.2.9")]),
        device(
            "sw",
            DeviceRole.SWITCH,
            log_targets=[syslog("192.0.2.5", enabled=False, transport=LogTransport.TCP)],
        ),
        device("far", site_id="b", log_targets=[syslog("198.51.100.5")]),
    )
    (f,) = run(inconsistent, n)
    assert f.severity == "info" and sorted(f.objects) == ["ap", "gw", "sw"]
    assert f.message == (
        "The devices of Home log to different targets "
        "(192.0.2.5: gw; 192.0.2.9: ap; no remote syslog: sw)"
    )
    assert f.message_id == "log.inconsistent" and f.params["site"] == "Home"


def test_nobody_logs_remotely_is_quiet() -> None:
    n = site_net(
        device("gw", log_targets=[]),
        device(
            "ap",
            DeviceRole.AP,
            log_targets=[LogTarget(kind=LogKind.NETFLOW, address="192.0.2.5")],
        ),
    )
    assert run(inconsistent, n) == []


# --- log.plain-transport (#327) --------------------------------------------------------------

SRV = segment_id(SITE.id, 30)
GUEST = segment_id(SITE.id, 40)


def two_networks(*targets: LogTarget, purpose: SegmentPurpose | None = None) -> Network:
    """The device at 192.0.2.1 in the LAN; a second network 198.51.100.0/24 (VLAN 30)."""
    return make(
        *targets,
        devices=[device("gw", log_targets=list(targets), management_address="192.0.2.1")],
        subnets=[
            lan(),
            Subnet(
                id="gw/subnet/srv",
                segment_id=SRV,
                interface=iface("198.51.100.1/24"),
                device_id="gw",
                gateway=True,
            ),
        ],
        segments=[
            Segment(id=LAN, site_id=SITE.id),
            Segment(id=SRV, site_id=SITE.id, vlan=30, purpose=purpose),
        ],
    )


def test_plain_syslog_in_the_own_network_is_quiet() -> None:
    n = make(
        syslog("192.0.2.5", transport=LogTransport.UDP),
        devices=[
            device(
                "gw",
                management_address="192.0.2.1",
                log_targets=[syslog("192.0.2.5", transport=LogTransport.UDP)],
            )
        ],
    )
    assert run(plain_transport, n) == []


def test_plain_syslog_to_another_network() -> None:
    (f,) = run(plain_transport, two_networks(syslog("198.51.100.5", transport=LogTransport.UDP)))
    assert f.severity == "info" and f.objects == ["gw"]
    assert f.message_id == "log.plainOtherSegment" and f.fix_id == "log.plain.fix"
    assert f.params["transport"] == "UDP" and f.params["target"] == "198.51.100.5:514"


def test_plain_syslog_across_an_untrusted_network() -> None:
    n = two_networks(syslog("198.51.100.5", transport=LogTransport.TCP), purpose=SegmentPurpose.IOT)
    (f,) = run(plain_transport, n)
    assert f.message_id == "log.plainUntrusted" and f.params["transport"] == "TCP"
    assert "untrusted" in f.message


def test_plain_syslog_to_the_internet() -> None:
    (f,) = run(plain_transport, two_networks(syslog("203.0.113.9", transport=LogTransport.UDP)))
    assert f.message_id == "log.plainPublic"


def test_syslog_over_tls_names_tunnels_and_unknowns_are_quiet() -> None:
    quiet = [
        syslog("203.0.113.9", transport=LogTransport.TLS),
        syslog("logs.example", transport=LogTransport.UDP),
        syslog("203.0.113.9"),  # transport not reported
        syslog("203.0.113.9", transport=LogTransport.UDP, enabled=False),
        syslog("127.0.0.1", transport=LogTransport.UDP),
        syslog("192.168.77.5", transport=LogTransport.UDP),  # private, no network: target-unknown
        LogTarget(kind=LogKind.NETFLOW, address="203.0.113.9", transport=LogTransport.UDP),
    ]
    assert run(plain_transport, two_networks(*quiet)) == []


def test_plain_syslog_of_a_device_without_known_network() -> None:
    n = two_networks(syslog("198.51.100.5", transport=LogTransport.UDP))
    n = n.model_copy(update={"devices": [device("gw", log_targets=n.devices[0].log_targets)]})
    assert run(plain_transport, n) == []  # its own network is not known: not judged
