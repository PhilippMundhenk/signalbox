"""Client rules: duplicate host names and randomised MACs (#82, #83).

Locally administered (randomised) MACs start with 02:; universally administered ones use the
documentation range 00:00:5e:00:53:xx (RFC 7042).
"""

from typing import Any

from factories import SITE, device, ip, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Client,
    DeviceRole,
    DhcpServer,
    DnsService,
    HostRecord,
    Reservation,
    Segment,
    Snapshot,
    segment_id,
)
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.clients import duplicate_hostname, is_randomised, random_mac

LAN = segment_id(SITE.id, 10)
IOT = segment_id(SITE.id, 20)
REAL = "00:00:5e:00:53:{:02x}"
RANDOM = "02:00:00:00:00:{:02x}"


def client(mac: str, hostname: str | None = None, seg: str | None = LAN, **kw: Any) -> Client:
    return Client(id=f"gw/client/{mac}", mac=mac, hostname=hostname, segment_id=seg, **kw)


def dhcp(seg: str = LAN, domain: str | None = None, **kw: Any) -> DhcpServer:
    return DhcpServer(
        id=f"gw/dhcp/{seg}", device_id="gw", segment_id=seg, enabled=True, domain=domain, **kw
    )


def gw(**kw: Any) -> Snapshot:
    segments = [
        Segment(id=LAN, site_id=SITE.id, vlan=10, name="LAN"),
        Segment(id=IOT, site_id=SITE.id, vlan=20, name="IoT"),
    ]
    return snapshot(device("gw", DeviceRole.GATEWAY), segments=segments, **kw)


def run(r: Rule, *snaps: Snapshot) -> list[Finding]:
    net = merge([SITE], snaps)
    return [f for f in evaluate(net, [r]) if f.rule_id == r.id]


def test_is_randomised() -> None:
    assert is_randomised("02:00:00:00:00:01")
    assert is_randomised("06:00:00:00:00:01") and is_randomised("fa:00:00:00:00:01")
    assert not is_randomised("00:00:5e:00:53:01") and not is_randomised("a4:00:00:00:00:01")


# clients.duplicate-hostname ----------------------------------------------------------------------


def test_duplicate_hostname_with_real_macs_is_a_warning() -> None:
    clients = [
        client(REAL.format(0x21), "raspberrypi.home.example"),
        client(REAL.format(0x22), "RaspberryPi"),
        client(REAL.format(0x23), "nas"),
    ]
    (f,) = run(duplicate_hostname, gw(clients=clients))
    assert f.severity is Severity.WARNING
    assert f.message == (
        "Two devices on LAN (VLAN 10) call themselves raspberrypi "
        "(00:00:5e:00:53:21, 00:00:5e:00:53:22)"
    )
    assert f.fix and "Rename one" in f.fix
    assert f.objects == ["client/00:00:5e:00:53:21", "client/00:00:5e:00:53:22"]


def test_duplicate_hostname_with_a_randomised_mac_is_info() -> None:
    clients = [client(REAL.format(0x21), "phone"), client(RANDOM.format(0x22), "phone")]
    (f,) = run(duplicate_hostname, gw(clients=clients))
    assert f.severity is Severity.INFO and "private (randomised)" in f.message


def test_duplicate_hostname_three_devices() -> None:
    clients = [client(REAL.format(i), "camera") for i in (1, 2, 3)]
    (f,) = run(duplicate_hostname, gw(clients=clients))
    assert f.message.startswith("3 devices on LAN")


def test_duplicate_hostname_stays_quiet() -> None:
    clients = [
        # different networks without a shared domain
        client(REAL.format(1), "printer", LAN),
        client(REAL.format(2), "printer", IOT),
        # generic and empty names, the MAC as name
        client(REAL.format(3), "android"),
        client(REAL.format(4), "Android"),
        client(REAL.format(5), ""),
        client(REAL.format(6), None),
        client(REAL.format(7), "00-00-5e-00-53-07"),
        client(REAL.format(8), "00005e005307"),
        # no network known
        client(REAL.format(9), "tv", None),
        client(REAL.format(10), "tv", None),
    ]
    assert run(duplicate_hostname, gw(clients=clients)) == []
    # the same device seen by two devices is one client (one MAC)
    ap = snapshot(device("ap", DeviceRole.AP), clients=[client(REAL.format(1), "printer")])
    assert run(duplicate_hostname, gw(clients=[client(REAL.format(1), "printer")]), ap) == []


def test_duplicate_hostname_across_networks_with_the_same_domain() -> None:
    clients = [client(REAL.format(1), "printer", LAN), client(REAL.format(2), "printer", IOT)]
    servers = [dhcp(LAN, "home.example"), dhcp(IOT, "Home.Example.")]
    (f,) = run(duplicate_hostname, gw(clients=clients, dhcp_servers=servers))
    assert "networks sharing the domain home.example (LAN (VLAN 10), IoT (VLAN 20))" in f.message
    # different domains keep them apart
    servers = [dhcp(LAN, "home.example"), dhcp(IOT, "iot.example")]
    assert run(duplicate_hostname, gw(clients=clients, dhcp_servers=servers)) == []


# clients.random-mac ---------------------------------------------------------------------------


def test_reservation_for_randomised_mac() -> None:
    res = [
        Reservation(mac="06:00:00:00:00:40", address=ip("192.0.2.40"), hostname="phone"),
        Reservation(mac=REAL.format(0x41), address=ip("192.0.2.41")),
    ]
    (f,) = run(random_mac, gw(dhcp_servers=[dhcp(reservations=res)]))
    assert f.severity is Severity.WARNING
    assert f.message == (
        "The reservation 192.0.2.40 (phone) on LAN (VLAN 10) is for a randomised MAC address "
        "(06:00:00:00:00:40)"
    )
    assert f.objects == [f"gw/dhcp/{LAN}"]
    assert f.fix and "reserve its real MAC" in f.fix


def test_same_reservation_on_two_servers_is_one_finding() -> None:
    res = [Reservation(mac=RANDOM.format(1), address=ip("192.0.2.40"))]
    ap = snapshot(
        device("ap", DeviceRole.AP),
        dhcp_servers=[
            DhcpServer(
                id="ap/dhcp/lan", device_id="ap", segment_id=LAN, enabled=False, reservations=res
            )
        ],
    )
    (f,) = run(random_mac, gw(dhcp_servers=[dhcp(reservations=res)]), ap)
    assert f.objects == ["ap/dhcp/lan", f"gw/dhcp/{LAN}"]
    assert "192.0.2.40 on LAN" in f.message


def test_dns_record_for_a_randomised_client() -> None:
    dns = DnsService(
        id="gw/dns/unbound",
        device_id="gw",
        host_records=[
            HostRecord(name="tablet.home.example", address=ip("192.0.2.60")),
            HostRecord(name="nas.home.example", address=ip("192.0.2.10")),
            HostRecord(name="ll.home.example", address=ip("fe80::1")),
        ],
    )
    clients = [
        client(RANDOM.format(0x60), addresses=[ip("192.0.2.60")], seg=None),
        client(REAL.format(0x10), addresses=[ip("192.0.2.10")], seg=None),
        client(RANDOM.format(0x61), addresses=[ip("fe80::1")], seg=None),
    ]
    (f,) = run(random_mac, gw(dns_services=[dns], clients=clients))
    assert f.message == (
        "The DNS name tablet.home.example points to 192.0.2.60, which a device with a "
        "randomised MAC address uses (02:00:00:00:00:60)"
    )
    assert f.objects == ["gw/dns/unbound", "client/02:00:00:00:00:60"]


def test_share_of_randomised_clients() -> None:
    clients = [
        client(RANDOM.format(1)),
        client(RANDOM.format(2)),
        client(REAL.format(3)),
        client(RANDOM.format(4), seg=IOT),
        client(REAL.format(5), seg=IOT),
        client(RANDOM.format(6), seg=None),
    ]
    found = run(random_mac, gw(clients=clients))
    assert [(f.severity, f.message) for f in found] == [
        (
            Severity.INFO,
            "1 of 2 known clients on IoT (VLAN 20) uses a randomised MAC address (50 %)",
        ),
        (
            Severity.INFO,
            "2 of 3 known clients on LAN (VLAN 10) use a randomised MAC address (67 %)",
        ),
    ]


def test_random_mac_stays_quiet_for_real_macs() -> None:
    res = [Reservation(mac=REAL.format(1), address=ip("192.0.2.40"))]
    clients = [client(REAL.format(1), addresses=[ip("192.0.2.40")])]
    dns = DnsService(
        id="gw/dns/unbound",
        device_id="gw",
        host_records=[HostRecord(name="nas.home.example", address=ip("192.0.2.40"))],
    )
    snap = gw(dhcp_servers=[dhcp(reservations=res)], clients=clients, dns_services=[dns])
    assert run(random_mac, snap) == []
