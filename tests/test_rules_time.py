"""Clock, NTP and time zone rules (#129, #179): passing, failing and silent cases."""

from datetime import timedelta
from typing import Any

from factories import SITE, T0, device, device_time, iface, ip, ntp_server, snapshot
from signalbox.adapters import Capability
from signalbox.merge import merge
from signalbox.model import (
    DeviceRole,
    DeviceTime,
    DhcpServer,
    Network,
    NtpClient,
    Segment,
    Site,
    Subnet,
    segment_id,
)
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.time_checks import RULES, _public, _utc_offset

LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
AWAY = Site(id="away", name="Away")


def subnet(dev: str, address: str, seg: str = LAN, gateway: bool = False) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{address}",
        segment_id=seg,
        interface=iface(address),
        device_id=dev,
        gateway=gateway,
    )


def gw(time: DeviceTime | None = None, **kw: Any) -> Any:
    """The gateway 192.0.2.1 (LAN) and 198.51.100.1 (IoT), serving time unless told otherwise."""
    if time is None:
        time = device_time(
            ntp_client=NtpClient(enabled=True, servers=["pool.ntp.org"], synchronised=True),
            ntp_server=ntp_server(),
        )
    dev = device("gw", capabilities=[Capability.CLIENTS, Capability.DHCP], time=time, name="router")
    return snapshot(
        dev,
        segments=[
            Segment(id=LAN, site_id=SITE.id, name="LAN"),
            Segment(id=IOT, site_id=SITE.id, vlan=20, name="IoT"),
        ],
        subnets=[
            subnet("gw", "192.0.2.1/24", gateway=True),
            subnet("gw", "198.51.100.1/24", IOT, gateway=True),
        ],
        dhcp_servers=kw.pop("dhcp", []),
        **kw,
    )


def ap(i: int = 1, time: DeviceTime | None = None, **kw: Any) -> Any:
    dev = device(
        f"ap{i}",
        DeviceRole.AP,
        name=f"ap-{i}",
        time=time or device_time(),
        management_address=f"192.0.2.{10 + i}",
        **kw,
    )
    return snapshot(dev)


def dhcp(seg: str, *ntp: str) -> DhcpServer:
    return DhcpServer(
        id=f"gw/dhcp/{seg}",
        device_id="gw",
        segment_id=seg,
        enabled=True,
        ntp_servers=[ip(a) for a in ntp],
    )


def net(*snaps: Any) -> Network:
    return merge([SITE, AWAY], list(snaps))


def run(n: Network) -> list[tuple[str, str, str]]:
    return sorted((f.rule_id, f.severity.value, f.message) for f in evaluate(n, RULES))


def client(server: str) -> NtpClient:
    return NtpClient(enabled=True, servers=[server], synchronised=True)


def test_registered_and_good_site_is_quiet() -> None:
    assert {r.id for r in RULES} <= {r.id for r in BUILTIN}
    assert run(net(gw(dhcp=[dhcp(LAN, "192.0.2.1")]), ap(1), ap(2))) == []


def test_silent_without_data() -> None:
    bare = DeviceTime()
    dev = device("x", DeviceRole.SWITCH, name="sw")
    assert run(net(snapshot(dev), ap(1, bare), ap(2, DeviceTime(timezone="CET-1CEST")))) == []


def test_offset() -> None:
    out = run(
        net(
            gw(),
            ap(1, device_time(offset_seconds=-420)),
            ap(2, device_time(offset_seconds=60.04)),  # within 60 s + uncertainty
            ap(3, device_time(offset_seconds=90)),
            ap(4, device_time(offset_seconds=3 * 86400)),
            ap(5, device_time(offset_seconds=-5 * 3600)),
        )
    )
    assert [m for r, _, m in out if r == "time.offset"] == [
        "The clock of ap-1 is 7 minutes behind",
        "The clock of ap-3 is 90 seconds ahead",
        "The clock of ap-4 is 3 days ahead",
        "The clock of ap-5 is 5 hours behind",
    ]
    (f,) = evaluate(net(gw(), ap(1, device_time(-420))), RULES)
    assert f.severity == "warning" and "router (192.0.2.1) can serve time" in (f.fix or "")
    lone = evaluate(net(ap(1, device_time(-420))), RULES)
    assert [f.fix for f in lone] == [
        "Configure NTP on it and check that it can reach the NTP server."
    ]


def test_not_synchronised() -> None:
    off = device_time(ntp_client=NtpClient(enabled=False, servers=["192.0.2.1"]))
    empty = device_time(ntp_client=NtpClient(enabled=True))
    lost = device_time(
        ntp_client=NtpClient(enabled=True, servers=["192.0.2.1"], synchronised=False)
    )
    unknown = device_time(ntp_client=NtpClient(enabled=True, servers=["192.0.2.1"]))
    out = run(net(gw(), ap(1, off), ap(2, empty), ap(3, lost), ap(4, unknown)))
    assert out == [
        ("time.not-synchronised", "info", "ap-1 has no NTP server configured"),
        ("time.not-synchronised", "info", "ap-2 has no NTP server configured"),
        (
            "time.not-synchronised",
            "warning",
            "ap-3 is not synchronised with its NTP servers (192.0.2.1)",
        ),
    ]
    (f,) = evaluate(net(ap(1, off)), RULES)
    assert f.fix == "Turn on its NTP client with a server."


def test_ntp_unreachable() -> None:
    nobody = device_time(ntp_client=client("192.0.2.99"))  # in the LAN, no device uses it
    no_server = device_time(ntp_client=client("192.0.2.12"))  # ap-2 does not serve time
    other_seg = device_time(ntp_client=client("198.51.100.1"))  # gw serves only the LAN
    public = device_time(ntp_client=client("203.0.113.123"))  # outside known networks
    name = device_time(ntp_client=client("time.example"))
    gateway = gw(
        device_time(
            ntp_client=client("pool.ntp.org"),
            ntp_server=ntp_server(LAN),
        )
    )
    ap2 = ap(2, device_time(ntp_server=ntp_server(enabled=False)))
    out = run(
        net(
            gateway,
            ap(1, nobody),
            ap2,
            ap(3, no_server),
            ap(4, other_seg),
            ap(5, public),
            ap(6, name),
        )
    )
    assert [(s, m) for r, s, m in out if r == "time.ntp-unreachable"] == [
        (
            "warning",
            "ap-1 uses the NTP server 192.0.2.99, but no device on LAN (untagged network) uses "
            "that address",
        ),
        ("warning", "ap-3 uses the NTP server 192.0.2.12, but ap-2 does not serve time"),
        (
            "warning",
            "ap-4 uses the NTP server 198.51.100.1, but router does not serve time on IoT "
            "(VLAN 20)",
        ),
    ]


def test_ntp_unreachable_quiet_without_client_data() -> None:
    dev = device("gw", time=device_time(ntp_server=ntp_server()), name="router")
    snap = snapshot(
        dev,
        segments=[Segment(id=LAN, site_id=SITE.id, name="LAN")],
        subnets=[subnet("gw", "192.0.2.1/24", gateway=True)],
    )
    nobody = device_time(ntp_client=client("192.0.2.99"))
    unknown = device_time(ntp_client=client("192.0.2.1"))  # ntp_server not reported by gw
    plain = device("gw2", site_id="away", time=device_time(), name="other")
    assert run(net(snap, ap(1, nobody))) == []
    assert [r for r, _, _ in run(net(gw(DeviceTime()), ap(1, unknown), snapshot(plain)))] == []


def test_dhcp_ntp_mismatch() -> None:
    gateway = gw(
        device_time(ntp_client=client("pool.ntp.org"), ntp_server=ntp_server(LAN)),
        dhcp=[dhcp(LAN, "192.0.2.1", "192.0.2.77"), dhcp(IOT, "198.51.100.1", "203.0.113.5")],
    )
    disabled = dhcp(LAN, "192.0.2.66").model_copy(update={"enabled": False, "id": "gw/dhcp/off"})
    out = run(net(gateway.model_copy(update={"dhcp_servers": [*gateway.dhcp_servers, disabled]})))
    assert [(s, m) for r, s, m in out if r == "time.dhcp-ntp-mismatch"] == [
        (
            "warning",
            "router hands out the NTP server 192.0.2.77 on LAN (untagged network), but no device "
            "on LAN (untagged network) uses that address",
        ),
        (
            "warning",
            "router hands out the NTP server 198.51.100.1 on IoT (VLAN 20), but router does not "
            "serve time on IoT (VLAN 20)",
        ),
    ]


def test_no_local_ntp_with_a_local_server() -> None:
    out = run(
        net(
            gw(),
            ap(1, device_time(ntp_client=client("pool.ntp.org"))),
            ap(2, device_time(ntp_client=client("203.0.113.123"))),
            ap(3, device_time(ntp_client=client("ntp.home.example"))),  # may be local
            ap(4, device_time(ntp_client=client("192.0.2.1"))),
        )
    )
    assert out == [
        (
            "time.no-local-ntp",
            "info",
            "ap-1, ap-2 use only internet NTP servers, although router (192.0.2.1) serves time "
            "at Home",
        )
    ]


def test_no_local_ntp_without_a_server() -> None:
    internet = device_time(ntp_client=client("0.openwrt.pool.ntp.org"))
    no_server = device_time(
        ntp_client=client("time.cloudflare.com"), ntp_server=ntp_server(enabled=False)
    )
    (f,) = evaluate(net(gw(no_server), ap(1, internet)), RULES)
    assert f.rule_id == "time.no-local-ntp"
    assert f.message == "No device at Home serves time: ap-1 ask the internet"
    assert f.fix is not None and "Turn on the NTP server of router" in f.fix
    # the gateway does not say whether it serves time: quiet
    unknown = device_time(ntp_client=client("time.cloudflare.com"))
    assert run(net(gw(unknown), ap(1, internet))) == []
    assert run(net(ap(1, internet))) == []


def test_timezone() -> None:
    utc = device_time(timezone="UTC", utc_offset_minutes=None)
    posix = device_time(timezone="CET-1CEST,M3.5.0,M10.5.0/3", utc_offset_minutes=60)
    iana = device_time(timezone="Europe/Berlin", utc_offset_minutes=None)
    away = device("far", site_id="away", time=device_time(utc_offset_minutes=-300), name="far")
    out = run(net(gw(), ap(1, posix), ap(2, iana), ap(3, utc), snapshot(away)))
    assert out == [
        (
            "time.timezone",
            "info",
            "Devices at Home use 2 time zones (ap-3: UTC, UTC+00:00; ap-1: "
            "CET-1CEST,M3.5.0,M10.5.0/3, UTC+01:00; ap-2: Europe/Berlin, UTC+01:00; router: "
            "Europe/Berlin, UTC+01:00)",
        )
    ]
    assert run(net(gw(), ap(1, posix), ap(2, iana))) == []


def test_utc_offset_helper() -> None:
    assert _utc_offset(DeviceTime(timezone="America/New_York", clock=T0)) == -300
    assert _utc_offset(DeviceTime(timezone="Mars/Olympus", clock=T0)) is None
    assert _utc_offset(DeviceTime(timezone="EST5EDT", clock=T0)) is None
    assert _utc_offset(DeviceTime(timezone="Europe/Berlin")) is None
    assert _utc_offset(DeviceTime(utc_offset_minutes=-90, timezone=None)) == -90
    summer = DeviceTime(timezone="Europe/Berlin", read_at=T0 + timedelta(days=180))
    assert _utc_offset(summer) == 120


def test_public_helper() -> None:
    n = net(gw())
    assert _public(n, "pool.ntp.org") and _public(n, "de.pool.ntp.org.")
    assert _public(n, "time.google.com") and not _public(n, "fritz.box")
    assert _public(n, "203.0.113.1") and not _public(n, "192.0.2.1")  # in the LAN
    assert not _public(n, "192.168.1.1") and not _public(n, "fd00::1")
