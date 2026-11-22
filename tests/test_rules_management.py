"""Management service rules (#122, #123, #120 level 1, #127)."""

from typing import Any

from factories import (
    SITE,
    device,
    iface,
    mikrotik_default_services,
    service,
    snmp,
    uplink,
)
from factories import (
    net as cidr,
)
from signalbox.model import (
    Client,
    DeviceRole,
    Network,
    Segment,
    SegmentPurpose,
    Subnet,
    Wlan,
    segment_id,
)
from signalbox.rules import Finding, Rule, Severity, evaluate
from signalbox.rules.management import (
    RULES,
    insecure_services,
    plaintext_read,
    service_exposure,
    wan_management,
)

LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)


def seg(sid: str, vlan: int | None, purpose: SegmentPurpose | None = None, **kw: Any) -> Segment:
    return Segment(id=sid, site_id=SITE.id, vlan=vlan, purpose=purpose, **kw)


def sub(dev: str, sid: str, cidr: str) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{sid}", segment_id=sid, interface=iface(cidr), device_id=dev, gateway=True
    )


def make(**kw: Any) -> Network:
    kw.setdefault("sites", [SITE])
    kw.setdefault("devices", [device("gw")])
    return Network(**kw)


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def test_registered() -> None:
    assert {r.id for r in RULES} == {
        "security.insecure-services",
        "security.wan-management",
        "security.service-exposure",
        "security.plaintext-read",
    }


# --- insecure-services ---------------------------------------------------------------------


def test_mikrotik_defaults() -> None:
    n = make(services=mikrotik_default_services("gw"))
    (f,) = run(insecure_services, n)
    assert f.severity == "warning"
    assert (
        f.message
        == "gw has FTP, MAC telnet, Telnet and HTTP (www) without redirect to HTTPS enabled"
    )
    assert "gw/service/telnet" in f.objects


def test_snmp_root_password_mac_telnet() -> None:
    sv = [
        service("gw", "snmp", snmp=snmp("1", default_community=True)),
        service("gw", "ssh", password_login=True, root_login=True),
        service("gw", "mac-telnet"),
    ]
    (f,) = run(insecure_services, make(services=sv))
    assert "default community" in f.message and "root with a password" in f.message
    assert "MAC telnet" in f.message


def test_restricted_is_info() -> None:
    sv = [service("gw", "telnet", allowed_from=[cidr("192.0.2.0/24")])]
    (f,) = run(insecure_services, make(services=sv))
    assert f.severity == Severity.INFO and "limited" in f.message


def test_insecure_services_quiet() -> None:
    sv = [
        service("gw", "telnet", enabled=False),
        service("gw", "http", redirects_to_https=True),
        service("gw", "https"),
        service("gw", "ssh", password_login=False, root_login=True),
        service("gw", "snmp", snmp=snmp("2c")),
        service("gw", "snmp", "snmp3", snmp=snmp("3", default_community=True)),
    ]
    assert run(insecure_services, make(services=sv)) == []
    assert run(insecure_services, make()) == []


# --- wan-management ------------------------------------------------------------------------


def test_wan_reported_by_device() -> None:
    sv = [service("gw", "https", "remote-access", from_wan=True, port=8443)]
    n = make(services=sv, uplinks=[uplink("gw")])
    (f,) = run(wan_management, n)
    assert f.severity == "error" and "HTTPS (remote-access) (port 8443)" in f.message


def test_wan_unknown_is_incomplete() -> None:
    n = make(services=[service("gw", "ssh")], uplinks=[uplink("gw")])
    (f,) = run(wan_management, n)
    assert f.incomplete and "firewall" in f.message


def test_wan_quiet() -> None:
    sv = [service("gw", "ssh"), service("gw", "https", from_wan=False)]
    assert run(wan_management, make(services=sv)) == []  # no uplink reported
    ap = make(
        devices=[device("ap", DeviceRole.AP)],
        services=[service("ap", "ssh")],
        uplinks=[uplink("ap")],
    )
    assert run(wan_management, ap) == []
    off = make(services=[service("gw", "ssh", enabled=False)], uplinks=[uplink("gw")])
    assert run(wan_management, off) == []
    assert run(wan_management, make(services=[service("x", "ssh")], uplinks=[uplink("x")])) == []


# --- service-exposure ----------------------------------------------------------------------


def exposure_net(**kw: Any) -> Network:
    return make(
        segments=[seg(LAN, None, SegmentPurpose.MAIN), seg(IOT, 20, SegmentPurpose.IOT)],
        subnets=[sub("gw", LAN, "192.0.2.1/24"), sub("gw", IOT, "198.51.100.1/24")],
        **kw,
    )


def test_router_in_iot_is_incomplete() -> None:
    (f,) = run(service_exposure, exposure_net(services=[service("gw", "https")]))
    assert f.incomplete and "gw has an address in" in f.message and IOT in f.objects


def test_service_bound_to_iot_is_error() -> None:
    sv = [service("gw", "ssh", segments=[IOT])]
    (f,) = run(service_exposure, exposure_net(services=sv))
    assert f.severity == "error" and f.message.startswith("gw offers SSH in")


def test_service_exposure_quiet() -> None:
    n = exposure_net(services=[service("gw", "ssh", segments=[LAN]), service("gw", "https")])
    sv = [service("gw", "ssh", enabled=False)]
    assert run(service_exposure, exposure_net(services=sv)) == []
    assert [f for f in run(service_exposure, n) if not f.incomplete] == []
    isolated = exposure_net(services=[service("gw", "ssh", segments=[IOT])])
    isolated.segments[1] = seg(IOT, 20, SegmentPurpose.IOT, isolated=True)
    assert run(service_exposure, isolated) == []
    ap = exposure_net(devices=[device("ap", DeviceRole.AP)], services=[service("ap", "ssh")])
    assert run(service_exposure, ap) == []
    assert run(service_exposure, exposure_net(services=[service("x", "ssh")])) == []


# --- plaintext-read ------------------------------------------------------------------------


def plain_net(purpose: SegmentPurpose, **kw: Any) -> Network:
    return make(
        devices=[
            device(
                "sw", DeviceRole.SWITCH, management_address="192.0.2.5", transport_encrypted=False
            )
        ],
        segments=[seg(LAN, None, purpose)],
        subnets=[sub("gw", LAN, "192.0.2.1/24")],
        **kw,
    )


def wlan() -> Wlan:
    return Wlan(
        id="ap/wlan/a",
        device_id="ap",
        ssid="Home",
        radio_id="ap/radio/0",
        segment_id=LAN,
        security="wpa2-psk",
    )


def client(n: int) -> Client:
    return Client(id=f"c{n}", mac=f"02:00:00:00:00:{n:02x}", segment_id=LAN)


def test_plaintext_read_clients_and_ssids() -> None:
    n = plain_net(SegmentPurpose.MAIN, clients=[client(1), client(2)], wlans=[wlan()])
    (f,) = run(plaintext_read, n)
    assert f.severity == "info"
    assert "where 2 clients and 1 Wi-Fi network are" in f.message
    (g,) = run(plaintext_read, plain_net(SegmentPurpose.IOT, clients=[client(1)]))
    assert g.severity == "warning" and "1 client are" in g.message


def test_plaintext_read_quiet() -> None:
    assert run(plaintext_read, plain_net(SegmentPurpose.MANAGEMENT)) == []
    n = plain_net(SegmentPurpose.MAIN, clients=[client(1)])
    n.devices[0] = n.devices[0].model_copy(update={"transport_encrypted": True})
    assert run(plaintext_read, n) == []
    n.devices[0] = n.devices[0].model_copy(
        update={"transport_encrypted": False, "management_address": None}
    )
    assert run(plaintext_read, n) == []
