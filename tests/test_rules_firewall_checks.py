"""Rules that read the firewall model (#135): management exposure through the firewall (#120
level 2), port forwards (#125), double NAT with forwards on the inner router only (#60), guest and
IoT reach, zones."""

from typing import Any

from factories import (
    SITE,
    client,
    device,
    dhcp_server,
    firewall,
    fw_rule,
    iface,
    ip,
    policy,
    port_forward,
    ports,
    service,
    uplink,
    zone,
)
from factories import net as cidr
from signalbox.model import (
    DeviceRole,
    FirewallProtocol,
    Network,
    PortForward,
    Reservation,
    Segment,
    SegmentPurpose,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.addressing import double_nat
from signalbox.rules.firewall_checks import (
    RULES,
    duplicate_port_forward,
    forward_into_guest,
    port_forward_target,
    segment_without_zone,
    untrusted_reaches_lan,
)
from signalbox.rules.networks import management_exposure

LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)


def seg(sid: str, vlan: int | None, purpose: SegmentPurpose | None) -> Segment:
    return Segment(id=sid, site_id=SITE.id, vlan=vlan, purpose=purpose)


def sub(dev: str, sid: str, text: str) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{sid}", segment_id=sid, interface=iface(text), device_id=dev, gateway=True
    )


def make(**kw: Any) -> Network:
    kw.setdefault("sites", [SITE])
    kw.setdefault("devices", [device("gw")])
    kw.setdefault(
        "segments",
        [
            seg(LAN, None, SegmentPurpose.MAIN),
            seg(IOT, 20, SegmentPurpose.IOT),
            seg(GUEST, 30, SegmentPurpose.GUEST),
        ],
    )
    kw.setdefault(
        "subnets",
        [
            sub("gw", LAN, "192.0.2.1/24"),
            sub("gw", IOT, "198.51.100.1/24"),
            sub("gw", GUEST, "203.0.113.1/24"),
        ],
    )
    return Network(**kw)


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


def gw_firewall(*policies: Any, **kw: Any) -> Any:
    kw.setdefault("forward_policy", "reject")
    return firewall(
        "gw",
        zone("lan", LAN),
        zone("iot", IOT),
        zone("guest", GUEST),
        zone("wan", "gw/uplink/wan"),
        policies=list(policies),
        **kw,
    )


def test_registered() -> None:
    assert {r.id for r in RULES} == {
        "security.port-forward-target",
        "firewall.forward-into-guest",
        "firewall.duplicate-port-forward",
        "firewall.segment-without-zone",
        "firewall.untrusted-reaches-lan",
    }


# --- security.management-exposure, level 2 (#120) -------------------------------------------


def exposure(*policies: Any, **kw: Any) -> Network:
    return make(
        devices=[device("gw"), device("sw", DeviceRole.SWITCH, management_address="192.0.2.5")],
        services=[service("sw", "https"), service("sw", "ssh")],
        firewalls=[gw_firewall(*policies, **kw)],
    )


def test_management_through_the_firewall() -> None:
    (f,) = run(management_exposure, exposure(policy("iot", "lan", "accept")))
    assert f.severity == "error" and not f.incomplete
    assert f.message.startswith("HTTPS, SSH of sw (192.0.2.5) can be reached from VLAN 20 (IoT)")
    assert "through the firewall of gw" in f.message and f.objects[:2] == ["sw", IOT]
    only_ssh = fw_rule("accept", "iot", "lan", port=22, proto="tcp")
    (g,) = run(management_exposure, exposure(policy("iot", "lan", "reject"), rules=[only_ssh]))
    assert g.message.startswith("SSH of sw")


def test_management_through_the_firewall_quiet() -> None:
    assert run(management_exposure, exposure(policy("iot", "lan", "reject"))) == []
    vague = fw_rule("accept", "iot", "lan", exact=False)
    assert run(management_exposure, exposure(rules=[vague])) == []  # not sure: quiet
    # firewall not read: nothing to say here (the level 1 router case is "not checked")
    blind = exposure()
    blind.firewalls.clear()
    assert [f for f in run(management_exposure, blind) if not f.incomplete] == []
    # restricted by the device itself, layer 2, hostname, no services, isolated source
    open_ = policy("iot", "lan", "accept")
    limited = exposure(open_)
    limited.services[:] = [service("sw", "https", allowed_from=[cidr("192.0.2.0/24")])]
    assert run(management_exposure, limited) == []
    l2 = exposure(open_)
    l2.services[:] = [service("sw", "mac-telnet")]
    assert run(management_exposure, l2) == []
    named = exposure(open_)
    named.devices[1] = device("sw", DeviceRole.SWITCH, management_address="sw.example.test")
    assert run(management_exposure, named) == []
    none = exposure(open_)
    none.services.clear()
    assert run(management_exposure, none) == []
    isolated = exposure(open_)
    isolated.segments[1] = seg(IOT, 20, SegmentPurpose.IOT).model_copy(update={"isolated": True})
    isolated.segments[2] = seg(GUEST, 30, SegmentPurpose.IOT).model_copy(update={"isolated": True})
    assert run(management_exposure, isolated) == []


def test_management_router_with_read_firewall_is_not_reported_as_unknown() -> None:
    n = make(devices=[device("gw", management_address="192.0.2.1")], firewalls=[gw_firewall()])
    assert [f for f in run(management_exposure, n) if f.incomplete] == []
    n.firewalls.clear()
    assert [f for f in run(management_exposure, n) if f.incomplete]


# --- security.port-forward-target (#125) -----------------------------------------------------


def fwd_net(target: str, *, dhcp: bool = True, **kw: Any) -> Network:
    pf = kw.pop("forward", None) or port_forward(target, 8443, name="web")
    firewalls = [gw_firewall(port_forwards=[pf])]
    servers = [dhcp_server("gw")] if dhcp else []
    return make(firewalls=firewalls, dhcp_servers=servers, **kw)


def test_forward_to_dynamic_address() -> None:
    n = fwd_net("192.0.2.150")
    (f,) = [f for f in run(port_forward_target, n) if "dynamic" in f.message]
    assert f.message == (
        "gw forwards 'web' (TCP 8443) to 192.0.2.150, a dynamic DHCP address in untagged network"
    )
    assert "Reserve 192.0.2.150" in (f.fix or "")


def test_forward_to_reserved_or_fixed_address_is_quiet() -> None:
    n = fwd_net("192.0.2.150")
    n.dhcp_servers[0].reservations.append(
        Reservation(mac="02:00:00:00:00:01", address=ip("192.0.2.150"))
    )
    assert run(port_forward_target, n) == []
    outside_pool = fwd_net("192.0.2.20")
    assert run(port_forward_target, outside_pool) == []
    no_dhcp = fwd_net("192.0.2.150", dhcp=False)
    assert run(port_forward_target, no_dhcp) == []
    disabled = fwd_net("192.0.2.150", forward=port_forward("192.0.2.150", 80, enabled=False))
    assert run(port_forward_target, disabled) == []


def test_forward_to_unknown_address_and_network() -> None:
    n = fwd_net("192.0.2.20", clients=[client("02:00:00:00:00:02", "192.0.2.30", segment_id=LAN)])
    (f,) = run(port_forward_target, n)
    assert f.severity == "info" and f.message.endswith("but no known device uses that address")
    known = fwd_net(
        "192.0.2.30", clients=[client("02:00:00:00:00:02", "192.0.2.30", segment_id=LAN)]
    )
    assert run(port_forward_target, known) == []
    (g,) = run(port_forward_target, fwd_net("10.99.0.5"))
    assert g.message.endswith("which is in none of the networks Signalbox knows")
    assert run(port_forward_target, fwd_net("203.0.113.77", dhcp=False, subnets=[])) == []


def test_forward_to_iot_and_management() -> None:
    n = fwd_net("198.51.100.20", dhcp=False)
    (f,) = run(port_forward_target, n)
    assert f.severity == "info" and "in the iot network" in f.message
    mgmt = make(
        devices=[device("gw"), device("sw", DeviceRole.SWITCH, management_address="192.0.2.5")],
        services=[service("sw", "https"), service("sw", "ssh", enabled=False)],
        firewalls=[gw_firewall(port_forwards=[port_forward("192.0.2.5", 443, name="sw")])],
    )
    (g,) = run(port_forward_target, mgmt)
    assert g.severity == "error" and "sw offers HTTPS" in g.message
    other = mgmt.model_copy(
        update={"firewalls": [gw_firewall(port_forwards=[port_forward("192.0.2.5", 8080)])]}
    )
    assert run(port_forward_target, other) == []
    host = PortForward(target_address=ip("192.0.2.5"))  # exposed host
    exposed = mgmt.model_copy(update={"firewalls": [gw_firewall(port_forwards=[host])]})
    (h,) = run(port_forward_target, exposed)
    assert "exposed host" in h.message and h.severity == "error"
    mapped = mgmt.model_copy(
        update={
            "firewalls": [
                gw_firewall(
                    port_forwards=[port_forward("192.0.2.5", 8443, target_port=443, name="m")]
                )
            ]
        }
    )
    assert len(run(port_forward_target, mapped)) == 1


# --- firewall.forward-into-guest -------------------------------------------------------------


def test_forward_into_guest() -> None:
    n = fwd_net("203.0.113.50", dhcp=False)
    (f,) = run(forward_into_guest, n)
    assert "in the guest network" in f.message and f.objects == ["gw", "gw/firewall", GUEST]
    assert run(forward_into_guest, fwd_net("192.0.2.50", dhcp=False)) == []
    assert run(forward_into_guest, fwd_net("10.99.0.5", dhcp=False)) == []
    off = fwd_net("203.0.113.50", forward=port_forward("203.0.113.50", 80, enabled=False))
    assert run(forward_into_guest, off) == []


# --- firewall.duplicate-port-forward ---------------------------------------------------------


def dup_net(*forwards: PortForward) -> Network:
    return make(firewalls=[gw_firewall(port_forwards=list(forwards))])


def test_duplicate_forward() -> None:
    a = port_forward("192.0.2.20", 8443, name="a")
    b = port_forward("192.0.2.21", 8443, name="b")
    (f,) = run(duplicate_port_forward, dup_net(a, b))
    assert f.message == (
        "gw forwards external port 8443 twice: 'a' (TCP 8443) to 192.0.2.20 and 'b' "
        "(TCP 8443) to 192.0.2.21"
    )
    wide = port_forward("192.0.2.22", 8000, external_ports=ports((8000, 8500)), name="c")
    (g,) = run(duplicate_port_forward, dup_net(a, wide))
    assert "8443" in g.message


def test_duplicate_forward_quiet() -> None:
    a = port_forward("192.0.2.20", 8443, name="a")
    udp = port_forward("192.0.2.21", 8443, protocols=[FirewallProtocol.UDP])
    other_port = port_forward("192.0.2.21", 8444)
    off = port_forward("192.0.2.21", 8443, enabled=False)
    host = PortForward(target_address=ip("192.0.2.9"))
    wan2 = port_forward("192.0.2.21", 8443, zones=["wan2"])
    wan1 = port_forward("192.0.2.20", 8443, zones=["wan"])
    addr = port_forward("192.0.2.21", 8443, external_address=ip("198.51.100.9"))
    addr2 = port_forward("192.0.2.21", 8443, external_address=ip("198.51.100.8"))
    s1 = port_forward("192.0.2.21", 8443, sources=[cidr("203.0.113.0/24")])
    s2 = port_forward("192.0.2.20", 8443, sources=[cidr("198.51.100.0/24")])
    for pair in (
        (a, udp),
        (a, other_port),
        (a, off),
        (a, host),
        (wan1, wan2),
        (addr, addr2),
        (s1, s2),
    ):
        assert run(duplicate_port_forward, dup_net(*pair)) == []


# --- firewall.segment-without-zone -----------------------------------------------------------


def test_segment_without_zone() -> None:
    fw = firewall("gw", zone("lan", LAN), zone("wan", "gw/uplink/wan"))
    n = make(firewalls=[fw])
    found = run(segment_without_zone, n)
    assert sorted(f.objects[2] for f in found) == [IOT, GUEST]
    assert found[0].message.endswith("but no firewall zone covers it")


def test_segment_without_zone_quiet() -> None:
    assert run(segment_without_zone, make(firewalls=[gw_firewall()])) == []
    assert run(segment_without_zone, make()) == []  # not read
    lan = zone("lan", LAN)
    for fw in (
        firewall("gw", lan, rules_complete=False),
        firewall("gw", lan, enabled=False),
        firewall("gw", lan.model_copy(update={"complete": False})),
        firewall("gw", lan.model_copy(update={"ports": ["gw/port/br9"]})),
        firewall("gw"),
    ):
        assert run(segment_without_zone, make(firewalls=[fw])) == []


# --- firewall.untrusted-reaches-lan ----------------------------------------------------------


def test_untrusted_reaches_lan() -> None:
    n = make(firewalls=[gw_firewall(policy("iot", "lan", "accept"))])
    (f,) = run(untrusted_reaches_lan, n)
    assert "(iot) can reach" in f.message
    assert f.objects == ["gw", IOT, LAN] and "policy iot" in f.message
    both = make(
        firewalls=[gw_firewall(policy("iot", "lan", "accept"), policy("guest", "lan", "accept"))]
    )
    assert len(run(untrusted_reaches_lan, both)) == 2


def test_untrusted_reaches_lan_quiet() -> None:
    assert run(untrusted_reaches_lan, make(firewalls=[gw_firewall()])) == []
    assert run(untrusted_reaches_lan, make()) == []  # firewall not read
    some = fw_rule("accept", "iot", "lan", port=53, proto="udp")
    assert run(untrusted_reaches_lan, make(firewalls=[gw_firewall(rules=[some])])) == []
    vague = fw_rule("accept", "iot", "lan", exact=False)
    assert run(untrusted_reaches_lan, make(firewalls=[gw_firewall(rules=[vague])])) == []
    open_ = gw_firewall(policy("iot", "lan", "accept"))
    n = make(firewalls=[open_])
    n.segments[1] = seg(IOT, 20, SegmentPurpose.IOT).model_copy(update={"isolated": True})
    assert run(untrusted_reaches_lan, n) == []
    # target without a usable address, or not a main or management network
    n = make(firewalls=[open_], subnets=[sub("gw", IOT, "198.51.100.1/24")])
    assert run(untrusted_reaches_lan, n) == []
    n = make(firewalls=[open_])
    n.segments[0] = seg(LAN, None, SegmentPurpose.SERVERS)
    assert run(untrusted_reaches_lan, n) == []
    # a host that exists is not probed
    n = make(
        firewalls=[open_],
        clients=[client("02:00:00:00:00:03", "192.0.2.2", segment_id=LAN)],
    )
    assert len(run(untrusted_reaches_lan, n)) == 1


# --- addr.double-nat: forwards on the inner router only (#60) ---------------------------------


def nat_net(inner: PortForward | None, outer_fwd: PortForward | None, **kw: Any) -> Network:
    outer_fw = firewall(
        "fb",
        zone("lan", LAN),
        zone("wan", "fb/uplink/wan"),
        port_forwards=[outer_fwd] if outer_fwd else [],
        **kw.pop("outer", {}),
    )
    inner_fw = firewall(
        "gw",
        zone("lan", segment_id(SITE.id, 5)),
        zone("wan", "gw/uplink/wan"),
        port_forwards=[inner] if inner else [],
    )
    return Network(
        sites=[SITE],
        devices=[device("fb"), device("gw")],
        segments=[seg(LAN, None, SegmentPurpose.MAIN)],
        subnets=[sub("fb", LAN, "192.0.2.1/24")],
        uplinks=[uplink("fb"), uplink("gw", addresses=[iface("192.0.2.20/24")])],
        firewalls=[outer_fw, inner_fw],
    )


def dead(net: Network) -> list[Finding]:
    return [f for f in run(double_nat, net) if f.severity == "warning"]


def test_double_nat_forward_only_on_the_inner_router() -> None:
    inner = port_forward("10.0.0.5", 8443, name="web")
    (f,) = dead(nat_net(inner, None))
    assert f.message.startswith("gw forwards TCP 8443 to devices behind it, but fb")
    assert "exposed host" in (f.fix or "") and f.objects == ["gw", "fb", "gw/uplink/wan"]
    # the outer router does not forward that port
    (g,) = dead(nat_net(inner, port_forward("192.0.2.20", 9000)))
    assert "TCP 8443" in g.message
    # the info finding stays
    assert any(x.severity == "info" for x in run(double_nat, nat_net(inner, None)))


def test_double_nat_forward_passed_on_is_quiet() -> None:
    inner = port_forward("10.0.0.5", 8443, name="web")
    assert dead(nat_net(inner, port_forward("192.0.2.20", 8443))) == []
    mapped = port_forward("192.0.2.20", 9000, target_port=8443)
    assert dead(nat_net(inner, mapped)) == []
    exposed_host = PortForward(target_address=ip("192.0.2.20"))
    assert dead(nat_net(inner, exposed_host)) == []
    assert dead(nat_net(None, None)) == []
    assert dead(nat_net(port_forward("10.0.0.5", 80, enabled=False), None)) == []
    assert dead(nat_net(PortForward(target_address=ip("10.0.0.5")), None)) == []
    other_if = port_forward("10.0.0.5", 8443, zones=["lan"])
    assert dead(nat_net(other_if, None)) == []
    # unknown: the outer router's forwards were not fully read, or a firewall is missing
    assert dead(nat_net(inner, None, outer={"port_forwards_complete": False})) == []
    missing = nat_net(inner, None)
    missing.firewalls.pop(0)
    assert dead(missing) == []
    missing = nat_net(inner, None)
    missing.firewalls.pop(1)
    assert dead(missing) == []
    incomplete_inner = nat_net(inner, None)
    incomplete_inner.firewalls[1] = incomplete_inner.firewalls[1].model_copy(
        update={"port_forwards_complete": False}
    )
    assert dead(incomplete_inner) == []
    udp_only = port_forward("192.0.2.20", 8443, protocols=[FirewallProtocol.UDP])
    assert len(dead(nat_net(inner, udp_only))) == 1
