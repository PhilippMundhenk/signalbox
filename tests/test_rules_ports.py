"""Port rules (PVID, MTU, admin state, auto-negotiation, EEE, descriptions) and link.slow."""

from __future__ import annotations

from typing import Any

from factories import SITE, configured_port, device, iface, ip, port
from signalbox.model import (
    Client,
    DeviceRole,
    FrameTypes,
    Link,
    LinkKind,
    LinkOrigin,
    Membership,
    Neighbour,
    Network,
    Port,
    PortKind,
    PortMembership,
    Segment,
    Subnet,
    port_id,
    segment_id,
)
from signalbox.rules import Result, Severity, evaluate
from signalbox.rules.builtin import RULES
from signalbox.rules.ports import (
    admin_down_with_neighbour,
    autoneg_mismatch,
    client_port_mismatch,
    description_mismatch,
    eee_on_uplink,
    link_mtu,
    single_untagged,
)
from signalbox.rules.vlan import slow

T, U = Membership.TAGGED, Membership.UNTAGGED
LAN = segment_id(SITE.id, None)
IOT = segment_id(SITE.id, 20)
GUEST = segment_id(SITE.id, 30)
NAMES = {None: "LAN", 20: "IoT", 30: "Guest"}


def seg(vlan: int | None, **ports: Membership) -> Segment:
    """Members as ``sw_3=U`` (device ``sw``, port ``3``)."""
    return Segment(
        id=segment_id(SITE.id, vlan),
        site_id=SITE.id,
        vlan=vlan,
        name=NAMES.get(vlan),
        members=[
            PortMembership(port_id=port_id(*key.split("_", 1)), mode=m) for key, m in ports.items()
        ],
    )


def link(a: str, b: str, **kw: Any) -> Link:
    return Link(id=f"{a}~{b}", a=a, b=b, origin=kw.pop("origin", LinkOrigin.LLDP), **kw)


def subnet(vlan: int | None, cidr: str) -> Subnet:
    sid = segment_id(SITE.id, vlan)
    return Subnet(id=f"gw/subnet/{sid}", segment_id=sid, interface=iface(cidr), device_id="gw")


def network(ports: list[Port], **kw: Any) -> Network:
    devices = kw.pop(
        "devices",
        [
            device("gw"),
            device("sw", DeviceRole.SWITCH, name="core-switch"),
            device("ap", DeviceRole.AP, name="office-ap"),
        ],
    )
    return Network(sites=[SITE], devices=devices, ports=ports, **kw)


def run(r: Any, net: Network) -> list[Result]:
    return list(r.check(net))


SW1, GW1, AP1 = port_id("sw", "1"), port_id("gw", "1"), port_id("ap", "eth0")


def uplink(a: dict[str, Any] | None = None, b: dict[str, Any] | None = None, **kw: Any) -> Network:
    """gw/1 -- sw/1, both configured ports with overrides."""
    return network(
        [configured_port("gw", "1", **(a or {})), configured_port("sw", "1", **(b or {}))],
        links=[link(GW1, SW1, **kw)],
    )


# --- vlan.single-untagged ------------------------------------------------------------------


def test_single_untagged_two_untagged_vlans() -> None:
    net = network(
        [configured_port("sw", "3", pvid=20, description="desk")],
        segments=[seg(None, sw_3=U), seg(20, sw_3=U)],
    )
    (res,) = run(single_untagged, net)
    assert (
        res.message
        == "core-switch port 3 (desk) is untagged in IoT (VLAN 20) and LAN (untagged network)."
    )
    assert res.objects == (port_id("sw", "3"), IOT, LAN)
    assert res.key == "several"


def test_single_untagged_pvid_not_untagged_vlan() -> None:
    net = network(
        [configured_port("sw", "3", pvid=30)], segments=[seg(20, sw_3=U), seg(30, sw_3=T)]
    )
    (res,) = run(single_untagged, net)
    assert "sends IoT (VLAN 20) untagged" in res.message
    assert "into Guest (VLAN 30)" in res.message
    assert res.key == "pvid"
    assert evaluate(net, [single_untagged])[0].severity is Severity.ERROR


def test_single_untagged_quiet() -> None:
    segments = [seg(None, sw_3=U, sw_4=T, sw_5=T, sw_6=U), seg(20, sw_4=T, sw_5=T, ap_wlan0=U)]
    net = network(
        [
            configured_port("sw", "3"),  # PVID 1 = native = untagged LAN
            configured_port("sw", "4", pvid=20),  # tagged-only trunk: PVID unused
            configured_port("sw", "5", pvid=20, frame_types=FrameTypes.TAGGED_ONLY),
            port("sw", "6"),  # no PVID reported
            port("ap", "wlan0", kind=PortKind.WIRELESS),
        ],
        segments=[*segments, seg(30, ap_wlan0=U)],  # wireless ports carry several SSIDs
    )
    assert run(single_untagged, net) == []


# --- vlan.client-port-mismatch -------------------------------------------------------------


def client(mac: str, *addresses: str, on: str = port_id("sw", "6"), **kw: Any) -> Client:
    return Client(
        id=f"client/{mac}",
        mac=mac,
        addresses=[ip(a) for a in addresses],
        seen_on=on,
        source=device("sw").source,
        **kw,
    )


SUBNETS = [subnet(None, "192.0.2.1/24"), subnet(20, "198.51.100.1/24")]


def access_net(*clients: Client, p: Port | None = None, **kw: Any) -> Network:
    return network(
        [
            p or port("sw", "6"),
            configured_port("sw", "7"),
            port("ap", "wlan0", kind=PortKind.WIRELESS),
        ],
        segments=kw.pop("segments", [seg(None, sw_6=U, sw_7=U), seg(20)]),
        subnets=kw.pop("subnets", SUBNETS),
        clients=list(clients),
        **kw,
    )


def test_client_port_mismatch_access_port() -> None:
    net = access_net(client("02:00:00:00:00:01", "fe80::1", "198.51.100.40", hostname="nas"))
    (res,) = run(client_port_mismatch, net)
    assert res.message == (
        "nas is on core-switch port 6 (LAN (untagged network), access port) but uses "
        "198.51.100.40 in IoT (VLAN 20)."
    )


def test_client_port_mismatch_uses_pvid() -> None:
    # untagged in LAN, but the PVID puts the client's frames into the IoT network
    p = configured_port("sw", "6", pvid=20)
    net = access_net(client("02:00:00:00:00:01", "192.0.2.40"), p=p)
    (res,) = run(client_port_mismatch, net)
    assert "(IoT (VLAN 20), PVID) but uses 192.0.2.40 in LAN (untagged network)" in res.message
    assert res.message.startswith("02:00:00:00:00:01 is on")


def test_client_port_mismatch_quiet() -> None:
    ok = client("02:00:00:00:00:01", "192.0.2.40")
    assert run(client_port_mismatch, access_net(ok)) == []
    # several clients behind the port
    two = access_net(
        client("02:00:00:00:00:01", "198.51.100.40"), client("02:00:00:00:00:02", "192.0.2.41")
    )
    assert run(client_port_mismatch, two) == []
    # trunk port (tagged VLAN on it)
    trunk = access_net(
        client("02:00:00:00:00:01", "198.51.100.40"), segments=[seg(None, sw_6=U), seg(20, sw_6=T)]
    )
    assert run(client_port_mismatch, trunk) == []
    # uplink port, wireless, unknown port, no subnet for the port's network
    bad = client("02:00:00:00:00:01", "198.51.100.40")
    assert run(client_port_mismatch, access_net(bad, links=[link(port_id("sw", "6"), GW1)])) == []
    assert (
        run(
            client_port_mismatch,
            access_net(client("02:00:00:00:00:01", "198.51.100.40", on=port_id("ap", "wlan0"))),
        )
        == []
    )
    assert (
        run(
            client_port_mismatch,
            access_net(client("02:00:00:00:00:01", "198.51.100.40", on="ap/wlan/x")),
        )
        == []
    )
    assert run(client_port_mismatch, access_net(bad, subnets=SUBNETS[1:])) == []
    # addresses in two networks, or only link-local: addr.client-subnet's job
    both = client("02:00:00:00:00:01", "192.0.2.40", "198.51.100.40")
    assert run(client_port_mismatch, access_net(both)) == []
    assert run(client_port_mismatch, access_net(client("02:00:00:00:00:01", "169.254.3.4"))) == []
    # port in no or several untagged VLANs, tagged-only port
    assert run(client_port_mismatch, access_net(bad, segments=[seg(20)])) == []
    tagged_only = configured_port("sw", "6", frame_types=FrameTypes.TAGGED_ONLY)
    assert run(client_port_mismatch, access_net(bad, p=tagged_only)) == []
    # port of a device Signalbox does not know
    assert run(client_port_mismatch, access_net(bad, devices=[device("gw")])) == []


# --- link.mtu ------------------------------------------------------------------------------


def test_link_mtu_mismatch() -> None:
    (res,) = run(link_mtu, uplink({"mtu": 9000}))
    assert res.message == "gw port 1 has MTU 9000, the connected port core-switch port 1 MTU 1500."
    assert res.objects == (f"{GW1}~{SW1}", GW1, SW1)
    # a switch with only a jumbo flag against a router MTU
    (res,) = run(link_mtu, uplink({"mtu": 9000}, {"mtu": None, "jumbo": False}))
    assert "MTU 9000, the connected port core-switch port 1 jumbo frames off" in res.message
    (res,) = run(link_mtu, uplink({"mtu": None, "jumbo": True}, {"mtu": None, "jumbo": False}))
    assert "jumbo frames on" in res.message


def test_link_mtu_quiet() -> None:
    assert run(link_mtu, uplink()) == []
    assert run(link_mtu, uplink({"mtu": 9000}, {"mtu": None, "jumbo": True})) == []
    assert run(link_mtu, uplink({"mtu": 9000}, {"mtu": None})) == []  # unknown end
    assert run(link_mtu, uplink({"mtu": 9000}, kind=LinkKind.WIRELESS)) == []
    wlan = uplink({"mtu": 9000, "kind": PortKind.WIRELESS})
    assert run(link_mtu, wlan) == []
    missing = network([configured_port("gw", "1", mtu=9000)], links=[link(GW1, SW1)])
    assert run(link_mtu, missing) == []


# --- port.admin-down-with-neighbour --------------------------------------------------------


def test_admin_down_with_link_or_lldp() -> None:
    (res,) = run(admin_down_with_neighbour, uplink(b={"admin_up": False, "up": False}))
    assert res.message == "core-switch port 1 is disabled, but gw port 1 is connected to it."
    nb = Neighbour(
        id="sw/nb/3",
        local_port_id=port_id("sw", "3"),
        chassis_id="02:00:00:00:00:09",
        system_name="printer",
        source=device("sw").source,
    )
    net = network([configured_port("sw", "3", admin_up=False, up=False)], neighbours=[nb])
    (res,) = run(admin_down_with_neighbour, net)
    assert "printer is connected" in res.message


def test_admin_down_names_unknown_far_end() -> None:
    net = network(
        [configured_port("sw", "1", admin_up=False, up=False)], links=[link(SW1, "nas/port/eth0")]
    )
    (res,) = run(admin_down_with_neighbour, net)
    assert "but nas port eth0 is connected" in res.message


def test_admin_down_quiet() -> None:
    assert run(admin_down_with_neighbour, uplink()) == []
    lonely = network([configured_port("sw", "3", admin_up=False, up=False)])
    assert run(admin_down_with_neighbour, lonely) == []
    assert (
        run(admin_down_with_neighbour, uplink(b={"admin_up": False}, kind=LinkKind.WIRELESS)) == []
    )


# --- port.eee-on-uplink --------------------------------------------------------------------


def test_eee_on_uplink() -> None:
    (res,) = run(eee_on_uplink, uplink(b={"eee": True}))
    assert res.message.startswith("Energy-efficient Ethernet is on for core-switch port 1 (link")
    assert evaluate(uplink(b={"eee": True}), [eee_on_uplink])[0].severity is Severity.INFO


def test_eee_quiet() -> None:
    assert run(eee_on_uplink, uplink()) == []
    assert run(eee_on_uplink, uplink(b={"eee": None})) == []
    pc = network(
        [configured_port("sw", "1", eee=True), configured_port("pc", "eth0", eee=True)],
        devices=[device("sw", DeviceRole.SWITCH), device("pc", DeviceRole.OTHER)],
        links=[link(SW1, port_id("pc", "eth0"))],
    )
    assert run(eee_on_uplink, pc) == []  # EEE towards an end device is fine
    gw_only = network(
        [configured_port("sw", "1", eee=True), configured_port("x", "1", eee=True)],
        devices=[device("sw", DeviceRole.SWITCH)],
        links=[link(port_id("x", "1"), SW1)],
    )
    assert run(eee_on_uplink, gw_only) == []


# --- port.autoneg-mismatch -----------------------------------------------------------------


def test_autoneg_mismatch() -> None:
    net = uplink({"autoneg": False, "speed_mbps": 100, "full_duplex": True})
    (res,) = run(autoneg_mismatch, net)
    assert res.message == (
        "gw port 1 is set to a fixed 100 Mbit/s full duplex, the connected port core-switch "
        "port 1 uses auto-negotiation."
    )
    (res,) = run(autoneg_mismatch, uplink(b={"autoneg": False, "speed_mbps": None}))
    assert res.message.startswith("core-switch port 1 is set to a fixed speed,")
    (res,) = run(autoneg_mismatch, uplink(b={"autoneg": False, "full_duplex": None}))
    assert "a fixed 1000 Mbit/s, the" in res.message


def test_autoneg_quiet() -> None:
    assert run(autoneg_mismatch, uplink()) == []
    assert run(autoneg_mismatch, uplink({"autoneg": False}, {"autoneg": False})) == []
    assert run(autoneg_mismatch, uplink({"autoneg": False}, {"autoneg": None})) == []


# --- port.description-mismatch -------------------------------------------------------------


def test_description_mismatch() -> None:
    net = uplink(b={"description": "Uplink to office-ap"})
    (res,) = run(description_mismatch, net)
    assert res.message == (
        "The description of core-switch port 1 (Uplink to office-ap) names office-ap, but gw is "
        "connected to it."
    )


def test_description_quiet() -> None:
    for text in (
        "uplink gw",  # names the connected device (too short a name is not looked for anyway)
        "office desk",  # names no device
        "to core-switch",  # its own device
        "officeap",  # not the name as whole words
    ):
        assert run(description_mismatch, uplink(b={"description": text})) == [], text
    renamed = network(
        [configured_port("gw", "1"), configured_port("sw", "1", description="router office-ap")],
        devices=[
            device("gw", name="router"),
            device("sw", DeviceRole.SWITCH),
            device("ap", DeviceRole.AP, name="office-ap"),
        ],
        links=[link(GW1, SW1)],
    )
    assert run(description_mismatch, renamed) == []  # also names the connected device
    nb = Neighbour(
        id="sw/nb/1",
        local_port_id=SW1,
        chassis_id="02:00:00:00:00:09",
        system_name="office-ap",
        source=device("sw").source,
    )
    lldp = uplink(b={"description": "office-ap"})
    lldp = lldp.model_copy(update={"neighbours": [nb]})
    assert run(description_mismatch, lldp) == []  # LLDP sees the named device
    no_link = network([configured_port("sw", "1", description="office-ap")])
    assert run(description_mismatch, no_link) == []
    unknown_far = network(
        [configured_port("sw", "1", description="office-ap")], links=[link(SW1, "x/port/1")]
    )
    assert run(description_mismatch, unknown_far) == []
    assert (
        run(description_mismatch, uplink(b={"description": "office-ap"}, kind=LinkKind.WIRELESS))
        == []
    )


# --- link.slow with the maximum port speed --------------------------------------------------


def test_slow_below_port_maximum_is_info() -> None:
    net = uplink({"max_speed_mbps": 2500}, {"max_speed_mbps": 2500, "description": "core"})
    (res,) = run(slow, net)
    assert res.message == (
        "The link gw port 1 to core-switch port 1 (core) runs at 1000 Mbit/s, but both ports "
        "support 2500 Mbit/s."
    )
    assert (res.severity, res.key) == (Severity.INFO, "max-speed")


def test_slow_respects_port_maximum() -> None:
    # 100 Mbit/s on a 100 Mbit/s-only device: as fast as it goes
    fast_ethernet = uplink({"speed_mbps": 100, "max_speed_mbps": 100})
    assert run(slow, fast_ethernet) == []
    # 100 Mbit/s on two gigabit ports: still the cable warning
    (res,) = run(slow, uplink({"speed_mbps": 100}))
    assert res.severity is None and res.key == "speed"
    # 1G on a 2.5G and a 1G port, or one maximum unknown: fine
    assert run(slow, uplink({"max_speed_mbps": 2500})) == []
    assert run(slow, uplink({"max_speed_mbps": 2500}, {"max_speed_mbps": None})) == []
    # a single 10 Mbit/s-only port is not reported
    ten = network([configured_port("sw", "4", speed_mbps=10, max_speed_mbps=10)])
    assert run(slow, ten) == []
    (res,) = run(slow, network([configured_port("sw", "4", speed_mbps=10)]))
    assert res.severity is Severity.INFO


def test_builtin_includes_port_rules() -> None:
    ids = {r.id for r in RULES}
    assert {
        "vlan.single-untagged",
        "vlan.client-port-mismatch",
        "link.mtu",
        "port.admin-down-with-neighbour",
        "port.eee-on-uplink",
        "port.autoneg-mismatch",
        "port.description-mismatch",
    } <= ids
