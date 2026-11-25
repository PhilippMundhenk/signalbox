"""Port access control, MAC filters and RADIUS servers (#162, ADR 0030): readers and rules.

The readers are tested on their rows; the OpenWrt reader also through its simulator, where a
RADIUS shared secret must never reach the model, the logs or the API output.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, device, port, wlan
from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import access as mt
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt import access as ow
from signalbox.adapters.opnsense import radius as opn
from signalbox.adapters.snmp import mapping, mib
from signalbox.adapters.unifi import access as ui
from signalbox.model import (
    AccessControlMode,
    DeviceRole,
    MacFilter,
    MacFilterMode,
    Membership,
    Network,
    PortAccessControl,
    PortAuthState,
    PortMembership,
    RadiusEndpoint,
    RadiusPurpose,
    RadiusRef,
    RadiusServer,
    Route,
    Security,
    Segment,
    Subnet,
    segment_id,
)
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.access_control import (
    dot1x_trunk,
    enterprise_consistent,
    mac_filter_as_security,
    radius_unreachable,
)
from signalbox.sim.openwrt import RADIUS_SECRET, OpenWrtSim, create_app
from signalbox.sim.server import serve
from signalbox.testing import SIM_SECRET_MARKER, assert_contract

SECRET = "never-ever-leak-this"

# --- readers: no secrets, only bools -----------------------------------------------------------


def test_the_simulator_secrets_carry_the_marker() -> None:
    assert SIM_SECRET_MARKER in RADIUS_SECRET


def test_openwrt_section_reader_keeps_no_secret_and_no_mac() -> None:
    s = {
        "macfilter": "allow",
        "maclist": ["02:00:00:00:99:01", "02:00:00:00:99:02"],
        "auth_server": "192.0.2.53",
        "auth_port": "1812",
        "auth_secret": SECRET,
        "acct_server": "192.0.2.53",
        "acct_port": "1813",
        "acct_secret": SECRET,
        "dynamic_vlan": "2",
    }
    assert ow.mac_filter(s) == MacFilter(mode=MacFilterMode.ALLOW, count=2)
    ref = ow.radius_ref(s)
    assert ref is not None and ref.secret_set is True
    assert ref.auth == [RadiusEndpoint(address="192.0.2.53", port=1812)]
    assert ow.dynamic_vlan(s) is True and ow.dynamic_vlan({}) is None
    (server,) = ow.servers([ref])
    assert server.purposes == [RadiusPurpose.WLAN] and server.acct_port == 1813
    text = ref.model_dump_json() + server.model_dump_json()
    assert SECRET not in text and "02:00:00:00:99" not in text
    assert ow.mac_filter({"macfilter": "disable"}) is None
    assert ow.radius_ref({"auth_server": ""}) is None
    assert ow.mac_filter(
        {"macfilter": "deny", "maclist": "02:00:00:00:99:01 02:00:00:00:99:02"}
    ) == (MacFilter(mode=MacFilterMode.DENY, count=2))


@pytest.fixture
def openwrt_url() -> Iterator[str]:
    sim = OpenWrtSim()
    sim.enterprise = True
    with serve(create_app(sim)) as url:
        yield url


async def test_openwrt_enterprise_ssid_secret_never_leaves_the_adapter(
    openwrt_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    ctx = AdapterContext(
        site_id="home",
        device_id="ap1",
        device_name="AP 1",
        role=DeviceRole.AP,
        config=OpenWrtConfig(url=f"{openwrt_url}/ubus", password=SecretStr(OpenWrtSim().password)),
    )
    adapter = OpenWrtAdapter(ctx)
    try:
        snap = await assert_contract(adapter)
        obs = await adapter.read_wireless()
    finally:
        await adapter.close()
    corp = next(w for w in snap.wlans if w.ssid == "Example-Corp")
    assert corp.security is Security.WPA2_ENTERPRISE
    assert corp.radius is not None and corp.radius.secret_set is True
    assert [(e.address, e.port) for e in corp.radius.auth] == [("192.0.2.53", 1812)]
    assert corp.mac_filter == MacFilter(mode=MacFilterMode.DENY, count=2)
    assert corp.dynamic_vlan is True
    assert snap.device.radius_servers is not None
    assert [s.address for s in snap.device.radius_servers] == ["192.0.2.53"]
    iot = next(w for w in snap.wlans if w.ssid == "Example-IoT")
    assert iot.radius is None
    # the shared secret and the MAC list are nowhere: model, API output, logs
    network = Network(sites=[SITE], devices=[snap.device], wlans=snap.wlans)
    texts = [
        snap.model_dump_json(),
        obs.model_dump_json(),
        network.model_dump_json(),
        repr(snap),
        caplog.text,
    ]
    for text in texts:
        assert RADIUS_SECRET not in text and "02:00:00:00:99:01" not in text


def test_mikrotik_radius_dot1x_and_access_list() -> None:
    servers = mt.radius_servers(
        [
            {
                "address": "192.0.2.53",
                "service": "wireless,dot1x,login",
                "authentication-port": "1812",
                "accounting-port": "1813",
                "secret": SECRET,
                "comment": "office",
            },
            {"address": "192.0.2.54", "service": "ppp", "disabled": "true"},
            {"address": "", "service": "login"},
        ]
    )
    (s,) = servers
    assert (s.name, s.auth_port, s.acct_port, s.secret_set) == ("office", 1812, 1813, True)
    assert s.purposes == [RadiusPurpose.WLAN, RadiusPurpose.DOT1X, RadiusPurpose.LOGIN]
    assert SECRET not in s.model_dump_json()
    ref = mt.wlan_radius(servers)
    assert ref is not None and ref.secret_set is True
    assert mt.wlan_radius([]) is None
    ports = mt.dot1x_ports(
        [
            {"interface": "ether2", "auth-types": "dot1x,mac-auth", "guest-vlan-id": "30"},
            {"interface": "ether3", "auth-types": "mac-auth", "reject-vlan-id": "99"},
            {"interface": "ether4", "disabled": "true"},
            {"interface": "ether5"},
        ]
    )
    assert (
        ports["ether2"].mode is AccessControlMode.DOT1X_OR_MAC and ports["ether2"].guest_vlan == 30
    )
    assert (
        ports["ether3"].mode is AccessControlMode.MAC_AUTH and ports["ether3"].auth_fail_vlan == 99
    )
    assert "ether4" not in ports and ports["ether5"].mode is AccessControlMode.DOT1X
    assert mt.learning_off({"learn": "no"}) == PortAccessControl(
        mode=AccessControlMode.STATIC_MACS, sticky=False
    )
    assert mt.learning_off({"learn": "yes"}) is None
    allow = [
        {"mac-address": "02:00:00:00:99:01", "action": "accept"},
        {"mac-address": "02:00:00:00:99:02", "action": "accept"},
        {"action": "reject"},
    ]
    assert mt.mac_filter(allow, "wifi1") == MacFilter(mode=MacFilterMode.ALLOW, count=2)
    deny = [{"mac-address": "02:00:00:00:99:03", "action": "reject", "interface": "wifi1"}]
    assert mt.mac_filter(deny, "wifi1") == MacFilter(mode=MacFilterMode.DENY, count=1)
    assert mt.mac_filter(deny, "wifi2") is None
    assert mt.mac_filter([{"signal-range": "-80..120"}], "wifi1") is None


def test_unifi_profiles_filters_and_port_security() -> None:
    profile = {
        "_id": "r1",
        "name": "Office",
        "auth_servers": [{"ip": "192.0.2.53", "port": 1812, "x_secret": SECRET}],
        "acct_servers": [{"ip": "192.0.2.53", "port": 1813, "x_secret": SECRET}],
    }
    ref = ui.ref_of(profile)
    (server,) = ui.servers_of([profile])
    assert ref is not None and ref.secret_set is True and ref.acct[0].port == 1813
    assert server.name == "Office" and server.secret_set is True
    assert SECRET not in ref.model_dump_json() + server.model_dump_json()
    assert ui.ref_of({"auth_servers": []}) is None
    conf = {"mac_filter_enabled": True, "mac_filter_policy": "deny", "mac_filter_list": ["a", "b"]}
    assert ui.mac_filter(conf) == MacFilter(mode=MacFilterMode.DENY, count=2)
    assert ui.mac_filter({"mac_filter_enabled": False}) is None
    assert ui.port_access({"dot1x_ctrl": "auto"}, {}) == PortAccessControl(
        mode=AccessControlMode.DOT1X
    )
    mac = ui.port_access({"dot1x_ctrl": "mac_based"}, {})
    assert mac is not None and mac.mode is AccessControlMode.MAC_AUTH
    sec = ui.port_access({}, {"port_security_enabled": True, "port_security_mac_address": ["a"]})
    assert sec == PortAccessControl(mode=AccessControlMode.STATIC_MACS, max_macs=1)
    assert ui.port_access({"dot1x_ctrl": "force_authorized"}, {}) is None


def test_opnsense_lists_only_radius_servers_without_the_secret() -> None:
    rows: list[dict[str, Any]] = [
        {
            "name": "Office",
            "type": "radius",
            "host": "192.0.2.53",
            "radius_auth_port": "1812",
            "radius_secret": SECRET,
        },
        {"name": "Directory", "type": "ldap", "host": "192.0.2.54"},
    ]
    (s,) = opn.servers(rows)
    assert (s.address, s.auth_port, s.secret_set) == ("192.0.2.53", 1812, True)
    assert SECRET not in s.model_dump_json()


def test_snmp_dot1x_per_port() -> None:
    pmap = mapping.PortMap(by_if={1: "sw/port/1", 2: "sw/port/2", 3: "sw/port/3"})
    data = mapping.Mib(
        walks={
            f"{mib.PAE_AUTH}.{mib.PAE_AUTH_PORT_CONTROL}": {
                f"{mib.PAE_AUTH}.{mib.PAE_AUTH_PORT_CONTROL}.1": 2,
                f"{mib.PAE_AUTH}.{mib.PAE_AUTH_PORT_CONTROL}.2": 3,
                f"{mib.PAE_AUTH}.{mib.PAE_AUTH_PORT_CONTROL}.3": 2,
            },
            f"{mib.PAE_AUTH}.{mib.PAE_AUTH_PORT_STATUS}": {
                f"{mib.PAE_AUTH}.{mib.PAE_AUTH_PORT_STATUS}.1": 1,
                f"{mib.PAE_AUTH}.{mib.PAE_AUTH_PORT_STATUS}.3": 2,
            },
        }
    )
    got = mapping.access_control(pmap, data)
    assert set(got) == {"sw/port/1", "sw/port/3"}  # port 2 is forced authorised: not 802.1X
    assert got["sw/port/1"].state is PortAuthState.AUTHORISED
    assert got["sw/port/3"].state is PortAuthState.UNAUTHORISED
    assert mapping.access_control(pmap, mapping.Mib()) == {}


# --- rules ---------------------------------------------------------------------------------------


def run(r: Rule, n: Network) -> list[Finding]:
    return [f for f in evaluate(n, [r]) if f.rule_id == r.id]


LAN = segment_id(SITE.id, None)


def subnet(cidr: str) -> Subnet:
    from ipaddress import ip_interface

    return Subnet(
        id=f"gw/subnet/{cidr}", segment_id=LAN, interface=ip_interface(cidr), device_id="gw"
    )


def enterprise(dev: str, ssid: str = "Corp", *servers: tuple[str, int | None], **kw: Any) -> Any:
    ref = RadiusRef(auth=[RadiusEndpoint(address=a, port=p) for a, p in servers], secret_set=True)
    return wlan(dev, ssid, security=Security.WPA2_ENTERPRISE, radius=ref, **kw)


def test_radius_unreachable_private_address_outside_every_network() -> None:
    ap = device("ap", DeviceRole.AP)
    n = Network(
        sites=[SITE],
        devices=[ap],
        subnets=[subnet("192.0.2.1/24")],
        wlans=[enterprise("ap", "Corp", ("198.51.100.7", 1812))],
    )
    (f,) = run(radius_unreachable, n)
    assert f.message_id == "radius.unreachable" and f.params["address"] == "198.51.100.7"
    assert f.objects == ["ap"]


def test_radius_unreachable_is_quiet_for_known_public_named_and_routed_servers() -> None:
    ap = device("ap", DeviceRole.AP)
    inside = enterprise("ap", "A", ("192.0.2.53", 1812))
    public = enterprise("ap", "B", ("8.8.8.8", 1812))
    named = enterprise("ap", "C", ("radius.example.invalid", 1812))
    for w in (inside, public, named):
        n = Network(sites=[SITE], devices=[ap], subnets=[subnet("192.0.2.1/24")], wlans=[w])
        assert run(radius_unreachable, n) == []
    outside = enterprise("ap", "D", ("198.51.100.7", 1812))
    base: dict[str, Any] = {"sites": [SITE], "devices": [ap], "wlans": [outside]}
    assert run(radius_unreachable, Network(**base)) == []  # no subnet known
    route = Route(
        id="gw/route/1", device_id="gw", destination="198.51.100.0/24", gateway="192.0.2.2"
    )
    n = Network(**base, subnets=[subnet("192.0.2.1/24")], routes=[route])
    assert run(radius_unreachable, n) == []


def test_radius_unreachable_reads_the_servers_of_a_device_too() -> None:
    sw = device(
        "sw",
        DeviceRole.SWITCH,
        radius_servers=[
            RadiusServer(name="r", address="198.51.100.7", purposes=[RadiusPurpose.DOT1X]),
            RadiusServer(name="v", address="198.51.100.8", purposes=[RadiusPurpose.VPN]),
        ],
    )
    n = Network(sites=[SITE], devices=[sw], subnets=[subnet("192.0.2.1/24")])
    (f,) = run(radius_unreachable, n)
    assert f.params["address"] == "198.51.100.7"


def test_dot1x_on_a_trunk_port() -> None:
    sw = device("sw", DeviceRole.SWITCH)
    trunk = port("sw", "1", access_control=PortAccessControl(mode=AccessControlMode.DOT1X))
    desk = port("sw", "2", access_control=PortAccessControl(mode=AccessControlMode.DOT1X))
    sticky = port("sw", "3", access_control=PortAccessControl(mode=AccessControlMode.STATIC_MACS))
    plain = port("sw", "4")
    seg = Segment(
        id=segment_id(SITE.id, 20),
        site_id=SITE.id,
        vlan=20,
        name="IoT",
        members=[
            PortMembership(port_id=trunk.id, mode=Membership.TAGGED),
            PortMembership(port_id=desk.id, mode=Membership.UNTAGGED),
            PortMembership(port_id=sticky.id, mode=Membership.TAGGED),
            PortMembership(port_id=plain.id, mode=Membership.TAGGED),
        ],
    )
    n = Network(sites=[SITE], devices=[sw], ports=[trunk, desk, sticky, plain], segments=[seg])
    (f,) = run(dot1x_trunk, n)
    assert f.message_id == "port.dot1xTrunk" and f.objects == [trunk.id]


def test_mac_filter_on_an_open_ssid_is_info_and_only_for_allow_lists() -> None:
    allow = MacFilter(mode=MacFilterMode.ALLOW, count=3)
    ap = device("ap", DeviceRole.AP)
    open_ = wlan("ap", "Open", security=Security.OPEN, mac_filter=allow)
    deny = wlan(
        "ap", "Deny", security=Security.OPEN, mac_filter=MacFilter(mode=MacFilterMode.DENY, count=1)
    )
    psk = wlan("ap", "Psk", security=Security.WPA2, mac_filter=allow)
    bare = wlan("ap", "Bare", security=Security.OPEN)
    n = Network(sites=[SITE], devices=[ap], wlans=[open_, deny, psk, bare])
    (f,) = run(mac_filter_as_security, n)
    assert f.message_id == "wifi.macFilterAsSecurity" and f.params["ssid"] == "Open"
    assert f.params["count"] == 3
    off = Network(sites=[SITE], devices=[ap], wlans=[open_.model_copy(update={"enabled": False})])
    assert run(mac_filter_as_security, off) == []


def test_enterprise_ssid_with_different_radius_servers_per_ap() -> None:
    a, b = device("ap1", DeviceRole.AP), device("ap2", DeviceRole.AP)
    same = [
        enterprise("ap1", "Corp", ("192.0.2.53", 1812)),
        enterprise("ap2", "Corp", ("192.0.2.53", None)),
    ]
    assert run(enterprise_consistent, Network(sites=[SITE], devices=[a, b], wlans=same)) == []
    differ = [
        enterprise("ap1", "Corp", ("192.0.2.53", 1812)),
        enterprise("ap2", "Corp", ("192.0.2.54", 1812)),
        enterprise("ap2", "Other", ("192.0.2.54", 1812)),
    ]
    (f,) = run(enterprise_consistent, Network(sites=[SITE], devices=[a, b], wlans=differ))
    assert f.message_id == "wifi.enterpriseInconsistent" and f.params["ssid"] == "Corp"
    assert len(f.objects) == 2
    unknown = [
        wlan("ap1", "Corp", security=Security.WPA2_ENTERPRISE),
        enterprise("ap2", "Corp", ("192.0.2.54", 1812)),
    ]
    assert run(enterprise_consistent, Network(sites=[SITE], devices=[a, b], wlans=unknown)) == []
