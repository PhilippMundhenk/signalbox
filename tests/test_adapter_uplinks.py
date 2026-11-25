"""WAN uplinks (#148) as each adapter reads them from its simulator.

The model, the NAT class and the contract checks are tested in test_uplinks.py; here: what the
vendor answers become, the connection kinds each simulator can show, and the refused paths.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Network, ip_address, ip_interface
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import Adapter, AdapterConfig, AdapterContext
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig, wan_uplink
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.omada import OmadaAdapter, OmadaConfig
from signalbox.adapters.omada import wan_uplink as omada_uplink
from signalbox.adapters.openwrt import NetworkView, OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense import wan_uplink as opnsense_uplink
from signalbox.model import DeviceRole, NatClass, Port, Uplink, UplinkKind, port_id
from signalbox.sim import mikrotik, omada, opnsense
from signalbox.sim.fritzbox import FritzboxSim
from signalbox.sim.fritzbox import create_app as fritzbox_app
from signalbox.sim.openwrt import OpenWrtSim
from signalbox.sim.openwrt import create_app as openwrt_app
from signalbox.sim.server import serve
from signalbox.testing import assert_contract, uplink_problems


def _context(config: AdapterConfig, role: DeviceRole = DeviceRole.GATEWAY) -> AdapterContext:
    return AdapterContext(
        site_id="home", device_id="gw", device_name="Gateway", role=role, config=config
    )


async def _uplinks(adapter: Adapter) -> list[Uplink]:
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    return snap.uplinks


def _recent(since: datetime | None, seconds: int) -> bool:
    expected = datetime.now(UTC) - timedelta(seconds=seconds)
    return since is not None and abs((since - expected).total_seconds()) < 30


# --- OpenWrt -----------------------------------------------------------------------------------


@pytest.fixture
def openwrt_sim() -> Iterator[tuple[OpenWrtSim, str]]:
    sim = OpenWrtSim(router=True)
    with serve(openwrt_app(sim)) as url:
        yield sim, url


def _openwrt(url: str, role: DeviceRole = DeviceRole.GATEWAY) -> OpenWrtAdapter:
    password = SecretStr(OpenWrtSim().password)
    config = OpenWrtConfig(url=f"{url}/ubus", password=password, allow_insecure_http=True)
    return OpenWrtAdapter(_context(config, role))


async def test_openwrt_wan_and_wan6_are_one_uplink(openwrt_sim: tuple[OpenWrtSim, str]) -> None:
    [up] = await _uplinks(_openwrt(openwrt_sim[1]))
    assert (up.id, up.name, up.port_id, up.kind, up.up) == (
        "gw/uplink/wan",
        "wan",
        "gw/port/eth0",
        UplinkKind.DHCP,
        True,
    )
    assert up.addresses == [ip_interface("203.0.113.45/24"), ip_interface("2001:db8:ffff::45/64")]
    assert up.delegated_prefixes == [IPv6Network("2001:db8:1::/56")]
    assert up.upstream_gateway == ip_address("203.0.113.1")
    assert up.dns_servers == [
        ip_address("203.0.113.53"),
        ip_address("203.0.113.54"),
        ip_address("2001:db8:ffff::53"),
    ]
    assert _recent(up.since, 5400)
    assert up.nat_class() is NatClass.PUBLIC
    assert up.vendor_extra == {"proto": ["dhcp", "dhcpv6"], "interfaces": ["wan", "wan6"]}


async def test_openwrt_access_point_has_no_uplink(openwrt_sim: tuple[OpenWrtSim, str]) -> None:
    assert await _uplinks(_openwrt(openwrt_sim[1], DeviceRole.AP)) == []


def _view(*entries: dict[str, Any]) -> NetworkView:
    return NetworkView.build({"values": {}}, {"interface": list(entries)})


def _openwrt_uplinks(view: NetworkView, *ports: str) -> list[Uplink]:
    adapter = _openwrt("http://192.0.2.2")
    known = {p: Port(id=port_id("gw", p), device_id="gw", name=p) for p in ports}
    return adapter._uplinks(view, known)


def test_openwrt_protocols() -> None:
    view = _view(
        {
            "interface": "wan",
            "proto": "pppoe",
            "up": True,
            "uptime": 60,
            "device": "eth0",
            "l3_device": "pppoe-wan",
            "ipv4-address": [{"address": "100.64.1.2", "mask": 32}],
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "100.64.0.1"}],
            "dns-server": ["100.64.0.53", "not an address"],
            "ipv6-prefix": [{"address": "bad"}, {"address": "2001:db8:5::", "mask": 48}],
        },
        {"interface": "lte", "proto": "qmi", "up": False, "uptime": 0, "device": "wwan0"},
        {"interface": "aftr", "proto": "dslite", "up": True, "device": "eth0"},
        {"interface": "lan", "proto": "static", "up": True, "device": "br-lan"},
        {
            "interface": "mgmt",
            "proto": "static",
            "up": True,
            "device": "eth0",
            "ipv4-address": [{"address": "192.168.1.2", "mask": 24}],
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "192.168.1.1"}],
        },
        {"interface": "wan2", "proto": "weird", "device": "eth9"},
    )
    aftr, lte, mgmt, pppoe, wan2 = _openwrt_uplinks(view, "eth0")
    # an interface with the default route that is no network of the site: behind a router
    assert (mgmt.kind, mgmt.upstream_gateway) == (UplinkKind.STATIC, ip_address("192.168.1.1"))
    assert mgmt.nat_class() is NatClass.PRIVATE
    assert (pppoe.kind, pppoe.port_id, pppoe.up) == (UplinkKind.PPPOE, "gw/port/eth0", True)
    assert pppoe.nat_class() is NatClass.CGNAT
    assert pppoe.upstream_gateway == ip_address("100.64.0.1")
    assert pppoe.dns_servers == [ip_address("100.64.0.53")]
    assert pppoe.delegated_prefixes == [IPv6Network("2001:db8:5::/48")]
    assert _recent(pppoe.since, 60)
    assert (lte.kind, lte.up, lte.since, lte.port_id) == (UplinkKind.LTE, False, None, None)
    assert (aftr.kind, aftr.since) == (UplinkKind.DSLITE, None)  # up, but no uptime given
    assert aftr.nat_class() is NatClass.NONE
    assert (wan2.kind, wan2.up) == (UplinkKind.OTHER, None)
    for u in (pppoe, aftr, lte, mgmt, wan2):
        assert uplink_problems(u, {"gw/port/eth0"}) == []


def test_openwrt_lone_wan6_is_its_own_uplink() -> None:
    view = _view({"interface": "wan6", "proto": "dhcpv6", "up": True, "device": "eth1"})
    [up] = _openwrt_uplinks(view, "eth1")
    assert (up.id, up.kind) == ("gw/uplink/wan6", UplinkKind.OTHER)


# --- OPNsense ----------------------------------------------------------------------------------


@pytest.fixture
def opnsense_sim() -> Iterator[tuple[opnsense.OpnsenseSimulator, str]]:
    sim = opnsense.OpnsenseSimulator()
    with serve(sim.app()) as url:
        yield sim, url


def _opnsense(url: str) -> OpnsenseAdapter:
    config = OpnsenseConfig(
        url=url,
        api_key=SecretStr(opnsense.KEY),
        api_secret=SecretStr(opnsense.SECRET),
        allow_insecure_http=True,
    )
    return OpnsenseAdapter(_context(config))


async def test_opnsense_wan_behind_carrier_grade_nat(
    opnsense_sim: tuple[opnsense.OpnsenseSimulator, str],
) -> None:
    [up] = await _uplinks(_opnsense(opnsense_sim[1]))
    assert (up.id, up.name, up.port_id, up.kind, up.up, up.since) == (
        "gw/uplink/wan",
        "WAN",
        "gw/port/igb1",
        UplinkKind.DHCP,
        True,
        None,  # the API has no uptime
    )
    assert up.addresses == [ip_interface("100.64.23.45/22"), ip_interface("2001:db8:ffff::2/64")]
    assert up.delegated_prefixes == [IPv6Network("2001:db8:1::/56")]
    assert up.upstream_gateway == ip_address("100.64.20.1")
    assert up.dns_servers == [
        ip_address("100.64.0.53"),
        ip_address("2001:db8:ffff::53"),
        ip_address("2001:db8:ffff::54"),
    ]
    assert up.nat_class() is NatClass.CGNAT
    assert up.vendor_extra == {"link_type": "dhcp", "link_typev6": "dhcp6"}


async def test_opnsense_without_wan_has_no_uplink(
    opnsense_sim: tuple[opnsense.OpnsenseSimulator, str],
) -> None:
    sim, url = opnsense_sim
    rows = sim.data[opnsense.INTERFACES]["rows"]
    rows[:] = [r for r in rows if r["identifier"] != "wan"]
    assert await _uplinks(_opnsense(url)) == []


def test_opnsense_wan_rows() -> None:
    pppoe = opnsense_uplink(
        {
            "identifier": "wan",
            "status": "up",
            "link_type": "pppoe",
            "ipv4": [{"ipaddr": "203.0.113.9/32"}],
            "gateways": [],
            "ifctl.router": "203.0.113.1",
            "ifctl.nameserver": "203.0.113.53 203.0.113.53",
            "ifctl.prefix": ["2001:db8:9::/56\nnot-a-prefix", "203.0.113.0/24"],
        },
        "gw",
        "gw/port/pppoe0",
    )
    assert (pppoe.kind, pppoe.up, pppoe.name) == (UplinkKind.PPPOE, True, "WAN")
    assert pppoe.upstream_gateway == ip_address("203.0.113.1")
    assert pppoe.dns_servers == [ip_address("203.0.113.53")]
    assert pppoe.delegated_prefixes == [IPv6Network("2001:db8:9::/56")]
    down = opnsense_uplink(
        {"identifier": "wan", "status": "no carrier", "link_type": "l2tp"}, "gw", None
    )
    assert (down.kind, down.up, down.upstream_gateway, down.nat_class()) == (
        UplinkKind.OTHER,
        False,
        None,
        None,
    )
    unknown = opnsense_uplink({"identifier": "wan", "description": "Fibre"}, "gw", None)
    assert (unknown.up, unknown.name, unknown.vendor_extra) == (None, "Fibre", {})


# --- MikroTik ----------------------------------------------------------------------------------


@pytest.fixture
def mikrotik_sim() -> Iterator[tuple[mikrotik.MikrotikSimulator, str]]:
    sim = mikrotik.MikrotikSimulator()
    with serve(sim.app()) as url:
        yield sim, url


def _mikrotik(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(
        url=url,
        username=mikrotik.USER,
        password=SecretStr(mikrotik.PASSWORD),
        allow_insecure_http=True,
    )
    return MikrotikAdapter(_context(config))


async def test_mikrotik_dhcp_client(mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str]) -> None:
    sim, url = mikrotik_sim
    [up] = await _uplinks(_mikrotik(url))
    assert (up.id, up.name, up.port_id, up.kind, up.up, up.since) == (
        "gw/uplink/ether1",
        "ether1",
        "gw/port/ether1",
        UplinkKind.DHCP,
        True,
        None,  # a DHCP client has no uptime, only the lease's expiry
    )
    assert up.addresses == [ip_interface("203.0.113.2/24"), ip_interface("2001:db8:ffff::2/64")]
    assert up.delegated_prefixes == [IPv6Network("2001:db8:1::/56")]
    assert up.upstream_gateway == ip_address("203.0.113.1")
    assert up.dns_servers == [ip_address("203.0.113.53"), ip_address("203.0.113.54")]
    assert up.public_ipv4 is None  # /ip/cloud saw the uplink's own address
    assert up.vendor_extra == {"status": "bound"}
    assert sim.writes == []


async def test_mikrotik_behind_carrier_grade_nat(
    mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str],
) -> None:
    sim, url = mikrotik_sim
    [client] = sim.data[mikrotik.DHCP_CLIENT]
    client.update(address="100.64.7.8/22", gateway="100.64.4.1", status="searching...")
    sim.data[mikrotik.IP_ADDRESS] = [
        r for r in sim.data[mikrotik.IP_ADDRESS] if r["interface"] != "ether1"
    ]
    sim.data["/rest/ip/cloud"]["public-address"] = "203.0.113.77"
    [up] = await _uplinks(_mikrotik(url))
    assert up.up is False and up.public_ipv4 is None  # only a connected uplink gets it
    client["status"] = "bound"
    [up] = await _uplinks(_mikrotik(url))
    assert up.addresses[0] == ip_interface("100.64.7.8/22")
    assert up.public_ipv4 == IPv4Address("203.0.113.77")
    assert up.nat_class() is NatClass.CGNAT  # its own address decides, not the cloud's
    sim.data["/rest/ip/cloud"]["public-address"] = "100.64.7.8"  # not public: ignored
    [up] = await _uplinks(_mikrotik(url))
    assert up.public_ipv4 is None


async def test_mikrotik_pppoe(mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str]) -> None:
    sim, url = mikrotik_sim
    sim.data[mikrotik.LIST_MEMBER].append(
        {"list": "WAN", "interface": "pppoe-out1", "disabled": "false", "dynamic": "false"}
    )
    sim.data[mikrotik.INTERFACE].append(
        {".id": "*99", "name": "pppoe-out1", "type": "pppoe-out", "running": "true"}
    )
    sim.data[mikrotik.PPPOE_CLIENT].append(
        {
            ".id": "*1",
            "name": "pppoe-out1",
            "interface": "ether1",
            "running": "true",
            "disabled": "false",
        }
    )
    del sim.data[mikrotik.DHCP_CLIENT][0]  # ether1 only carries the PPPoE session
    [up] = await _uplinks(_mikrotik(url))
    assert (up.id, up.port_id, up.kind, up.up) == (
        "gw/uplink/pppoe-out1",
        "gw/port/ether1",
        UplinkKind.PPPOE,
        True,
    )
    assert up.addresses == [ip_interface("203.0.113.77/32")]
    assert up.upstream_gateway == ip_address("203.0.113.1")
    assert _recent(up.since, 93784)  # 1d2h3m4s
    assert up.vendor_extra == {"status": "connected", "ac-name": "isp-bras", "mtu": "1492"}
    assert sim.writes == []  # the monitor is a read
    assert sim.monitor({"numbers": "nothere", "once": ""}).status_code == 404  # as on the CHR
    # without the right to monitor: the client's running flag, no uptime
    sim.read_only_monitor = True
    [up] = await _uplinks(_mikrotik(url))
    assert (up.up, up.since, up.addresses, up.upstream_gateway) == (True, None, [], None)
    sim.read_only_monitor = False
    sim.data[mikrotik.PPPOE_CLIENT][0]["running"] = "false"
    [up] = await _uplinks(_mikrotik(url))
    assert (up.up, up.since) == (False, None)


async def test_mikrotik_static_lte_and_bare_ports(
    mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str],
) -> None:
    sim, url = mikrotik_sim
    sim.data[mikrotik.DHCP_CLIENT] = []
    sim.data[mikrotik.LIST_MEMBER] += [
        {"list": "WAN", "interface": name, "disabled": "false", "dynamic": "false"}
        for name in ("lte1", "ether5")
    ]
    sim.data[mikrotik.INTERFACE].append(
        {".id": "*98", "name": "lte1", "type": "lte", "running": "true"}
    )
    ether1, ether5, lte = await _uplinks(_mikrotik(url))
    assert (ether1.kind, ether1.up) == (UplinkKind.STATIC, True)
    assert (ether5.kind, ether5.up) == (UplinkKind.OTHER, False)  # disabled, no address
    assert (lte.kind, lte.up, lte.port_id) == (UplinkKind.LTE, False, "gw/port/lte1")


async def test_mikrotik_without_wan_list_reads_nothing_more(
    mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str],
) -> None:
    sim, url = mikrotik_sim
    sim.data[mikrotik.LIST_MEMBER] = []
    assert await _uplinks(_mikrotik(url)) == []
    # (/ip/dhcp-client is still read with dhcp: its server on other networks, #184)
    assert "/rest/ipv6/dhcp-client" not in sim.requests


async def test_mikrotik_without_cloud_menu(
    mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str],
) -> None:
    sim, url = mikrotik_sim
    del sim.data["/rest/ip/cloud"]
    sim.data[mikrotik.DHCP_CLIENT][0]["address"] = "not an address"
    sim.data["/rest/ipv6/dhcp-client"][0]["prefix"] = "not a prefix, 1d"
    [up] = await _uplinks(_mikrotik(url))
    assert up.addresses[0] == ip_interface("203.0.113.2/24")  # from /ip/address
    assert up.public_ipv4 is None and up.delegated_prefixes == []


# --- Fritz!Box ---------------------------------------------------------------------------------


@pytest.fixture
async def fritzbox() -> AsyncIterator[tuple[FritzboxSim, str]]:
    sim = FritzboxSim()
    with serve(fritzbox_app(sim)) as url:
        yield sim, url


def _fritzbox(url: str, role: DeviceRole = DeviceRole.GATEWAY) -> FritzboxAdapter:
    sim = FritzboxSim()
    config = FritzboxConfig(
        url=url, username=sim.username, password=SecretStr(sim.password), allow_insecure_http=True
    )
    return FritzboxAdapter(_context(config, role))


async def test_fritzbox_dsl(fritzbox: tuple[FritzboxSim, str]) -> None:
    url = fritzbox[1]
    [up] = await _uplinks(_fritzbox(url))
    assert (up.id, up.name, up.port_id, up.kind, up.up) == (
        "gw/uplink/internet",
        "internet",
        None,  # TR-064 has no port for the line
        UplinkKind.PPPOE,
        True,
    )
    assert up.addresses == [ip_interface("203.0.113.45/32")]
    assert up.upstream_gateway == ip_address("203.0.113.1")
    assert up.dns_servers == [ip_address("203.0.113.53"), ip_address("203.0.113.54")]
    assert (up.downstream_kbps, up.upstream_kbps) == (116790, 46719)
    assert _recent(up.since, 7200)
    assert up.nat_class() is NatClass.PUBLIC
    assert up.vendor_extra == {
        "ConnectionType": "IP_Routed",
        "WANAccessType": "DSL",
        "PhysicalLinkStatus": "Up",
        "service": "WANPPPConnection:1",
    }


@pytest.mark.parametrize(
    ("wan", "kind", "nat"),
    [("cable", UplinkKind.OTHER, NatClass.CGNAT), ("lte", UplinkKind.LTE, NatClass.CGNAT)],
)
async def test_fritzbox_ip_connection(
    fritzbox: tuple[FritzboxSim, str], wan: str, kind: UplinkKind, nat: NatClass
) -> None:
    sim, url = fritzbox
    sim.wan = wan
    [up] = await _uplinks(_fritzbox(url))
    assert (up.kind, up.up, up.upstream_gateway, up.nat_class()) == (kind, True, None, nat)
    assert up.name == "mstv" and up.vendor_extra["service"] == "WANIPConnection:1"


async def test_fritzbox_down_client_and_access_point(fritzbox: tuple[FritzboxSim, str]) -> None:
    sim, url = fritzbox
    sim.wan_up = False
    [up] = await _uplinks(_fritzbox(url))
    assert (up.up, up.since, up.addresses, up.dns_servers) == (False, None, [], [])
    sim.wan = "client"
    assert await _uplinks(_fritzbox(url)) == []
    sim.wan = "dsl"
    calls = len(sim.calls)
    assert await _uplinks(_fritzbox(url, DeviceRole.AP)) == []
    assert not any(s.startswith("WAN") for s, _, _ in sim.calls[calls:])


async def test_fritzbox_refused_wan_services(fritzbox: tuple[FritzboxSim, str]) -> None:
    sim, url = fritzbox
    sim.denied = {"GetInfo"}  # 606 for every GetInfo: the LAN still reads
    sim.faults = {"GetCommonLinkProperties": 401}
    adapter = _fritzbox(url)
    try:
        snap = await adapter.observe()
    finally:
        await adapter.close()
    assert snap.uplinks == []
    sim.denied = set()
    [up] = await _uplinks(_fritzbox(url))
    assert (up.downstream_kbps, up.kind) == (None, UplinkKind.PPPOE)


def test_fritzbox_bridged_and_unset_values() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    bridged = wan_uplink(
        "gw",
        None,
        {
            "NewEnable": "1",
            "NewConnectionType": "IP_Bridged",
            "NewConnectionStatus": "Connected",
            "NewExternalIPAddress": "203.0.113.5",
            "NewUptime": "0",
        },
        {"NewLayer1DownstreamMaxBitRate": "0"},
        now,
    )
    assert bridged is not None
    assert (bridged.kind, bridged.addresses, bridged.since, bridged.downstream_kbps) == (
        UplinkKind.BRIDGE,
        [],
        None,
        None,
    )
    assert uplink_problems(bridged, set()) == []
    assert wan_uplink("gw", {"NewEnable": "0"}, None, {}, now) is None


# --- Omada -------------------------------------------------------------------------------------


@pytest.fixture
def omada_sim() -> Iterator[tuple[omada.OmadaSimulator, str]]:
    sim = omada.OmadaSimulator()
    with serve(sim.app()) as url:
        yield sim, url


def _omada(url: str) -> OmadaAdapter:
    config = OmadaConfig(
        url=url,
        client_id=omada.CLIENT_ID,
        client_secret=SecretStr(omada.CLIENT_SECRET),
        allow_insecure_http=True,
    )
    return OmadaAdapter(_context(config, DeviceRole.OTHER))


WAN_STATUS = f"{omada.SITE}/gateways/{omada.GATEWAY}/wan-status"


async def test_omada_gateway_wan_ports(omada_sim: tuple[omada.OmadaSimulator, str]) -> None:
    dhcp, pppoe = await _uplinks(_omada(omada_sim[1]))  # port 3 is in LAN mode
    gw = "gw/gateway-020000000a01"
    assert (dhcp.id, dhcp.device_id, dhcp.name, dhcp.kind, dhcp.up, dhcp.port_id) == (
        f"{gw}/uplink/port1",
        gw,
        "SFP WAN",
        UplinkKind.DHCP,
        True,
        None,  # the gateway's ports are not reported
    )
    assert dhcp.addresses == [ip_interface("203.0.113.45/24"), ip_interface("2001:db8:ffff::45")]
    assert dhcp.upstream_gateway == ip_address("203.0.113.1")
    assert dhcp.dns_servers == [
        ip_address("203.0.113.53"),
        ip_address("203.0.113.54"),
        ip_address("2001:db8:ffff::53"),
    ]
    assert dhcp.since is None and dhcp.nat_class() is NatClass.PUBLIC
    assert dhcp.vendor_extra["proto"] == "DHCP" and dhcp.vendor_extra["port"] == 1
    device = dhcp.vendor_extra["omada_device"]
    assert isinstance(device, dict) and device["type"] == "gateway"
    assert (pppoe.kind, pppoe.up, pppoe.addresses, pppoe.upstream_gateway) == (
        UplinkKind.PPPOE,
        False,
        [],
        None,
    )


async def test_omada_wan_status_refused_or_without_gateway(
    omada_sim: tuple[omada.OmadaSimulator, str],
) -> None:
    sim, url = omada_sim
    sim.error[WAN_STATUS] = (-39999, "simulated failure")
    assert await _uplinks(_omada(url)) == []
    del sim.error[WAN_STATUS]
    devices = sim.data[f"{omada.SITE}/devices"]
    devices[:] = [d for d in devices if d["type"] != "gateway"]
    before = len(sim.requests)
    assert await _uplinks(_omada(url)) == []
    assert WAN_STATUS not in sim.requests[before:]


def test_omada_wan_entries() -> None:
    extra: dict[str, Any] = {}
    assert omada_uplink({"name": "no port"}, "gw", extra) is None
    assert omada_uplink({"port": 4, "type": 2}, "gw", extra) is None  # a LAN port
    bare = omada_uplink(
        {"port": 5, "type": 1, "proto": "MAP-E", "ip": "203.0.113.9", "status": 1}, "gw", extra
    )
    assert bare is not None
    assert (bare.kind, bare.up, bare.name, bare.addresses) == (
        UplinkKind.MAP_E,
        None,  # connected port, internet state not reported
        "WAN5",
        [ip_interface("203.0.113.9/32")],
    )
    odd = omada_uplink(
        {
            "port": 6,
            "proto": "Static IP",
            "internetState": 1,
            "wanPortIpv4Config": {"ip": "198.51.100.7", "netmask": "bogus", "priDns": "0.0.0.0"},
            "wanPortIpv6Config": {"enable": 1, "addr": "not an address", "gateway": "fe80::1"},
        },
        "gw",
        extra,
    )
    assert odd is not None
    assert (odd.kind, odd.up, odd.addresses, odd.dns_servers, odd.upstream_gateway) == (
        UplinkKind.STATIC,
        True,
        [ip_interface("198.51.100.7/32")],
        [],
        ip_address("fe80::1"),
    )
    lite = omada_uplink({"port": 7, "proto": "ds-lite", "internetState": 0}, "gw", extra)
    assert lite is not None and (lite.kind, lite.up) == (UplinkKind.DSLITE, False)


async def test_mikrotik_server_sightings(
    mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str],
) -> None:
    """#184: the server of a DHCP client on the LAN and the rogue DHCP detector's unknown
    servers; the WAN's DHCP client is the provider's, not a sighting."""
    sim, url = mikrotik_sim
    adapter = _mikrotik(url)
    try:
        assert (await assert_contract(adapter)).server_sightings == []
    finally:
        await adapter.close()
    sim.data[mikrotik.DHCP_CLIENT].append(
        {
            ".id": "*9",
            "interface": "bridge",
            "status": "bound",
            "address": "192.0.2.77/24",
            "gateway": "192.0.2.254",
            "dhcp-server": "192.0.2.254",
            "primary-dns": "192.0.2.254",
            "disabled": "false",
            "invalid": "false",
        }
    )
    sim.data[mikrotik.DHCP_CLIENT].append(
        {".id": "*a", "interface": "bridge", "status": "searching", "dhcp-server": "192.0.2.9"}
    )
    sim.data[mikrotik.DHCP_CLIENT].append(
        {
            ".id": "*b",
            "interface": "bridge",
            "status": "bound",
            "address": "bad",
            "dhcp-server": "192.0.2.8",
        }
    )
    sim.data["/rest/ip/dhcp-server/alert"][0]["unknown-server"] = "02:00:00:00:00:99,junk"
    sim.data["/rest/ip/dhcp-server/alert"].append(
        {".id": "*2", "interface": "nowhere", "unknown-server": "02:00:00:00:00:98"}
    )
    adapter = _mikrotik(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    by = {(s.origin.value, str(s.server_address)): s for s in snap.server_sightings}
    lease = by[("client-lease", "192.0.2.254")]
    assert lease.segment_id
    assert [str(a) for a in lease.offered.routers] == ["192.0.2.254"]
    assert str(lease.offered.address) == "192.0.2.77"
    assert [str(p) for p in lease.offered.prefixes] == ["192.0.2.0/24"]
    assert by[("client-lease", "192.0.2.8")].offered.address is None
    assert by[("device-alert", "None")].server_mac == "02:00:00:00:00:99"
    assert len(by) == 3


# --- gateway health (#150) and dynamic DNS (#154) on OPNsense ----------------------------------


async def test_opnsense_gateway_health_and_ddns(
    opnsense_sim: tuple[opnsense.OpnsenseSimulator, str],
) -> None:
    adapter = _opnsense(opnsense_sim[1])
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    [up] = snap.uplinks
    assert up.monitor is not None and up.monitor.targets == [ip_address("100.64.20.1")]
    assert up.health is not None and up.health.state.value == "online"
    assert (up.health.latency_ms, up.health.loss_pct) == (4.2, 0.0)
    [dd] = snap.ddns
    assert (dd.provider, dd.hostname, dd.enabled, dd.uplink_id) == (
        "dyndns2",
        "fw.example.dyndns.invalid",
        True,
        up.id,
    )
    assert dd.last_result.value == "unknown" and dd.published_address is None
    assert "sim-secret-token" not in snap.model_dump_json()


async def test_opnsense_gateway_states_and_missing_ddns(
    opnsense_sim: tuple[opnsense.OpnsenseSimulator, str],
) -> None:
    sim, url = opnsense_sim
    for status, state in (("down", "down"), ("loss", "degraded"), ("force_down", "down")):
        sim.data["/api/routes/gateway/status"]["items"][0]["status"] = status
        adapter = _opnsense(url)
        try:
            snap = await assert_contract(adapter)
        finally:
            await adapter.close()
        assert snap.uplinks[0].health is not None
        assert snap.uplinks[0].health.state.value == state
    del sim.data["/api/dyndns/accounts/search_item"]  # os-ddclient not installed: 404
    adapter = _opnsense(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    assert snap.ddns == []


# --- default routes as a gateway group (#150) and MikroTik Cloud (#154) --------------------------


async def test_mikrotik_cloud_name_is_a_ddns_client(
    mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str],
) -> None:
    sim, url = mikrotik_sim
    adapter = _mikrotik(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    [dd] = snap.ddns
    assert (dd.provider, dd.hostname, dd.last_result.value) == (
        "mikrotik-cloud",
        "abc123def456.sn.mynetname.invalid",
        "ok",
    )
    assert dd.published_address == ip_address("203.0.113.2") and dd.enabled
    assert dd.uplink_id is not None and snap.gateway_groups == []  # one default route
    sim.data["/rest/ip/cloud"]["status"] = "error: no internet"
    sim.data["/rest/ip/cloud"]["ddns-enabled"] = "no"
    adapter = _mikrotik(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    assert snap.ddns[0].last_result.value == "error" and not snap.ddns[0].enabled
    del sim.data["/rest/ip/cloud"]["dns-name"]
    adapter = _mikrotik(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    assert snap.ddns == []


async def test_mikrotik_two_default_routes_are_a_failover_group(
    mikrotik_sim: tuple[mikrotik.MikrotikSimulator, str],
) -> None:
    sim, url = mikrotik_sim
    primary = next(r for r in sim.data["/rest/ip/route"] if r["dst-address"] == "0.0.0.0/0")
    primary.update({"check-gateway": "ping", "gateway-status": "203.0.113.1 reachable via ether1"})
    sim.data["/rest/ip/route"].append(
        {
            ".id": "*FF",
            "dst-address": "0.0.0.0/0",
            "gateway": "198.51.100.1",
            "distance": "5",
            "comment": "lte",
            "routing-table": "main",
            "static": "true",
            "active": "false",
            "disabled": "false",
            "check-gateway": "ping",
            "gateway-status": "198.51.100.1 unreachable",
        }
    )
    sim.data["/rest/tool/netwatch"] = [
        {".id": "*1", "host": "203.0.113.53", "status": "up", "comment": "lte", "disabled": "false"}
    ]
    adapter = _mikrotik(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    [group] = snap.gateway_groups
    assert (group.name, group.mode.value) == ("default", "failover")
    first, lte = sorted(group.members, key=lambda m: m.tier)
    assert (first.tier, first.state.value if first.state else None) == (1, "online")
    assert first.monitor_targets == [ip_address("203.0.113.1")]  # the gateway pings itself
    assert group.active == first.name
    assert (lte.name, lte.tier, lte.gateway) == ("lte", 2, ip_address("198.51.100.1"))
    assert lte.state is not None and lte.state.value == "down"
    assert ip_address("203.0.113.53") in lte.monitor_targets
    [up] = snap.uplinks
    assert up.monitor is not None and up.health is not None


# --- FRITZ!Box DDNS provider and MyFRITZ! (#154) --------------------------------------------------


async def test_fritzbox_ddns_provider_and_myfritz(fritzbox: tuple[FritzboxSim, str]) -> None:
    sim, url = fritzbox
    adapter = _fritzbox(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    by = {d.id: d for d in snap.ddns}
    provider, my = by["gw/ddns/provider"], by["gw/ddns/myfritz"]
    assert (provider.provider, provider.hostname, provider.families) == (
        "dyndns2",
        "home.example.dyndns.invalid",
        [4],
    )
    assert provider.enabled and provider.last_result.value == "ok"
    assert provider.published_address is None and provider.uplink_id is not None
    assert provider.tls is True and my.tls is None  # scheme of the update URL (#440)
    assert (my.provider, my.hostname, my.last_result.value) == (
        "myfritz",
        "example.myfritz.example",
        "ok",
    )
    text = snap.model_dump_json()
    assert "sim-user" not in text and "dyn.example.invalid" not in text
    sim.ddns.update({"NewStatusIPv4": "error: authentication failed", "NewMode": "ddns_both"})
    sim.myfritz["NewDynDNSName"] = ""
    adapter = _fritzbox(url)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    [only] = snap.ddns
    assert only.last_result.value == "error" and only.families == [4, 6]


async def test_fritzbox_access_point_has_no_ddns(fritzbox: tuple[FritzboxSim, str]) -> None:
    adapter = _fritzbox(fritzbox[1], DeviceRole.AP)
    try:
        snap = await assert_contract(adapter)
    finally:
        await adapter.close()
    assert snap.ddns == []


# --- gateway groups of OPNsense 26.7 and Omada's WAN mode (#150) --------------------------------

GROUPS = "/api/routing/group_settings/search"


async def _snapshot(adapter: Adapter) -> Any:
    try:
        return await assert_contract(adapter)
    finally:
        await adapter.close()


async def test_opnsense_gateway_group(opnsense_sim: tuple[opnsense.OpnsenseSimulator, str]) -> None:
    snap = await _snapshot(_opnsense(opnsense_sim[1]))
    [up] = snap.uplinks
    [group] = snap.gateway_groups
    assert (group.name, group.mode.value, group.active) == ("WAN_FAILOVER", "failover", "WAN_DHCP")
    first, backup = group.members
    assert (first.name, first.tier, first.uplink_id, first.state.value) == (
        "WAN_DHCP",
        1,
        up.id,
        "online",
    )
    assert (first.latency_ms, first.loss_pct) == (4.2, 0.0)
    assert (backup.name, backup.tier, backup.uplink_id) == ("WAN2_LTE", 2, None)
    assert backup.gateway == ip_address("198.51.100.1")
    assert backup.monitor_targets == [ip_address("203.0.113.53")]
    assert "opnsense.groupsUnread" not in {e.message_id for e in snap.errors}


async def test_opnsense_gateway_group_states(
    opnsense_sim: tuple[opnsense.OpnsenseSimulator, str],
) -> None:
    sim, url = opnsense_sim
    tiers = sim.data[GROUPS]["rows"][0]["gateways"]
    tiers["0"][0]["status"] = "down"
    snap = await _snapshot(_opnsense(url))
    assert snap.gateway_groups[0].active == "WAN2_LTE"
    # a gateway that is disabled or inactive is listed without a status row of its own
    tiers["1"][0] = {"name": "WAN2_LTE", "label": "danger", "status_translated": "Disabled"}
    snap = await _snapshot(_opnsense(url))
    group = snap.gateway_groups[0]
    assert group.members[1].state.value == "down" and group.active is None
    # two gateways in the first tier share the load
    tiers["0"][0]["status"] = "none"
    tiers["0"].append({"name": "WAN3", "address": "198.51.100.9", "status": "loss"})
    del tiers["1"]
    snap = await _snapshot(_opnsense(url))
    group = snap.gateway_groups[0]
    assert (group.mode.value, group.active) == ("balance", None)
    assert [m.state.value for m in group.members] == ["online", "degraded"]
    # a group without a name or gateways is skipped
    sim.data[GROUPS]["rows"] = [{"name": "", "gateways": tiers}, {"name": "empty", "gateways": []}]
    snap = await _snapshot(_opnsense(url))
    assert snap.gateway_groups == []


async def test_opnsense_without_group_api_is_an_optional_gap(
    opnsense_sim: tuple[opnsense.OpnsenseSimulator, str],
) -> None:
    sim, url = opnsense_sim
    del sim.data[GROUPS]
    snap = await _snapshot(_opnsense(url))
    assert snap.gateway_groups == []
    [gap] = [e for e in snap.errors if e.message_id == "opnsense.groupsUnread"]
    assert gap.optional and "26.7" in gap.message
    # a firewall with one gateway has no use for groups: no gap
    sim.data["/api/routes/gateway/status"]["items"] = sim.data["/api/routes/gateway/status"][
        "items"
    ][:1]
    snap = await _snapshot(_opnsense(url))
    assert "opnsense.groupsUnread" not in {e.message_id for e in snap.errors}


GW = "gw/gateway-020000000a01"


async def test_omada_wan_health_and_link_backup(
    omada_sim: tuple[omada.OmadaSimulator, str],
) -> None:
    snap = await _snapshot(_omada(omada_sim[1]))
    dhcp, pppoe = snap.uplinks
    assert dhcp.health is not None and dhcp.health.state.value == "online"
    assert (dhcp.health.latency_ms, dhcp.health.loss_pct) == (9.0, 0.0)
    assert pppoe.health is not None and pppoe.health.state.value == "down"
    assert pppoe.health.latency_ms is None
    [group] = snap.gateway_groups
    assert (group.id, group.mode.value, group.active) == (
        f"{GW}/gateway-group/wan",
        "failover",
        "SFP WAN",
    )
    assert [(m.name, m.tier, m.state.value) for m in group.members] == [
        ("SFP WAN", 1, "online"),
        ("WAN2", 2, "down"),
    ]
    assert "omada.wanModeUnread" not in {e.message_id for e in snap.errors}


async def test_omada_load_balancing_and_missing_mode(
    omada_sim: tuple[omada.OmadaSimulator, str],
) -> None:
    sim, url = omada_sim
    path = f"{omada.SITE}/internet/load-balance"
    sim.data[path] = {"mode": 0, "ports": [{"port": 1, "weight": 3}, {"port": 2, "weight": 1}]}
    snap = await _snapshot(_omada(url))
    [group] = snap.gateway_groups
    assert (group.mode.value, group.active) == ("balance", None)
    assert [(m.tier, m.weight) for m in group.members] == [(1, 3), (1, 1)]
    del sim.data[path]  # a controller that does not know the setting
    snap = await _snapshot(_omada(url))
    assert snap.gateway_groups == []
    [gap] = [e for e in snap.errors if e.message_id == "omada.wanModeUnread"]
    assert gap.optional
    # one WAN port only: nothing to group, no gap
    sim.data[WAN_STATUS] = sim.data[WAN_STATUS][:1]
    snap = await _snapshot(_omada(url))
    assert snap.gateway_groups == [] and "omada.wanModeUnread" not in {
        e.message_id for e in snap.errors
    }


def test_omada_wan_health_entries() -> None:
    odd = omada_uplink({"port": 1, "internetState": 1, "latency": "x", "loss": 250}, "gw", {})
    assert odd is not None and odd.health is not None
    assert (odd.health.latency_ms, odd.health.loss_pct) == (None, 100.0)
    unknown = omada_uplink({"port": 2, "proto": "DHCP"}, "gw", {})
    assert unknown is not None and unknown.health is None
    negative = omada_uplink({"port": 3, "internetState": 1, "latency": -1, "loss": True}, "gw", {})
    assert negative is not None and negative.health is not None
    assert (negative.health.latency_ms, negative.health.loss_pct) == (None, None)
