"""MikroTik adapter against its simulator, over real sockets (plain HTTP and pinned TLS)."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from signalbox.adapters import AdapterContext, load_adapters
from signalbox.adapters import https as https_mod
from signalbox.adapters.mikrotik import (
    ARP,
    BRIDGE,
    BRIDGE_HOST,
    BRIDGE_PORT,
    BRIDGE_VLAN,
    DHCP_LEASE,
    DHCP_SERVER,
    DNS,
    DNS_STATIC,
    INTERFACE,
    IP_ADDRESS,
    IPV6_ADDRESS,
    LIST_MEMBER,
    NEIGHBOR,
    PACKAGE_UPDATE,
    POOL,
    RESOURCE,
    ROUTERBOARD,
    VLAN,
    WIFI,
    MikrotikAdapter,
    MikrotikConfig,
    _int,
    _object,
    band_of,
    duration,
    frequency_channel,
    security_of,
    speed,
    vlan_ids,
    width_of,
)
from signalbox.model import (
    Band,
    DeviceRole,
    DeviceStatus,
    Membership,
    Pmf,
    Security,
    Snapshot,
    passphrase_fingerprint,
    port_id,
)
from signalbox.sim.mikrotik import PASSPHRASE, PASSWORD, USER, MikrotikSimulator
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract

SIM = MikrotikSimulator()


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


@pytest.fixture(scope="module")
def http_url() -> Iterator[str]:
    with serve(SIM.app()) as url:
        yield url


@pytest.fixture(scope="module")
def https_url(tls: TlsFiles) -> Iterator[str]:
    with serve(SIM.app(), tls=tls) as url:
        yield url


@pytest.fixture(autouse=True)
def sim() -> MikrotikSimulator:
    SIM.__dict__.update(MikrotikSimulator().__dict__)  # fresh data and switches every test
    return SIM


def adapter(
    url: str,
    pin: str | None = None,
    timeout: float = 5.0,
    role: DeviceRole = DeviceRole.GATEWAY,
    password: str = PASSWORD,
) -> MikrotikAdapter:
    config = MikrotikConfig(
        url=url, password=SecretStr(password), allow_insecure_http=url.startswith("http://")
    )
    return MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="rt",
            device_name="Router",
            role=role,
            config=config,
            pinned_fingerprint=pin,
            timeout=timeout,
        )
    )


async def observe(a: MikrotikAdapter) -> Snapshot:
    try:
        return await a.observe()
    finally:
        await a.close()


_SNAPSHOT: list[Snapshot] = []


@pytest.fixture
async def snap(http_url: str) -> Snapshot:
    """The sample data's snapshot, observed once (snapshots are immutable)."""
    if not _SNAPSHOT:
        a = adapter(http_url)
        try:
            _SNAPSHOT.append(await assert_contract(a))
        finally:
            await a.close()
    return _SNAPSHOT[0]


def errors(snap: Snapshot) -> dict[str, str]:
    return {e.capability: e.message for e in snap.errors}


P = port_id


# --- contract and mapping --------------------------------------------------------------------


async def test_contract_over_pinned_tls(
    https_url: str, tls: TlsFiles, sim: MikrotikSimulator
) -> None:
    a = adapter(https_url, pin=tls.fingerprint)
    try:
        snap = await assert_contract(a)
        again = await a.observe()  # a second observation probes and pins again
    finally:
        await a.close()
    assert snap.status is again.status is DeviceStatus.OK
    assert snap.subnets and snap.wlans and snap.clients and snap.neighbours
    assert all(p.startswith("/rest/") for p in sim.requests)


def test_entry_point() -> None:
    assert load_adapters()["mikrotik"] is MikrotikAdapter


async def test_system(snap: Snapshot) -> None:
    d = snap.device
    assert (d.vendor, d.model, d.management_address) == (
        "MikroTik",
        "C52iG-5HaxD2HaxD",
        "127.0.0.1",
    )
    assert d.firmware is not None
    assert (d.firmware.current, d.firmware.available) == ("7.15.3", "7.16")


async def test_system_without_routerboard_and_update(http_url: str, sim: MikrotikSimulator) -> None:
    del sim.data[ROUTERBOARD]
    sim.fail = {PACKAGE_UPDATE: 403}
    d = (await observe(adapter(http_url))).device
    assert d.model == "hAP ax^2" and d.firmware is not None and d.firmware.available is None
    sim.data[ROUTERBOARD] = {"routerboard": "false"}  # CHR answers like this
    sim.data[PACKAGE_UPDATE] = {"installed-version": "7.15.3", "latest-version": "7.15.3"}
    sim.fail = {}
    d = (await observe(adapter(http_url))).device
    assert d.model == "hAP ax^2" and d.firmware is not None and d.firmware.available is None


async def test_ports(snap: Snapshot) -> None:
    ports = {p.name: p for p in snap.ports}
    assert sorted(ports) == [
        "bridge",
        "ether1",
        "ether2",
        "ether3",
        "ether4",
        "ether5",
        "wifi1",
        "wifi2",
        "wifi3",
    ]  # no VLAN interface, no loopback
    e1 = ports["ether1"]
    assert (e1.up, e1.speed_mbps, e1.full_duplex, e1.mac) == (True, 1000, True, "02:00:00:00:00:01")
    assert e1.vendor_extra["comment"] == "uplink"
    assert (ports["ether2"].speed_mbps, ports["ether2"].full_duplex) == (1000, None)
    assert (ports["ether3"].speed_mbps, ports["ether3"].full_duplex) == (100, False)
    assert ports["ether5"].up is False and ports["ether5"].vendor_extra["disabled"] is True
    assert ports["wifi1"].kind.value == "wireless" and ports["bridge"].kind.value == "bridge"


async def test_segments(snap: Snapshot) -> None:
    segs = {s.id: s for s in snap.segments}
    assert sorted(segs) == ["home/segment/20", "home/segment/native"]
    native = segs["home/segment/native"]
    assert (native.vlan, native.name) == (None, "LAN")
    assert [(m.port_id, m.mode) for m in native.members] == [
        (P("rt", n), Membership.UNTAGGED) for n in ("ether2", "ether3", "ether5", "wifi1", "wifi2")
    ]
    iot = segs["home/segment/20"]
    assert (iot.vlan, iot.name) == (20, "IoT devices")
    assert [(m.port_id, m.mode) for m in iot.members] == [
        (P("rt", "ether2"), Membership.TAGGED),
        (P("rt", "ether4"), Membership.UNTAGGED),
        (P("rt", "wifi3"), Membership.UNTAGGED),
    ]


async def test_subnets(snap: Snapshot) -> None:
    got = {(s.segment_id, str(s.interface), s.gateway) for s in snap.subnets}
    assert got == {
        ("home/segment/native", "192.0.2.1/24", True),
        ("home/segment/native", "2001:db8:1::1/64", True),
        ("home/segment/20", "198.51.100.1/24", True),
    }  # no WAN, no link-local


async def test_switch_is_not_the_gateway(http_url: str) -> None:
    snap = await observe(adapter(http_url, role=DeviceRole.SWITCH))
    assert snap.subnets and not any(s.gateway for s in snap.subnets)


async def test_dhcp(snap: Snapshot) -> None:
    servers = {s.id: s for s in snap.dhcp_servers}
    assert sorted(servers) == ["rt/dhcp/defconf", "rt/dhcp/iot-dhcp"]
    lan = servers["rt/dhcp/defconf"]
    assert lan.enabled and lan.segment_id == "home/segment/native"
    assert [(str(p.start), str(p.end)) for p in lan.pools] == [("192.0.2.100", "192.0.2.199")]
    assert lan.router == ip_address("192.0.2.1") and lan.dns_servers == [ip_address("192.0.2.1")]
    assert (lan.lease_seconds, lan.domain) == (1800, "home.example")
    assert [(r.mac, str(r.address), r.hostname) for r in lan.reservations] == [
        ("02:00:00:00:00:10", "192.0.2.10", "printer")
    ]
    iot = servers["rt/dhcp/iot-dhcp"]
    assert iot.segment_id == "home/segment/20" and iot.lease_seconds == 86400
    assert [(str(p.start), str(p.end)) for p in iot.pools] == [
        ("198.51.100.100", "198.51.100.149"),
        ("198.51.100.200", "198.51.100.210"),
    ]
    assert iot.dns_servers == [ip_address("198.51.100.1"), ip_address("192.0.2.1")]
    assert [r.hostname for r in iot.reservations] == ["sensor"]
    assert iot.vendor_extra["network"] == "198.51.100.0/24"


async def test_dns(snap: Snapshot) -> None:
    (dns,) = snap.dns_services
    assert dns.enabled
    assert [str(a) for a in dns.listen] == ["192.0.2.1", "198.51.100.1", "2001:db8:1::1"]
    assert [str(a) for a in dns.forwarders] == ["192.0.2.53", "2001:db8:53::53"]
    assert [(h.name, str(h.address)) for h in dns.host_records] == [
        ("nas.home.example", "192.0.2.10"),
        ("nas.home.example", "2001:db8:1::10"),
    ]  # not disabled, CNAME or regexp entries
    assert dns.vendor_extra == {"dynamic-servers": "203.0.113.1", "cache-size": "2048"}


async def test_dns_without_remote_requests(http_url: str, sim: MikrotikSimulator) -> None:
    sim.data[DNS]["allow-remote-requests"] = "false"
    (dns,) = (await observe(adapter(http_url))).dns_services
    assert not dns.enabled and dns.listen == []


async def test_wireless(snap: Snapshot) -> None:
    radios = {r.name: r for r in snap.radios}
    assert sorted(radios) == ["wifi1", "wifi2"]  # wifi3 is a virtual AP on wifi1
    r1, r2 = radios["wifi1"], radios["wifi2"]
    assert (r1.band, r1.channel, r1.width_mhz, r1.tx_power_dbm, r1.country) == (
        Band.GHZ_2_4,
        6,
        40,
        17,
        "Germany",
    )
    assert (r2.band, r2.channel, r2.width_mhz, r2.tx_power_dbm) == (Band.GHZ_5, None, 80, 23)
    wlans = {w.id: w for w in snap.wlans}
    home = wlans["rt/wlan/wifi1"]
    assert (home.ssid, home.security, home.pmf) == ("Example", Security.WPA2_WPA3, Pmf.OPTIONAL)
    assert home.passphrase_fingerprint == passphrase_fingerprint("Example", PASSPHRASE)
    assert PASSPHRASE not in snap.model_dump_json()
    assert (home.roaming_80211r, home.roaming_80211k, home.roaming_80211v) == (True, True, True)
    assert home.segment_id == "home/segment/native"
    five = wlans["rt/wlan/wifi2"]  # SSID from a configuration profile
    assert five.ssid == "Example" and five.radio_id == "rt/radio/wifi2"
    iot = wlans["rt/wlan/wifi3"]
    assert (iot.ssid, iot.radio_id, iot.security, iot.hidden) == (
        "Example-IoT",
        "rt/radio/wifi1",
        Security.WPA2,
        True,
    )
    assert iot.segment_id == "home/segment/20"


async def test_wifi_odd_entries(http_url: str, sim: MikrotikSimulator) -> None:
    sim.data[WIFI] += [
        {"name": "wifi9", "channel.frequency": "5955,5975", "configuration.ssid": "Six"},
        {"name": "wifi8", "configuration.mode": "station", "channel.band": "5ghz-ax"},
        {"name": "wifi7"},  # no band, no frequency: not a radio we can describe
        {"name": "wifi6", "master-interface": "wifi7", "configuration.ssid": "Lost"},
        {
            "name": "wifi5",
            "master-interface": "wifi9",
            "configuration.ssid": "Vlan",
            "datapath.vlan-id": "30",
            "security.authentication-types": "",
        },
    ]
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors
    six = next(r for r in snap.radios if r.name == "wifi9")
    assert (six.band, six.channel) == (Band.GHZ_6, 1)
    assert "rt/radio/wifi7" not in {r.id for r in snap.radios}
    wlans = {w.id: w for w in snap.wlans}
    assert "rt/wlan/wifi8" not in wlans and "rt/wlan/wifi6" not in wlans
    assert (wlans["rt/wlan/wifi9"].security, wlans["rt/wlan/wifi9"].segment_id) == (
        Security.OPEN,
        None,
    )
    assert wlans["rt/wlan/wifi5"].segment_id == "home/segment/30"


async def test_legacy_wireless(http_url: str, sim: MikrotikSimulator) -> None:
    sim.wireless = "legacy"
    sim.data["/rest/interface/wireless"].append({"name": "wlan9", "frequency": "auto"})  # no band
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors
    radios = {r.name: r for r in snap.radios}
    assert sorted(radios) == ["wlan1", "wlan2"]
    assert (radios["wlan1"].band, radios["wlan1"].channel, radios["wlan1"].width_mhz) == (
        Band.GHZ_2_4,
        1,
        40,
    )
    assert (radios["wlan2"].band, radios["wlan2"].channel, radios["wlan2"].enabled) == (
        Band.GHZ_5,
        None,
        False,
    )
    wlans = {w.id: w for w in snap.wlans}
    assert sorted(wlans) == ["rt/wlan/wlan1", "rt/wlan/wlan2", "rt/wlan/wlan3"]  # no station
    home = wlans["rt/wlan/wlan1"]
    assert (home.security, home.pmf) == (Security.WPA2, Pmf.OPTIONAL)
    assert home.passphrase_fingerprint == passphrase_fingerprint("Example", PASSPHRASE)
    assert not wlans["rt/wlan/wlan2"].enabled
    guest = wlans["rt/wlan/wlan3"]
    assert (guest.security, guest.segment_id, guest.passphrase_fingerprint) == (
        Security.OPEN,
        "home/segment/30",
        None,
    )
    by_mac = {c.mac: c for c in snap.clients}
    assert by_mac["02:00:00:00:00:23"].seen_on == "rt/wlan/wlan1"


async def test_no_wireless_package(http_url: str, sim: MikrotikSimulator) -> None:
    sim.wireless = "none"
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert errors(snap) == {
        "wireless": f"no wireless package: neither {WIFI} nor /rest/interface/wireless exists "
        "on this device"
    }
    assert snap.clients and snap.subnets


async def test_clients(snap: Snapshot) -> None:
    by_mac = {c.mac: c for c in snap.clients}
    assert sorted(by_mac) == [
        "02:00:00:00:00:10",
        "02:00:00:00:00:20",
        "02:00:00:00:00:21",
        "02:00:00:00:00:22",
        "02:00:00:00:00:50",
    ]  # not the router's own MACs, not the uplink's neighbour, not the failed ARP entry
    printer = by_mac["02:00:00:00:00:10"]
    assert [str(a) for a in printer.addresses] == ["192.0.2.10", "2001:db8:1::10"]
    assert printer.hostname == "PRN-0010"  # from the (static, bound) lease
    assert (printer.segment_id, printer.seen_on) == ("home/segment/native", P("rt", "ether3"))
    sensor = by_mac["02:00:00:00:00:20"]
    assert (sensor.segment_id, sensor.seen_on) == ("home/segment/20", P("rt", "ether4"))
    phone = by_mac["02:00:00:00:00:22"]
    assert (phone.hostname, phone.segment_id, phone.seen_on) == (
        "phone",
        "home/segment/20",
        "rt/wlan/wifi3",
    )
    assert by_mac["02:00:00:00:00:21"].hostname == "laptop"


async def test_neighbours(snap: Snapshot) -> None:
    (nb,) = snap.neighbours  # the entry without a MAC is skipped
    assert (nb.local_port_id, nb.chassis_id, nb.remote_port, nb.system_name) == (
        P("rt", "ether2"),
        "02:00:00:00:00:50",
        "ether24",
        "switch",
    )
    assert nb.management_address == "192.0.2.2"
    assert nb.vendor_extra["discovered-by"] == "lldp,mndp"


# --- other layouts ---------------------------------------------------------------------------


async def test_bridge_without_vlan_filtering(http_url: str, sim: MikrotikSimulator) -> None:
    sim.data[BRIDGE][0]["vlan-filtering"] = "false"
    sim.data[INTERFACE].append(
        {"name": "ether6", "type": "ether", "mac-address": "02:00:00:00:00:09", "running": "true"}
    )
    sim.data[IP_ADDRESS].append({"address": "203.0.113.129/25", "interface": "ether6"})
    sim.data[VLAN].append({"name": "guest", "vlan-id": "30", "interface": "ether3"})
    sim.data[VLAN].append({"name": "bad", "vlan-id": "0", "interface": "ether3"})
    sim.data[VLAN].append({"name": "wan-vlan", "vlan-id": "7", "interface": "ether1"})
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors
    segs = {s.id: s for s in snap.segments}
    assert sorted(segs) == [
        "home/segment/20",
        "home/segment/30",
        "home/segment/ether6",
        "home/segment/native",
    ]
    native = segs["home/segment/native"]
    assert [m.port_id for m in native.members] == [
        P("rt", n) for n in ("ether2", "ether3", "ether4", "ether5", "wifi1", "wifi2", "wifi3")
    ]
    assert segs["home/segment/20"].members == []  # VLAN interface on the bridge itself
    assert [(m.port_id, m.mode) for m in segs["home/segment/30"].members] == [
        (P("rt", "ether3"), Membership.TAGGED)
    ]
    assert [m.port_id for m in segs["home/segment/ether6"].members] == [P("rt", "ether6")]
    assert ("home/segment/ether6", "203.0.113.129/25") in {
        (s.segment_id, str(s.interface)) for s in snap.subnets
    }
    wlans = {w.id: w for w in snap.wlans}
    assert wlans["rt/wlan/wifi3"].segment_id == "home/segment/native"  # bridge port wins


async def test_router_without_bridge(http_url: str, sim: MikrotikSimulator) -> None:
    for path in (BRIDGE, BRIDGE_PORT, BRIDGE_VLAN, BRIDGE_HOST, VLAN):
        sim.data[path] = []
    sim.data[IP_ADDRESS] = [
        {"address": "192.0.2.1/24", "interface": "ether2"},
        {"address": "198.51.100.1/24", "interface": "ether3"},
        {"address": "bogus", "interface": "ether4"},
    ]
    del sim.data[IPV6_ADDRESS]  # ipv6 package disabled
    del sim.data[LIST_MEMBER]
    snap = await observe(adapter(http_url))
    segs = {s.id: [m.port_id for m in s.members] for s in snap.segments}
    assert segs == {
        "home/segment/native": [P("rt", "ether2")],
        "home/segment/ether3": [P("rt", "ether3")],
    }
    # Without the WAN list the uplink with its address is a network of its own.
    assert {s.segment_id for s in snap.subnets} == {
        "home/segment/native",
        "home/segment/ether3",
    }
    assert errors(snap) == {}


async def test_odd_data_is_tolerated(http_url: str, sim: MikrotikSimulator) -> None:
    sim.data[INTERFACE] += [
        {"name": "", "type": "ether"},
        {"name": "wg0", "type": "wg", "running": "true"},
        {"name": "bond1", "type": "bond"},
        "not a row",
    ]
    sim.data[BRIDGE_VLAN] += [
        {"bridge": "other", "vlan-ids": "40"},  # a bridge we do not know
        {"bridge": "bridge", "vlan-ids": "100-102,abc,0", "tagged": "ether2,nonexistent"},
        {"bridge": "bridge", "vlan-ids": "50", "disabled": "true"},
    ]
    sim.data[BRIDGE_PORT].append(
        {"interface": "bond1", "bridge": "bridge", "frame-types": "admit-only-vlan-tagged"}
    )
    sim.data[IP_ADDRESS] += [
        {"address": "192.0.2.200/24", "interface": "bridge", "disabled": "true"},
        {"address": "127.0.0.1/8", "interface": "lo"},
    ]
    sim.data[DHCP_SERVER] += [
        {"name": "wan-dhcp", "interface": "ether1"},  # on the uplink: skipped
        {"name": "", "interface": "bridge"},
        {"name": "off", "interface": "bridge", "disabled": "true", "lease-time": "nonsense"},
    ]
    sim.data[POOL].append({"name": "loop", "ranges": "192.0.2.50/31,x-y", "next-pool": "loop"})
    sim.data[DHCP_SERVER][-1]["address-pool"] = "loop"
    sim.data["/rest/ip/dhcp-server/network"].append({"address": "nonsense"})
    sim.data[DHCP_LEASE] += [
        {"address": "192.0.2.30", "mac-address": "02-00-00-00-00-30", "server": "all"},
        {"address": "x", "mac-address": "nonsense", "server": "defconf"},
        {"address": "192.0.2.31", "mac-address": "02:00:00:00:00:31", "disabled": "true"},
        {"address": "203.0.113.5", "mac-address": "02:00:00:00:00:32", "status": "bound"},
    ]
    sim.data[DNS_STATIC].append({"name": "", "address": "192.0.2.12"})
    sim.data[ARP] += [
        {"address": "198.51.100.77", "mac-address": "02:00:00:00:00:77", "interface": "x"},
        {"address": "192.0.2.98", "interface": "bridge", "status": "reachable"},  # no MAC
    ]
    sim.data[BRIDGE_HOST].append({"mac-address": "02:00:00:00:00:78", "interface": "ghost"})
    sim.data[NEIGHBOR].append({"interface": "ghost", "mac-address": "02:00:00:00:00:79"})
    sim.data[RESOURCE] = [sim.data[RESOURCE]]  # one object in a list is fine too

    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors
    ports = {p.name: p for p in snap.ports}
    assert "" not in ports and ports["wg0"].kind.value == "virtual"
    assert ports["bond1"].kind.value == "lag" and ports["bond1"].up is None
    segs = {s.id: s for s in snap.segments}
    assert "home/segment/40" not in segs and "home/segment/50" not in segs
    assert [m.port_id for m in segs["home/segment/101"].members] == [P("rt", "ether2")]
    assert P("rt", "bond1") not in [m.port_id for m in segs["home/segment/native"].members]
    servers = {s.id: s for s in snap.dhcp_servers}
    assert sorted(servers) == ["rt/dhcp/defconf", "rt/dhcp/iot-dhcp", "rt/dhcp/off"]
    off = servers["rt/dhcp/off"]
    assert not off.enabled and off.lease_seconds is None
    assert [(str(p.start), str(p.end)) for p in off.pools] == [("192.0.2.50", "192.0.2.51")]
    assert "02:00:00:00:00:30" in [r.mac for r in servers["rt/dhcp/defconf"].reservations]
    by_mac = {c.mac: c for c in snap.clients}
    assert by_mac["02:00:00:00:00:77"].segment_id == "home/segment/20"  # by address
    assert by_mac["02:00:00:00:00:32"].segment_id is None
    assert by_mac["02:00:00:00:00:78"].seen_on is None
    assert len(snap.neighbours) == 1


# --- refused paths ---------------------------------------------------------------------------


async def test_wrong_password(http_url: str) -> None:
    snap = await observe(adapter(http_url, password="wrong"))
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert "refused the credentials (HTTP 401)" in snap.errors[0].message


async def test_certificate_not_pinned(
    https_url: str, tls: TlsFiles, sim: MikrotikSimulator
) -> None:
    snap = await observe(adapter(https_url))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert tls.fingerprint in snap.errors[0].message and "not yet trusted" in snap.errors[0].message
    assert sim.requests == []  # nothing, credentials included, was sent


async def test_pin_mismatch(https_url: str, sim: MikrotikSimulator) -> None:
    snap = await observe(adapter(https_url, pin="ab" * 32))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert "new certificate" in snap.errors[0].message and sim.requests == []


async def test_certificate_swapped_after_probe(
    https_url: str, tmp_path: Path, sim: MikrotikSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = self_signed_certificate(tmp_path, "other")
    der = https_mod.ssl.PEM_cert_to_DER_cert(other.cert.read_text())

    async def fake_probe(host: str, port: int, timeout: float) -> bytes:
        return der

    monkeypatch.setattr(https_mod, "peer_certificate", fake_probe)
    snap = await observe(adapter(https_url, pin=other.fingerprint))
    assert snap.status is DeviceStatus.UNREACHABLE and "cannot reach" in snap.errors[0].message
    assert sim.requests == []


@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_unreachable(scheme: str) -> None:
    snap = await observe(adapter(f"{scheme}://127.0.0.1:{free_port()}"))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "127.0.0.1" in snap.errors[0].message


async def test_tls_handshake_timeout() -> None:
    with socket.socket() as silent:  # accepts TCP (backlog) but never speaks TLS
        silent.bind(("127.0.0.1", 0))
        silent.listen()
        port = silent.getsockname()[1]
        snap = await observe(adapter(f"https://127.0.0.1:{port}", timeout=0.3))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "within 0.3 s" in snap.errors[0].message


async def test_timeout(http_url: str, sim: MikrotikSimulator) -> None:
    sim.delay = 1.0
    snap = await observe(adapter(http_url, timeout=0.2))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "within 0.2 s" in snap.errors[0].message


async def test_rest_disabled(http_url: str, sim: MikrotikSimulator) -> None:
    sim.rest_enabled = False
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert errors(snap) == {"system": f"{RESOURCE}: not found (HTTP 404); is the API enabled?"}


async def test_malformed_json_is_partial(http_url: str, sim: MikrotikSimulator) -> None:
    sim.malformed = {ARP}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert errors(snap) == {"clients": f"{ARP}: answer is not valid JSON"}
    assert snap.subnets and snap.dhcp_servers and snap.wlans and not snap.clients


async def test_malformed_interfaces_hit_every_capability(
    http_url: str, sim: MikrotikSimulator
) -> None:
    sim.malformed = {INTERFACE}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert set(errors(snap)) == {"interfaces", "dhcp", "dns", "wireless", "clients", "neighbours"}


async def test_menu_without_the_policy(http_url: str, sim: MikrotikSimulator) -> None:
    """RouterOS answers a menu the group may not read with HTTP 500 (seen on 7.25.1 CHR)."""
    sim.no_policy = {DNS_STATIC}
    snap = await observe(adapter(http_url))
    assert errors(snap) == {
        "dns": f"{DNS_STATIC}: access denied (not enough permissions (9)); "
        "check the user's group policies"
    }


async def test_missing_policy(http_url: str, sim: MikrotikSimulator) -> None:
    sim.fail = {DNS_STATIC: 403, NEIGHBOR: 500}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert errors(snap) == {
        "dns": f"{DNS_STATIC}: access denied (HTTP 403); check the user's privileges",
        "neighbours": f"{NEIGHBOR}: HTTP 500 Internal Server Error",
    }


@pytest.mark.parametrize(
    ("path", "value", "capability", "needle"),
    [
        (RESOURCE, {"board-name": "x"}, "system", f"unexpected answer from {RESOURCE}: no version"),
        (RESOURCE, "nonsense", "system", "str, expected an object"),
        (INTERFACE, {"name": "ether1"}, "interfaces", f"{INTERFACE}: dict, expected a list"),
        (DNS, [], "dns", f"unexpected answer from {DNS}: list, expected an object"),
        (POOL, None, "dhcp", f"unexpected answer from {POOL}: NoneType, expected a list"),
        (WIFI, {}, "wireless", WIFI),
        (BRIDGE_HOST, 5, "clients", BRIDGE_HOST),
    ],
)
async def test_unexpected_shapes(
    http_url: str, sim: MikrotikSimulator, path: str, value: Any, capability: str, needle: str
) -> None:
    sim.data[path] = value
    snap = await observe(adapter(http_url))
    assert needle in errors(snap)[capability]


# --- config and helpers ----------------------------------------------------------------------


def test_config_validation() -> None:
    def cfg(url: str, insecure: bool = False) -> MikrotikConfig:
        return MikrotikConfig(url=url, password=SecretStr("p"), allow_insecure_http=insecure)

    c = cfg("https://192.0.2.1:8443/")
    assert (c.url, c.username) == ("https://192.0.2.1:8443", USER)
    assert cfg("http://192.0.2.1", insecure=True).allow_insecure_http
    with pytest.raises(ValidationError, match="allow_insecure_http"):
        cfg("http://192.0.2.1")
    with pytest.raises(ValidationError, match="device's address"):
        cfg("ftp://192.0.2.1")
    assert MikrotikConfig.model_json_schema()["properties"]["password"]["format"] == "password"


def test_parsing_helpers() -> None:
    assert vlan_ids("1,20, 100-102,5000,x,3-2") == [1, 20, 100, 101, 102]
    assert vlan_ids(["7", 8]) == [7]
    assert duration("30m") == 1800 and duration("1d00:00:00") == 86400
    assert duration("00:10:00") == 600 and duration("1w2d3h4m5s") == 788645
    assert duration("") is None and duration("soon") is None and duration(None) is None
    assert speed("2.5G-baseT") == (2500, None) and speed("10Gbps") == (10000, None)
    assert speed("") == (None, None) and speed("auto") == (None, None)
    assert frequency_channel(2484) == (Band.GHZ_2_4, 14)
    assert frequency_channel(5180) == (Band.GHZ_5, 36) and frequency_channel(900) is None
    assert band_of("2ghz-onlyn") is Band.GHZ_2_4 and band_of("60ghz") is None
    assert width_of("20/40/80/160mhz") == 160 and width_of("") is None
    assert width_of("20/40mhz-Ce") == 40
    assert security_of("wpa3-psk") is Security.WPA3
    assert security_of("wpa2-eap") is Security.WPA2_ENTERPRISE
    assert security_of("wpa3-eap,wpa2-eap") is Security.WPA3_ENTERPRISE
    assert security_of("owe") is Security.OWE and security_of("wep") is Security.OTHER
    assert security_of("wpa2-psk", mode="none") is Security.OPEN
    assert _object([{"a": "1"}], "/x") == {"a": "1"}
    assert _int(True) is None and _int(5) == 5 and _int("-3dBm") == -3


@pytest.mark.parametrize("header", ["Bearer x", "Basic !!!", "Basic //8="])
async def test_simulator_rejects_odd_auth(http_url: str, header: str) -> None:
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.get(http_url + RESOURCE, headers={"Authorization": header})
    assert response.status_code == 401
