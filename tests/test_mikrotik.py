"""MikroTik adapter against its simulator, over real sockets (plain HTTP and pinned TLS)."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
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
    CLOCK,
    DHCP_LEASE,
    DHCP_SERVER,
    DNS,
    DNS_STATIC,
    HEALTH,
    INTERFACE,
    IP_ADDRESS,
    IPV6_ADDRESS,
    LIST_MEMBER,
    NEIGHBOR,
    NTP_CLIENT,
    NTP_SERVER,
    PACKAGE_UPDATE,
    POOL,
    RESOURCE,
    ROUTERBOARD,
    VLAN,
    WIFI,
    WIFI_RADIO,
    WIFI_REGISTRATION,
    MikrotikAdapter,
    MikrotikConfig,
    _int,
    _object,
    advertised,
    band_of,
    bridge_port_details,
    channels_of,
    cipher_of,
    ciphers_of,
    clock_date,
    duration,
    flow_control,
    frequency_channel,
    gmt_offset,
    health_rows,
    mtu_of,
    security_of,
    speed,
    standard_of,
    standards_of,
    time_of,
    vlan_ids,
    width_of,
    wireguard_peers,
    wireguard_rows,
    wps_of,
)
from signalbox.model import (
    Band,
    Cipher,
    DeviceRole,
    DeviceStatus,
    Dhcp6Mode,
    FrameTypes,
    LeaseState,
    Membership,
    NtpClient,
    NtpServer,
    Pmf,
    PortKind,
    PortRole,
    RaMode,
    SaePwe,
    Security,
    Snapshot,
    WifiStandard,
    WpsMethod,
    passphrase_digest,
    passphrase_fingerprint,
    port_id,
)
from signalbox.sim.mikrotik import (
    PASSPHRASE,
    PASSWORD,
    USER,
    WG_KEY,
    WG_SITE,
    MikrotikSimulator,
    _wg_key,
)
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract, passphrase_digest_key

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


async def test_bootloader_versions(http_url: str, sim: MikrotikSimulator, snap: Snapshot) -> None:
    """RouterBOOT: installed ``current-firmware`` and bundled ``upgrade-firmware`` (#444)."""
    assert (snap.device.bootloader, snap.device.bootloader_available) == ("7.15.3", "7.15.3")
    sim.data[ROUTERBOARD] = {**sim.data[ROUTERBOARD], "upgrade-firmware": "7.16"}
    d = (await observe(adapter(http_url))).device
    assert (d.bootloader, d.bootloader_available) == ("7.15.3", "7.16")
    sim.data[ROUTERBOARD] = {"routerboard": "false"}  # CHR: no boot loader
    d = (await observe(adapter(http_url))).device
    assert d.bootloader is None and d.bootloader_available is None


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


async def test_port_structure(snap: Snapshot) -> None:
    """Roles and lower ports (#252, ADR 0008)."""
    ports = {p.name: p for p in snap.ports}
    ids = {n: p.id for n, p in ports.items()}
    assert {n: p.role for n, p in ports.items()} == {
        "ether1": PortRole.JACK,
        "ether2": PortRole.JACK,
        "ether3": PortRole.JACK,
        "ether4": PortRole.JACK,
        "ether5": PortRole.JACK,
        "bridge": PortRole.BRIDGE,
        "iot": PortRole.VLAN,
        "switch1-cpu": PortRole.CPU,
        "wg0": PortRole.TUNNEL,
        "wifi1": PortRole.WIRELESS,
        "wifi2": PortRole.WIRELESS,
        "wifi3": PortRole.WIRELESS,
    }
    assert ports["bridge"].lower == [ids[n] for n in ("ether2", "ether3", "ether4", "ether5")] + [
        ids[n] for n in ("wifi1", "wifi2", "wifi3")
    ]
    assert ports["iot"].lower == [ids["bridge"]]
    assert ports["ether2"].lower == [ids["switch1-cpu"]] and ports["ether1"].lower == []
    assert ports["wifi3"].lower == [ids["wifi1"]]
    assert ports["wg0"].kind is PortKind.VIRTUAL
    assert [w.port_id for w in snap.wlans if w.ssid == "Example-IoT"] == [ids["wifi3"]]
    assert ports["ether1"].external is True and ports["bridge"].external is False


async def test_bonding_members(http_url: str, sim: MikrotikSimulator) -> None:
    sim.data["/rest/interface"].append(
        {".id": "*99", "name": "bond1", "type": "bond", "running": "true", "disabled": "false"}
    )
    sim.data["/rest/interface/bonding"] = [{"name": "bond1", "slaves": "ether4,ether5"}]
    obs = await observe(adapter(http_url))
    ports = {p.name: p for p in obs.ports}
    assert ports["bond1"].role is PortRole.LAG and ports["bond1"].kind is PortKind.LAG
    assert ports["bond1"].lower == [ports["ether4"].id, ports["ether5"].id]


async def test_ports(snap: Snapshot) -> None:
    ports = {p.name: p for p in snap.ports}
    assert sorted(ports) == [
        "bridge",
        "ether1",
        "ether2",
        "ether3",
        "ether4",
        "ether5",
        "iot",
        "switch1-cpu",
        "wg0",
        "wifi1",
        "wifi2",
        "wifi3",
    ]  # no loopback
    e1 = ports["ether1"]
    assert (e1.up, e1.speed_mbps, e1.full_duplex, e1.mac) == (True, 1000, True, "02:00:00:00:00:01")
    assert (e1.description, e1.admin_up, e1.mtu, e1.l2_mtu) == ("uplink", True, 1500, 1568)
    assert e1.vendor_extra == {"type": "ether"}  # comment, mtu and disabled are fields now
    assert e1.advertised_speeds_mbps == [10, 100, 1000] and e1.autoneg is True
    assert e1.flow_control is False and e1.pvid is None  # ether1 is in no bridge
    e3 = ports["ether3"]
    assert (e3.autoneg, e3.advertised_speeds_mbps, e3.flow_control) == (False, [], True)
    assert (e3.pvid, e3.frame_types, e3.ingress_filter) == (1, FrameTypes.UNTAGGED_ONLY, True)
    assert (ports["ether4"].pvid, ports["wifi3"].pvid) == (20, 20)
    assert ports["wifi1"].frame_types is FrameTypes.ALL and ports["wifi1"].l2_mtu == 1568
    assert ports["ether5"].ingress_filter is False
    bridge = ports["bridge"]
    assert (bridge.description, bridge.pvid, bridge.frame_types) == ("LAN", 1, FrameTypes.ALL)
    assert bridge.l2_mtu is None and bridge.advertised_speeds_mbps == []
    assert (ports["ether2"].speed_mbps, ports["ether2"].full_duplex) == (1000, None)
    assert (ports["ether3"].speed_mbps, ports["ether3"].full_duplex) == (100, False)
    assert ports["ether5"].up is False and ports["ether5"].admin_up is False
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


async def test_dhcp_leases_options_and_relay(snap: Snapshot) -> None:
    servers = {s.id: s for s in snap.dhcp_servers}
    lan, iot = servers["rt/dhcp/defconf"], servers["rt/dhcp/iot-dhcp"]
    assert lan.leases is not None and iot.leases is not None
    printer, laptop = lan.leases
    assert (printer.state, printer.reserved, printer.hostname) == (
        LeaseState.ACTIVE,
        True,
        "PRN-0010",
    )
    assert printer.expires is None  # static lease: no countdown
    assert (laptop.state, laptop.reserved, laptop.vendor_class) == (
        LeaseState.ACTIVE,
        False,
        "android-dhcp-14",
    )
    assert laptop.client_id == "1:02:00:00:00:00:21" and laptop.expires is not None
    assert 1400 < (laptop.expires - datetime.now(UTC)).total_seconds() <= 1510
    sensor, phone, offered = iot.leases
    assert (sensor.state, sensor.reserved) == (LeaseState.RESERVED, True)  # status waiting
    assert phone.expires is not None and offered.state is LeaseState.OFFERED
    assert offered.mac == "02:00:00:00:00:23" and offered.hostname is None
    assert lan.search_domains == ["home.example"]
    assert [(str(r.destination), str(r.gateway)) for r in lan.static_routes] == [
        ("203.0.113.0/24", "192.0.2.254")
    ]
    assert lan.boot is not None
    assert (str(lan.boot.next_server), lan.boot.filename) == ("192.0.2.5", "pxelinux.0")
    assert [(o.code, o.name, o.value) for o in lan.options] == [
        (252, "wpad", "'http://192.0.2.1/wpad.dat'")
    ]
    assert lan.authoritative is True and iot.authoritative is None and iot.options == []
    (relay,) = snap.dhcp_relays
    assert (relay.id, relay.segment_id) == ("rt/dhcp-relay/20", "home/segment/20")
    assert [str(a) for a in relay.servers] == ["192.0.2.53"] and relay.enabled


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


async def test_wifi_security_details(http_url: str) -> None:
    with passphrase_digest_key():
        snap = await observe(adapter(http_url))
        expected = passphrase_digest(PASSPHRASE), passphrase_digest("iot-passphrase")
    wlans = {w.id: w for w in snap.wlans}
    home, iot = wlans["rt/wlan/wifi1"], wlans["rt/wlan/wifi3"]
    assert expected[0] and expected[0] != expected[1]
    assert (home.passphrase_digest, iot.passphrase_digest) == expected
    assert home.ciphers == [Cipher.CCMP] and home.group_cipher is Cipher.CCMP
    assert home.sae is not None
    assert (home.sae.pwe, home.sae.anti_clogging_threshold) == (SaePwe.BOTH, 5)
    assert home.wps is not None and home.wps.enabled is False
    assert home.key_rotation_seconds == 3600 and home.beacon_protection is None
    assert iot.ciphers == [Cipher.CCMP, Cipher.TKIP] and iot.group_cipher is None
    assert iot.sae is None and iot.wps is not None and iot.wps.methods == [WpsMethod.PUSH_BUTTON]
    assert iot.key_rotation_seconds is None
    for r in snap.radios:
        assert r.supported_security is not None and Security.WPA3 in r.supported_security


async def test_legacy_wireless_security_details(http_url: str, sim: MikrotikSimulator) -> None:
    sim.wireless = "legacy"
    with passphrase_digest_key():
        snap = await observe(adapter(http_url))
        expected = passphrase_digest(PASSPHRASE)
    wlans = {w.id: w for w in snap.wlans}
    home, guest = wlans["rt/wlan/wlan1"], wlans["rt/wlan/wlan3"]
    assert expected and home.passphrase_digest == expected
    assert home.ciphers == [Cipher.CCMP] and home.group_cipher is Cipher.CCMP
    assert home.key_rotation_seconds == 300 and home.sae is None
    assert home.wps is not None and home.wps.methods == [WpsMethod.PUSH_BUTTON]
    assert guest.passphrase_digest is None and guest.ciphers is None and guest.wps is None
    assert guest.key_rotation_seconds is None
    for r in snap.radios:
        assert r.supported_security is not None and Security.WPA3 not in r.supported_security
        assert Security.WEP in r.supported_security


@pytest.mark.parametrize(
    ("types", "mode", "expected"),
    [
        ("wpa-psk", "dynamic-keys", Security.WPA),
        ("wpa-psk,wpa2-psk", "dynamic-keys", Security.WPA_WPA2),
        ("wpa2-psk", None, Security.WPA2),
        ("", "static-keys-required", Security.WEP),
        ("wpa-eap", None, Security.WPA_ENTERPRISE),
        ("wpa-eap,wpa2-eap", None, Security.WPA_ENTERPRISE),
        ("wpa2-eap", None, Security.WPA2_ENTERPRISE),
        ("wpa3-eap", None, Security.WPA3_ENTERPRISE),
        ("wpa3-eap-192", None, Security.WPA3_ENTERPRISE_192),
        ("ft-psk", None, Security.OTHER),
    ],
)
def test_security_modes(types: str, mode: str | None, expected: Security) -> None:
    assert security_of(types, mode) is expected


def test_cipher_helpers() -> None:
    assert ciphers_of("aes-ccm,tkip", Security.WPA2) == [Cipher.CCMP, Cipher.TKIP]
    assert ciphers_of("ccmp,bogus", Security.WPA2) is None and ciphers_of("", Security.WPA2) is None
    assert ciphers_of("ccmp", Security.OPEN) is None
    assert (
        ciphers_of("", Security.WEP) == [Cipher.WEP] and cipher_of("", Security.WEP) is Cipher.WEP
    )
    assert cipher_of("gcmp-256", Security.WPA3_ENTERPRISE_192) is Cipher.GCMP_256
    assert cipher_of("ccmp", Security.OPEN) is None and cipher_of("", Security.WPA2) is None
    assert wps_of("disabled") is not None and wps_of("push-button-virtual-only") is not None
    assert wps_of("") is None and wps_of("pin") is None


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
    assert {str(a): s.value for a, s in printer.address_sources.items()} == {
        "192.0.2.10": "dhcp-reserved"
    }  # the IPv6 address comes from the neighbour table: not known
    assert (printer.segment_id, printer.seen_on) == ("home/segment/native", P("rt", "ether3"))
    # the bridge host table as forwarding database entries (#160)
    fdb = {(e.port_id, e.mac): e for e in snap.fdb}
    assert fdb[(P("rt", "ether3"), printer.mac)].kind.value == "dynamic"
    assert fdb[(P("rt", "ether4"), "02:00:00:00:00:20")].vlan == 20
    own = [e for e in snap.fdb if e.kind.value == "self"]
    assert [(e.port_id, e.segment_id) for e in own] == [(P("rt", "bridge"), "home/segment/native")]
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
    # the enabled system capabilities, not the announced ones (#113)
    assert nb.capabilities == ["bridge", "router"]
    assert nb.description == "MikroTik RouterOS 7.15.3 CRS326-24G-2S+"
    # protocol, age and VLAN (#163)
    assert (nb.protocol, nb.chassis_id_kind, nb.age_seconds, nb.port_vlan) == ("lldp", "mac", 65, 1)


def test_duration_and_vlan_helpers() -> None:
    from signalbox.adapters.mikrotik import _duration_s, _vlan_id

    assert _duration_s("1w2d3h4m5s") == 604800 + 2 * 86400 + 3 * 3600 + 245
    assert _duration_s("12") == 12 and _duration_s("") is None
    assert _vlan_id("20") == 20 and _vlan_id("0") is None and _vlan_id(None) is None


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


ROS6_MESSAGE = (
    f"RouterOS 6 is not supported: {RESOURCE} has no REST API (RouterOS 6 answers 404 or a web "
    "page there). Signalbox needs RouterOS 7.1 or newer"
)


NO_REST_MESSAGE = (
    "no RouterOS REST API at this address (RouterOS 6, REST disabled, or wrong address/port)"
)


async def test_routeros6_page_does_not_claim_version_6(
    http_url: str, sim: MikrotikSimulator
) -> None:
    """A 404 web page may be RouterOS 6 or any other service: the message says so (#425)."""
    sim.routeros6 = True
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert errors(snap) == {"system": NO_REST_MESSAGE}
    assert "RouterOS 6 is not supported" not in snap.errors[0].message
    assert "SNMP" in (snap.errors[0].fix or "")


async def test_routeros6_known_version_is_not_supported(
    http_url: str, sim: MikrotikSimulator
) -> None:
    sim.data[RESOURCE]["version"] = "6.48.6 (stable)"
    snap = await observe(adapter(http_url))
    assert errors(snap) == {"system": ROS6_MESSAGE}
    assert "7.1" in (snap.errors[0].fix or "") and "SNMP" in (snap.errors[0].fix or "")


async def test_routeros6_version_string(http_url: str, sim: MikrotikSimulator) -> None:
    sim.data[RESOURCE]["version"] = "6.49.10 (long-term)"
    snap = await observe(adapter(http_url))
    assert errors(snap) == {"system": ROS6_MESSAGE}


async def test_rest_disabled(http_url: str, sim: MikrotikSimulator) -> None:
    sim.rest_enabled = False
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert errors(snap) == {"system": NO_REST_MESSAGE}


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
    assert set(errors(snap)) == {
        "interfaces",
        "dhcp",
        "dns",
        "wireless",
        "clients",
        "neighbours",
        "vpn",
        "firewall",
    }


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
    assert advertised("10M-full,100M-half,1000M-full") == [10, 100, 1000]
    assert advertised("2.5G-baseT,10G-baseSR-LR,x") == [2500, 10000] and advertised(None) == []
    assert mtu_of("auto", "1500") == 1500 and mtu_of("9", None) is None and mtu_of(None) is None
    assert flow_control({"rx-flow-control": "auto", "tx-flow-control": "off"}) is None
    assert flow_control({}) is None and flow_control({"tx-flow-control": "on"}) is True
    assert bridge_port_details({"pvid": "5000", "frame-types": "odd"}) == {
        "pvid": None,
        "frame_types": None,
        "ingress_filter": None,
    }
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


# --- health and time (#178, #179) ------------------------------------------------------------


async def test_health(snap: Snapshot) -> None:
    h = snap.device.health
    assert h is not None
    assert (h.uptime_seconds, h.cpu_load_pct, h.cpu_count) == (273906, 3, 4)
    assert (h.memory_total_bytes, h.memory_used_bytes) == (268435456, 268435456 - 190000000)
    assert [(s.name, s.kind.value, s.total_bytes, s.used_bytes) for s in h.storage] == [
        ("hdd", "system", 134217728, 134217728 - 103260160)
    ]
    assert [(t.name, t.value_c) for t in h.temperatures] == [("cpu-temperature", 52)]
    assert h.fans == h.power_supplies == []
    assert h.boot_time is not None and "health" in snap.device.capabilities


async def test_time(snap: Snapshot) -> None:
    t = snap.device.time
    assert t is not None and t.clock is not None and t.read_at is not None
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 2
    assert t.uncertainty_seconds is not None and 0.5 <= t.uncertainty_seconds < 2
    assert (t.timezone, t.utc_offset_minutes) == ("Europe/Berlin", 60)
    assert t.clock.utcoffset() == timedelta(hours=1)
    assert t.ntp_client == NtpClient(
        enabled=True,
        servers=["0.pool.ntp.org", "1.pool.ntp.org"],
        synchronised=True,
        stratum=2,
        current_server="203.0.113.123",
    )
    assert t.ntp_server == NtpServer(enabled=True)
    lan = next(s for s in snap.dhcp_servers if s.id == "rt/dhcp/defconf")
    iot = next(s for s in snap.dhcp_servers if s.id == "rt/dhcp/iot-dhcp")
    assert lan.ntp_servers == [ip_address("192.0.2.1")] and iot.ntp_servers == []


async def test_health_of_a_switch_with_fans_and_psus(http_url: str, sim: MikrotikSimulator) -> None:
    """A CRS3xx-like answer: temperatures, fans, PSU states, input voltage, odd rows."""
    sim.data[HEALTH] = [
        {".id": "*1", "name": "fan-state", "value": "ok", "type": ""},
        {".id": "*2", "name": "fan1-speed", "value": "5400", "type": "RPM"},
        {".id": "*3", "name": "fan2-speed", "value": "0", "type": "RPM"},
        {".id": "*4", "name": "fan2-state", "value": "fail", "type": ""},
        {".id": "*5", "name": "psu1-state", "value": "ok", "type": ""},
        {".id": "*6", "name": "psu2-state", "value": "fail", "type": ""},
        {".id": "*7", "name": "board-temperature1", "value": "38", "type": "C"},
        {".id": "*8", "name": "switch-temperature", "value": "61.5", "type": ""},
        {".id": "*9", "name": "voltage", "value": "24.1", "type": "V"},
        {".id": "*A", "name": "", "value": "1", "type": "C"},
        {".id": "*B", "name": "poe-out-status", "value": "on", "type": ""},
        {".id": "*C", "name": "jitter", "value": "-1", "type": "V"},
        "not a row",
    ]
    snap = await observe(adapter(http_url))
    h = snap.device.health
    assert h is not None
    assert [(f.name, f.rpm, f.ok) for f in h.fans] == [
        ("fan", None, True),
        ("fan1", 5400, None),
        ("fan2", 0, False),
    ]
    assert [(p.name, p.ok) for p in h.power_supplies] == [("psu1", True), ("psu2", False)]
    assert [(t.name, t.value_c) for t in h.temperatures] == [
        ("board-temperature1", 38),
        ("switch-temperature", 61.5),
    ]


async def test_health_of_chr_and_old_shapes(http_url: str, sim: MikrotikSimulator) -> None:
    """CHR has no sensors: RouterOS 7.25.1 answers one object with the monitoring state (seen
    in CI), which is nothing, not an error. A single object of values (older versions) with
    voltage and power consumption only, an empty list, no menu at all."""
    sim.data[HEALTH] = {"state": "disabled", "state-after-reboot": "enabled"}
    sim.data[RESOURCE] = {
        **sim.data[RESOURCE],
        "free-memory": "x",
        "total-hdd-space": "0",
        "cpu-load": "120",
    }
    snap = await observe(adapter(http_url))
    h = snap.device.health
    assert h is not None and not snap.errors
    assert h.temperatures == h.fans == h.power_supplies == h.storage == []
    assert h.memory_used_bytes is None and h.cpu_load_pct is None
    sim.data[HEALTH] = {"voltage": "12.2", "power-consumption": "4.5", "temperature": "41"}
    h = (await observe(adapter(http_url))).device.health
    assert h is not None
    assert [(p.name, p.input_voltage, p.watts) for p in h.power_supplies] == [("power", 12.2, 4.5)]
    assert [t.name for t in h.temperatures] == ["temperature"]
    sim.data[HEALTH] = []
    h = (await observe(adapter(http_url))).device.health
    assert h is not None and h.temperatures == []
    del sim.data[HEALTH]  # a device without the menu
    h = (await observe(adapter(http_url))).device.health
    assert h is not None and h.temperatures == [] and h.uptime_seconds == 273906


async def test_time_without_ntp_and_odd_clock(http_url: str, sim: MikrotikSimulator) -> None:
    sim.clock_ticks = False
    sim.data[CLOCK] = {"date": "nov/22/2026", "time": "25:00:00", "gmt-offset": "+05:30"}
    sim.data[NTP_CLIENT] = {
        "enabled": "false",
        "primary-ntp": "192.0.2.1",
        "secondary-ntp": "0.0.0.0",
    }
    del sim.data[NTP_SERVER]
    snap = await observe(adapter(http_url))
    t = snap.device.time
    assert t is not None
    assert t.read_at is None and t.utc_offset_minutes == 330
    assert t.ntp_client == NtpClient(enabled=False, servers=["192.0.2.1"])
    assert t.ntp_server is None and t.timezone is None
    del sim.data[NTP_CLIENT]
    sim.data[CLOCK] = {"date": "2026-11-22", "time": "10:00:00", "time-zone-name": "manual"}
    t = (await observe(adapter(http_url))).device.time
    assert t is not None and t.ntp_client is None and t.clock is None and t.timezone is None


async def test_time_errors_are_partial(http_url: str, sim: MikrotikSimulator) -> None:
    sim.no_policy = {CLOCK}
    sim.malformed = {HEALTH}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert set(errors(snap)) == {"time", "health"}
    assert snap.device.time is None and snap.device.health is None


def test_health_and_time_helpers() -> None:
    assert clock_date("nov/22/2026") == date(2026, 11, 22)
    assert clock_date("2026-11-22") == date(2026, 11, 22)
    assert clock_date("smarch/1/2026") is None and clock_date(None) is None
    assert gmt_offset("+01:00") == 60 and gmt_offset("-05:30") == -330
    assert gmt_offset(3600) == 60 and gmt_offset("-3600") == -60 and gmt_offset("") is None
    assert health_rows({".id": "*1", "temperature": "40"}) == [
        {"name": "temperature", "value": "40"}
    ]
    start = datetime(2026, 1, 1, tzinfo=UTC)
    far = time_of(
        {"date": "2026-01-01", "time": "00:00:00", "gmt-offset": "+20:00"}, None, None, start, start
    )
    assert far.utc_offset_minutes is None and far.clock is None
    ok = time_of(
        {"date": "2026-01-01", "time": "01:00:00", "gmt-offset": "+01:00"},
        {"enabled": "true", "servers": "a", "status": "started", "synced-stratum": "99"},
        {"enabled": "false"},
        start,
        start + timedelta(seconds=1),
    )
    assert ok.offset_seconds() == 0 and ok.uncertainty_seconds == 1
    assert ok.ntp_client == NtpClient(enabled=True, servers=["a"], synchronised=False)
    assert ok.ntp_server == NtpServer(enabled=False)


# --- management services (#173) --------------------------------------------------------------


async def test_services(snap: Snapshot) -> None:
    by = {s.id: s for s in snap.services}
    assert sorted(by) == sorted(
        f"rt/service/{n}"
        for n in (
            *("api", "api-ssl", "ftp", "ssh", "telnet", "winbox", "www", "www-ssl"),
            *("mac-telnet", "mac-winbox", "romon", "snmp", "upnp", "mikrotik-cloud"),
        )
    )
    ssh = by["rt/service/ssh"]
    assert (ssh.kind.value, ssh.port, ssh.enabled, ssh.encrypted) == ("ssh", 22, True, True)
    assert [str(n) for n in ssh.allowed_from] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert ssh.password_login is None  # password-authentication=yes-if-no-key
    assert by["rt/service/www"].kind.value == "http" and by["rt/service/www"].enabled
    assert by["rt/service/www-ssl"].kind.value == "https"
    assert not by["rt/service/telnet"].enabled and not by["rt/service/api-ssl"].enabled
    assert by["rt/service/api"].port == 8728 and by["rt/service/api"].encrypted is False
    mac = by["rt/service/mac-telnet"]  # list LAN = the bridge
    assert (mac.port, mac.transport.value, mac.interfaces) == (None, "layer2", ["rt/port/bridge"])
    assert not by["rt/service/mac-winbox"].enabled and not by["rt/service/romon"].enabled
    assert not by["rt/service/upnp"].enabled
    # dynamic rows (resolver, open connections) and unknown names are no services
    assert len([s for s in snap.services if s.kind.value == "https"]) == 1
    snmp = by["rt/service/snmp"]
    assert snmp.enabled and snmp.snmp is not None
    assert snmp.snmp.default_community and not snmp.snmp.write_access
    assert [v.value for v in snmp.snmp.versions] == ["2c"]


async def test_cloud_service(http_url: str, sim: MikrotikSimulator) -> None:
    """``/ip/cloud`` (#327): DDNS on, or ``auto`` that reached the cloud, or Back to Home."""

    async def cloud() -> Any:
        snap = await observe(adapter(http_url))
        return {s.id: s for s in snap.services}.get("rt/service/mikrotik-cloud")

    on = await cloud()  # the simulator: ddns-enabled auto, status updated
    assert on is not None and on.kind.value == "cloud" and on.enabled
    assert on.label() == "MikroTik Cloud"
    base = {"ddns-enabled": "no", "status": "", "back-to-home-vpn": "disabled"}
    for values, enabled in (
        ({"ddns-enabled": "yes"}, True),
        ({"ddns-enabled": "auto", "status": "updating..."}, False),
        ({}, False),
        ({"back-to-home-vpn": "enabled"}, True),
    ):
        sim.data["/rest/ip/cloud"] = base | values
        assert (await cloud()).enabled is enabled, values
    sim.no_policy.add("/rest/ip/cloud")
    assert await cloud() is None  # refused: not read, the rest still is


async def test_services_not_read_when_refused(http_url: str, sim: MikrotikSimulator) -> None:
    sim.no_policy.add("/rest/ip/service")
    snap = await observe(adapter(http_url))
    assert snap.services == [] and not snap.errors  # not read, the rest still is
    sim.no_policy.clear()
    sim.no_policy.update({"/rest/tool/romon", "/rest/snmp"})
    snap = await observe(adapter(http_url))
    kinds = {s.kind.value for s in snap.services}
    assert "ssh" in kinds and not kinds & {"romon", "snmp"}, kinds


async def test_snmp_v3_and_ssh_password(http_url: str, sim: MikrotikSimulator) -> None:
    sim.data["/rest/snmp/community"] = [
        {"name": "x", "security": "private", "encryption-protocol": "AES", "write-access": "true"},
        {"name": "y", "security": "authorized", "encryption-protocol": "DES"},
    ]
    sim.data["/rest/ip/ssh"] = {"password-authentication": "yes"}
    snap = await observe(adapter(http_url))
    by = {s.id: s for s in snap.services}
    snmp = by["rt/service/snmp"].snmp
    assert snmp is not None
    assert [v.value for v in snmp.versions] == ["3"] and snmp.write_access
    assert snmp.v3_privacy is False  # one user is authNoPriv
    assert not snmp.default_community
    assert by["rt/service/ssh"].password_login is True
    sim.data["/rest/snmp/community"].pop()
    sim.data["/rest/ip/ssh"] = {"password-authentication": "no"}
    snap = await observe(adapter(http_url))
    by = {s.id: s for s in snap.services}
    assert by["rt/service/snmp"].snmp.v3_privacy is True and by["rt/service/snmp"].encrypted
    assert by["rt/service/ssh"].password_login is False
    sim.data["/rest/ip/ssh"] = {"always-allow-password-login": "true"}  # RouterOS 7 before 7.25
    snap = await observe(adapter(http_url))
    assert {s.id: s for s in snap.services}["rt/service/ssh"].password_login is True


async def test_transport_encrypted(http_url: str) -> None:
    assert (await observe(adapter(http_url))).device.transport_encrypted is False


# --- WireGuard (#152) ------------------------------------------------------------------------


async def test_wireguard_tunnel_and_peers(snap: Snapshot) -> None:
    (t,) = snap.tunnels
    assert (t.id, t.name, t.description, t.up, t.listen_port, t.mtu) == (
        "rt/tunnel/wg0",
        "wg0",
        "site link",
        True,
        51820,
        1420,
    )
    assert t.public_key == WG_KEY and t.port_id == "rt/port/wg0"
    assert [str(a) for a in t.addresses] == ["2001:db8:ff::4/64"]
    site, phone = t.peers
    assert (site.name, site.endpoint_host, site.endpoint_port) == ("site-b", "198.51.100.77", 51820)
    assert [str(n) for n in site.allowed_ips] == ["2001:db8:ff::1/128", "203.0.113.0/24"]
    assert (site.keepalive_seconds, site.preshared_key, site.rx_bytes, site.tx_bytes) == (
        25,
        True,
        1834567,
        2934871,
    )
    age = site.handshake_age(datetime.now(UTC))
    assert age is not None and 40 <= age < 120
    assert (phone.name, phone.endpoint_host, phone.endpoint_port) == ("phone", None, None)
    assert (phone.latest_handshake, phone.keepalive_seconds, phone.preshared_key) == (
        None,
        0,
        False,
    )


async def test_a_tunnel_address_is_no_segment(snap: Snapshot) -> None:
    assert not any("wg0" in s.id for s in snap.segments)


async def test_no_private_or_preshared_key_leaves_the_adapter(http_url: str, sim: Any) -> None:
    secrets = [_wg_key("sim-secret-private"), _wg_key("sim-secret-psk")]
    assert all(s in str(sim.data) for s in secrets), "the sample must carry keys to be dropped"
    a = adapter(http_url)
    try:
        snap = await a.observe()
        assert not any(s in snap.model_dump_json() for s in secrets)
        assert not any(s in str(a._cache) for s in secrets)
    finally:
        await a.close()


async def test_wireguard_not_installed(http_url: str, sim: Any) -> None:
    del sim.data["/rest/interface/wireguard"]
    snap = await observe(adapter(http_url))
    assert snap.tunnels == [] and "vpn" not in errors(snap)


async def test_wireguard_needs_its_policy(http_url: str, sim: Any) -> None:
    sim.no_policy = {"/rest/interface/wireguard/peers"}
    snap = await observe(adapter(http_url))
    assert snap.tunnels == [] and "access denied" in errors(snap)["vpn"]


def test_wireguard_rows_drop_the_keys() -> None:
    rows = wireguard_rows(
        [
            {"private-key": "x", "preshared-key": "y", "n": 1},
            {"preshared-key": "auto"},
            {"preshared-key": ""},
            "odd",
        ],
        "/rest/interface/wireguard/peers",
    )
    assert rows == [
        {"n": 1, "preshared-key-set": True},
        {"preshared-key-set": False},
        {"preshared-key-set": False},
    ]


def test_wireguard_peers_are_parsed_defensively() -> None:
    now = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
    rows = wireguard_rows(
        [
            {"public-key": "bad"},
            {
                "public-key": WG_SITE,
                "current-endpoint-address": "203.0.113.9",
                "current-endpoint-port": "40000",
                "allowed-address": "192.0.2.0/24,nonsense",
                "last-handshake": "1m5s",
                "persistent-keepalive": "99999",
                "rx": "-5",
                "disabled": "true",
            },
            {"public-key": WG_SITE},
        ],
        "x",
    )
    (peer,) = wireguard_peers(rows, now)
    assert (peer.endpoint_host, peer.endpoint_port) == ("203.0.113.9", 40000)
    assert [str(n) for n in peer.allowed_ips] == ["192.0.2.0/24"]
    assert peer.latest_handshake == now - timedelta(seconds=65)
    assert (peer.keepalive_seconds, peer.rx_bytes, peer.enabled) == (0, None, False)


# --- log and flow targets (#180) -------------------------------------------------------------


async def test_log_targets(sim: MikrotikSimulator, http_url: str) -> None:
    sim.data["/rest/ip/traffic-flow"]["enabled"] = "true"
    sim.data["/rest/ip/traffic-flow/target"] = [
        {
            ".id": "*1",
            "dst-address": "192.0.2.5",
            "port": "2055",
            "version": "9",
            "disabled": "false",
        },
        {".id": "*2", "dst-address": "192.0.2.6", "version": "ipfix", "disabled": "true"},
        {".id": "*3", "dst-address": ""},
    ]
    sim.data["/rest/snmp"] |= {"trap-target": "192.0.2.5,0.0.0.0", "trap-generators": "interfaces"}
    a = adapter(http_url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    rows = [
        (t.kind.value, t.endpoint(), t.enabled, t.name, t.topics)
        for t in snap.device.log_targets or []
    ]
    assert rows == [
        (
            "syslog",
            "192.0.2.5:514",
            True,
            "syslog",
            ["info", "warning"],
        ),  # "remote" (0.0.0.0) is left out
        ("netflow", "192.0.2.5:2055", True, "traffic-flow", ["v9"]),
        ("ipfix", "192.0.2.6:2055", False, "traffic-flow", []),
        ("snmp-trap", "192.0.2.5:162", True, "snmp", ["interfaces"]),
    ]


async def test_log_targets_refused_and_unused(sim: MikrotikSimulator, http_url: str) -> None:
    sim.data["/rest/system/logging"] = []  # no rule uses the remote action
    a = adapter(http_url)
    try:
        snap = await a.observe()
        (t,) = snap.device.log_targets or []
        assert not t.enabled and t.topics == []
        sim.fail = {"/rest/system/logging/action": 403}
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.device.log_targets is None
    (gap,) = snap.errors
    assert gap.optional and gap.message.startswith("log targets") and snap.status.value == "ok"


# --- accounts (#175) -------------------------------------------------------------------------


async def test_accounts_with_policies_keys_and_login_times(
    sim: MikrotikSimulator, http_url: str
) -> None:
    from signalbox.model import AccountPrivilege

    sim.data["/rest/user"] += [
        {
            ".id": "*2",
            "name": USER,
            "group": "read",
            "disabled": "false",
            "address": "192.0.2.0/24,bad",
            "last-logged-in": "2026-11-20 10:11:12",
        },
        {".id": "*3", "name": "old", "group": "full", "disabled": "true"},
        {".id": "*4", "name": "ops", "group": "nope", "last-logged-in": "nov/02/2025 01:02:03"},
    ]
    sim.data["/rest/user/ssh-keys"] = [{".id": "*1", "user": "old", "key-owner": "x"}]
    snap = await assert_contract(adapter(http_url))
    by = {a.name: a for a in snap.device.accounts or []}
    assert by["admin"].privilege is AccountPrivilege.ADMIN and by["admin"].last_login is None
    own = by[USER]
    assert own.is_signalbox and own.privilege is AccountPrivilege.READ
    assert [str(n) for n in own.allowed_from] == ["192.0.2.0/24"]
    assert own.last_login == datetime(2026, 11, 20, 10, 11, 12, tzinfo=UTC)
    assert by["old"].key_auth and not by["old"].enabled and by["admin"].key_auth is False
    assert by["ops"].privilege is AccountPrivilege.OTHER
    assert by["ops"].last_login == datetime(2025, 11, 2, 1, 2, 3, tzinfo=UTC)
    assert all(a.password_set is None and a.logins_tracked for a in by.values())
    dev = snap.device
    assert dev.signalbox_account_privilege is AccountPrivilege.READ
    assert dev.signalbox_account_needed is AccountPrivilege.READ
    assert dev.default_credentials is False


async def test_accounts_refused_are_an_optional_gap(sim: MikrotikSimulator, http_url: str) -> None:
    sim.no_policy = {"/rest/user"}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK and snap.device.accounts is None
    (gap,) = [e for e in snap.errors if e.message.startswith("accounts:")]
    assert gap.optional and gap.message_id == "mikrotik.accounts"
    assert snap.device.signalbox_account_privilege is None


async def test_admin_without_password_is_the_factory_default(
    sim: MikrotikSimulator, http_url: str
) -> None:
    sim.username, sim.password = "admin", ""
    config = MikrotikConfig(
        url=http_url, username="admin", password=SecretStr(""), allow_insecure_http=True
    )
    a = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="rt",
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
        )
    )
    snap = await observe(a)
    assert snap.device.default_credentials is True
    assert snap.device.signalbox_account_privilege is not None
    assert sim.requests.count("/rest/user") == 1  # read once, no login tried


def test_user_privilege_and_login_time() -> None:
    from signalbox.adapters.mikrotik import login_time, user_privilege
    from signalbox.model import AccountPrivilege

    assert user_privilege("read,write,policy") is AccountPrivilege.ADMIN
    assert user_privilege("read,write,!policy") is AccountPrivilege.WRITE
    assert user_privilege("read,!write") is AccountPrivilege.READ
    assert user_privilege(["api", "!read"]) is AccountPrivilege.OTHER
    assert login_time("") is None and login_time("2026-13-01 00:00:00") is None
    assert login_time("2026-11-01 25:00") is None


# radio capabilities and state (#172) ----------------------------------------------------------


async def test_wifi_radio_capabilities_and_clients(http_url: str) -> None:
    snap = await observe(adapter(http_url))
    radios = {r.name: r for r in snap.radios}
    w1, w2 = radios["wifi1"], radios["wifi2"]
    assert (w1.standard, w1.channel_auto, w1.client_count) == (WifiStandard.AX, False, 1)
    assert w1.standards == [WifiStandard.G, WifiStandard.N, WifiStandard.AX]
    assert w1.supported_channels == list(range(1, 14)) and w1.antennas == "2x2"
    assert w1.dfs_capable is None
    assert (w2.standard, w2.channel_auto, w2.client_count) == (WifiStandard.AX, True, 0)
    assert w2.antennas == "4x4" and w2.dfs_capable is True
    assert w2.standards == [WifiStandard.A, WifiStandard.N, WifiStandard.AC, WifiStandard.AX]
    assert 149 not in (w2.supported_channels or [])


async def test_wifi_radio_menu_missing_or_refused(http_url: str, sim: MikrotikSimulator) -> None:
    sim.fail = {WIFI_RADIO: 403}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors  # only detail: not an error
    w1 = next(r for r in snap.radios if r.name == "wifi1")
    assert w1.standards is None and w1.client_count == 1 and w1.standard is WifiStandard.AX
    sim.fail = {WIFI_REGISTRATION: 403}  # the clients read reports it
    snap = await observe(adapter(http_url))
    assert next(r for r in snap.radios if r.name == "wifi1").client_count is None
    del sim.data[WIFI_RADIO]
    sim.fail = {}
    snap = await observe(adapter(http_url))
    assert next(r for r in snap.radios if r.name == "wifi1").standards is None


async def test_wifi_radio_matched_by_mac(http_url: str, sim: MikrotikSimulator) -> None:
    rows = sim.data[WIFI_RADIO]
    for row in rows:
        row.pop("interface")
    rows.append({"radio-mac": "02:00:00:00:00:99", "bands": "5ghz-ax"})  # no such interface
    snap = await observe(adapter(http_url))
    w2 = next(r for r in snap.radios if r.name == "wifi2")
    assert w2.antennas == "4x4"


async def test_legacy_wireless_radio_state(http_url: str, sim: MikrotikSimulator) -> None:
    sim.wireless = "legacy"
    snap = await observe(adapter(http_url))
    radios = {r.name: r for r in snap.radios}
    assert (radios["wlan1"].standard, radios["wlan1"].channel_auto) == (WifiStandard.N, False)
    assert (radios["wlan2"].standard, radios["wlan2"].channel_auto) == (WifiStandard.AC, True)
    assert (radios["wlan1"].client_count, radios["wlan2"].client_count) == (1, 0)
    assert radios["wlan1"].standards is None  # the legacy package has no radio menu


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2ghz-ax", [WifiStandard.AX]),
        ("5ghz-a/n/ac", [WifiStandard.A, WifiStandard.N, WifiStandard.AC]),
        ("2ghz-onlyn", [WifiStandard.N]),
        ("2ghz-g,2ghz-n,2ghz-ax", [WifiStandard.G, WifiStandard.N, WifiStandard.AX]),
        ("", []),
        ("5ghz", []),
    ],
)
def test_standards_of(text: str, expected: list[WifiStandard]) -> None:
    assert standards_of(text) == expected
    assert standard_of(text) == (expected[-1] if expected else None)


def test_channels_of() -> None:
    assert channels_of("2412,5180,x", Band.GHZ_2_4) == [1]
    assert channels_of("", Band.GHZ_5) is None


async def test_ipv6_router_advertisements_and_dhcpv6(snap: Snapshot) -> None:
    """``/ipv6/nd`` (``all`` as the default), ``nd/prefix``, ``dhcp-server`` and ``pool`` (#151):
    RouterOS' DHCPv6 server only delegates prefixes, so it is a stateless server with a pool."""
    assert snap.router_adverts
    for ra in snap.router_adverts:
        assert ra.mode is RaMode.STATELESS and ra.managed is False and ra.other is True
        assert [str(x) for x in ra.rdnss] == ["2001:db8:1::1"] and ra.router_lifetime == 1800
    prefixes = {str(p.prefix) for ra in snap.router_adverts for p in ra.prefixes}
    assert prefixes == {"2001:db8:1::/64"}
    [server] = snap.dhcp6_servers
    assert server.id == "rt/dhcp6/dhcp6-lan" and server.mode is Dhcp6Mode.STATELESS
    assert server.lease_seconds == 3 * 86400 and server.pools == []
    [pool] = server.prefix_pools
    assert (str(pool.prefix), pool.length) == ("2001:db8:2::/48", 56)


async def test_config_state_and_backups(snap: Snapshot) -> None:
    """RouterOS saves at once; the last change and the backup files are read (#181)."""
    d = snap.device
    assert d.config_state is not None
    assert (d.config_state.unsaved, d.config_state.pending) == (False, False)
    assert (d.config_state.changed_by, d.config_state.last_changed) == (
        "admin",
        datetime(2026, 11, 20, 10, 11, 12, tzinfo=UTC),
    )
    assert d.local_backups is not None and d.local_backups.count == 1
    assert d.local_backups.newest == datetime(2026, 11, 18, 9, 0, tzinfo=UTC)
    assert d.firmware is not None and d.firmware.channel is not None
    assert d.firmware.channel.value == "stable"


async def test_dns_forward_entries_are_domain_upstreams(
    http_url: str, sim: MikrotikSimulator
) -> None:
    """#182: static ``type=FWD`` entries send one domain to another server."""
    sim.data[DNS_STATIC] += [
        {"name": "Corp.Example", "type": "FWD", "forward-to": "192.0.2.53", "disabled": "false"},
        {"name": "off.example", "type": "FWD", "forward-to": "192.0.2.54", "disabled": "true"},
        {"name": "bad.example", "type": "FWD", "forward-to": "nonsense", "disabled": "false"},
    ]
    (dns,) = (await observe(adapter(http_url))).dns_services
    (split,) = [f for f in dns.forwarders if f.domain is not None]
    assert (split.domain, str(split.address)) == ("corp.example", "192.0.2.53")
    assert [str(f) for f in dns.forwarders if f.domain is None] == ["192.0.2.53", "2001:db8:53::53"]
    assert dns.cache_size == 2048 and dns.recursive is False


async def test_station_bridge_is_an_uplink_peer(http_url: str, sim: MikrotikSimulator) -> None:
    """A wifi interface in station-bridge mode and its registration row (#171)."""
    sim.data["/rest/interface"].append(
        {".id": "*98", "name": "wifi4", "type": "wifi", "running": "true", "disabled": "false"}
    )
    sim.data["/rest/interface/wifi"].append(
        {
            "name": "wifi4",
            "mac-address": "02:00:00:00:00:09",
            "configuration.mode": "station-bridge",
            "channel.band": "5ghz-ax",
            "channel.frequency": "5180",
            "disabled": "false",
            "running": "true",
        }
    )
    sim.data["/rest/interface/wifi/registration-table"].append(
        {
            ".id": "*77",
            "interface": "wifi4",
            "mac-address": "02:00:00:00:00:77",
            "signal": "-67",
            "tx-rate": "433.3Mbps-80MHz-1S",
            "rx-rate": "390.0Mbps-80MHz-1S",
        }
    )
    snap = await observe(adapter(http_url))
    (peer,) = snap.mesh_peers
    assert peer.peer_mac == "02:00:00:00:00:77" and peer.role.value == "uplink"
    assert peer.port_id == "rt/port/wifi4"
    info = peer.wireless
    assert (info.kind.value, info.band, info.channel) == ("client-bridge", Band.GHZ_5, 36)
    assert (info.signal_dbm, info.tx_rate_mbps, info.rx_rate_mbps) == (-67, 433.3, 390.0)
    assert snap.device.mesh is not None and snap.device.mesh.role.value == "repeater"
    assert not any(w.id == "rt/wlan/wifi4" for w in snap.wlans)


async def test_plain_station_and_ap_registrations_are_no_mesh(http_url: str) -> None:
    snap = await observe(adapter(http_url))
    assert snap.mesh_peers == [] and snap.device.mesh is None


async def test_hotspot_is_a_captive_portal(snap: Snapshot) -> None:
    """A hotspot with a trial login is click-through; the session comes from the default user
    profile (#460)."""
    (portal,) = snap.portals
    assert portal.id == "rt/portal/hotspot1" and portal.enabled
    assert portal.auth is not None and portal.auth.value == "click-through"
    assert portal.session_minutes == 480
    assert len(portal.segments) == 1


def test_hotspot_login_methods() -> None:
    from signalbox.adapters.mikrotik import hotspot

    assert hotspot.auth_of({"use-radius": "yes", "login-by": "trial"}).value == "radius"
    assert hotspot.auth_of({"login-by": "http-chap,cookie"}).value == "password"
    assert hotspot.auth_of({"login-by": "trial,http-pap"}).value == "password"
    assert hotspot.auth_of({"login-by": "trial"}).value == "click-through"
    assert hotspot.auth_of({"login-by": "mac,cookie"}) is None
    assert hotspot.auth_of({}) is None
    rows = [
        {"name": "h1", "interface": "bridge", "profile": "p", "disabled": "true"},
        {"name": "h1", "interface": "bridge"},
        {"interface": "nowhere"},
    ]
    a, b = hotspot.hotspots(
        "rt", rows, [{"name": "p", "login-by": "https"}], [], {"bridge": "s"}, lambda v: 30
    )
    assert (a.id, a.enabled, a.segments, a.auth.value) == ("rt/portal/h1", False, ["s"], "password")  # type: ignore[union-attr]
    assert (b.id, b.segments, b.auth) == ("rt/portal/hotspot3", [], None)
