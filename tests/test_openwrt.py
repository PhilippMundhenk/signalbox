"""OpenWrt adapter against the ubus simulator (TLS with a self-signed certificate)."""

from __future__ import annotations

import ssl
import statistics
import time
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from pydantic import SecretStr

import signalbox.adapters.https as https_mod
import signalbox.sim.openwrt as openwrt_sim
from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    load_adapters,
)
from signalbox.adapters.https import DeviceHttp
from signalbox.adapters.openwrt import (
    NetworkView,
    OpenWrtAdapter,
    OpenWrtConfig,
    band,
    bridge_vlans,
    ciphers,
    group_cipher,
    lease_seconds,
    link_speeds,
    monitoring,
    security,
    supported_from_features,
    supported_from_packages,
    vitals,
    width,
    wireguard,
)
from signalbox.adapters.openwrt import radio as radio_state
from signalbox.adapters.openwrt import stp as ostp
from signalbox.adapters.openwrt.structure import structure
from signalbox.adapters.openwrt.ubus import AccessDenied, NotFound, Ubus
from signalbox.model import (
    AddressSource,
    Band,
    Cipher,
    DeviceRole,
    DeviceStatus,
    DfsState,
    LeaseState,
    Membership,
    Network,
    NtpClient,
    NtpServer,
    Pmf,
    PortKind,
    PortRole,
    SaePwe,
    Security,
    StpPortRole,
    StpPortState,
    StpProtocol,
    WifiStandard,
    WpsMethod,
    passphrase_digest,
    passphrase_fingerprint,
)
from signalbox.sim.openwrt import WG_KEY, WG_PHONE, WG_SITE_A, OpenWrtSim, _wg_key, create_app
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract, passphrase_digest_key

SIM = OpenWrtSim()


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"), "openwrt")


@pytest.fixture(scope="module")
def https_url(cert: TlsFiles) -> Iterator[str]:
    with serve(create_app(SIM), tls=cert) as url:
        yield url


@pytest.fixture(scope="module")
def http_url() -> Iterator[str]:
    with serve(create_app(SIM)) as url:
        yield url


@pytest.fixture
def sim() -> OpenWrtSim:
    SIM.reset()
    return SIM


def context(url: str, **kw: Any) -> AdapterContext:
    cfg = {"url": f"{url}/ubus", "password": SecretStr(OpenWrtSim().password)} | kw.pop(
        "config", {}
    )
    return AdapterContext(
        site_id="home",
        device_id="ap1",
        device_name="AP 1",
        role=kw.pop("role", DeviceRole.AP),
        config=OpenWrtConfig(**cfg),
        **kw,
    )


@pytest.fixture
async def adapter(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> AsyncIterator[OpenWrtAdapter]:
    a = OpenWrtAdapter(context(https_url, pinned_fingerprint=cert.fingerprint))
    yield a
    await a.close()


async def observe(ctx: AdapterContext) -> Any:
    a = OpenWrtAdapter(ctx)
    try:
        return await a.observe()
    finally:
        await a.close()


# --- happy path -----------------------------------------------------------------------


async def test_contract_over_pinned_tls(adapter: OpenWrtAdapter, sim: OpenWrtSim) -> None:
    snap = await assert_contract(adapter)
    assert snap.device.model == "Example AP"
    assert snap.device.firmware is not None and snap.device.firmware.current == "23.05.5"
    assert snap.device.management_address == "127.0.0.1"
    assert sim.logins == 1  # one session for every call
    assert adapter.ubus.http.secure


def test_entry_point() -> None:
    assert load_adapters()["openwrt"] is OpenWrtAdapter


BRIDGED = ("lan1", "lan2", "lan3", "lan4", "phy0-ap0", "phy0-ap1", "phy1-ap0")


async def test_interfaces_ports_and_vlans(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_interfaces()
    ports = {p.name: p for p in obs.ports}
    assert set(ports) >= {"lan1", "lan2", "lan3", "lan4", "br-lan", "eth0", "phy0-ap0"}
    assert "lo" not in ports
    # internal structure (#252): DSA user ports on the conduit eth1 (simulated: a guess, #21)
    cpu, jack = PortRole.CPU, PortRole.JACK
    assert (ports["eth1"].role, ports["eth1"].lower, ports["eth1"].external) == (cpu, [], False)
    assert all(ports[f"lan{n}"].role is jack for n in range(1, 5))
    assert ports["lan1"].lower == ["ap1/port/eth1"] and ports["lan1"].external is True
    assert ports["eth0"].role is jack and ports["eth0"].lower == []
    assert ports["br-lan"].role is PortRole.BRIDGE
    assert ports["br-lan"].lower == [f"ap1/port/{n}" for n in BRIDGED]
    vlan = ports["br-lan.1"]
    assert (vlan.role, vlan.kind) == (PortRole.VLAN, PortKind.VIRTUAL)
    assert vlan.lower == ["ap1/port/br-lan"]
    assert ports["phy0-ap0"].role is PortRole.WIRELESS and ports["phy0-ap0"].external is False
    assert not obs.incomplete
    assert ports["lan1"].up and ports["lan1"].speed_mbps == 1000 and ports["lan1"].full_duplex
    assert ports["lan4"].up is False and ports["lan4"].speed_mbps is None
    assert ports["br-lan"].kind is PortKind.BRIDGE
    assert ports["phy0-ap0"].kind is PortKind.WIRELESS
    assert ports["lan1"].mac == "02:00:00:00:00:01"
    # port details (#156)
    lan1, eth0 = ports["lan1"], ports["eth0"]
    assert (lan1.admin_up, lan1.mtu, lan1.pvid, lan1.autoneg) == (True, 1500, 1, True)
    assert (lan1.max_speed_mbps, lan1.advertised_speeds_mbps) == (1000, [10, 100, 1000])
    assert lan1.vendor_extra == {"type": "Network device"}
    assert eth0.max_speed_mbps == 2500 and eth0.advertised_speeds_mbps[-1] == 2500
    assert ports["lan3"].pvid is None  # untagged in VLAN 1, but not marked primary (``*``)
    assert ports["lan4"].admin_up is False  # ``device`` section with ``enabled 0``
    assert ports["br-lan"].max_speed_mbps is None and ports["br-lan"].advertised_speeds_mbps == []
    segs = {s.vlan: s for s in obs.segments}
    assert set(segs) == {1, 20}
    assert segs[1].id == "home/segment/native" and segs[1].name == "lan"
    assert {(m.port_id, m.mode) for m in segs[1].members} == {
        (f"ap1/port/lan{n}", Membership.UNTAGGED) for n in (1, 2, 3)
    }
    assert segs[20].name == "iot"
    assert [(m.port_id, m.mode) for m in segs[20].members] == [("ap1/port/lan1", Membership.TAGGED)]
    subnets = {str(s.interface): s for s in obs.subnets}
    assert set(subnets) == {"192.0.2.2/24", "2001:db8::2/64"}  # no loopback
    assert all(s.segment_id == "home/segment/native" and not s.gateway for s in subnets.values())


async def test_wireless(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_wireless()
    radios = {r.name: r for r in obs.radios}
    r0, r1 = radios["radio0"], radios["radio1"]
    assert (r0.band, r0.channel, r0.width_mhz, r0.tx_power_dbm, r0.country) == (
        Band.GHZ_2_4,
        6,
        20,
        20,
        "DE",
    )
    assert (r1.band, r1.channel, r1.width_mhz) == (Band.GHZ_5, 36, 80)
    assert r0.enabled and r1.enabled
    wlans = {w.id: w for w in obs.wlans}
    assert set(wlans) == {
        "ap1/wlan/default_radio0",
        "ap1/wlan/default_radio1",
        "ap1/wlan/iot_radio0",
    }
    main = wlans["ap1/wlan/default_radio0"]
    assert main.ssid == "Example" and main.security is Security.WPA2_WPA3
    assert main.pmf is Pmf.OPTIONAL  # sae-mixed default
    assert main.roaming_80211r and main.roaming_80211k and main.roaming_80211v
    assert main.segment_id == "home/segment/native" and main.radio_id == "ap1/radio/radio0"
    assert main.passphrase_fingerprint == passphrase_fingerprint("Example", "example-passphrase")
    assert wlans["ap1/wlan/default_radio1"].pmf is Pmf.OPTIONAL
    iot = wlans["ap1/wlan/iot_radio0"]
    assert iot.security is Security.WPA2 and iot.segment_id == "home/segment/20"
    assert iot.hidden and iot.pmf is None and not iot.roaming_80211r
    assert "example-iot-passphrase" not in iot.model_dump_json()
    # client isolation: option isolate (default off); a purpose is not reported by OpenWrt
    assert iot.client_isolation is True and main.client_isolation is False
    assert iot.purpose is None and main.purpose is None


async def test_wifi_security_details(adapter: OpenWrtAdapter) -> None:
    with passphrase_digest_key():
        obs = await adapter.read_wireless()
        wlans = {w.id: w for w in obs.wlans}
        main, iot = wlans["ap1/wlan/default_radio0"], wlans["ap1/wlan/iot_radio0"]
        assert main.passphrase_digest == passphrase_digest("example-passphrase")
        assert iot.passphrase_digest == passphrase_digest("example-iot-passphrase")
        assert main.passphrase_digest != iot.passphrase_digest
    assert main.ciphers == [Cipher.CCMP] and main.group_cipher is Cipher.CCMP
    assert main.sae is not None and main.sae.pwe is SaePwe.BOTH
    assert main.wps is not None and main.wps.enabled is False
    assert iot.sae is None and iot.ciphers == [Cipher.CCMP]
    assert iot.wps is not None and iot.wps.methods == [WpsMethod.PUSH_BUTTON]
    assert iot.key_rotation_seconds == 3600 and main.key_rotation_seconds is None
    assert main.beacon_protection is None
    for r in obs.radios:  # luci getFeatures of the full wpad build
        assert r.supported_security is not None
        assert Security.WPA3 in r.supported_security
        assert Security.WPA3_ENTERPRISE_192 in r.supported_security
    # no key installed (the default): no digest, the rest is unchanged
    [plain] = [w for w in (await adapter.read_wireless()).wlans if w.id == iot.id]
    assert plain.passphrase_digest is None and plain.passphrase_fingerprint is not None


async def test_supported_security_fallbacks(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.luci_features = False
    sim.wpad = "wpad-basic-mbedtls"
    modes = (await adapter.read_wireless()).radios[0].supported_security
    assert modes == [Security.OPEN, Security.WPA, Security.WPA_WPA2, Security.WPA2]
    sim.wpad = "wpad-mbedtls"
    modes = (await adapter.read_wireless()).radios[0].supported_security
    assert modes is not None and Security.WPA2_WPA3 in modes and Security.OWE in modes
    sim.denied |= {"luci", "rpc-sys"}  # an ACL from before #167: not reported, not an error
    snap = await adapter.observe()
    assert not snap.errors and all(r.supported_security is None for r in snap.radios)


def test_ciphers_and_group_cipher() -> None:
    assert ciphers("none", Security.OPEN) is None
    assert ciphers("wep-open", Security.WEP) == [Cipher.WEP]
    assert ciphers("psk2", Security.WPA2) == [Cipher.CCMP]
    assert ciphers("psk2+aes", Security.WPA2) == [Cipher.CCMP]
    assert ciphers("psk-mixed", Security.WPA_WPA2) == [Cipher.TKIP, Cipher.CCMP]
    assert ciphers("psk2+tkip+ccmp", Security.WPA2) == [Cipher.TKIP, Cipher.CCMP]
    assert ciphers("wpa3-192", Security.WPA3_ENTERPRISE_192) == [Cipher.GCMP_256]
    assert ciphers("psk2+gcmp", Security.WPA2) == [Cipher.GCMP]
    assert ciphers("psk2+bogus", Security.WPA2) is None
    assert ciphers("bogus", Security.OTHER) is None
    assert group_cipher([Cipher.CCMP, Cipher.TKIP]) is Cipher.TKIP
    assert group_cipher([Cipher.GCMP_256]) is Cipher.GCMP_256
    assert group_cipher(None) is None and group_cipher([]) is None


def test_supported_security_helpers() -> None:
    assert supported_from_packages({"base-files": "1"}) is None
    assert Security.WPA3 not in (supported_from_packages({"wpad-basic-wolfssl": "1"}) or [])
    assert supported_from_features({"hostapd": {"sae": 1, "eap": 1}}) == [
        Security.OPEN,
        Security.WPA,
        Security.WPA_WPA2,
        Security.WPA2,
        Security.WPA3,
        Security.WPA2_WPA3,
        Security.WPA_ENTERPRISE,
        Security.WPA2_ENTERPRISE,
        Security.WPA3_ENTERPRISE,
    ]
    assert supported_from_features({}) == [
        Security.OPEN,
        Security.WPA,
        Security.WPA_WPA2,
        Security.WPA2,
    ]


async def test_dhcp_off_on_an_ap(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_dhcp()
    [server] = obs.dhcp_servers
    assert server.id == "ap1/dhcp/lan" and server.segment_id == "home/segment/native"
    assert server.enabled is False and server.pools == []
    assert server.lease_seconds == 12 * 3600
    assert [(r.mac, str(r.address), r.hostname) for r in server.reservations] == [
        ("00:00:5e:00:53:01", "192.0.2.50", "printer")
    ]


async def test_dnsmasq_dns(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    """#241: dnsmasq's port and ``server`` entries with ``#port``."""
    (dns,) = (await adapter.read_dns()).dns_services
    assert (dns.id, dns.name, dns.port, dns.enabled) == ("ap1/dns/dnsmasq", "dnsmasq", 53, True)
    assert dns.listen == [] and dns.forwarders == []
    assert "resolvfile" in str(dns.vendor_extra["upstream"])  # no noresolv: the WAN's servers
    assert [(h.name, str(h.address)) for h in dns.host_records] == [("printer.lan", "192.0.2.50")]
    main = next(k for k, v in sim.state["dhcp"].items() if v[".type"] == "dnsmasq")
    sim.state["dhcp"][main].update(
        {
            "port": "53530",
            "noresolv": "1",
            "server": [
                "192.0.2.53",
                "198.51.100.53#5353",
                "2001:db8::53#5353@eth0",
                "/corp.example/198.51.100.53",
                "not-an-address",
                "192.0.2.53",
            ],
            "interface": ["lan"],
        }
    )
    (dns,) = (await adapter.read_dns()).dns_services
    assert dns.port == 53530 and dns.vendor_extra == {}
    assert [str(f) for f in dns.forwarders] == [
        "192.0.2.53",
        "198.51.100.53:5353",
        "[2001:db8::53]:5353",
    ]
    assert [str(a) for a in dns.listen] == ["192.0.2.2", "2001:db8::2"]
    sim.state["dhcp"][main].update({"port": "0", "listen_address": ["192.0.2.2", "bad"]})
    sim.state["dhcp"]["second"] = {".type": "dnsmasq", ".anonymous": False}
    sim.state["dhcp"]["broken"] = {".type": "domain", ".anonymous": False, "ip": "nas"}
    first, second = (await adapter.read_dns()).dns_services
    assert first.id == f"ap1/dns/{main}" and not first.enabled and first.port == 53
    assert [str(a) for a in first.listen] == ["192.0.2.2"]
    assert second.id == "ap1/dns/second" and second.enabled and second.host_records == []


async def test_router_mode(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> None:
    sim.router = True
    a = OpenWrtAdapter(
        context(https_url, pinned_fingerprint=cert.fingerprint, role=DeviceRole.GATEWAY)
    )
    try:
        [server] = (await a.read_dhcp()).dhcp_servers
        subnets = (await a.read_interfaces()).subnets
    finally:
        await a.close()
    assert server.enabled
    assert [(str(p.start), str(p.end)) for p in server.pools] == [("192.0.2.100", "192.0.2.249")]
    assert server.router == ip_address("192.0.2.2")
    assert server.dns_servers == [ip_address("192.0.2.1"), ip_address("192.0.2.53")]
    assert server.ntp_servers == [ip_address("192.0.2.1")]
    assert all(s.gateway for s in subnets)


async def test_clients(adapter: OpenWrtAdapter) -> None:
    clients = {c.mac: c for c in (await adapter.read_clients()).clients}
    assert set(clients) == {
        "00:00:5e:00:53:01",  # the printer's lease
        "02:00:00:00:20:01",
        "02:00:00:00:20:02",
        "02:00:00:00:20:03",
    }
    assert clients["02:00:00:00:20:01"].seen_on == "ap1/wlan/default_radio0"
    assert clients["02:00:00:00:20:02"].seen_on == "ap1/wlan/iot_radio0"
    assert clients["02:00:00:00:20:02"].segment_id == "home/segment/20"
    laptop = clients["02:00:00:00:20:03"]
    assert laptop.seen_on == "ap1/wlan/default_radio1" and laptop.hostname == "laptop"
    assert laptop.addresses == [ip_address("192.0.2.103")]
    assert laptop.address_sources == {ip_address("192.0.2.103"): AddressSource.DHCP}  # #183


async def test_lease_table_options_and_relay(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles
) -> None:
    sim.router = True
    a = OpenWrtAdapter(
        context(https_url, pinned_fingerprint=cert.fingerprint, role=DeviceRole.GATEWAY)
    )
    try:
        obs = await a.read_dhcp()
    finally:
        await a.close()
    [server] = obs.dhcp_servers
    assert server.leases is not None
    by_addr = {str(x.address): x for x in server.leases}
    assert set(by_addr) == {"192.0.2.103", "192.0.2.50", "2001:db8::1a2"}
    laptop, printer, v6 = by_addr["192.0.2.103"], by_addr["192.0.2.50"], by_addr["2001:db8::1a2"]
    assert laptop.state is LeaseState.ACTIVE and laptop.reserved is False
    assert laptop.expires is not None and laptop.hostname == "laptop"
    assert 40000 < (laptop.expires - datetime.now(UTC)).total_seconds() <= 43000
    assert printer.reserved is True and printer.expires is None  # never expires
    assert v6.mac is None and v6.client_id == "000100012d1b2c3d02000000200a"
    assert server.search_domains == ["home.example", "lan.example"]
    assert [(str(r.destination), str(r.gateway)) for r in server.static_routes] == [
        ("203.0.113.0/24", "192.0.2.254")
    ]
    assert server.boot is not None
    assert (str(server.boot.next_server), server.boot.filename) == ("192.0.2.5", "pxelinux.0")
    assert [(o.code, o.name, o.value) for o in server.options] == [
        (252, "wpad", "http://192.0.2.1/wpad.dat")
    ]
    assert server.authoritative is True
    [relay] = obs.dhcp_relays
    assert (relay.id, relay.segment_id) == ("ap1/dhcp-relay/20", "home/segment/20")
    assert [str(x) for x in relay.servers] == ["192.0.2.53"] and relay.enabled


async def test_lease_table_from_file_without_luci_rpc(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.luci_rpc = False
    [server] = (await adapter.read_dhcp()).dhcp_servers
    assert server.leases is not None
    laptop = next(x for x in server.leases if str(x.address) == "192.0.2.103")
    assert laptop.client_id == "01:02:00:00:00:20:03" and laptop.expires is not None
    assert laptop.expires.year == 2100
    sim.denied = {"luci-rpc", "file"}
    [server] = (await adapter.read_dhcp()).dhcp_servers
    assert server.leases is None  # neither source readable: not read, not "no leases"


async def test_leases_from_file_without_luci_rpc(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.luci_rpc = False
    clients = {c.mac: c for c in (await adapter.read_clients()).clients}
    assert clients["02:00:00:00:20:03"].hostname == "laptop"


async def test_no_leases_when_neither_source_is_allowed(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.denied = {"luci-rpc", "file"}
    clients = {c.mac: c for c in (await adapter.read_clients()).clients}
    assert len(clients) == 3 and clients["02:00:00:00:20:03"].hostname is None


async def test_neighbours(adapter: OpenWrtAdapter) -> None:
    [nb] = (await adapter.read_neighbours()).neighbours
    assert nb.local_port_id == "ap1/port/lan1" and nb.chassis_id == "02:00:00:00:30:01"
    assert (nb.system_name, nb.remote_port, nb.management_address) == (
        "switch",
        "port 8",
        "192.0.2.3",
    )
    # only the enabled system capabilities (#113)
    assert nb.capabilities == ["bridge", "router"]
    assert nb.description == "MikroTik RouterOS 7.15.3 CRS326-24G-2S+"


def test_lldp_capabilities_shapes() -> None:
    from signalbox.adapters.openwrt import _capabilities

    assert _capabilities({"type": "Wlan", "enabled": True}) == ["wlan-access-point"]
    assert _capabilities([{"type": "Telephone", "enabled": True}, "x", {"enabled": True}]) == [
        "telephone"
    ]
    assert _capabilities([{"type": "Bridge", "enabled": False}]) == []
    assert _capabilities(None) == [] and _capabilities("bridge") == []


async def test_session_expiry_logs_in_again(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    await adapter.read_system()
    sim.expire_sessions()
    await adapter.read_system()
    assert sim.logins == 2


async def test_plain_http_only_when_allowed(sim: OpenWrtSim, http_url: str) -> None:
    snap = await observe(context(http_url))
    assert snap.status is DeviceStatus.UNREACHABLE and "plain http" in snap.errors[0].message
    a = OpenWrtAdapter(context(http_url, config={"allow_insecure_http": True}))
    try:
        assert (await a.observe()).status is DeviceStatus.OK
        assert not a.ubus.http.secure
    finally:
        await a.close()


# --- refused paths --------------------------------------------------------------------


async def test_wrong_password(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> None:
    sim.password = "something-else"
    snap = await observe(context(https_url, pinned_fingerprint=cert.fingerprint))
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert "login as 'signalbox' refused" in snap.errors[0].message


@pytest.mark.parametrize(
    ("denied", "capabilities", "named"),
    [
        ({"hostapd.phy1-ap0"}, ["clients"], "hostapd.phy1-ap0.get_clients"),
        ({"network.wireless.status"}, ["clients", "wireless"], "network.wireless.status"),
        ({"uci:dhcp"}, ["dhcp", "dns"], "uci.get (dhcp)"),
    ],
)
async def test_missing_acl_is_partial(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, denied: set[str], capabilities: list[str], named: str
) -> None:
    sim.denied = denied
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    assert [e.capability for e in snap.errors] == capabilities
    assert all(
        named in e.message and e.fix and "acl.d/signalbox.json" in e.fix for e in snap.errors
    )
    assert snap.ports  # the rest is still read


@pytest.mark.parametrize("pinned", [None, "ab" * 32])
async def test_untrusted_certificate_sends_no_password(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles, pinned: str | None
) -> None:
    snap = await observe(context(https_url, pinned_fingerprint=pinned))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert cert.fingerprint in snap.errors[0].message
    assert sim.requests == 0


async def test_pin_accepts_colon_notation(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> None:
    fp = ":".join(cert.fingerprint[i : i + 2] for i in range(0, 64, 2)).upper()
    assert (await observe(context(https_url, pinned_fingerprint=fp))).status is DeviceStatus.OK


async def test_certificate_swapped_after_probe(
    sim: OpenWrtSim,
    https_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The probe sees another certificate than the request connection: the handshake of the
    # login fails, so the password never reaches the server.
    other = self_signed_certificate(tmp_path, "other")
    der = ssl.PEM_cert_to_DER_cert(other.cert.read_text())

    async def fake_probe(host: str, port: int, timeout: float) -> bytes:
        return der

    monkeypatch.setattr(https_mod, "peer_certificate", fake_probe)
    snap = await observe(context(https_url, pinned_fingerprint=other.fingerprint))
    assert snap.status is DeviceStatus.UNREACHABLE and "cannot reach" in snap.errors[0].message
    assert sim.requests == 0


async def test_certificate_probed_again_every_observation(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (await adapter.observe()).status is DeviceStatus.OK
    probes: list[int] = []
    real = https_mod.peer_certificate

    async def counting(host: str, port: int, timeout: float) -> bytes:
        probes.append(port)
        return await real(host, port, timeout)

    monkeypatch.setattr(https_mod, "peer_certificate", counting)
    assert (await adapter.observe()).status is DeviceStatus.OK
    assert len(probes) == 1  # one probe per observation, the connection is reused after it
    assert sim.logins == 1  # the ubus session survives the new connection


async def test_kept_connection_has_no_nagle_delay(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles
) -> None:
    # #189: without TCP_NODELAY on the simulator's sockets every request on a kept connection
    # waited for the client's delayed ACK (about 40 ms, so 25 requests took over a second).
    http = DeviceHttp(https_url, pinned_fingerprint=cert.fingerprint, timeout=5)
    try:
        await http.request("POST", "/ubus", json={}, accept=range(200, 600))
        durations = []
        for _ in range(25):
            start = time.perf_counter()
            await http.request("POST", "/ubus", json={}, accept=range(200, 600))
            durations.append(time.perf_counter() - start)
    finally:
        await http.close()
    # The median, not the total: a loaded CI worker delays single requests by arbitrary amounts, but
    # the stall hits every request (>= 40 ms each), while a healthy one takes a few ms.
    median = statistics.median(durations)
    assert median < 0.03, f"median request took {median * 1000:.0f} ms"


async def test_unreachable(sim: OpenWrtSim) -> None:
    snap = await observe(context(f"https://127.0.0.1:{free_port()}", pinned_fingerprint="ab"))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "cannot open a TLS connection" in snap.errors[0].message
    snap = await observe(
        context(f"http://127.0.0.1:{free_port()}", config={"allow_insecure_http": True})
    )
    assert snap.status is DeviceStatus.UNREACHABLE and "cannot reach" in snap.errors[0].message


async def test_timeout(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> None:
    sim.delay = 1.0
    snap = await observe(context(https_url, pinned_fingerprint=cert.fingerprint, timeout=0.2))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert any("within 0.2 s" in e.message for e in snap.errors), snap.errors


async def test_slow_capability_is_partial(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.delay, sim.slow = 3.0, {"luci.lldpd"}
    object.__setattr__(adapter.context, "timeout", 1.0)
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    assert [e.capability for e in snap.errors] == ["neighbours"]


@pytest.mark.parametrize(
    ("switch", "value", "status", "message"),
    [
        ("malformed", {"*"}, DeviceStatus.UNREACHABLE, "not valid JSON"),
        ("odd", {"system"}, DeviceStatus.UNREACHABLE, "unexpected answer to system.board"),
        ("malformed", {"network.wireless"}, DeviceStatus.PARTIAL, "not valid JSON"),
        ("odd", {"luci.lldpd"}, DeviceStatus.PARTIAL, "unexpected answer to luci.lldpd"),
    ],
)
async def test_malformed_answers(
    sim: OpenWrtSim,
    adapter: OpenWrtAdapter,
    switch: str,
    value: set[str],
    status: DeviceStatus,
    message: str,
) -> None:
    setattr(sim, switch, value)
    snap = await adapter.observe()
    assert snap.status is status
    assert any(message in e.message for e in snap.errors), snap.errors


async def test_wireless_status_through_luci_rpc_on_25_12(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    before = await adapter.observe()
    sim.wireless_ucode = True  # netifd's ucode object refuses calls through rpcd
    snap = await adapter.observe()

    def wlans(s: Any) -> list[tuple[str, bool]]:
        return [(w.id, w.enabled) for w in s.wlans]

    assert not snap.errors and wlans(snap) == wlans(before) and snap.clients
    sim.luci_rpc = False
    snap = await adapter.observe()
    assert {e.capability for e in snap.errors} == {"wireless", "clients"}
    assert "install rpcd-mod-luci" in snap.errors[0].message


async def test_lldpd_missing(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.lldpd = False
    snap = await adapter.observe()
    assert [(e.capability, e.message, e.optional) for e in snap.errors] == [
        ("neighbours", "LLDP is not installed on the router (no ubus object luci.lldpd)", True)
    ]
    # an optional feature does not make the device "partly read" (#278)
    assert snap.status is DeviceStatus.OK
    assert snap.errors[0].remedy == "lldp" and snap.errors[0].fix


async def test_lldpd_not_running_is_optional(
    adapter: OpenWrtAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def not_running(obj: str, method: str, *args: Any, **kw: Any) -> Any:
        return {"statistics": {}}  # luci.lldpd answers without a neighbours section

    monkeypatch.setattr(adapter.ubus, "call", not_running)
    obs = await adapter.read_neighbours()
    assert not obs.neighbours and [g.optional for g in obs.incomplete] == [True]
    assert "not running" in obs.incomplete[0].message


async def test_stopped_lldpd_fails_the_ubus_call_optionally(
    adapter: OpenWrtAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from signalbox.adapters.openwrt.ubus import CallFailed

    async def failing(obj: str, method: str, *args: Any, **kw: Any) -> Any:
        raise CallFailed("ubus luci.lldpd.getStatus failed: unknown error")

    monkeypatch.setattr(adapter.ubus, "call", failing)
    [gap] = (await adapter.read_neighbours()).incomplete
    assert gap.optional and gap.remedy == "lldp" and "not running" in gap.message


async def test_wrong_path_is_reported(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> None:
    a = OpenWrtAdapter(
        context(
            https_url,
            pinned_fingerprint=cert.fingerprint,
            config={"url": f"{https_url}/elsewhere"},
        )
    )
    try:
        snap = await a.observe()
    finally:
        await a.close()
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "/elsewhere" in snap.errors[0].message and "HTTP 404" in snap.errors[0].message


async def test_url_without_path_uses_ubus(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> None:
    ctx = context(https_url, pinned_fingerprint=cert.fingerprint, config={"url": https_url})
    assert (await observe(ctx)).status is DeviceStatus.OK


async def test_simulator_parse_error(sim: OpenWrtSim, http_url: str) -> None:
    http = DeviceHttp(http_url, pinned_fingerprint=None, timeout=2, allow_insecure_http=True)
    answer = await http.post_json("/ubus", {"jsonrpc": "2.0"})
    assert answer["error"]["code"] == -32700
    await http.close()


def test_bad_url() -> None:
    with pytest.raises(ValueError, match="device's address"):
        OpenWrtConfig(url="ftp://192.0.2.2/ubus", password=SecretStr("x"))


# --- ubus client against canned answers -----------------------------------------------


class Canned:
    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.sent: list[Any] = []

    async def connect(self) -> None:
        pass

    async def post_json(self, path: str, payload: Any) -> Any:
        self.sent.append((path, payload))
        return self.answers.pop(0)


LOGIN = {"result": [0, {"ubus_rpc_session": "s" * 32}]}


@pytest.mark.parametrize(
    ("answer", "error", "message"),
    [
        ({"error": {"code": -32000, "message": "Object not found"}}, NotFound, "x.y not found"),
        ({"error": {"code": -32601}}, NotFound, "not found"),
        ({"error": {"code": -32602, "message": "Invalid params"}}, AdapterError, "Invalid params"),
        ({"result": [4]}, NotFound, "x.y: not found"),
        ({"result": [9]}, AdapterError, "unknown error"),
        ({"result": [42]}, AdapterError, "failed: 42"),
        ({"result": [0, []]}, AdapterError, "unexpected answer"),
        ([1, 2], AdapterError, "unexpected answer"),
    ],
)
async def test_ubus_errors(answer: Any, error: type[Exception], message: str) -> None:
    ubus = Ubus(Canned(LOGIN, answer), "/ubus", "signalbox", "pw")  # type: ignore[arg-type]
    with pytest.raises(error, match=message):
        await ubus.call("x", "y")


async def test_ubus_status_without_data() -> None:
    ubus = Ubus(Canned(LOGIN, {"result": [0]}), "/ubus", "signalbox", "pw")  # type: ignore[arg-type]
    assert await ubus.call("x", "y") == {}


async def test_ubus_login_without_session() -> None:
    ubus = Ubus(Canned({"result": [0, {}]}), "/ubus", "signalbox", "pw")  # type: ignore[arg-type]
    with pytest.raises(AdapterError, match=r"session\.login"):
        await ubus.login()


async def test_ubus_login_access_denied_error() -> None:
    answer = {"error": {"code": -32002, "message": "Access denied"}}
    ubus = Ubus(Canned(answer), "/ubus", "signalbox", "pw")  # type: ignore[arg-type]
    with pytest.raises(AuthFailed):
        await ubus.login()


async def test_ubus_denied_twice_names_acl() -> None:
    denied = {"result": [6]}
    ubus = Ubus(Canned(LOGIN, denied, LOGIN, denied), "/ubus", "ro", "pw")  # type: ignore[arg-type]
    with pytest.raises(AccessDenied, match=r"x\.y: the login 'ro' is not allowed"):
        await ubus.call("x", "y")


# --- mapping helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("3600", 3600), ("30m", 1800), ("12h", 43200), ("1d", 86400), ("2w", 1209600)],
)
def test_lease_seconds(text: str, seconds: int) -> None:
    assert lease_seconds(text) == seconds


def test_lease_seconds_infinite() -> None:
    assert lease_seconds("infinite") is None


@pytest.mark.parametrize(
    ("encryption", "expected"),
    [
        ("none", Security.OPEN),
        (None, Security.OPEN),
        ("owe", Security.OWE),
        ("psk", Security.WPA),
        ("psk2+ccmp", Security.WPA2),
        ("psk-mixed", Security.WPA_WPA2),
        ("sae", Security.WPA3),
        ("sae-mixed", Security.WPA2_WPA3),
        ("wpa2", Security.WPA2_ENTERPRISE),
        ("wpa3", Security.WPA3_ENTERPRISE),
        ("wep-open", Security.WEP),
        ("wep-shared", Security.WEP),
        ("wpa", Security.WPA_ENTERPRISE),
        ("wpa-mixed", Security.WPA_ENTERPRISE),
        ("wpa3-192", Security.WPA3_ENTERPRISE_192),
        ("unknown", Security.OTHER),
    ],
)
def test_security(encryption: str | None, expected: Security) -> None:
    assert security(encryption) is expected


@pytest.mark.parametrize(
    ("section", "expected"),
    [
        ({"band": "6g"}, Band.GHZ_6),
        ({"band": "60g"}, None),
        ({"hwmode": "11a"}, Band.GHZ_5),
        ({"hwmode": "11g"}, Band.GHZ_2_4),
        ({"channel": "149"}, Band.GHZ_5),
        ({"channel": "auto"}, None),
    ],
)
def test_band(section: dict[str, str], expected: Band | None) -> None:
    assert band(section) is expected


@pytest.mark.parametrize(
    ("htmode", "expected"),
    [("HT40", 40), ("VHT80", 80), ("EHT160", 160), ("NOHT", 20), (None, None), ("odd", None)],
)
def test_width(htmode: str | None, expected: int | None) -> None:
    assert width(htmode) == expected


def test_port_without_suffix_in_two_vlans_is_tagged() -> None:
    vlans = bridge_vlans(
        [
            ("a", {"device": "br-lan", "vlan": "1", "ports": "lan1 lan2"}),
            ("b", {"device": "br-lan", "vlan": "2", "ports": ["lan1", "lan3:u"]}),
            ("c", {"device": "br-lan", "vlan": "x", "ports": ["lan1"]}),
        ]
    )
    assert vlans["br-lan"][1] == [("lan1", Membership.TAGGED), ("lan2", Membership.UNTAGGED)]
    assert vlans["br-lan"][2] == [("lan1", Membership.TAGGED), ("lan3", Membership.UNTAGGED)]


def _uci(*sections: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
    return {"values": {n: {".type": t, ".name": n, **o} for t, n, o in sections}}


def test_link_speeds_and_primary_vlans() -> None:
    assert link_speeds(["1000baseT-F", "100baseT-H", "2500baseX-F", "odd", 7]) == [100, 1000, 2500]
    assert link_speeds(None) == [] and link_speeds("1000baseT-F") == []
    view = NetworkView.build(
        _uci(
            ("bridge-vlan", "a", {"device": "br-lan", "vlan": "10", "ports": ["lan1:u*"]}),
            ("bridge-vlan", "b", {"device": "br-lan", "vlan": "20", "ports": ["lan1:t*"]}),
            ("bridge-vlan", "c", {"device": "br-lan", "vlan": "9999", "ports": ["lan2:u*"]}),
            ("device", "d", {"name": "lan3", "enabled": "1"}),
        )
    )
    assert view.pvids == {"lan1": 10} and view.disabled == set()


def test_bridge_without_vlan_filtering_is_the_native_segment() -> None:
    view = NetworkView.build(
        _uci(
            ("device", "d", {"type": "bridge", "name": "br-lan", "ports": ["lan1", "lan2"]}),
            ("interface", "lan", {"device": "br-lan"}),
            ("interface", "wan", {"ifname": "eth1"}),
            ("interface", "none", {}),
        ),
        {"interface": [{"interface": "lan", "ipv4-address": [{"address": "bad"}]}, "junk"]},
    )
    assert view.vlan_of_interface("lan") == 0  # native
    assert view.vlan_of_interface("wan") is None and view.vlan_of_interface("none") is None
    assert view.vlan_of_device("br-lan.5") is None
    assert view.addresses("lan") == []
    assert view.segment_names() == {0: "lan"}


async def test_native_segment_through_the_adapter(
    adapter: OpenWrtAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def network(running: bool = True) -> NetworkView:
        return NetworkView.build(
            _uci(
                ("device", "d", {"type": "bridge", "name": "br-lan", "ports": ["lan1", "lan9"]}),
                ("interface", "lan", {"device": "br-lan"}),
            ),
            {
                "interface": [
                    {"interface": "lan", "ipv4-address": [{"address": "192.0.2.2", "mask": 24}]}
                ]
            },
        )

    monkeypatch.setattr(adapter, "_network", network)
    obs = await adapter.read_interfaces()
    [seg] = obs.segments
    assert seg.id == "home/segment/native" and seg.vlan is None
    assert {m.port_id for m in seg.members} == {"ap1/port/lan1", "ap1/port/lan9"}
    assert "ap1/port/lan9" in {p.id for p in obs.ports}  # configured but absent: still a port
    assert obs.subnets[0].interface == ip_interface("192.0.2.2/24")


def test_unexpected_uci_and_dump_answers() -> None:
    with pytest.raises(AdapterError, match=r"uci\.get"):
        NetworkView.build({"values": []})
    with pytest.raises(AdapterError, match="interface dump"):
        NetworkView.build({"values": {}}, {"interface": {}})


def test_setup_commands_install_the_documented_acl() -> None:
    """The commands in the device form install exactly the read-only ACL of the docs, which the
    integration test image installs too."""
    import json
    import re

    from signalbox.adapters.openwrt import setup

    doc = (Path(__file__).parent.parent / "docs" / "adapters" / "openwrt.md").read_text()
    block = re.search(
        r"```json\n(.*?)```", doc.split("## Read-only user on the device", 1)[1], re.S
    )
    assert block and json.loads(block.group(1)) == setup.READ_ACL
    cmds = setup.commands()
    acl = cmds.split("<<'END'\n", 1)[1].split("\nEND\n", 1)[0]
    assert json.loads(acl) == setup.READ_ACL
    assert "service rpcd restart" in cmds and "CHOOSE-A-PASSWORD" in cmds
    assert OpenWrtAdapter.manifest.setup_commands == cmds


@pytest.mark.parametrize("missing", ["wireless", "dhcp"])
async def test_router_without_wifi_or_dhcp_config(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, missing: str
) -> None:
    """No /etc/config/wireless (no radios) or dhcp (no DHCP server): empty, not an error."""
    sim.missing = {missing}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK, snap.errors
    assert not (snap.wlans if missing == "wireless" else snap.dhcp_servers)


async def test_router_without_network_config(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.missing = {"network"}
    snap = await adapter.observe()
    err = next(e for e in snap.errors if e.capability == "interfaces")
    assert "no readable network configuration" in err.message and err.fix


def test_address_alone_is_enough() -> None:
    cfg = OpenWrtConfig(url="192.0.2.2", password=SecretStr("x"))
    assert cfg.url == "https://192.0.2.2/ubus"
    assert OpenWrtConfig(url="https://192.0.2.2:8443/", password=SecretStr("x")).url == (
        "https://192.0.2.2:8443/ubus"
    )


# --- health and time (#178, #179) ------------------------------------------------------------


async def test_health(adapter: OpenWrtAdapter) -> None:
    [(key, h)] = (await adapter.read_health()).health.items()
    assert key == "ap1"
    assert h.uptime_seconds == 273906 and h.load_average == (0.11, 0.07, 0.04)
    assert (h.memory_total_bytes, h.memory_used_bytes) == (515878912, 515878912 - 371363840)
    assert [(s.name, s.kind.value, s.total_bytes, s.used_bytes) for s in h.storage] == [
        ("/", "system", 104320 * 1024, 3584 * 1024),
        ("/tmp", "temporary", 251892 * 1024, 404 * 1024),
    ]
    assert [(t.name, t.value_c) for t in h.temperatures] == [("cpu-thermal", 47.823)]
    assert h.cpu_load_pct is None and h.cpu_count is None  # not in system info


async def test_health_without_thermal_access_and_old_rpcd(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.thermal_zones = [("", 51000), ("soc-thermal", 39500), ("gpu", 1)]
    [h] = (await adapter.read_health()).health.values()
    assert [(t.name, t.value_c) for t in h.temperatures] == [
        ("thermal_zone0", 51),
        ("soc-thermal", 39.5),
        ("gpu", 0.001),
    ]
    sim.denied = {"file"}  # rpcd-mod-file missing from the ACL: no temperatures, no error
    [h] = (await adapter.read_health()).health.values()
    assert h.temperatures == [] and h.uptime_seconds == 273906


def test_health_mapping_of_odd_answers() -> None:
    old = vitals.health_of(
        {
            "uptime": -1,
            "load": [65536, "x", 0],
            "memory": {"total": 1000, "free": 300, "buffered": 100, "cached": 100},
            "root": {"total": 10, "free": 4},
            "tmp": {"total": 0},
        },
        [],
    )
    assert old.uptime_seconds is None and old.load_average is None
    assert old.memory_used_bytes == 500
    assert [(s.name, s.used_bytes) for s in old.storage] == [("/", 6 * 1024)]
    bare = vitals.health_of({"memory": "none", "root": {"total": 5, "used": 9}}, [])
    assert bare.memory_total_bytes is None and bare.storage[0].used_bytes == 5 * 1024
    assert vitals.health_of({"root": {"total": 5}}, []).storage[0].used_bytes is None
    assert vitals.thermal(0, None, None) is None and vitals.thermal(0, "hot", "x") is None


async def test_time(adapter: OpenWrtAdapter) -> None:
    [(key, t)] = (await adapter.read_time()).time.items()
    assert key == "ap1" and t.clock is not None and t.read_at is not None
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 2
    assert t.uncertainty_seconds is not None and t.uncertainty_seconds >= 0.5
    assert t.timezone == "Europe/Berlin"
    expected = datetime.now(ZoneInfo("Europe/Berlin")).utcoffset()
    assert expected is not None and t.utc_offset_minutes == expected.total_seconds() // 60
    assert t.ntp_client == NtpClient(enabled=True, servers=["192.0.2.1"])
    assert t.ntp_server == NtpServer(enabled=False)


async def test_time_of_a_router_serving_ntp(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles
) -> None:
    sim.router = True
    sim.clock_skew = 300
    a = OpenWrtAdapter(
        context(https_url, pinned_fingerprint=cert.fingerprint, role=DeviceRole.GATEWAY)
    )
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    t = snap.device.time
    assert t is not None and t.ntp_client is not None and t.ntp_server is not None
    offset = t.offset_seconds()
    assert offset is not None and 298 < offset < 302
    assert t.ntp_client.servers[0] == "0.openwrt.pool.ntp.org"
    assert t.ntp_server == NtpServer(enabled=True, segments=["home/segment/native"])
    [server] = snap.dhcp_servers
    assert server.ntp_servers == [ip_address("192.0.2.1")]


async def test_time_needs_the_system_config(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.denied = {"uci:system"}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    error, logs = sorted(snap.errors, key=lambda e: e.capability, reverse=True)
    assert error.capability == "time" and "uci.get (system)" in error.message
    assert logs.capability == "interfaces" and logs.message.startswith("log targets")
    assert snap.device.health is not None and snap.device.log_targets is None


def test_time_mapping_without_zone_or_ntp() -> None:
    start = datetime(2026, 7, 1, 12, tzinfo=UTC)
    bare = vitals.time_of({"localtime": int(start.timestamp())}, {"values": {}}, start, start, {})
    assert bare.timezone == "UTC" and bare.utc_offset_minutes == 0
    assert bare.offset_seconds() == 0.5 and bare.ntp_client is None and bare.ntp_server is None
    odd = vitals.time_of(
        {"localtime": "soon"},
        {
            "values": {
                "a": {".type": "system", "timezone": "<+0545>-5:45"},
                "ntp": {".type": "timeserver", "enabled": "0", "interface": "wan"},
            }
        },
        start,
        start,
        {"lan": "home/segment/native"},
    )
    assert odd.clock is None and odd.read_at is None and odd.utc_offset_minutes == 345
    assert odd.ntp_client == NtpClient(enabled=False)
    assert odd.ntp_server == NtpServer(enabled=False)
    huge = vitals.time_of(
        {"localtime": 0},
        {"values": {"a": {".type": "system", "timezone": "XYZ-20"}}},
        start,
        start,
        {},
    )
    assert huge.utc_offset_minutes is None and huge.clock is None
    assert vitals.time_of({"localtime": 10**20}, {}, start, start, {}).clock is None


@pytest.mark.parametrize(
    ("tz", "when", "minutes"),
    [
        ("UTC", "2026-07-01T00:00:00+00:00", 0),
        ("GMT0", "2026-07-01T00:00:00+00:00", 0),
        ("CET-1CEST,M3.5.0,M10.5.0/3", "2026-01-15T12:00:00+00:00", 60),
        ("CET-1CEST,M3.5.0,M10.5.0/3", "2026-07-15T12:00:00+00:00", 120),
        ("CET-1CEST,M3.5.0,M10.5.0/3", "2026-03-29T00:59:59+00:00", 60),  # 01:59:59 CET
        ("CET-1CEST,M3.5.0,M10.5.0/3", "2026-03-29T01:00:00+00:00", 120),  # 03:00 CEST
        ("CET-1CEST,M3.5.0,M10.5.0/3", "2026-10-25T00:59:59+00:00", 120),
        ("CET-1CEST,M3.5.0,M10.5.0/3", "2026-10-25T01:00:00+00:00", 60),
        ("EST5EDT,M3.2.0,M11.1.0", "2026-07-04T12:00:00+00:00", -240),
        ("EST5EDT,M3.2.0,M11.1.0", "2026-12-24T12:00:00+00:00", -300),
        ("AEST-10AEDT,M10.1.0,M4.1.0/3", "2026-01-10T00:00:00+00:00", 660),  # southern summer
        ("AEST-10AEDT,M10.1.0,M4.1.0/3", "2026-07-10T00:00:00+00:00", 600),
        ("<+0330>-3:30", "2026-07-10T00:00:00+00:00", 210),
        ("NZST-12NZDT-13,M9.5.0,M4.1.0/3", "2026-01-10T00:00:00+00:00", 780),
        ("EST5EDT", "2026-07-04T12:00:00+00:00", None),  # DST without rules
        ("CET-1CEST,J60,J300", "2026-07-04T12:00:00+00:00", None),  # Julian days: not read
        ("CET-1CEST,M13.5.0,M10.5.0", "2026-07-04T12:00:00+00:00", None),
        ("Europe/Berlin", "2026-07-04T12:00:00+00:00", None),  # not a POSIX string
        ("UTC0X", "2026-07-04T12:00:00+00:00", None),
    ],
)
def test_posix_offset(tz: str, when: str, minutes: int | None) -> None:
    assert vitals.posix_offset(tz, datetime.fromisoformat(when)) == minutes


@pytest.mark.parametrize("zone", ["Europe/Berlin", "America/New_York", "Australia/Sydney"])
def test_posix_offset_agrees_with_zoneinfo(zone: str) -> None:
    posix = {
        "Europe/Berlin": "CET-1CEST,M3.5.0,M10.5.0/3",
        "America/New_York": "EST5EDT,M3.2.0,M11.1.0",
        "Australia/Sydney": "AEST-10AEDT,M10.1.0,M4.1.0/3",
    }[zone]
    when = datetime(2026, 1, 1, tzinfo=UTC)
    while when.year == 2026:
        expected = when.astimezone(ZoneInfo(zone)).utcoffset()
        assert expected is not None
        assert vitals.posix_offset(posix, when) == expected.total_seconds() // 60, when
        when += timedelta(hours=7)


# --- management services (#173) --------------------------------------------------------------


async def test_services(adapter: OpenWrtAdapter, sim: OpenWrtSim) -> None:
    obs = await adapter.read_interfaces()
    by = {s.id: s for s in obs.services}
    assert sorted(by) == ["ap1/service/dropbear", "ap1/service/uhttpd", "ap1/service/uhttpd-ssl"]
    ssh = by["ap1/service/dropbear"]
    assert (ssh.kind.value, ssh.port, ssh.enabled, ssh.encrypted) == ("ssh", 22, True, True)
    assert ssh.segments == ["home/segment/native"]  # Interface lan
    assert ssh.password_login and ssh.root_login and ssh.root_password_login
    http, https = by["ap1/service/uhttpd"], by["ap1/service/uhttpd-ssl"]
    assert (http.port, http.enabled, http.redirects_to_https) == (80, True, False)
    assert (https.port, https.enabled, https.redirects_to_https) == (443, True, None)
    assert http.listen == [ip_address("0.0.0.0"), ip_address("::")]
    assert (await adapter.read_system()).transport_encrypted is True


async def test_services_follow_the_config(adapter: OpenWrtAdapter, sim: OpenWrtSim) -> None:
    sim.state["dropbear"] = {
        "cfg1": {".type": "dropbear", "enable": "0", "RootPasswordAuth": "off", "Port": "2222"},
        "cfg2": {".type": "dropbear", "DirectInterface": "lan1", "RootLogin": "0"},
    }
    sim.state["uhttpd"]["main"].update(
        {"listen_http": [], "listen_https": ["192.0.2.2:8443"], "redirect_https": "1"}
    )
    by = {s.id: s for s in (await adapter.read_interfaces()).services}
    off, second = by["ap1/service/dropbear"], by["ap1/service/dropbear-22"]
    assert (off.enabled, off.port, off.root_password_login, off.segments) == (
        False,
        2222,
        False,
        [],
    )
    assert second.interfaces == ["ap1/port/lan1"] and second.root_login is False
    assert not by["ap1/service/uhttpd"].enabled and by["ap1/service/uhttpd"].redirects_to_https
    assert by["ap1/service/uhttpd-ssl"].port == 8443
    assert by["ap1/service/uhttpd-ssl"].listen == [ip_address("192.0.2.2")]


async def test_old_acl_leaves_services_unread(adapter: OpenWrtAdapter, sim: OpenWrtSim) -> None:
    sim.denied = {"uci:dropbear", "uci:uhttpd"}
    snap = await adapter.observe()
    # the rest is read; the missing permission is reported with what to paste (gap)
    assert snap.status is DeviceStatus.PARTIAL and snap.ports and snap.services == []
    [gap] = snap.errors
    assert gap.capability == "interfaces" and "management services" in gap.message
    assert gap.fix and "Prepare the router" in gap.fix


async def test_router_without_dropbear_config(adapter: OpenWrtAdapter, sim: OpenWrtSim) -> None:
    sim.missing = {"dropbear"}  # not installed: only the web UI
    names = {s.name for s in (await adapter.read_interfaces()).services}
    assert names == {"uhttpd", "uhttpd-ssl"}


async def test_device_without_wifi_has_no_radios(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    """A switch running OpenWrt: no network.wireless object and no wireless config."""
    sim.missing = {"wireless"}
    sim.no_wireless_object = True
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK, snap.errors
    assert snap.radios == [] and snap.wlans == [] and snap.ports


# --- internal port structure (#252) ---------------------------------------------------------


async def test_structure_without_luci_rpc(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    """Without rpcd-mod-luci: netifd still tells bridges, VLAN devices and Wi-Fi interfaces;
    Ethernet ports stay unknown, and nothing is reported as missing."""
    sim.luci_rpc = False
    obs = await adapter.read_interfaces()
    ports = {p.name: p for p in obs.ports}
    assert ports["br-lan"].role is PortRole.BRIDGE and ports["br-lan.20"].role is PortRole.VLAN
    assert ports["phy0-ap0"].role is PortRole.WIRELESS
    assert ports["lan1"].role is None and ports["eth1"].role is None and ports["lan1"].lower == []
    assert ports["lan1"].external is None
    assert not obs.incomplete


async def test_structure_with_an_older_acl(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.denied = {"luci-rpc.getNetworkDevices"}
    obs = await adapter.read_interfaces()
    assert {p.name: p.role for p in obs.ports}["lan1"] is None
    [gap] = obs.incomplete
    assert "getNetworkDevices" in gap.message and gap.fix and "permission file" in gap.fix


async def test_wlans_name_their_interface(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_wireless()
    ports = {w.ssid: w.port_id for w in obs.wlans}
    assert ports["Example"] in {"ap1/port/phy0-ap0", "ap1/port/phy1-ap0"}
    assert all(p is None or p.startswith("ap1/port/phy") for p in ports.values())


async def test_port_tree_of_the_simulated_ap(adapter: OpenWrtAdapter) -> None:
    snap = await adapter.observe()
    net = Network(devices=[snap.device], ports=snap.ports, radios=snap.radios, wlans=snap.wlans)
    tree = {n.id: n for n in net.port_tree("ap1")}
    conduit = tree["ap1/port/eth1"]
    assert [c.id for c in conduit.children] == [f"ap1/port/lan{n}" for n in range(1, 5)]
    bridge = tree["ap1/port/br-lan"]
    assert bridge.members == [f"ap1/port/{n}" for n in BRIDGED]
    assert [c.id for c in bridge.children] == ["ap1/port/br-lan.1", "ap1/port/br-lan.20"]
    radio = tree["ap1/radio/radio0"]
    assert radio.node == "radio"
    assert {c.id for c in radio.children} == {"ap1/port/phy0-ap0", "ap1/port/phy0-ap1"}
    assert all(c.wlans for c in radio.children)  # each interface carries its SSID
    jacks = [p.name for p in net.external_ports("ap1", unknown=False)]
    assert jacks == ["eth0", "lan1", "lan2", "lan3", "lan4"]


def test_structure_of_a_swconfig_device() -> None:
    """swconfig: eth0 is the CPU port of switch0 (VLAN devices eth0.1, eth0.2 for its VLANs)."""
    uci = {
        "values": {
            "cfg1": {".type": "switch", "name": "switch0", "enable_vlan": "1"},
            "cfg2": {".type": "switch_vlan", "device": "switch0", "vlan": "1", "ports": "0t 1 2"},
            "cfg3": {".type": "switch_vlan", "device": "switch0", "vlan": "2", "vid": "2"},
            "cfg4": "odd",
        }
    }
    status = {
        "eth0": {"type": "Network device"},
        "eth0.1": {"type": "VLAN"},
        "eth0.2": {"type": "VLAN"},
        "br-lan": {"type": "bridge", "bridge-members": ["eth0.1", "wlan0", "gone"]},
        "wlan0": {"type": "Network device", "wireless": True},
    }
    out = structure(sorted(status), status, None, uci)
    assert out["eth0"] == (PortRole.CPU, [], None)
    assert out["eth0.2"] == (PortRole.VLAN, ["eth0"], PortKind.VIRTUAL)
    assert out["br-lan"] == (PortRole.BRIDGE, ["eth0.1", "wlan0"], PortKind.BRIDGE)
    assert out["wlan0"][0] is PortRole.WIRELESS
    # without swconfig sections eth0 stays unknown
    plain = structure(["eth0", "eth0.1"], {"eth0.1": {"type": "VLAN"}}, None, None)
    assert plain["eth0"][0] is None
    assert structure(["x"], {}, None, {"values": "odd"})["x"] == (None, [], None)


def test_structure_kernel_types() -> None:
    devices: dict[str, Any] = {
        "wg0": {"devtype": "wireguard", "type": 65534},
        "pppoe-wan": {"devtype": "ethernet", "type": 512},
        "veth0": {"devtype": "veth", "type": 1},
        "eth9": {"devtype": "ethernet", "type": 1},
        "lan1": {"devtype": "dsa", "parent": "eth0", "type": 1},
        "lan2": {"devtype": "dsa", "type": 1},
        "eth0": {"devtype": "ethernet", "type": 1},
        "v": {"devtype": "vlan", "parent": "eth9"},
        "odd": "not a table",
    }
    out = structure(sorted(devices), {"odd": "x"}, devices)
    assert out["wg0"][0] is PortRole.TUNNEL and out["pppoe-wan"][0] is PortRole.TUNNEL
    assert out["veth0"][0] is PortRole.VIRTUAL
    assert out["eth9"][0] is PortRole.JACK and out["eth0"][0] is PortRole.CPU
    assert out["lan1"] == (PortRole.JACK, ["eth0"], None) and out["lan2"][1] == []
    assert out["v"] == (PortRole.VLAN, ["eth9"], PortKind.VIRTUAL)
    assert out["odd"] == (None, [], None)


# --- WireGuard (#152) -----------------------------------------------------------------------


async def test_no_tunnels_without_wireguard(adapter: OpenWrtAdapter) -> None:
    assert (await adapter.read_vpn()).tunnels == []


async def test_wireguard_tunnel_and_peers(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.wireguard = True
    snap = await assert_contract(adapter)
    (t,) = snap.tunnels
    assert (t.id, t.name, t.up, t.listen_port, t.mtu) == (
        "ap1/tunnel/wg0",
        "wg0",
        True,
        51820,
        1420,
    )
    assert t.public_key == WG_KEY and t.port_id == "ap1/port/wg0"
    assert [str(a) for a in t.addresses] == ["2001:db8:ff::2/64"]
    site, phone = t.peers
    assert (site.name, site.public_key, site.endpoint_host, site.endpoint_port) == (
        "site-a",
        WG_SITE_A,
        "203.0.113.10",
        51820,
    )
    assert [str(n) for n in site.allowed_ips] == ["2001:db8:ff::1/128", "192.0.2.0/24"]
    assert (site.keepalive_seconds, site.preshared_key, site.rx_bytes, site.tx_bytes) == (
        25,
        True,
        1834567,
        2934871,
    )
    age = site.handshake_age(datetime.now(UTC))
    assert age is not None and 40 <= age < 60
    assert (phone.name, phone.endpoint_host, phone.latest_handshake, phone.preshared_key) == (
        "phone",
        None,
        None,
        False,
    )
    assert phone.keepalive_seconds == 0 and phone.rx_bytes == 0
    assert [str(n) for n in t.remote_networks(site)] == ["192.0.2.0/24"]
    assert [str(n) for n in t.routes or []] == ["2001:db8:ff::1/128", "192.0.2.0/24"]


async def test_no_private_or_preshared_key_leaves_the_adapter(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.wireguard = True
    secrets = [_wg_key("sim-secret-private"), _wg_key("sim-secret-psk")]
    uci = await adapter.ubus.call("uci", "get", {"config": "network"})
    assert all(s in str(uci) for s in secrets), "the sample must carry keys to be scrubbed"
    snap = await adapter.observe()
    assert not any(s in snap.model_dump_json() for s in secrets)
    scrubbed = await adapter._uci("network")
    assert not any(s in str(scrubbed) for s in secrets)


async def test_wireguard_without_luci_proto_wireguard(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.wireguard, sim.luci_wireguard = True, False
    (t,) = (await adapter.read_vpn()).tunnels
    assert t.public_key is None and t.up is True and len(t.peers) == 2
    assert all(p.latest_handshake is None and p.rx_bytes is None for p in t.peers)


async def test_wireguard_needs_its_acl_entry(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.wireguard = True
    sim.denied = {"luci.wireguard.getWgInstances"}
    snap = await adapter.observe()
    err = next(e for e in snap.errors if e.capability == "vpn")
    assert snap.tunnels == [] and "denied" in err.message.lower()


def test_wireguard_helpers_are_defensive() -> None:
    uci: dict[str, Any] = {
        "values": {
            "a": {
                ".type": "interface",
                ".name": "a",
                "proto": "wireguard",
                "private_key": "x",
                "ipaddr": "192.0.2.9",
                "netmask": "255.255.255.0",
                "listen_port": "0",
                "mtu": "9",
                "disabled": "1",
            },
            "p1": {".type": "wireguard_a", "public_key": "bad"},
            "p2": {
                ".type": "wireguard_a",
                "public_key": WG_PHONE,
                "preshared_key": " ",
                "endpoint_host": "vpn.example",
                "allowed_ips": "192.0.2.0/24 nonsense",
            },
            "p3": {".type": "wireguard_a", "public_key": WG_PHONE},
            "odd": "not a section",
        }
    }
    wireguard.scrub(uci)
    assert "private_key" not in uci["values"]["a"] and "preshared_key" not in str(uci)
    runtime = wireguard.instances({"a": {"peers": ["x", {}]}})
    (t,) = wireguard.tunnels(uci, runtime, "d", {}, set())
    assert (t.up, t.enabled, t.listen_port, t.mtu) == (False, False, None, None)
    assert [str(a) for a in t.addresses] == ["192.0.2.9/24"]
    (peer,) = t.peers
    assert (peer.endpoint_host, peer.endpoint_port) == ("vpn.example", None)
    assert peer.preshared_key is False
    assert [str(n) for n in peer.allowed_ips] == ["192.0.2.0/24"]
    assert wireguard.instances("odd") == {}
    assert wireguard.instances({"instances": {"a": {}}}) == {"a": {}}
    assert wireguard._endpoint("[2001:db8::1]:51820") == ("2001:db8::1", 51820)
    assert wireguard._endpoint("(none)") == (None, None)
    assert wireguard._endpoint("h:x") == ("h:x", None)


def test_wireguard_routes_come_from_route_sections_and_route_allowed_ips() -> None:
    uci: dict[str, Any] = {
        "values": {
            "a": {
                ".type": "route",
                "interface": "wg0",
                "target": "198.51.100.0",
                "netmask": "255.255.255.0",
            },
            "b": {".type": "route6", "interface": "wg0", "target": "2001:db8:20::/64"},
            "c": {".type": "route", "interface": "lan", "target": "203.0.113.0/24"},
            "d": {
                ".type": "route",
                "interface": "wg0",
                "target": "203.0.113.0/24",
                "disabled": "1",
            },
            "e": {".type": "route", "interface": "wg0", "target": "nonsense"},
            "f": {".type": "route", "interface": "wg0"},
            "g": {
                ".type": "wireguard_wg0",
                "route_allowed_ips": "1",
                "allowed_ips": ["192.0.2.0/24"],
            },
            "h": {".type": "wireguard_wg0", "allowed_ips": ["192.0.2.128/25"]},
        }
    }
    assert [str(n) for n in wireguard.routes(uci, "wg0")] == [
        "198.51.100.0/24",
        "2001:db8:20::/64",
        "192.0.2.0/24",
    ]


# --- log and monitoring targets (#180) -------------------------------------------------------


async def test_log_targets_from_system_and_optional_packages(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    snap = await assert_contract(adapter)
    assert [
        (t.kind.value, t.endpoint(), t.transport.value, t.name)
        for t in snap.device.log_targets or []
    ] == [("syslog", "192.0.2.5:514", "udp", "logd")]
    assert not any(s.kind.value == "snmp" for s in snap.services)  # snmpd not installed
    sim.packages = {"snmpd", "luci_statistics", "softflowd"}
    sim.configs = None
    snap = await assert_contract(adapter)
    by = {(t.kind.value, t.name): t for t in snap.device.log_targets or []}
    trap = by[("snmp-trap", "trap2sink")]
    assert (trap.endpoint(), trap.enabled, trap.topics) == ("192.0.2.5:162", True, ["v2c"])
    assert by[("metrics", "collectd")].endpoint() == "192.0.2.5:25826"
    flow = by[("netflow", "softflowd")]
    assert (flow.endpoint(), flow.enabled, flow.topics) == ("192.0.2.5:9995", False, ["v5"])
    (agent,) = [s for s in snap.services if s.kind.value == "snmp"]
    assert agent.id == "ap1/service/snmp" and agent.enabled and agent.snmp is not None
    assert agent.snmp.default_community and agent.snmp.write_access
    assert [v.value for v in agent.snmp.versions] == ["1", "2c"] and agent.allowed_from == []
    assert '"public"' not in snap.model_dump_json()  # the community is never kept


async def test_log_targets_with_an_older_acl(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.packages = {"snmpd"}
    sim.denied = {"uci:snmpd", "uci:luci_statistics", "uci:softflowd"}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK  # optional: the rest is read
    (gap,) = snap.errors
    assert gap.optional and gap.message.startswith("SNMP and monitoring targets (snmpd, ")
    assert gap.remedy == "access" and snap.device.log_targets is not None


def test_log_target_mapping_edge_cases() -> None:
    def uci(*sections: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
        return {"values": {n: {".type": k, ".name": n, **o} for k, n, o in sections}}

    system = uci(
        ("system", "cfg1", {"log_ip": ["192.0.2.5", ""], "log_proto": "tcp", "log_remote": "0"})
    )
    (t,) = monitoring.system_targets(system)
    assert (t.transport.value, t.enabled, t.port) == ("tcp", False, 514)
    assert monitoring.system_targets(uci()) == [] and monitoring.system_targets({}) == []
    agent, traps = monitoring.snmpd(
        "ap1",
        uci(
            ("com2sec", "lan", {"community": "s3cret", "source": "192.0.2.0/24"}),
            ("com2sec", "lo", {"community": "other", "source": "localhost"}),
            ("agent", "a", {"agentaddress": "UDP:1161"}),
            ("snmpd", "general", {"enabled": "0"}),
            ("trapsink", "t", {"host": ""}),
        ),
    )
    assert agent is not None and not agent.enabled and agent.port == 1161 and traps == []
    assert agent.snmp is not None and agent.snmp.default_community is False
    assert [str(n) for n in agent.allowed_from] == ["192.0.2.0/24", "127.0.0.1/32"]
    assert monitoring.snmpd("ap1", {"values": {}}) == (None, [])
    assert monitoring.collectd(uci()) == []
    (ipfix,) = monitoring.softflowd(
        uci(
            (
                "softflowd",
                "main",
                {"enabled": "1", "host_port": "[2001:db8::5]:4739", "export_version": "10"},
            )
        )
    )
    assert (ipfix.kind.value, ipfix.endpoint(), ipfix.name, ipfix.topics) == (
        "ipfix",
        "[2001:db8::5]:4739",
        "softflowd main",
        [],
    )
    assert monitoring.host_port("collector") == ("collector", None)
    assert monitoring.softflowd(uci(("softflowd", "x", {"host_port": ""}))) == []


# --- accounts (#175) -------------------------------------------------------------------------


async def test_rpcd_logins_without_their_hashes(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    from signalbox.model import AccountPrivilege

    snap = await assert_contract(adapter)
    by = {a.name: a for a in snap.device.accounts or []}
    assert by["root"].privilege is AccountPrivilege.ADMIN and by["root"].password_set is None
    own = by[sim.username]
    assert own.is_signalbox and own.privilege is AccountPrivilege.READ and own.password_set
    assert snap.device.signalbox_account_privilege is AccountPrivilege.READ
    assert snap.device.default_credentials is False
    text = snap.model_dump_json()
    assert "$1$" not in text and "$p$" not in text and "notarealhash" not in text
    assert sim.root_attempts == 0  # no probe unless asked for


async def test_rpcd_with_an_older_acl(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.denied = {"uci:rpcd"}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK and snap.device.accounts is None
    (gap,) = snap.errors
    assert gap.optional and gap.remedy == "access" and gap.message_id == "openwrt.accounts"


async def test_empty_root_password_probe_is_opt_in(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles
) -> None:
    probe = {"probe_empty_root_password": True}
    ctx = context(https_url, pinned_fingerprint=cert.fingerprint, config=probe)
    snap = await observe(ctx)
    assert snap.device.default_credentials is False and sim.root_attempts == 1
    sim.root_password = ""
    sessions = len(sim.sessions)
    snap = await observe(ctx)
    assert snap.device.default_credentials is True and sim.root_attempts == 2
    assert len(sim.sessions) == sessions + 1  # Signalbox's own; the probe's was destroyed


async def test_root_without_password_configured_is_the_factory_default(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles
) -> None:
    sim.root_password = ""
    config = {"username": "root", "password": SecretStr(""), "probe_empty_root_password": True}
    snap = await observe(context(https_url, pinned_fingerprint=cert.fingerprint, config=config))
    assert snap.device.default_credentials is True
    assert sim.root_attempts == 1  # the login itself, no extra probe


def test_rpcd_scrub_and_privileges() -> None:
    from signalbox.adapters.openwrt import accounts
    from signalbox.model import AccountPrivilege

    answer = {
        "values": {
            "a": {".type": "login", ".index": 2, "username": "x", "password": "$1$s$h"},
            "b": {".type": "login", ".index": "1", "username": "y", "write": "net wifi"},
            "c": {".type": "login", ".index": "z", "username": " ", "read": ["*"]},
            "d": {".type": "rpcd", "socket": "/var/run/ubus/ubus.sock"},
            "e": "not a section",
        }
    }
    accounts.scrub(answer)
    assert "password" not in str(answer) or "password_kind" in str(answer)
    assert "$1$" not in str(answer)
    found = accounts.logins(answer, "x")
    assert [(a.name, a.privilege, a.password_set, a.is_signalbox) for a in found] == [
        ("y", AccountPrivilege.WRITE, False, False),
        ("x", AccountPrivilege.OTHER, True, True),
    ]
    assert accounts.logins({"values": None}, "x") == [] and accounts.scrub({}) == {}
    assert accounts.privilege(["signalbox"], []) is AccountPrivilege.READ


# radio capabilities and state (#172) ----------------------------------------------------------


async def test_radio_capabilities_and_state(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_wireless()
    radios = {r.name: r for r in obs.radios}
    r0, r1 = radios["radio0"], radios["radio1"]
    assert r0.standard is WifiStandard.AX and r0.channel_auto is False
    assert r0.standards == [WifiStandard.B, WifiStandard.G, WifiStandard.N, WifiStandard.AX]
    assert r0.supported_channels == list(range(1, 14)) and r0.supported_widths_mhz == [20, 40]
    assert (r0.max_tx_power_dbm, r0.noise_dbm, r0.dfs_capable) == (20, -92, None)
    assert (r0.channel_utilisation_pct, r0.interference_pct) == (31.0, 10.3)
    assert r0.client_count == 2 and r0.center_channel is None and r0.dfs_state is None
    assert r1.standards == [WifiStandard.A, WifiStandard.N, WifiStandard.AC, WifiStandard.AX]
    assert r1.supported_widths_mhz == [20, 40, 80, 160] and r1.dfs_capable is True
    assert 149 not in (r1.supported_channels or []) and r1.center_channel == 42
    assert r1.client_count == 1 and r1.channel_utilisation_pct == 12.0
    assert not obs.incomplete


async def test_radio_state_with_an_acl_from_before_172(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.denied = {"iwinfo", "hostapd.phy0-ap0.get_status"}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK  # optional: the rest is read
    (gap,) = [e for e in snap.errors if e.capability == "wireless"]
    assert gap.optional and gap.message_id == "openwrt.radioState" and "iwinfo" in gap.message
    r0 = next(r for r in snap.radios if r.name == "radio0")
    assert r0.standard is WifiStandard.AX and r0.standards is None and r0.dfs_state is None


async def test_radio_state_without_rpcd_mod_iwinfo(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.iwinfo = False
    obs = await adapter.read_wireless()
    (gap,) = obs.incomplete
    assert gap.optional and gap.message_id == "openwrt.noIwinfo"
    assert gap.fix_id == "openwrt.noIwinfo.fix" and "rpcd-mod-iwinfo" in (gap.fix or "")
    assert all(r.standards is None for r in obs.radios)


async def test_radio_state_without_radios_makes_no_call(
    sim: OpenWrtSim, adapter: OpenWrtAdapter
) -> None:
    sim.no_wireless_object = True
    sim.denied = {"iwinfo"}
    obs = await adapter.read_wireless()
    assert not obs.incomplete and all(not r.enabled for r in obs.radios)


@pytest.mark.parametrize(
    ("htmode", "band", "expected"),
    [
        ("EHT320", Band.GHZ_6, WifiStandard.BE),
        ("HE80", Band.GHZ_5, WifiStandard.AX),
        ("VHT40", Band.GHZ_5, WifiStandard.AC),
        ("HT20", Band.GHZ_2_4, WifiStandard.N),
        ("NOHT", Band.GHZ_2_4, WifiStandard.G),
        ("NOHT", Band.GHZ_5, WifiStandard.A),
        ("", Band.GHZ_5, None),
        ("HE", Band.GHZ_5, None),
        ("odd", Band.GHZ_5, None),
    ],
)
def test_standard_of_htmode(htmode: str, band: Band, expected: WifiStandard | None) -> None:
    assert radio_state.standard_of(htmode, band) is expected


def test_radio_capability_parsing() -> None:
    modes = ["b", "g", "n", "a", "ac", "ax", "be", "x"]
    info = {"hwmodes": modes, "htmodes": ["HT20", "EHT320", "VHT80+80"], "noise": 0}
    six = radio_state.capabilities(Band.GHZ_6, info, None, None)
    assert six == {
        "standards": [WifiStandard.AX, WifiStandard.BE],
        "supported_widths_mhz": [20, 320],
    }
    two = radio_state.capabilities(Band.GHZ_2_4, {"htmodes": ["HE80"]}, {"results": "odd"}, {})
    assert two == {"supported_widths_mhz": None}
    freqs = {"results": [{"channel": 36, "mhz": 5180}, {"channel": 1, "mhz": 5955}, {"mhz": 5200}]}
    assert radio_state.capabilities(Band.GHZ_5, None, freqs, None) == {
        "supported_channels": [36],
        "dfs_capable": False,
    }
    assert radio_state.band_of_mhz(900) is None


def test_radio_utilisation_and_status_parsing() -> None:
    row = {"mhz": 5180, "active_time": 100, "busy_time": 50, "noise": -90}
    assert radio_state.utilisation({"results": [row]}, 5180) == {
        "channel_utilisation_pct": 50.0,
        "noise_dbm": -90,
    }
    assert radio_state.utilisation({"results": [row]}, 2412) == {}
    assert radio_state.utilisation({"results": [{**row, "active_time": 0}]}, 5180) == {}
    assert radio_state.status(None, True) == {}
    cac = {"dfs": {"cac_active": True}, "airtime": {"utilization": 255}}
    assert radio_state.status(cac, True) == {
        "dfs_state": DfsState.CAC,
        "channel_utilisation_pct": 100.0,
    }
    assert radio_state.status(cac, False) == {"channel_utilisation_pct": 100.0}


# --- spanning tree (#155) ------------------------------------------------------------


def _stp_on(sim: OpenWrtSim, priority: str | None = "4096") -> None:
    for section in sim.state["network"].values():
        if section.get("name") == "br-lan":
            section["stp"] = "1"
            if priority is not None:
                section["priority"] = priority


async def test_stp_off_is_the_default(adapter: OpenWrtAdapter) -> None:
    snap = await assert_contract(adapter)
    assert snap.device.stp_bridges is not None
    (b,) = snap.device.stp_bridges
    assert (b.name, b.protocol, b.priority, b.port_id) == (
        "br-lan",
        StpProtocol.NONE,
        0x7FFF,
        "ap1/port/br-lan",
    )
    assert b.bridge_id is not None and b.bridge_id.startswith("7fff.02:")
    assert b.root_bridge_id is None
    assert all(p.stp is None for p in snap.ports)


async def test_stp_on_reads_sysfs(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    _stp_on(sim)
    snap = await assert_contract(adapter)
    assert snap.device.stp_bridges is not None
    (b,) = snap.device.stp_bridges
    assert b.protocol is StpProtocol.STP and b.priority == 4096 and b.is_root is True
    assert b.bridge_id is not None and b.bridge_id.startswith("1000.02:")
    lan1 = next(p for p in snap.ports if p.name == "lan1")
    assert lan1.stp is not None
    assert (lan1.stp.state, lan1.stp.path_cost, lan1.stp.bpdu_guard) == (
        StpPortState.FORWARDING,
        4,
        False,
    )
    assert not [e for e in snap.errors if e.message_id == "openwrt.stpState"]


async def test_old_acl_keeps_the_setting(
    sim: OpenWrtSim, adapter: OpenWrtAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stp_on(sim, priority=None)
    monkeypatch.setattr(openwrt_sim, "FILES", ("/tmp/dhcp.leases",))
    obs = await adapter.read_interfaces()
    (b,) = obs.stp_bridges["ap1"]
    assert b.protocol is StpProtocol.STP and b.root_bridge_id is None
    assert b.bridge_id is not None and b.bridge_id.startswith("7fff.")  # from netifd's MAC
    (gap,) = [g for g in obs.incomplete if g.message_id == "openwrt.stpState"]
    assert gap.optional and gap.remedy


async def test_port_without_brport(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    _stp_on(sim)
    sim.no_brport = {"lan2"}
    obs = await adapter.read_interfaces()
    ports = {p.name: p for p in obs.ports}
    assert ports["lan2"].stp is None and ports["lan1"].stp is not None


def test_settings_and_parsers() -> None:
    devices = [
        {"type": "bridge", "name": "br-x", "stp": "1", "priority": "x"},
        {"type": "bridge"},
        {"type": "8021q", "name": "eth0.2"},
    ]
    (s,) = ostp.settings(devices, {"br-x": {"bridge-attributes": {"priority": 70000}}})
    assert s.on and s.priority is None and s.mac is None and s.members == []
    b = ostp.bridge(s, {}, {}, {})
    assert b.bridge_id is None and b.protocol is StpProtocol.STP
    s.priority, s.mac = 4096, "bogus"
    assert ostp.bridge(s, {}, {}, {}).bridge_id is None
    b = ostp.bridge(
        s, {"root_id": "8000.020000000001", "root_port": "2", "root_path_cost": "4"},
        {"lan2": "d/port/lan2"}, {2: "lan2"},
    )  # fmt: skip
    assert b.root_port_id == "d/port/lan2" and b.root_path_cost == 4 and b.is_root is None
    root = ostp.port({"state": "3", "port_no": "0x2"}, 2)
    assert root.role is StpPortRole.ROOT
    assert ostp.port({"state": "4"}, 2).role is StpPortRole.ALTERNATE
    assert ostp.port({"state": "0"}, None).role is StpPortRole.DISABLED
    assert ostp.port({}, None).state is None
    assert ostp._flag(True) is True and ostp._flag("maybe") is None and ostp._flag("0") is False
    assert ostp._number(True) is None and ostp._number(5) == 5 and ostp._number("x") is None


# BSSIDs and neighbouring networks (#169) ---------------------------------------------


async def test_openwrt_reports_bssids_and_no_scan_by_default(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles
) -> None:
    sim.denied = {"iwinfo.scan"}  # a scan would be refused: it must not be tried
    a = OpenWrtAdapter(context(https_url, pinned_fingerprint=cert.fingerprint))
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.status is DeviceStatus.OK and not snap.wifi_scan
    assert not [e for e in snap.errors if e.capability == "wireless"]
    bssids = {w.port_id: w.bssid for w in snap.wlans}
    ports = {p.id: p.mac for p in snap.ports}
    assert bssids and all(b is not None and b == ports[p] for p, b in bssids.items())


async def test_openwrt_scans_when_asked(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> None:
    ctx = context(https_url, pinned_fingerprint=cert.fingerprint, config={"scan_neighbours": True})
    a = OpenWrtAdapter(ctx)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    by = {r.bssid: r for r in snap.wifi_scan}
    a1 = by["02:5e:00:00:01:01"]
    assert a1.ssid == "Neighbour-A" and a1.band is Band.GHZ_2_4 and a1.channel == 6
    assert a1.signal_dbm == -58 and a1.security is Security.WPA2 and a1.width_mhz == 20
    assert a1.kind.value == "scan" and a1.last_seen is not None
    assert a1.radio_id is not None and a1.id == f"{a1.radio_id}/scan/{a1.bssid}"
    assert by["02:5e:00:00:01:02"].security is Security.WPA2_WPA3
    assert by["02:5e:00:00:01:03"].ssid is None  # hidden
    assert by["02:5e:00:00:01:04"].security is Security.OPEN
    c = by["02:5e:00:00:02:02"]
    assert c.band is Band.GHZ_5 and c.width_mhz == 80 and c.security is Security.WPA3
    radios = {r.id: r for r in snap.radios}
    assert all(radios[r.radio_id or ""].band is r.band for r in snap.wifi_scan)


async def test_openwrt_scan_refused_by_an_old_acl(
    sim: OpenWrtSim, https_url: str, cert: TlsFiles
) -> None:
    sim.denied = {"iwinfo.scan"}
    ctx = context(https_url, pinned_fingerprint=cert.fingerprint, config={"scan_neighbours": True})
    a = OpenWrtAdapter(ctx)
    try:
        obs = await a.read_wireless()
    finally:
        await a.close()
    assert not obs.wifi_scan
    (gap,) = obs.incomplete
    assert gap.optional and gap.message_id == "openwrt.radioState"
    assert obs.radios[0].standards is not None  # the rest of the radio is read
