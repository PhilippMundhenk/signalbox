"""OPNsense adapter against its simulator, over real sockets (plain HTTP and pinned TLS)."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    Unreachable,
    load_adapters,
)
from signalbox.adapters import https as https_mod
from signalbox.adapters.https import DeviceHttp, NotFound, normalise_fingerprint
from signalbox.adapters.opnsense import (
    ARP,
    CPU_TYPE,
    DNSMASQ,
    FIRMWARE,
    HOST_ALIASES,
    HOST_OVERRIDES,
    INTERFACES,
    ISC_LEASES,
    ISC_STATUS,
    KEA,
    KEA_LEASES,
    NTP_STATUS,
    SYSTEM_TEMPERATURE,
    SYSTEM_TIME,
    UNBOUND,
    VLANS,
    WG_SHOW,
    OpnsenseAdapter,
    OpnsenseConfig,
    _addrs,
    _endpoint,
    _int,
    _items,
    _pool,
    _rows,
    _selected,
    _speed,
    autoneg_of,
    max_speed,
    media_of,
    vitals,
    wireguard_tunnels,
)
from signalbox.merge import merge
from signalbox.model import (
    AddressSource,
    DeviceRole,
    DeviceStatus,
    LeaseState,
    Membership,
    NtpClient,
    PortMedia,
    Site,
    Snapshot,
    port_id,
)
from signalbox.rules import evaluate
from signalbox.rules.dns import forwarder_loop, single_forwarder
from signalbox.sim.opnsense import (
    KEY,
    SECRET,
    WG_KEY,
    WG_PHONE,
    WG_SITE_B,
    OpnsenseSimulator,
    _iface,
)
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract

SIM = OpnsenseSimulator()


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
def sim() -> OpnsenseSimulator:
    SIM.__dict__.update(OpnsenseSimulator().__dict__)  # fresh data and switches every test
    return SIM


def adapter(url: str, pin: str | None = None, timeout: float = 5.0, **cfg: Any) -> OpnsenseAdapter:
    config = OpnsenseConfig(
        url=url,
        api_key=SecretStr(cfg.pop("key", KEY)),
        api_secret=SecretStr(cfg.pop("secret", SECRET)),
        allow_insecure_http=url.startswith("http://"),
    )
    return OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="Firewall",
            role=DeviceRole.GATEWAY,
            config=config,
            pinned_fingerprint=pin,
            timeout=timeout,
        )
    )


async def observe(a: OpnsenseAdapter) -> Snapshot:
    try:
        return await a.observe()
    finally:
        await a.close()


@pytest.fixture
async def snap(http_url: str) -> Snapshot:
    a = adapter(http_url)
    try:
        return await assert_contract(a)
    finally:
        await a.close()


# --- contract and mapping --------------------------------------------------------------------


async def test_contract_over_pinned_tls(https_url: str, tls: TlsFiles) -> None:
    a = adapter(https_url, pin=tls.fingerprint)
    try:
        snap = await assert_contract(a)
        again = await a.observe()  # a second observation probes and pins again
    finally:
        await a.close()
    assert snap.status is again.status is DeviceStatus.OK
    assert snap.subnets


def test_entry_point() -> None:
    assert load_adapters()["opnsense"] is OpnsenseAdapter


async def test_system(snap: Snapshot) -> None:
    d = snap.device
    assert (d.vendor, d.model, d.management_address) == ("Deciso", "OPNsense", "127.0.0.1")
    assert d.firmware is not None
    assert (d.firmware.current, d.firmware.available) == ("26.7.8_1", "26.7.9")


async def test_package_revision_is_not_an_update(http_url: str, sim: OpnsenseSimulator) -> None:
    """OPNsense 26.7: product_version carries the package revision, product_latest not."""
    product = sim.data[FIRMWARE]["product"]
    product["product_version"], product["product_latest"] = "26.7.9_3", "26.7.9"
    snap = await observe(adapter(http_url))
    assert snap.device.firmware is not None
    assert (snap.device.firmware.current, snap.device.firmware.available) == ("26.7.9_3", None)


async def test_port_structure(http_url: str, sim: OpnsenseSimulator) -> None:
    """NICs are jacks, VLAN devices run on their parent, laggs and bridges list members (#252)."""
    sim.data[INTERFACES]["rows"] += [
        {**_iface("lagg0", "", ""), "members": ["igb1", "igb2"]},
        {**_iface("bridge0", "", ""), "members": "igb0, lagg0"},
    ]
    snap = await observe(adapter(http_url))
    ports = {p.name: p for p in snap.ports}
    ids = {n: p.id for n, p in ports.items()}
    assert {n: p.role.value for n, p in ports.items() if p.role} == {
        "igb0": "jack",
        "igb1": "jack",
        "igb2": "jack",
        "vlan01": "vlan",
        "vlan02": "vlan",
        "lagg0": "lag",
        "bridge0": "bridge",
        "wg0": "tunnel",
    }
    assert ports["vlan01"].lower == [ids["igb0"]] and ports["igb0"].lower == []
    assert ports["lagg0"].lower == [ids["igb1"], ids["igb2"]]
    assert ports["bridge0"].lower == [ids["igb0"], ids["lagg0"]]
    assert ports["wg0"].kind.value == "virtual" and ports["vlan01"].external is False


async def test_ports_and_segments(snap: Snapshot) -> None:
    assert sorted(p.name for p in snap.ports) == ["igb0", "igb1", "igb2", "vlan01", "vlan02", "wg0"]
    igb0 = next(p for p in snap.ports if p.name == "igb0")
    assert (igb0.up, igb0.speed_mbps, igb0.full_duplex) == (True, 1000, True)
    assert igb0.mac == "02:00:00:00:01:00" and igb0.vendor_extra["identifier"] == "lan"
    igb1 = next(p for p in snap.ports if p.name == "igb1")
    assert igb1.speed_mbps == 2500
    igb2 = next(p for p in snap.ports if p.name == "igb2")
    assert (igb2.up, igb2.speed_mbps, igb2.full_duplex) == (False, None, None)
    # port details (#156)
    assert (igb0.description, igb0.admin_up, igb0.mtu, igb0.autoneg) == ("LAN", True, 1500, True)
    assert (igb0.max_speed_mbps, igb0.media) == (1000, PortMedia.COPPER)
    assert igb0.vendor_extra == {"identifier": "lan"}
    assert (igb1.max_speed_mbps, igb1.description) == (2500, "WAN")
    assert (igb2.description, igb2.admin_up, igb2.mtu) == (None, None, 9000)  # unassigned
    assert (igb2.max_speed_mbps, igb2.media, igb2.vendor_extra) == (10000, PortMedia.SFP_PLUS, {})

    segs = {s.id: s for s in snap.segments}
    assert sorted(segs) == [
        "home/segment/20",
        "home/segment/30",
        "home/segment/40",
        "home/segment/native",
    ]
    lan = port_id("fw", "igb0")
    assert [(m.port_id, m.mode) for m in segs["home/segment/native"].members] == [
        (lan, Membership.UNTAGGED)
    ]
    for vlan, name in [(20, "IoT"), (30, "Guest"), (40, "Lab")]:
        seg = segs[f"home/segment/{vlan}"]
        assert (seg.vlan, seg.name) == (vlan, name)
        assert [(m.port_id, m.mode) for m in seg.members] == [(lan, Membership.TAGGED)]
    assert segs["home/segment/native"].name == "LAN"


async def test_subnets(snap: Snapshot) -> None:
    got = {(s.segment_id, str(s.interface)) for s in snap.subnets}
    assert got == {
        ("home/segment/native", "192.0.2.1/24"),
        ("home/segment/native", "2001:db8:1::1/64"),
        ("home/segment/20", "198.51.100.1/24"),
        ("home/segment/30", "203.0.113.1/24"),
    }  # no WAN, no link-local, no loopback
    assert all(s.gateway for s in snap.subnets)


async def test_dhcp(snap: Snapshot) -> None:
    servers = {s.id: s for s in snap.dhcp_servers}
    assert sorted(servers) == ["fw/dhcp/isc-opt2", "fw/dhcp/kea-lan", "fw/dhcp/kea-opt1"]
    lan = servers["fw/dhcp/kea-lan"]
    assert lan.enabled and lan.segment_id == "home/segment/native"
    assert [(str(p.start), str(p.end)) for p in lan.pools] == [("192.0.2.100", "192.0.2.199")]
    assert lan.router == ip_address("192.0.2.1") and lan.dns_servers == [ip_address("192.0.2.1")]
    assert lan.lease_seconds == 4000
    assert [(r.mac, str(r.address), r.hostname) for r in lan.reservations] == [
        ("00:00:5e:00:53:10", "192.0.2.10", "printer")
    ]
    iot = servers["fw/dhcp/kea-opt1"]
    assert [(str(p.start), str(p.end)) for p in iot.pools] == [
        ("198.51.100.129", "198.51.100.190"),
        ("198.51.100.200", "198.51.100.210"),
    ]
    assert iot.dns_servers == [ip_address("198.51.100.1"), ip_address("192.0.2.1")]
    assert iot.domain == "iot.example" and iot.reservations[0].hostname == "sensor"
    guest = servers["fw/dhcp/isc-opt2"]
    assert guest.enabled and guest.segment_id == "home/segment/30" and not guest.pools
    assert [r.hostname for r in guest.reservations] == ["kiosk"]
    assert guest.vendor_extra["server"] == "isc"


async def test_dhcp_leases_options_and_relay(snap: Snapshot) -> None:
    servers = {s.id: s for s in snap.dhcp_servers}
    lan, iot, guest = (servers[f"fw/dhcp/{n}"] for n in ("kea-lan", "kea-opt1", "isc-opt2"))
    assert lan.leases is not None and iot.leases is not None and guest.leases is not None
    laptop, phone = lan.leases
    assert (laptop.mac, laptop.state, laptop.reserved) == (
        "02:00:00:00:00:21",
        LeaseState.ACTIVE,
        False,
    )
    assert laptop.client_id == "01:02:00:00:00:00:21" and laptop.hostname == "laptop"
    assert laptop.expires is not None and laptop.starts is not None
    assert (laptop.expires - laptop.starts).total_seconds() == 4000
    assert phone.state is LeaseState.EXPIRED
    assert [(x.address.compressed, x.reserved) for x in iot.leases] == [("198.51.100.20", True)]
    assert iot.search_domains == ["iot.example", "example.net"]
    assert [(str(r.destination), str(r.gateway)) for r in iot.static_routes] == [
        ("203.0.113.0/24", "198.51.100.254")
    ]
    assert iot.boot is not None
    assert (str(iot.boot.next_server), iot.boot.server_name, iot.boot.filename) == (
        "198.51.100.5",
        "tftp.iot.example",
        "pxelinux.0",
    )
    dynamic, static = guest.leases
    assert (dynamic.state, dynamic.reserved) == (LeaseState.ACTIVE, False)
    assert dynamic.expires is not None and dynamic.starts is not None
    assert (static.state, static.reserved) == (LeaseState.RESERVED, True)
    (relay,) = snap.dhcp_relays
    assert relay.id == "fw/dhcp-relay/30" and relay.segment_id == "home/segment/30"
    assert [str(a) for a in relay.servers] == ["192.0.2.53"] and relay.enabled


async def test_dns(snap: Snapshot) -> None:
    (dns,) = snap.dns_services  # dnsmasq does DHCP only (port 0): no DNS service
    assert dns.id == "fw/dns/unbound" and dns.name == "unbound"
    assert dns.enabled and dns.port == 53 and dns.config_read
    assert [str(a) for a in dns.listen] == ["192.0.2.1", "2001:db8:1::1", "198.51.100.1"]
    assert [str(a) for a in dns.forwarders] == ["192.0.2.53", "[2001:db8:53::53]:853"]
    assert [(h.name, str(h.address)) for h in dns.host_records] == [
        ("nas.home.example", "192.0.2.10"),
        ("nas.home.example", "2001:db8:1::10"),
        ("storage.home.example", "192.0.2.10"),  # the alias, with its override's address
    ]
    assert [h.source for h in dns.host_records] == ["host-override"] * 2 + ["alias"]
    assert [(f.transport, f.tls_name) for f in dns.forwarders] == [
        ("udp", None),
        ("tls", "dns.example.net"),
    ]
    assert dns.dnssec is True and dns.supports_encrypted_dns
    # selected predefined list by name, own list by host only (the token is dropped)
    assert [b.name for b in dns.blocklists] == ["AdGuard List", "lists.example.net"]
    assert dns.host_records_read
    assert dns.vendor_extra == {"domain_forwards": {"corp.example": "198.51.100.53"}}


def _unbound(sim: OpnsenseSimulator, port: str, *forwards: dict[str, str]) -> None:
    unbound = sim.data[UNBOUND]["unbound"]
    unbound["general"]["port"] = port
    unbound["dots"]["dot"] = {f"d-{i}": {"enabled": "1", **f} for i, f in enumerate(forwards)}


async def test_adguard_home_next_to_unbound_is_not_a_loop(
    http_url: str, sim: OpnsenseSimulator
) -> None:
    """#241: AdGuard Home (plugin) answers on 53, Unbound moved to 53530 and forwards to the
    firewall's own address: two services, not a loop."""
    _unbound(sim, "53530", {"type": "forward", "server": "192.0.2.1", "port": ""})
    snap = await observe(adapter(http_url))
    unbound, other = snap.dns_services
    assert unbound.port == 53530 and [(str(f.address), f.port) for f in unbound.forwarders] == [
        ("192.0.2.1", 53)
    ]
    assert other.id == "fw/dns/port-53" and other.port == 53 and not other.config_read
    assert other.listen == [] and "unbound on 53530" in str(other.vendor_extra["note"])
    net = merge([Site(id="home", name="Home")], [snap])
    found = [f for f in evaluate(net, [forwarder_loop, single_forwarder]) if not f.acknowledged]
    assert [(f.rule_id, f.incomplete) for f in found] == [("dns.forwarder-loop", True)]
    assert found[0].message == (
        "Firewall (unbound) forwards DNS to 192.0.2.1, the DNS service Firewall (port 53) "
        "that Signalbox does not read: whether lookups come back in a loop cannot be checked"
    )
    # Unbound forwarding to its own port is still a loop
    _unbound(sim, "53530", {"type": "forward", "server": "192.0.2.1", "port": "53530"})
    net = merge([Site(id="home", name="Home")], [await observe(adapter(http_url))])
    (loop,) = evaluate(net, [forwarder_loop])
    assert not loop.incomplete and loop.message == (
        "DNS lookups loop: Firewall (unbound) forwards to 192.0.2.1:53530, itself"
    )


async def test_unbound_forwarding_to_adguard_on_another_port(
    http_url: str, sim: OpnsenseSimulator
) -> None:
    """The other way round: Unbound on 53 forwards to AdGuard Home on 127.0.0.1:5353."""
    _unbound(sim, "", {"type": "forward", "server": "127.0.0.1", "port": "5353"})
    snap = await observe(adapter(http_url))
    (unbound,) = snap.dns_services
    assert unbound.port == 53 and [str(f) for f in unbound.forwarders] == ["127.0.0.1:5353"]
    net = merge([Site(id="home", name="Home")], [snap])
    (f,) = evaluate(net, [forwarder_loop])
    assert f.incomplete and "port 5353 of Firewall, where another DNS server" in f.message


async def test_dnsmasq_dns(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.data[DNSMASQ]["dnsmasq"] = {
        "enable": "1",
        "port": "5353",
        "interface": {"lan": {"value": "LAN", "selected": 1}, "opt1": {"value": "IoT"}},
        "hosts": {
            "h1": {"host": "printer", "domain": "home.example", "ip": "192.0.2.50,2001:db8:1::50"},
            "h2": {"host": "", "domain": "", "ip": "192.0.2.51"},
        },
    }
    _, dnsmasq = (await observe(adapter(http_url))).dns_services
    assert dnsmasq.id == "fw/dns/dnsmasq" and dnsmasq.port == 5353 and dnsmasq.enabled
    assert [str(a) for a in dnsmasq.listen] == ["192.0.2.1", "2001:db8:1::1"]
    assert [(h.name, str(h.address)) for h in dnsmasq.host_records] == [
        ("printer.home.example", "192.0.2.50"),
        ("printer.home.example", "2001:db8:1::50"),
    ]
    assert dnsmasq.forwarders == [] and "system" in str(dnsmasq.vendor_extra["upstream"])
    sim.data[DNSMASQ]["dnsmasq"]["port"] = ""  # default port: dnsmasq answers on 53
    sim.data[UNBOUND]["unbound"]["general"]["port"] = "53530"
    services = (await observe(adapter(http_url))).dns_services
    assert [(d.id, d.port) for d in services] == [("fw/dns/unbound", 53530), ("fw/dns/dnsmasq", 53)]
    sim.data[DNSMASQ]["dnsmasq"]["enable"] = "0"
    assert [d.id for d in (await observe(adapter(http_url))).dns_services] == [
        "fw/dns/unbound",
        "fw/dns/port-53",
    ]
    sim.fail = {DNSMASQ: 403}  # no privilege for dnsmasq: not read
    assert len((await observe(adapter(http_url))).dns_services) == 2
    sim.fail = {}
    del sim.data[DNSMASQ]  # not installed
    sim.data[UNBOUND]["unbound"]["general"]["enabled"] = "0"
    assert [d.id for d in (await observe(adapter(http_url))).dns_services] == ["fw/dns/unbound"]


async def test_clients(snap: Snapshot) -> None:
    by_mac = {c.mac: c for c in snap.clients}
    assert sorted(by_mac) == [
        "00:00:5e:00:53:10",
        "00:00:5e:00:53:20",
        "00:00:5e:00:53:30",
        "02:00:00:00:00:21",
        "02:00:00:00:00:22",
        "02:00:00:00:00:31",
    ]  # not the firewall's own MAC, not "(incomplete)"
    printer = by_mac["00:00:5e:00:53:10"]
    assert [str(a) for a in printer.addresses] == ["192.0.2.10", "2001:db8:1::10"]
    assert printer.hostname == "printer.home.example"
    assert printer.segment_id == "home/segment/native" and printer.seen_on == port_id("fw", "igb0")
    assert by_mac["00:00:5e:00:53:20"].segment_id == "home/segment/20"
    assert by_mac["02:00:00:00:00:21"].hostname == "laptop"  # from the Kea lease
    laptop = by_mac["02:00:00:00:00:21"]
    assert set(laptop.address_sources.values()) == {AddressSource.DHCP}  # #183
    assert set(laptop.address_sources) <= set(laptop.addresses)
    assert by_mac["02:00:00:00:00:31"].segment_id == "home/segment/30"


# --- refused paths ---------------------------------------------------------------------------


async def test_wrong_key(http_url: str) -> None:
    snap = await observe(adapter(http_url, secret="wrong"))
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert "refused the credentials (HTTP 401)" in snap.errors[0].message


async def test_certificate_not_pinned(
    https_url: str, tls: TlsFiles, sim: OpnsenseSimulator
) -> None:
    snap = await observe(adapter(https_url))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert tls.fingerprint in snap.errors[0].message and "not yet trusted" in snap.errors[0].message
    assert sim.requests == []  # nothing, credentials included, was sent


async def test_pin_mismatch(https_url: str, sim: OpnsenseSimulator) -> None:
    snap = await observe(adapter(https_url, pin="ab" * 32))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert "new certificate" in snap.errors[0].message and sim.requests == []


async def test_pin_in_colon_notation(https_url: str, tls: TlsFiles) -> None:
    pin = ":".join(tls.fingerprint[i : i + 2] for i in range(0, 64, 2)).upper()
    assert (await observe(adapter(https_url, pin=pin))).status is DeviceStatus.OK


async def test_certificate_swapped_after_probe(
    https_url: str, tmp_path: Path, sim: OpnsenseSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The probe sees another certificate than the request connection: the handshake of the
    # request fails, so the credentials never reach the server.
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


async def test_tls_to_a_plain_http_server(http_url: str) -> None:
    snap = await observe(adapter(http_url.replace("http://", "https://")))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "cannot open a TLS connection" in snap.errors[0].message


async def test_tls_handshake_timeout() -> None:
    with socket.socket() as silent:  # accepts TCP (backlog) but never speaks TLS
        silent.bind(("127.0.0.1", 0))
        silent.listen()
        port = silent.getsockname()[1]
        with pytest.raises(Unreachable, match=r"no TLS answer within 0\.3 s"):
            await https_mod.peer_certificate("127.0.0.1", port, 0.3)
        snap = await observe(adapter(f"https://127.0.0.1:{port}", timeout=0.3))
    assert snap.status is DeviceStatus.UNREACHABLE


async def test_timeout(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.delay = 1.0
    snap = await observe(adapter(http_url, timeout=0.2))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "within 0.2 s" in snap.errors[0].message


async def test_request_timeout_message(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.delay = 1.0
    http = DeviceHttp(
        http_url, pinned_fingerprint=None, timeout=0.2, auth=(KEY, SECRET), allow_insecure_http=True
    )
    with pytest.raises(Unreachable, match=r"no answer within 0\.2 s"):
        await http.get_json(FIRMWARE)
    await http.close()


async def test_api_disabled(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.api_enabled = False
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "is the API enabled?" in snap.errors[0].message


async def test_malformed_json_is_partial(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.malformed = {ARP}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert [(e.capability, e.message) for e in snap.errors] == [
        ("clients", f"{ARP}: answer is not valid JSON")
    ]
    assert snap.subnets and snap.dhcp_servers and not snap.clients


async def test_missing_privilege_and_server_error(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.fail = {UNBOUND: 403, HOST_OVERRIDES: 500}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert "access denied (HTTP 403)" in snap.errors[0].message
    sim.fail = {UNBOUND: 500}
    snap = await observe(adapter(http_url))
    assert snap.errors[0].message == f"{UNBOUND}: HTTP 500 Internal Server Error"


@pytest.mark.parametrize(
    ("path", "value", "capability", "needle"),
    [
        (VLANS, "nonsense", "dhcp", f"unexpected answer from {VLANS}: no list of rows"),
        (FIRMWARE, {"product": {}}, "system", "no product_version"),
        (FIRMWARE, [], "system", "the answer is list, expected an object"),
        (KEA, {"dhcpv4": None}, "dhcp", "dhcpv4 is NoneType"),
        (UNBOUND, {"unbound": []}, "dns", "unbound is list"),
        (ISC_STATUS, "running", "dhcp", ISC_STATUS),
    ],
)
async def test_unexpected_shapes(
    http_url: str,
    sim: OpnsenseSimulator,
    path: str,
    value: Any,
    capability: str,
    needle: str,
) -> None:
    sim.data[path] = value
    snap = await observe(adapter(http_url))
    errors = {e.capability: e.message for e in snap.errors}
    assert needle in errors[capability]


async def test_optional_components_absent(http_url: str, sim: OpnsenseSimulator) -> None:
    for path in (KEA, KEA_LEASES, ISC_STATUS, ISC_LEASES):
        del sim.data[path]
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK
    assert snap.dhcp_servers == [] and len(snap.clients) == 3


async def test_isc_disabled_and_stopped(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.data[ISC_STATUS] = {"status": "disabled"}
    snap = await observe(adapter(http_url))
    assert not any(s.id.endswith("isc-opt2") for s in snap.dhcp_servers)
    sim.data[ISC_STATUS] = {"status": "stopped"}
    snap = await observe(adapter(http_url))
    assert not next(s for s in snap.dhcp_servers if s.id.endswith("isc-opt2")).enabled


async def test_kea_first_isc_fallback(http_url: str, sim: OpnsenseSimulator) -> None:
    """ISC lists only the interfaces no enabled Kea server serves (#242)."""
    general = sim.data[KEA]["dhcpv4"]["general"]
    general["interfaces"] = {**general["interfaces"], "opt2": {"value": "Guest", "selected": 1}}
    sim.data[KEA]["dhcpv4"]["subnets"]["subnet4"]["s-guest"] = {
        "subnet": "203.0.113.0/24",
        "pools": "203.0.113.100-203.0.113.199",
    }
    snap = await observe(adapter(http_url))
    ids = {s.id for s in snap.dhcp_servers}
    assert "fw/dhcp/kea-opt2" in ids and "fw/dhcp/isc-opt2" not in ids
    general["enabled"] = "0"
    snap = await observe(adapter(http_url))
    isc = next(s for s in snap.dhcp_servers if s.id == "fw/dhcp/isc-opt2")
    assert isc.enabled and isc.vendor_extra["server"] == "isc"


async def test_odd_data_is_tolerated(http_url: str, sim: OpnsenseSimulator) -> None:
    rows = sim.data[INTERFACES]["rows"]
    rows += [
        {"device": "vlan99", "identifier": "opt9", "vlan_tag": 99},  # VLAN without table entry
        {"device": "bridge0", "identifier": "opt3", "ipv4": ["bad", "192.0.2.129/25"]},
        {"device": "ghost0", "identifier": "opt4"},  # assigned, but no port row
        {"no": "device"},
        "not a row",
    ]
    rows[0]["ipv6"].append({"ipaddr": "fe80::2%igb0/64"})
    rows[1]["media"] = "10Gbase-T <half-duplex>"
    rows[1]["enabled"] = False  # the WAN switched off, but its device is up (VLANs on it)
    rows[4]["enabled"] = False  # unassigned: no enable setting of its own
    sim.data[VLANS]["rows"] += [
        {"vlanif": "vlan05", "if": "igb9", "tag": "50"},  # parent unknown: segment, no member
        {"vlanif": "vlan06", "if": "igb0", "tag": "abc"},
        {"vlanif": "vlan07", "if": "igb0", "tag": "0"},
        {"vlanif": "vlan08", "if": "igb2", "tag": "20"},  # VLAN 20 on a second port
    ]
    rows.append({"device": "vlan08", "identifier": "opt5", "description": "IoT2"})
    kea = sim.data[KEA]["dhcpv4"]
    kea["subnets"]["subnet4"]["s-x"] = {"subnet": "not a subnet"}
    kea["subnets"]["subnet4"]["s-y"] = {"subnet": "203.0.113.0/24", "pools": "x-y\n"}
    kea["subnets"]["subnet4"]["s-z"] = {"subnet": "192.0.2.128/25", "pools": "192.0.2.128/30"}
    kea["subnets"]["subnet4"]["s-v"] = {"subnet": "192.0.2.0/25"}  # second one on the LAN
    kea["subnets"]["subnet4"]["s-w"] = {"subnet": "2001:db8:42::/64"}  # on no interface
    kea["reservations"]["reservation"]["r-3"] = {"hw_address": "nonsense", "ip_address": "x"}
    kea["reservations"]["reservation"]["r-4"] = {
        "subnet": "203.0.113.0/24",
        "ip_address": "203.0.113.5",
        "hw_address": "02-00-00-00-00-05",
    }
    sim.data[ISC_LEASES]["rows"] += [{"if": "opt99"}, {"if": "wan"}]
    sim.data[UNBOUND]["unbound"]["general"] = {"enabled": "1", "active_interface": "lan"}
    sim.data[HOST_OVERRIDES]["rows"].append(
        {"hostname": "*", "domain": "wild.example", "server": "192.0.2.12"}
    )
    sim.data[ARP].append({"mac": "02:00:00:00:00:77", "ip": "203.0.113.77", "intf": "unknown"})
    sim.data[KEA_LEASES] = {"rows": [{"hwaddr": "02:00:00:00:00:78", "address": "2001:db8:99::9"}]}

    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors
    ports = {p.name: p for p in snap.ports}
    assert "vlan99" not in ports and ports["bridge0"].kind.value == "bridge"
    assert (ports["igb1"].speed_mbps, ports["igb1"].full_duplex) == (10000, False)
    assert ports["igb1"].admin_up is None and ports["igb2"].admin_up is None
    segs = {s.id: s for s in snap.segments}
    assert [m.port_id for m in segs["home/segment/20"].members] == [
        port_id("fw", "igb0"),
        port_id("fw", "igb2"),
    ]
    assert segs["home/segment/20"].name == "IoT"
    assert segs["home/segment/50"].members == [] and "home/segment/opt3" in segs
    servers = {s.id: s for s in snap.dhcp_servers}
    assert "fw/dhcp/kea-lan-192.0.2.0" in servers
    assert servers["fw/dhcp/kea-opt2"].pools == [] and not servers["fw/dhcp/kea-opt2"].enabled
    assert servers["fw/dhcp/kea-opt2"].reservations[0].mac == "02:00:00:00:00:05"
    z = servers["fw/dhcp/kea-opt3"].pools[0]
    assert (str(z.start), str(z.end)) == ("192.0.2.129", "192.0.2.130")
    (dns,) = snap.dns_services
    assert [str(a) for a in dns.listen] == ["192.0.2.1", "2001:db8:1::1"]
    assert ("wild.example", ip_address("192.0.2.12")) in [
        (h.name, h.address) for h in dns.host_records
    ]
    by_mac = {c.mac: c for c in snap.clients}
    assert by_mac["02:00:00:00:00:77"].segment_id == "home/segment/30"  # found by address
    assert by_mac["02:00:00:00:00:78"].segment_id is None


# --- config and helpers ----------------------------------------------------------------------


def test_config_validation() -> None:
    def cfg(url: str, insecure: bool = False) -> OpnsenseConfig:
        return OpnsenseConfig(
            url=url, api_key=SecretStr("k"), api_secret=SecretStr("s"), allow_insecure_http=insecure
        )

    assert cfg("https://192.0.2.1:8443/").url == "https://192.0.2.1:8443"
    assert cfg("http://192.0.2.1", insecure=True).allow_insecure_http
    with pytest.raises(ValidationError, match="allow_insecure_http"):
        cfg("http://192.0.2.1")
    with pytest.raises(ValidationError, match="device's address"):
        cfg("ftp://192.0.2.1")
    schema = OpnsenseConfig.model_json_schema()
    assert schema["properties"]["api_secret"]["format"] == "password"


def test_device_http_refuses_bad_urls() -> None:
    with pytest.raises(AdapterError, match="not an http"):
        DeviceHttp("192.0.2.1", pinned_fingerprint=None, timeout=1)
    with pytest.raises(AdapterError, match="plain http sends credentials"):
        DeviceHttp("http://192.0.2.1", pinned_fingerprint=None, timeout=1)
    assert DeviceHttp("https://192.0.2.1", pinned_fingerprint=None, timeout=1).port == 443
    assert normalise_fingerprint("AB:cd") == "abcd"


async def test_device_http_post_and_errors(http_url: str, sim: OpnsenseSimulator) -> None:
    http = DeviceHttp(
        http_url, pinned_fingerprint=None, timeout=5, auth=(KEY, SECRET), allow_insecure_http=True
    )
    assert (await http.post_json(ISC_STATUS, {}))["status"] == "running"
    with pytest.raises(NotFound):
        await http.get_json("/api/nothing")
    sim.fail = {FIRMWARE: 403}
    with pytest.raises(AuthFailed, match="privileges"):
        await http.get_json(FIRMWARE)
    await http.close()
    await http.close()  # idempotent


def test_parsing_helpers() -> None:
    assert (
        _selected(["a", 1]) == ["a"] and _selected(None) == [] and _selected("a, b") == ["a", "b"]
    )
    assert _int(True) is None and _int(5) == 5 and _int("x") is None
    assert list(_items([{"a": 1}, "x"])) == [("0", {"a": 1})] and list(_items(None)) == []
    assert _addrs(["192.0.2.1", "nope"]) == [ip_address("192.0.2.1")]
    one = _pool("192.0.2.7/32")
    assert one is not None and one.start == one.end == ip_address("192.0.2.7")
    assert _pool("nope") is None
    assert _speed("100baseTX <full-duplex>") == (100, True)
    assert max_speed("1000baseT") is None and max_speed(["autoselect", 5]) is None
    phys = {"is_physical": True}
    assert media_of({**phys, "media": "100baseTX <full-duplex>"}) is PortMedia.COPPER
    assert media_of({**phys, "supported_media": ["1000baseSX", "1000baseLX"]}) is PortMedia.SFP
    assert media_of({**phys, "media": "1000baseKX"}) is None  # backplane: no medium of ours
    assert media_of({"media": "1000baseT"}) is None and media_of(phys) is None
    assert autoneg_of("Ethernet 100baseTX <full-duplex>") is False and autoneg_of(None) is None
    with pytest.raises(AdapterError, match="no list of rows"):
        _rows({"rows": None}, "/x")
    assert ip_interface("192.0.2.1/24")  # sanity: documentation prefixes only


async def test_close_without_observing(http_url: str) -> None:
    await adapter(http_url).close()
    await asyncio.sleep(0)


@pytest.mark.parametrize("header", ["Bearer x", "Basic !!!", "Basic //8="])
async def test_simulator_rejects_odd_auth(http_url: str, header: str) -> None:
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.get(http_url + FIRMWARE, headers={"Authorization": header})
    assert response.status_code == 401


# --- health and time (#178, #179) ------------------------------------------------------------


async def test_health(snap: Snapshot) -> None:
    h = snap.device.health
    assert h is not None
    assert (h.uptime_seconds, h.load_average, h.cpu_count) == (273906, (0.13, 0.07, 0.04), 4)
    assert h.memory_total_bytes == 4277690368
    assert h.memory_used_bytes == 1015021568 - 209715200  # the ZFS ARC is cache
    assert [(s.name, s.kind.value, s.total_bytes, s.used_bytes) for s in h.storage] == [
        ("/", "system", 27917287424, 1932735283),
        ("/var/log", "data", 26038288384, 53736243),
        ("/tmp", "temporary", 2138845184, 266240),
        ("/boot/efi", "other", 272629760, 1363148),
    ]
    assert [(t.name, t.value_c) for t in h.temperatures] == [
        ("dev.cpu.0.temperature", 47),
        ("dev.cpu.1.temperature", 45),
    ]
    assert h.cpu_load_pct is None  # only as an event stream: not read


async def test_time(snap: Snapshot) -> None:
    t = snap.device.time
    assert t is not None and t.clock is not None and t.read_at is not None
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 2
    zone = datetime.now(ZoneInfo("Europe/Berlin")).utcoffset()
    assert zone is not None and t.utc_offset_minutes == zone.total_seconds() // 60
    assert t.clock.utcoffset() == zone
    assert t.timezone is None and t.ntp_server is None  # not in the API
    assert t.ntp_client == NtpClient(
        enabled=True,
        servers=["203.0.113.123", "198.51.100.123", "0.opnsense.pool.ntp.org"],
        synchronised=True,
        stratum=1,
        current_server="203.0.113.123",
    )
    iot = next(s for s in snap.dhcp_servers if s.segment_id == "home/segment/20")
    assert iot.ntp_servers == [ip_address("198.51.100.1")]
    lan = next(s for s in snap.dhcp_servers if s.segment_id == "home/segment/native")
    assert lan.ntp_servers == [ip_address("192.0.2.1")]  # autocollect: the interface address


async def test_time_without_ntpd_and_unsynchronised(http_url: str, sim: OpnsenseSimulator) -> None:
    rows = sim.data[NTP_STATUS]["rows"]
    for row in rows:
        row["status"] = " "
    sim.timezone = "UTC"
    t = (await observe(adapter(http_url))).device.time
    assert t is not None and t.utc_offset_minutes == 0 and t.ntp_client is not None
    assert t.ntp_client.synchronised is False and t.ntp_client.current_server is None
    sim.data[NTP_STATUS] = {"rows": []}
    t = (await observe(adapter(http_url))).device.time
    assert t is not None and t.ntp_client == NtpClient(enabled=False)
    del sim.data[NTP_STATUS]
    t = (await observe(adapter(http_url))).device.time
    assert t is not None and t.ntp_client is None and t.clock is not None


async def test_health_and_time_need_the_dashboard_privilege(
    http_url: str, sim: OpnsenseSimulator
) -> None:
    sim.fail = {SYSTEM_TIME: 403, NTP_STATUS: 403}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    errors = {e.capability: e.message for e in snap.errors}
    assert set(errors) == {"health", "time"}
    assert all("check the user's privileges" in m for m in errors.values())
    sim.fail = {NTP_STATUS: 403}
    snap = await observe(adapter(http_url))
    assert [e.capability for e in snap.errors] == ["time"] and snap.device.health


async def test_health_of_odd_answers(http_url: str, sim: OpnsenseSimulator) -> None:
    sim.data[SYSTEM_TEMPERATURE] = []
    sim.data["/api/diagnostics/system/system_resources"] = {"memory": {"used": "N/A"}}
    sim.data["/api/diagnostics/system/system_disk"] = []
    del sim.data[CPU_TYPE]
    sim.data[SYSTEM_TIME] = {**sim.data[SYSTEM_TIME], "uptime": "00:00:09", "loadavg": "N/A"}
    h = (await observe(adapter(http_url))).device.health
    assert h is not None and h.uptime_seconds == 9 and h.load_average is None
    assert h.memory_total_bytes is None and h.memory_used_bytes is None
    assert h.storage == h.temperatures == [] and h.cpu_count is None
    sim.data[SYSTEM_TEMPERATURE] = {"not": "a list"}
    snap = await observe(adapter(http_url))
    assert "system_temperature" in {e.capability: e.message for e in snap.errors}["health"]
    sim.data[SYSTEM_TIME] = []
    snap = await observe(adapter(http_url))
    assert {e.capability for e in snap.errors} == {"health", "time"}
    sim.malformed = {SYSTEM_TIME}
    snap = await observe(adapter(http_url))
    assert "not valid JSON" in {e.capability: e.message for e in snap.errors}["time"]


def test_health_and_time_helpers() -> None:
    assert vitals.uptime("1 day, 00:00:01") == 86401 and vitals.uptime("3 days, 04:05:06")
    assert vitals.uptime("soon") is None and vitals.uptime(None) is None
    assert vitals.load_average("1, 2") is None and vitals.load_average("-1, 0, 0") is None
    assert vitals.cpu_count(["x (1 cores, 2 threads)"]) == 2 and vitals.cpu_count([]) is None
    assert vitals.cpu_count("x (1 core, 0 threads)") is None
    assert vitals.local_time("Sun Nov 22 17:12:00 CET 2026") == datetime(2026, 11, 22, 17, 12)
    assert vitals.local_time("Sun Nov 22 17:12:00 2026") is None
    assert vitals.local_time("Sun Nox 22 17:12:00 CET 2026") is None
    assert vitals.http_date("Sun, 22 Nov 2026 16:12:00 GMT") == datetime(
        2026, 11, 22, 16, 12, tzinfo=UTC
    )
    assert vitals.http_date(None) is None and vitals.http_date("yesterday") is None
    assert vitals.http_date("Sun, 22 Nov 2026 16:12:00 -0000") is None  # no zone
    start = datetime(2026, 11, 22, 16, 12, tzinfo=UTC)
    head = "Sun, 22 Nov 2026 16:12:00 GMT"
    odd = vitals.time_of({"datetime": "Sun Nov 22 16:19:00 X 2026"}, head, None, start, start)
    assert odd.utc_offset_minutes is None and odd.offset_seconds() == 0.5  # 7 min: no zone
    india = vitals.time_of({"datetime": "Sun Nov 22 21:42:00 IST 2026"}, head, None, start, start)
    assert india.utc_offset_minutes == 330
    none = vitals.time_of({}, None, [{"server": ""}, "x"], start, start)
    assert none.clock is None and none.ntp_client == NtpClient(enabled=False)
    assert (
        vitals.health_of({}, {"memory": {"total": 10, "used": 50}}, {}, [], None).memory_used_bytes
        == 10
    )
    disks = {
        "devices": [
            {"mountpoint": "/", "total_bytes": 0},
            {"mountpoint": "", "total_bytes": 5},
            "x",
        ]
    }
    assert (
        vitals.health_of({}, {}, disks, [{"device": "", "temperature": "1"}, 5], None).storage == []
    )
    assert (
        vitals.health_of({}, {}, {"devices": [{"mountpoint": "/", "total_bytes": 9}]}, [], None)
        .storage[0]
        .used_bytes
        is None
    )


# --- management services (#173) --------------------------------------------------------------


async def test_services(snap: Snapshot) -> None:
    by = {s.id: s for s in snap.services}
    assert sorted(by) == ["fw/service/snmp", "fw/service/webgui"]
    web = by["fw/service/webgui"]  # the plain-HTTP simulator
    assert (web.kind.value, web.enabled, web.encrypted) == ("http", True, False)
    snmp = by["fw/service/snmp"]
    assert snmp.enabled and snmp.port == 161 and snmp.name == "net-snmp"
    assert [str(a) for a in snmp.listen] == ["192.0.2.1"]  # the unselected one is not listened on
    assert snmp.snmp is not None and snmp.snmp.default_community
    assert [v.value for v in snmp.snmp.versions] == ["2c"]
    assert snap.device.transport_encrypted is False


async def test_services_without_the_plugin_or_privilege(http_url: str, sim: Any) -> None:
    del sim.data["/api/netsnmp/general/get"]  # os-net-snmp not installed
    snap = await observe(adapter(http_url))
    assert [s.name for s in snap.services] == ["webgui"]
    sim.fail["/api/netsnmp/general/get"] = 403
    snap = await observe(adapter(http_url))
    assert [s.name for s in snap.services] == ["webgui"] and not snap.errors


async def test_never_downloads_the_backup(http_url: str, sim: Any) -> None:
    await observe(adapter(http_url))
    assert not [p for p in sim.requests if "backup" in p], sim.requests


async def test_tls_web_interface(https_url: str, tls: TlsFiles) -> None:
    snap = await observe(adapter(https_url, pin=tls.fingerprint))
    web = next(s for s in snap.services if s.name == "webgui")
    assert (web.kind.value, web.encrypted) == ("https", True)


# --- WireGuard (#239) ------------------------------------------------------------------------


async def test_wireguard_tunnel_and_peers(snap: Snapshot) -> None:
    (t,) = snap.tunnels
    assert (t.id, t.name, t.description, t.port_id) == (
        "fw/tunnel/wg0",
        "wg0",
        "s2s",
        "fw/port/wg0",
    )
    assert (t.up, t.listen_port, t.mtu, t.public_key) == (True, 51820, 1420, WG_KEY)
    assert [str(a) for a in t.addresses] == ["2001:db8:ff::1/128"]
    site_b, phone = t.peers
    assert (site_b.name, site_b.public_key) == ("site-b", WG_SITE_B)
    assert (site_b.endpoint_host, site_b.endpoint_port) == ("2001:db8:ffff:20::1", 51820)
    assert [str(n) for n in t.remote_networks(site_b)] == ["2001:db8:20::/64"]
    assert (site_b.rx_bytes, site_b.tx_bytes, site_b.keepalive_seconds) == (1834567, 2934871, 25)
    age = site_b.handshake_age(datetime.now(UTC))
    assert age is not None and 40 <= age < 600
    assert (phone.name, phone.public_key, phone.endpoint_host) == ("phone", WG_PHONE, None)
    assert (phone.latest_handshake, phone.keepalive_seconds) == (None, 0)
    assert t.site_peers() == [site_b]


async def test_wireguard_needs_its_privilege(http_url: str, sim: Any) -> None:
    sim.fail[WG_SHOW] = 403
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL and snap.tunnels == []
    (err,) = snap.errors
    assert err.capability == "vpn" and "HTTP 403" in err.message


async def test_wireguard_without_the_interface_overview(http_url: str, sim: Any) -> None:
    sim.fail[INTERFACES] = 403
    snap = await observe(adapter(http_url))
    (t,) = snap.tunnels
    assert (t.addresses, t.port_id, t.up) == ([], None, True)
    assert "vpn" not in {e.capability for e in snap.errors}


async def test_wireguard_not_in_use(http_url: str, sim: Any) -> None:
    sim.data[WG_SHOW] = {"total": 0, "rowCount": 0, "current": 1, "rows": []}
    assert (await observe(adapter(http_url))).tunnels == []


def test_wireguard_records_are_parsed_defensively() -> None:
    rows: list[dict[str, Any]] = [
        {"type": "peer", "public-key": WG_KEY},  # no interface name
        {"if": "wg1", "type": "peer", "public-key": "not a key"},
        {
            "if": "wg1",
            "type": "peer",
            "public-key": WG_SITE_B,
            "endpoint": "198.51.100.9:x",
            "allowed-ips": "(none)",
            "latest-handshake": "0",
            "persistent-keepalive": "",
        },
        {"if": "wg1", "type": "peer", "public-key": WG_SITE_B},  # twice
        {
            "if": "wg1",
            "type": "peer",
            "public-key": WG_PHONE,
            "endpoint": "203.0.113.4:51820",
            "allowed-ips": "192.0.2.7/32, bad, 198.51.100.0/24",
        },
        {"if": "wg1", "type": "something"},
    ]
    (t,) = wireguard_tunnels(rows, "fw", {"wg1": {"status": "down", "mtu": "9"}})
    assert (t.public_key, t.up, t.mtu, t.listen_port, t.description) == (
        None,
        False,
        None,
        None,
        None,
    )
    a, b = t.peers
    assert (a.endpoint_host, a.endpoint_port, a.allowed_ips, a.keepalive_seconds) == (
        "198.51.100.9:x",
        None,
        [],
        None,
    )
    assert (b.endpoint_host, b.endpoint_port) == ("203.0.113.4", 51820)
    assert [str(n) for n in b.allowed_ips] == ["192.0.2.7/32", "198.51.100.0/24"]


def test_wireguard_endpoints() -> None:
    assert _endpoint("(none)") == (None, None)
    assert _endpoint("") == (None, None)
    assert _endpoint("[2001:db8::1]:51820") == ("2001:db8::1", 51820)
    assert _endpoint("site.example:70000") == ("site.example:70000", None)
    assert _endpoint("vpn.example") == ("vpn.example", None)


# --- log and flow targets (#180) -------------------------------------------------------------


async def test_log_targets(snap: Snapshot) -> None:
    rows = [
        (t.kind.value, t.endpoint(), t.transport.value, t.enabled, t.name)
        for t in snap.device.log_targets or []
    ]
    assert rows == [
        ("syslog", "192.0.2.5:514", "udp", True, "collector"),
        ("netflow", "192.0.2.5:2055", "udp", False, "netflow"),  # on no interface
    ]
    assert snap.device.log_targets is not None and "info" in snap.device.log_targets[0].topics


async def test_log_targets_shapes_and_refusals(sim: OpnsenseSimulator, http_url: str) -> None:
    rows = sim.data["/api/syslog/settings/search_destinations"]["rows"]
    rows[0] |= {"transport": "TLS(6)", "hostname": "2001:db8::5", "port": "6514", "enabled": "0"}
    rows.append({"hostname": "", "transport": "tcp4"})
    rows.append({"hostname": "logs.home.example", "transport": "tcp4", "port": "x"})
    capture = sim.data["/api/diagnostics/netflow/getconfig"]["netflow"]["capture"]
    capture["interfaces"] = "lan"
    capture["targets"] = "127.0.0.1:2056,[2001:db8::6]:2055"
    a = adapter(http_url)
    try:
        snap = await a.observe()
        got = [(t.endpoint(), t.transport.value, t.enabled) for t in snap.device.log_targets or []]
        assert got == [
            ("[2001:db8::5]:6514", "tls", False),
            ("logs.home.example:514", "tcp", True),
            ("[2001:db8::6]:2055", "udp", True),
        ]
        sim.fail = {"/api/diagnostics/netflow/getconfig": 403}
        snap = await a.observe()
        assert [t.kind.value for t in snap.device.log_targets or []] == ["syslog", "syslog"]
        (gap,) = snap.errors
        assert (
            gap.optional
            and gap.remedy == "privileges"
            and "page-diagnostics-netflow" in (gap.fix or "")
        )
        sim.fail = {"/api/syslog/settings/search_destinations": 403}
        snap = await a.observe()
        assert snap.device.log_targets is None and snap.status.value == "ok"
        sim.fail = {"/api/syslog/settings/search_destinations": 404}
        snap = await a.observe()
        assert [t.kind.value for t in snap.device.log_targets or []] == ["netflow"]
    finally:
        await a.close()


# --- accounts (#175) -------------------------------------------------------------------------


async def test_accounts_only_with_a_key_that_can_read_the_user_manager(
    sim: OpnsenseSimulator, http_url: str
) -> None:
    from signalbox.model import AccountPrivilege

    sim.accounts.users.append(
        {
            "uuid": "11111111-0000-4000-8000-000000000000",
            "name": "signalbox",
            "scope": "user",
            "descr": "",
            "priv": ["page-status-interfaces"],
            "groups": [],
        }
    )
    sim.accounts.users.append(
        {"uuid": "", "name": "nouuid", "scope": "user", "descr": "", "priv": [], "groups": []}
    )
    sim.accounts.keys.append({"id": "k1", "key": KEY, "secret": "x", "username": "root"})
    a = adapter(http_url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    by = {x.name: x for x in snap.device.accounts or []}
    assert by["root"].privilege is AccountPrivilege.ADMIN and by["root"].is_signalbox
    assert by["signalbox"].privilege is AccountPrivilege.WRITE
    assert by["nouuid"].privilege is AccountPrivilege.OTHER
    dev = snap.device
    assert dev.signalbox_account_privilege is AccountPrivilege.ADMIN
    assert dev.signalbox_account_needed is AccountPrivilege.WRITE
    assert dev.default_credentials is None
    sim.fail = {"/api/auth/user/search": 403}
    a = adapter(http_url)
    snap = await observe(a)
    assert snap.device.accounts is None and snap.device.signalbox_account_privilege is None
    # not readable (None) is not "no accounts" ([]): an optional gap names the privilege (#349)
    (gap,) = [e for e in snap.errors if e.message.startswith("accounts")]
    assert gap.optional and gap.message_id == "opnsense.accounts" and snap.status.value == "ok"
    assert "page-system-usermanager" in (gap.fix or "") and "every account" in (gap.fix or "")
    assert gap.remedy is None  # Fix it never hands out the user manager by itself
    # an OPNsense without the user manager API has nothing to report
    sim.fail = {"/api/auth/user/search": 404}
    a = adapter(http_url)
    snap = await observe(a)
    assert snap.device.accounts is None and not [
        e for e in snap.errors if e.message.startswith("accounts")
    ]
    # a key that may read it, with nobody listed: an empty list, no gap
    sim.fail = {}
    sim.accounts.users.clear()
    a = adapter(http_url)
    snap = await observe(a)
    assert snap.device.accounts == [] and not snap.errors


async def test_host_overrides_of_25_1(http_url: str, sim: OpnsenseSimulator) -> None:
    """#386: 25.1 knows ``searchHostOverride`` only, with ``address`` for the target and a
    label in ``rr``; both spellings and shapes are read."""
    sim.camel_only = {HOST_OVERRIDES, HOST_ALIASES}
    sim.data[HOST_OVERRIDES]["rows"] = [
        {
            "uuid": "h-9",
            "enabled": "1",
            "hostname": "old",
            "domain": "split.example",
            "rr": "A (IPv4 address)",
            "address": "192.0.2.77",
        },
    ]
    sim.data[HOST_ALIASES]["rows"] = [
        {
            "uuid": "a-9",
            "enabled": "1",
            "host": "h-9",
            "hostname": "older",
            "domain": "split.example",
        }
    ]
    (dns,) = (await observe(adapter(http_url))).dns_services
    assert dns.host_records_read
    assert [(h.name, str(h.address), h.source) for h in dns.host_records] == [
        ("old.split.example", "192.0.2.77", "host-override"),
        ("older.split.example", "192.0.2.77", "alias"),
    ]


async def test_host_overrides_refused_is_a_gap_not_none(
    http_url: str, sim: OpnsenseSimulator
) -> None:
    sim.fail = {HOST_OVERRIDES: 403}
    snap = await observe(adapter(http_url))
    (dns,) = snap.dns_services
    assert dns.host_records == [] and not dns.host_records_read
    (gap,) = [e for e in snap.errors if e.message.startswith("DNS host overrides")]
    assert gap.optional and "page-services-unbound" in (gap.fix or "")
    assert snap.status.value == "ok"


async def test_host_overrides_missing_on_both_spellings(
    http_url: str, sim: OpnsenseSimulator
) -> None:
    del sim.data[HOST_OVERRIDES]
    snap = await observe(adapter(http_url))
    (dns,) = snap.dns_services
    assert not dns.host_records_read
    assert any(e.message.startswith("DNS host overrides") and e.optional for e in snap.errors)


async def test_registered_dhcp_names(http_url: str, sim: OpnsenseSimulator) -> None:
    """#386: with "Register DHCP static mappings" and "Register DHCP leases" on, the names of
    reservations and active leases are host records with their source."""
    general = sim.data[UNBOUND]["unbound"]["general"]
    general |= {"regdhcpstatic": "1", "regdhcp": "0", "regdhcpdomain": "lan.example"}
    (dns,) = (await observe(adapter(http_url))).dns_services
    got = {(h.name, str(h.address), h.source) for h in dns.host_records}
    assert ("printer.lan.example", "192.0.2.10", "dhcp-static") in got
    assert ("kiosk.lan.example", "203.0.113.10", "dhcp-static") in got
    assert not any(h.source == "dhcp-lease" for h in dns.host_records)
    general["regdhcp"] = "1"
    (dns,) = (await observe(adapter(http_url))).dns_services
    got = {(h.name, str(h.address), h.source) for h in dns.host_records}
    assert ("guest-phone.lan.example", "203.0.113.150", "dhcp-lease") in got
    assert sum(h.name == "kiosk.lan.example" for h in dns.host_records) == 1


async def test_many_host_overrides_are_read_completely(
    http_url: str, sim: OpnsenseSimulator
) -> None:
    """#386: a long split-DNS list is paged; a capped answer (``rowCount=-1`` honoured only up to
    100 rows) is completed page by page."""
    sim.page_limit = 100
    sim.data[HOST_OVERRIDES]["rows"] = [
        {
            "uuid": f"o-{i}",
            "enabled": "1",
            "hostname": f"host{i}",
            "domain": "split.example",
            "rr": "A",
            "server": f"203.0.113.{i % 250 + 1}",
        }
        for i in range(450)
    ]
    (dns,) = (await observe(adapter(http_url))).dns_services
    names = [h.name for h in dns.host_records if h.source == "host-override"]
    assert len(names) == 450 and len(set(names)) == 450


async def test_config_history_and_channel(snap: Snapshot) -> None:
    """Revisions of the configuration history and the update channel (#181)."""
    d = snap.device
    assert d.local_backups is not None and (d.local_backups.count or 0) >= 1
    assert d.local_backups.automatic is True
    assert d.config_state is not None and d.config_state.revision
    assert d.firmware is not None and d.firmware.channel is not None
    assert d.firmware.channel.value == "stable" and d.firmware.reboot_pending is False
