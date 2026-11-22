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
    FIRMWARE,
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
    OpnsenseAdapter,
    OpnsenseConfig,
    _addrs,
    _int,
    _items,
    _pool,
    _rows,
    _selected,
    _speed,
    vitals,
)
from signalbox.model import DeviceRole, DeviceStatus, Membership, NtpClient, Snapshot, port_id
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
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


async def test_ports_and_segments(snap: Snapshot) -> None:
    assert sorted(p.name for p in snap.ports) == ["igb0", "igb1", "igb2"]  # no lo0, no VLANs
    igb0 = next(p for p in snap.ports if p.name == "igb0")
    assert (igb0.up, igb0.speed_mbps, igb0.full_duplex) == (True, 1000, True)
    assert igb0.mac == "02:00:00:00:01:00" and igb0.vendor_extra["identifier"] == "lan"
    igb1 = next(p for p in snap.ports if p.name == "igb1")
    assert igb1.speed_mbps == 2500
    igb2 = next(p for p in snap.ports if p.name == "igb2")
    assert (igb2.up, igb2.speed_mbps, igb2.full_duplex) == (False, None, None)

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


async def test_dns(snap: Snapshot) -> None:
    (dns,) = snap.dns_services
    assert dns.enabled
    assert [str(a) for a in dns.listen] == ["192.0.2.1", "2001:db8:1::1", "198.51.100.1"]
    assert [str(a) for a in dns.forwarders] == ["192.0.2.53", "2001:db8:53::53"]
    assert [(h.name, str(h.address)) for h in dns.host_records] == [
        ("nas.home.example", "192.0.2.10"),
        ("nas.home.example", "2001:db8:1::10"),
    ]
    assert dns.vendor_extra == {"port": 53, "domain_forwards": {"corp.example": "198.51.100.53"}}


async def test_clients(snap: Snapshot) -> None:
    by_mac = {c.mac: c for c in snap.clients}
    assert sorted(by_mac) == [
        "00:00:5e:00:53:10",
        "00:00:5e:00:53:20",
        "00:00:5e:00:53:30",
        "02:00:00:00:00:21",
        "02:00:00:00:00:31",
    ]  # not the firewall's own MAC, not "(incomplete)"
    printer = by_mac["00:00:5e:00:53:10"]
    assert [str(a) for a in printer.addresses] == ["192.0.2.10", "2001:db8:1::10"]
    assert printer.hostname == "printer.home.example"
    assert printer.segment_id == "home/segment/native" and printer.seen_on == port_id("fw", "igb0")
    assert by_mac["00:00:5e:00:53:20"].segment_id == "home/segment/20"
    assert by_mac["02:00:00:00:00:21"].hostname == "laptop"  # from the Kea lease
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
