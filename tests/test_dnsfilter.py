"""AdGuard Home and Pi-hole v6 against their simulators (#304), and the shared DNS mapping."""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import ip_address
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from signalbox.adapters import (
    AdapterContext,
    DeviceRole,
    load_adapters,
)
from signalbox.adapters.adguardhome import AdGuardHomeAdapter, AdGuardHomeConfig
from signalbox.adapters.dnsmap import lease_seconds, parse_upstreams
from signalbox.adapters.pihole import PiholeAdapter, PiholeConfig
from signalbox.merge import merge
from signalbox.model import DeviceStatus, DnsForwarder, LeaseState, Site, Snapshot
from signalbox.rules import evaluate
from signalbox.rules.dhcp import RULES as DHCP_RULES
from signalbox.rules.dns import forwarder_loop
from signalbox.sim.dnsfilter import (
    AG_PASSWORD,
    AG_USER,
    MAC_LAPTOP,
    MAC_NAS,
    MAC_PHONE,
    PH_PASSWORD,
    AdGuardSim,
    PiholeSim,
)
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.testing import assert_contract


def context(config: Any, device_id: str, pin: str | None = None) -> AdapterContext:
    return AdapterContext(
        site_id="home",
        device_id=device_id,
        device_name=device_id,
        role=DeviceRole.OTHER,
        config=config,
        pinned_fingerprint=pin,
        timeout=5.0,
    )


def adguard(url: str, pin: str | None = None, password: str = AG_PASSWORD) -> AdGuardHomeAdapter:
    cfg = AdGuardHomeConfig(
        url=url,
        username=AG_USER,
        password=SecretStr(password),
        allow_insecure_http=url.startswith("http://"),
    )
    return AdGuardHomeAdapter(context(cfg, "adguard", pin))


def pihole(url: str, pin: str | None = None, password: str = PH_PASSWORD) -> PiholeAdapter:
    cfg = PiholeConfig(
        url=url, password=SecretStr(password), allow_insecure_http=url.startswith("http://")
    )
    return PiholeAdapter(context(cfg, "pihole", pin))


async def observe(a: AdGuardHomeAdapter | PiholeAdapter) -> Snapshot:
    try:
        return await a.observe()
    finally:
        await a.close()


@pytest.fixture
def ag() -> Iterator[tuple[AdGuardSim, str]]:
    sim = AdGuardSim()
    with serve(sim.app()) as url:
        yield sim, url


@pytest.fixture
def ph() -> Iterator[tuple[PiholeSim, str]]:
    sim = PiholeSim()
    with serve(sim.app()) as url:
        yield sim, url


# --- AdGuard Home ----------------------------------------------------------------------------


def test_entry_points() -> None:
    found = load_adapters()
    assert found["adguardhome"] is AdGuardHomeAdapter
    assert found["pihole"] is PiholeAdapter
    for cls in (AdGuardHomeAdapter, PiholeAdapter):
        m = cls.manifest
        assert m.roles == {DeviceRole.OTHER} and m.setup_steps and m.setup_url and not m.writes


async def test_adguard_contract_and_mapping(ag: tuple[AdGuardSim, str]) -> None:
    sim, url = ag
    a = adguard(url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.device.model == "AdGuard Home" and snap.device.firmware
    assert snap.device.firmware.current == "0.107.52"
    assert snap.device.transport_encrypted is False
    (dns,) = snap.dns_services
    assert dns.id == "adguard/dns/adguardhome" and dns.port == 53 and dns.config_read
    assert [str(x) for x in dns.listen] == ["192.0.2.53", "2001:db8::53"]
    assert [str(f) for f in dns.forwarders] == ["192.0.2.1", "203.0.113.53:853"]
    assert dns.vendor_extra["named_upstreams"] == ["https://dns.example.net"]
    assert dns.vendor_extra["domain_forwards"] == {"example.lan": ["192.0.2.1:5353"]}
    assert dns.vendor_extra["filtering_enabled"] is True
    assert [(r.name, str(r.address)) for r in dns.host_records] == [
        ("nas.example.lan", "192.0.2.20")
    ]
    (dhcp,) = snap.dhcp_servers
    assert dhcp.segment_id == "home/segment/native" and dhcp.enabled
    assert (str(dhcp.pools[0].start), str(dhcp.pools[0].end)) == ("192.0.2.100", "192.0.2.199")
    assert dhcp.lease_seconds == 86400 and str(dhcp.router) == "192.0.2.1"
    assert [(r.mac, str(r.address)) for r in dhcp.reservations] == [(MAC_NAS, "192.0.2.20")]
    states = {str(x.address): x.state for x in dhcp.leases or []}
    assert states == {
        "192.0.2.20": LeaseState.RESERVED,
        "192.0.2.101": LeaseState.ACTIVE,
        "192.0.2.102": LeaseState.ACTIVE,
    }
    assert [(c.mac, c.hostname) for c in snap.clients] == [
        (MAC_LAPTOP, "Laptop"),
        (MAC_NAS, "NAS"),
    ]
    # AdGuard Home hands out itself: its own IPv4 address in the DHCP network (#314)
    assert [str(x) for x in dhcp.dns_servers] == ["192.0.2.53"]
    assert {m for m, _ in sim.requests} == {"GET"}  # read only


async def test_adguard_over_pinned_tls(tmp_path: Any) -> None:
    tls: TlsFiles = self_signed_certificate(tmp_path, "adguard")
    with serve(AdGuardSim().app(), tls=tls) as url:
        a = adguard(url, pin=tls.fingerprint)
        try:
            snap = await assert_contract(a)
        finally:
            await a.close()
        assert snap.device.transport_encrypted is True
        unpinned = await observe(adguard(url))
    assert unpinned.status is DeviceStatus.UNTRUSTED


async def test_adguard_dhcp_off_reads_no_server(ag: tuple[AdGuardSim, str]) -> None:
    sim, url = ag
    sim.data["/control/dhcp/status"]["enabled"] = False
    snap = await observe(adguard(url))
    assert snap.status is DeviceStatus.OK and not snap.dhcp_servers and not snap.segments


async def test_adguard_dhcp_dns_servers(ag: tuple[AdGuardSim, str]) -> None:
    sim, url = ag
    status = sim.data["/control/status"]
    status["dns_addresses"] = ["192.0.2.53", "198.51.100.5", "2001:db8::53"]
    dhcp = (await observe(adguard(url))).dhcp_servers[0]
    assert [str(x) for x in dhcp.dns_servers] == ["192.0.2.53"]  # the DHCP network only
    sim.data["/control/dhcp/status"]["v4"]["subnet_mask"] = "bad"
    dhcp = (await observe(adguard(url))).dhcp_servers[0]
    assert [str(x) for x in dhcp.dns_servers] == ["192.0.2.53", "198.51.100.5"]
    sim.data["/control/dhcp/status"]["v4"]["subnet_mask"] = "255.0.255.0"  # not a netmask
    assert len((await observe(adguard(url))).dhcp_servers[0].dns_servers) == 2
    sim.data["/control/dhcp/status"]["v4"].pop("subnet_mask")
    assert (await observe(adguard(url))).dhcp_servers[0].dns_servers


async def test_adguard_wrong_password(ag: tuple[AdGuardSim, str]) -> None:
    snap = await observe(adguard(ag[1], password="wrong"))
    assert snap.status is DeviceStatus.AUTH_FAILED and "wrong" not in snap.model_dump_json()


async def test_adguard_upstream_file_is_a_gap(ag: tuple[AdGuardSim, str]) -> None:
    sim, url = ag
    sim.upstream_file()
    snap = await observe(adguard(url))
    assert snap.status is DeviceStatus.PARTIAL
    (err,) = snap.errors
    assert err.capability == "dns" and "upstream_dns_file" in err.message and err.fix
    assert not snap.dns_services[0].config_read  # not "resolves itself"


@pytest.mark.parametrize("status", [404, 500])
async def test_adguard_missing_rewrites_is_a_gap(ag: tuple[AdGuardSim, str], status: int) -> None:
    sim, url = ag
    sim.fail["/control/rewrite/list"] = status
    snap = await observe(adguard(url))
    assert snap.status is DeviceStatus.PARTIAL
    assert snap.errors[0].capability == "dns" and snap.errors[0].fix
    assert snap.dns_services[0].forwarders  # the rest was read


async def test_adguard_unexpected_answer(ag: tuple[AdGuardSim, str]) -> None:
    sim, url = ag
    sim.data["/control/dhcp/status"] = []
    snap = await observe(adguard(url))
    assert any("unexpected answer" in e.message for e in snap.errors)


def test_adguard_plain_http_needs_opt_in() -> None:
    with pytest.raises(ValidationError):
        AdGuardHomeConfig(url="http://192.0.2.53", username="u", password=SecretStr("p"))


# --- Pi-hole ---------------------------------------------------------------------------------


async def test_pihole_contract_mapping_and_logout(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    a = pihole(url)
    try:
        snap = await assert_contract(a)
        assert sim.sessions  # logged in until the observation is over
    finally:
        await a.close()
    assert not sim.sessions and sim.logouts == 1
    assert ("DELETE", "/api/auth") in sim.requests
    assert snap.device.model == "Pi-hole" and snap.device.firmware
    assert (snap.device.firmware.current, snap.device.firmware.available) == ("6.0.2", "6.1")
    (dns,) = snap.dns_services
    assert dns.id == "pihole/dns/pihole" and dns.config_read
    assert [str(f) for f in dns.forwarders] == ["192.0.2.53", "203.0.113.53:5353", "2001:db8::1"]
    assert dns.vendor_extra["domain_forwards"] == {"lan": ["192.0.2.1"]}
    assert [(r.name, str(r.address)) for r in dns.host_records] == [
        ("printer.lan", "192.0.2.10"),
        ("printer", "192.0.2.10"),
        ("cam.lan", "192.0.2.11"),
    ]
    (dhcp,) = snap.dhcp_servers
    assert dhcp.lease_seconds == 86400 and str(dhcp.pools[0].start) == "192.0.2.150"
    assert dhcp.domain == "lan"
    assert [(r.mac, r.hostname) for r in dhcp.reservations] == [(MAC_NAS, "nas")]
    leases = {str(x.address): x for x in dhcp.leases or []}
    assert set(leases) == {"192.0.2.151", "192.0.2.20"}  # the entry without a MAC is dropped
    assert leases["192.0.2.20"].reserved and leases["192.0.2.20"].expires is None
    assert leases["192.0.2.20"].hostname is None  # "*"
    assert leases["192.0.2.151"].expires is not None
    assert [str(x) for x in dhcp.dns_servers] == ["127.0.0.1"]  # itself, as reached (#314)
    by_mac = {c.mac: c for c in snap.clients}
    assert set(by_mac) == {MAC_LAPTOP, MAC_PHONE}  # "ip-192.0.2.99" has no MAC
    laptop = by_mac[MAC_LAPTOP]
    assert laptop.hostname == "laptop" and laptop.last_seen is not None
    assert [str(x) for x in laptop.addresses] == ["192.0.2.151", "2001:db8::151"]
    assert by_mac[MAC_PHONE].hostname is None and by_mac[MAC_PHONE].last_seen is None
    assert sim.last_sid not in snap.model_dump_json()
    assert {m for m, _ in sim.requests} <= {"GET", "POST", "DELETE"}


async def test_pihole_over_pinned_tls(tmp_path: Any) -> None:
    tls = self_signed_certificate(tmp_path, "pihole")
    sim = PiholeSim()
    with serve(sim.app(), tls=tls) as url:
        a = pihole(url, pin=tls.fingerprint)
        try:
            snap = await assert_contract(a)
        finally:
            await a.close()
        assert snap.device.transport_encrypted is True
        # no password is sent to a certificate that is not pinned
        sim.requests.clear()
        assert (await observe(pihole(url))).status is DeviceStatus.UNTRUSTED
        assert sim.requests == []


async def test_pihole_dhcp_off(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.dhcp_active = False
    snap = await observe(pihole(url))
    assert snap.status is DeviceStatus.OK and not snap.dhcp_servers
    assert ("GET", "/api/dhcp/leases") not in sim.requests


async def test_pihole_wrong_password(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    snap = await observe(pihole(url, password="not-the-password"))
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert "app password" in (snap.errors[0].fix or "")
    assert "not-the-password" not in snap.model_dump_json() and sim.logouts == 0


async def test_pihole_two_factor(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.totp = True
    snap = await observe(pihole(url))
    assert snap.status is DeviceStatus.AUTH_FAILED and "app password" in (snap.errors[0].fix or "")


async def test_pihole_too_many_sessions(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.max_sessions = 0
    snap = await observe(pihole(url))
    assert snap.status is DeviceStatus.UNREACHABLE and "429" in snap.errors[0].message
    assert "max_sessions" in (snap.errors[0].fix or "")


async def test_pihole_v5_is_refused_with_a_fix(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.version = "v5"
    snap = await observe(pihole(url))
    (err,) = snap.errors
    assert "v5" in err.message and "v6" in (err.fix or "")


async def test_pihole_that_is_no_pihole(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.version = "other"
    snap = await observe(pihole(url))
    assert "does not look like Pi-hole v6" in snap.errors[0].message


async def test_pihole_lease_table_failure_is_a_gap(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.fail["/api/dhcp/leases"] = 500
    snap = await observe(pihole(url))
    assert snap.status is DeviceStatus.PARTIAL
    assert snap.errors[0].capability == "dhcp" and snap.errors[0].fix
    assert snap.dhcp_servers[0].leases is None  # not read, not "no leases"
    assert sim.logouts == 1


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        (["dhcp-option=6,192.0.2.1,0.0.0.0"], ["192.0.2.1", "127.0.0.1"]),
        (["dhcp-option=option:dns-server,192.0.2.1"], ["192.0.2.1"]),
        (["dhcp-option=tag:kids,6,198.51.100.1", "dhcp-option=3,192.0.2.1"], ["127.0.0.1"]),
        (["dhcp-option=6,not-an-address"], []),
    ],
)
async def test_pihole_dhcp_dns_option(
    ph: tuple[PiholeSim, str], lines: list[str], expected: list[str]
) -> None:
    sim, url = ph
    sim.data["/api/config"]["config"]["misc"]["dnsmasq_lines"] = lines
    snap = await observe(pihole(url))
    assert [str(x) for x in snap.dhcp_servers[0].dns_servers] == expected


async def test_pihole_clients_gap_and_odd_rows(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.data["/api/network/devices"]["devices"] += [
        "junk",
        {"hwaddr": "02:00:5e:00:53:20", "ips": ["x", {"ip": "bad", "lastSeen": True}]},
    ]
    snap = await observe(pihole(url))
    assert "02:00:5e:00:53:20" in {c.mac for c in snap.clients}
    sim.data["/api/network/devices"] = {"devices": "none"}
    assert not (await observe(pihole(url))).clients
    sim.fail["/api/network/devices"] = 500
    snap = await observe(pihole(url))
    assert snap.status is DeviceStatus.PARTIAL and snap.errors[0].capability == "clients"


async def test_pihole_old_version_is_refused(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.data["/api/info/version"]["version"]["ftl"]["local"]["version"] = "v5.25"
    snap = await observe(pihole(url))
    assert "not supported" in snap.errors[0].message


async def test_pihole_unreachable() -> None:
    cfg = PiholeConfig(url="http://127.0.0.1:9", password=SecretStr("x"), allow_insecure_http=True)
    snap = await observe(PiholeAdapter(context(cfg, "pihole")))
    assert snap.status is DeviceStatus.UNREACHABLE


async def test_pihole_unexpected_config(ph: tuple[PiholeSim, str]) -> None:
    sim, url = ph
    sim.data["/api/config"] = {"config": {"dns": {}}}
    snap = await observe(pihole(url))
    assert any("dns.upstreams" in e.message for e in snap.errors)
    assert sim.logouts == 1


# --- the mapping and the checks --------------------------------------------------------------


def test_parse_upstreams() -> None:
    up = parse_upstreams(
        [
            "192.0.2.1",
            "192.0.2.1",
            "192.0.2.2#5353",
            "[2001:db8::1]:53",
            "tcp://192.0.2.3",
            "quic://203.0.113.1",
            "https://203.0.113.2/dns-query",
            "tls://dns.example.net:853/x",
            "sdns://AQcAAAAA",
            "[//]192.0.2.9",
            "[/a.lan/b.lan/]192.0.2.8 192.0.2.7",
            "[/c.lan/]#",
            "#",
            "192.0.2.4:70000",
            "",
        ]
    )
    assert [str(f) for f in up.forwarders] == [
        "192.0.2.1",
        "192.0.2.2:5353",
        "2001:db8::1",
        "192.0.2.3",
        "203.0.113.1:853",
        "203.0.113.2:443",
    ]
    assert up.named == ["tls://dns.example.net:853", "sdns://", "192.0.2.4:70000"]
    assert up.domains["a.lan"] == ["192.0.2.8", "192.0.2.7"] == up.domains["b.lan"]
    assert up.domains["(names without a dot)"] == ["192.0.2.9"]
    assert DnsForwarder(address=ip_address("192.0.2.1")) in up.forwarders


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("24h", 86400),
        ("90m", 5400),
        ("7d", 604800),
        ("1w", 604800),
        ("3600", 3600),
        ("30s", 30),
        ("infinite", None),
        ("", None),
        (None, None),
    ],
)
def test_lease_seconds(text: object, seconds: int | None) -> None:
    assert lease_seconds(text) == seconds


async def test_dns_checks_see_the_real_data(
    ag: tuple[AdGuardSim, str], ph: tuple[PiholeSim, str]
) -> None:
    """Pi-hole forwards to AdGuard Home and back: a loop; two DHCP servers on one network."""
    asim, aurl = ag
    purl = ph[1]
    asim.data["/control/dns_info"]["upstream_dns"] = ["192.0.2.54"]
    snaps = [await observe(adguard(aurl)), await observe(pihole(purl))]
    snaps[1] = snaps[1].model_copy(
        update={"device": snaps[1].device.model_copy(update={"management_address": "192.0.2.54"})}
    )
    net = merge([Site(id="home", name="Home")], snaps)
    (loop,) = evaluate(net, [forwarder_loop])
    assert "dhcp.one-server" in {f.rule_id for f in evaluate(net, DHCP_RULES)}
    assert set(loop.objects) == {"adguard/dns/adguardhome", "pihole/dns/pihole"}
