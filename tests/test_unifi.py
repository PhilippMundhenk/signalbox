"""UniFi adapter against its simulator, over real sockets (plain HTTP and pinned TLS), for the
three Network application versions and both kinds of installation; recording replay."""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from signalbox.adapters import AdapterContext, load_adapters
from signalbox.adapters.unifi import (
    UnifiAdapter,
    UnifiConfig,
    ciphers_of,
    health_of,
    major_of,
    security_of,
    time_of,
    uplink_of,
    wlan_bands,
)
from signalbox.model import (
    Cipher,
    DeviceRole,
    DeviceStatus,
    Membership,
    NeighbourProtocol,
    PoeStatus,
    PortKind,
    PortRole,
    Security,
    SegmentPurpose,
    Snapshot,
)
from signalbox.recording import Exchange, build, recording, replay_snapshot
from signalbox.sim.server import self_signed_certificate, serve
from signalbox.sim.unifi import (
    AP1,
    AP2,
    API_KEY,
    GATEWAY,
    PASSWORD,
    SWITCH,
    USERNAME,
    UnifiSimulator,
)
from signalbox.testing import assert_contract, passphrase_digest_key

DEV = "unifi1"
SW = f"{DEV}/switch-020000000b01"
GW = f"{DEV}/gateway-020000000a01"
AP_1 = f"{DEV}/uap-020000000c01"
AP_2 = f"{DEV}/uap-020000000c02"
VERSIONS = ["8.6.9", "9.0.114", "10.0.26"]
STYLES = ["unifi_os", "controller"]


@contextmanager
def running(**kw: Any) -> Iterator[tuple[UnifiSimulator, str]]:
    sim = UnifiSimulator(**kw)
    with serve(sim.app()) as url:
        yield sim, url


def adapter(url: str, pin: str | None = None, **cfg: Any) -> UnifiAdapter:
    cfg.setdefault("api_key", None)
    if cfg["api_key"] is None:
        cfg.setdefault("username", USERNAME)
        cfg.setdefault("password", SecretStr(PASSWORD))
    elif isinstance(cfg["api_key"], str):
        cfg["api_key"] = SecretStr(cfg["api_key"])
    config = UnifiConfig(url=url, allow_insecure_http=url.startswith("http://"), **cfg)
    return UnifiAdapter(
        AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name="UniFi",
            role=DeviceRole.OTHER,
            config=config,
            pinned_fingerprint=pin,
            timeout=5.0,
        )
    )


async def observe(a: UnifiAdapter) -> Snapshot:
    try:
        return await a.observe()
    finally:
        await a.close()


async def contract(a: UnifiAdapter) -> Snapshot:
    try:
        with passphrase_digest_key():
            return await assert_contract(a)
    finally:
        await a.close()


# --- contract and mapping, every version and both installations ------------------------------


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("style", STYLES)
async def test_contract_login(style: str, version: str) -> None:
    with running(style=style, version=version) as (sim, url):
        snap = await contract(adapter(url))
    assert snap.device.firmware is not None and snap.device.firmware.current == version
    assert (snap.device.vendor, snap.device.model) == ("Ubiquiti", "UniFi Network Application")
    login = "/api/auth/login" if style == "unifi_os" else "/api/login"
    assert login in sim.requests
    assert len(snap.extra_devices) == 4  # the pending switch is not adopted
    # the site setting auto_upgrade (#181) reaches every managed device that has a firmware
    assert {d.firmware.auto_update for d in snap.extra_devices if d.firmware} == {False}


@pytest.mark.parametrize("style", STYLES)
async def test_contract_api_key(style: str) -> None:
    with running(style=style) as (sim, url):
        snap = await contract(adapter(url, api_key=API_KEY))
    assert "/api/auth/login" not in sim.requests and "/api/login" not in sim.requests
    assert snap.status is DeviceStatus.OK and snap.ports


@pytest.mark.parametrize("kind", ["unifi_os", "controller"])
async def test_configured_kind_skips_detection(kind: str) -> None:
    with running(style=kind) as (sim, url):
        snap = await contract(adapter(url, kind=kind))
    assert "/" not in sim.requests and snap.ports


async def test_forced_kind_is_not_second_guessed() -> None:
    with running(style="controller") as (_, url):
        snap = await observe(adapter(url, kind="unifi_os"))
    assert snap.status is not DeviceStatus.OK


async def test_detection_falls_back_to_the_other_style() -> None:
    """A console taken for a controller (or the reverse) is found on the first 404."""
    with running(style="controller") as (sim, url):
        a = adapter(url)

        async def wrong_guess() -> None:
            a._os = True

        a._guess_style = wrong_guess  # type: ignore[method-assign]
        snap = await observe(a)
    assert snap.status is DeviceStatus.OK
    assert "/api/login" in sim.requests


@pytest.fixture(scope="module")
def snaps() -> dict[str, Snapshot]:
    async def read() -> dict[str, Snapshot]:
        out: dict[str, Snapshot] = {}
        for version in VERSIONS:
            with running(version=version) as (_, url):
                out[version] = await contract(adapter(url))
        return out

    return asyncio.run(read())


async def test_the_versions_read_the_same(snaps: dict[str, Snapshot]) -> None:
    """The field spellings of 8, 9 and 10 (#389): the same segments, ports, Wi-Fi networks."""
    first = snaps[VERSIONS[0]]
    for version in VERSIONS[1:]:
        other = snaps[version]
        assert [(s.id, s.members) for s in other.segments] == [
            (s.id, s.members) for s in first.segments
        ]
        assert [w.id for w in other.wlans] == [w.id for w in first.wlans]
        assert [(w.security, w.ciphers) for w in other.wlans] == [
            (w.security, w.ciphers) for w in first.wlans
        ]
        assert [n.id for n in other.neighbours] == [n.id for n in first.neighbours]
        assert [p.id for p in other.ports] == [p.id for p in first.ports]


async def test_ports_and_vlans(snaps: dict[str, Snapshot]) -> None:
    snap = snaps["10.0.26"]
    ports = {p.id: p for p in snap.ports}
    p1 = ports[f"{SW}/port/1"]
    assert p1.poe is not None
    assert (p1.up, p1.speed_mbps, p1.poe.enabled, p1.profile, p1.pvid) == (
        True,
        1000,
        True,
        "All",
        1,
    )
    # #159: the delivered power, the class and the state of the port, and the switch's budget
    assert (p1.poe.power_w, p1.poe.power_class, p1.poe.status) == (4.2, 2, PoeStatus.DELIVERING)
    assert p1.name == "Switch Port 1" and p1.role is PortRole.JACK
    p4 = ports[f"{SW}/port/4"]
    assert p4.poe is not None
    assert (p4.admin_up, p4.up, p4.poe.enabled) == (False, False, False)
    assert p4.poe.status is PoeStatus.DISABLED
    switch = next(d for d in snap.extra_devices if d.id == SW)
    assert switch.poe is not None and switch.poe.budget_w == 60 and switch.poe.used_w == 4.2
    # reserved by class: the one delivering port is class 2 (7 W)
    assert switch.poe.reserved_w == 7.0
    segments = {s.id: {m.port_id: m.mode for m in s.members} for s in snap.segments}
    native, iot, guest = "home/segment/native", "home/segment/20", "home/segment/30"
    assert segments[native][f"{SW}/port/1"] is Membership.UNTAGGED
    assert segments[iot][f"{SW}/port/1"] is Membership.TAGGED
    assert segments[iot][f"{SW}/port/2"] is Membership.UNTAGGED  # profile IoT access
    assert f"{SW}/port/2" not in segments[native]
    assert segments[iot][f"{SW}/port/6"] is Membership.TAGGED  # trunk: IoT tagged only
    assert f"{SW}/port/6" not in segments[guest]
    assert f"{SW}/port/4" not in segments[native]  # profile "disabled"
    assert {s.id: s.purpose for s in snap.segments}[guest] is SegmentPurpose.GUEST
    lag = ports[f"{SW}/port/lag7"]
    assert (lag.kind, lag.role) == (PortKind.LAG, PortRole.LAG)
    assert lag.lower == [f"{SW}/port/7", f"{SW}/port/8"]
    assert ports[f"{SW}/port/8"].lag == "7"


async def test_wan_subnets_and_dhcp(snaps: dict[str, Snapshot]) -> None:
    snap = snaps["10.0.26"]
    assert [str(u.addresses[0]) for u in snap.uplinks] == ["203.0.113.45/24"]
    assert snap.uplinks[0].kind.value == "dhcp" and snap.uplinks[0].up is True
    assert {str(s.interface) for s in snap.subnets} == {
        "192.0.2.1/24",
        "198.51.100.1/24",
        "203.0.113.129/25",
    }
    servers = {s.segment_id: s for s in snap.dhcp_servers}
    assert set(servers) == {"home/segment/native", "home/segment/20"}  # Guest has no DHCP
    lan = servers["home/segment/native"]
    assert (lan.lease_seconds, lan.domain) == (86400, "lan.example")
    assert [str(a) for a in lan.dns_servers] == ["192.0.2.53"]
    assert str(lan.pools[0].start) == "192.0.2.100"


async def test_neighbours(snaps: dict[str, Snapshot]) -> None:
    snap = snaps["9.0.114"]
    by_local = {n.local_port_id: n for n in snap.neighbours}
    ap1 = by_local[f"{AP_1}/port/1"]
    assert (ap1.chassis_id, ap1.remote_port, ap1.system_name) == (SWITCH, "Switch Port 3", "Switch")
    assert not ap1.wireless
    mesh = by_local[f"{AP_2}/port/mesh"]
    assert (mesh.chassis_id, mesh.wireless, mesh.remote_port) == (AP1, True, "AP One Mesh")
    up = [n for n in snap.neighbours if n.local_port_id == f"{SW}/port/5"]
    assert len(up) == 1 and up[0].chassis_id == GATEWAY  # uplink and LLDP are one neighbour
    assert {p.id for p in snap.ports} >= {f"{AP_1}/port/mesh", f"{AP_2}/port/mesh"}


async def test_lldp_details_fill_the_uplink_neighbour(snaps: dict[str, Snapshot]) -> None:
    """chassis name, port description, capabilities and protocol of the LLDP table (#470),
    for both field layouts (per device and per port)."""
    for snap in snaps.values():
        up = [n for n in snap.neighbours if n.local_port_id == f"{SW}/port/5"]
        assert len(up) == 1
        n = up[0]
        assert (n.protocol, n.chassis_id_kind) == (NeighbourProtocol.LLDP, "mac")
        assert (n.port_description, n.capabilities) == ("LAN 1", ["bridge", "router"])
        assert n.age_seconds is None and n.last_seen is None


async def test_wireless(snaps: dict[str, Snapshot]) -> None:
    snap = snaps["10.0.26"]
    radios = {r.id: r for r in snap.radios}
    ng = radios[f"{AP_1}/radio/wifi0"]
    assert (ng.band.value, ng.channel, ng.channel_auto, ng.width_mhz) == ("2.4", 6, True, 20)
    assert (ng.channel_utilisation_pct, ng.interference_pct, ng.client_count) == (20, 10, 1)
    na = radios[f"{AP_1}/radio/wifi1"]
    assert (na.band.value, na.channel, na.channel_auto, na.dfs_capable) == ("5", 36, False, True)
    wlans = {w.id: w for w in snap.wlans}
    home = wlans[f"{AP_1}/wlan/wlan-home-wifi0"]
    assert home.ssid == "Home" and home.security is Security.WPA2_WPA3
    assert home.ciphers == [Cipher.CCMP] and home.pmf is not None
    assert home.passphrase_fingerprint and "example-passphrase" not in snap.model_dump_json()
    assert home.segment_id == "home/segment/native" and home.key_rotation_seconds == 3600
    iot = wlans[f"{AP_1}/wlan/wlan-iot-wifi0"]
    assert iot.hidden and iot.segment_id == "home/segment/20" and iot.client_isolation is True
    guest = wlans[f"{AP_1}/wlan/wlan-guest-wifi0"]
    assert guest.security is Security.OPEN and guest.purpose is SegmentPurpose.GUEST
    assert guest.ciphers is None and guest.passphrase_digest is None
    assert len([w for w in snap.wlans if w.device_id == AP_2]) == 1


async def test_clients_and_mac_table(snaps: dict[str, Snapshot]) -> None:
    snap = snaps["10.0.26"]
    clients = {c.hostname: c for c in snap.clients}
    assert set(clients) == {"desk", "sensor", "phone"}
    assert clients["desk"].seen_on == f"{SW}/port/1"
    assert clients["desk"].segment_id == "home/segment/native"
    assert clients["phone"].seen_on == f"{AP_1}/wlan/wlan-home-wifi1"
    assert clients["sensor"].segment_id == "home/segment/20"
    assert clients["desk"].last_seen == datetime.fromtimestamp(1790000000, UTC)
    ports = {f.port_id for f in snap.fdb}
    assert {f"{SW}/port/1", f"{SW}/port/2"} <= ports
    assert any(f.vlan == 20 and f.segment_id == "home/segment/20" for f in snap.fdb)


async def test_health_and_time(snaps: dict[str, Snapshot]) -> None:
    snap = snaps["10.0.26"]
    gw = next(d for d in snap.extra_devices if d.id == GW)
    assert gw.health is not None
    assert (gw.health.uptime_seconds, gw.health.cpu_load_pct) == (864000, 7.5)
    assert gw.health.load_average == (0.2, 0.3, 0.4)
    assert gw.health.max_temperature_c() == 52 and gw.health.storage[0].name == "/data"
    assert gw.vendor == "Ubiquiti" and gw.role is DeviceRole.GATEWAY and gw.mac == GATEWAY
    assert snap.device.time is not None and snap.device.time.timezone == "Europe/Berlin"
    roles = {d.id: d.role for d in snap.extra_devices}
    assert roles[SW] is DeviceRole.SWITCH and roles[AP_1] is DeviceRole.AP


async def test_site_to_site_vpn_without_secrets(snaps: dict[str, Snapshot]) -> None:
    """Site-to-site IPsec and the OpenVPN server of the gateway (#527); the key is never kept."""
    snap = snaps["10.0.26"]
    by_name = {t.name: t for t in snap.tunnels}
    ipsec = by_name["ipsec-Office_B"]
    assert (ipsec.kind.value, ipsec.ike_version, ipsec.auth.value) == ("ipsec", 1, "psk")  # type: ignore[union-attr]
    assert ipsec.id.startswith(f"{GW}/tunnel/") and ipsec.remote_gateway == "203.0.113.90"
    assert [(p.encryption, p.dh_group) for p in ipsec.proposals] == [("3des", 2), ("aes256", 14)]
    assert [str(n) for n in ipsec.children[0].remote_networks] == ["198.51.100.0/25"]
    server = by_name["openvpn-Road_warriors"]
    assert server.role is not None and server.role.value == "server"
    assert str(server.tunnel_network) == "198.18.88.0/24" and server.up is None
    assert "do-not-leak" not in snap.model_dump_json()


# --- logins, sites and failures --------------------------------------------------------------


@pytest.mark.parametrize("style", STYLES)
async def test_wrong_password(style: str) -> None:
    with running(style=style) as (_, url):
        snap = await observe(adapter(url, password=SecretStr("not-the-password")))
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert snap.errors[0].message_id == "unifi.loginRefused"
    assert "not-the-password" not in snap.errors[0].message


async def test_wrong_api_key() -> None:
    with running() as (_, url):
        snap = await observe(adapter(url, api_key="not-the-key"))
    assert snap.status is DeviceStatus.AUTH_FAILED


@pytest.mark.parametrize("site", ["default", "Default", "DEFAULT"])
async def test_site_by_name_or_description(site: str) -> None:
    with running() as (_, url):
        snap = await observe(adapter(url, site=site))
    assert snap.status is DeviceStatus.OK


async def test_unknown_site() -> None:
    with running() as (_, url):
        snap = await observe(adapter(url, site="Elsewhere"))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert snap.errors[0].message == (
        "the Network application has no site 'Elsewhere' (sites: Default)"
    )


@pytest.mark.parametrize("style", STYLES)
async def test_expired_session_is_renewed(style: str) -> None:
    with running(style=style) as (sim, url):
        sim.expire_next = True
        snap = await observe(adapter(url))
    login = "/api/auth/login" if style == "unifi_os" else "/api/login"
    assert snap.status is DeviceStatus.OK
    assert sim.requests.count(login) == 2


async def test_unifi_error_is_a_read_error() -> None:
    with running() as (sim, url):
        sim.error["stat/sta"] = "api.err.NoPermission"
        snap = await observe(adapter(url))
    assert snap.status is DeviceStatus.PARTIAL
    err = next(e for e in snap.errors if e.capability == "clients")
    assert err.message_id == "unifi.error" and "NoPermission" in err.message
    assert snap.ports  # the rest was read


async def test_missing_profiles_are_a_gap() -> None:
    with running() as (sim, url):
        sim.missing.add("rest/portconf")
        snap = await contract(adapter(url))
    assert any(e.message_id == "unifi.optional" and e.optional for e in snap.errors)
    port = next(p for p in snap.ports if p.id == f"{SW}/port/1")
    assert port.profile is None and port.up is True


async def test_other_version_is_an_optional_gap() -> None:
    with running(version="7.5.176") as (_, url):
        snap = await contract(adapter(url))
    gap = next(e for e in snap.errors if e.message_id == "unifi.version")
    assert gap.optional and gap.params["version"] == "7.5.176"


async def test_api_key_that_only_reaches_the_integration_api() -> None:
    with running(key_classic=False) as (_, url):
        snap = await contract(adapter(url, api_key=API_KEY))
    gap = next(e for e in snap.errors if e.message_id == "unifi.integrationOnly")
    assert gap.optional and gap.fix_id == "unifi.integrationOnly.fix"
    assert {d.id for d in snap.extra_devices} == {SW, AP_1}
    assert {s.id for s in snap.segments} == {"home/segment/native", "home/segment/20"}
    assert [c.hostname for c in snap.clients] == ["desk"]
    assert snap.ports == [] and snap.wlans == []
    assert snap.device.firmware is not None and snap.device.firmware.current == "10.0.26"
    assert next(d for d in snap.extra_devices if d.id == SW).health is not None


async def test_pinned_tls_and_untrusted_certificate(tmp_path: Path) -> None:
    tls = self_signed_certificate(tmp_path)
    sim = UnifiSimulator(style="unifi_os")
    with serve(sim.app(), tls=tls) as url:
        untrusted = await observe(adapter(url))
        trusted = await contract(adapter(url, pin=tls.fingerprint))
    assert untrusted.status is DeviceStatus.UNTRUSTED
    assert trusted.status is DeviceStatus.OK and trusted.device.certificate is not None


async def test_unreachable() -> None:
    snap = await observe(adapter("http://127.0.0.1:9"))
    assert snap.status is DeviceStatus.UNREACHABLE


# --- recording replay ------------------------------------------------------------------------


@pytest.mark.parametrize("style", STYLES)
async def test_recording_replays(style: str) -> None:
    """What the adapter asks and is answered is recorded, neutralised and replayed (#403)."""
    exchanges: list[Exchange] = []
    with tempfile.TemporaryDirectory() as tmp:
        tls = self_signed_certificate(Path(tmp))
        with serve(UnifiSimulator(style=style).app(), tls=tls) as secure:
            a = adapter(secure, pin=tls.fingerprint)
            try:
                with recording(exchanges):
                    live = await a.observe()
            finally:
                await a.close()
    assert live.status is DeviceStatus.OK and len(exchanges) > 10
    data = build(
        "unifi",
        exchanges,
        role="other",
        path="",
        settings={},
        password=PASSWORD,
        username=USERNAME,
        secret_names=["password"],
    )
    text = str(data)
    assert PASSWORD not in text and "example-passphrase" not in text
    assert "02:00:00:00" not in text
    snapshot, unmatched = await replay_snapshot(data)
    assert unmatched == []
    assert snapshot["status"] == "ok"
    for kind in ("ports", "wlans", "clients", "segments", "neighbours", "extra_devices"):
        assert len(snapshot[kind]) == len(getattr(live, kind)), kind


# --- parsing ---------------------------------------------------------------------------------


def test_entry_point_and_manifest() -> None:
    cls = load_adapters()["unifi"]
    assert cls is UnifiAdapter
    assert not cls.manifest.writes
    assert {r.value for r in cls.manifest.roles} == {"other", "ap", "switch", "gateway"}


def test_config_needs_a_login_and_https() -> None:
    with pytest.raises(ValidationError, match="API key"):
        UnifiConfig(url="https://192.0.2.1")
    with pytest.raises(ValidationError, match="API key"):
        UnifiConfig(url="https://192.0.2.1", username="reader")
    with pytest.raises(ValidationError, match="allow_insecure_http"):
        UnifiConfig(url="http://192.0.2.1", api_key=SecretStr("k"))
    cfg = UnifiConfig(url="192.0.2.1", api_key=SecretStr("k"), password=SecretStr(" "))
    assert cfg.url == "https://192.0.2.1" and cfg.password is None


def test_versions() -> None:
    assert [major_of(v) for v in ("10.0.26", "8.6.9", "", "x")] == [10, 8, None, None]


def test_security_of() -> None:
    assert security_of({"security": "open"}) is Security.OPEN
    assert security_of({"security": "open", "owe_enabled": True}) is Security.OWE
    assert security_of({"security": "wep"}) is Security.WEP
    assert security_of({"security": "wpapsk"}) is Security.WPA2
    assert security_of({"security": "wpapsk", "wpa_mode": "wpa1"}) is Security.WPA
    assert security_of({"security": "wpapsk", "wpa3_support": True}) is Security.WPA3
    mixed = {"security": "wpapsk", "wpa3_support": True, "wpa3_transition": True}
    assert security_of(mixed) is Security.WPA2_WPA3
    assert security_of({"security": "wpaeap"}) is Security.WPA2_ENTERPRISE
    assert security_of({"security": "wpaeap", "wpa_mode": "wpa1"}) is Security.WPA_ENTERPRISE
    assert security_of({"security": "wpaeap", "wpa3_support": True}) is Security.WPA3_ENTERPRISE
    assert security_of({"security": "x"}) is Security.OTHER
    assert ciphers_of({"wpa_enc": "tkip"}, Security.WPA) == [Cipher.TKIP]
    assert ciphers_of({"wpa_enc": "auto"}, Security.WPA2) == [Cipher.TKIP, Cipher.CCMP]
    assert ciphers_of({}, Security.WPA2) == [Cipher.CCMP]
    assert ciphers_of({}, Security.OPEN) is None


def test_wlan_bands_both_spellings() -> None:
    assert wlan_bands({"wlan_band": "both"}) == ("ng", "na")
    assert wlan_bands({"wlan_band": "5g"}) == ("na",)
    assert wlan_bands({"wlan_bands": ["2g", "6g"]}) == ("ng", "6e", "6g")
    assert wlan_bands({}) == ("ng", "na")


def test_uplink_of() -> None:
    row = {"mac": AP1, "uplink": {"type": "wire", "uplink_mac": SWITCH, "uplink_remote_port": 3}}
    link = uplink_of(row)
    assert link is not None and (link.parent, link.remote_idx, link.mesh) == (SWITCH, 3, False)
    assert uplink_of({"mac": AP1, "uplink": {"uplink_mac": AP1}}) is None  # itself
    last = {"mac": AP2, "last_uplink": {"type": "wireless", "uplink_mac": AP1}}
    mesh = uplink_of(last)
    assert mesh is not None and mesh.mesh
    assert uplink_of({"mac": AP1}) is None


def test_health_of_is_tolerant() -> None:
    assert health_of({}) == health_of({"system-stats": "x", "storage": [{"size": "x"}]})
    h = health_of({"sys_stats": {"mem_total": 10, "mem_used": 20}, "uptime": -5})
    assert h.memory_used_bytes is None and h.uptime_seconds is None
    t = health_of({"temperatures": [{"name": "CPU", "value": 61}, {"value": "x"}]})
    assert [(x.name, x.value_c) for x in t.temperatures] == [("CPU", 61)]


def test_time_of() -> None:
    start = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    value = time_of("Tue, 24 Nov 2026 10:00:00 GMT", " Europe/Berlin ", start, start)
    assert value.clock is not None and value.timezone == "Europe/Berlin"
    assert time_of("nonsense", None, start, start).clock is None
    assert time_of(None, 5, start, start).timezone is None


# --- WAN failover (#150) and dynamic DNS (#154) ---------------------------------------------------


async def test_dynamic_dns_and_wan_health(snaps: dict[str, Snapshot]) -> None:
    for snap in snaps.values():
        [up] = snap.uplinks
        assert up.priority == 1 and up.health is not None
        assert (up.health.state.value, up.health.latency_ms) == ("online", 9)
        [dd] = snap.ddns
        assert (dd.provider, dd.hostname, dd.uplink_id, dd.last_result.value) == (
            "dyndns2",
            "home.example.dyndns.invalid",
            up.id,
            "unknown",
        )
        assert snap.gateway_groups == []  # one WAN: no group
        assert "sim-secret-token" not in snap.model_dump_json()


async def test_two_wans_are_a_failover_group() -> None:
    with running(version="10.0.26") as (sim, url):
        gateway = next(d for d in sim.data["stat/device"] if d.get("type") == "udm")
        gateway["wan2"] = {
            "name": "WAN2",
            "ip": "198.51.100.45",
            "netmask": "255.255.255.0",
            "gateway": "198.51.100.1",
            "up": False,
        }
        sim.data["rest/networkconf"].append(
            {
                "_id": "net-wan2",
                "name": "Backup",
                "purpose": "wan",
                "wan_type": "dhcp",
                "wan_networkgroup": "WAN2",
                "wan_failover_priority": 2,
                "wan_load_balance_type": "failover-only",
                "enabled": True,
            }
        )
        snap = await contract(adapter(url))
    [group] = snap.gateway_groups
    assert (group.name, group.mode.value, group.active) == ("WAN", "failover", "WAN")
    first, backup = group.members
    assert (first.tier, first.state.value if first.state else None) == (1, "online")
    assert (backup.tier, backup.state.value if backup.state else None) == (2, "down")
    assert all(m.uplink_id in {u.id for u in snap.uplinks} for m in group.members)


async def test_mesh_uplink_has_radio_details_and_membership(snaps: dict[str, Snapshot]) -> None:
    """#459: the wireless uplink of an access point is a backhaul link with radio details."""
    from signalbox.model import Band

    snap = snaps["9.0.114"]
    (link,) = [x for x in snap.wireless_links if x.b == f"{AP_2}/port/mesh"]
    assert link.a == f"{AP_1}/port/mesh" and link.origin.value == "mesh"
    w = link.wireless
    assert w is not None and (w.band, w.channel, w.signal_dbm) == (Band.GHZ_5, 36, -58)
    assert (w.tx_rate_mbps, w.rx_rate_mbps) == (866.0, 780.0)
    devices = {d.id: d for d in snap.extra_devices}
    mesh2, mesh1 = devices[AP_2].mesh, devices[AP_1].mesh
    assert mesh2 is not None and mesh2.hop == 1 and mesh2.uplink is not None
    assert mesh2.uplink.value == "wireless"
    assert mesh1 is not None and mesh1.hop == 0 and mesh1.uplink is not None
    assert mesh1.uplink.value == "wired"


def test_mesh_info_tolerates_missing_and_odd_values() -> None:
    from signalbox.adapters.unifi import mesh_info

    link = uplink_of({"mac": AP2, "uplink": {"type": "wireless", "uplink_mac": AP1, "speed": 300}})
    assert link is not None
    w = mesh_info(link)  # no radio details: only the negotiated speed
    assert (w.band, w.channel, w.signal_dbm, w.tx_rate_mbps) == (None, None, None, 300.0)
    odd = {"type": "wireless", "uplink_mac": AP1, "signal": 50, "tx_rate": 120, "channel": 0}
    link = uplink_of({"mac": AP2, "uplink": odd})
    assert link is not None
    w = mesh_info(link)
    assert (w.signal_dbm, w.channel, w.tx_rate_mbps, w.rx_rate_mbps) == (None, None, 120.0, None)


# --- multicast (#161) -------------------------------------------------------------------------


async def test_multicast_of_the_networks_on_the_gateway(snaps: dict[str, Snapshot]) -> None:
    from signalbox.model import ReflectorKind, segment_id

    gw = next(d for d in snaps["10.0.26"].extra_devices if d.id == GW)
    assert gw.multicast is not None
    by_name = {s.name: s for s in gw.multicast.settings}
    assert set(by_name) == {"LAN", "IoT"}  # the guest network does not say
    assert by_name["LAN"].igmp_snooping is True and by_name["LAN"].querier is None
    assert by_name["IoT"].segment_id == segment_id("home", 20)
    (mdns,) = gw.multicast.reflectors
    assert mdns.kind is ReflectorKind.MDNS
    assert mdns.segments == sorted([segment_id("home", None), segment_id("home", 20)])


def test_multicast_fields_of_a_network() -> None:
    from signalbox.adapters.unifi import multicast as umc
    from signalbox.model import ReflectorKind, UnknownMulticast

    nets = [
        (
            "Main",
            "s/native",
            {
                "igmp_snooping": True,
                "igmp_flood_unknown_multicast": False,
                "igmp_querier_switches": [
                    {"switch_mac": "02:00:00:00:0b:01", "querier_address": "192.0.2.5"},
                    "junk",
                ],
                "igmp_proxy_upstream": True,
                "igmp_proxy_for": "all",
            },
        ),
        ("Cams", "s/30", {"igmp_snooping": "false", "mdns_enabled": True, "igmp_proxy_for": "all"}),
        ("Odd", "s/40", {"igmp_snooping": "maybe"}),
    ]
    out = umc.multicast(nets)
    main, cams = out.settings
    assert main.unknown_multicast is UnknownMulticast.DROP
    assert str(main.observed_querier) == "192.0.2.5"
    assert cams.igmp_snooping is False and cams.observed_querier is None
    mdns, proxy = out.reflectors
    assert mdns.kind is ReflectorKind.MDNS and mdns.segments == ["s/30"]
    assert proxy.kind is ReflectorKind.IGMP_PROXY and proxy.upstream_segment_id == "s/native"
    assert proxy.upstream_interface == "Main" and proxy.segments == ["s/30", "s/native"]
    assert umc.multicast([]).settings == []


async def test_smart_queues_of_the_wan(snaps: dict[str, Snapshot]) -> None:
    """The WAN network's Smart Queues fields are an fq_codel shaper, in every version (#166)."""
    for snap in snaps.values():
        (shaper,) = snap.shapers
        assert shaper.kind.value == "fq-codel" and shaper.enabled
        assert (shaper.download_kbps, shaper.upload_kbps) == (90_000, 18_000)
        assert shaper.uplink_id is not None and shaper.uplink_id.endswith("/uplink/wan1")
