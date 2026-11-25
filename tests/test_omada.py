"""Omada adapter against its simulator, over real sockets (plain HTTP and pinned TLS)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

import httpx
import pytest
from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import SecretStr, ValidationError

from signalbox.adapters import AdapterContext, AdapterError, load_adapters
from signalbox.adapters.omada import (
    INFO,
    PAGE_SIZE,
    TOKEN,
    OmadaAdapter,
    OmadaConfig,
    _check,
    _int,
    _psk_details,
    _security,
    _width,
    ap_link,
    jumbo_of,
    radio_state,
    vitals,
)
from signalbox.model import (
    Cipher,
    DeviceHealth,
    DeviceRole,
    DeviceStatus,
    LagMode,
    Membership,
    Pmf,
    PoeStatus,
    PoeSupply,
    PortKind,
    PortPoe,
    PortRole,
    Security,
    Snapshot,
    WifiStandard,
    passphrase_digest,
    passphrase_fingerprint,
)
from signalbox.sim.omada import (
    CLIENT_ID,
    CLIENT_SECRET,
    EAP1,
    EAP2,
    OMADAC_ID,
    SITE,
    SWITCH,
    OmadaSimulator,
    create_app,
)
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract, passphrase_digest_key

SIM = OmadaSimulator()
DEV = "omada1"
SW = f"{DEV}/switch-020000000b01"
AP1 = f"{DEV}/eap-020000000c01"
AP2 = f"{DEV}/eap-020000000c02"
GW = f"{DEV}/gateway-020000000a01"
CLIENTS = f"{SITE}/clients"
SSIDS = f"{SITE}/wireless-network/wlans/wlan-default/ssids"


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
def sim() -> OmadaSimulator:
    SIM.__dict__.update(OmadaSimulator().__dict__)  # fresh data and switches every test
    return SIM


def adapter(url: str, pin: str | None = None, timeout: float = 5.0, **cfg: Any) -> OmadaAdapter:
    config = OmadaConfig(
        url=url,
        client_id=cfg.pop("client_id", CLIENT_ID),
        client_secret=SecretStr(cfg.pop("secret", CLIENT_SECRET)),
        allow_insecure_http=url.startswith("http://"),
        **cfg,
    )
    return OmadaAdapter(
        AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name="Omada",
            role=DeviceRole.OTHER,
            config=config,
            pinned_fingerprint=pin,
            timeout=timeout,
        )
    )


async def observe(a: OmadaAdapter) -> Snapshot:
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
        again = await a.observe()  # a second observation probes, pins and authorises again
    finally:
        await a.close()
    assert snap.status is again.status is DeviceStatus.OK
    assert snap.ports and snap.wlans and snap.clients


def test_entry_point_and_manifest() -> None:
    cls = load_adapters()["omada"]
    assert cls is OmadaAdapter
    assert {r.value for r in cls.manifest.roles} == {"other", "ap", "switch", "gateway"}


async def test_system(snap: Snapshot, sim: OmadaSimulator) -> None:
    d = snap.device
    assert (d.id, d.role, d.vendor, d.model) == (
        DEV,
        DeviceRole.OTHER,
        "TP-Link",
        "Omada Controller",
    )
    assert d.firmware is not None and d.firmware.current == "6.3.0.111"
    assert d.management_address == "127.0.0.1"
    assert sim.token_requests == 1


async def test_configured_controller_id_and_site_case(http_url: str, sim: OmadaSimulator) -> None:
    sim.data[INFO] = {"controllerVer": ""}  # no omadacId: the configured one is used
    snap = await observe(adapter(http_url, omadac_id=OMADAC_ID, site="default"))
    assert snap.status is DeviceStatus.OK and snap.device.firmware is None


async def test_unknown_site(http_url: str) -> None:
    snap = await observe(adapter(http_url, site="Elsewhere"))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert snap.errors[0].message == (
        "the controller has no site 'Elsewhere' (sites: Branch, Default)"
    )


async def test_no_controller_id(http_url: str, sim: OmadaSimulator) -> None:
    sim.data[INFO] = {}
    snap = await observe(adapter(http_url))
    assert "no omadacId" in snap.errors[0].message


async def test_ports_and_segments(snap: Snapshot) -> None:
    ports = {p.id: p for p in snap.ports}
    assert sorted(p for p in ports if p.startswith(SW)) == [
        f"{SW}/port/{n}" for n in [*range(1, 9), "lag1"]
    ]
    # #252: switch ports are jacks, a link aggregation group a port of role lag over its members
    assert all(
        p.role is PortRole.JACK for p in snap.ports if "lag" not in p.id and p.id.startswith(SW)
    )
    lag = ports[f"{SW}/port/lag1"]
    assert (lag.role, lag.kind, lag.external) == (PortRole.LAG, PortKind.LAG, True)
    assert lag.lower == [f"{SW}/port/2", f"{SW}/port/3"]
    assert lag.lag_mode is LagMode.LACP_ACTIVE  # #157: lagType of both members
    p1 = ports[f"{SW}/port/1"]
    assert (p1.name, p1.up, p1.speed_mbps, p1.full_duplex, p1.poe) == (
        "Switch Port1",
        True,
        2500,
        True,
        PortPoe(enabled=False, status=PoeStatus.DISABLED),
    )
    assert p1.vendor_extra == {
        "omada_device": {
            "name": "Switch",
            "mac": "02:00:00:00:0b:01",
            "type": "switch",
            "model": "TL-SG2008P",
            "firmware": "1.0.5",
        },
        "port": 1,
    }
    # port details (#156): profile, enabled, PVID from the native network, maximum, jumbo
    assert (p1.profile, p1.admin_up, p1.pvid, p1.max_speed_mbps) == ("All", True, 1, 2500)
    assert p1.jumbo is True and p1.jumbo_frames() is True
    assert ports[f"{SW}/port/7"].pvid == 20 and ports[f"{SW}/port/8"].pvid == 30  # override
    assert ports[f"{SW}/port/2"].max_speed_mbps == 1000
    assert ports[f"{SW}/port/2"].poe == PortPoe(
        enabled=True, status=PoeStatus.DELIVERING, power_w=12.3
    )  # #159
    switch = next(d for d in snap.extra_devices if d.id == SW)
    assert switch.poe == PoeSupply(budget_w=65, used_w=17.5)
    p4 = ports[f"{SW}/port/4"]
    assert (p4.up, p4.speed_mbps, p4.full_duplex) == (False, None, None)
    p5 = ports[f"{SW}/port/5"]
    assert (p5.speed_mbps, p5.full_duplex) == (100, False)
    p6 = ports[f"{SW}/port/6"]
    assert (p6.admin_up, p6.up, p6.profile) == (False, False, "LAN")

    segs = {s.id: s for s in snap.segments}
    assert sorted(segs) == ["home/segment/20", "home/segment/30", "home/segment/native"]
    native = segs["home/segment/native"]
    assert (native.vlan, native.name) == (None, "LAN")
    assert {m.port_id.rsplit("/", 1)[1] for m in native.members} == {"1", "2", "3", "4", "5", "6"}
    assert all(m.mode is Membership.UNTAGGED for m in native.members)
    iot = {m.port_id.rsplit("/", 1)[1]: m.mode for m in segs["home/segment/20"].members}
    assert iot == {
        "1": Membership.TAGGED,
        "2": Membership.TAGGED,
        "3": Membership.TAGGED,
        "7": Membership.UNTAGGED,
    }
    guest = {m.port_id.rsplit("/", 1)[1]: m.mode for m in segs["home/segment/30"].members}
    assert guest["8"] is Membership.UNTAGGED  # the port-level override wins over the profile
    assert segs["home/segment/30"].vlan == 30


async def test_subnets_and_dhcp(snap: Snapshot) -> None:
    subnets = {s.id: s for s in snap.subnets}
    assert sorted(subnets) == [f"{GW}/subnet/net-iot", f"{GW}/subnet/net-lan"]
    lan = subnets[f"{GW}/subnet/net-lan"]
    assert (str(lan.interface), lan.segment_id, lan.gateway) == (
        "192.0.2.1/24",
        "home/segment/native",
        True,
    )
    assert lan.vendor_extra["omada_device"]["model"] == "ER605 v2.0"  # type: ignore[index]

    servers = {s.id: s for s in snap.dhcp_servers}
    assert sorted(servers) == [f"{GW}/dhcp/net-iot", f"{GW}/dhcp/net-lan"]
    s = servers[f"{GW}/dhcp/net-lan"]
    assert s.enabled and s.lease_seconds == 7200 and s.domain == "lan.example"
    assert [(str(p.start), str(p.end)) for p in s.pools] == [("192.0.2.100", "192.0.2.199")]
    assert s.router == ip_address("192.0.2.1") and s.dns_servers == [ip_address("192.0.2.1")]
    iot = servers[f"{GW}/dhcp/net-iot"]
    assert iot.router == ip_address("198.51.100.1")  # no gateway option: the interface
    assert iot.dns_servers == [ip_address("198.51.100.1"), ip_address("192.0.2.53")]


async def test_wireless(snap: Snapshot) -> None:
    radios = {r.id: r for r in snap.radios}
    assert sorted(radios) == [
        f"{AP1}/radio/2g",
        f"{AP1}/radio/5g",
        f"{AP2}/radio/2g",
        f"{AP2}/radio/5g",
    ]
    r = radios[f"{AP1}/radio/5g"]
    assert (r.name, r.band.value, r.channel, r.width_mhz, r.tx_power_dbm, r.enabled) == (
        "AP 1 5 GHz",
        "5",
        36,
        80,
        23,
        True,
    )
    off = radios[f"{AP2}/radio/5g"]
    assert (off.enabled, off.channel, off.width_mhz) == (False, None, None)

    wlans = {w.id: w for w in snap.wlans}
    assert len(wlans) == 10  # Home and Guest on both bands, IoT on 2.4 GHz, on two EAPs
    home = wlans[f"{AP1}/wlan/ssid-home-5g"]
    assert (home.ssid, home.security, home.pmf, home.segment_id, home.hidden) == (
        "Home",
        Security.WPA2,
        Pmf.OPTIONAL,
        "home/segment/native",
        False,
    )
    # the SSID detail has the passphrase: only its fingerprint is kept
    assert home.passphrase_fingerprint == passphrase_fingerprint("Home", "example-home-passphrase")
    assert home.vendor_extra["wlan_group"] == "Default"
    iot = wlans[f"{AP2}/wlan/ssid-iot-2g"]  # EAP 2 names no WLAN group: the primary one
    assert iot.hidden and iot.segment_id == "home/segment/20" and iot.passphrase_fingerprint
    assert iot.passphrase_fingerprint == wlans[f"{AP1}/wlan/ssid-iot-2g"].passphrase_fingerprint
    guest = wlans[f"{AP1}/wlan/ssid-guest-2g"]
    assert guest.security is Security.OPEN
    # the Omada guest network flag is a reported purpose; isolation is not read
    assert (guest.purpose, guest.purpose_source) == ("guest", "reported")
    assert guest.client_isolation is None and home.purpose is None
    assert not wlans[f"{AP2}/wlan/ssid-home-5g"].enabled  # its radio is off


async def test_wifi_security_details(http_url: str) -> None:
    with passphrase_digest_key():
        snap = await observe(adapter(http_url))
        home_digest = passphrase_digest("example-home-passphrase")
        iot_digest = passphrase_digest("example-iot-passphrase")
    wlans = {w.id: w for w in snap.wlans}
    home = wlans[f"{AP1}/wlan/ssid-home-5g"]
    iot = wlans[f"{AP1}/wlan/ssid-iot-2g"]
    assert home_digest != iot_digest
    assert (home.passphrase_digest, iot.passphrase_digest) == (home_digest, iot_digest)
    assert home.ciphers == [Cipher.CCMP] and home.key_rotation_seconds == 0
    assert iot.ciphers == [Cipher.TKIP, Cipher.CCMP] and iot.key_rotation_seconds == 3600
    guest = wlans[f"{AP1}/wlan/ssid-guest-2g"]
    assert guest.passphrase_digest is None and guest.ciphers is None
    for w in snap.wlans:  # not in the Open API
        assert w.wps is None and w.sae is None and w.group_cipher is None
        assert w.beacon_protection is None
    assert all(r.supported_security is None for r in snap.radios)


def test_psk_details() -> None:
    def psk(**kw: Any) -> dict[str, Any]:
        return {"pskSetting": kw}

    assert _psk_details(psk(encryptionPsk=2), Security.WPA)["ciphers"] == [Cipher.TKIP]
    assert _psk_details(psk(), Security.WPA2) == {"ciphers": None}
    assert _psk_details(psk(gikRekeyPskEnable=True), Security.WPA2)["key_rotation_seconds"] is None
    assert _psk_details(psk(gikRekeyPskEnable=True, rekeyPskInterval=0), Security.WPA2) == {
        "ciphers": None,
        "key_rotation_seconds": None,
    }
    assert _psk_details(psk(encryptionPsk=3), Security.OPEN) == {}
    assert _psk_details(psk(encryptionPsk=3), Security.WPA2_ENTERPRISE) == {}


async def test_clients(snap: Snapshot) -> None:
    by_mac = {c.mac: c for c in snap.clients}
    assert sorted(by_mac) == [
        "02:00:00:00:00:10",
        "02:00:00:00:00:20",
        "02:00:00:00:00:21",
        "02:00:00:00:00:30",
        "02:00:00:00:00:31",
    ]
    laptop = by_mac["02:00:00:00:00:21"]
    assert [str(a) for a in laptop.addresses] == ["192.0.2.100", "2001:db8:1::21"]
    assert laptop.seen_on == f"{AP1}/wlan/ssid-home-5g"
    assert laptop.segment_id == "home/segment/native"
    assert laptop.last_seen == datetime(2026, 1, 1, tzinfo=UTC)
    assert by_mac["02:00:00:00:00:20"].seen_on == f"{AP2}/wlan/ssid-iot-2g"
    printer = by_mac["02:00:00:00:00:10"]
    assert printer.seen_on == f"{SW}/port/5" and printer.hostname == "printer"
    # wired clients with their switch port are that switch's table entries (#160)
    assert [(e.device_id, e.port_id, e.mac, e.vlan) for e in snap.fdb] == [
        (SW, f"{SW}/port/5", "02:00:00:00:00:10", 1),
        (SW, f"{SW}/port/7", "02:00:00:00:00:30", 20),
    ]
    assert by_mac["02:00:00:00:00:30"].segment_id == "home/segment/20"
    guest = by_mac["02:00:00:00:00:31"]
    assert guest.hostname is None and guest.segment_id == "home/segment/30"  # by network name
    assert guest.addresses == []


# --- paging ----------------------------------------------------------------------------------


async def test_paging(http_url: str, sim: OmadaSimulator) -> None:
    sim.page_limit = 2  # the controller returns smaller pages than asked for
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK and len(snap.clients) == 5 and len(snap.ports) == 13
    assert sim.requests.count(CLIENTS) == 3


async def test_paging_many_rows(http_url: str, sim: OmadaSimulator) -> None:
    template = sim.data[CLIENTS][0]
    sim.data[CLIENTS] = [
        {**template, "mac": f"02-00-00-00-{i // 256:02X}-{i % 256:02X}", "ip": ""}
        for i in range(PAGE_SIZE + 5)
    ]
    snap = await observe(adapter(http_url))
    assert len(snap.clients) == PAGE_SIZE + 5 and sim.requests.count(CLIENTS) == 2


async def test_plain_list_and_missing_total(http_url: str) -> None:
    class Plain(OmadaSimulator):
        """Port lists as plain lists, every other list as a page without ``totalRows``."""

        def _page(self, value: Any, request: Request) -> Any:
            if not isinstance(value, list) or request.url.path.endswith("/ports"):
                return value
            return {"data": value}

    with serve(Plain().app()) as url:
        snap = await observe(adapter(url))
    assert snap.status is DeviceStatus.OK, snap.errors
    assert len(snap.ports) == 13 and len(snap.clients) == 5


# --- refused paths ---------------------------------------------------------------------------


async def test_wrong_client_secret(http_url: str, sim: OmadaSimulator) -> None:
    snap = await observe(adapter(http_url, secret="wrong"))
    assert snap.status is DeviceStatus.AUTH_FAILED
    msg = snap.errors[0].message
    assert "refused the client credentials" in msg and "-44106" in msg
    assert "wrong" not in msg


async def test_token_expired_once_is_renewed(http_url: str, sim: OmadaSimulator) -> None:
    sim.expire_next = True
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK
    assert sim.token_requests == 2


async def test_token_refused_again_is_partial(http_url: str, sim: OmadaSimulator) -> None:
    sim.error = {CLIENTS: (-44112, "The access token has expired.")}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert [(e.capability, e.message) for e in snap.errors] == [
        (
            "clients",
            f"{CLIENTS}: the controller refused the access token (The access token has expired.)",
        )
    ]
    assert sim.token_requests == 2  # renewed once, not in a loop


async def test_error_code_is_partial(http_url: str, sim: OmadaSimulator) -> None:
    sim.error = {CLIENTS: (-1001, "Invalid request parameters.")}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert [(e.capability, e.message) for e in snap.errors] == [
        ("clients", f"{CLIENTS}: Omada error -1001: Invalid request parameters.")
    ]
    assert snap.ports and snap.wlans and not snap.clients


async def test_certificate_not_pinned(https_url: str, tls: TlsFiles, sim: OmadaSimulator) -> None:
    snap = await observe(adapter(https_url))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert tls.fingerprint in snap.errors[0].message
    assert sim.requests == [] and sim.token_requests == 0  # no credential was sent


async def test_pin_mismatch(https_url: str, sim: OmadaSimulator) -> None:
    snap = await observe(adapter(https_url, pin="ab" * 32))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert "new certificate" in snap.errors[0].message and sim.requests == []


@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_unreachable(scheme: str) -> None:
    snap = await observe(adapter(f"{scheme}://127.0.0.1:{free_port()}"))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "127.0.0.1" in snap.errors[0].message


async def test_timeout(http_url: str, sim: OmadaSimulator) -> None:
    sim.delay = 1.0
    snap = await observe(adapter(http_url, timeout=0.2))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "within 0.2 s" in snap.errors[0].message


async def test_malformed_json_is_partial(http_url: str, sim: OmadaSimulator) -> None:
    sim.malformed = {CLIENTS}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.PARTIAL
    assert [(e.capability, e.message) for e in snap.errors] == [
        ("clients", f"{CLIENTS}: answer is not valid JSON")
    ]


@pytest.mark.parametrize(
    ("path", "value", "capability", "needle"),
    [
        (INFO, "x", "system", "result is str, expected an object"),
        (f"{SITE}/lan-networks", {"rows": []}, "interfaces", "no list of data"),
    ],
)
async def test_unexpected_shapes(
    http_url: str, sim: OmadaSimulator, path: str, value: Any, capability: str, needle: str
) -> None:
    sim.data[path] = value
    snap = await observe(adapter(http_url))
    errors = {e.capability: e.message for e in snap.errors}
    assert needle in errors[capability]


async def test_answer_without_error_code_and_token() -> None:
    class Odd(OmadaSimulator):
        def _token(self, body: Any) -> JSONResponse:
            return JSONResponse({"errorCode": 0, "result": {"tokenType": "bearer"}})

    with serve(Odd().app()) as url:
        snap = await observe(adapter(url))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert snap.errors[0].message == f"unexpected answer from {TOKEN}: no accessToken"
    with pytest.raises(AdapterError, match="no errorCode"):
        _check({"result": 1}, "/x")


# --- missing and odd data --------------------------------------------------------------------


async def test_optional_endpoints_absent(http_url: str, sim: OmadaSimulator) -> None:
    del sim.data[f"{SITE}/lan-profiles"]
    del sim.data[f"{SITE}/aps/{EAP1}/radio-config"]
    sim.error = {f"{SITE}/aps/{EAP2}/radio-config": (-39303, "AP does not exist.")}
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors
    native = next(s for s in snap.segments if s.id == "home/segment/native")
    assert native.members == []  # without the profiles only the port override is known
    guest = next(s for s in snap.segments if s.id == "home/segment/30")
    assert [m.port_id for m in guest.members] == [f"{SW}/port/8"]
    # Radios derived from the SSIDs' bands, details unknown.
    radios = {r.id: r for r in snap.radios}
    assert sorted(radios) == [
        f"{AP1}/radio/2g",
        f"{AP1}/radio/5g",
        f"{AP2}/radio/2g",
        f"{AP2}/radio/5g",
    ]
    assert radios[f"{AP1}/radio/5g"].channel is None and radios[f"{AP1}/radio/5g"].enabled


async def test_wireless_failure_keeps_clients(http_url: str, sim: OmadaSimulator) -> None:
    sim.error = {SSIDS: (-1001, "nope")}
    snap = await observe(adapter(http_url))
    assert [e.capability for e in snap.errors] == ["wireless"]
    by_mac = {c.mac: c for c in snap.clients}
    assert by_mac["02:00:00:00:00:21"].seen_on is None  # its WLAN is not known
    assert by_mac["02:00:00:00:00:10"].seen_on == f"{SW}/port/5"


async def test_no_gateway_and_odd_data(http_url: str, sim: OmadaSimulator) -> None:
    devices = sim.data[f"{SITE}/devices"]
    devices[:] = [d for d in devices if d["type"] != "gateway"]
    devices += [{"mac": "nonsense", "type": "ap"}, {"mac": "02-00-00-00-0D-01", "type": "olt"}]
    devices[2]["wlanId"] = "wlan-unknown"  # EAP 2: an unknown group falls back to the primary
    nets = sim.data[f"{SITE}/lan-networks"]
    nets += [{"id": "net-bad", "vlan": 5000}, {"name": "no id", "vlan": 40}]
    nets.append({"id": "net-x", "vlan": 50, "gatewaySubnet": "bad", "dhcpSettings": {"enable": 1}})
    ports = sim.data[f"{SITE}/switches/{SWITCH}/ports"]
    ports += [{"name": "no number"}, {"port": 9, "tagNetworkIds": ["net-iot", "net-unknown"]}]
    ports[0]["tagNetworkIds"] = ["net-lan", "net-iot"]  # native again as tagged: stays untagged
    ssids = sim.data[SSIDS]
    ssids += [
        {"name": "", "band": 1},
        {"ssidId": "ssid-lab", "name": "Lab", "band": 4, "security": 3, "vlanEnable": True},
        {"ssidId": "ssid-x", "name": "X", "band": 1, "vlanEnable": True, "vlanId": 99},
    ]
    sim.data[CLIENTS] += [
        {"mac": "02-00-00-00-0B-01"},  # the switch itself
        {"mac": "nonsense"},
        {"mac": "02-00-00-00-00-21"},  # twice
        {
            "mac": "02-00-00-00-00-40",
            "wireless": False,
            "switchMac": "02-00-00-00-FF-FF",
            "port": 1,
        },
        {"mac": "02-00-00-00-00-41", "wireless": True, "apMac": "", "ipv6List": ["fe80::1", "x"]},
    ]
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK, snap.errors
    assert sorted(s.id for s in snap.subnets) == [
        f"{DEV}/gateway/subnet/net-iot",
        f"{DEV}/gateway/subnet/net-lan",
    ]
    assert "network" in snap.subnets[0].vendor_extra
    x = next(s for s in snap.dhcp_servers if s.id == f"{DEV}/gateway/dhcp/net-x")
    assert x.enabled and x.pools == [] and x.router is None and x.dns_servers == []
    assert "home/segment/50" in {s.id for s in snap.segments}
    native = next(s for s in snap.segments if s.id == "home/segment/native")
    assert (f"{SW}/port/1", Membership.UNTAGGED) in [(m.port_id, m.mode) for m in native.members]
    p9 = next(p for p in snap.ports if p.id == f"{SW}/port/9")
    assert p9.up is None and p9.name == "Switch Port9"
    wlans = {w.id: w for w in snap.wlans}
    assert f"{AP1}/wlan/ssid-lab-6g" not in wlans  # no 6 GHz radio
    xw = wlans[f"{AP2}/wlan/ssid-x-2g"]
    assert xw.segment_id is None and xw.vendor_extra["vlan"] == 99
    assert xw.security is Security.OTHER
    by_mac = {c.mac: c for c in snap.clients}
    assert "02:00:00:00:0b:01" not in by_mac and len(by_mac) == 7
    assert by_mac["02:00:00:00:00:40"].seen_on is None
    assert (
        by_mac["02:00:00:00:00:41"].addresses == [] and by_mac["02:00:00:00:00:41"].seen_on is None
    )


def test_security_mapping() -> None:
    assert _security({"security": 0, "oweEnable": True}) is Security.OWE
    assert _security({"security": 0}) is Security.OPEN
    assert _security({"security": 1}) is Security.OTHER  # no such mode
    assert _security({"security": 2}) is Security.WPA2_ENTERPRISE
    assert _security({"security": 2, "entSetting": {"versionEnt": 4}}) is Security.WPA3_ENTERPRISE
    assert _security({"security": 3, "pskSetting": {"versionPsk": 4}}) is Security.WPA2_WPA3
    assert _security({"security": 3, "pskSetting": {"versionPsk": 3}}) is Security.WPA_WPA2
    assert _security({"security": 3, "pskSetting": {"versionPsk": 1}}) is Security.WPA
    assert _security({"security": 2, "entSetting": {"versionEnt": 1}}) is Security.WPA_ENTERPRISE
    assert _security({"security": 2, "entSetting": {"versionEnt": 3}}) is Security.WPA_ENTERPRISE
    assert _security({"security": 2, "entSetting": {"versionEnt": 2}}) is Security.WPA2_ENTERPRISE
    assert _security({"security": 3, "pskSetting": {"versionPsk": 9}}) is Security.OTHER
    assert _security({"security": 3}) is Security.WPA2
    assert _security({"security": 5}) is Security.OTHER
    assert _width("160") == 160 and _width("5") == 80 and _width("6") is None  # 6: auto
    assert _width("2") == 20 and _width("99") is None
    assert jumbo_of(None) is None and jumbo_of({"jumbo": "1518"}) is False
    assert jumbo_of({"jumbo": True}) is True and jumbo_of({"jumbo": "x"}) is None
    assert _int(True) is None and _int("-3") == -3 and _int(None) is None


# --- config and simulator --------------------------------------------------------------------


def test_config_validation() -> None:
    def cfg(url: str, insecure: bool = False) -> OmadaConfig:
        return OmadaConfig(
            url=url, client_id="c", client_secret=SecretStr("s"), allow_insecure_http=insecure
        )

    c = cfg("https://192.0.2.5:8043/")
    assert (c.url, c.site, c.omadac_id) == ("https://192.0.2.5:8043", "Default", "")
    with pytest.raises(ValidationError, match="allow_insecure_http"):
        cfg("http://192.0.2.5")
    with pytest.raises(ValidationError, match="device's address"):
        cfg("ftp://192.0.2.5")
    schema = OmadaConfig.model_json_schema()
    assert schema["properties"]["client_secret"]["format"] == "password"


async def test_simulator_odd_requests(http_url: str) -> None:
    async with httpx.AsyncClient(base_url=http_url, trust_env=False) as client:
        r = await client.post("/openapi/authorize/token?grant_type=password", json={})
        assert r.json()["errorCode"] == -44111
        r = await client.post("/openapi/authorize/token?grant_type=client_credentials", content="x")
        assert r.json()["errorCode"] == -44106
        r = await client.get(f"/openapi/v1/{OMADAC_ID}/sites")
        assert (r.status_code, r.json()["errorCode"]) == (401, -44116)
        r = await client.get(f"/openapi/v1/{OMADAC_ID}/sites", headers={"Authorization": "x"})
        assert r.json()["errorCode"] == -44116
        bogus = {"Authorization": "AccessToken=AT-bogus"}
        r = await client.get(f"/openapi/v1/{OMADAC_ID}/sites", headers=bogus)
        assert r.json()["errorCode"] == -44112  # a token never issued reads as expired
        body = {"omadacId": OMADAC_ID, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}
        r = await client.post("/openapi/authorize/token?grant_type=client_credentials", json=body)
        token = r.json()["result"]["accessToken"]
        headers = {"Authorization": f"AccessToken={token}"}
        r = await client.get(f"/openapi/v1/{OMADAC_ID}/sites?page=x", headers=headers)
        assert r.json() == {"errorCode": 0, "msg": "Success."}
        r = await client.get(f"{SITE}/nothing", headers=headers)
        assert r.status_code == 404
    assert create_app() is not None
    assert EAP1 != EAP2


async def test_managed_devices_are_reported_as_devices(https_url: str, tls: TlsFiles) -> None:
    from signalbox.merge import merge
    from signalbox.model import Site

    a = adapter(https_url, pin=tls.fingerprint)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    roles = {d.role.value for d in snap.extra_devices}
    assert {"gateway", "switch", "ap"} <= roles
    assert all(d.managed_by == snap.device.id for d in snap.extra_devices)
    owners = {d.id for d in snap.extra_devices}
    assert {p.device_id for p in snap.ports} <= owners
    assert {r.device_id for r in snap.radios} <= owners
    net = merge([Site(id=snap.device.site_id, name="Home")], [snap])
    assert len(net.devices) == 1 + len(snap.extra_devices)
    assert all(net.statuses[d.id] == snap.status for d in net.devices)


# --- health and time (#178, #179) ------------------------------------------------------------


async def test_health_of_the_managed_devices(snap: Snapshot) -> None:
    by_name = {d.name: d.health for d in snap.extra_devices}
    gw, sw, ap1, ap2 = (by_name[n] for n in ("Gateway", "Switch", "AP 1", "AP 2"))
    assert gw is not None and sw is not None and ap1 is not None and ap2 is not None
    assert (gw.uptime_seconds, gw.cpu_load_pct) == (((12 * 24 + 3) * 60 + 4) * 60 + 5, 7)
    assert (ap1.uptime_seconds, ap1.cpu_load_pct) == ((3 * 60 + 4) * 60 + 5, 12)
    assert (ap2.uptime_seconds, ap2.cpu_load_pct) == (86400, 5)
    assert gw.boot_time is not None and gw.memory_used_bytes is None  # memUtil: percent only
    assert snap.device.health == DeviceHealth()  # the controller's host is not described


async def test_health_guesses_and_odd_rows(http_url: str, sim: OmadaSimulator) -> None:
    rows = sim.data[f"{SITE}/devices"]
    rows[0] |= {"temp": 48.5, "fanStatus": "Normal", "powerStatus": "abnormal", "cpuUtil": 140}
    rows[1] |= {"uptime": "2 days 04:05:06", "fanStatus": 1, "powerStatus": None}
    rows[2] |= {"uptime": "soon"}
    rows[3] |= {"uptimeLong": -1, "uptime": 60.0, "temperature": "hot"}
    snap = await observe(adapter(http_url))
    by_name = {d.name: d.health for d in snap.extra_devices}
    gw, sw, ap1, ap2 = (by_name[n] for n in ("Gateway", "Switch", "AP 1", "AP 2"))
    assert gw is not None and sw is not None and ap1 is not None and ap2 is not None
    assert [(t.name, t.value_c) for t in gw.temperatures] == [("device", 48.5)]
    assert [(f.name, f.ok) for f in gw.fans] == [("fan", True)]
    assert [(p.name, p.ok) for p in gw.power_supplies] == [("power", False)]
    assert gw.cpu_load_pct is None
    assert sw.uptime_seconds == ((2 * 24 + 4) * 60 + 5) * 60 + 6 and sw.fans == []
    assert ap1.uptime_seconds is None and ap2.uptime_seconds == 60 and ap2.temperatures == []


async def test_time_of_the_controller(http_url: str, sim: OmadaSimulator) -> None:
    sim.data[f"/openapi/v1/{OMADAC_ID}/sites"][0]["timeZone"] = "Europe/Berlin"
    snap = await observe(adapter(http_url))
    t = snap.device.time
    assert t is not None and t.clock is not None and t.timezone == "Europe/Berlin"
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 2
    assert t.ntp_client is None and t.ntp_server is None
    assert all(d.time is None for d in snap.extra_devices)


def test_time_and_uptime_helpers() -> None:
    start = datetime(2026, 11, 22, 16, tzinfo=UTC)
    t = vitals.time_of("Sun, 22 Nov 2026 16:00:00 GMT", " ", start, start)
    assert t.offset_seconds() == 0.5 and t.timezone is None
    for bad in (None, "", "yesterday", "Sun, 22 Nov 2026 16:00:00 -0000"):
        assert vitals.time_of(bad, "UTC", start, start).clock is None
    assert vitals.uptime({"uptime": "1d 2h"}) == 93600 and vitals.uptime({"uptime": True}) is None
    assert vitals.uptime({}) is None


# --- management services (#173) --------------------------------------------------------------


async def test_services_of_every_managed_device(snap: Snapshot) -> None:
    ids = {d.id for d in snap.extra_devices}
    by = {s.id: s for s in snap.services}
    cloud = by.pop(f"{snap.device.id}/service/omada-cloud")
    assert (cloud.kind.value, cloud.enabled, cloud.label()) == ("cloud", True, "Omada Cloud access")
    assert {s.device_id for s in by.values()} == ids
    assert len(by) == 2 * len(ids)
    for device in ids:
        ssh, snmp = by[f"{device}/service/ssh"], by[f"{device}/service/snmp"]
        assert (ssh.kind.value, ssh.enabled, ssh.port, ssh.encrypted) == ("ssh", True, 22, True)
        assert snmp.enabled and snmp.port == 161 and snmp.snmp is not None
        assert snmp.snmp.default_community and snmp.snmp.v3_privacy
        assert [v.value for v in snmp.snmp.versions] == ["2c", "3"]
        assert snmp.encrypted is False  # v2c answers too
    assert snap.device.transport_encrypted is False  # the plain-HTTP simulator


async def test_services_follow_the_site_settings(http_url: str, sim: OmadaSimulator) -> None:
    sim.data[f"{SITE}/ssh"] = {"sshEnable": False, "sshServerPort": 2222}
    sim.data[f"{SITE}/setting/service/snmp"] = {
        "snmpV1V2CEnable": False,
        "snmpV3Enable": True,
        "securityLevel": 1,
        "communityString": "public",
    }
    snap = await observe(adapter(http_url))
    ssh = next(s for s in snap.services if s.kind.value == "ssh")
    assert (ssh.enabled, ssh.port) == (False, 2222)
    snmp = next(s for s in snap.services if s.kind.value == "snmp")
    assert snmp.snmp is not None
    assert [v.value for v in snmp.snmp.versions] == ["3"] and snmp.snmp.v3_privacy is False
    assert snmp.snmp.default_community is None  # v1/v2c is off: the community is not used


async def test_cloud_access_follows_the_controller_setting(
    http_url: str, sim: OmadaSimulator
) -> None:
    sim.data[f"/openapi/v1/{OMADAC_ID}/cloud-access"] = {"enable": False}
    snap = await observe(adapter(http_url))
    (cloud,) = [s for s in snap.services if s.kind.value == "cloud"]
    assert not cloud.enabled
    sim.data[f"/openapi/v1/{OMADAC_ID}/cloud-access"] = {"somethingElse": 1}
    snap = await observe(adapter(http_url))
    assert not [s for s in snap.services if s.kind.value == "cloud"]  # unknown shape: not read


# --- log targets (#327) ------------------------------------------------------------------------


async def test_remote_syslog_of_the_site(snap: Snapshot) -> None:
    ids = {d.id for d in snap.extra_devices}
    assert ids and {d.id for d in snap.extra_devices if d.log_targets} == ids
    for d in snap.extra_devices:
        (t,) = d.log_targets or []
        assert (t.kind.value, t.address, t.port, t.transport.value, t.enabled, t.name) == (
            "syslog",
            "192.0.2.50",
            514,
            "udp",
            True,
            "site",
        )
    assert snap.device.log_targets is None  # the controller itself is not read


async def test_remote_syslog_off_or_missing(http_url: str, sim: OmadaSimulator) -> None:
    sim.data[f"{SITE}/setting/service/logging"] = {"enable": False, "serverIp": "", "serverPort": 0}
    snap = await observe(adapter(http_url))
    assert all(d.log_targets == [] for d in snap.extra_devices)  # read: sends nothing
    sim.data[f"{SITE}/setting/service/logging"] = {"enable": False, "serverIp": "192.0.2.51"}
    snap = await observe(adapter(http_url))
    assert [t.enabled for t in snap.extra_devices[0].log_targets or []] == [False]
    del sim.data[f"{SITE}/setting/service/logging"]
    snap = await observe(adapter(http_url))
    assert all(d.log_targets is None for d in snap.extra_devices) and not snap.errors


async def test_services_not_read_when_the_controller_has_no_such_setting(
    http_url: str, sim: OmadaSimulator
) -> None:
    del sim.data[f"{SITE}/ssh"]
    del sim.data[f"{SITE}/setting/service/snmp"]
    del sim.data[f"/openapi/v1/{OMADAC_ID}/cloud-access"]
    snap = await observe(adapter(http_url))
    assert snap.services == [] and not snap.errors


async def test_access_point_uplinks(snap: Snapshot) -> None:
    """AP 1 hangs on switch port 5 (wired), AP 2 on AP 1 by mesh (#336)."""
    ports = {p.id: p for p in snap.ports}
    ap1, ap2 = "omada1/eap-020000000c01", "omada1/eap-020000000c02"
    assert ports[f"{ap1}/port/1"].name == "AP 1 ETH1" and ports[f"{ap1}/port/1"].up is True
    assert ports[f"{ap1}/port/1"].speed_mbps == 1000
    assert ports[f"{ap2}/port/mesh"].kind.value == "wireless"
    by_local = {n.local_port_id: n for n in snap.neighbours}
    wired = by_local[f"{ap1}/port/1"]
    assert wired.remote_port == "Switch Port5" and wired.system_name == "Switch"
    assert wired.chassis_id == "02:00:00:00:0b:01" and not wired.wireless
    mesh = by_local[f"{ap2}/port/mesh"]
    assert mesh.wireless and mesh.remote_port == "AP 1 Mesh"
    assert len(snap.neighbours) == 2


def test_ap_link_shapes() -> None:
    mac = "02-00-00-00-0B-01"
    assert ap_link({}, {}) is None
    wired = ap_link({"uplinkMac": mac, "uplinkPort": "Port3", "linkSpeed": 4}, {})
    assert wired is not None and wired.port == "Port3" and wired.speed == 2500 and not wired.mesh
    # a mesh uplink under the camel-case spelling; not wireless-linked: wired fields win
    info = {"wirelessUpLinkInfo": {"uplinkMac": mac}, "wirelessLinked": True}
    mesh = ap_link({}, info)
    assert mesh is not None and mesh.mesh and mesh.parent == "02:00:00:00:0b:01"
    assert ap_link({}, {**info, "wirelessLinked": False}) is None


async def test_ap_uplink_edge_cases(http_url: str, sim: OmadaSimulator) -> None:
    # to itself, to an unknown AP, then no AP detail at all
    sim.data[f"{SITE}/aps/{EAP1}"]["uplinkDeviceMac"] = EAP1
    sim.data[f"{SITE}/aps/{EAP2}"]["wireless uplink info"]["uplinkMac"] = "02-00-00-00-0C-99"
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK and snap.neighbours == []
    del sim.data[f"{SITE}/aps/{EAP1}"], sim.data[f"{SITE}/aps/{EAP2}"]
    snap = await observe(adapter(http_url))
    assert snap.status is DeviceStatus.OK and snap.neighbours == []
    assert [p.name for p in snap.ports if "ETH1" in p.name] == ["AP 1 ETH1", "AP 2 ETH1"]


async def test_ap_uplink_port_names(http_url: str, sim: OmadaSimulator) -> None:
    sim.data[f"{SITE}/aps/{EAP1}"]["uplinkDevicePort"] = "no digits"
    sim.data[f"{SITE}/aps/{EAP2}"] = {**sim.data[f"{SITE}/aps/{EAP1}"], "uplinkDevicePort": "99"}
    snap = await observe(adapter(http_url))
    assert sorted(n.remote_port or "" for n in snap.neighbours) == ["99", "no digits"]


# --- accounts (#175) -------------------------------------------------------------------------


async def test_controller_users_and_the_site_device_account(
    sim: OmadaSimulator, http_url: str
) -> None:
    from signalbox.adapters.omada import omada_role
    from signalbox.model import AccountPrivilege
    from signalbox.sim.omada import OMADAC_ID, SITE

    a = adapter(http_url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert [(x.name, x.privilege) for x in snap.device.accounts or []] == [
        ("owner", AccountPrivilege.ADMIN),
        ("helpdesk", AccountPrivilege.READ),
    ]
    assert snap.extra_devices
    for d in snap.extra_devices:
        (acc,) = d.accounts or []
        assert (acc.name, acc.privilege, acc.password_set) == (
            "admin",
            AccountPrivilege.ADMIN,
            True,
        )
        assert d.default_credentials is False
    assert "example-device-secret" not in snap.model_dump_json()
    sim.data[f"{SITE}/device-account"] = {"username": "admin", "password": "admin"}
    sim.data[f"/openapi/v1/{OMADAC_ID}/users"] = [{"userName": "x", "disable": True}]
    snap = await observe(adapter(http_url))
    assert all(d.default_credentials is True for d in snap.extra_devices)
    (only,) = snap.device.accounts or []
    assert (only.name, only.privilege, only.enabled) == ("x", None, False)
    sim.data[f"{SITE}/device-account"] = {"username": "admin", "password": "******"}
    del sim.data[f"/openapi/v1/{OMADAC_ID}/users"]
    snap = await observe(adapter(http_url))
    assert all(d.default_credentials is None for d in snap.extra_devices)
    assert snap.device.accounts is None
    del sim.data[f"{SITE}/device-account"]
    snap = await observe(adapter(http_url))
    assert all(d.accounts is None for d in snap.extra_devices)
    # refused (not "no accounts") is an optional gap (#349); a missing endpoint is not
    sim.data[f"{SITE}/device-account"] = {"username": "admin", "password": "x"}
    sim.error = {f"/openapi/v1/{OMADAC_ID}/users": (-1005, "no permission")}
    snap = await observe(adapter(http_url))
    assert snap.device.accounts is None
    (gap,) = [e for e in snap.errors if e.message.startswith("accounts")]
    assert gap.optional and gap.message_id == "omada.accounts"
    assert snap.status.value == "ok"
    assert omada_role({"roleName": "Operator"}) is AccountPrivilege.OTHER
    assert omada_role({"role": "read-only"}) is AccountPrivilege.READ


# radio state (#172) ---------------------------------------------------------------------------


async def test_radio_state(snap: Snapshot) -> None:
    radios = {r.id: r for r in snap.radios}
    r2, r5 = radios[f"{AP1}/radio/2g"], radios[f"{AP1}/radio/5g"]
    assert (r2.standard, r2.channel_utilisation_pct, r2.interference_pct) == (
        WifiStandard.AX,
        35.0,
        12.0,
    )
    assert (r2.client_count, r2.channel_auto, r5.client_count) == (1, False, 2)
    off = radios[f"{AP2}/radio/5g"]  # no state in its detail, channel 0: automatic
    assert (off.standard, off.client_count, off.channel_auto) == (None, None, True)


def test_radio_state_fields() -> None:
    wp = {"rdMode": "802.11a/n/ac", "channelUtil": "40%", "interUtil": "odd", "txUtil": 1}
    assert radio_state({"wp5g": wp, "clientNum5g": -1}, "5g") == {
        "standard": WifiStandard.AC,
        "channel_utilisation_pct": 40.0,
    }
    assert radio_state({"wp2g": {"txUtil": 70, "rxUtil": 30, "interUtil": 20}}, "2g") == {
        "channel_utilisation_pct": 100.0,
        "interference_pct": 20.0,
    }
    assert radio_state({"wp6g": {"channelUtil": 120, "rdMode": ""}}, "6g") == {}
    assert radio_state({"wp6g": "odd", "clientNum6g": True}, "6g") == {}


async def test_users_in_client_mode_are_a_known_limit_and_asked_once(
    sim: OmadaSimulator, http_url: str
) -> None:
    """Controller 6.3 answers -44118 to client credentials (#354): its own gap, no retry."""
    from signalbox.sim.omada import OMADAC_ID

    users = f"/openapi/v1/{OMADAC_ID}/users"
    sim.error = {users: (-44118, "This interface only supports the authorization code mode")}
    a = adapter(http_url)
    try:
        first = await a.observe()
        second = await a.observe()
    finally:
        await a.close()
    for snap in (first, second):
        (gap,) = [e for e in snap.errors if e.message.startswith("accounts")]
        assert gap.optional and gap.message_id == "omada.accounts.client_mode"
        assert gap.fix_id == "omada.accounts.client_mode.fix"
        assert "authorization-code mode; Signalbox uses client mode" in gap.message
        assert snap.status.value == "ok"
    assert sim.requests.count(users) == 1


async def test_rogue_ap_list(snap: Snapshot) -> None:
    """#169: the controller's rogue AP list (passive), under the EAP radio that heard it."""
    from signalbox.model import Band, ScanSource, Security

    by = {r.bssid: r for r in snap.wifi_scan}
    a = by["02:5e:00:00:03:01"]
    assert a.radio_id == f"{AP1}/radio/2g" and a.device_id == AP1 and a.band is Band.GHZ_2_4
    assert (a.ssid, a.channel, a.signal_dbm, a.security) == ("Neighbour-A", 6, -63, Security.WPA2)
    assert a.kind is ScanSource.ROGUE_DETECTION and a.last_seen is not None
    hidden = by["02:5e:00:00:03:02"]
    assert hidden.ssid is None and hidden.radio_id == f"{AP1}/radio/5g"
    assert hidden.security is Security.WPA2_WPA3
    cafe = by["02:5e:00:00:03:03"]  # no detecting EAP: the controller's
    assert cafe.device_id == DEV and cafe.radio_id is None and cafe.security is Security.OPEN
    assert cafe.band is Band.GHZ_2_4


async def test_rogue_ap_list_missing(sim: OmadaSimulator, http_url: str) -> None:
    sim.data.pop(next(k for k in sim.data if k.endswith("/insight/rogue-aps")))
    a = adapter(http_url)
    try:
        got = await a.observe()
    finally:
        await a.close()
    assert got.wifi_scan == [] and got.wlans


# --- controller releases (#415) --------------------------------------------------------------


@pytest.mark.parametrize("release", ["6.3", "5.15", "5.9"])
async def test_contract_per_release(http_url: str, sim: OmadaSimulator, release: str) -> None:
    sim.release = release
    a = adapter(http_url)
    try:
        snap = await assert_contract(a)
    finally:
        await a.close()
    assert snap.status is DeviceStatus.OK
    assert snap.device.firmware is not None
    assert snap.device.firmware.current.startswith(release)
    assert snap.ports and snap.wlans and snap.clients
    old = [g.message for g in snap.errors if g.message_id == "omada.oldController"]
    if release == "6.3":
        assert not old
    elif release == "5.15":
        assert old == [
            "accounts: controller 5.15 does not offer it through the Open API (controller 6 does)"
        ]
    else:
        assert sorted(m.split(":")[0] for m in old) == [
            "accounts",
            "firewall ACLs",
            "port forwarding",
        ]
        assert all(g.optional for g in snap.errors if g.message_id == "omada.oldController")


@pytest.mark.parametrize(("release", "version"), [("5.8", "5.8"), ("4.4", "4.4")])
async def test_controller_without_open_api(
    http_url: str, sim: OmadaSimulator, release: str, version: str
) -> None:
    sim.release = release
    snap = await observe(adapter(http_url, omadac_id=OMADAC_ID if release == "5.8" else ""))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert snap.errors[0].message == (
        f"this controller ({version}) has no Open API: Signalbox needs Omada controller "
        "5.9 or later"
    )
    assert snap.errors[0].message_id == "omada.noOpenApi"
    assert sim.token_requests == 0


def test_controller_release() -> None:
    from signalbox.adapters.omada import controller_release

    assert controller_release("5.15.20.18") == (5, 15)
    assert controller_release("6.3.0.111") == (6, 3)
    assert controller_release("") is None and controller_release("x") is None
