"""Fritz!Box adapter against the TR-064 simulator (TLS with a self-signed certificate)."""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from pydantic import SecretStr, ValidationError

import signalbox.adapters.https as https_mod
from signalbox.adapters import AdapterContext, AdapterError, load_adapters
from signalbox.adapters.fritzbox import (
    FritzboxAdapter,
    FritzboxConfig,
    WlanService,
    band,
    local_time,
    security,
    supported_security,
    time_of,
    wps_of,
)
from signalbox.adapters.fritzbox.soap import SoapFault, Tr064, parse_answer, parse_xml
from signalbox.adapters.https import DeviceHttp
from signalbox.model import (
    AddressSource,
    Band,
    Cipher,
    DeviceHealth,
    DeviceRole,
    DeviceStatus,
    LeaseState,
    NtpClient,
    Security,
    WifiStandard,
    Wps,
    WpsMethod,
    passphrase_digest,
    passphrase_fingerprint,
)
from signalbox.sim import fritzbox as fritz_sim
from signalbox.sim.fritzbox import FritzboxSim, create_app
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract, passphrase_digest_key

SIM = FritzboxSim()


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"), "fritzbox")


@pytest.fixture(scope="module")
def https_url(cert: TlsFiles) -> Iterator[str]:
    with serve(create_app(SIM), tls=cert) as url:
        yield url


@pytest.fixture(scope="module")
def http_url() -> Iterator[str]:
    with serve(create_app(SIM)) as url:
        yield url


@pytest.fixture
def sim() -> FritzboxSim:
    SIM.reset()
    return SIM


def context(url: str, **kw: Any) -> AdapterContext:
    cfg = {
        "url": url,
        "username": "signalbox",
        "password": SecretStr(FritzboxSim().password),
    } | kw.pop("config", {})
    return AdapterContext(
        site_id="home",
        device_id="fb",
        device_name="Fritz!Box",
        role=kw.pop("role", DeviceRole.GATEWAY),
        config=FritzboxConfig(**cfg),
        **kw,
    )


@pytest.fixture
async def adapter(
    sim: FritzboxSim, https_url: str, cert: TlsFiles
) -> AsyncIterator[FritzboxAdapter]:
    a = FritzboxAdapter(context(https_url, pinned_fingerprint=cert.fingerprint))
    yield a
    await a.close()


async def observe(ctx: AdapterContext) -> Any:
    a = FritzboxAdapter(ctx)
    try:
        return await a.observe()
    finally:
        await a.close()


# --- happy path -----------------------------------------------------------------------


async def test_contract_over_pinned_tls(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    snap = await assert_contract(adapter)
    assert (snap.device.vendor, snap.device.model) == ("AVM", "FRITZ!Box 7590")
    assert snap.device.firmware is not None and snap.device.firmware.current == "154.07.57"
    assert snap.device.management_address == "127.0.0.1"
    assert adapter.http.secure
    assert sim.authenticated > 0
    assert "000000000000" not in snap.model_dump_json()  # the serial number is not kept


def test_entry_point() -> None:
    assert load_adapters()["fritzbox"] is FritzboxAdapter


async def test_interfaces(adapter: FritzboxAdapter) -> None:
    obs = await adapter.read_interfaces()
    port, wan = obs.ports
    assert wan.id == "fb/port/wan" and wan.counters is not None  # the WAN totals only (#158)
    assert (wan.counters.rx_bytes, wan.counters.tx_packets) == (3_881_020_914, 7_204_511)
    assert wan.counters.rx_errors is None and wan.kind.value == "virtual"
    assert (port.id, port.up, port.speed_mbps, port.full_duplex) == (
        "fb/port/lan",
        True,
        None,  # TR-064 has no link speed: NewMaxBitRate is the maximum (#156)
        True,
    )
    assert (port.admin_up, port.max_speed_mbps, port.autoneg) == (True, 1000, None)
    assert port.mac == "02:00:00:00:00:01" and port.vendor_extra["BytesSent"] == "1000"
    segs = {s.id: s for s in obs.segments}
    assert set(segs) == {"home/segment/native", "home/segment/guest"}
    assert [m.port_id for m in segs["home/segment/native"].members] == ["fb/port/lan"]
    guest_seg = segs["home/segment/guest"]
    assert guest_seg.vendor_extra and guest_seg.isolated is True
    assert (guest_seg.purpose, guest_seg.purpose_source) == ("guest", "reported")
    assert segs["home/segment/native"].purpose is None
    [subnet] = obs.subnets
    assert subnet.interface == ip_interface("192.0.2.1/24") and subnet.gateway


async def test_ap_role_is_not_the_gateway(sim: FritzboxSim, https_url: str, cert: TlsFiles) -> None:
    a = FritzboxAdapter(context(https_url, pinned_fingerprint=cert.fingerprint, role=DeviceRole.AP))
    try:
        [subnet] = (await a.read_interfaces()).subnets
    finally:
        await a.close()
    assert not subnet.gateway


async def test_dhcp(adapter: FritzboxAdapter) -> None:
    [server] = (await adapter.read_dhcp()).dhcp_servers
    assert server.enabled and server.segment_id == "home/segment/native"
    assert [(str(p.start), str(p.end)) for p in server.pools] == [("192.0.2.20", "192.0.2.200")]
    assert server.router == ip_address("192.0.2.1")
    assert server.dns_servers == [ip_address("192.0.2.1")] and server.domain == "fritz.box"
    assert server.reservations == []


async def test_dhcp_leases_from_the_host_list(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    obs = await adapter.read_dhcp()
    [server] = obs.dhcp_servers
    assert server.leases is not None and obs.dhcp_relays == []
    by_mac = {x.mac: x for x in server.leases}
    laptop, gone = by_mac["02:00:00:00:20:01"], by_mac["02:00:00:00:10:02"]
    assert (laptop.state, laptop.hostname) == (LeaseState.ACTIVE, "laptop")
    assert laptop.expires is not None
    assert 80000 < (laptop.expires - datetime.now(UTC)).total_seconds() <= 86400
    assert (gone.state, gone.expires) == (LeaseState.EXPIRED, None)  # remembered host
    assert "02:00:00:00:20:02" not in by_mac  # no address: no lease
    sim.lan["NewDHCPRelay"] = "1"
    [relay] = (await adapter.read_dhcp()).dhcp_relays
    assert (relay.id, relay.segment_id, relay.servers) == (
        "fb/dhcp-relay/lan",
        "home/segment/native",
        [],
    )


async def test_leases_not_read_without_the_host_list(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    sim.faults = {"X_AVM-DE_GetHostListPath": 606}
    [server] = (await adapter.read_dhcp()).dhcp_servers
    assert server.leases is None  # not read, which is not "no leases"


async def test_wireless(adapter: FritzboxAdapter) -> None:
    obs = await adapter.read_wireless()
    radios = {r.id: r for r in obs.radios}
    assert set(radios) == {"fb/radio/1", "fb/radio/2"}
    assert (radios["fb/radio/1"].band, radios["fb/radio/1"].channel) == (Band.GHZ_2_4, 6)
    assert (radios["fb/radio/2"].band, radios["fb/radio/2"].channel) == (Band.GHZ_5, 36)
    wlans = {w.id: w for w in obs.wlans}
    main = wlans["fb/wlan/1"]
    assert main.ssid == "Example" and main.security is Security.WPA2_WPA3
    assert main.passphrase_fingerprint == passphrase_fingerprint("Example", "example-passphrase")
    assert main.segment_id == "home/segment/native"
    guest = wlans["fb/wlan/3"]
    assert guest.ssid == "Example-Guest" and guest.security is Security.WPA2
    assert guest.segment_id == "home/segment/guest" and guest.vendor_extra["guest"] is True
    assert (guest.purpose, guest.purpose_source) == ("guest", "reported")
    assert wlans["fb/wlan/1"].purpose is None and guest.client_isolation is None
    assert guest.radio_id == "fb/radio/1"  # rides on the 2.4 GHz radio
    assert "example-guest-passphrase" not in obs.model_dump_json()


async def test_wifi_security_details(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    with passphrase_digest_key():
        obs = await adapter.read_wireless()
        digest = passphrase_digest("example-passphrase")
        guest_digest = passphrase_digest("example-guest-passphrase")
    wlans = {w.id: w for w in obs.wlans}
    assert digest and digest != guest_digest
    assert (wlans["fb/wlan/1"].passphrase_digest, wlans["fb/wlan/3"].passphrase_digest) == (
        digest,
        guest_digest,
    )
    assert wlans["fb/wlan/1"].wps == Wps(enabled=True)  # status inactive, mode stop
    assert wlans["fb/wlan/2"].wps == Wps(enabled=True, methods=[WpsMethod.PUSH_BUTTON])
    assert wlans["fb/wlan/3"].wps == Wps(enabled=False)
    for w in obs.wlans:  # not in TR-064
        assert w.ciphers is None and w.group_cipher is None and w.sae is None
        assert w.key_rotation_seconds is None and w.beacon_protection is None
    for r in obs.radios:
        assert r.supported_security == [
            Security.OPEN,
            Security.WPA2,
            Security.WPA_WPA2,
            Security.WPA3,
            Security.WPA2_WPA3,
        ]
    sim.faults["X_AVM-DE_GetWPSInfo"] = 401  # a FRITZ!OS without it
    assert all(w.wps is None for w in (await adapter.read_wireless()).wlans)


async def test_wep_and_open_basic_networks(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    sim.wlans[1] |= {"NewBeaconType": "Basic", "NewBasicEncryptionModes": "WEPEncryption"}
    sim.wlans[2] |= {"NewBeaconType": "Basic"}  # the sample box's modes "None": open
    wlans = {w.id: w for w in (await adapter.read_wireless()).wlans}
    wep, plain = wlans["fb/wlan/1"], wlans["fb/wlan/2"]
    assert wep.security is Security.WEP and wep.ciphers == [Cipher.WEP]
    assert wep.passphrase_fingerprint is None and wep.wps is None
    assert plain.security is Security.OPEN and plain.ciphers is None


async def test_lan_with_automatic_bit_rate(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    sim.ethernet |= {"NewMaxBitRate": "Auto", "NewDuplexMode": "Auto", "NewEnable": "0"}
    sim.ethernet["NewStatus"] = "Disabled"
    port, _wan = (await adapter.read_interfaces()).ports
    assert (port.max_speed_mbps, port.autoneg, port.full_duplex) == (None, True, None)
    assert (port.admin_up, port.up) == (False, False)


async def test_guest_without_ext_info_is_the_last_wlan(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    sim.ext_info = False
    wlans = await adapter._wlans()
    assert [w.guest for w in wlans] == [False, False, True]


async def test_clients(adapter: FritzboxAdapter) -> None:
    clients = {c.mac: c for c in (await adapter.read_clients()).clients}
    assert set(clients) == {"02:00:00:00:20:01", "02:00:00:00:20:02", "02:00:00:00:10:01"}
    laptop = clients["02:00:00:00:20:01"]
    assert laptop.seen_on == "fb/wlan/2" and laptop.hostname == "laptop"
    assert laptop.addresses == [ip_address("192.0.2.101")]
    phone = clients["02:00:00:00:20:02"]
    assert phone.seen_on == "fb/wlan/3" and phone.segment_id == "home/segment/guest"
    assert phone.addresses == []
    printer = clients["02:00:00:00:10:01"]
    assert printer.seen_on == "fb/port/lan" and printer.segment_id == "home/segment/native"
    assert printer.vendor_extra == {"interface_type": "Ethernet"}
    assert printer.address_sources == dict.fromkeys(printer.addresses, AddressSource.DHCP)
    assert printer.addresses


async def test_clients_entry_by_entry_without_host_list(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    sim.host_list = False
    clients = {c.mac: c for c in (await adapter.read_clients()).clients}
    assert clients["02:00:00:00:10:01"].hostname == "printer"
    assert "02:00:00:00:10:02" not in clients  # inactive


async def test_plain_http_only_when_allowed(sim: FritzboxSim, http_url: str) -> None:
    with pytest.raises(ValidationError, match="allow_insecure_http"):
        context(http_url)
    snap = await observe(context(http_url, config={"allow_insecure_http": True}))
    assert snap.status is DeviceStatus.OK


def test_config_url() -> None:
    cfg = FritzboxConfig(url="https://192.0.2.1/", password=SecretStr("x"))
    assert cfg.url == "https://192.0.2.1:49443"
    assert FritzboxConfig(url="https://192.0.2.1:8443", password=SecretStr("x")).url.endswith(
        ":8443"
    )
    with pytest.raises(ValidationError, match="device's address"):
        FritzboxConfig(url="ftp://192.0.2.1", password=SecretStr("x"))
    # the box's name alone is enough; http:// without a port is the web interface
    assert FritzboxConfig(url="fritz.box", password=SecretStr("x")).url == "https://fritz.box:49443"
    with pytest.raises(ValidationError, match="use https://"):
        FritzboxConfig(url="http://192.0.2.1", password=SecretStr("x"), allow_insecure_http=True)


async def test_wrong_port_names_the_right_one(
    sim: FritzboxSim, http_url: str, cert: TlsFiles, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TR-064 not at the address: the box tells its HTTPS port on its UPnP port, unasked."""
    from starlette.applications import Starlette

    import signalbox.adapters.fritzbox.soap as soap_mod
    from signalbox.sim.server import serve as serve_app

    monkeypatch.setattr(soap_mod, "UPNP_PORT", int(http_url.rsplit(":", 1)[1]))
    sim.security_port = 12345
    with serve_app(Starlette(), tls=cert) as web_ui:  # answers 404 everywhere
        snap = await observe(context(web_ui, pinned_fingerprint=cert.fingerprint))
    assert snap.status is DeviceStatus.UNREACHABLE
    err = snap.errors[0]
    assert "serves TR-064 on port 12345" in err.message
    assert err.fix and "https://127.0.0.1:12345" in err.fix
    assert sim.authenticated == 0  # the port is asked without credentials

    sim.security_port = int(web_ui.rsplit(":", 1)[1])  # same port: generic help
    with serve_app(Starlette(), tls=cert) as web_ui2:
        sim.security_port = int(web_ui2.rsplit(":", 1)[1])
        snap = await observe(context(web_ui2, pinned_fingerprint=cert.fingerprint))
    assert snap.errors[0].fix and "Zugriff für Anwendungen zulassen" in snap.errors[0].fix


# --- refused paths --------------------------------------------------------------------


async def test_wrong_password(sim: FritzboxSim, https_url: str, cert: TlsFiles) -> None:
    sim.password = "something-else"
    snap = await observe(context(https_url, pinned_fingerprint=cert.fingerprint))
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert "refused the credentials" in snap.errors[0].message
    assert sim.authenticated == 0


@pytest.mark.parametrize("pinned", [None, "ab" * 32])
async def test_untrusted_certificate_sends_nothing(
    sim: FritzboxSim, https_url: str, cert: TlsFiles, pinned: str | None
) -> None:
    snap = await observe(context(https_url, pinned_fingerprint=pinned))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert cert.fingerprint in snap.errors[0].message
    assert sim.requests == 0


async def test_certificate_swapped_after_probe(
    sim: FritzboxSim, https_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = self_signed_certificate(tmp_path, "other")
    der = ssl.PEM_cert_to_DER_cert(other.cert.read_text())

    async def fake_probe(host: str, port: int, timeout: float) -> bytes:
        return der

    monkeypatch.setattr(https_mod, "peer_certificate", fake_probe)
    snap = await observe(context(https_url, pinned_fingerprint=other.fingerprint))
    assert snap.status is DeviceStatus.UNREACHABLE and "cannot reach" in snap.errors[0].message
    assert sim.requests == 0


async def test_unreachable(sim: FritzboxSim) -> None:
    snap = await observe(context(f"https://127.0.0.1:{free_port()}", pinned_fingerprint="ab"))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "cannot open a TLS connection" in snap.errors[0].message


async def test_timeout(sim: FritzboxSim, https_url: str, cert: TlsFiles) -> None:
    sim.delay = 1.0
    snap = await observe(context(https_url, pinned_fingerprint=cert.fingerprint, timeout=0.2))
    assert snap.status is DeviceStatus.UNREACHABLE
    assert any("0.2 s" in e.message for e in snap.errors), snap.errors


async def test_slow_capability_is_partial(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    # Generous timeout, far longer delay: the fast actions must never hit the timeout on a loaded
    # runner (-n auto), only the slow one, which takes three times as long.
    sim.delay, sim.slow = 6.0, {"GetGenericAssociatedDeviceInfo"}
    object.__setattr__(adapter.context, "timeout", 2.0)
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    assert [e.capability for e in snap.errors] == ["clients"]


async def test_missing_right_for_keys_is_partial(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    sim.denied = {"GetSecurityKeys"}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    [error] = snap.errors
    assert error.capability == "wireless"
    assert "UPnP error 606" in error.message and "FRITZ!Box settings" in error.message
    assert snap.subnets and snap.clients  # the rest is still read


@pytest.mark.parametrize(
    ("faults", "capabilities", "message"),
    [
        ({"LANHostConfigManagement#GetInfo": 820}, ["dhcp", "interfaces"], "UPnP error 820"),
        ({"Hosts#GetGenericHostEntry": 402, "X_AVM-DE_GetHostListPath": 401}, ["clients"], "402"),
        ({"X_AVM-DE_GetHostListPath": 606}, ["clients"], "not authorised"),
        ({"WLANConfiguration#GetInfo": 501}, ["clients", "wireless"], "action failed"),
    ],
)
async def test_faults_are_partial(
    sim: FritzboxSim,
    adapter: FritzboxAdapter,
    faults: dict[str, int],
    capabilities: list[str],
    message: str,
) -> None:
    sim.faults = faults
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    assert [e.capability for e in snap.errors] == capabilities
    assert all(message in e.message for e in snap.errors), snap.errors


async def test_fault_on_system(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    sim.faults = {"DeviceInfo#GetInfo": 401}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "DeviceInfo1 GetInfo: UPnP error 401 (Invalid Action)" in snap.errors[0].message


@pytest.mark.parametrize(
    ("switch", "value", "status", "message"),
    [
        ("malformed", {"*"}, DeviceStatus.UNREACHABLE, "not valid XML"),
        ("doctype", {"GetInfo"}, DeviceStatus.UNREACHABLE, "contains a DTD"),
        ("malformed", {"GetTotalAssociations"}, DeviceStatus.PARTIAL, "not valid XML"),
        ("doctype", {"GetSecurityKeys"}, DeviceStatus.PARTIAL, "contains a DTD"),
        ("doctype", {"HostList"}, DeviceStatus.PARTIAL, "contains a DTD"),
        ("malformed", {"HostList"}, DeviceStatus.PARTIAL, "host list: answer is not valid"),
    ],
)
async def test_malformed_answers(
    sim: FritzboxSim,
    adapter: FritzboxAdapter,
    switch: str,
    value: set[str],
    status: DeviceStatus,
    message: str,
) -> None:
    setattr(sim, switch, value)
    snap = await adapter.observe()
    assert snap.status is status
    assert any(message in e.message for e in snap.errors), snap.errors


async def test_host_list_must_be_a_path_on_the_device(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    sim.host_list_path = "https://198.51.100.9/devicehostlist.lua"
    snap = await adapter.observe()
    assert [e.capability for e in snap.errors] == ["clients"]
    assert "refused to follow" in snap.errors[0].message


async def test_unknown_control_url_and_bad_request(sim: FritzboxSim, http_url: str) -> None:
    http = DeviceHttp(
        http_url,
        pinned_fingerprint=None,
        timeout=2,
        auth=https_mod.httpx.DigestAuth(sim.username, sim.password),
        allow_insecure_http=True,
    )
    try:
        with pytest.raises(https_mod.NotFound):
            await http.request("POST", "/upnp/control/nothing", content=b"<x/>")
        response = await http.request(
            "POST",
            "/upnp/control/hosts",
            accept={500},
            content=b"not xml",
            headers={"SOAPAction": '"urn:dslforum-org:service:Hosts:1#GetHostNumberOfEntries"'},
        )
        assert response.status_code == 500 and b"402" in response.content
        response = await http.request(  # a known action, but not of this service
            "POST",
            "/upnp/control/hosts",
            accept={500},
            content=b"<x/>",
            headers={"SOAPAction": '"urn:dslforum-org:service:DeviceInfo:1#GetInfo"'},
        )
        assert response.status_code == 500 and b"401" in response.content
        with pytest.raises(AdapterError, match="403"):
            await http.request("GET", "/devicehostlist.lua?sid=wrong")
    finally:
        await http.close()


# --- SOAP parsing ---------------------------------------------------------------------

ENV = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>{}</s:Body></s:Envelope>'


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"<x/>", "no SOAP body"),
        (ENV.format("<OtherResponse/>").encode(), "no GetInfoResponse"),
        (ENV.format("<s:Fault><faultstring>boom</faultstring></s:Fault>").encode(), r"\? \(boom\)"),
        (b'<!doctype x SYSTEM "file:///etc/passwd"><x/>', "DTD"),
        (b'<?xml version="1.0"?>\n<! ENTITY x "y">', "DTD"),
    ],
)
def test_parse_answer_errors(body: bytes, message: str) -> None:
    with pytest.raises(AdapterError, match=message):
        parse_answer(body, "GetInfo", "X GetInfo")


def test_fault_code_without_known_meaning() -> None:
    fault = SoapFault("X Y", 999, "")
    assert str(fault) == "X Y: UPnP error 999" and fault.code == 999


def test_parse_xml_ok() -> None:
    assert parse_xml(b"<a><b>1</b></a>", "x").tag == "a"


async def test_envelope_escapes_arguments(sim: FritzboxSim, http_url: str) -> None:
    http = DeviceHttp(
        http_url,
        pinned_fingerprint=None,
        timeout=2,
        auth=https_mod.httpx.DigestAuth(sim.username, sim.password),
        allow_insecure_http=True,
    )
    try:
        # "<" in an argument must not break the envelope: the simulator reads the text "<1>",
        # which is not a number (ui2), and answers "argument value invalid".
        with pytest.raises(SoapFault, match=r"UPnP error 600 \(Argument Value Invalid\)"):
            await Tr064(http).call("Hosts1", "GetGenericHostEntry", NewIndex="<1>")
    finally:
        await http.close()


# --- mapping helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("beacon", "expected"),
    [
        ("None", Security.OPEN),
        (None, Security.OPEN),
        ("Basic", Security.OTHER),  # no word on its encryption
        ("WPA", Security.WPA),
        ("11i", Security.WPA2),
        ("WPAand11i", Security.WPA_WPA2),
        ("WPA3", Security.WPA3),
        ("11iandWPA3", Security.WPA2_WPA3),
        ("OWE", Security.OWE),
        ("OWETrans", Security.OWE),
        ("Unknown", Security.OTHER),
    ],
)
def test_security(beacon: str | None, expected: Security) -> None:
    assert security(beacon) is expected


def test_basic_beacon_depends_on_the_encryption_modes() -> None:
    assert security("Basic", "WEPEncryption") is Security.WEP
    assert security("Basic", "None") is Security.OPEN
    assert security("Basic", "") is Security.OTHER


def test_supported_security_and_wps() -> None:
    assert supported_security("None,11i,WPAand11i,OWE,OWETrans,Bogus") == [
        Security.OPEN,
        Security.WPA2,
        Security.WPA_WPA2,
        Security.OWE,
    ]
    assert supported_security("Basic,WPA") == [Security.WEP, Security.WPA]
    assert supported_security("") is None and supported_security(None) is None
    assert wps_of("stop", "off") == Wps(enabled=False)
    assert wps_of("pbc", "active") == Wps(enabled=True, methods=[WpsMethod.PUSH_BUTTON])
    assert wps_of("other", "inactive") == Wps(enabled=True)
    assert wps_of("", "") is None and wps_of(None, None) is None


@pytest.mark.parametrize(
    ("info", "index", "count", "expected"),
    [
        ({"NewX_AVM-DE_FrequencyBand": "6000"}, 3, 4, Band.GHZ_6),
        ({"NewChannel": "100"}, 1, 3, Band.GHZ_5),
        ({"NewChannel": "11"}, 2, 3, Band.GHZ_2_4),
        ({"NewChannel": "0"}, 2, 3, Band.GHZ_5),
        ({}, 2, 2, Band.GHZ_2_4),
        ({}, 1, 3, Band.GHZ_2_4),
    ],
)
def test_band(info: dict[str, str], index: int, count: int, expected: Band) -> None:
    assert band(info, index, count) is expected


def test_guest_only_box_has_no_radio_for_the_guest(adapter: FritzboxAdapter) -> None:
    ids = adapter._radio_ids([WlanService(1, {}, guest=True)])
    assert ids == {1: ""}


async def test_guest_without_radio_is_skipped(
    adapter: FritzboxAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def only_guest() -> list[WlanService]:
        return [WlanService(1, {"NewSSID": "G", "NewBeaconType": "None"}, guest=True)]

    monkeypatch.setattr(adapter, "_wlans", only_guest)
    obs = await adapter.read_wireless()
    assert obs.radios == [] and obs.wlans == []


async def test_odd_lan_answers(adapter: FritzboxAdapter, monkeypatch: pytest.MonkeyPatch) -> None:
    assert adapter._lan_interface({"NewIPRouters": "", "NewSubnetMask": "255.255.255.0"}) is None
    assert adapter._lan_interface({"NewIPRouters": "192.0.2.1", "NewSubnetMask": "1.2.3.4"}) is None

    async def empty_lan() -> dict[str, str]:
        return {"NewDHCPServerEnable": "0"}

    monkeypatch.setattr(adapter, "_lan", empty_lan)
    await adapter.read_system()
    obs = await adapter.read_interfaces()  # falls back to GetIPRoutersList / GetSubnetMask
    assert obs.subnets[0].interface == ip_interface("192.0.2.1/24")
    [server] = (await adapter.read_dhcp()).dhcp_servers  # and GetAddressRange
    assert not server.enabled and server.router is None
    # the range stays known while the server is off
    assert [(str(p.start), str(p.end)) for p in server.pools] == [("192.0.2.20", "192.0.2.200")]


async def test_host_count_unexpected(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    sim.host_list = False
    real = adapter.tr064.call

    async def call(service: str, action: str, **args: Any) -> dict[str, str]:
        if action == "GetHostNumberOfEntries":
            return {}
        return await real(service, action, **args)

    adapter.tr064.call = call  # type: ignore[method-assign]
    snap = await adapter.observe()
    assert [e.message for e in snap.errors] == [
        "unexpected answer from Hosts1 GetHostNumberOfEntries: no entry count"
    ]


async def test_odd_station_and_host_entries(
    adapter: FritzboxAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(fritz_sim.STATIONS, 1, [("bogus", "0.0.0.0")])
    monkeypatch.setattr(
        fritz_sim,
        "HOSTS",
        [
            *fritz_sim.HOSTS,
            ("bogus", "", "", "", "1", ""),
            ("02:00:00:00:10:03", "", "", "", "1", ""),
        ],
    )
    clients = {c.mac: c for c in (await adapter.read_clients()).clients}
    odd = clients["02:00:00:00:10:03"]
    assert odd.seen_on is None and odd.vendor_extra == {} and odd.hostname is None


async def test_fewer_wlan_services(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    sim.faults = {"WLANConfiguration#X_AVM-DE_GetWLANExtInfo": 401}
    wlans = await adapter._wlans()
    assert len(wlans) == 3  # WLANConfiguration4 answers 404: the end of the list
    monkey = {"WLANConfiguration#GetInfo": 401}
    sim.faults = monkey
    assert await adapter._wlans() == []


async def test_digest_realm_over_https(https_url: str) -> None:
    import httpx

    async with httpx.AsyncClient(base_url=https_url, verify=False, trust_env=False) as client:
        challenge = await client.post("/upnp/control/deviceinfo")
    assert challenge.status_code == 401
    assert challenge.headers["www-authenticate"].startswith('Digest realm="HTTPS Access",nonce="')


async def test_box_without_users_logs_in_with_password_only(
    sim: FritzboxSim, https_url: str, cert: TlsFiles
) -> None:
    """A box set to log in with its password only: the user name stays empty (#202)."""
    sim.username = ""
    snap = await observe(
        context(https_url, pinned_fingerprint=cert.fingerprint, config={"username": ""})
    )
    assert snap.status is DeviceStatus.OK, snap.errors


# --- password-only mode: the box's hidden user (#373) ----------------------------------------


@pytest.fixture
def web_port(https_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The simulator's one https port stands in for the box's web port 443."""
    import signalbox.adapters.fritzbox as fritzbox_mod

    monkeypatch.setattr(fritzbox_mod, "WEB_PORT", int(https_url.rsplit(":", 1)[1]))


def test_login_user_takes_the_last_user_or_the_only_one() -> None:
    from signalbox.adapters.fritzbox.soap import login_user

    page = b"<SessionInfo><Users>%s</Users></SessionInfo>"
    assert login_user(page % b'<User>fritz0000</User><User last="1">fritz1111</User>') == (
        "fritz1111"
    )
    assert login_user(page % b"<User>fritz0000</User>") == "fritz0000"
    assert login_user(page % b"<User>fritz0000</User><User>fritz1111</User>") is None
    assert login_user(page % b"") is None
    with pytest.raises(AdapterError):
        login_user(b'<!DOCTYPE x [<!ENTITY a "b">]><Users/>')


async def test_password_only_box_is_read_with_the_looked_up_user(
    sim: FritzboxSim, https_url: str, cert: TlsFiles, web_port: None
) -> None:
    sim.password_only = True
    ctx = context(https_url, pinned_fingerprint=cert.fingerprint, config={"username": ""})
    snap = await observe(ctx)
    assert snap.status is DeviceStatus.OK, snap.errors


async def test_password_only_box_over_plain_http(sim: FritzboxSim, http_url: str) -> None:
    sim.password_only = True
    ctx = context(http_url, config={"username": "", "allow_insecure_http": True})
    snap = await observe(ctx)
    assert snap.status is DeviceStatus.OK, snap.errors


async def test_a_configured_user_name_is_not_looked_up(
    sim: FritzboxSim, https_url: str, cert: TlsFiles, web_port: None
) -> None:
    sim.no_login_page = True  # would fail the lookup; none is made
    snap = await observe(context(https_url, pinned_fingerprint=cert.fingerprint))
    assert snap.status is DeviceStatus.OK, snap.errors


async def test_empty_user_name_and_failed_lookup_names_the_gap(
    sim: FritzboxSim, https_url: str, cert: TlsFiles, web_port: None
) -> None:
    sim.password_only = True
    sim.no_login_page = True
    ctx = context(https_url, pinned_fingerprint=cert.fingerprint, config={"username": ""})
    a = FritzboxAdapter(ctx)
    try:
        with pytest.raises(AdapterError) as exc:
            await a.read_system()
    finally:
        await a.close()
    assert exc.value.message_id == "fritzbox.noUserName"
    assert exc.value.fix_id == "fritzbox.noUserName.fix"
    assert "login_sid.lua?version=2" in (exc.value.fix or "")
    assert sim.password not in str(exc.value) + (exc.value.fix or "")


async def test_wrong_user_name_gets_the_fritzbox_hints(
    sim: FritzboxSim, https_url: str, cert: TlsFiles
) -> None:
    ctx = context(https_url, pinned_fingerprint=cert.fingerprint, config={"username": "Signalbox"})
    a = FritzboxAdapter(ctx)
    try:
        with pytest.raises(AdapterError) as exc:
            await a.read_system()
    finally:
        await a.close()
    assert exc.value.message_id == "fritzbox.loginRefused"
    assert exc.value.fix_id == "fritzbox.loginRefused.fix"
    fix = exc.value.fix or ""
    assert "FRITZ!Box Einstellungen" in fix and "case-sensitive" in fix and "blocks" in fix


# --- health and time (#178, #179) ------------------------------------------------------------


async def test_health_is_the_uptime(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    [(key, h)] = (await adapter.read_health()).health.items()
    assert key == "fb" and h == DeviceHealth(uptime_seconds=1209600)
    sim.uptime = 0  # NewUpTime is a ui4 in the description: never negative
    [h] = (await adapter.read_health()).health.values()
    assert h.uptime_seconds == 0


async def test_time(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    snap = await assert_contract(adapter)
    t = snap.device.time
    assert t is not None and t.clock is not None
    offset = t.offset_seconds()
    assert offset is not None and abs(offset) < 2
    zone = datetime.now(ZoneInfo("Europe/Berlin")).utcoffset()
    assert zone is not None and t.utc_offset_minutes == zone.total_seconds() // 60
    assert t.timezone == "CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00"
    assert t.ntp_client == NtpClient(enabled=True, servers=["ntp.example.net"])
    assert t.ntp_server is None
    sim.clock_skew = -3600
    t = (await adapter.observe()).device.time
    assert t is not None and (offset := t.offset_seconds()) is not None
    assert -3602 < offset < -3598


async def test_time_needs_the_right(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    sim.faults = {"Time#GetInfo": 606}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    [error] = snap.errors
    assert error.capability == "time" and "not authorised" in error.message


def test_time_mapping() -> None:
    start = datetime(2026, 11, 22, 16, tzinfo=UTC)
    bare = time_of({"NewCurrentLocalTime": "2026-11-22T17:00:00"}, start, start)
    assert bare.clock is None and bare.utc_offset_minutes is None and bare.timezone is None
    assert bare.ntp_client == NtpClient(enabled=False)
    odd = time_of({"NewCurrentLocalTime": "soon", "NewLocalTimeZone": "UTC"}, start, start)
    assert odd.clock is None and odd.timezone == "UTC"
    ok = time_of({"NewCurrentLocalTime": "2026-11-22T21:30:00+05:30"}, start, start)
    assert ok.utc_offset_minutes == 330 and ok.offset_seconds() == 0.5
    assert local_time(None) is None


# --- management services (#173) --------------------------------------------------------------


async def test_services(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    by = {s.name: s for s in (await adapter.read_interfaces()).services}
    assert sorted(by) == [
        "ftp",
        "ftp-internet",
        "http",
        "https",
        "myfritz",
        "myfritz-cloud",
        "remote-access",
        "tr-064",
        "upnp",
    ]
    assert (by["http"].port, by["https"].port) == (80, 443)
    tr = by["tr-064"]
    assert (tr.kind.value, tr.port, tr.encrypted) == ("tr-064", 49443, True)
    remote = by["remote-access"]  # off as shipped: not reachable from the internet
    assert (remote.enabled, remote.from_wan, remote.kind.value) == (False, False, "https")
    assert by["myfritz"].enabled and by["myfritz"].from_wan
    cloud = by["myfritz-cloud"]  # the registration with AVM (#327)
    assert (cloud.kind.value, cloud.enabled, cloud.label()) == ("cloud", True, "MyFRITZ!")
    assert by["ftp"].enabled and by["ftp"].from_wan is False
    wan = by["ftp-internet"]
    assert (wan.enabled, wan.from_wan, wan.port) == (False, False, 21)
    assert by["upnp"].enabled and by["upnp"].kind.value == "upnp" and by["upnp"].port is None
    assert (await adapter.read_system()).transport_encrypted is True


async def test_services_open_to_the_internet(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    sim.remote_access |= {"NewEnabled": "1", "NewPort": "8443"}
    sim.storage |= {"NewFTPWANEnable": "1", "NewFTPWANSSLOnly": "0", "NewFTPWANPort": "2121"}
    sim.myfritz |= {"NewEnabled": "0", "NewPort": "0"}
    by = {s.name: s for s in (await adapter.read_interfaces()).services}
    assert (by["remote-access"].port, by["remote-access"].from_wan) == (8443, True)
    ftp = by["ftp-internet"]
    assert (ftp.enabled, ftp.from_wan, ftp.port, ftp.encrypted) == (True, True, 2121, False)
    assert (by["myfritz"].enabled, by["myfritz"].port, by["myfritz"].from_wan) == (
        False,
        None,
        False,
    )
    assert not by["myfritz-cloud"].enabled
    sim.myfritz |= {"NewEnabled": "1", "NewDeviceRegistered": "0"}
    unregistered = {s.name: s for s in (await adapter.read_interfaces()).services}
    assert not unregistered["myfritz-cloud"].enabled  # on, but no account behind it
    sim.storage |= {"NewFTPWANSSLOnly": "1"}
    ftp = {s.name: s for s in (await adapter.read_interfaces()).services}["ftp-internet"]
    assert ftp.encrypted is True


async def test_services_missing_on_an_older_box(adapter: FritzboxAdapter, sim: FritzboxSim) -> None:
    sim.faults = {"X_AVM-DE_RemoteAccess#GetInfo": 401, "X_AVM-DE_Storage#GetInfo": 401}
    snap = await adapter.observe()
    names = {s.name for s in snap.services}
    assert not snap.errors and {"remote-access", "ftp", "ftp-internet"}.isdisjoint(names)
    assert {"http", "myfritz", "upnp"} <= names


# --- accounts (#175) -------------------------------------------------------------------------


async def test_users_rights_and_default_password(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    from signalbox.model import AccountPrivilege

    snap = await assert_contract(adapter)
    dev = snap.device
    assert [(a.name, a.privilege, a.is_signalbox) for a in dev.accounts or []] == [
        ("fritz0000", None, False),
        ("signalbox", AccountPrivilege.ADMIN, True),
    ]
    assert dev.default_credentials is False
    assert dev.signalbox_account_privilege is AccountPrivilege.ADMIN
    assert dev.signalbox_account_needed is AccountPrivilege.ADMIN  # no smaller login exists
    sim.default_password = True
    sim.users = ["fritz0000"]
    sim.user_rights = {"BoxAdmin": "read"}
    snap = await adapter.observe()
    dev = snap.device
    assert dev.default_credentials is True
    assert dev.signalbox_account_privilege is AccountPrivilege.READ
    assert [a.name for a in dev.accounts or []] == ["fritz0000", "signalbox"]


async def test_a_box_without_the_user_actions_reports_nothing(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    sim.faults = {"LANConfigSecurity#X_AVM-DE_GetUserList": 401}
    sim.denied = {"X_AVM-DE_GetCurrentUser"}
    snap = await adapter.observe()
    dev = snap.device
    assert dev.accounts is None and dev.signalbox_account_privilege is None
    assert dev.default_credentials is False
    assert not [e for e in snap.errors if e.message.startswith("accounts")]
    # a user without the right: not "no accounts" but an optional gap naming the right (#349)
    sim.faults = {"LANConfigSecurity#X_AVM-DE_GetUserList": 606}
    snap = await adapter.observe()
    assert snap.device.accounts is None
    (gap,) = [e for e in snap.errors if e.message.startswith("accounts")]
    assert gap.optional and gap.message_id == "fritzbox.accounts"
    assert "FRITZ!Box settings" in (gap.fix or "")
    sim.faults = {"LANConfigSecurity#GetInfo": 401}
    snap = await adapter.observe()
    assert snap.device.default_credentials is None


def test_user_list_and_rights_parsing() -> None:
    from signalbox.adapters.fritzbox.accounts import box_rights, user_names
    from signalbox.model import AccountPrivilege

    assert user_names("") == [] and user_names("<List><Username>") == []
    assert user_names(
        '<List><Username last_user="1">a</Username><Username>a</Username><Username> </Username>'
        "<Username>b</Username></List>"
    ) == ["a", "b"]
    evil = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "e">]><List><Username>&e;</Username></List>'
    )
    assert user_names(evil) == []
    assert box_rights("") is None and box_rights("<rights>") is None
    assert box_rights("<rights><path>NAS</path><access>readwrite</access></rights>") is (
        AccountPrivilege.OTHER
    )
    assert box_rights("<rights><path>BoxAdmin</path><access>ReadWrite</access></rights>") is (
        AccountPrivilege.ADMIN
    )


# radio capabilities and state (#172) ----------------------------------------------------------


async def test_radio_channels_standard_and_clients(adapter: FritzboxAdapter) -> None:
    obs = await adapter.read_wireless()
    radios = {r.id: r for r in obs.radios}
    r1, r2 = radios["fb/radio/1"], radios["fb/radio/2"]
    assert (r1.standard, r1.channel_auto, r1.dfs_capable) == (WifiStandard.AX, True, None)
    assert r1.supported_channels == list(range(1, 14))
    assert r2.dfs_capable is True and 149 not in (r2.supported_channels or [])
    # the guest WLAN shares the 2.4 GHz radio: its stations count there
    stations = fritz_sim.STATIONS
    assert r1.client_count == len(stations[1]) + len(stations[3])
    assert r2.client_count == len(stations[2])


async def test_radio_details_refused(sim: FritzboxSim, adapter: FritzboxAdapter) -> None:
    sim.faults = {"GetChannelInfo": 401, "GetTotalAssociations": 606}
    try:
        obs = await adapter.read_wireless()
    finally:
        sim.faults = {}
    r1 = next(r for r in obs.radios if r.id == "fb/radio/1")
    assert r1.supported_channels is None and r1.channel_auto is None
    assert r1.client_count is None and r1.standard is WifiStandard.AX


async def test_mesh_list_reports_repeaters_links_and_roles(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    """FRITZ!Mesh (#171): repeaters are devices the box manages, the wireless uplinks links."""
    sim.mesh = True
    snap = await assert_contract(adapter)
    names = {d.id: d for d in snap.extra_devices}
    hall, garden = names["fb/node/n-rep1"], names["fb/node/n-rep2"]
    assert (hall.name, hall.model, hall.vendor) == ("Repeater Hall", "FRITZ!Repeater 3000", "AVM")
    assert hall.management_address == "192.0.2.21" and hall.managed_by == "fb"
    assert "fb/node/n-client" not in names  # a client of the mesh list is not a node
    assert snap.device.mesh is not None and snap.device.mesh.role.value == "controller"
    assert hall.mesh is not None and hall.mesh.hop == 1 and hall.mesh.uplink is not None
    assert hall.mesh.uplink.value == "wireless"
    assert garden.mesh is not None and garden.mesh.hop == 2 and garden.mesh.controller_id == "fb"
    links = {link.b: link for link in snap.wireless_links}
    first = links["fb/node/n-rep1/port/uplink"]
    assert first.a == "fb/port/mesh-n-rep1" and first.origin.value == "mesh"
    assert first.wireless is not None
    assert (first.wireless.band, first.wireless.channel) == (Band.GHZ_5, 36)
    assert first.wireless.signal_dbm == -60 and first.wireless.tx_rate_mbps == 866.0
    second = links["fb/node/n-rep2/port/uplink"]
    assert second.a == "fb/node/n-rep1/port/mesh-n-rep2"  # behind the first repeater
    assert second.wireless is not None and second.wireless.band is Band.GHZ_2_4
    assert second.wireless.signal_dbm == -82 and second.wireless.rx_rate_mbps == 40.0


async def test_box_without_a_mesh_reports_nothing(adapter: FritzboxAdapter) -> None:
    snap = await adapter.observe()
    assert snap.wireless_links == [] and snap.device.mesh is None
    assert not any("/node/" in d.id for d in snap.extra_devices)


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"nodes": "x"},
        {"nodes": [{"uid": "a", "is_meshed": True, "mesh_role": "master"}]},  # one box
        {"nodes": [{"uid": "a", "is_meshed": True}, {"uid": "b", "is_meshed": True}]},  # no master
    ],
)
async def test_odd_mesh_documents_report_nothing(
    sim: FritzboxSim, adapter: FritzboxAdapter, doc: Any
) -> None:
    sim.mesh, sim.mesh_doc = True, doc
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK and snap.wireless_links == []
    assert snap.device.mesh is None


async def test_broken_or_foreign_mesh_list_is_skipped(
    sim: FritzboxSim, adapter: FritzboxAdapter
) -> None:
    sim.mesh = True
    sim.malformed = {"MeshList"}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK and snap.wireless_links == []
    sim.malformed = set()
    sim.mesh_list_path = "https://198.51.100.9/meshlist.lua"  # not a path on the box
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK and snap.wireless_links == []


def test_mesh_signal_and_rate_helpers() -> None:
    from signalbox.adapters.fritzbox import mesh

    assert (mesh.dbm(100), mesh.dbm(0), mesh.dbm(220)) == (-60, -110, 0)
    assert mesh.dbm(255) is None and mesh.dbm("x") is None and mesh.dbm(True) is None
    assert mesh._mbps(866_000) == 866.0 and mesh._mbps(0) is None and mesh._mbps(None) is None
    assert mesh._band("UPLINK:5G:0") is Band.GHZ_5 and mesh._band("LAN:0") is None
    assert mesh._band("AP:6G:1") is Band.GHZ_6
