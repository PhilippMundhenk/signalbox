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
    time_of,
)
from signalbox.adapters.fritzbox.soap import SoapFault, Tr064, parse_answer, parse_xml
from signalbox.adapters.https import DeviceHttp
from signalbox.model import (
    Band,
    DeviceHealth,
    DeviceRole,
    DeviceStatus,
    NtpClient,
    Security,
    passphrase_fingerprint,
)
from signalbox.sim import fritzbox as fritz_sim
from signalbox.sim.fritzbox import FritzboxSim, create_app
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract

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
    [port] = obs.ports
    assert (port.id, port.up, port.speed_mbps, port.full_duplex) == (
        "fb/port/lan",
        True,
        1000,
        True,
    )
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
    assert printer.vendor_extra == {"interface_type": "Ethernet", "address_source": "DHCP"}


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
    sim.delay, sim.slow = 3.0, {"GetGenericAssociatedDeviceInfo"}
    object.__setattr__(adapter.context, "timeout", 1.0)
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
        ("Basic", Security.OTHER),
        ("WPA", Security.OTHER),
        ("11i", Security.WPA2),
        ("WPAand11i", Security.WPA2),
        ("WPA3", Security.WPA3),
        ("11iandWPA3", Security.WPA2_WPA3),
        ("OWE", Security.OWE),
        ("OWETrans", Security.OWE),
        ("Unknown", Security.OTHER),
    ],
)
def test_security(beacon: str | None, expected: Security) -> None:
    assert security(beacon) is expected


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
    assert [e.message for e in snap.errors] == ["Hosts1 GetHostNumberOfEntries: unexpected answer"]


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
