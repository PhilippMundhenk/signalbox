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
    lease_seconds,
    link_speeds,
    security,
    vitals,
    width,
)
from signalbox.adapters.openwrt.ubus import AccessDenied, NotFound, Ubus
from signalbox.model import (
    Band,
    DeviceRole,
    DeviceStatus,
    Membership,
    NtpClient,
    NtpServer,
    Pmf,
    PortKind,
    Security,
    passphrase_fingerprint,
)
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import TlsFiles, free_port, self_signed_certificate, serve
from signalbox.testing import assert_contract

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


async def test_interfaces_ports_and_vlans(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_interfaces()
    ports = {p.name: p for p in obs.ports}
    assert set(ports) >= {"lan1", "lan2", "lan3", "lan4", "br-lan", "eth0", "phy0-ap0"}
    assert "lo" not in ports and "br-lan.1" not in ports
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


async def test_dhcp_off_on_an_ap(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_dhcp()
    [server] = obs.dhcp_servers
    assert server.id == "ap1/dhcp/lan" and server.segment_id == "home/segment/native"
    assert server.enabled is False and server.pools == []
    assert server.lease_seconds == 12 * 3600
    assert [(r.mac, str(r.address), r.hostname) for r in server.reservations] == [
        ("00:00:5e:00:53:01", "192.0.2.50", "printer")
    ]


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
    assert set(clients) == {"02:00:00:00:20:01", "02:00:00:00:20:02", "02:00:00:00:20:03"}
    assert clients["02:00:00:00:20:01"].seen_on == "ap1/wlan/default_radio0"
    assert clients["02:00:00:00:20:02"].seen_on == "ap1/wlan/iot_radio0"
    assert clients["02:00:00:00:20:02"].segment_id == "home/segment/20"
    laptop = clients["02:00:00:00:20:03"]
    assert laptop.seen_on == "ap1/wlan/default_radio1" and laptop.hostname == "laptop"
    assert laptop.addresses == [ip_address("192.0.2.103")]


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
        ({"uci:dhcp"}, ["dhcp"], "uci.get (dhcp)"),
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
    assert [(e.capability, e.message) for e in snap.errors] == [
        ("neighbours", "LLDP is not installed on the router (no ubus object luci.lldpd)")
    ]


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
        ("psk", Security.OTHER),
        ("psk2+ccmp", Security.WPA2),
        ("psk-mixed", Security.WPA2),
        ("sae", Security.WPA3),
        ("sae-mixed", Security.WPA2_WPA3),
        ("wpa2", Security.WPA2_ENTERPRISE),
        ("wpa3", Security.WPA3_ENTERPRISE),
        ("wep-open", Security.OTHER),
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
    [error] = snap.errors
    assert error.capability == "time" and "uci.get (system)" in error.message
    assert snap.device.health is not None


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
