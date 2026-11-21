"""OpenWrt adapter against the ubus simulator (TLS with a self-signed certificate)."""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator, Iterator
from ipaddress import ip_address, ip_interface
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    Unreachable,
    UntrustedCertificate,
    load_adapters,
)
from signalbox.adapters.openwrt import (
    NetworkView,
    OpenWrtAdapter,
    OpenWrtConfig,
    band,
    bridge_vlans,
    lease_seconds,
    security,
    width,
)
from signalbox.adapters.openwrt.transport import Transport, fingerprint, peer_fingerprint
from signalbox.adapters.openwrt.ubus import AccessDenied, NotFound, Ubus
from signalbox.model import (
    Band,
    DeviceRole,
    DeviceStatus,
    Membership,
    Pmf,
    PortKind,
    Security,
    passphrase_fingerprint,
)
from signalbox.sim.openwrt import NO_SESSION, OpenWrtSim, create_app
from signalbox.testing import assert_contract
from simserver import Cert, self_signed, serve

SIM = OpenWrtSim()


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> Cert:
    return self_signed(tmp_path_factory.mktemp("tls"))


@pytest.fixture(scope="module")
def https_url(cert: Cert) -> Iterator[str]:
    with serve(create_app(SIM), cert) as url:
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
async def adapter(sim: OpenWrtSim, https_url: str, cert: Cert) -> AsyncIterator[OpenWrtAdapter]:
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
    assert not adapter.ubus.transport.insecure


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
    segs = {s.vlan: s for s in obs.segments}
    assert set(segs) == {1, 20}
    assert segs[1].id == "home/segment/1" and segs[1].name == "lan"
    assert {(m.port_id, m.mode) for m in segs[1].members} == {
        (f"ap1/port/lan{n}", Membership.UNTAGGED) for n in (1, 2, 3)
    }
    assert segs[20].name == "iot"
    assert [(m.port_id, m.mode) for m in segs[20].members] == [("ap1/port/lan1", Membership.TAGGED)]
    subnets = {str(s.interface): s for s in obs.subnets}
    assert set(subnets) == {"192.0.2.2/24", "2001:db8::2/64"}  # no loopback
    assert all(s.segment_id == "home/segment/1" and not s.gateway for s in subnets.values())


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
    assert main.segment_id == "home/segment/1" and main.radio_id == "ap1/radio/radio0"
    assert main.passphrase_fingerprint == passphrase_fingerprint("Example", "example-passphrase")
    assert wlans["ap1/wlan/default_radio1"].pmf is Pmf.OPTIONAL
    iot = wlans["ap1/wlan/iot_radio0"]
    assert iot.security is Security.WPA2 and iot.segment_id == "home/segment/20"
    assert iot.hidden and iot.pmf is None and not iot.roaming_80211r
    assert "example-iot-passphrase" not in iot.model_dump_json()


async def test_dhcp_off_on_an_ap(adapter: OpenWrtAdapter) -> None:
    obs = await adapter.read_dhcp()
    [server] = obs.dhcp_servers
    assert server.id == "ap1/dhcp/lan" and server.segment_id == "home/segment/1"
    assert server.enabled is False and server.pools == []
    assert server.lease_seconds == 12 * 3600
    assert [(r.mac, str(r.address), r.hostname) for r in server.reservations] == [
        ("02:00:00:00:10:01", "192.0.2.50", "printer")
    ]


async def test_router_mode(sim: OpenWrtSim, https_url: str, cert: Cert) -> None:
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
    assert snap.status is DeviceStatus.UNREACHABLE and "plain HTTP" in snap.errors[0].message
    a = OpenWrtAdapter(context(http_url, config={"allow_insecure_http": True}))
    try:
        assert (await a.observe()).status is DeviceStatus.OK
        assert a.ubus.transport.insecure
    finally:
        await a.close()


# --- refused paths --------------------------------------------------------------------


async def test_wrong_password(sim: OpenWrtSim, https_url: str, cert: Cert) -> None:
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
    assert all(named in e.message and "rpcd ACL" in e.message for e in snap.errors)
    assert snap.ports  # the rest is still read


@pytest.mark.parametrize("pinned", [None, "ab" * 32])
async def test_untrusted_certificate_sends_no_password(
    sim: OpenWrtSim, https_url: str, cert: Cert, pinned: str | None
) -> None:
    snap = await observe(context(https_url, pinned_fingerprint=pinned))
    assert snap.status is DeviceStatus.UNTRUSTED
    assert cert.fingerprint in snap.errors[0].message
    assert sim.requests == 0


async def test_pin_accepts_colon_notation(sim: OpenWrtSim, https_url: str, cert: Cert) -> None:
    fp = ":".join(cert.fingerprint[i : i + 2] for i in range(0, 64, 2)).upper()
    assert (await observe(context(https_url, pinned_fingerprint=fp))).status is DeviceStatus.OK


async def test_certificate_swapped_after_check(adapter: OpenWrtAdapter) -> None:
    transport = adapter.ubus.transport
    await transport.verify()
    transport.pinned = "cd" * 32  # as if the device now presented another certificate
    with pytest.raises(UntrustedCertificate):
        await transport.post({})


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_unreachable(sim: OpenWrtSim) -> None:
    snap = await observe(context(f"https://127.0.0.1:{_closed_port()}", pinned_fingerprint="ab"))
    assert snap.status is DeviceStatus.UNREACHABLE and "cannot connect" in snap.errors[0].message
    with pytest.raises(Unreachable, match="cannot reach"):
        await Transport(
            f"http://127.0.0.1:{_closed_port()}/ubus", pinned=None, timeout=1, allow_http=True
        ).post({})


async def test_timeout(sim: OpenWrtSim, https_url: str, cert: Cert) -> None:
    sim.delay = 1.0
    snap = await observe(context(https_url, pinned_fingerprint=cert.fingerprint, timeout=0.2))
    assert snap.status is DeviceStatus.UNREACHABLE
    t = Transport(f"{https_url}/ubus", pinned=cert.fingerprint, timeout=0.2)
    with pytest.raises(Unreachable, match=r"within 0\.2 s"):
        await t.post({"id": 1, "params": [NO_SESSION, "system", "board", {}]})
    await t.aclose()


async def test_slow_capability_is_partial(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.delay, sim.slow = 3.0, {"lldpd"}
    object.__setattr__(adapter.context, "timeout", 1.0)
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    assert [e.capability for e in snap.errors] == ["neighbours"]


@pytest.mark.parametrize(
    ("switch", "value", "status", "message"),
    [
        ("malformed", {"*"}, DeviceStatus.UNREACHABLE, "not JSON"),
        ("odd", {"system"}, DeviceStatus.UNREACHABLE, "unexpected answer to system.board"),
        ("malformed", {"network.wireless"}, DeviceStatus.PARTIAL, "not JSON"),
        ("odd", {"lldpd"}, DeviceStatus.PARTIAL, "unexpected answer to lldpd"),
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


async def test_lldpd_missing(sim: OpenWrtSim, adapter: OpenWrtAdapter) -> None:
    sim.lldpd = False
    snap = await adapter.observe()
    assert [(e.capability, e.message) for e in snap.errors] == [
        ("neighbours", "lldpd not installed (no ubus object lldpd)")
    ]


async def test_http_error_status(sim: OpenWrtSim, https_url: str, cert: Cert) -> None:
    t = Transport(f"{https_url}/elsewhere", pinned=cert.fingerprint, timeout=2)
    with pytest.raises(AdapterError, match="HTTP 404"):
        await t.post({})
    await t.aclose()


async def test_simulator_parse_error(sim: OpenWrtSim, http_url: str) -> None:
    t = Transport(f"{http_url}/ubus", pinned=None, timeout=2, allow_http=True)
    answer = await t.post({"jsonrpc": "2.0"})
    assert answer["error"]["code"] == -32700
    await t.aclose()


def test_bad_url() -> None:
    with pytest.raises(AdapterError, match="not an http"):
        Transport("ftp://192.0.2.2/ubus", pinned=None, timeout=1)


async def test_peer_fingerprint(https_url: str, cert: Cert) -> None:
    port = int(https_url.rsplit(":", 1)[1])
    assert await peer_fingerprint("127.0.0.1", port, 2) == cert.fingerprint
    assert fingerprint(b"x") == fingerprint(b"x") != fingerprint(b"y")


# --- ubus client against canned answers -----------------------------------------------


class Canned:
    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.sent: list[Any] = []

    async def verify(self) -> None:
        pass

    async def post(self, payload: Any) -> Any:
        self.sent.append(payload)
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
    ubus = Ubus(Canned(LOGIN, answer), "signalbox", "pw")  # type: ignore[arg-type]
    with pytest.raises(error, match=message):
        await ubus.call("x", "y")


async def test_ubus_status_without_data() -> None:
    ubus = Ubus(Canned(LOGIN, {"result": [0]}), "signalbox", "pw")  # type: ignore[arg-type]
    assert await ubus.call("x", "y") == {}


async def test_ubus_login_without_session() -> None:
    ubus = Ubus(Canned({"result": [0, {}]}), "signalbox", "pw")  # type: ignore[arg-type]
    with pytest.raises(AdapterError, match=r"session\.login"):
        await ubus.login()


async def test_ubus_login_access_denied_error() -> None:
    answer = {"error": {"code": -32002, "message": "Access denied"}}
    ubus = Ubus(Canned(answer), "signalbox", "pw")  # type: ignore[arg-type]
    with pytest.raises(AuthFailed):
        await ubus.login()


async def test_ubus_denied_twice_names_acl() -> None:
    denied = {"result": [6]}
    ubus = Ubus(Canned(LOGIN, denied, LOGIN, denied), "ro", "pw")  # type: ignore[arg-type]
    with pytest.raises(AccessDenied, match=r"x\.y: add it to the rpcd ACL of 'ro'"):
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
