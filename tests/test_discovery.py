"""Device discovery (#203): probes against the simulators, the toolkit, the engine and the API.

The simulators listen on 127.0.0.1 on free ports; ``extra["ports"]`` points each probe's
standard port (49000, 443, 8043, ...) at them, the way a test points an adapter at a simulator.
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
import time
from collections.abc import Iterator
from ipaddress import ip_interface
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from factories import SITE, device, iface, port, snapshot, uplink
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    Manifest,
    SystemInfo,
    load_adapters,
    probes_broadcast,
    probes_hosts,
)
from signalbox.adapters.fritzbox import FritzboxAdapter
from signalbox.adapters.mikrotik import MikrotikAdapter
from signalbox.adapters.omada import OmadaAdapter
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.discovery import BroadcastResult, Candidate, HostProbe, NetworkProbe, RateLimiter
from signalbox.discovery import clean as clean_text
from signalbox.discovery.engine import normal_host
from signalbox.discovery.probe import ProbeResponse, _no_route
from signalbox.discovery.targets import RangeError, infrastructure, parse_range, plan
from signalbox.model import (
    Client,
    DeviceRole,
    DhcpServer,
    Neighbour,
    Network,
    Reservation,
    Subnet,
)
from signalbox.service import Services, build
from signalbox.sim import fritzbox as fritz_sim
from signalbox.sim import openwrt as openwrt_sim
from signalbox.sim.mikrotik import MikrotikSimulator
from signalbox.sim.omada import OmadaSimulator
from signalbox.sim.opnsense import OpnsenseSimulator
from signalbox.sim.server import free_port, self_signed_certificate, serve
from signalbox.store import DeviceRecord

try:
    import switchyard  # noqa: F401
except ImportError:  # pragma: no cover - depends on the installation
    HAVE_SWITCHYARD = False
    if os.environ.get("REQUIRE_SWITCH_TESTS"):
        raise
else:
    HAVE_SWITCHYARD = True

needs_switchyard = pytest.mark.skipif(not HAVE_SWITCHYARD, reason="Switchyard not installed")
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
PW = "correct-horse-battery"


@pytest.fixture(scope="module")
def sims(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, int]]:
    """Every HTTP simulator, by the name of the probe port it stands in for."""
    tls = self_signed_certificate(tmp_path_factory.mktemp("tls"))
    apps = {
        "fritzbox.upnp": (fritz_sim.create_app(), None),
        "openwrt.https": (openwrt_sim.create_app(), tls),
        "opnsense.https": (OpnsenseSimulator().app(), tls),
        "mikrotik.https": (MikrotikSimulator().app(), tls),
        "omada.https": (OmadaSimulator().app(), tls),
    }
    ports: dict[str, int] = {}
    with contextlib_exit() as stack:
        for name, (app, cert) in apps.items():
            url = stack.enter_context(serve(app, tls=cert))
            ports[name] = int(url.rsplit(":", 1)[1])
        yield ports


def contextlib_exit() -> Any:
    import contextlib

    return contextlib.ExitStack()


#: every port a probe uses, pointed at nothing (refused) unless a test sets it
ALL_PORTS = (
    "fritzbox.upnp",
    "openwrt.https",
    "openwrt.http",
    "opnsense.https",
    "mikrotik.https",
    "mikrotik.http",
    "omada.https",
    "omada.hardware",
    "linux.ssh",
)


def closed_ports() -> dict[str, int]:
    port = free_port()
    return dict.fromkeys(ALL_PORTS, port)


def probe_for(ports: dict[str, int], **kw: Any) -> HostProbe:
    return HostProbe(
        "127.0.0.1",
        timeout=kw.pop("timeout", 3.0),
        limiter=RateLimiter(1000),
        extra={"ports": {**closed_ports(), **ports}},
        **kw,
    )


ADAPTERS: dict[str, type[Adapter]] = {
    "fritzbox.upnp": FritzboxAdapter,
    "openwrt.https": OpenWrtAdapter,
    "opnsense.https": OpnsenseAdapter,
    "mikrotik.https": MikrotikAdapter,
    "omada.https": OmadaAdapter,
}


# --- the probes find their simulators, and only theirs ---------------------------------------


async def found(cls: type[Adapter], ports: dict[str, int]) -> Candidate | None:
    probe = probe_for(ports)
    try:
        return await cls.discover(probe)
    finally:
        await probe.close()


async def test_fritzbox_probe_reads_description_and_security_port(sims: dict[str, int]) -> None:
    c = await found(FritzboxAdapter, {"fritzbox.upnp": sims["fritzbox.upnp"]})
    assert c is not None
    assert c.role is DeviceRole.GATEWAY and c.vendor == "AVM"
    assert c.model == "FRITZ!Box 7590" and c.name == "FRITZ!Box 7590"
    assert c.firmware == "154.07.57"
    assert c.config == {"url": "https://127.0.0.1:49443"}  # GetSecurityPort, without login
    assert c.note is None and "49443" in (c.evidence or "")
    assert any(i.startswith("udn:") for i in c.identities)  # #224: same on every address


async def test_openwrt_probe_gets_access_denied_from_ubus(sims: dict[str, int]) -> None:
    port = sims["openwrt.https"]
    c = await found(OpenWrtAdapter, {"openwrt.https": port})
    assert c is not None and c.vendor == "OpenWrt" and c.name == "OpenWrt"
    assert c.config == {"url": f"https://127.0.0.1:{port}"} and c.note is None
    assert c.model is None  # the null session may not read the board


async def test_opnsense_probe_reads_the_login_page(sims: dict[str, int]) -> None:
    port = sims["opnsense.https"]
    c = await found(OpnsenseAdapter, {"opnsense.https": port})
    assert c is not None and c.name == "OPNsense" and c.role is DeviceRole.GATEWAY
    assert c.config == {"url": f"https://127.0.0.1:{port}"}


async def test_mikrotik_probe_sees_the_routeros_realm(sims: dict[str, int]) -> None:
    port = sims["mikrotik.https"]
    c = await found(MikrotikAdapter, {"mikrotik.https": port})
    assert c is not None and c.vendor == "MikroTik" and c.note is None
    assert c.config == {"url": f"https://127.0.0.1:{port}"}
    assert c.evidence == f"RouterOS REST API on https port {port}"


async def test_omada_probe_reads_api_info(sims: dict[str, int]) -> None:
    port = sims["omada.https"]
    c = await found(OmadaAdapter, {"omada.https": port})
    assert c is not None and c.role is DeviceRole.OTHER
    assert c.firmware == "6.3.0.111" and c.model == "Omada Controller"
    assert c.config == {"url": f"https://127.0.0.1:{port}"}
    # an OC200 answers on 443
    c = await found(OmadaAdapter, {"omada.hardware": port})
    assert c is not None and c.config == {"url": f"https://127.0.0.1:{port}"}


@pytest.mark.parametrize("probe_port", sorted(ADAPTERS))
@pytest.mark.parametrize("sim", sorted(ADAPTERS))
async def test_no_probe_mistakes_another_device(
    sims: dict[str, int], probe_port: str, sim: str
) -> None:
    """Every probe pointed at every other simulator (on all its ports) finds nothing."""
    if probe_port == sim:
        return
    cls = ADAPTERS[probe_port]
    prefix = probe_port.split(".")[0]
    ports = {name: sims[sim] for name in ALL_PORTS if name.startswith(prefix)}
    assert await found(cls, ports) is None


async def test_nothing_listening_is_nothing_found() -> None:
    for cls in ADAPTERS.values():
        assert await found(cls, {}) is None


# --- variants of the probes, with canned answers ------------------------------------------------


class Canned(HostProbe):
    """A probe whose answers are given per (scheme, port, path); everything else: None."""

    def __init__(self, answers: dict[tuple[str, int, str], ProbeResponse | None]) -> None:
        super().__init__("192.0.2.1", timeout=1.0, limiter=RateLimiter(1000))
        self.answers = answers
        self.sent: list[tuple[str, str, int, str]] = []

    async def request(  # type: ignore[override]
        self, method: str, scheme: str, port: int, path: str, **kw: Any
    ) -> ProbeResponse | None:
        self.sent.append((method, scheme, port, path))
        return self.answers.get((scheme, port, path))


def answer(status: int, body: str | bytes = b"", **headers: str) -> ProbeResponse:
    data = body.encode() if isinstance(body, str) else body
    return ProbeResponse(status, {k.replace("_", "-"): v for k, v in headers.items()}, data)


async def test_openwrt_variants() -> None:
    board = (
        '{"jsonrpc": "2.0", "id": 1, "result": [0, {"model": "Example AP", '
        '"release": {"version": "24.10.0"}}]}'
    )
    c = await OpenWrtAdapter.discover(Canned({("http", 80, "/ubus"): answer(200, board)}))
    assert c is not None and c.model == "Example AP" and c.firmware == "24.10.0"
    assert c.config == {"url": "https://192.0.2.1"} and "luci-ssl" in (c.note or "")
    luci = answer(200, "<title>OpenWrt - LuCI</title>")
    c = await OpenWrtAdapter.discover(Canned({("https", 443, "/cgi-bin/luci/"): luci}))
    assert c is not None and "uhttpd-mod-ubus" in (c.note or "")
    odd = answer(200, '{"jsonrpc": "2.0", "id": 1, "result": "x"}')
    c = await OpenWrtAdapter.discover(Canned({("https", 443, "/ubus"): odd}))
    assert c is not None and c.model is None
    for body in ('{"jsonrpc": "1.0"}', '{"jsonrpc": "2.0"}', "[1]", "not json"):
        assert (
            await OpenWrtAdapter.discover(Canned({("https", 443, "/ubus"): answer(200, body)}))
            is None
        )


async def test_mikrotik_variants() -> None:
    realm = answer(401, "", www_authenticate='Basic realm="RouterOS"')
    c = await MikrotikAdapter.discover(Canned({("http", 80, "/rest/system/resource"): realm}))
    assert (
        c is not None and "www-ssl" in (c.note or "") and c.config == {"url": "https://192.0.2.1"}
    )
    page = answer(200, "<title>RouterOS router configuration page</title>")
    c = await MikrotikAdapter.discover(Canned({("http", 80, "/"): page}))
    assert c is not None and c.evidence == "RouterOS WebFig page on http port 80"
    other = answer(401, "", www_authenticate='Basic realm="api"')
    assert (
        await MikrotikAdapter.discover(Canned({("https", 443, "/rest/system/resource"): other}))
        is None
    )


async def test_opnsense_needs_its_name_and_the_login_form() -> None:
    pfsense = answer(200, '<title>pfSense - Login</title><input name="usernamefld">')
    assert await OpnsenseAdapter.discover(Canned({("https", 443, "/"): pfsense})) is None
    name_only = answer(200, "<p>OPNsense</p>")
    assert await OpnsenseAdapter.discover(Canned({("https", 443, "/"): name_only})) is None
    assert await OpnsenseAdapter.discover(Canned({("https", 443, "/"): answer(302)})) is None


async def test_omada_needs_a_controller_id() -> None:
    for body in ('{"errorCode": 0, "result": {"controllerVer": "5"}}', '{"errorCode": -1}', "[]"):
        probe = Canned({("https", 8043, "/api/info"): answer(200, body)})
        assert await OmadaAdapter.discover(probe) is None
    probe = Canned(
        {("https", 8043, "/api/info"): answer(200, '{"errorCode": 0, "result": {"omadacId": "x"}}')}
    )
    c = await OmadaAdapter.discover(probe)
    assert c is not None and c.firmware is None and c.config == {"url": "https://192.0.2.1:8043"}


TR64 = """<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0">
<systemVersion><Display>154.07.57</Display></systemVersion>
<device><manufacturer>{manufacturer}</manufacturer><modelName>{model}</modelName></device></root>"""


async def test_fritzbox_variants() -> None:
    desc = ("http", 49000, "/tr64desc.xml")
    soap = ("http", 49000, "/upnp/control/deviceinfo")
    box = answer(200, TR64.format(manufacturer="AVM", model="FRITZ!Box 7590"))
    c = await FritzboxAdapter.discover(Canned({desc: box}))  # no GetSecurityPort answer
    assert c is not None and c.config == {"url": "https://192.0.2.1:49443"}
    assert "Allow access for applications" in (c.note or "")
    fault = answer(
        500,
        "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body/></s:Envelope>",
    )
    c = await FritzboxAdapter.discover(Canned({desc: box, soap: fault}))
    assert c is not None and c.note is not None
    big = answer(
        200,
        "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>"
        "<u:GetSecurityPortResponse xmlns:u='x'><NewSecurityPort>70000</NewSecurityPort>"
        "</u:GetSecurityPortResponse></s:Body></s:Envelope>",
    )
    c = await FritzboxAdapter.discover(Canned({desc: box, soap: big}))
    assert c is not None and c.config == {"url": "https://192.0.2.1:49443"}
    other = answer(200, TR64.format(manufacturer="Example", model="Gateway"))
    assert await FritzboxAdapter.discover(Canned({desc: other})) is None
    entity = answer(200, '<!DOCTYPE r [<!ENTITY x "x">]><root/>')
    assert await FritzboxAdapter.discover(Canned({desc: entity})) is None
    assert await FritzboxAdapter.discover(Canned({desc: answer(404)})) is None
    cut = ProbeResponse(200, {}, box.body, truncated=True)
    assert await FritzboxAdapter.discover(Canned({desc: cut})) is None
    v6 = Canned({})
    v6.host = "2001:db8::1"
    v6.answers = {desc: answer(200, TR64.format(manufacturer="x", model="FRITZ!Box 6690"))}
    c = await FritzboxAdapter.discover(v6)
    assert c is not None and c.config == {"url": "https://[2001:db8::1]:49443"}


# --- the probe toolkit ----------------------------------------------------------------------


def mock_probe(handler: Any, **kw: Any) -> HostProbe:
    probe = HostProbe("192.0.2.9", timeout=1.0, limiter=RateLimiter(1000), **kw)
    probe._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return probe


async def test_answers_are_cut_off_and_cached() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert "authorization" not in request.headers
        return httpx.Response(200, content=b"x" * 5000, headers={"Set-Cookie": "s=1"})

    probe = mock_probe(handler, max_bytes=1000)
    first = await probe.get("https", 443, "/")
    assert first is not None and first.truncated and len(first.body) == 1000
    assert first.json() is None and first.text() == "x" * 1000
    assert await probe.get("https", 443, "/") is first and len(calls) == 1
    await probe.post("https", 443, "/", content=b"{}")
    assert len(calls) == 2 and "cookie" not in calls[1].headers  # cookies are not kept
    with pytest.raises(ValueError):
        await probe.get("ftp", 21, "/")
    with pytest.raises(ValueError):
        await probe.get("https", 443, "x")
    await probe.close()
    await probe.close()


async def test_a_silent_host_is_given_up_after_two_ports() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    probe = mock_probe(handler)
    assert await probe.get("https", 443, "/") is None
    assert await probe.get("https", 443, "/other") is None  # the port is known dead
    assert probe.requests == 1 and not probe.silent
    assert await probe.get("http", 80, "/") is None
    assert probe.silent and probe.requests == 2
    assert await probe.get("https", 8043, "/") is None and probe.requests == 2


async def test_no_route_means_silent_at_once_and_refused_means_alive() -> None:
    def unreachable(request: httpx.Request) -> httpx.Response:
        try:
            raise OSError(errno.EHOSTUNREACH, "No route to host")
        except OSError as exc:
            raise httpx.ConnectError("no route", request=request) from exc

    probe = mock_probe(unreachable)
    assert await probe.get("https", 443, "/") is None and probe.silent

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    for handler in (refused, slow):
        probe = mock_probe(handler)
        for number in (1, 2, 3):
            assert await probe.get("https", number, "/") is None
        assert not probe.silent and probe.requests == 3
    assert _no_route(ValueError()) is False


async def test_real_requests_without_proxy_or_verification(sims: dict[str, int]) -> None:
    probe = probe_for({})
    answer = await probe.get("https", sims["omada.https"], "/api/info")
    assert answer is not None and answer.status == 200 and isinstance(answer.json(), dict)
    assert probe.origin("https", 443) == "https://127.0.0.1"
    assert probe.origin("http", 8080) == "http://127.0.0.1:8080"
    await probe.close()
    six = HostProbe("2001:db8::1", timeout=1, limiter=RateLimiter(1))
    assert six.url("https", 443, "/x") == "https://[2001:db8::1]:443/x"
    assert six.origin("https", 443) == "https://[2001:db8::1]"


async def test_rate_limiter_spaces_requests() -> None:
    limiter = RateLimiter(50)
    start = time.monotonic()
    for _ in range(6):
        await limiter.acquire()
    assert time.monotonic() - start >= 0.09 and limiter.count == 6
    unlimited = RateLimiter(0)
    await unlimited.acquire()


def test_device_text_is_cleaned() -> None:
    assert clean_text(None) is None and clean_text("  \x00 ") is None
    assert clean_text("a‮b\n c") == "a b c"
    assert clean_text("x" * 200) == "x" * 79 + "…"
    c = Candidate(
        address="192.0.2.1",
        role=DeviceRole.GATEWAY,
        model="<img src=x onerror=alert(1)>⁦",
        config={"url": "https://192.0.2.1\x00", "port": 1},
        note="n" * 400,
    )
    assert c.model == "<img src=x onerror=alert(1)>"  # stays text; the UI never parses it
    assert c.config == {"url": "https://192.0.2.1", "port": 1} and len(c.note or "") == 300


def test_hooks_are_optional_and_detected() -> None:
    adapters = load_adapters()
    hosts = sorted(k for k, cls in adapters.items() if probes_hosts(cls))
    casts = sorted(k for k, cls in adapters.items() if probes_broadcast(cls))
    assert hosts == ["fritzbox", "linux", "mikrotik", "omada", "openwrt", "opnsense"]
    assert casts == ["easysmart", "prosafe"]
    assert not probes_hosts(Adapter) and not probes_broadcast(Adapter)


async def test_default_hooks_find_nothing() -> None:
    assert await Adapter.discover(probe_for({})) is None
    assert await Adapter.discover_broadcast(NetworkProbe(1, RateLimiter(1))) is None


# --- where to look -------------------------------------------------------------------------


def test_parse_range() -> None:
    assert parse_range("192.0.2.5", 10) == ["192.0.2.5"]
    assert parse_range("192.0.2.0/30", 10) == ["192.0.2.1", "192.0.2.2"]
    assert parse_range("192.0.2.4/31", 10) == ["192.0.2.4", "192.0.2.5"]
    assert parse_range("192.0.2.10-12", 10) == ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
    assert parse_range("192.0.2.254-192.0.3.1", 10)[-1] == "192.0.3.1"
    assert parse_range("Fritz.Box", 10) == ["fritz.box"]
    assert parse_range("my-router", 10) == ["my-router"]
    assert parse_range("2001:db8::1", 10) == ["2001:db8::1"]
    for bad in (
        "",
        "192.0.2.0/22",
        "192.0.2.0/33",
        "192.0.2.10-5",
        "192.0.2.1-192.0.3.200",
        "192.0.2.1-x",
        "224.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "not an address!",
    ):
        with pytest.raises(RangeError):
            parse_range(bad, 300)


def test_infrastructure_hints() -> None:
    assert infrastructure("38:10:d5:00:00:01", None)  # AVM
    assert infrastructure("02:00:00:00:00:01", "fritz-repeater")
    assert infrastructure(None, "office-ap1") and infrastructure(None, "GS108E")
    assert not infrastructure("02:00:00:00:00:01", "laptop")
    assert not infrastructure(None, None)


def known_network() -> Network:
    gw = device("gw", role=DeviceRole.GATEWAY)
    seg = "home/segment/native"
    return Network(
        devices=[gw],
        subnets=[
            Subnet(
                id="gw/s/1",
                segment_id=seg,
                interface=ip_interface("192.0.2.1/29"),
                device_id="gw",
                gateway=True,
            ),
            Subnet(
                id="gw/s/2",
                segment_id=seg,
                interface=ip_interface("198.51.100.1/16"),
                device_id="gw",
                gateway=True,
            ),
            Subnet(
                id="gw/s/3",
                segment_id=seg,
                interface=ip_interface("2001:db8::1/64"),
                device_id="gw",
                gateway=True,
            ),
            Subnet(
                id="ap/s/1",
                segment_id=seg,
                interface=ip_interface("203.0.113.9/24"),
                device_id="ap",
            ),
        ],
        clients=[
            Client(
                id="c1",
                mac="02:00:00:00:00:01",
                addresses=["198.51.100.20", "2001:db8::20"],
                hostname="laptop",
            ),
            Client(
                id="c2",
                mac="02:00:00:00:00:02",
                addresses=["198.51.100.30"],
                hostname="office-switch",
            ),
            Client(id="c3", mac="02:00:00:00:00:03", addresses=["192.0.2.3"]),
        ],
        dhcp_servers=[
            DhcpServer(
                id="gw/dhcp",
                device_id="gw",
                segment_id=seg,
                enabled=True,
                reservations=[Reservation(mac="00:0c:42:00:00:01", address="198.51.100.40")],
            )
        ],
        neighbours=[
            Neighbour(
                id="n1",
                local_port_id="gw/port/1",
                chassis_id="02:00:00:00:00:09",
                management_address="198.51.100.50",
            ),
            Neighbour(
                id="n2", local_port_id="gw/port/2", chassis_id="x", management_address="not-an-ip"
            ),
        ],
    )


def test_plan_known_networks_infrastructure_first() -> None:
    p = plan(known_network(), ["203.0.113.7"])
    order = [t.address for t in p.targets]
    first = {
        "192.0.2.1",
        "198.51.100.1",
        "2001:db8::1",
        "198.51.100.30",
        "198.51.100.40",
        "198.51.100.50",
    }
    assert set(order[:6]) == first
    assert order[6] == "203.0.113.7"
    assert set(order[7:9]) == {"198.51.100.20", "192.0.2.3"}  # clients, then the sweep
    assert set(order[9:]) == {"192.0.2.2", "192.0.2.4", "192.0.2.5", "192.0.2.6"}
    assert "2001:db8::20" not in order and "203.0.113.9" not in order  # not a gateway subnet
    by = {t.address: t for t in p.targets}
    assert by["192.0.2.1"].gateway and by["192.0.2.3"].why == "client 02:00:00:00:00:03"
    assert not by["192.0.2.3"].gateway
    assert any("only the gateway" in s for s in p.scope) and any(
        "every address (6)" in s for s in p.scope
    )
    assert any("LLDP" in s for s in p.scope)
    only_mine = plan(known_network(), ["203.0.113.7"], known_networks=False)
    assert [t.address for t in only_mine.targets] == ["203.0.113.7"]


def test_plan_is_bounded() -> None:
    p = plan(known_network(), [], max_hosts=3)
    assert len(p.targets) == 3 and "only the first 3" in p.notes[0]
    assert plan(Network(), []).targets == []


# --- the engine through the API -----------------------------------------------------------


class Broken(Adapter):
    """A third-party integration whose probe raises: the run goes on and says so."""

    manifest = Manifest(
        id="broken",
        name="Broken",
        version="1",
        api_version="1.0",
        vendor="Example",
        roles=frozenset({DeviceRole.SWITCH}),
        capabilities=frozenset(),
        config=AdapterConfig,
    )

    async def read_system(self) -> SystemInfo:  # pragma: no cover - never read
        return SystemInfo()

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        raise RuntimeError("bug")

    @classmethod
    async def discover_broadcast(cls, probe: NetworkProbe) -> BroadcastResult | None:
        raise RuntimeError("bug")


class Slow(Broken):
    manifest = Broken.manifest.model_copy(update={"id": "slow", "name": "Slow"})

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        await asyncio.sleep(10)
        return None  # pragma: no cover - cancelled

    @classmethod
    async def discover_broadcast(cls, probe: NetworkProbe) -> BroadcastResult | None:
        return BroadcastResult(
            [
                Candidate(
                    address="192.0.2.77",
                    role=DeviceRole.GATEWAY,  # not a role of this integration
                    config={"address": "192.0.2.77", "unknown": "x"},
                    model="SW-1 ‮",
                )
            ],
            note="slow note",
        )


def make_services(tmp_path: Path, adapters: dict[str, type[Adapter]], **env: str) -> Services:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW, "SIGNALBOX_DISCOVERY_RATE_PER_SECOND": "500", **env},
        adapters=adapters,
        rules=[],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    return svc


def client_for(svc: Services, extra: dict[str, Any]) -> Iterator[TestClient]:
    from signalbox.web.app import create_app

    app = create_app(svc, run_background=False)
    app.state.discovery.extra = extra
    with TestClient(app) as c:
        assert c.post("/api/login", json={"password": PW}).status_code == 200
        yield c


def wait_done(c: TestClient) -> dict[str, Any]:
    for _ in range(300):
        status: dict[str, Any] = c.get("/api/discovery").json()
        if status["state"] != "running":
            return status
        time.sleep(0.05)
    raise AssertionError("discovery did not finish")


@pytest.fixture
def real(tmp_path: Path, sims: dict[str, int]) -> Iterator[TestClient]:
    adapters = {k: v for k, v in load_adapters().items() if k not in ("prosafe", "easysmart")}
    svc = make_services(tmp_path, adapters)
    yield from client_for(svc, {"ports": {**closed_ports(), **sims}})
    svc.close()


def test_api_finds_the_simulators_and_marks_added_ones(real: TestClient) -> None:
    c = real
    idle = c.get("/api/discovery").json()
    assert idle["state"] == "idle" and idle["candidates"] == [] and idle["enabled"]
    r = c.post("/api/discovery", json={"ranges": ["127.0.0.1"], "known_networks": False})
    assert r.status_code == 202 and r.json()["state"] == "running"
    assert c.post("/api/discovery", json={"ranges": ["127.0.0.1"]}).status_code == 409
    status = wait_done(c)
    assert status["state"] == "done" and status["total"] == status["done"] == 1
    assert status["requests"] >= 5 and status["finished_at"]
    assert status["scope"] == ["127.0.0.1: 1 address(es) you entered"]
    by = {x["adapter"]: x for x in status["candidates"]}
    assert set(by) == {"fritzbox", "mikrotik", "omada", "openwrt", "opnsense"}
    fritz = by["fritzbox"]
    assert fritz["name"] == "FRITZ!Box 7590" and fritz["adapter_name"] == "AVM Fritz!Box"
    assert fritz["why"] == "entered by you" and fritz["added"] is None and not fritz["ignored"]
    assert fritz["key"] == "fritzbox|127.0.0.1"
    assert by["omada"]["role"] == "other"
    # add the Fritz!Box with the prefilled settings: the candidate is marked as added
    body = {
        "name": fritz["name"],
        "site_id": "home",
        "role": fritz["role"],
        "adapter": "fritzbox",
        "config": {**fritz["config"], "password": "pw"},
    }
    added = c.post("/api/devices", json=body)
    assert added.status_code == 201, added.text
    status = c.get("/api/discovery").json()
    by = {x["adapter"]: x for x in status["candidates"]}
    assert by["fritzbox"]["added"] == added.json()["id"]
    assert status["candidates"][-1]["adapter"] == "fritzbox"  # added ones last
    # ignore and un-ignore
    r = c.post("/api/discovery/ignore", json={"key": "omada|127.0.0.1"})
    assert {x["adapter"]: x for x in r.json()["candidates"]}["omada"]["ignored"]
    r = c.post("/api/discovery/ignore", json={"key": "omada|127.0.0.1", "ignored": False})
    assert not {x["adapter"]: x for x in r.json()["candidates"]}["omada"]["ignored"]


def test_api_refuses_bad_input(real: TestClient) -> None:
    c = real
    r = c.post("/api/discovery", json={"ranges": ["192.0.2.0/16"]})
    assert r.status_code == 422 and "at most 1024" in r.json()["message"]
    r = c.post("/api/discovery", json={})
    assert r.status_code == 422 and r.json()["error"] == "nothing_to_probe"
    r = c.post("/api/discovery", json={"ranges": ["x" * 101]})
    assert r.status_code == 422


def test_a_known_network_is_probed_with_the_gateway_as_router(
    tmp_path: Path, sims: dict[str, int]
) -> None:
    svc = make_services(tmp_path, {"openwrt": OpenWrtAdapter})
    gw = device("gw", role=DeviceRole.GATEWAY)
    sub = Subnet(
        id="gw/subnet/lo",
        segment_id="home/segment/native",
        interface=ip_interface("127.0.0.1/30"),
        device_id="gw",
        gateway=True,
    )
    svc.store.put_device(
        DeviceRecord(
            id="gw", site_id="home", name="gw", role=DeviceRole.GATEWAY, adapter="openwrt"
        ),
        {"url": "https://192.0.2.200", "username": "u", "password": "p"},
        OpenWrtConfig,
    )
    svc.store.save_snapshot(snapshot(gw, subnets=[sub]))
    svc.runner.evaluate()
    for c in client_for(svc, {"ports": {**closed_ports(), **sims}}):
        assert c.post("/api/discovery", json={"broadcast": False}).status_code == 202
        status = wait_done(c)
        assert status["total"] == 2  # the gateway 127.0.0.1 and 127.0.0.2
        (cand,) = status["candidates"]
        assert cand["adapter"] == "openwrt" and cand["role"] == "gateway"
        assert cand["why"] == "gateway of 127.0.0.0/30 (gw)"
    svc.close()


def test_broken_probes_are_reported_not_fatal(tmp_path: Path) -> None:
    svc = make_services(
        tmp_path, {"broken": Broken, "slow": Slow}, SIGNALBOX_DISCOVERY_TIMEOUT_SECONDS="0.01"
    )
    for c in client_for(svc, {}):
        assert c.post("/api/discovery", json={"ranges": ["192.0.2.5"]}).status_code == 202
        status = wait_done(c)
        assert status["state"] == "done"
        assert (
            status["notes"].count(
                "The Broken probe failed (RuntimeError); its devices may be missing."
            )
            == 1
        )
        assert "slow note" in status["notes"]
        (cand,) = status["candidates"]
        assert cand["role"] == "switch" and cand["config"] == {}  # unknown keys dropped
        assert cand["name"] == "SW-1" and cand["why"] == "answered the broadcast"
    svc.close()


def test_discovery_can_be_turned_off(tmp_path: Path) -> None:
    svc = make_services(tmp_path, {"slow": Slow}, SIGNALBOX_DISCOVERY_ENABLED="false")
    for c in client_for(svc, {}):
        assert c.get("/api/discovery").json()["enabled"] is False
        r = c.post("/api/discovery", json={"ranges": ["192.0.2.5"]})
        assert r.status_code == 403 and r.json()["error"] == "disabled"
    svc.close()


def test_ignored_setting_survives_garbage(tmp_path: Path) -> None:
    svc = make_services(tmp_path, {"slow": Slow})
    for c in client_for(svc, {}):
        svc.store.set_setting("discovery.ignored", "not json")
        c.post("/api/discovery", json={"known_networks": False})
        assert wait_done(c)["candidates"][0]["ignored"] is False
        svc.store.set_setting("discovery.ignored", '{"a": 1}')
        assert c.get("/api/discovery").json()["candidates"][0]["ignored"] is False
    svc.close()


async def test_stopping_a_run_cancels_it(tmp_path: Path) -> None:
    from signalbox.discovery.engine import Discovery

    svc = make_services(tmp_path, {"slow": Slow})
    d = Discovery(svc.store, svc.runner, svc.adapters, svc.config.discovery)
    d.start(["192.0.2.5"], broadcast=False)
    await asyncio.sleep(0.05)
    await d.stop()
    assert d.run is not None and d.run.state == "failed" and d.run.finished_at
    await d.stop()  # idempotent
    svc.close()


def test_normal_host() -> None:
    assert normal_host("https://[2001:DB8::1]:443/ubus") == "2001:db8::1"
    assert normal_host(" Fritz.Box ") == "fritz.box"
    assert normal_host("192.0.2.010") == "192.0.2.010"  # not an address: compared as text


# --- switches: the broadcast through Switchyard's simulators -------------------------------


@needs_switchyard
async def test_switch_broadcasts_find_the_simulators() -> None:
    from switchyard.easysmart.sim import EasySmartSimulator, SimEasySmart
    from switchyard.sim import SimSwitch, Simulator

    from signalbox.adapters.plusswitch import EasySmartAdapter, ProsafeAdapter

    netgear = Simulator([SimSwitch("02:00:00:00:10:01", ip="192.0.2.10", name="office")])
    tplink = EasySmartSimulator([SimEasySmart("02:00:00:00:20:01", ip="192.0.2.11", name="")])
    n_port, t_port = await netgear.start(), await tplink.start()
    try:
        extra = {
            "prosafe": {"client_port": 0, "targets": [f"127.0.0.1:{n_port}"], "seconds": 0.5},
            "easysmart": {"client_port": 0, "targets": [f"127.0.0.1:{t_port}"], "seconds": 0.5},
        }
        probe = NetworkProbe(1.0, RateLimiter(100), extra)
        found = await ProsafeAdapter.discover_broadcast(probe)
        assert found is not None and found.note is None
        (sw,) = found.candidates
        assert sw.address == "192.0.2.10" and sw.config == {"address": "192.0.2.10"}
        assert sw.name == "office" and sw.model == "GS108E" and sw.mac == "02:00:00:00:10:01"
        found = await EasySmartAdapter.discover_broadcast(probe)
        assert found is not None and found.note is None
        (sw,) = found.candidates
        assert sw.address == "192.0.2.11" and sw.vendor == "TP-Link"
        assert sw.name == sw.model and sw.role is DeviceRole.SWITCH
    finally:
        netgear.stop()
        tplink.stop()
    # nobody answers: the result says why that may be
    quiet = NetworkProbe(
        1.0,
        RateLimiter(100),
        {
            name: {"client_port": 0, "targets": [f"127.0.0.1:{free_port()}"], "seconds": 0.2}
            for name in ("prosafe", "easysmart")
        },
    )
    for cls in (ProsafeAdapter, EasySmartAdapter):
        result = await cls.discover_broadcast(quiet)
        assert result is not None and result.candidates == []
        assert "host networking" in (result.note or "")


@needs_switchyard
async def test_switch_broadcast_problems_become_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from signalbox.adapters.plusswitch import EasySmartAdapter, ProsafeAdapter
    from signalbox.adapters.plusswitch import discovery as plus

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("0.0.0.0", 0))
        port = busy.getsockname()[1]
        probe = NetworkProbe(
            1.0, RateLimiter(100), {n: {"client_port": port} for n in ("prosafe", "easysmart")}
        )
        for cls in (ProsafeAdapter, EasySmartAdapter):
            result = await cls.discover_broadcast(probe)
            assert result is not None and "cannot send the broadcast" in (result.note or "")
    assert plus._address({"ip": None}, "0.0.0.0") is None
    assert plus._candidates([({"ip": "x"}, None)], "NETGEAR", "x") == []

    async def garbled(*args: Any, **kw: Any) -> Any:
        raise ValueError("garbled")

    monkeypatch.setattr("switchyard.nsdp.discover", garbled)
    monkeypatch.setattr("switchyard.easysmart.transport.EasySmartTransport.collect", garbled)
    probe = NetworkProbe(
        1.0,
        RateLimiter(100),
        {n: {"client_port": 0, "targets": ["127.0.0.1:9"]} for n in ("prosafe", "easysmart")},
    )
    for cls in (ProsafeAdapter, EasySmartAdapter):
        result = await cls.discover_broadcast(probe)
        assert result is not None and "garbled" in (result.note or "")
    for name in ("switchyard.nsdp", "switchyard.easysmart.client"):
        monkeypatch.setitem(sys.modules, name, None)
    for cls in (ProsafeAdapter, EasySmartAdapter):
        result = await cls.discover_broadcast(probe)
        assert result is not None and "needs Switchyard" in (result.note or "")


# --- one device on several addresses (#224) ----------------------------------------------------


class DualConfig(AdapterConfig):
    host: str = ""


class Dual(Adapter):
    """A firewall behind an ISP router: answers on its WAN and on its LAN address with the
    same serial number (what a probe reads), one of them slower."""

    manifest = Manifest(
        id="dual",
        name="Dual",
        version="1",
        api_version="1.0",
        vendor="Example",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset(),
        config=DualConfig,
    )
    answers: dict[str, tuple[float, list[str], str | None]] = {
        "192.0.2.10": (0.0, ["serial:FW-1"], None),  # WAN, in the outer network
        "198.51.100.10": (0.3, ["serial:FW-1"], None),  # LAN, answers later
        "198.51.100.20": (0.0, [], "02:00:5e:00:00:01"),  # only the MAC says who it is
        "192.0.2.20": (0.0, [], "02:00:5E:00:00:01"),
        "192.0.2.30": (0.0, ["serial:OTHER"], None),
    }

    async def read_system(self) -> SystemInfo:  # pragma: no cover - never read
        return SystemInfo()

    @classmethod
    async def discover(cls, probe: HostProbe) -> Candidate | None:
        if probe.host not in cls.answers:
            return None
        delay, identities, mac = cls.answers[probe.host]
        await asyncio.sleep(delay)
        return Candidate(
            address=probe.host,
            role=DeviceRole.GATEWAY,
            config={"host": probe.host},
            identities=identities,
            mac=mac,
        )


def dual_client(tmp_path: Path) -> tuple[Services, Iterator[TestClient]]:
    svc = make_services(tmp_path, {"dual": Dual})
    return svc, client_for(svc, {})


def search(c: TestClient, *addresses: str) -> dict[str, Any]:
    r = c.post("/api/discovery", json={"ranges": list(addresses), "known_networks": False})
    assert r.status_code == 202
    return wait_done(c)


def test_one_device_on_two_addresses_is_one_entry(tmp_path: Path) -> None:
    svc, clients = dual_client(tmp_path)
    for c in clients:
        status = search(c, "192.0.2.10", "198.51.100.10", "192.0.2.30")
        by = {x["addresses"][0]: x for x in status["candidates"]}
        assert len(status["candidates"]) == 2  # a different serial number stays apart
        fw = by["192.0.2.10"]  # nothing known about the networks: the first that answered
        assert fw["address"] == "192.0.2.10"
        assert fw["addresses"] == ["192.0.2.10", "198.51.100.10"]
        assert fw["config"] == {"host": "192.0.2.10"} and fw["added"] is None
        assert "identities" not in fw
        assert status["candidates"][0]["key"] == "dual|192.0.2.10" or fw["key"] == "dual|192.0.2.10"
    svc.close()


def test_the_address_in_a_known_network_is_offered(tmp_path: Path) -> None:
    svc, clients = dual_client(tmp_path)
    gw = device("isp", role=DeviceRole.GATEWAY)
    sub = Subnet(
        id="isp/subnet/lan",
        segment_id="home/segment/native",
        interface=ip_interface("198.51.100.1/24"),
        device_id="isp",
        gateway=True,
    )
    svc.store.put_device(
        DeviceRecord(id="isp", site_id="home", name="isp", role=DeviceRole.GATEWAY, adapter="x"),
        {},
        AdapterConfig,
    )
    svc.store.save_snapshot(snapshot(gw, subnets=[sub]))
    for c in clients:
        (fw,) = search(c, "192.0.2.10", "198.51.100.10")["candidates"]
        assert fw["address"] == "198.51.100.10" and fw["config"] == {"host": "198.51.100.10"}
        assert fw["addresses"] == ["198.51.100.10", "192.0.2.10"]
    svc.close()


def add_firewall(svc: Services, host: str, **snap: Any) -> None:
    svc.store.put_device(
        DeviceRecord(id="fw", site_id="home", name="fw", role=DeviceRole.GATEWAY, adapter="dual"),
        {"host": host},
        DualConfig,
    )
    if snap:
        svc.store.save_snapshot(snapshot(device("fw", adapter="dual"), **snap))


def test_a_device_added_by_its_lan_address_is_marked_when_found_by_its_wan_address(
    tmp_path: Path,
) -> None:
    """The reported case: added by 198.51.100.10, found only at 192.0.2.10, its uplink."""
    svc, clients = dual_client(tmp_path)
    for c in clients:
        assert search(c, "192.0.2.10")["candidates"][0]["added"] is None
        add_firewall(svc, "198.51.100.10")  # nothing observed yet, another address
        assert c.get("/api/discovery").json()["candidates"][0]["added"] is None
        add_firewall(
            svc, "198.51.100.10", uplinks=[uplink("fw", addresses=[iface("192.0.2.10/24")])]
        )
        (fw,) = c.get("/api/discovery").json()["candidates"]
        assert fw["added"] == "fw" and fw["addresses"] == ["192.0.2.10"]
    svc.close()


def test_added_by_any_known_address_or_identity(tmp_path: Path) -> None:
    svc, clients = dual_client(tmp_path)
    for c in clients:
        search(c, "192.0.2.10", "192.0.2.20", "192.0.2.30")
        by = {x["address"]: x for x in c.get("/api/discovery").json()["candidates"]}
        assert {x["added"] for x in by.values()} == {None}

        def added(c: TestClient = c) -> dict[str, Any]:
            rows = c.get("/api/discovery").json()["candidates"]
            return {x["address"]: x["added"] for x in rows}

        # a subnet address of the device (its LAN interface), management address, public address
        add_firewall(
            svc,
            "203.0.113.9",
            subnets=[
                Subnet(
                    id="fw/subnet/lan",
                    segment_id="home/segment/native",
                    interface=ip_interface("192.0.2.10/24"),
                    device_id="fw",
                )
            ],
        )
        assert added() == {"192.0.2.10": "fw", "192.0.2.20": None, "192.0.2.30": None}
        snap = snapshot(
            device("fw", adapter="dual", management_address="192.0.2.30"),
            uplinks=[uplink("fw", addresses=[], public_ipv4="192.0.2.20")],
        )
        svc.store.save_snapshot(snap)
        assert added() == {"192.0.2.10": None, "192.0.2.20": "fw", "192.0.2.30": "fw"}
        # the same MAC on a port, whatever the address
        svc.store.save_snapshot(
            snapshot(
                device("fw", adapter="dual"), ports=[port("fw", "wan", mac="02:00:5e:00:00:01")]
            )
        )
        assert added() == {"192.0.2.10": None, "192.0.2.20": "fw", "192.0.2.30": None}
    svc.close()


def test_a_merged_entry_is_ignored_and_shown_again_as_a_whole(tmp_path: Path) -> None:
    svc, clients = dual_client(tmp_path)
    for c in clients:
        (fw,) = search(c, "192.0.2.10", "198.51.100.10")["candidates"]
        other = "dual|198.51.100.10" if fw["key"] == "dual|192.0.2.10" else "dual|192.0.2.10"
        assert c.post("/api/discovery/ignore", json={"key": other}).json()["candidates"][0][
            "ignored"
        ]
        shown = c.post("/api/discovery/ignore", json={"key": fw["key"], "ignored": False}).json()
        assert not shown["candidates"][0]["ignored"]
        assert c.get("/api/discovery").json()["candidates"][0]["ignored"] is False
    svc.close()


def test_identities_are_normalised() -> None:
    from signalbox.discovery.engine import identities_of

    mac = Candidate(address="192.0.2.1", role=DeviceRole.AP, mac="02:00:5E:00:00:01")
    assert identities_of(mac) == {"mac:02:00:5e:00:00:01"}
    bad = Candidate(address="192.0.2.1", role=DeviceRole.AP, mac="no mac", identities=["a:b"])
    assert identities_of(bad, "ab12") == {"a:b", "cert:ab12"}


async def test_the_certificate_fingerprint_is_read_and_matches_the_pinned_one(
    sims: dict[str, int],
) -> None:
    from signalbox.adapters.https import fingerprint, peer_certificate

    probe = probe_for({})
    port_ = sims["omada.https"]
    assert (await probe.get("https", port_, "/api/info")) is not None
    der = await peer_certificate("127.0.0.1", port_, 3)
    url = f"https://127.0.0.1:{port_}"
    assert probe.certificate_of({"url": url}) == fingerprint(der)
    assert probe.certificate_of({"url": "https://127.0.0.1:1"}) is None
    assert probe.certificate_of({"url": 5}) is None and probe.certificate_of({}) is None
    assert probe.certificate_of({"url": "http://[bad"}) is None
    assert probe.certificate_of({"url": "http://127.0.0.1"}) is None
    await probe.close()


def test_the_same_certificate_is_the_same_device(tmp_path: Path, sims: dict[str, int]) -> None:
    """OPNsense tells no identity: one simulator reached as 127.0.0.1 and as localhost is one
    device because both answers carry its certificate."""
    svc = make_services(tmp_path, {"opnsense": OpnsenseAdapter})
    for c in client_for(svc, {"ports": {**closed_ports(), **sims}}):
        (fw,) = search(c, "127.0.0.1", "localhost")["candidates"]
        assert sorted(fw["addresses"]) == ["127.0.0.1", "localhost"] and fw["added"] is None
        # a device added at another address, but with this certificate pinned, is the same
        from signalbox.adapters.https import fingerprint, peer_certificate

        der = asyncio.run(peer_certificate("127.0.0.1", sims["opnsense.https"], 3))
        svc.store.put_device(
            DeviceRecord(
                id="fw",
                site_id="home",
                name="fw",
                role=DeviceRole.GATEWAY,
                adapter="opnsense",
                pinned_fingerprint=fingerprint(der).upper(),
            ),
            {"url": "https://192.0.2.99", "api_key": "k", "api_secret": "s"},
            OpnsenseConfig,
        )
        assert c.get("/api/discovery").json()["candidates"][0]["added"] == "fw"
    svc.close()
