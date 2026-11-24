"""Path traces (#253): matching, routed view, checks, storage, the tracer and its API."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Iterator
from datetime import timedelta
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from factories import SITE, T0, device, iface, site_link, snapshot, uplink
from signalbox.adapters import (
    Adapter,
    AdapterConfig,
    AdapterError,
    AuthFailed,
    Manifest,
    SystemInfo,
    TraceAnswer,
    TraceSupport,
)
from signalbox.model import (
    DeviceRole,
    Network,
    PathTrace,
    Site,
    Subnet,
    TraceHop,
    object_id,
    trace_id,
)
from signalbox.rules import evaluate
from signalbox.rules.traces import extra_nat, not_via_tunnel
from signalbox.secrets import load_vault
from signalbox.service import Services, build
from signalbox.store import SCHEMA, DeviceRecord, Store
from signalbox.tracer import Pair, TraceError, Tracer
from signalbox.traces import (
    attach,
    gateway_target,
    hop_kind,
    in_front,
    match,
    routed_view,
    tunnel_of,
)
from signalbox.web.app import create_app

PW = "trace-test-password"
B = Site(id="b", name="Other site")


def sub(device_id: str, address: str, name: str = "lan", gateway: bool = True) -> Subnet:
    return Subnet(
        id=object_id(device_id, "subnet", name),
        segment_id=f"{SITE.id}/segment/native",
        interface=iface(address),
        device_id=device_id,
        gateway=gateway,
    )


def hops(*items: tuple[str | None, float | None]) -> list[TraceHop]:
    return [
        TraceHop(ttl=i, address=ip_address(a) if a else None, rtt_ms=r)
        for i, (a, r) in enumerate(items, start=1)
    ]


def trace(
    source: str, target: str, *items: tuple[str | None, float | None], **kw: Any
) -> PathTrace:
    return PathTrace(
        id=trace_id(source, target),
        source=source,
        target=ip_address(target),
        started_at=T0,
        hops=hops(*items),
        reached=kw.pop("reached", True),
        **kw,
    )


def two_sites() -> Network:
    """fw (home, LAN 192.0.2.1/24, public uplink) and pi (site b, LAN 198.51.100.1/24 behind
    a site-to-site tunnel; tunnel addresses 2001:db8:ff::1 and ::2)."""
    fw_t, pi_t = site_link("fw", "pi")
    return Network(
        sites=[SITE, B],
        devices=[device("fw"), device("pi", site_id="b"), device("sw", DeviceRole.SWITCH)],
        subnets=[sub("fw", "192.0.2.1/24"), sub("pi", "198.51.100.1/24")],
        uplinks=[uplink("fw", addresses=[iface("203.0.113.2/24")])],
        tunnels=[fw_t, pi_t],
    )


# matching and the routed view ----------------------------------------------------------------


def test_match_subnet_uplink_tunnel_and_management_address() -> None:
    net = two_sites()
    net = net.model_copy(
        update={
            "devices": [*net.devices, device("ap", DeviceRole.AP, management_address="[192.0.2.5]")]
        }
    )
    assert match(net, ip_address("192.0.2.1")) == ("fw", "fw/subnet/lan")
    assert match(net, ip_address("203.0.113.2")) == ("fw", "fw/uplink/wan")
    assert match(net, ip_address("2001:db8:ff::2")) == ("pi", "pi/tunnel/wg0")
    assert match(net, ip_address("192.0.2.5")) == ("ap", None)
    assert match(net, ip_address("192.0.2.99")) == (None, None)


def test_attach_and_routed_view() -> None:
    net = attach(
        two_sites(),
        [
            trace(
                "fw",
                "198.51.100.1",
                ("2001:db8:ff::2", 9.0),
                ("198.51.100.1", 10.5),
                purpose="gateway",
            ),
            trace(
                "pi",
                "1.1.1.1",
                ("192.0.2.1", 1.0),
                ("10.0.0.1", 2.0),
                ("100.64.0.1", 3.0),
                ("1.1.1.1", 9.0),
                purpose="internet",
            ),
            trace("signalbox", "203.0.113.9", (None, None), reached=False, error="no result"),
        ],
    )
    first = next(t for t in net.traces if t.source == "fw")
    assert first.target_device == "pi"
    assert first.hops[0].device_id == "pi" and first.hops[0].interface_id == "pi/tunnel/wg0"
    view = routed_view(net)
    by_id = {p["id"]: p for p in view["paths"]}
    path = by_id["trace/fw/198.51.100.1"]
    assert path["tunnels"] == ["pi/tunnel/wg0"] and path["rtt_ms"] == 10.5
    assert path["target_name"] == "pi" and path["source_name"] == "fw"
    assert [h["kind"] for h in by_id["trace/pi/1.1.1.1"]["hops"]] == [
        "device",
        "private",
        "cgnat",
        "public",
    ]
    failed = by_id["trace/signalbox/203.0.113.9"]
    assert failed["source_name"] == "Signalbox" and failed["error"] and failed["rtt_ms"] is None
    assert view["in_front"] == [
        {
            "behind": "fw",
            "front": None,
            "address": "10.0.0.1",
            "kind": "private",
            "traces": ["trace/pi/1.1.1.1"],
        },
        {
            "behind": "pi",
            "front": "fw",
            "address": None,
            "kind": "device",
            "traces": ["trace/pi/1.1.1.1"],
        },
    ]


def test_in_front_skips_errors_and_other_purposes() -> None:
    net = attach(
        two_sites(),
        [
            trace("pi", "1.1.1.1", ("192.0.2.1", 1.0), error="x", purpose="internet"),
            trace("pi", "192.0.2.1", ("192.0.2.1", 1.0), purpose="gateway"),
            trace(
                "signalbox",
                "1.1.1.1",
                ("192.0.2.1", 1.0),
                ("192.0.2.1", 1.0),
                (None, None),
                purpose="internet",
            ),
        ],
    )
    assert in_front(net) == []


def test_tunnel_of_and_hop_kind() -> None:
    net = two_sites()
    other = TraceHop(ttl=1, address=ip_address("2001:db8:ff::77"))
    assert tunnel_of(net, other) == "fw/tunnel/wg0"
    assert tunnel_of(net, TraceHop(ttl=1)) is None
    assert tunnel_of(net, TraceHop(ttl=1, address=ip_address("192.0.2.9"))) is None
    assert hop_kind(TraceHop(ttl=1, address=ip_address("fd00::1"))) == "private"
    assert hop_kind(TraceHop(ttl=1, address=ip_address("2001:db8::1"))) == "public"
    assert hop_kind(TraceHop(ttl=1)) == "none"


def test_gateway_target() -> None:
    net = two_sites()
    fw, pi = net.device("fw"), net.device("pi")
    assert fw and pi
    assert gateway_target(net, pi, "fw") == ip_address("198.51.100.1")
    # a router behind fw: its uplink address in fw's LAN is what fw reaches
    behind = net.model_copy(
        update={
            "devices": [*net.devices, device("nat")],
            "uplinks": [*net.uplinks, uplink("nat", addresses=[iface("192.0.2.20/24")])],
            "subnets": [*net.subnets, sub("nat", "10.0.0.1/24")],
        }
    )
    nat = behind.device("nat")
    assert nat
    assert gateway_target(behind, nat, "fw") == ip_address("192.0.2.20")
    assert gateway_target(behind, nat, "pi") == ip_address("10.0.0.1")
    v6 = Network(
        devices=[device("x", management_address="127.0.0.1")],
        subnets=[sub("x", "2001:db8:5::1/64")],
    )
    x = v6.device("x")
    assert x and gateway_target(v6, x) == ip_address("2001:db8:5::1")
    m = Network(devices=[device("y", management_address="192.0.2.7")])
    y = m.device("y")
    assert y and gateway_target(m, y) == ip_address("192.0.2.7")
    assert gateway_target(Network(devices=[device("z")]), device("z")) is None


# checks ------------------------------------------------------------------------------------


def results(rule: Any, net: Network) -> list[Any]:
    return list(rule.check(net))


def test_not_via_tunnel() -> None:
    bad = attach(
        two_sites(), [trace("fw", "198.51.100.1", ("203.0.113.1", 1.0), ("198.51.100.1", 9.0))]
    )
    (res,) = results(not_via_tunnel, bad)
    assert "203.0.113.1" in res.message and "trace/fw/198.51.100.1" in res.objects
    quiet = [
        trace(
            "fw", "198.51.100.1", ("2001:db8:ff::2", 1.0), ("198.51.100.1", 9.0)
        ),  # in the tunnel
        trace("fw", "198.51.100.1", ("198.51.100.1", 9.0)),  # one hop: cannot tell
        trace("fw", "198.51.100.1", ("203.0.113.1", 1.0), (None, None), ("198.51.100.1", 9.0)),
        trace("fw", "198.51.100.1", ("203.0.113.1", 1.0), reached=False),
        trace("signalbox", "198.51.100.1", ("203.0.113.1", 1.0), ("198.51.100.1", 9.0)),
        trace("fw", "1.1.1.1", ("203.0.113.1", 1.0), ("1.1.1.1", 9.0)),  # not routed by it
    ]
    for t in quiet:
        assert results(not_via_tunnel, attach(two_sites(), [t])) == [], t.id
    down = two_sites()
    down = down.model_copy(
        update={"tunnels": [t.model_copy(update={"up": False}) for t in down.tunnels]}
    )
    assert results(not_via_tunnel, attach(down, [bad.traces[0]])) == []
    off = two_sites()
    tunnels = [
        t.model_copy(update={"peers": [p.model_copy(update={"enabled": False}) for p in t.peers]})
        for t in off.tunnels
    ]
    assert (
        results(
            not_via_tunnel, attach(off.model_copy(update={"tunnels": tunnels}), [bad.traces[0]])
        )
        == []
    )
    # a hop that is one of the peer's allowed IPs counts as inside the tunnel
    fw = bad.tunnels[0]
    peer = fw.peers[0].model_copy(
        update={"allowed_ips": [*fw.peers[0].allowed_ips, ip_network("203.0.113.1/32")]}
    )
    via = bad.model_copy(
        update={"tunnels": [fw.model_copy(update={"peers": [peer]}), bad.tunnels[1]]}
    )
    assert results(not_via_tunnel, via) == []


def test_extra_nat() -> None:
    base = two_sites()
    one = trace("fw", "1.1.1.1", ("10.0.0.1", 1.0), ("1.1.1.1", 9.0), purpose="internet")
    (res,) = results(extra_nat, attach(base, [one]))
    assert "1 router(s)" in res.message and "expects 0" in res.message and "10.0.0.1" in res.message
    # pi behind fw: one known router with a private... public address in front -> expect 1
    behind = base.model_copy(
        update={
            "uplinks": [
                uplink("fw", addresses=[iface("192.168.178.2/24")]),
                uplink("pi", addresses=[iface("192.168.1.20/24")]),
            ],
            "subnets": [sub("fw", "192.168.1.1/24"), sub("pi", "198.51.100.1/24")],
        }
    )
    ok = trace(
        "pi",
        "1.1.1.1",
        ("192.168.1.1", 1.0),
        ("192.168.178.1", 2.0),
        ("1.1.1.1", 9.0),
        purpose="internet",
    )
    assert results(extra_nat, attach(behind, [ok])) == []  # expected: fw and the box in front
    more = trace(
        "pi",
        "1.1.1.1",
        ("192.168.1.1", 1.0),
        ("192.168.178.1", 2.0),
        ("10.1.1.1", 2.0),
        ("1.1.1.1", 9.0),
        purpose="internet",
    )
    (res,) = results(extra_nat, attach(behind, [more]))
    assert "3 router(s)" in res.message and "expects 2" in res.message
    quiet = [
        trace("fw", "1.1.1.1", ("10.0.0.1", 1.0), ("1.1.1.1", 9.0), purpose="gateway"),
        trace("signalbox", "1.1.1.1", ("10.0.0.1", 1.0), ("1.1.1.1", 9.0), purpose="internet"),
        trace(
            "fw", "1.1.1.1", ("10.0.0.1", 1.0), (None, None), ("1.1.1.1", 9.0), purpose="internet"
        ),
        trace("fw", "2001:db8::9", ("2001:db8::1", 1.0), ("2001:db8::9", 9.0), purpose="internet"),
        trace("fw", "10.9.9.9", ("10.0.0.1", 1.0), ("10.9.9.9", 9.0), purpose="internet"),
        trace(
            "pi", "1.1.1.1", ("10.0.0.1", 1.0), ("1.1.1.1", 9.0), purpose="internet"
        ),  # no uplink read
    ]
    for t in quiet:
        assert results(extra_nat, attach(base, [t])) == [], t.id
    unknown = base.model_copy(update={"uplinks": [uplink("fw", addresses=[], kind="bridge")]})
    assert results(extra_nat, attach(unknown, [one])) == []
    cgnat = trace("fw", "1.1.1.1", ("100.64.0.1", 1.0), ("1.1.1.1", 9.0), purpose="internet")
    assert results(extra_nat, attach(base, [cgnat])) == []
    loop = base.model_copy(
        update={
            "uplinks": [
                uplink("fw", addresses=[iface("198.51.100.7/24")]),
                uplink("pi", addresses=[iface("192.0.2.7/24")]),
            ],
            "subnets": [sub("fw", "192.0.2.1/24"), sub("pi", "198.51.100.1/24")],
        }
    )
    deep = trace(
        "fw",
        "1.1.1.1",
        *[(f"10.0.0.{i}", 1.0) for i in range(1, 5)],
        ("1.1.1.1", 9.0),
        purpose="internet",
    )
    assert len(results(extra_nat, attach(loop, [deep]))) == 1


def test_checks_quiet_without_traces() -> None:
    findings = evaluate(two_sites(), [not_via_tunnel, extra_nat])
    assert [f for f in findings if f.rule_id.startswith("trace.")] == []


# storage ------------------------------------------------------------------------------------


def test_store_migration_and_traces(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    db = sqlite3.connect(path)
    db.executescript("BEGIN; " + "; ".join(SCHEMA[:4]) + "; PRAGMA user_version = 4; COMMIT;")
    db.close()
    store = Store(path, load_vault(tmp_path, env={}))
    try:
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == len(SCHEMA) == 7
        old = trace("fw", "1.1.1.1", ("1.1.1.1", 1.0)).model_copy(
            update={"started_at": T0 - timedelta(days=40)}
        )
        store.put_trace(old)
        new = trace("fw", "1.1.1.1", ("192.0.2.254", 1.0), ("1.1.1.1", 2.0))
        store.put_trace(new)
        store.put_trace(trace("pi", "1.1.1.1", ("1.1.1.1", 1.0)))
        assert [t.id for t in store.traces()] == ["trace/fw/1.1.1.1", "trace/pi/1.1.1.1"]
        assert len(store.traces()[0].hops) == 2  # the latest per pair
        assert store.prune_traces(T0 - timedelta(days=1)) == 0
        assert store.delete_traces("pi") == 1
        assert store.delete_traces() == 1
    finally:
        store.close()


# the tracer and its API -----------------------------------------------------------------------


class TrConfig(AdapterConfig):
    mode: str = "ok"


ROUTES: dict[tuple[str, str], Any] = {}


class Tr(Adapter):
    manifest = Manifest(
        id="tr",
        name="Tracing router",
        version="1",
        api_version="1.3",
        vendor="Test",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset(),
        config=TrConfig,
        traces=TraceSupport(permission="a test permission", method="test"),
    )

    async def read_system(self) -> SystemInfo:
        return SystemInfo()

    async def trace(self, target: Any, max_hops: int, wait: float) -> TraceAnswer:
        mode = self.context.config.mode  # type: ignore[attr-defined]
        if mode == "slow":
            await asyncio.sleep(30)
        if mode == "denied":
            raise AuthFailed("may not trace", fix="grant it", remedy="privileges")
        if mode == "broken":
            raise RuntimeError("boom")
        if mode == "missing":
            raise NotImplementedError
        found = ROUTES.get((self.context.device_id, str(target)))
        if isinstance(found, Exception):
            raise found
        return found or TraceAnswer(
            hops=[TraceHop(ttl=1, address=target, rtt_ms=1.0)], reached=True
        )


class Plain(Adapter):
    manifest = Manifest(
        id="plain",
        name="Plain",
        version="1",
        api_version="1.3",
        vendor="Test",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset(),
        config=TrConfig,
    )

    async def read_system(self) -> SystemInfo:
        return SystemInfo()


def services_for(tmp_path: Path, **env: str) -> Services:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW, "SIGNALBOX_TRACES_MIN_GAP_SECONDS": "0", **env},
        adapters={"tr": Tr, "plain": Plain},
        rules=[not_via_tunnel, extra_nat],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    svc.store.put_site(B)
    for dev_id, site, adapter, mode in (
        ("fw", "home", "tr", "ok"),
        ("pi", "b", "tr", "ok"),
        ("box", "home", "plain", "ok"),
    ):
        rec = DeviceRecord(
            id=dev_id, site_id=site, name=dev_id.upper(), role=DeviceRole.GATEWAY, adapter=adapter
        )
        svc.store.put_device(rec, {"mode": mode}, TrConfig)
    net = two_sites()
    for dev_id in ("fw", "pi", "box"):
        d = device(dev_id, adapter="tr", site_id="b" if dev_id == "pi" else "home")
        svc.store.save_snapshot(
            snapshot(
                d,
                subnets=[s for s in net.subnets if s.device_id == dev_id]
                or ([sub("box", "192.0.2.250/24", gateway=True)] if dev_id == "box" else []),
                uplinks=[u for u in net.uplinks if u.device_id == dev_id],
                tunnels=[t for t in net.tunnels if t.device_id == dev_id],
            )
        )
    return svc


@pytest.fixture
def svc(tmp_path: Path) -> Iterator[Services]:
    ROUTES.clear()
    s = services_for(tmp_path, SIGNALBOX_TRACES_ENABLED="true")
    yield s
    s.close()


async def host(target: Any, max_hops: int, wait: float) -> TraceAnswer:
    return TraceAnswer(
        hops=[
            TraceHop(ttl=1, address=ip_address("192.0.2.1"), rtt_ms=0.3),
            TraceHop(ttl=2, address=target, rtt_ms=5.0),
        ],
        reached=True,
    )


def tracer(svc: Services) -> Tracer:
    return Tracer(svc.store, svc.runner, svc.adapters, svc.config, host_trace=host)


async def finish(t: Tracer) -> None:
    for _ in range(200):
        if not t.running:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("run did not finish")


async def test_plan_all_and_chosen(svc: Services) -> None:
    t = tracer(svc)
    net = svc.runner.network()
    pairs = t.plan(net)
    sources = {p.source for p in pairs}
    assert sources == {"signalbox", "fw", "pi"}  # box's integration cannot trace
    assert Pair("fw", ip_address("198.51.100.1"), "gateway", "pi") in pairs
    assert Pair("fw", ip_address("1.1.1.1"), "internet") in pairs
    assert any(p.target_device == "box" for p in pairs)
    assert t.plan(net, "fw", "pi") == [Pair("fw", ip_address("198.51.100.1"), "gateway", "pi")]
    assert t.plan(net, "fw", "1.1.1.1")[0].purpose == "internet"
    assert t.plan(net, "fw", "192.0.2.250") == [
        Pair("fw", ip_address("192.0.2.250"), "address", "box")
    ]
    assert {p.source for p in t.plan(net, None, "box")} == {"signalbox", "fw", "pi"}
    for args, code in (
        (("box", None), "not_supported"),
        (("nope", None), "not_supported"),
        (("fw", "fw.example"), "invalid"),
        (("fw", "fw"), "nothing"),
    ):
        with pytest.raises(TraceError) as err:
            t.plan(net, *args)
        assert err.value.code == code


async def test_plan_limits_and_settings(tmp_path: Path) -> None:
    s = services_for(
        tmp_path,
        SIGNALBOX_TRACES_ENABLED="true",
        SIGNALBOX_TRACES_MAX_PAIRS="2",
        SIGNALBOX_TRACES_FROM_SIGNALBOX="false",
        SIGNALBOX_TRACES_INTERNET_TARGET="",
    )
    try:
        t = tracer(s)
        net = s.runner.network()
        pairs = t.plan(net)
        assert len(pairs) == 2 and t.limited and "signalbox" not in {p.source for p in pairs}
        with pytest.raises(TraceError, match="turned off"):
            t.plan(net, "signalbox")
        assert [x["id"] for x in t.sources(net)] == ["BOX".lower(), "fw", "pi"]
        net2 = net.model_copy(
            update={
                "devices": [d for d in net.devices if d.id == "fw"] + [device("pi", site_id="b")],
                "subnets": [x for x in net.subnets if x.device_id == "fw"],
            }
        )
        with pytest.raises(TraceError, match="no address"):
            t.plan(net2, "fw", "pi")
    finally:
        s.close()


async def test_run_stores_traces_and_errors(svc: Services) -> None:
    ROUTES[("fw", "198.51.100.1")] = TraceAnswer(
        hops=[
            TraceHop(ttl=1, address=ip_address("203.0.113.1"), rtt_ms=1.0),
            TraceHop(ttl=2, address=ip_address("198.51.100.1"), rtt_ms=9.0),
            TraceHop(ttl=40, address=ip_address("198.51.100.1")),
        ],
        reached=True,
    )
    ROUTES[("pi", "1.1.1.1")] = AdapterError("device said no", fix="do this")
    t = tracer(svc)
    status = t.start()
    assert status["running"] and status["total"] == len(t.pairs)
    with pytest.raises(TraceError) as err:
        t.start()
    assert err.value.code == "running"
    await finish(t)
    done = t.status()
    assert done["done"] == done["total"] and not done["running"]
    assert {p["state"] for p in done["pairs"]} == {"done", "failed"}
    net = svc.runner.network()
    by_id = {x.id: x for x in net.traces}
    bad = by_id["trace/fw/198.51.100.1"]
    assert [h.ttl for h in bad.hops] == [1, 2] and bad.target_device == "pi"
    assert (
        by_id["trace/pi/1.1.1.1"].error == "device said no"
        and by_id["trace/pi/1.1.1.1"].fix == "do this"
    )
    assert by_id["trace/signalbox/1.1.1.1"].reached
    findings = {r.finding.rule_id for r in svc.store.findings()}
    assert "trace.not-via-tunnel" in findings


@pytest.mark.parametrize(
    ("mode", "error"),
    [
        ("denied", "may not trace"),
        ("broken", "adapter error: RuntimeError: boom"),
        ("missing", "cannot run traceroutes"),
    ],
)
async def test_one_trace_failures(svc: Services, mode: str, error: str) -> None:
    rec = svc.store.device("fw")
    assert rec
    svc.store.put_device(rec, {"mode": mode}, TrConfig)
    result = await tracer(svc).trace(Pair("fw", ip_address("1.1.1.1"), "internet"))
    assert result.error and error in result.error
    ids = {"broken": "trace.adapter", "missing": "trace.unsupported"}
    if mode in ids:
        assert result.message_id == ids[mode]
    if mode == "denied":
        assert result.remedy == "privileges" and result.fix == "grant it"


async def test_trace_timeout_and_removed_device(tmp_path: Path) -> None:
    s = services_for(
        tmp_path, SIGNALBOX_TRACES_ENABLED="true", SIGNALBOX_TRACES_TIMEOUT_SECONDS="5"
    )
    try:
        rec = s.store.device("fw")
        assert rec
        s.store.put_device(rec, {"mode": "slow"}, TrConfig)
        t = tracer(s)
        t.settings.__dict__["timeout_seconds"] = 0.05  # faster than the minimum for the test
        result = await t.trace(Pair("fw", ip_address("1.1.1.1"), "internet"))
        assert result.error and "no result within" in result.error
        assert result.message_id == "trace.timeout" and result.params == {"seconds": "0.05"}
        gone = await t.trace(Pair("gone", ip_address("1.1.1.1"), "internet"))
        assert gone.error == "the device was removed" and gone.message_id == "trace.removed"
    finally:
        s.close()


async def test_start_refused_when_off_and_too_soon(tmp_path: Path) -> None:
    off = services_for(tmp_path / "a")
    try:
        with pytest.raises(TraceError) as err:
            tracer(off).start()
        assert err.value.status == 403
        await tracer(off).run_forever()  # off: returns at once
        assert off.runner.network().traces == []
    finally:
        off.close()
    gap = services_for(
        tmp_path / "b", SIGNALBOX_TRACES_ENABLED="true", SIGNALBOX_TRACES_MIN_GAP_SECONDS="600"
    )
    try:
        t = tracer(gap)
        t.start(source="fw", target="pi")
        await finish(t)
        with pytest.raises(TraceError) as err:
            t.start()
        assert err.value.status == 429
        t.start(source="fw", target="pi", scheduled=True)  # the schedule is not held back
        await finish(t)
        await t.stop()
    finally:
        gap.close()


async def test_schedule_runs_and_stops(tmp_path: Path) -> None:
    s = services_for(tmp_path, SIGNALBOX_TRACES_ENABLED="true", SIGNALBOX_TRACES_INTERVAL_HOURS="1")
    try:
        t = tracer(s)
        started: list[bool] = []
        t.start = lambda **kw: started.append(kw["scheduled"]) or {}  # type: ignore[method-assign]
        original = asyncio.wait_for

        async def quick(aw: Any, timeout: float | None) -> Any:
            return await original(aw, 0.01 if timeout and timeout > 100 else timeout)

        import signalbox.tracer as mod

        mod.asyncio.wait_for = quick  # type: ignore[assignment]
        try:
            task = asyncio.create_task(t.run_forever())
            for _ in range(100):
                if started:
                    break
                await asyncio.sleep(0.01)
            await t.stop()
            await asyncio.wait_for(task, 2)
        finally:
            mod.asyncio.wait_for = original
        assert started and started[0] is True
        assert t.status()["next_run"] is None
    finally:
        s.close()


def test_api(tmp_path: Path) -> None:
    s = services_for(tmp_path, SIGNALBOX_TRACES_ENABLED="true")
    try:
        with TestClient(create_app(s, run_background=False)) as c:
            assert c.post("/api/login", json={"password": PW}).status_code == 200
            state = c.get("/api/traces").json()
            assert state["status"]["enabled"] and state["paths"] == []
            assert {x["id"]: x["supported"] for x in state["sources"]} == {
                "signalbox": True,
                "box": False,
                "fw": True,
                "pi": True,
            }
            r = c.post("/api/traces", json={"source": "fw", "target": "pi"})
            assert r.status_code == 202 and r.json()["total"] == 1
            for _ in range(200):
                state = c.get("/api/traces").json()
                if not state["status"]["running"]:
                    break
            assert [p["id"] for p in state["paths"]] == ["trace/fw/198.51.100.1"]
            bad = c.post("/api/traces", json={"source": "box"})
            assert bad.status_code == 422 and bad.json()["error"] == "not_supported"
            assert c.delete("/api/traces").status_code == 204
            assert c.get("/api/traces").json()["paths"] == []
    finally:
        s.close()


def test_api_when_off(tmp_path: Path) -> None:
    s = services_for(tmp_path)
    try:
        s.store.put_trace(trace("fw", "1.1.1.1", ("1.1.1.1", 1.0)))
        with TestClient(create_app(s, run_background=False)) as c:
            c.post("/api/login", json={"password": PW})
            state = c.get("/api/traces").json()
            assert not state["status"]["enabled"] and state["paths"] == []  # kept, not shown
            r = c.post("/api/traces", json={})
            assert r.status_code == 403 and r.json()["error"] == "disabled"
            assert c.get("/api/network").json()["traces"] == []
    finally:
        s.close()


def test_config_validates_the_internet_target(tmp_path: Path) -> None:
    from signalbox.config import ConfigError, load

    with pytest.raises(ConfigError, match="internet_target"):
        load(tmp_path, {"SIGNALBOX_TRACES_INTERNET_TARGET": "example.org"})
    assert (
        load(tmp_path, {"SIGNALBOX_TRACES_INTERNET_TARGET": " 9.9.9.9 "}).traces.internet_target
        == "9.9.9.9"
    )
