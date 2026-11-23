"""Traceroutes run on the devices (#253): OPNsense, MikroTik and Linux against their simulators,
the output parsers, the permissions the setup adds, and Signalbox's own host."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox import tracehost
from signalbox.adapters import (
    Adapter,
    AdapterContext,
    AdapterContractError,
    AdapterError,
    AuthFailed,
    Manifest,
    SetupRequest,
    SystemInfo,
    TraceSupport,
    check_setup,
    load_adapters,
    traces,
)
from signalbox.adapters.linux import trace as linux_trace
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik import trace as ros_trace
from signalbox.adapters.mikrotik.provision import MikrotikSetup
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense import trace as opn_trace
from signalbox.adapters.opnsense.provision import OpnsenseSetup
from signalbox.model import DeviceRole
from signalbox.sim.linux import LinuxSim
from signalbox.sim.mikrotik import PASSWORD, MikrotikSimulator
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import serve
from test_linux import adapter_for, device

T = ip_address("198.51.100.9")


def ctx(config: Any, device_id: str = "gw") -> AdapterContext:
    return AdapterContext(
        site_id="home",
        device_id=device_id,
        device_name=device_id,
        role=DeviceRole.GATEWAY,
        config=config,
        timeout=5,
    )


def test_registered_integrations_that_trace() -> None:
    found = {k for k, cls in load_adapters().items() if traces(cls)}
    assert found == {"opnsense", "mikrotik", "linux"}
    for cls in load_adapters().values():
        check_setup(cls)


def test_declaring_traces_needs_the_hook() -> None:
    class Bad(Adapter):
        manifest = Manifest(
            id="bad",
            name="Bad",
            version="1",
            api_version="1.3",
            vendor="x",
            roles=frozenset({DeviceRole.GATEWAY}),
            capabilities=frozenset(),
            config=OpnsenseConfig,
            traces=TraceSupport(permission="none"),
        )

        async def read_system(self) -> SystemInfo:
            return SystemInfo()

    with pytest.raises(AdapterContractError, match="does not implement trace"):
        check_setup(Bad)


# OPNsense ----------------------------------------------------------------------------------


def opnsense(url: str, key: str = KEY, secret: str = SECRET) -> OpnsenseAdapter:
    cfg = OpnsenseConfig(
        url=url, api_key=SecretStr(key), api_secret=SecretStr(secret), allow_insecure_http=True
    )
    return OpnsenseAdapter(ctx(cfg))


async def test_opnsense_trace_through_the_api() -> None:
    sim = OpnsenseSimulator()
    sim.routes[str(T)] = [("192.0.2.254", 0.5), (None, None), (str(T), 3.25)]
    with serve(sim.app()) as url:
        a = opnsense(url)
        try:
            answer = await a.trace(T, 16, 1)
        finally:
            await a.close()
    assert answer.reached
    assert [(h.ttl, h.address, h.rtt_ms) for h in answer.hops] == [
        (1, ip_address("192.0.2.254"), 0.5),
        (2, None, None),
        (3, T, 3.25),
    ]
    settings = sim.traces[0]["traceroute"]["settings"]
    assert settings == {
        "hostname": str(T),
        "ipproto": "inet",
        "protocol": "icmp",
        "source_address": "",
    }


async def test_opnsense_trace_refused_without_the_privilege() -> None:
    sim = OpnsenseSimulator()
    sim.accounts.users.append(
        {"uuid": "u1", "name": "signalbox", "scope": "user", "descr": "", "priv": [], "groups": []}
    )
    sim.accounts.keys.append({"key": "k1", "secret": "s1", "username": "signalbox", "id": "k1"})
    with serve(sim.app()) as url:
        a = opnsense(url, "k1", "s1")
        try:
            with pytest.raises(AuthFailed) as err:
                await a.trace(T, 16, 1)
        finally:
            await a.close()
    assert err.value.remedy == "privileges"
    assert "page-diagnostics-traceroute" in (err.value.fix or "")


def test_opnsense_parser() -> None:
    v6 = ip_address("2001:db8::9")
    assert opn_trace.request_body(v6)["traceroute"]["settings"]["ipproto"] == "inet6"
    rows = [
        {"ttl": "1", "host": "192.0.2.254", "address": "192.0.2.254", "probes": "0.4 ms"},
        {"ttl": "1", "host": "192.0.2.253", "address": "192.0.2.253", "probes": "0.9 ms"},
        {"ttl": "x"},
        "junk",
        {"ttl": "40", "address": "192.0.2.1"},
        {"ttl": "2", "host": "198.51.100.9", "address": "", "probes": "!H"},
    ]
    answer = opn_trace.parse({"result": "ok", "response": {"rows": rows}}, T, 16)
    assert [h.address for h in answer.hops] == [ip_address("192.0.2.254"), T]
    assert answer.reached and answer.hops[1].rtt_ms is None
    assert opn_trace.parse({"result": "ok", "response": {"rows": []}}, T, 16).hops == []
    for bad in ([], {"result": "failed", "validations": {"x": "y"}}, {"response": None}):
        with pytest.raises(AdapterError):
            opn_trace.parse(bad, T, 16)
    with pytest.raises(AdapterError, match="unexpected"):
        opn_trace.parse({"response": {"rows": "x"}}, T, 16)
    with pytest.raises(AdapterError, match="timeout reached"):
        opn_trace.parse({"response": {"rows": [], "error": "timeout reached"}}, T, 16)


async def test_opnsense_setup_adds_the_privilege_only_while_traces_are_on() -> None:
    base = {
        "config": {"url": "https://192.0.2.1"},
        "admin_user": "k",
        "admin_secret": SecretStr("s"),
    }
    off = OpnsenseSetup(SetupRequest(**base))
    on = OpnsenseSetup(SetupRequest(**base, traces=True))
    assert opn_trace.PRIVILEGE not in off.privileges
    assert opn_trace.PRIVILEGE in on.privileges


# MikroTik ----------------------------------------------------------------------------------


def mikrotik(url: str) -> MikrotikAdapter:
    cfg = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    return MikrotikAdapter(ctx(cfg, "rt"))


async def test_mikrotik_trace_and_policy() -> None:
    sim = MikrotikSimulator()
    sim.routes[str(T)] = [("192.0.2.254", 0.4), (None, None), (str(T), 2.5)]
    with serve(sim.app()) as url:
        a = mikrotik(url)
        try:
            answer = await a.trace(T, 8, 0.5)
            sim.no_policy.add(ros_trace.TRACEROUTE)
            with pytest.raises(AuthFailed, match=r"policy test|may not run"):
                await a.trace(T, 8, 0.5)
            sim.no_policy.clear()
            with pytest.raises(AdapterError, match=r"missing address|HTTP 400"):
                await _raw(a)
        finally:
            await a.close()
    assert answer.reached
    assert [h.address for h in answer.hops] == [ip_address("192.0.2.254"), None, T]
    assert sim.traces[0] == {
        "address": str(T),
        "count": "1",
        "max-hops": "8",
        "timeout": "500ms",
        "use-dns": "no",
    }


async def _raw(a: MikrotikAdapter) -> None:
    """A request the simulator refuses with HTTP 400 (no address)."""
    response = await a.http.request("POST", ros_trace.TRACEROUTE, json={}, accept=(400, 500))
    from signalbox.adapters.mikrotik import ros_error

    raise ros_error(ros_trace.TRACEROUTE, response)


def test_mikrotik_parser() -> None:
    rows = [
        {".section": "0", "address": "192.0.2.254", "last": "timeout"},
        {".section": "1", "address": "192.0.2.254", "last": "1ms200us"},
        {".section": "1", "address": "", "last": "timeout"},
        {".section": "1", "address": str(T), "last": "850us"},
        {".section": "1", "address": "198.51.100.10", "last": "1ms"},
    ]
    answer = ros_trace.parse(rows, T, 16)
    assert [h.rtt_ms for h in answer.hops] == [1.2, None, 0.85]
    assert answer.reached
    partial = ros_trace.parse([{"address": "192.0.2.254"}, {"address": ""}, "x"], T, 16)
    assert not partial.reached and len(partial.hops) == 1 and partial.hops[0].rtt_ms is None
    with pytest.raises(AdapterError):
        ros_trace.parse({}, T, 16)


def test_mikrotik_setup_policy_test_only_while_traces_are_on() -> None:
    base = {
        "config": {"url": "https://192.0.2.1", "username": "signalbox"},
        "admin_user": "admin",
        "admin_secret": SecretStr("pw"),
    }
    assert ",!test," in MikrotikSetup(SetupRequest(**base)).policy
    on = MikrotikSetup(SetupRequest(**base, traces=True)).policy
    assert ",test," in on and "!test" not in on


# Linux --------------------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["tracepath", "traceroute"])
async def test_linux_trace_over_ssh(tool: str) -> None:
    box: LinuxSim = device(trace_tool=tool)
    box.routes[str(T)] = [("198.51.100.1", 0.6), (None, None), (str(T), 4.5)]
    async with adapter_for(box) as a:
        answer = await a.trace(T, 10, 1)
    assert answer.reached
    assert [(h.address, h.rtt_ms) for h in answer.hops] == [
        (ip_address("198.51.100.1"), 0.6),
        (None, None),
        (T, 4.5),
    ]
    script = box.scripts[-1]
    assert script.startswith(linux_trace.MARK) and "-n" in script and "sudo" not in script


async def test_linux_trace_without_a_tool() -> None:
    async with adapter_for(device(trace_tool="none")) as a:
        with pytest.raises(AdapterError, match="neither") as err:
            await a.trace(T, 10, 1)
    assert "iputils-tracepath" in (err.value.fix or "")


def test_linux_parser_edges() -> None:
    with pytest.raises(AdapterError, match="did not finish"):
        linux_trace.parse("@@tracepath\n", T, 16)
    with pytest.raises(AdapterError, match="no hops"):
        linux_trace.parse(
            "@@tracepath\ntracepath: 198.51.100.9: Network is unreachable\n@@end", T, 16
        )
    text = "\n".join(
        [
            "@@tracepath",
            " 1?: [LOCALHOST]                      pmtu 1500",
            " 1:  192.0.2.254                                           0.400ms",
            " 1:  192.0.2.254                                           0.350ms",
            " 2:  no reply",
            " 3:  no reply",
            "40:  192.0.2.1  1.0ms",
            "     Too many hops: pmtu 1500",
            "@@end",
        ]
    )
    answer = linux_trace.parse(text, T, 16)
    assert not answer.reached and [h.rtt_ms for h in answer.hops] == [0.4]
    assert "tracepath -n -m 16 198.51.100.9" in linux_trace.script(T, 16, 1)
    assert "-w 2" in linux_trace.script(T, 16, 2.4)


# Signalbox's host ---------------------------------------------------------------------------


async def test_host_trace_to_loopback() -> None:
    answer = await tracehost.trace(ip_address("127.0.0.1"), 4, 1)
    assert answer.reached and answer.hops[0].address == ip_address("127.0.0.1")
    assert answer.hops[0].rtt_ms is not None


def test_host_trace_classify_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    assert tracehost.classify(False, 2, 11, 0) == "hop"
    assert tracehost.classify(False, 2, 3, 3) == "reached"
    assert tracehost.classify(False, 2, 3, 1) == "unreachable"
    assert tracehost.classify(True, 3, 3, 0) == "hop"
    assert tracehost.classify(True, 3, 1, 4) == "reached"
    assert tracehost.classify(True, 3, 1, 0) == "unreachable"
    assert tracehost.classify(True, 2, 1, 4) is None
    assert tracehost.classify(False, 2, 0, 0) is None
    monkeypatch.setattr(tracehost.sys, "platform", "darwin")
    with pytest.raises(AdapterError, match="needs Linux"):
        tracehost.trace_blocking(ip_address("127.0.0.1"), 2, 0.1)


def test_host_trace_silent_and_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    from signalbox.model import TraceHop

    answers = iter(
        [("hop", TraceHop(ttl=1, address=ip_address("192.0.2.254"), rtt_ms=1.0))]
        + [("none", TraceHop(ttl=n)) for n in range(2, 8)]
    )
    monkeypatch.setattr(tracehost, "probe", lambda target, ttl, wait: next(answers))
    answer = tracehost.trace_blocking(T, 16, 0.1)
    assert not answer.reached and len(answer.hops) == 1
    monkeypatch.setattr(
        tracehost, "probe", lambda target, ttl, wait: ("unreachable", TraceHop(ttl=ttl))
    )
    assert tracehost.trace_blocking(T, 16, 0.1).hops == []


def test_host_offender_parsing() -> None:
    import socket
    import struct

    v4 = struct.pack("=IBBBBII", 113, 2, 11, 0, 0, 0, 0) + struct.pack(
        "=HH4s8x", socket.AF_INET, 0, socket.inet_aton("192.0.2.254")
    )
    assert tracehost._offender(v4, False) == (2, 11, 0, "192.0.2.254")
    v6 = struct.pack("=IBBBBII", 113, 3, 3, 0, 0, 0, 0) + struct.pack(
        "=HHI16sI", socket.AF_INET6, 0, 0, socket.inet_pton(socket.AF_INET6, "2001:db8::1"), 0
    )
    assert tracehost._offender(v6, True) == (3, 3, 0, "2001:db8::1")
    assert tracehost._offender(v4[:16], False)[3] is None


def test_mikrotik_fix_adds_test_only_while_traces_are_on() -> None:
    from signalbox.adapters import RemedyRequest
    from signalbox.adapters.mikrotik.provision import MikrotikFix

    users = [{"name": "signalbox", "group": "signalbox-read"}]
    groups = [{".id": "*1", "name": "signalbox-read", "policy": "read,api,rest-api,!test"}]

    def steps(traces: bool) -> Any:
        fix = MikrotikFix(
            RemedyRequest(
                remedy="policies",
                config={"url": "https://192.0.2.1"},
                admin_user="admin",
                admin_secret=SecretStr("pw"),
                traces=traces,
            )
        )
        return fix.policy_steps(None, users, groups)  # type: ignore[arg-type]

    assert not steps(False)[0].needed
    on = steps(True)[0]
    assert on.needed and "+ test" in on.detail
