"""NETGEAR ProSAFE Plus (NSDP) and TP-Link Easy Smart adapters.

The mapping tests run everywhere. The tests against Switchyard's simulators need the extra
``signalbox-net[switches]``; without it they are skipped, unless ``REQUIRE_SWITCH_TESTS``
is set (CI sets it, so there they fail instead of being skipped).
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

import signalbox.adapters.plusswitch as plus
from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    AuthFailed,
    Unreachable,
    load_adapters,
)
from signalbox.adapters.plusswitch import (
    EasySmartAdapter,
    EasySmartConfig,
    ProsafeAdapter,
    ProsafeConfig,
)
from signalbox.adapters.plusswitch.mapping import interfaces, system_info
from signalbox.model import DeviceRole, DeviceStatus, Membership
from signalbox.sim.server import free_port
from signalbox.testing import assert_contract

try:
    import switchyard  # noqa: F401
except ImportError:  # pragma: no cover - depends on the installation
    HAVE_SWITCHYARD = False
    if os.environ.get("REQUIRE_SWITCH_TESTS"):
        raise
else:
    HAVE_SWITCHYARD = True

needs_switchyard = pytest.mark.skipif(
    not HAVE_SWITCHYARD,
    reason="Switchyard is not installed: pip install -e '.[dev,switches]'",
)

NATIVE = "home/segment/native"


# --- mapping (no Switchyard needed) -------------------------------------------------------


def _ports(n: int = 4) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {"port": p, "up": p != 3, "speed_mbps": 1000 if p != 3 else 0, "duplex": "full"}
        for p in range(1, n + 1)
    ]
    rows[1].update(speed_mbps=100, duplex="half", link="100M half")
    return rows


def test_port_settings_from_admin_and_status() -> None:
    rows = _ports()
    rows[0]["enabled"] = True  # Easy Smart statistics
    rows[1]["flow_control"] = True  # ProSAFE status: flow control of the link
    admin = {2: {"speed_code": 5}, 3: {"speed_code": 1, "flow_control": False}, 4: "odd"}
    ports, _ = _by(interfaces("sw", "home", rows, None, None, admin))
    assert (ports["1"].admin_up, ports["1"].autoneg, ports["1"].flow_control) == (True, None, None)
    assert (ports["2"].admin_up, ports["2"].autoneg, ports["2"].flow_control) == (True, False, True)
    assert (ports["3"].admin_up, ports["3"].autoneg, ports["3"].up) == (False, None, False)
    assert ports["4"].admin_up is None and ports["4"].pvid is None
    rows[0]["up"], rows[0]["enabled"] = True, False  # a disabled port has no link
    ports, _ = _by(interfaces("sw", "home", rows, None, None))
    assert (ports["1"].up, ports["1"].speed_mbps) == (False, None)


def _by(obs: Any) -> tuple[dict[str, Any], dict[int | None, Any]]:
    return {p.name: p for p in obs.ports}, {s.vlan: s for s in obs.segments}


def _members(seg: Any) -> set[tuple[str, Membership]]:
    return {(m.port_id.rsplit("/", 1)[1], m.mode) for m in seg.members}


def test_dot1q_vlans_tagged_untagged_and_pvid() -> None:
    vlan = {
        "mode": "dot1q_advanced",
        "dot1q": [
            {"id": 1, "members": [1, 2, 3, 4], "tagged": [], "name": "Default"},
            {"id": 10, "members": [1, 4, 9], "tagged": [1]},
            {"id": 20, "members": [2], "tagged": [1]},  # tagged but not listed as member
            {"id": 10, "members": [3]},  # repeated id: the first one counts
            {"id": 0, "members": [1]},
            {"id": 5000, "members": [1]},
            "garbage",
        ],
        "pvid": {1: 1, 2: 1, 3: 1, 4: 10, 9: 10},
    }
    obs = interfaces("sw", "home", _ports(), vlan, None)
    ports, segs = _by(obs)
    assert set(segs) == {1, 10, 20}
    assert segs[1].id == NATIVE and segs[1].name == "Default"
    assert _members(segs[1]) == {(str(p), Membership.UNTAGGED) for p in (1, 2, 3, 4)}
    assert segs[10].id == "home/segment/10" and segs[10].name is None
    assert _members(segs[10]) == {("1", Membership.TAGGED), ("4", Membership.UNTAGGED)}
    assert _members(segs[20]) == {("1", Membership.TAGGED), ("2", Membership.UNTAGGED)}
    assert ports["4"].pvid == 10
    assert ports["1"].pvid == 1 and ports["1"].vendor_extra == {"vlan_mode": "dot1q_advanced"}
    assert ports["2"].vendor_extra["link"] == "100M half"
    assert ports["2"].speed_mbps == 100 and ports["2"].full_duplex is False
    assert ports["3"].up is False and ports["3"].speed_mbps is None
    assert ports["3"].full_duplex is None
    assert ports["1"].id == "sw/port/1" and ports["1"].device_id == "sw"


def test_no_vlans_is_the_native_network() -> None:
    _, segs = _by(interfaces("sw", "home", _ports(), {"mode": "disabled"}, None))
    assert list(segs) == [None]
    assert segs[None].id == NATIVE
    assert _members(segs[None]) == {(str(p), Membership.UNTAGGED) for p in (1, 2, 3, 4)}


def test_port_based_groups_stay_on_the_native_network() -> None:
    vlan = {
        "mode": "port_basic",
        "port_vlans": [
            {"id": 1, "members": [1, 2, 4]},
            {"id": 2, "members": [3, 4]},
            {"id": "x", "members": [1]},
            None,
        ],
    }
    ports, segs = _by(interfaces("sw", "home", _ports(), vlan, None))
    assert list(segs) == [None]  # the groups are not VLANs on the wire
    assert len(segs[None].members) == 4
    assert ports["4"].vendor_extra["port_groups"] == [1, 2]
    assert ports["3"].vendor_extra["port_groups"] == [2]
    assert ports["1"].vendor_extra["vlan_mode"] == "port_basic"


def test_unknown_vlans_report_no_segments() -> None:
    ports, segs = _by(interfaces("sw", "home", _ports(), None, None))
    assert segs == {} and "vlan_mode" not in ports["1"].vendor_extra


def test_lag_and_odd_port_rows() -> None:
    rows = [*_ports(2), {"port": 0}, {"port": "3"}, "junk", {"port": 3, "up": "yes"}]
    lag = {"lags": [{"id": 1, "enabled": True, "members": [1, 2]}, {"id": 2, "enabled": False}]}
    ports, _ = _by(interfaces("sw", "home", rows, None, lag))  # type: ignore[arg-type]
    assert set(ports) == {"1", "2", "3"}
    assert ports["1"].lag == ports["2"].lag == "lag1"
    assert ports["3"].lag is None and ports["3"].up is None
    assert interfaces("sw", "home", rows, None, {"lags": None}).ports  # type: ignore[arg-type]


def test_members_that_are_not_lists_are_ignored() -> None:
    vlan = {"mode": "dot1q_basic", "dot1q": [{"id": 3, "members": "1,2", "tagged": 7}]}
    _, segs = _by(interfaces("sw", "home", _ports(), vlan, None))
    assert segs[3].members == []


def test_system_info() -> None:
    info = system_info(
        {
            "mac": "02-00-00-00-10-01",
            "model": "GS108E",
            "name": "office",
            "ip": "192.0.2.10",
            "firmware": "1.00.12",
            "dhcp": False,
            "serial": None,
            "hardware": "",
            "ports": 8,
            "other": [1],
        },
        "NETGEAR",
        "192.0.2.10",
    )
    assert info.vendor == "NETGEAR" and info.model == "GS108E"
    assert info.firmware is not None and info.firmware.current == "1.00.12"
    assert info.management_address == "192.0.2.10"
    assert info.vendor_extra == {
        "mac": "02:00:00:00:10:01",
        "name": "office",
        "ip": "192.0.2.10",
        "dhcp": False,
        "ports": 8,
    }
    bare = system_info({"mac": "02:00:00:00:10:01"}, "TP-Link", "192.0.2.11")
    assert bare.model is None and bare.firmware is None
    with pytest.raises(AdapterError, match="MAC"):
        system_info({"mac": "nonsense"}, "NETGEAR", "192.0.2.10")
    with pytest.raises(AdapterError, match="identity"):
        system_info([], "NETGEAR", "192.0.2.10")  # type: ignore[arg-type]


def test_config_wants_a_unicast_ipv4_address() -> None:
    assert ProsafeConfig(address=" 192.0.2.10 ", password=SecretStr("x")).address == "192.0.2.10"
    for bad in ("switch.example", "255.255.255.255", "0.0.0.0", "224.0.0.1", "2001:db8::1"):
        with pytest.raises(ValidationError):
            EasySmartConfig(address=bad, password=SecretStr("x"))
    assert EasySmartConfig(address="192.0.2.11", password=SecretStr("x")).username == "admin"
    schema = ProsafeConfig.model_json_schema()
    secret = next(s for s in schema["properties"]["password"]["anyOf"] if s.get("type") == "string")
    assert secret["format"] == "password"
    assert ProsafeConfig(address="192.0.2.10").password is None  # reading needs none


def test_entry_points() -> None:
    found = load_adapters()
    assert found["prosafe"] is ProsafeAdapter and found["easysmart"] is EasySmartAdapter
    assert ProsafeAdapter.manifest.roles == {DeviceRole.SWITCH}


def _context(cls: type, port: int = 9, timeout: float = 4.0, **cfg: Any) -> AdapterContext:
    config_cls = ProsafeConfig if cls is ProsafeAdapter else EasySmartConfig
    password = cfg.pop("password", "password" if cls is ProsafeAdapter else "admin")
    extra = {"client_port": 0, "device_port": port} | cfg.pop("extra", {})
    return AdapterContext(
        site_id="home",
        device_id="sw1",
        device_name="Switch 1",
        role=DeviceRole.SWITCH,
        config=config_cls(address="127.0.0.1", password=SecretStr(password), **cfg),
        timeout=timeout,
        extra=extra,
    )


@pytest.mark.parametrize("cls", [ProsafeAdapter, EasySmartAdapter])
async def test_without_switchyard_the_switch_is_not_read(
    cls: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "switchyard.drivers.base", None)
    snap = await cls(_context(cls)).observe()
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "signalbox-net[switches]" in snap.errors[0].message


async def test_interfaces_before_system() -> None:
    with pytest.raises(AdapterError, match="read_system"):
        await ProsafeAdapter(_context(ProsafeAdapter)).read_interfaces()


def test_errors_are_translated(monkeypatch: pytest.MonkeyPatch) -> None:
    class Errors:
        class SwitchError(Exception):
            pass

        class AuthError(SwitchError):
            pass

        class Unreachable(Exception):
            pass

    a = "192.0.2.10"
    assert isinstance(plus._translate(Errors.AuthError("no"), Errors, a), AuthFailed)
    assert isinstance(plus._translate(Errors.Unreachable(), Errors, a), Unreachable)
    assert isinstance(plus._translate(TimeoutError(), Errors, a), Unreachable)
    plain = plus._translate(Errors.SwitchError("refused"), Errors, a)
    assert type(plain) is AdapterError and "refused" in str(plain)
    assert "unexpected" in str(plus._translate(IndexError(), Errors, a))
    mine = Unreachable("x")
    assert plus._translate(mine, Errors, a) is mine


# --- against Switchyard's simulators -----------------------------------------------------

if HAVE_SWITCHYARD:
    from switchyard.drivers.base import SwitchError
    from switchyard.easysmart.sim import SIM_MODULUS, EasySmartSimulator, SimEasySmart
    from switchyard.nsdp.auth import PasswordMode
    from switchyard.sim import SimSwitch, Simulator

Start = Callable[..., Any]


@pytest.fixture
async def nsdp() -> AsyncIterator[Start]:
    """Start a NETGEAR simulator with the given switches; returns (simulator, port)."""
    started: list[Any] = []

    async def start(*switches: Any) -> tuple[Any, int]:
        sim = Simulator(list(switches))
        port = await sim.start()
        started.append(sim)
        return sim, port

    yield start
    for sim in started:
        sim.stop()


@pytest.fixture
async def easysmart() -> AsyncIterator[Start]:
    started: list[Any] = []

    async def start(*switches: Any) -> tuple[Any, int]:
        sim = EasySmartSimulator(list(switches))
        port = await sim.start()
        started.append(sim)
        return sim, port

    yield start
    for sim in started:
        sim.stop()


def netgear(**kw: Any) -> Any:
    return SimSwitch("02:00:00:00:10:01", **{"ip": "192.0.2.10", "name": "office"} | kw)


def tplink(**kw: Any) -> Any:
    return SimEasySmart("02:00:00:00:20:01", **{"ip": "192.0.2.11", "name": "garage"} | kw)


def es_context(port: int, **cfg: Any) -> AdapterContext:
    extra = {"rsa_modulus": SIM_MODULUS} | cfg.pop("extra", {})
    return _context(EasySmartAdapter, port, extra=extra, **cfg)


@needs_switchyard
@pytest.mark.parametrize(
    "switch",
    [
        {},
        {"model": "GS108Ev3", "password_mode": "HASH8", "links": [5, 5, 5, 5, 4, 0, 0, 5]},
        {"model": "GS105E", "ports": 5, "unsupported": {"loop", "serial", "admin"}},
        {"model": "GS108E", "unknown_tag": "status", "serial": "SERIAL0001"},
    ],
)
async def test_prosafe_contract(nsdp: Start, switch: dict[str, Any]) -> None:
    from switchyard.nsdp import tags as T

    if "password_mode" in switch:
        switch["password_mode"] = PasswordMode[switch["password_mode"]]
    if "unsupported" in switch:
        names = {"loop": T.LOOP_DETECTION, "serial": T.SERIAL, "admin": T.PORT_ADMIN}
        switch["unsupported"] = {names[n] for n in switch["unsupported"]}
    sim, port = await nsdp(netgear(**switch))
    snap = await assert_contract(ProsafeAdapter(_context(ProsafeAdapter, port)))
    dev = snap.device
    assert dev.vendor == "NETGEAR" and dev.model == switch.get("model", "GS108E")
    assert dev.firmware is not None and dev.firmware.current == "1.00.12"
    assert dev.management_address == "127.0.0.1"
    assert dev.vendor_extra["mac"] == "02:00:00:00:10:01"
    assert dev.vendor_extra["ip"] == "192.0.2.10" and dev.vendor_extra["name"] == "office"
    assert len(snap.ports) == switch.get("ports", 8)
    ports = {p.name: p for p in snap.ports}
    assert ports["1"].up and ports["1"].speed_mbps == 1000 and ports["1"].full_duplex
    # the default is "no VLANs": every port untagged on the native network
    assert [s.id for s in snap.segments] == [NATIVE]
    assert len(snap.segments[0].members) == len(snap.ports)
    assert sim.switches[0].failed_logins == 0
    # management services (#173): fixed, unencrypted
    assert dev.transport_encrypted is False
    assert [
        (x.id, x.kind.value, x.port, x.transport.value, x.encrypted) for x in snap.services
    ] == [
        ("sw1/service/nsdp", "vendor", 63322, "udp", False),
        ("sw1/service/http", "http", 80, "tcp", False),
    ]


@needs_switchyard
async def test_prosafe_dot1q_and_lag(nsdp: Start) -> None:
    switch = netgear()
    switch.vlan_mode = 4  # dot1q_advanced
    switch.dot1q = {1: ([1, 2, 3, 4, 5, 6, 7], []), 10: ([1, 8], [1]), 20: ([1, 2], [1, 2])}
    switch.pvid = {**switch.pvid, 8: 10}
    switch.lags[1] = (True, [5, 6])
    _, port = await nsdp(switch)
    snap = await assert_contract(ProsafeAdapter(_context(ProsafeAdapter, port)))
    ports, segs = _by(snap)
    assert set(segs) == {1, 10, 20}
    assert segs[1].id == NATIVE and ("8", Membership.UNTAGGED) not in _members(segs[1])
    assert _members(segs[10]) == {("1", Membership.TAGGED), ("8", Membership.UNTAGGED)}
    assert _members(segs[20]) == {("1", Membership.TAGGED), ("2", Membership.TAGGED)}
    assert ports["8"].pvid == 10 and ports["1"].pvid == 1 and "pvid" not in ports["1"].vendor_extra
    assert ports["5"].lag == ports["6"].lag == "lag1" and ports["1"].lag is None


@needs_switchyard
async def test_prosafe_port_settings(nsdp: Start) -> None:
    switch = netgear()
    switch.admin[2] = (5, True)  # 100M full, flow control on
    switch.admin[3] = (1, False)  # disabled
    _, port = await nsdp(switch)
    snap = await assert_contract(ProsafeAdapter(_context(ProsafeAdapter, port)))
    ports, _ = _by(snap)
    assert (ports["1"].admin_up, ports["1"].autoneg, ports["1"].flow_control) == (True, True, False)
    assert (ports["2"].admin_up, ports["2"].autoneg, ports["2"].flow_control) == (True, False, True)
    assert (ports["3"].admin_up, ports["3"].up, ports["3"].speed_mbps) == (False, False, None)


@needs_switchyard
async def test_port_settings_that_fail_leave_the_rest() -> None:
    import switchyard.drivers.base as errors

    class Client:
        async def read_port_admin(self) -> Any:
            raise errors.SwitchError("not supported here")

    adapter = ProsafeAdapter(_context(ProsafeAdapter, 1))
    adapter._switchyard()
    reading = plus._Reading(info={})
    await adapter._read_admin(reading, Client())
    assert reading.admin is None and reading.error is None
    reading.error = plus.AdapterError("ports failed")
    await adapter._read_admin(reading, None)  # not asked at all
    assert reading.admin is None


@needs_switchyard
async def test_easysmart_disabled_port(easysmart: Start) -> None:
    switch = tplink()
    switch.config["port"][4] = {"enabled": False, "speed": 1, "flow": False}
    switch.config["port"][5] = {"enabled": True, "speed": 6, "flow": True}
    _, port = await easysmart(switch)
    snap = await assert_contract(EasySmartAdapter(es_context(port)))
    ports, _ = _by(snap)
    assert (ports["4"].admin_up, ports["4"].up) == (False, False)
    assert (ports["5"].autoneg, ports["5"].flow_control) == (False, True)
    assert [(x.name, x.port, x.enabled) for x in snap.services] == [
        ("easy-smart", 29808, True),
        ("http", 80, True),
    ]
    assert snap.device.transport_encrypted is False


@needs_switchyard
async def test_prosafe_port_based_vlans(nsdp: Start) -> None:
    switch = netgear(ports=5, links=[5, 0, 4, 0, 5])
    switch.vlan_mode = 1  # port_basic
    switch.port_vlans = {1: [1, 2, 5], 2: [3, 4, 5]}
    _, port = await nsdp(switch)
    snap = await assert_contract(ProsafeAdapter(_context(ProsafeAdapter, port)))
    ports, segs = _by(snap)
    assert list(segs) == [None] and len(segs[None].members) == 5
    assert ports["5"].vendor_extra["port_groups"] == [1, 2]
    assert ports["3"].vendor_extra["vlan_mode"] == "port_basic"


@needs_switchyard
@pytest.mark.parametrize("generation", ["A", "B"])
async def test_easysmart_contract(easysmart: Start, generation: str) -> None:
    _, port = await easysmart(tplink(generation=generation))
    snap = await assert_contract(EasySmartAdapter(es_context(port)))
    dev = snap.device
    assert dev.vendor == "TP-Link" and dev.model == "TL-SG108PE"
    assert dev.firmware is not None and dev.firmware.current.startswith("1.0.0 Build")
    assert dev.vendor_extra["mac"] == "02:00:00:00:20:01"
    assert dev.vendor_extra["hardware"] == "TL-SG108PE 3.0"
    expected = "token" if generation == "A" else "session key"
    assert dev.vendor_extra["protocol_generation"] == expected
    ports = {p.name: p for p in snap.ports}
    assert len(ports) == 8
    assert ports["1"].up and ports["1"].speed_mbps == 1000 and ports["1"].full_duplex
    assert ports["3"].up is False and ports["3"].speed_mbps is None
    # port details (#156): enabled, speed setting auto, flow control off
    p1 = ports["1"]
    assert (p1.admin_up, p1.autoneg, p1.flow_control) == (True, True, False), p1
    assert "enabled" not in p1.vendor_extra
    assert [s.id for s in snap.segments] == [NATIVE]


@needs_switchyard
async def test_easysmart_dot1q_and_lag(easysmart: Start) -> None:
    switch = tplink(generation="B")
    switch.config["dot1q"] = True
    switch.config["vlans"] = {
        1: {"members": [1, 2, 3, 4, 5, 6], "tagged": [], "name": "Default"},
        30: {"members": [1, 7, 8], "tagged": [1], "name": "cameras"},
    }
    switch.config["pvid"] = {**switch.config["pvid"], 7: 30, 8: 30}
    switch.config["lags"] = {1: [5, 6], 2: []}
    _, port = await easysmart(switch)
    snap = await assert_contract(EasySmartAdapter(es_context(port)))
    ports, segs = _by(snap)
    assert set(segs) == {1, 30}
    assert segs[30].name == "cameras" and segs[30].id == "home/segment/30"
    assert _members(segs[30]) == {
        ("1", Membership.TAGGED),
        ("7", Membership.UNTAGGED),
        ("8", Membership.UNTAGGED),
    }
    assert ports["7"].pvid == 30 and ports["1"].pvid == 1
    assert ports["5"].lag == "lag1" and ports["7"].lag is None


@needs_switchyard
async def test_easysmart_port_based_vlans(easysmart: Start) -> None:
    switch = tplink()
    switch.config["port_vlan"] = True
    switch.config["port_groups"] = {1: [1, 2, 8], 2: [3, 4, 8]}
    _, port = await easysmart(switch)
    snap = await assert_contract(EasySmartAdapter(es_context(port)))
    ports, segs = _by(snap)
    assert list(segs) == [None]
    assert ports["8"].vendor_extra["port_groups"] == [1, 2]


# --- refused paths ----------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _forget_refused() -> None:
    plus._REFUSED.clear()


@needs_switchyard
async def test_prosafe_wrong_password_is_not_resent(
    nsdp: Start, monkeypatch: pytest.MonkeyPatch
) -> None:
    sim, port = await nsdp(netgear())
    ctx = _context(ProsafeAdapter, port, password="wrong")
    # reading needs no password (like Switchyard): a wrong one is not even sent
    snap = await ProsafeAdapter(ctx).observe()
    assert snap.status is DeviceStatus.OK and sim.switches[0].failed_logins == 0
    # a change (backup first) checks the password
    with pytest.raises(AuthFailed, match=r"(?i)password") as refused:
        await ProsafeAdapter(ctx).backup()
    assert refused.value.fix and "management password" in refused.value.fix
    assert sim.switches[0].failed_logins == 1
    with pytest.raises(AuthFailed, match="not sent again"):  # refused without sending it
        await ProsafeAdapter(ctx).backup()
    assert sim.switches[0].failed_logins == 1
    monkeypatch.setattr(plus, "REFUSED_FOR", 0.0)  # after the wait it is tried once more
    with pytest.raises(AuthFailed):
        await ProsafeAdapter(ctx).backup()
    assert sim.switches[0].failed_logins == 2


@needs_switchyard
async def test_prosafe_without_password_reads_but_does_not_change(nsdp: Start) -> None:
    sim, port = await nsdp(netgear())
    base = _context(ProsafeAdapter, port)
    ctx = AdapterContext(**{**base.__dict__, "config": ProsafeConfig(address="127.0.0.1")})
    adapter = ProsafeAdapter(ctx)
    assert (await adapter.observe()).status is DeviceStatus.OK
    with pytest.raises(AuthFailed, match="needs its password") as exc:
        await adapter.backup()
    assert exc.value.fix and sim.switches[0].failed_logins == 0


@needs_switchyard
async def test_prosafe_old_firmware_refuses_the_identity_read(
    nsdp: Start, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An old switch answers the full identity read with "incorrect password": the discovery
    answer stands in, the ports are still read (#210)."""
    from switchyard.nsdp import client as nsdp_client
    from switchyard.nsdp import tags

    async def refused(self: Any) -> dict[str, Any]:
        raise nsdp_client.NsdpError(7, tags.SERIAL)

    monkeypatch.setattr(nsdp_client.SwitchClient, "read_info", refused)
    sim, port = await nsdp(netgear())
    snap = await ProsafeAdapter(_context(ProsafeAdapter, port)).observe()
    assert snap.status is DeviceStatus.OK, snap.errors
    assert snap.device.model and snap.ports
    assert sim.switches[0].failed_logins == 0


@needs_switchyard
@pytest.mark.parametrize("refused", ["read_vlan", "read_lag"])
async def test_prosafe_old_firmware_refuses_vlan_or_lag(
    nsdp: Start, monkeypatch: pytest.MonkeyPatch, refused: str
) -> None:
    """Old firmware answers the VLAN or LAG read with "incorrect password": the ports stay."""
    from switchyard.nsdp import client as nsdp_client

    async def no(self: Any) -> Any:
        raise nsdp_client.NsdpError(7)

    monkeypatch.setattr(nsdp_client.SwitchClient, refused, no)
    sim, port = await nsdp(netgear())
    snap = await ProsafeAdapter(_context(ProsafeAdapter, port)).observe()
    assert snap.status is DeviceStatus.PARTIAL
    assert snap.ports and sim.switches[0].failed_logins == 0
    [gap] = snap.errors
    assert gap.capability == "interfaces" and "without a password" in gap.message and gap.fix


def test_refused_setting_is_named() -> None:
    from switchyard.drivers import base as errors
    from switchyard.nsdp import client as nsdp_client
    from switchyard.nsdp import tags

    err = plus._translate(nsdp_client.NsdpError(7, tags.SERIAL), errors, "192.0.2.10")
    assert "without a password" in str(err) and err.fix
    assert repr(tags.NAMES[tags.SERIAL]) in str(err)


@needs_switchyard
async def test_easysmart_wrong_password_or_user(easysmart: Start) -> None:
    sim, port = await easysmart(tplink())
    snap = await EasySmartAdapter(es_context(port, password="wrong")).observe()
    assert snap.status is DeviceStatus.AUTH_FAILED
    snap = await EasySmartAdapter(es_context(port, username="guest")).observe()
    assert snap.status is DeviceStatus.AUTH_FAILED
    assert sim.switches[0].writes == 0


@needs_switchyard
@pytest.mark.parametrize("cls", [ProsafeAdapter, EasySmartAdapter])
async def test_no_answer(cls: type) -> None:
    ctx = _context(cls, free_port(), timeout=2.0)
    snap = await cls(ctx).observe()
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "answer" in snap.errors[0].message


class _Junk(asyncio.DatagramProtocol):
    """Answers every datagram with bytes that are not a switch reply."""

    def connection_made(self, transport: Any) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.transport.sendto(b"\x01\x02junk" + data[:3], addr)


@needs_switchyard
@pytest.mark.parametrize("cls", [ProsafeAdapter, EasySmartAdapter])
async def test_malformed_datagrams_count_as_no_answer(cls: type) -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(_Junk, local_addr=("127.0.0.1", 0))
    try:
        port = transport.get_extra_info("sockname")[1]
        snap = await cls(_context(cls, port, timeout=2.0)).observe()
    finally:
        transport.close()
    assert snap.status is DeviceStatus.UNREACHABLE


@needs_switchyard
@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5, 6])
async def test_garbled_settings_never_break_the_adapter(nsdp: Start, seed: int) -> None:
    """Valid packets with random setting values: a finding, never an exception."""
    _, port = await nsdp(netgear(garble=seed))
    adapter = ProsafeAdapter(_context(ProsafeAdapter, port, timeout=3.0))
    snap = await adapter.observe()
    assert snap.status in set(DeviceStatus)
    if snap.status is DeviceStatus.OK:
        assert await assert_contract(ProsafeAdapter(_context(ProsafeAdapter, port, timeout=3.0)))


@needs_switchyard
async def test_easysmart_several_switches_on_one_address(easysmart: Start) -> None:
    _, port = await easysmart(tplink(), SimEasySmart("02:00:00:00:20:02", ip="192.0.2.12"))
    snap = await EasySmartAdapter(es_context(port)).observe()
    assert snap.status is DeviceStatus.UNREACHABLE
    assert "2 switches answer" in snap.errors[0].message


@needs_switchyard
async def test_failed_vlan_read_keeps_the_identity(
    nsdp: Start, monkeypatch: pytest.MonkeyPatch
) -> None:
    from switchyard.nsdp import SwitchClient

    async def broken(self: Any) -> None:
        raise SwitchError("The switch does not support this setting.")

    monkeypatch.setattr(SwitchClient, "read_vlan", broken)
    _, port = await nsdp(netgear())
    snap = await ProsafeAdapter(_context(ProsafeAdapter, port)).observe()
    assert snap.status is DeviceStatus.PARTIAL  # the ports are kept, VLANs reported missing
    assert snap.device.model == "GS108E" and snap.ports
    assert snap.errors[0].capability == "interfaces"


@needs_switchyard
async def test_unexpected_mapping_error_is_a_read_error(
    easysmart: Start, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any) -> None:
        raise ValueError("odd")

    monkeypatch.setattr(plus.mapping, "interfaces", broken)
    _, port = await easysmart(tplink())
    snap = await EasySmartAdapter(es_context(port)).observe()
    assert snap.status is DeviceStatus.PARTIAL and "odd" in snap.errors[0].message


@needs_switchyard
async def test_client_port_in_use(nsdp: Start) -> None:
    _, port = await nsdp(netgear())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("0.0.0.0", 0))
        taken = busy.getsockname()[1]
        ctx = _context(ProsafeAdapter, port, extra={"client_port": taken})
        snap = await ProsafeAdapter(ctx).observe()
    assert snap.status is DeviceStatus.UNREACHABLE
    assert f"cannot use UDP port {taken}" in snap.errors[0].message


@needs_switchyard
async def test_sessions_on_one_port_take_turns(nsdp: Start) -> None:
    """Two switches read at once through the same fixed client port: one after the other."""
    _, port_a = await nsdp(netgear())
    _, port_b = await nsdp(SimSwitch("02:00:00:00:10:02", ip="192.0.2.13"))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("0.0.0.0", 0))
        shared = probe.getsockname()[1]
    snaps = await asyncio.gather(
        *(
            ProsafeAdapter(_context(ProsafeAdapter, p, extra={"client_port": shared})).observe()
            for p in (port_a, port_b)
        )
    )
    assert [s.status for s in snaps] == [DeviceStatus.OK, DeviceStatus.OK]
    assert {s.device.vendor_extra["mac"] for s in snaps} == {
        "02:00:00:00:10:01",
        "02:00:00:00:10:02",
    }


@needs_switchyard
async def test_real_switches_use_switchyards_interface_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Against a real switch the transport has no fixed target, like Switchyard: it sends from
    the host's interfaces with a real MAC (old firmware refuses the broadcast MAC)."""
    import switchyard.nsdp as nsdp_mod

    seen: dict[str, Any] = {}

    class Stop(OSError):
        pass

    class Recorder:
        def __init__(self, **kw: Any) -> None:
            seen.update(kw)

        async def start(self) -> None:
            raise Stop

    monkeypatch.setattr(nsdp_mod, "Transport", Recorder)
    ctx = _context(ProsafeAdapter, 9)
    real = AdapterContext(**{**ctx.__dict__, "extra": {"client_port": 0}})
    snap = await ProsafeAdapter(real).observe()
    assert seen["targets"] is None and snap.status is not DeviceStatus.OK
