"""Spanning tree of the MikroTik integration against the simulator (#155)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik import stp as mstp
from signalbox.model import (
    DeviceRole,
    Snapshot,
    StpPortRole,
    StpPortState,
    StpProtocol,
)
from signalbox.sim.mikrotik import PASSWORD, MikrotikSimulator
from signalbox.sim.server import serve
from signalbox.testing import assert_contract

SIM = MikrotikSimulator()


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as u:
        yield u


@pytest.fixture(autouse=True)
def sim() -> MikrotikSimulator:
    SIM.__dict__.update(MikrotikSimulator().__dict__)
    return SIM


async def observe(url: str) -> Snapshot:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    a = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="rt",
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
            timeout=5.0,
        )
    )
    try:
        return await assert_contract(a)
    finally:
        await a.close()


async def test_bridge_and_ports_from_the_monitor(url: str, sim: MikrotikSimulator) -> None:
    snap = await observe(url)
    assert snap.device.stp_bridges is not None
    (b,) = snap.device.stp_bridges
    assert (b.name, b.port_id, b.protocol, b.priority) == (
        "bridge",
        "rt/port/bridge",
        StpProtocol.RSTP,
        0x8000,
    )
    assert b.bridge_id == b.root_bridge_id and b.is_root is True
    assert b.bridge_id is not None and b.bridge_id.startswith("8000.02:")
    ports = {p.name: p.stp for p in snap.ports if p.stp}
    assert ports["ether2"] is not None
    assert (ports["ether2"].role, ports["ether2"].state) == (
        StpPortRole.DESIGNATED,
        StpPortState.FORWARDING,
    )
    assert ports["ether2"].path_cost == 20000 and ports["ether2"].edge is False
    assert ports["ether3"].state is StpPortState.DISCARDING
    assert ports["ether3"].role is StpPortRole.ALTERNATE
    e4 = ports["ether4"]
    assert e4.edge is True and e4.bpdu_guard is True and e4.loop_protect is True
    assert ports["ether2"].loop_protect is False
    assert ports["ether5"].state is StpPortState.DISABLED
    assert "ether1" not in ports  # not in a bridge
    assert not [e for e in snap.errors if e.message_id == "mikrotik.stpMonitor"]


async def test_refused_monitor_keeps_the_configuration(url: str, sim: MikrotikSimulator) -> None:
    sim.read_only_monitor = True
    snap = await observe(url)
    assert snap.device.stp_bridges is not None
    (b,) = snap.device.stp_bridges
    assert b.protocol is StpProtocol.RSTP and b.root_bridge_id is None and b.is_root is None
    e4 = next(p.stp for p in snap.ports if p.name == "ether4")
    assert e4 is not None and e4.edge is True and e4.role is None
    gap = next(e for e in snap.errors if e.message_id == "mikrotik.stpMonitor")
    assert gap.optional


async def test_running_state_from_the_print_needs_no_monitor(
    url: str, sim: MikrotikSimulator
) -> None:
    rows = sim.data["/rest/interface/bridge/port"]
    sim.data["/rest/interface/bridge/port"] = [
        {**r, "role": "root-port", "forwarding": "true"} for r in rows
    ]
    sim.bridge_monitor = {
        **sim.bridge_monitor,
        "root-bridge": "false",
        "root-bridge-id": "0x1000.02:00:00:00:99:01",
        "root-port": "ether2",
        "root-path-cost": "10",
    }
    snap = await observe(url)
    assert snap.device.stp_bridges is not None
    (b,) = snap.device.stp_bridges
    assert b.root_bridge_id == "1000.02:00:00:00:99:01" and b.is_root is False
    assert b.root_port_id == "rt/port/ether2" and b.root_path_cost == 10
    e3 = next(p.stp for p in snap.ports if p.name == "ether3")
    assert e3 is not None and e3.role is StpPortRole.ROOT and e3.state is StpPortState.FORWARDING


async def test_bridge_without_spanning_tree(url: str, sim: MikrotikSimulator) -> None:
    sim.data["/rest/interface/bridge"] = [
        {**r, "protocol-mode": "none"} for r in sim.data["/rest/interface/bridge"]
    ]
    snap = await observe(url)
    assert snap.device.stp_bridges is not None
    (b,) = snap.device.stp_bridges
    assert b.protocol is StpProtocol.NONE and b.root_bridge_id is None
    e2 = next(p.stp for p in snap.ports if p.name == "ether2")
    assert e2 is not None and e2.role is None and e2.state is None


def test_parsers() -> None:
    assert mstp.protocol({"protocol-mode": "MSTP"}) is StpProtocol.MSTP
    assert mstp.protocol({}) is StpProtocol.RSTP
    assert mstp.protocol({"protocol-mode": "other"}) is None
    assert mstp.bridge({"protocol-mode": "rstp"}, {}, {}) is None  # no name
    b = mstp.bridge({"name": "br", "priority": "99999", "mac-address": "zz"}, {}, {})
    assert b is not None and b.priority is None and b.bridge_id is None
    b = mstp.bridge({"name": "br", "priority": "0x1000", "mac-address": "zz"}, {}, {})
    assert b is not None and b.priority == 0x1000 and b.bridge_id is None
    b = mstp.bridge(
        {"name": "br", "priority": "0x1000", "mac-address": "02:00:00:00:00:01"},
        {"root-bridge": "true", "root-path-cost": "x"},
        {},
    )
    assert b is not None and b.is_root is True and b.root_path_cost is None
    p = mstp.port({"edge": "no-discover", "learning": "true"}, {}, StpProtocol.STP, None)
    assert p.edge is False and p.state is StpPortState.LEARNING and p.loop_protect is None
    p = mstp.port({"edge": "auto", "forwarding": "false"}, {}, StpProtocol.STP, {})
    assert p.edge is None and p.state is StpPortState.BLOCKING and p.loop_protect is None
    p = mstp.port({}, {}, StpProtocol.RSTP, {"loop-protect-status": "disable"})
    assert p.state is StpPortState.DISABLED
    assert mstp.monitor_rows({"a": "b"}) == [{"a": "b"}] and mstp.monitor_rows("x") == []
    assert mstp.needs_monitor([{"x": 1}]) and not mstp.needs_monitor([])
    assert mstp._number(True) is None and mstp._number(5) == 5
    assert mstp._bool(True) is True and mstp._bool("maybe") is None
