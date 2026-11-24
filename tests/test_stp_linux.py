"""Spanning tree of the Linux integration (#155): ``ip -j -d link show`` only."""

from __future__ import annotations

import copy
import json
from typing import Any

from signalbox.adapters.linux import parse
from signalbox.adapters.linux.collect import Answer
from signalbox.model import StpPortRole, StpPortState, StpProtocol
from signalbox.sim.linux import default_links
from test_linux import adapter_for, device


def _links(rows: list[dict[str, Any]]) -> dict[str, parse.Link]:
    return parse.links(Answer(sections={"link": json.dumps(rows), "addr": "[]"}))


def _ids(links: dict[str, parse.Link]) -> dict[str, str]:
    return {n: f"gw/port/{n}" for n in links}


async def test_linux_bridge_without_stp() -> None:
    async with adapter_for(device()) as adapter:
        await adapter.read_system()
        obs = await adapter.read_interfaces()
    (b,) = obs.stp_bridges["gw2"]
    assert (b.name, b.protocol, b.priority, b.port_id) == (
        "br0",
        StpProtocol.NONE,
        32768,
        "gw2/port/br0",
    )
    assert b.bridge_id == "8000.02:5b:00:00:00:02" and b.root_bridge_id is None
    eth1 = next(p for p in obs.ports if p.name == "eth1")
    assert eth1.stp is not None and eth1.stp.state is None and eth1.stp.bpdu_guard is False


def test_kernel_stp_roles() -> None:
    rows = copy.deepcopy(default_links())
    br = next(r for r in rows if r["ifname"] == "br0")
    br["linkinfo"]["info_data"].update(
        stp_state=1, root_id="1000.2:0:0:0:99:1", root_port=1, root_path_cost=4
    )
    eth1 = next(r for r in rows if r["ifname"] == "eth1")
    eth1["linkinfo"]["info_slave_data"].update(designated_bridge="1000.2:0:0:0:99:1", guard=True)
    wlan = next(r for r in rows if r["ifname"] == "wlan0")
    wlan["linkinfo"]["info_slave_data"]["state"] = "blocking"
    wlan["linkinfo"]["info_slave_data"]["designated_bridge"] = "1000.2:0:0:0:99:1"
    links = _links(rows)
    bridges, ports = parse.stp(links, _ids(links))
    (b,) = bridges
    assert b.protocol is StpProtocol.STP and b.is_root is False
    assert b.root_bridge_id == "1000.02:00:00:00:99:01" and b.root_port_id == "gw/port/eth1"
    assert b.root_path_cost == 4
    assert ports["eth1"].role is StpPortRole.ROOT and ports["eth1"].bpdu_guard is True
    assert ports["eth1"].state is StpPortState.FORWARDING and ports["eth1"].path_cost == 100
    assert ports["wlan0"].role is StpPortRole.ALTERNATE

    wlan["linkinfo"]["info_slave_data"]["state"] = "disabled"
    eth1["linkinfo"]["info_slave_data"]["designated_bridge"] = "8000.2:5b:0:0:0:2"
    br["linkinfo"]["info_data"].update(stp_state=2, root_port=0)
    links = _links(rows)
    bridges, ports = parse.stp(links, _ids(links))
    assert bridges[0].protocol is StpProtocol.RSTP and bridges[0].root_port_id is None
    assert ports["eth1"].role is StpPortRole.DESIGNATED
    assert ports["wlan0"].role is StpPortRole.DISABLED


def test_unknown_stp_state_and_odd_values() -> None:
    rows = copy.deepcopy(default_links())
    br = next(r for r in rows if r["ifname"] == "br0")
    br["linkinfo"]["info_data"]["stp_state"] = 7
    links = _links(rows)
    assert parse.stp(links, _ids(links)) == ([], {})
    del br["linkinfo"]["info_data"]["stp_state"]
    links = _links(rows)
    assert parse.stp(links, _ids(links)) == ([], {})
    assert parse._number(True) is None and parse._number(3) == 3
    assert parse._number("0x10") == 16 and parse._number("x") is None
