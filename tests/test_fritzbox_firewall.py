"""Fritz!Box firewall (#135, ADR 0013): the fixed policies and the TR-064 port sharing."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from ipaddress import ip_network
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.fritzbox import FritzboxAdapter, FritzboxConfig, port_forward
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Flow,
    Verdict,
)
from signalbox.sim.fritzbox import FritzboxSim, create_app, port_mapping
from signalbox.sim.server import serve
from signalbox.testing import assert_contract

SIM = FritzboxSim()


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(create_app(SIM)) as address:
        yield address


@pytest.fixture
async def adapter(url: str) -> AsyncIterator[FritzboxAdapter]:
    SIM.reset()
    a = make(url)
    yield a
    await a.close()


def make(url: str, role: DeviceRole = DeviceRole.GATEWAY) -> FritzboxAdapter:
    return FritzboxAdapter(
        AdapterContext(
            site_id="home",
            device_id="fb",
            device_name="Fritz!Box",
            role=role,
            config=FritzboxConfig(
                url=url,
                username=SIM.username,
                password=SecretStr(SIM.password),
                allow_insecure_http=True,
            ),
        )
    )


async def test_contract(adapter: FritzboxAdapter) -> None:
    snap = await assert_contract(adapter)
    assert len(snap.firewalls) == 1


async def test_fixed_policies_and_port_sharing(adapter: FritzboxAdapter) -> None:
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK
    (fw,) = snap.firewalls
    assert fw.id == "fb/firewall" and fw.enabled
    zones = {z.name: z for z in fw.zones}
    assert set(zones) == {"lan", "guest", "wan"}
    assert zones["lan"].segments == ["home/segment/native"]
    assert zones["guest"].segments == ["home/segment/guest"]
    assert zones["wan"].uplinks == ["fb/uplink/internet"] and zones["wan"].masquerade
    assert fw.policy("lan", "wan") is FirewallAction.ACCEPT
    assert fw.policy("guest", "lan") is FirewallAction.DROP
    assert fw.policy("guest", "wan") is FirewallAction.ACCEPT
    assert fw.policy("wan", None) is FirewallAction.DROP
    assert fw.policy("wan", "lan") is FirewallAction.DROP
    nas, game, off, phone = fw.port_forwards
    assert nas.name == "NAS" and nas.protocols == [FirewallProtocol.TCP]
    assert [str(p) for p in nas.external_ports] == ["8443"] and nas.target_port == 443
    assert str(nas.target_address) == "192.0.2.20" and nas.passes_filter and nas.zones == ["wan"]
    assert game.protocols == [FirewallProtocol.UDP] and off.enabled is False
    assert [str(n) for n in phone.sources] == ["203.0.113.0/24"]
    assert fw.port_forwards_complete is False  # IPv6 port sharing is not in TR-064
    assert fw.rules_complete

    def flow(**kw: Any) -> Flow:
        return Flow(protocol=FirewallProtocol.TCP, port=443, **kw)

    guest = fw.evaluate(flow(chain=FirewallChain.INPUT, source_zones={"guest"}))
    assert guest.verdict is Verdict.DENIED
    dns = fw.evaluate(
        Flow(
            chain=FirewallChain.INPUT,
            source_zones={"guest"},
            protocol=FirewallProtocol.UDP,
            port=53,
        )
    )
    assert dns.verdict is Verdict.ALLOWED
    lan_out = fw.evaluate(
        flow(chain=FirewallChain.FORWARD, source_zones={"lan"}, destination_zones={"wan"})
    )
    assert lan_out.verdict is Verdict.ALLOWED
    wan_in = fw.evaluate(
        flow(chain=FirewallChain.FORWARD, source_zones={"wan"}, destination_zones={"lan"})
    )
    assert wan_in.verdict is Verdict.DENIED


async def test_the_index_loop_ends_at_fault_713(adapter: FritzboxAdapter) -> None:
    await adapter.observe()
    calls = [a for s, a, _ in SIM.calls if a == "GetGenericPortMappingEntry"]
    assert len(calls) == len(SIM.port_mappings) + 1  # the last one is answered with 713
    SIM.calls.clear()
    SIM.port_mappings.clear()
    SIM.wan = "cable"  # WANIPConnection answers instead of WANPPPConnection
    SIM.port_mappings.append(port_mapping(80, "TCP", 8080, "192.0.2.50", "Web"))
    obs = await adapter.read_firewall()
    assert [f.name for f in obs.firewalls[0].port_forwards] == ["Web"]
    services = {s for s, a, _ in SIM.calls if a == "GetGenericPortMappingEntry"}
    assert services == {"WANIPConnection:1"}


async def test_no_guest_network_no_internet_connection(adapter: FritzboxAdapter) -> None:
    SIM.wan = "client"  # neither connection is enabled
    SIM.wlans.pop(3, None)
    SIM.wlans.pop(4, None)
    obs = await adapter.read_firewall()
    (fw,) = obs.firewalls
    assert {z.name for z in fw.zones} <= {"lan", "guest"}
    assert fw.policy("lan", "wan") is None and fw.port_forwards == []


async def test_unreadable_port_sharing_is_a_gap(adapter: FritzboxAdapter) -> None:
    SIM.denied.add("GetGenericPortMappingEntry")
    obs = await adapter.read_firewall()
    assert obs.firewalls[0].port_forwards == []
    (gap,) = obs.incomplete
    assert "port sharing is not read" in gap.message and gap.fix
    SIM.denied.clear()
    SIM.faults["GetGenericPortMappingEntry"] = 820
    obs = await adapter.read_firewall()
    (gap,) = obs.incomplete
    assert "820" in gap.message and gap.fix is None


async def test_an_access_point_reports_no_firewall(url: str) -> None:
    SIM.reset()
    ap = make(url, DeviceRole.AP)
    try:
        obs = await ap.read_firewall()
    finally:
        await ap.close()
    assert obs.firewalls == [] and obs.incomplete == []


def test_port_mapping_rows() -> None:
    row = port_mapping(0, "UDP", 0, "192.0.2.9", "", remote="203.0.113.7")
    found = port_forward(row)
    assert found is not None and found.external_ports == [] and found.target_port is None
    assert found.name is None and found.sources == [ip_network("203.0.113.7/32")]
    assert port_forward(port_mapping(80, "TCP", 80, "", "x")) is None
    assert port_forward(port_mapping(80, "TCP", 80, "192.0.2.9", "x", remote="host")) is None
    assert port_forward(port_mapping(80, "GRE", 80, "192.0.2.9", "x")).protocols == []  # type: ignore[union-attr]
