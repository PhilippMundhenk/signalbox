"""Multicast of the MikroTik integration against the simulator (#161)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik import multicast as mmc
from signalbox.model import DeviceRole, ReflectorKind, Snapshot, UnknownMulticast, segment_id
from signalbox.sim.mikrotik import PASSWORD, MikrotikSimulator
from signalbox.sim.server import serve
from signalbox.testing import assert_contract

SIM = MikrotikSimulator()
PROXY = "/rest/routing/igmp-proxy/interface"
NATIVE = segment_id("home", None)
IOT = segment_id("home", 20)


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


async def test_bridge_snooping_and_the_mdns_repeater(url: str) -> None:
    snap = await observe(url)
    m = snap.device.multicast
    assert m is not None
    (s,) = m.settings
    assert (s.name, s.segment_id, s.igmp_snooping, s.querier, s.querier_version) == (
        "bridge",
        NATIVE,
        True,
        True,
        2,
    )
    assert s.fast_leave is False and s.unknown_multicast is UnknownMulticast.FLOOD
    (mdns,) = m.reflectors
    assert mdns.kind is ReflectorKind.MDNS and mdns.enabled
    assert mdns.interfaces == ["bridge", "iot"] and mdns.segments == sorted([NATIVE, IOT])


async def test_repeater_is_absent_before_routeros_7_16(url: str, sim: MikrotikSimulator) -> None:
    del sim.data["/rest/ip/dns"]["mdns-repeat-ifaces"]
    snap = await observe(url)
    assert snap.device.multicast is not None and snap.device.multicast.reflectors == []


async def test_igmp_proxy_with_its_upstream(url: str, sim: MikrotikSimulator) -> None:
    sim.data[PROXY] = [
        {".id": "*1", "interface": "ether1", "upstream": "true", "disabled": "false"},
        {".id": "*2", "interface": "bridge", "upstream": "false", "disabled": "false"},
        {".id": "*3", "interface": "iot", "disabled": "true"},
    ]
    snap = await observe(url)
    assert snap.device.multicast is not None
    proxy = next(r for r in snap.device.multicast.reflectors if r.kind is ReflectorKind.IGMP_PROXY)
    assert proxy.interfaces == ["ether1", "bridge"] and proxy.segments == [NATIVE]
    assert proxy.upstream_interface == "ether1" and proxy.upstream_segment_id is None


async def test_igmp_proxy_refused_is_an_optional_gap(url: str, sim: MikrotikSimulator) -> None:
    sim.data[PROXY] = []
    sim.fail[PROXY] = 403
    snap = await observe(url)
    gap = next(e for e in snap.errors if e.message_id == "mikrotik.igmpProxy")
    assert gap.optional
    assert snap.device.multicast is not None


def test_bridge_row_parsing() -> None:
    off = mmc.settings({"name": "b", "igmp-snooping": "no", "multicast-querier": "no"}, [], None)
    assert (off.igmp_snooping, off.querier, off.querier_version) == (False, False, None)
    ports = [{"unknown-multicast-flood": "no"}, {"unknown-multicast-flood": "yes"}]
    mixed = mmc.settings({"name": "b"}, ports, None)
    assert mixed.igmp_snooping is None and mixed.unknown_multicast is None
    dropped = mmc.settings({"name": "b", "multicast-querier": "yes", "igmp-version": "3"}, [], None)
    assert dropped.querier_version == 3
    assert mmc.mdns_repeater({}, {}) is None
    empty = mmc.mdns_repeater({"mdns-repeat-ifaces": ""}, {})
    assert empty is not None and not empty.enabled
    assert mmc.igmp_proxy([{"interface": "a", "disabled": "true"}], {}) is None
