"""UPnP of the MikroTik integration against the simulator (#176)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik import upnp as mu
from signalbox.model import DeviceRole, Snapshot, segment_id
from signalbox.sim.mikrotik import PASSWORD, MikrotikSimulator
from signalbox.sim.server import serve
from signalbox.testing import assert_contract

SIM = MikrotikSimulator()
NAT = "/rest/ip/firewall/nat"
NATIVE = segment_id("home", None)


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    with serve(SIM.app()) as u:
        yield u


@pytest.fixture(autouse=True)
def sim() -> MikrotikSimulator:
    SIM.__dict__.update(MikrotikSimulator().__dict__)
    return SIM


def make(url: str) -> MikrotikAdapter:
    config = MikrotikConfig(url=url, password=SecretStr(PASSWORD), allow_insecure_http=True)
    return MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="rt",
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=config,
            timeout=5.0,
        )
    )


async def observe(url: str) -> Snapshot:
    a = make(url)
    try:
        return await assert_contract(a)
    finally:
        await a.close()


def dynamic(port: str, to: str, comment: str, **kw: str) -> dict[str, str]:
    return {
        ".id": "*D1",
        "chain": "dstnat",
        "action": "dst-nat",
        "protocol": "udp",
        "dst-port": port,
        "to-addresses": to,
        "to-ports": port,
        "comment": comment,
        "dynamic": "true",
        "disabled": "false",
        **kw,
    }


async def test_upnp_off_has_no_mappings_but_is_reported(url: str) -> None:
    snap = await observe(url)
    (svc,) = [s for s in snap.services if s.kind.value == "upnp"]
    assert not svc.enabled and svc.segments == [NATIVE]  # the bridge is the internal interface
    assert snap.device.upnp is not None and snap.device.upnp.mappings == []
    assert [p.value for p in snap.device.upnp.protocols] == ["upnp-igd"]


async def test_dynamic_nat_rows_are_the_mappings(url: str, sim: MikrotikSimulator) -> None:
    sim.data["/rest/ip/upnp"]["enabled"] = "true"
    sim.data[NAT] += [
        dynamic("3074", "192.0.2.60", "upnp 192.0.2.60: Example console"),
        dynamic("4000", "192.0.2.61", "upnp", protocol="tcp", **{"to-ports": "4001"}),
        dynamic("5000-5010", "192.0.2.62", "upnp"),  # a range: not a single mapping
        dynamic("6000", "192.0.2.63", "upnp", disabled="true"),
        dynamic("7000", "192.0.2.64", "defconf", dynamic="false"),  # not created by UPnP
    ]
    snap = await observe(url)
    (svc,) = [s for s in snap.services if s.kind.value == "upnp"]
    assert svc.enabled
    u = snap.device.upnp
    assert u is not None and u.mappings_complete
    by = {m.external_port: m for m in u.mappings}
    assert sorted(by) == [3074, 4000]
    assert by[3074].description == "192.0.2.60: Example console" and str(
        by[3074].internal_address
    ) == ("192.0.2.60")
    assert by[4000].protocol == "tcp" and by[4000].internal_port == 4001
    assert by[4000].description is None and by[4000].lease_seconds is None


async def test_unreadable_nat_marks_the_list_incomplete(url: str, sim: MikrotikSimulator) -> None:
    sim.data["/rest/ip/upnp"]["enabled"] = "true"
    sim.fail[NAT] = 403
    a = make(url)
    try:
        obs = await a.read_interfaces()
    finally:
        await a.close()
    assert obs.upnp["rt"].mappings == [] and not obs.upnp["rt"].mappings_complete


def test_row_parsing() -> None:
    assert mu.mappings([dynamic("1", "not-an-address", "upnp")]) == []
    assert mu.mappings([dynamic("1", "192.0.2.5", "upnp", protocol="icmp")]) == []
    assert mu.mappings([dynamic("1", "192.0.2.5", "upnp", action="masquerade")]) == []
    (m,) = mu.mappings([dynamic("9", "192.0.2.5", "UPnP - thing", **{"to-ports": ""})])
    assert (m.internal_port, m.description) == (9, "thing")
