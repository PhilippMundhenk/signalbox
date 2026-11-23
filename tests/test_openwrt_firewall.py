"""OpenWrt firewall (UCI ``firewall``, #135, ADR 0013) against the ubus simulator."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Flow,
    PortRange,
    Verdict,
)
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.testing import assert_contract

SIM = OpenWrtSim()


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"), "openwrt")


@pytest.fixture(scope="module")
def https_url(cert: TlsFiles) -> Iterator[str]:
    with serve(create_app(SIM), tls=cert) as url:
        yield url


@pytest.fixture
def sim() -> OpenWrtSim:
    SIM.reset()
    return SIM


def make(url: str, cert: TlsFiles, role: DeviceRole) -> OpenWrtAdapter:
    return OpenWrtAdapter(
        AdapterContext(
            site_id="home",
            device_id="ap1",
            device_name="AP 1",
            role=role,
            config=OpenWrtConfig(url=f"{url}/ubus", password=SecretStr(OpenWrtSim().password)),
            pinned_fingerprint=cert.fingerprint,
        )
    )


@pytest.fixture
async def adapter(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> AsyncIterator[OpenWrtAdapter]:
    a = make(https_url, cert, DeviceRole.AP)
    yield a
    await a.close()


@pytest.fixture
async def router(sim: OpenWrtSim, https_url: str, cert: TlsFiles) -> AsyncIterator[OpenWrtAdapter]:
    sim.router = True
    a = make(https_url, cert, DeviceRole.GATEWAY)
    yield a
    await a.close()


async def test_firewall_of_a_router(router: OpenWrtAdapter, sim: OpenWrtSim) -> None:
    sim.wireguard = True
    snap = await assert_contract(router)
    [fw] = snap.firewalls
    assert fw.id == "ap1/firewall" and fw.enabled and fw.rules_complete
    zones = {z.name: z for z in fw.zones}
    assert zones["lan"].segments == ["home/segment/native"] and zones["lan"].complete
    assert zones["iot"].segments == ["home/segment/20"]
    assert zones["wan"].uplinks == ["ap1/uplink/wan"] and zones["wan"].masquerade is True
    assert zones["vpn"].tunnels == ["ap1/tunnel/wg0"] and zones["vpn"].masquerade is False
    assert fw.policy("lan", "wan") is FirewallAction.ACCEPT
    assert fw.policy("lan", None) is FirewallAction.ACCEPT
    assert fw.policy("wan", None) is FirewallAction.REJECT
    assert fw.policy("iot", "iot") is FirewallAction.REJECT
    assert fw.input_policy is FirewallAction.REJECT
    assert fw.forward_policy is FirewallAction.REJECT
    by = {r.name: r for r in fw.rules}
    ping = by["Allow-Ping"]
    assert ping.chain is FirewallChain.INPUT and ping.family == 4 and not ping.exact
    esp = by["Allow-IPSec-ESP"]
    assert esp.chain is FirewallChain.FORWARD and esp.destination.zones == ["lan"] and esp.exact
    dns = by["Allow-DNS-IoT"]
    assert dns.source.zones == ["iot"] and dns.destination.ports == [PortRange(start=53)]
    [pf] = fw.port_forwards
    assert (pf.name, pf.zones, pf.passes_filter, pf.exact) == ("nas-https", ["wan"], True, True)
    assert pf.external_ports == [PortRange(start=8443)] and pf.target_port == 443
    assert str(pf.target_address) == "192.0.2.10"
    # the reachability helper reads it the way the router does
    to_dns = Flow(
        chain=FirewallChain.INPUT,
        source_zones={"iot"},
        protocol=FirewallProtocol.UDP,
        port=53,
    )
    assert fw.evaluate(to_dns).verdict is Verdict.ALLOWED
    from_wan = to_dns.model_copy(update={"source_zones": {"wan"}, "port": 443})
    assert fw.evaluate(from_wan).verdict is Verdict.DENIED


async def test_firewall_of_an_access_point(adapter: OpenWrtAdapter) -> None:
    [fw] = (await adapter.read_firewall()).firewalls
    assert [z.name for z in fw.zones] == ["lan"] and fw.rules == [] and fw.port_forwards == []


async def test_unmapped_zones_includes_and_odd_sections(
    router: OpenWrtAdapter, sim: OpenWrtSim
) -> None:
    fw = sim.state["firewall"]
    fw["cfg02dc81"]["device"] = ["tun0"]
    fw["vpn2"] = {
        ".type": "zone",
        "name": "vpn2",
        "network": ["nothere"],
        "masq": "1",
        "masq_src": "192.0.2.0/24",
    }
    fw["inc"] = {".type": "include", "path": "/etc/firewall.nft", "type": "nftables"}
    fw["to_router"] = {".type": "redirect", "src": "wan", "src_dport": "22", "dest_port": "22"}
    fw["snat"] = {
        ".type": "redirect",
        "target": "SNAT",
        "src": "wan",
        "snat_ip": "203.0.113.9",
        "src_ip": "192.0.2.0/24",
    }
    fw["nat1"] = {".type": "nat", "target": "MASQUERADE", "src": "wan", "src_ip": "!192.0.2.8"}
    fw["mark"] = {".type": "rule", "name": "mark", "target": "MARK", "src": "lan"}
    fw["timed"] = {
        ".type": "rule",
        "name": "timed",
        "src": "lan",
        "dest": "*",
        "target": "REJECT",
        "weekdays": "Sat Sun",
        "src_ip": ["192.0.2.0/24", "!192.0.2.9"],
        "dest_port": "80-90 443",
        "proto": "all",
    }
    [out] = (await router.read_firewall()).firewalls
    zones = {z.name: z for z in out.zones}
    assert not zones["lan"].complete and not zones["vpn2"].complete
    assert zones["vpn2"].masquerade is None
    assert not out.rules_complete and not out.port_forwards_complete
    assert "mark" not in {r.name for r in out.rules}
    timed = next(r for r in out.rules if r.name == "timed")
    assert not timed.exact and timed.protocols == [] and timed.destination.zones == []
    assert timed.destination.ports == [PortRange(start=80, end=90), PortRange(start=443)]
    assert [(n.zones, n.masquerade, n.exact) for n in out.nat] == [
        (["wan"], False, True),
        (["wan"], True, False),
    ]
    assert str(out.nat[0].to_address) == "203.0.113.9"


async def test_firewall_without_config_filters_nothing(
    adapter: OpenWrtAdapter, sim: OpenWrtSim
) -> None:
    sim.missing = {"firewall"}
    [fw] = (await adapter.read_firewall()).firewalls
    assert fw.enabled is False


async def test_old_acl_leaves_the_firewall_unread(adapter: OpenWrtAdapter, sim: OpenWrtSim) -> None:
    sim.denied = {"uci:firewall"}
    snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL and snap.ports and snap.firewalls == []
    [gap] = snap.errors
    assert gap.capability == "firewall" and "firewall" in gap.message
    assert gap.fix and "Prepare the router" in gap.fix
