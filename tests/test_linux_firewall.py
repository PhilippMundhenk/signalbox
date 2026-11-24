"""Firewall of the Linux gateway (#135, ADR 0013): ``nft -j list ruleset`` against the SSH
simulator and the parser on crafted rulesets."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from ipaddress import ip_network
from typing import Any

import asyncssh

from signalbox.adapters import AdapterContext
from signalbox.adapters.linux import LinuxAdapter, LinuxConfig, nftables
from signalbox.adapters.linux.setup import SUDOERS_PATH, sudoers
from signalbox.adapters.ssh import sha256_hex
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    Flow,
    Verdict,
)
from signalbox.sim.linux import (
    LEGACY_IP6TABLES_SAVE,
    LEGACY_IPTABLES_SAVE,
    NFT_BACKED_IPTABLES_SAVE,
    LinuxSim,
    User,
    serve_ssh,
)
from signalbox.testing import assert_contract

KEY = asyncssh.generate_private_key("ssh-ed25519")
PRIVATE = KEY.export_private_key().decode()
PUBLIC = KEY.export_public_key("openssh").decode().strip()


def device(**changes: Any) -> LinuxSim:
    box = LinuxSim(**changes)
    box.users["signalbox"] = User(keys=[PUBLIC], system=True)
    box.sudoers_files[SUDOERS_PATH] = sudoers("signalbox")
    return box


@asynccontextmanager
async def adapter_for(box: LinuxSim) -> AsyncIterator[LinuxAdapter]:
    async with serve_ssh(box) as (port, fingerprint):
        ctx = AdapterContext(
            site_id="home",
            device_id="gw2",
            device_name="gw2",
            role=DeviceRole.GATEWAY,
            config=LinuxConfig(
                host="127.0.0.1", port=port, username="signalbox", private_key=PRIVATE
            ),
            pinned_fingerprint=sha256_hex(fingerprint),
            timeout=5,
        )
        adapter = LinuxAdapter(ctx)
        try:
            yield adapter
        finally:
            await adapter.close()


async def firewall_of(box: LinuxSim) -> tuple[Any, Any]:
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    return snap, (snap.firewalls[0] if snap.firewalls else None)


async def test_contract() -> None:
    async with adapter_for(device()) as adapter:
        snap = await assert_contract(adapter)
    assert len(snap.firewalls) == 1


async def test_firewall_from_nft() -> None:
    snap, fw = await firewall_of(device())
    assert snap.status is DeviceStatus.OK
    assert fw.id == "gw2/firewall" and fw.enabled and fw.rules_complete
    assert fw.input_policy is FirewallAction.DROP and fw.forward_policy is FirewallAction.DROP
    zones = {z.name: z for z in fw.zones}
    assert set(zones) == {"br0", "eth0", "eth1.30", "lo", "wg0"}
    assert zones["br0"].segments == ["home/segment/native"]
    assert zones["eth0"].uplinks == ["gw2/uplink/eth0"]
    assert zones["wg0"].tunnels == ["gw2/tunnel/wg0"]
    assert zones["eth1.30"].segments == ["home/segment/30"] and zones["lo"].complete
    # ct state established/related/invalid rules are left out, the jump is flattened
    assert len(fw.rules) == 9 and fw.rules[0].source.zones == ["lo"]
    ssh = next(r for r in fw.rules if r.name == "ssh from the office")
    assert ssh.chain is FirewallChain.INPUT and ssh.action is FirewallAction.ACCEPT
    assert [str(n) for n in ssh.source.networks] == ["203.0.113.0/24"]  # the named set
    assert [str(p) for p in ssh.destination.ports] == ["22"] and ssh.exact
    icmp = next(r for r in fw.rules if FirewallProtocol.ICMP in r.protocols)
    assert icmp.exact is False  # the ICMP type is not modelled
    vpn = fw.rules[-1]
    assert vpn.source.zones == ["wg0"]
    assert [str(n) for n in vpn.destination.networks] == ["192.0.2.20/32"]
    assert [str(p) for p in vpn.destination.ports] == ["80", "443"]
    dnat = next(r for r in fw.rules if r.forwarded)
    assert dnat.source.zones == ["eth0"]
    (fwd,) = fw.port_forwards
    assert fwd.name == "nas" and fwd.zones == ["eth0"] and fwd.passes_filter is False
    assert str(fwd.target_address) == "192.0.2.20" and fwd.target_port == 443
    assert [str(p) for p in fwd.external_ports] == ["8443"] and fwd.exact
    (nat,) = fw.nat
    assert nat.zones == ["eth0"] and nat.masquerade and nat.exact

    def ssh_flow(address: str) -> Flow:
        return Flow(
            chain=FirewallChain.INPUT,
            source_zones={"eth0"},
            source=ip_network(address),
            protocol=FirewallProtocol.TCP,
            port=22,
        )

    assert fw.evaluate(ssh_flow("203.0.113.5/32")).verdict is Verdict.ALLOWED
    assert fw.evaluate(ssh_flow("198.51.100.7/32")).verdict is Verdict.DENIED


async def test_without_the_sudoers_rule_nothing_is_reported() -> None:
    box = device()
    box.sudoers_files.clear()
    snap, fw = await firewall_of(box)
    assert fw is None
    err = next(e for e in snap.errors if e.capability == "firewall")
    assert "nft" in err.message and err.fix and "sudoers" in err.fix


async def test_legacy_iptables_rules_next_to_nft_rules_are_incomplete() -> None:
    legacy = device(iptables_save=LEGACY_IPTABLES_SAVE)
    legacy.sections["iptables"] = "iptables v1.8.9 (legacy)\n"
    snap, fw = await firewall_of(legacy)
    assert fw.rules_complete is False and fw.rules  # what nft shows is kept
    assert fw.vendor_extra == {"source": "nft"}
    assert snap.status is DeviceStatus.PARTIAL
    assert "iptables-legacy" in next(e for e in snap.errors if e.capability == "firewall").message

    # the legacy backend in use but without rules (the rules are in nft): nothing is hidden
    empty = device()
    empty.sections["iptables"] = "iptables v1.8.9 (legacy)\n"
    snap, fw = await firewall_of(empty)
    assert fw.rules_complete and snap.status is DeviceStatus.OK


async def test_only_iptables_without_iptables_save_and_nothing_at_all() -> None:
    only_iptables = device(nft_installed=False, iptables_installed=False)
    only_iptables.sections["iptables"] = "iptables v1.8.9 (legacy)\n"
    snap, fw = await firewall_of(only_iptables)
    assert fw.rules_complete is False and fw.port_forwards_complete is False and not fw.rules
    assert "no nft command" in next(e for e in snap.errors if e.capability == "firewall").message

    nothing = device(nft_installed=False, iptables_installed=False)
    nothing.sections["iptables"] = ""
    snap, fw = await firewall_of(nothing)
    assert fw.enabled is False and snap.status is DeviceStatus.OK
    flow = Flow(chain=FirewallChain.INPUT, source_zones={"x"})
    assert fw.evaluate(flow).verdict is Verdict.ALLOWED


async def test_legacy_iptables_without_nft_is_read_like_nft() -> None:
    """#394: ``iptables-save`` and ``ip6tables-save`` give the model of the nft reader."""
    box = device(
        nft_installed=False,
        iptables_save=LEGACY_IPTABLES_SAVE,
        ip6tables_save=LEGACY_IP6TABLES_SAVE,
    )
    box.sections["iptables"] = "iptables v1.8.9 (legacy)\n"
    snap, fw = await firewall_of(box)
    assert snap.status is DeviceStatus.OK and not [
        e for e in snap.errors if e.capability == "firewall"
    ]
    assert fw.id == "gw2/firewall" and fw.enabled and fw.rules_complete
    assert fw.vendor_extra == {"source": "iptables-save"}
    assert fw.input_policy is FirewallAction.DROP and fw.forward_policy is FirewallAction.DROP
    zones = {z.name: z for z in fw.zones}
    assert set(zones) == {"br0", "eth0", "lo", "wg0"}
    assert zones["br0"].segments == ["home/segment/native"]
    assert zones["eth0"].uplinks == ["gw2/uplink/eth0"] and zones["wg0"].tunnels == [
        "gw2/tunnel/wg0"
    ]
    v4 = [r for r in fw.rules if r.family == 4]
    v6 = [r for r in fw.rules if r.family == 6]
    # the same rules as the nft ruleset (default_nft) except its two IPv6-only and its set
    assert [r.chain.value for r in v4] == ["input"] * 4 + ["forward"] * 3
    assert len(v6) == 3 and all(r.chain is FirewallChain.INPUT for r in v6)
    ssh = next(r for r in fw.rules if r.name == "ssh from the office")
    assert [str(n) for n in ssh.source.networks] == ["203.0.113.0/24"]
    assert [str(p) for p in ssh.destination.ports] == ["22"] and ssh.exact
    assert next(r for r in v4 if FirewallProtocol.ICMP in r.protocols).exact is False
    vpn = v4[-1]
    assert vpn.source.zones == ["wg0"] and [str(p) for p in vpn.destination.ports] == ["80", "443"]
    dnat = next(r for r in fw.rules if r.forwarded)
    assert dnat.source.zones == ["eth0"]
    (fwd,) = fw.port_forwards
    assert fwd.name == "nas" and fwd.zones == ["eth0"] and fwd.passes_filter is False
    assert str(fwd.target_address) == "192.0.2.20" and fwd.target_port == 443 and fwd.exact
    (nat,) = fw.nat
    assert nat.zones == ["eth0"] and nat.masquerade and nat.exact


async def test_nft_wins_when_it_has_rules_and_iptables_fills_in_when_it_is_empty() -> None:
    backed = device(iptables_save=NFT_BACKED_IPTABLES_SAVE)
    _, fw = await firewall_of(backed)
    assert fw.vendor_extra == {"source": "nft"} and len(fw.rules) == 9

    empty_nft = device(iptables_save=LEGACY_IPTABLES_SAVE, nft=nft_json())
    empty_nft.sections["iptables"] = "iptables v1.8.9 (legacy)\n"
    snap, fw = await firewall_of(empty_nft)
    assert fw.vendor_extra == {"source": "iptables-save"} and fw.rules_complete
    assert not [e for e in snap.errors if e.capability == "firewall"]

    nothing = device(nft=nft_json())  # neither has rules: nft is the source
    _, fw = await firewall_of(nothing)
    assert fw.vendor_extra == {"source": "nft"} and fw.enabled is False


async def test_iptables_save_needs_the_sudoers_rule() -> None:
    box = device(nft_installed=False, iptables_save=LEGACY_IPTABLES_SAVE)
    box.sudoers_files.clear()
    snap, fw = await firewall_of(box)
    assert fw is None
    err = next(e for e in snap.errors if e.capability == "firewall")
    assert "iptables-save" in err.message and err.fix and "sudoers" in err.fix


async def test_ip6tables_save_not_allowed_keeps_the_ipv4_rules_incomplete() -> None:
    box = device(
        nft_installed=False,
        iptables_save=LEGACY_IPTABLES_SAVE,
        ip6tables_save=LEGACY_IP6TABLES_SAVE,
        ip6tables_denied=True,
    )
    snap, fw = await firewall_of(box)
    assert fw.rules_complete is False and fw.rules and all(r.family == 4 for r in fw.rules)
    err = next(e for e in snap.errors if e.capability == "firewall")
    assert "ip6tables-save" in err.message and "IPv6" in err.message


async def test_unparsable_nft_output() -> None:
    box = device()
    box.nft = "not json"
    snap, fw = await firewall_of(box)
    assert fw is None
    err = next(e for e in snap.errors if e.capability == "firewall")
    assert "not an nftables ruleset" in err.message


# parser -----------------------------------------------------------------------------------------


def nft_json(*objects: dict[str, Any]) -> str:
    return json.dumps({"nftables": [{"metainfo": {}}, *objects]})


def base(name: str, hook: str, policy: str = "accept", prio: int = 0, **kw: Any) -> dict[str, Any]:
    return {
        "chain": {
            "family": kw.get("family", "inet"),
            "table": kw.get("table", "t"),
            "name": name,
            "type": kw.get("type", "filter"),
            "hook": hook,
            "prio": prio,
            "policy": policy,
        }
    }


def regular(name: str) -> dict[str, Any]:
    return {"chain": {"family": "inet", "table": "t", "name": name}}


def rule(chain: str, *expr: dict[str, Any], **kw: str) -> dict[str, Any]:
    family, table = kw.get("family", "inet"), kw.get("table", "t")
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": list(expr)}}


def m(left: dict[str, Any], right: Any, op: str = "==") -> dict[str, Any]:
    return {"match": {"op": op, "left": left, "right": right}}


IIF = {"meta": {"key": "iifname"}}
OIF = {"meta": {"key": "oifname"}}
MARK = {"meta": {"key": "mark"}}
L4 = {"meta": {"key": "l4proto"}}
STATE = {"ct": {"key": "state"}}
SADDR = {"payload": {"protocol": "ip", "field": "saddr"}}
DADDR = {"payload": {"protocol": "ip", "field": "daddr"}}
ACCEPT, DROP = {"accept": None}, {"drop": None}


def dport(proto: str = "tcp") -> dict[str, Any]:
    return {"payload": {"protocol": proto, "field": "dport"}}


def test_conditions_and_negations() -> None:
    p = nftables.parse(
        nft_json(
            base("in", "input", "drop"),
            rule(
                "in",
                m(IIF, {"set": ["eth1", "eth2"]}),
                m(dport("th"), {"range": [1000, 2000]}),
                ACCEPT,
            ),
            rule("in", m(IIF, "eth3", "!="), m(L4, "gre"), DROP),
            rule("in", m({"meta": {"key": "nfproto"}}, "ipv6"), m(MARK, 1), DROP),
            rule(
                "in",
                m(SADDR, {"range": ["192.0.2.1", "192.0.2.4"]}),
                m(DADDR, {"prefix": {"addr": "192.0.2.0", "len": 24}}, "!="),
                {"counter": None},
                {"reject": {"type": "icmp"}},
            ),
            rule("in", m(STATE, "new"), {"log": None}),
            rule("in", m(STATE, {"set": ["related", "new"]}), ACCEPT),
            rule("in", m(STATE, {"set": ["related", "bogus"]}), ACCEPT),
            rule("in", m(dport(), 70000), ACCEPT),
            rule("in", m(dport(), 22, "!="), ACCEPT),
            rule("in", m(dport("udp"), "@nothing"), DROP),
        )
    )
    r = p.rules
    assert r[0].source.zones == ["eth1", "eth2"] and r[0].protocols[0].value == "tcp"
    assert [str(x) for x in r[0].destination.ports] == ["1000-2000"] and r[0].exact
    assert r[1].source.zones_not and r[1].protocols == [FirewallProtocol.GRE]
    assert r[2].family == 6 and r[2].exact is False
    nets = [str(n) for n in r[3].source.networks]
    assert nets == ["192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/32"]
    assert r[3].destination.networks_not and r[3].action is FirewallAction.REJECT
    assert r[4].action is FirewallAction.ACCEPT and r[4].exact  # new + related
    assert r[5].exact is False  # an unknown state
    assert r[6].exact is False and r[7].exact is False and r[8].exact is False
    assert p.input_policy is FirewallAction.DROP and p.forward_policy is FirewallAction.ACCEPT
    assert p.enabled and p.complete and "eth3" in p.zone_names


def test_jump_goto_return_and_loops() -> None:
    p = nftables.parse(
        nft_json(
            base("fw", "forward", "drop"),
            regular("a"),
            regular("b"),
            regular("loop"),
            rule("fw", m(IIF, "eth0"), {"jump": {"target": "a"}}),
            rule("fw", m(IIF, "eth1"), {"goto": {"target": "b"}}),
            rule("fw", {"jump": {"target": "nowhere"}}),
            rule("fw", {"jump": {"target": "loop"}}),
            rule("loop", {"jump": {"target": "loop"}}),
            rule("a", m(IIF, "eth9"), ACCEPT),  # conflicts with the jump's interface
            rule("a", m(IIF, "eth0"), m(SADDR, "192.0.2.0/24"), {"return": None}),
            rule("a", {"jump": {"target": "b"}}),
            rule("a", {"return": None}),
            rule("a", DROP),  # never reached: unconditional return before
            rule("b", m(OIF, "eth2"), ACCEPT),
            rule("b", {"vmap": {"key": {}, "data": {}}}),
        )
    )
    assert not p.complete
    assert sum("cannot be followed" in g for g in p.gaps) == 2
    assert any("vmap" in g for g in p.gaps)
    assert {g.message_id for g in p.gaps} == {"linux.nft.chainJump", "linux.nft.vmap"}
    jump = next(g for g in p.gaps if g.message_id == "linux.nft.chainJump")
    assert set(jump.params) == {"kind", "chain"}
    first, second, third = p.rules[0], p.rules[1], p.rules[2]
    assert first.source.zones == ["eth9"] and first.exact is False
    assert second.source.zones == ["eth0"] and second.destination.zones == ["eth2"]
    assert second.exact is False  # after a conditional return
    assert third.source.zones == ["eth1"] and third.destination.zones == ["eth2"]


def test_several_base_chains() -> None:
    drops_first = nftables.parse(
        nft_json(
            base("early", "input", "accept", -10, table="f2b"),
            rule("early", m(IIF, "eth0"), DROP, table="f2b"),
            base("in", "input", "drop", 0),
            rule("in", ACCEPT),
        )
    )
    assert drops_first.complete
    assert [r.action.value for r in drops_first.rules] == ["drop", "accept"]
    clash = nftables.parse(
        nft_json(
            base("in", "input", "drop", 0),
            rule("in", m(IIF, "eth0"), ACCEPT),
            base("in2", "input", "accept", 10, table="u"),
            rule("in2", m(IIF, "eth1"), DROP, table="u"),
        )
    )
    assert not clash.complete and "several base chains" in clash.gaps[0]
    families = nftables.parse(
        nft_json(
            base("in", "input", "drop", family="ip"),
            rule("in", ACCEPT, family="ip"),
            base("in6", "input", "accept", family="ip6", table="t6"),
            rule("in6", DROP, family="ip6", table="t6"),
        )
    )
    assert families.complete and families.input_policy is None  # ip drops, ip6 accepts
    assert [r.family for r in families.rules] == [4, 6]
    empty = nftables.parse(nft_json(base("in", "input"), base("fw", "forward", type="route")))
    assert not empty.enabled and not empty.rules
    raw = nftables.parse(
        nft_json(
            base("pre", "prerouting", prio=-300, table="raw"),
            rule("pre", m(IIF, "eth0"), DROP, table="raw"),
        )
    )
    assert not raw.complete and "prerouting chain" in raw.gaps[0]


def test_nat() -> None:
    nat = nftables.parse(
        nft_json(
            base("pre", "prerouting", type="nat", family="ip", prio=-100),
            rule("pre", m(dport(), 80), ACCEPT, family="ip"),
            rule(
                "pre",
                m(dport("udp"), {"set": [53, 5353]}),
                m(DADDR, "198.51.100.2"),
                m(SADDR, "203.0.113.0/24"),
                {"dnat": {"addr": "192.0.2.53", "port": {"range": [1, 2]}}},
                family="ip",
            ),
            rule("pre", {"dnat": {"addr": {"range": ["192.0.2.1", "192.0.2.2"]}}}, family="ip"),
            rule("pre", m(dport(), 81), {"redirect": {"port": 8081}}, family="ip"),
            rule("pre", m(dport(), 82), {"dnat": {"addr": "192.0.2.9"}}, family="ip"),
            base("post", "postrouting", type="nat", family="ip", prio=100),
            rule("post", m(OIF, "eth0", "!="), {"masquerade": None}, family="ip"),
            rule("post", m(OIF, "eth0"), {"snat": {"addr": "198.51.100.2"}}, family="ip"),
            rule("post", {"snat": {"addr": {"range": []}}}, family="ip"),
            base("out", "output", type="nat", family="ip"),
            rule("out", {"masquerade": None}, family="ip"),
        )
    )
    assert not nat.port_forwards_complete and not nat.complete
    f1, f2 = nat.port_forwards
    assert f1.protocols == [FirewallProtocol.UDP] and f1.exact is False  # after an accept
    assert str(f1.external_address) == "198.51.100.2"
    assert [str(n) for n in f1.sources] == ["203.0.113.0/24"]
    assert f1.target_port is None and [str(p) for p in f1.external_ports] == ["53", "5353"]
    assert f2.target_port is None and f2.external_ports[0].start == 82
    n1, n2 = nat.nat
    assert n1.masquerade and n1.exact is False and n1.zones == []
    assert not n2.masquerade and str(n2.to_address) == "198.51.100.2"


def test_gap_texts_name_the_real_source() -> None:
    """#404: the shared mapping says iptables when the rules came from iptables-save."""
    g = nftables.NftGap("nftables: x", "linux.nft.vmap").named("iptables")
    assert g == "iptables: x" and g.params == {"source": "iptables"}
