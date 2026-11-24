"""The legacy iptables reader (#394): ``iptables-save`` text mapped to the nft firewall model."""

from __future__ import annotations

from signalbox.adapters.linux import iptables
from signalbox.adapters.linux.nftables import Parsed
from signalbox.model import FirewallAction, FirewallChain, FirewallProtocol
from signalbox.sim.linux import (
    LEGACY_IP6TABLES_SAVE,
    LEGACY_IPTABLES_SAVE,
    NFT_BACKED_IPTABLES_SAVE,
)


def filter_table(*lines: str, policy: str = "ACCEPT") -> str:
    head = f"*filter\n:INPUT {policy} [0:0]\n:FORWARD {policy} [0:0]\n:u - [0:0]\n"
    return head + "\n".join(lines) + "\nCOMMIT\n"


def nat_table(*lines: str) -> str:
    head = "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"
    return head + "\n".join(lines) + "\nCOMMIT\n"


def only(parsed: Parsed):  # type: ignore[no-untyped-def]
    assert len(parsed.rules) == 1
    return parsed.rules[0]


def test_the_fixtures_give_the_model_of_the_nft_reader() -> None:
    p = iptables.parse(LEGACY_IPTABLES_SAVE, LEGACY_IP6TABLES_SAVE)
    assert p.complete and p.enabled and not p.gaps
    assert p.input_policy is FirewallAction.DROP and p.forward_policy is FirewallAction.DROP
    assert len(p.rules) == 10 and p.zone_names == {"lo", "br0", "eth0", "wg0"}
    assert len(p.port_forwards) == 1 and len(p.nat) == 1
    assert iptables.has_rules(p)


def test_nft_backed_output_and_a_system_without_rules() -> None:
    p = iptables.parse(NFT_BACKED_IPTABLES_SAVE)
    # comment lines are skipped, the jump to a chain that returns adds nothing
    assert p.forward_policy is None  # IPv4 drops, no IPv6 table was given: they differ
    assert p.zone_names == {"docker0"}
    (rule,) = p.rules
    assert rule.chain is FirewallChain.FORWARD and rule.destination.zones_not
    assert not iptables.has_rules(iptables.parse(""))
    assert not iptables.has_rules(iptables.parse(filter_table()))  # chains, all accept, no rule


def test_conditions_and_negations() -> None:
    r = only(iptables.parse(filter_table("-A INPUT ! -s 192.0.2.0/24 -j DROP")))
    assert r.source.networks_not and [str(n) for n in r.source.networks] == ["192.0.2.0/24"]
    assert r.action is FirewallAction.DROP and r.exact

    r = only(iptables.parse(filter_table("-A INPUT -p tcp -m tcp --dport 8000:8100 -j ACCEPT")))
    assert [str(p) for p in r.destination.ports] == ["8000-8100"] and r.exact

    r = only(iptables.parse(filter_table("-A INPUT -p tcp -m tcp ! --dport 22 -j ACCEPT")))
    assert r.exact is False  # a negated port is not modelled

    r = only(
        iptables.parse(filter_table("-A INPUT -p udp -m multiport --sports 53,1000:2000 -j ACCEPT"))
    )
    assert [str(p) for p in r.source.ports] == ["53", "1000-2000"] and r.exact

    r = only(iptables.parse(filter_table("-A INPUT -p 6 -m tcp --dport abc -j ACCEPT")))
    assert r.protocols == [FirewallProtocol.TCP] and r.exact is False

    r = only(iptables.parse(filter_table("-A INPUT -p all -i eth+ -j ACCEPT")))
    assert r.source.zones == ["eth*"] and r.protocols == []

    r = only(iptables.parse(filter_table("-A INPUT ! -p tcp -j ACCEPT")))
    assert r.exact is False


def test_modules_and_options_the_model_lacks_keep_the_rule_inexact() -> None:
    p = iptables.parse(
        filter_table(
            "-A INPUT -f -j DROP",
            "-A INPUT -m limit --limit 5/min -j ACCEPT",
            "-A INPUT -m recent --set --name x -j LOG --log-prefix 'a b'",
            "-A INPUT -m conntrack --ctstate DNAT,SNAT -j ACCEPT",
            "-A INPUT -j MARK --set-mark 1",
            "-A INPUT -j NOSUCH",
        )
    )
    # the LOG, MARK and unknown targets decide nothing; the rest keep their verdict
    assert [(r.action, r.exact) for r in p.rules] == [
        (FirewallAction.DROP, False),
        (FirewallAction.ACCEPT, False),
        (FirewallAction.ACCEPT, False),
    ]


def test_jump_goto_and_return() -> None:
    p = iptables.parse(
        filter_table(
            "-A FORWARD -j u",
            "-A u -j RETURN",
            "-A u -s 192.0.2.7/32 -j ACCEPT",
            "-A FORWARD -g u",
        )
    )
    assert p.complete and p.rules and all(r.chain is FirewallChain.FORWARD for r in p.rules)


def test_a_comment_with_spaces_and_a_broken_line() -> None:
    p = iptables.parse(
        filter_table(
            '-A INPUT -m comment --comment "ssh from the lab" -j ACCEPT',
            '-A INPUT -m comment --comment "unterminated -j DROP',
        )
    )
    assert [r.name for r in p.rules] == ["ssh from the lab"]
    assert iptables.parse("garbage\n").rules == []


def test_nat_forwards_masquerade_and_what_is_not_read() -> None:
    p = iptables.parse(
        nat_table(
            "-A PREROUTING -p tcp --dport 81 -j DNAT --to-destination 192.0.2.5:8000-8010",
            "-A PREROUTING -p tcp --dport 82 -j DNAT",
            "-A PREROUTING -p tcp --dport 83 -j DNAT --to-destination 192.0.2.5-192.0.2.9",
            "-A PREROUTING -p tcp --dport 84 -j DNAT --to-destination [2001:db8::5]:80",
            "-A PREROUTING -j REDIRECT --to-ports 3128",
            "-A POSTROUTING -j SNAT --to-source 192.0.2.1",
            "-A POSTROUTING -j SNAT --to-source 192.0.2.1:1000-2000",
            "-A POSTROUTING -j SNAT",
            "-A POSTROUTING -o eth0 -j MASQUERADE",
        )
    )
    assert p.port_forwards_complete is False and p.complete is False  # redirect, ranges, SNAT
    targets = {str(f.target_address): (f.target_port, f.exact) for f in p.port_forwards}
    assert targets == {"192.0.2.5": (None, False), "2001:db8::5": (80, True)}
    assert [(n.masquerade, str(n.to_address)) for n in p.nat] == [
        (False, "192.0.2.1"),
        (True, "None"),
    ]
    assert any("redirect" in g for g in p.gaps)


def test_a_dropping_raw_chain_makes_the_rules_incomplete() -> None:
    p = iptables.parse("*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp -j DROP\nCOMMIT\n")
    assert p.complete is False and any("drops traffic" in g for g in p.gaps)
