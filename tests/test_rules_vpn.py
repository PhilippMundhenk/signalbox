"""VPN rules (#152): passing, failing and silent cases."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from factories import SITE, T0, device, iface, peer, site_link, tunnel, uplink
from signalbox.model import Network, Segment, Site, Subnet, Tunnel, segment_id
from signalbox.rules import Finding, Severity, evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.vpn import (
    RULES,
    allowed_ips_overlap,
    allowed_ips_unrouted,
    ends_disagree,
    handshake_stale,
    keepalive_behind_nat,
)

AWAY = Site(id="away", name="Away")


def subnet(address: str, dev: str, seg: str | None = None) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{address}",
        segment_id=seg or segment_id(SITE.id, None),
        interface=iface(address),
        device_id=dev,
        gateway=True,
    )


def network(*tunnels: Tunnel, **kw: Any) -> Network:
    values: dict[str, Any] = {
        "sites": [SITE, AWAY],
        "devices": [
            device("fw", name="Router"),
            device("pi", name="Pi", site_id=AWAY.id),
        ],
        "segments": [Segment(id=segment_id(SITE.id, None), site_id=SITE.id)],
        "tunnels": list(tunnels),
    }
    return Network(**(values | kw))


def run(rule: Any, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [rule]) if f.rule_id == rule.id]


def test_rules_are_registered() -> None:
    assert {r.id for r in RULES} <= {r.id for r in BUILTIN}
    assert len(RULES) == 5


# --- vpn.handshake-stale ----------------------------------------------------------------------


def stale(**kw: Any) -> Tunnel:
    values = {
        "allowed": ("2001:db8:ff::2/128", "198.51.100.0/24"),
        "endpoint_host": "203.0.113.20",
        "keepalive_seconds": 25,
        "rx_bytes": 10,
        "tx_bytes": 10,
        "latest_handshake": T0 - timedelta(minutes=9),
    }
    values.update(kw)
    allowed = values.pop("allowed")
    return tunnel("fw", peer("pi", *allowed, **values))


def test_stale_handshake_with_keepalive() -> None:
    (f,) = run(handshake_stale, network(stale()))
    assert f.severity is Severity.WARNING and f.objects == ["fw/tunnel/wg0"]
    assert "peer pi" in f.message and "9 minutes" in f.message
    assert "203.0.113.20" not in f.message


def test_stale_handshake_without_keepalive_is_info() -> None:
    (f,) = run(handshake_stale, network(stale(keepalive_seconds=0)))
    assert f.severity is Severity.INFO and "quiet by design" in (f.fix or "")


def test_never_handshaken_when_counters_are_known() -> None:
    (f,) = run(handshake_stale, network(stale(latest_handshake=None)))
    assert "since the tunnel came up" in f.message


def test_fresh_handshake_is_fine() -> None:
    assert not run(handshake_stale, network(stale(latest_handshake=T0 - timedelta(minutes=2))))


def test_handshake_rule_stays_quiet_without_data_or_expectation() -> None:
    assert not run(handshake_stale, network(stale(latest_handshake=None, rx_bytes=None)))
    # a phone connects to us: no endpoint, no keepalive
    assert not run(
        handshake_stale, network(stale(endpoint_host=None, keepalive_seconds=0, rx_bytes=0))
    )
    assert not run(handshake_stale, network(stale(enabled=False)))
    down = stale()
    assert not run(handshake_stale, network(down.model_copy(update={"up": False})))
    assert not run(handshake_stale, network(down.model_copy(update={"observed_at": None})))
    # a handshake in the future (clock skew) is not stale
    assert not run(handshake_stale, network(stale(latest_handshake=T0 + timedelta(minutes=1))))


# --- vpn.allowed-ips-overlap --------------------------------------------------------------------


def test_two_peers_with_the_same_network() -> None:
    t = tunnel(
        "fw",
        peer("a", "2001:db8:ff::2/128", "198.51.100.0/24"),
        peer("b", "2001:db8:ff::3/128", "198.51.100.0/24"),
    )
    (f,) = run(allowed_ips_overlap, network(t))
    assert "198.51.100.0/24" in f.message and "peer a" in f.message and "peer b" in f.message


def test_nested_networks_and_host_routes_are_no_overlap() -> None:
    t = tunnel(
        "fw",
        peer("a", "2001:db8:ff::2/128", "198.51.100.0/24"),
        peer("b", "2001:db8:ff::2/128", "198.51.100.0/25"),
        peer("c", "0.0.0.0/0"),
        peer("d", "0.0.0.0/0", enabled=False),
    )
    assert not run(allowed_ips_overlap, network(t))


def test_peer_network_overlaps_a_local_network() -> None:
    t = tunnel(
        "fw", peer("pi", "2001:db8:ff::2/128", "192.0.2.128/25"), addresses=["2001:db8:ff::1/64"]
    )
    net = network(t, subnets=[subnet("192.0.2.1/24", "fw")])
    (f,) = run(allowed_ips_overlap, net)
    assert "192.0.2.128/25" in f.message and "192.0.2.0/24" in f.message


def test_remote_networks_that_do_not_overlap_and_full_tunnels_are_fine() -> None:
    t = tunnel("fw", peer("pi", "198.51.100.0/24"), peer("exit", "0.0.0.0/0"))
    assert not run(allowed_ips_overlap, network(t, subnets=[subnet("192.0.2.1/24", "fw")]))
    # a local network of another site does not count
    away = network(t, subnets=[subnet("198.51.100.1/24", "pi")])
    assert not run(allowed_ips_overlap, away)


# --- vpn.allowed-ips-unrouted -------------------------------------------------------------------


def test_unrouted_peer_network() -> None:
    t = tunnel("fw", peer("pi", "2001:db8:ff::2/128", "198.51.100.0/24"), routes=[])
    (f,) = run(allowed_ips_unrouted, network(t))
    assert "198.51.100.0/24" in f.message and "no route" in f.message


def test_routed_or_unknown_routes_are_fine() -> None:
    p = peer("pi", "2001:db8:ff::2/128", "198.51.100.0/24")
    assert not run(allowed_ips_unrouted, network(tunnel("fw", p, routes=["198.51.100.0/24"])))
    assert not run(allowed_ips_unrouted, network(tunnel("fw", p, routes=["198.51.100.0/22"])))
    assert not run(allowed_ips_unrouted, network(tunnel("fw", p)))  # routes not read
    assert not run(allowed_ips_unrouted, network(tunnel("fw", p, routes=[], up=False)))
    # host routes (the peer's own address) need no route of their own
    assert not run(
        allowed_ips_unrouted, network(tunnel("fw", peer("p", "2001:db8:ff::2/128"), routes=[]))
    )


# --- vpn.keepalive-behind-nat -------------------------------------------------------------------


def behind(*up: Any, **kw: Any) -> Network:
    t = tunnel("fw", peer("pi", "198.51.100.0/24", endpoint_host="203.0.113.20", **kw))
    return network(t, uplinks=list(up))


def test_keepalive_missing_behind_nat() -> None:
    nat = uplink("fw", addresses=[iface("100.64.0.23/10")])
    (f,) = run(keepalive_behind_nat, behind(nat, keepalive_seconds=0))
    assert "behind NAT" in f.message and f.fix and "25 seconds" in f.fix
    private = uplink("fw", addresses=[iface("10.0.0.20/24")])
    assert len(run(keepalive_behind_nat, behind(private, keepalive_seconds=0))) == 1


def test_keepalive_rule_stays_quiet() -> None:
    nat = uplink("fw", addresses=[iface("100.64.0.23/10")])
    assert not run(keepalive_behind_nat, behind(nat, keepalive_seconds=25))
    assert not run(keepalive_behind_nat, behind(nat))  # keepalive not known
    assert not run(keepalive_behind_nat, behind(uplink("fw"), keepalive_seconds=0))  # public
    assert not run(keepalive_behind_nat, behind(keepalive_seconds=0))  # no uplinks read
    mixed = [nat, uplink("fw", "backup")]
    assert not run(keepalive_behind_nat, behind(*mixed, keepalive_seconds=0))
    assert not run(keepalive_behind_nat, behind(nat, keepalive_seconds=0, enabled=False))
    # a peer that connects to us has no endpoint: our keepalive would not help
    t = tunnel("fw", peer("phone", "2001:db8:ff::3/128", keepalive_seconds=0))
    assert not run(keepalive_behind_nat, network(t, uplinks=[nat]))


# --- vpn.ends-disagree --------------------------------------------------------------------------


def link() -> Network:
    fw, pi = site_link()
    return network(
        fw,
        pi,
        subnets=[subnet("192.0.2.1/24", "fw"), subnet("198.51.100.1/24", "pi")],
    )


def test_matching_ends_are_fine() -> None:
    assert not run(ends_disagree, link())


def test_other_end_does_not_list_us() -> None:
    fw, pi = site_link()
    one_sided = pi.model_copy(update={"peers": []})
    (f,) = run(ends_disagree, network(fw, one_sided))
    assert "does not list" in f.message and f.objects == ["fw/tunnel/wg0", "pi/tunnel/wg0"]


def test_routed_network_does_not_exist_at_the_other_end() -> None:
    fw, pi = site_link()
    net = network(
        fw,
        pi,
        subnets=[subnet("192.0.2.1/24", "fw"), subnet("203.0.113.1/24", "pi")],
    )
    findings = run(ends_disagree, net)
    assert [f.objects[0] for f in findings] == ["fw/tunnel/wg0"]
    assert "198.51.100.0/24" in findings[0].message


def test_ends_rule_stays_quiet_when_it_cannot_compare() -> None:
    fw, pi = site_link()
    assert not run(ends_disagree, network(fw))  # the other end is not read
    assert not run(ends_disagree, network(fw, pi))  # no subnets known
    no_key = fw.model_copy(update={"public_key": None})
    assert not run(ends_disagree, network(no_key, pi))
    off = pi.model_copy(update={"peers": [pi.peers[0].model_copy(update={"enabled": False})]})
    assert len(run(ends_disagree, network(fw, off))) == 1
    assert not run(ends_disagree, network(fw.model_copy(update={"enabled": False}), pi))
    # a full tunnel routes everything: no network to compare
    full = tunnel("fw", peer("pi", "0.0.0.0/0"))
    pi2 = tunnel("pi", peer("fw", "192.0.2.0/24"))
    net = network(full, pi2, subnets=[subnet("198.51.100.1/24", "pi")])
    assert not run(ends_disagree, net)
