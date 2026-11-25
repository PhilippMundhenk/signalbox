"""IPsec and OpenVPN rules (#153): passing, failing and silent cases."""

from __future__ import annotations

from typing import Any

from factories import SITE, T0, device, iface, uplink
from signalbox.model import (
    CryptoProposal,
    Network,
    Segment,
    Subnet,
    Tunnel,
    TunnelAuth,
    TunnelChild,
    TunnelKind,
    TunnelRole,
    object_id,
    segment_id,
)
from signalbox.rules import Finding, Severity, evaluate
from signalbox.rules.builtin import RULES as BUILTIN
from signalbox.rules.vpn_tunnels import (
    RULES,
    child_down,
    openvpn_no_tls_auth,
    selector_mismatch,
    selector_overlap_local,
    tunnel_down,
    weak_crypto,
)


def ipsec(dev: str = "fw", name: str = "ipsec-a", **kw: Any) -> Tunnel:
    values: dict[str, Any] = {
        "id": object_id(dev, "tunnel", name),
        "device_id": dev,
        "kind": TunnelKind.IPSEC,
        "name": name,
        "description": "site-c",
        "up": True,
        "observed_at": T0,
        "ike_version": 2,
        "remote_gateway": "203.0.113.50",
        "auth": TunnelAuth.CERTIFICATE,
        "proposals": [CryptoProposal(encryption="aes256", integrity="sha256", dh_group=14)],
    }
    return Tunnel(**(values | kw))


def child(local: str, remote: str, **kw: Any) -> TunnelChild:
    return TunnelChild(
        name="c1",
        local_networks=[iface(local).network],
        remote_networks=[iface(remote).network],
        **kw,
    )


def openvpn(role: TunnelRole = TunnelRole.SERVER, **kw: Any) -> Tunnel:
    values: dict[str, Any] = {
        "id": object_id("fw", "tunnel", "ovpn"),
        "device_id": "fw",
        "kind": TunnelKind.OPENVPN,
        "name": "ovpn",
        "observed_at": T0,
        "role": role,
        "protocol": "udp",
        "cipher": "AES-256-GCM",
        "tls_auth": True,
    }
    return Tunnel(**(values | kw))


def subnet(address: str, dev: str) -> Subnet:
    return Subnet(
        id=f"{dev}/subnet/{address}",
        segment_id=segment_id(SITE.id, None),
        interface=iface(address),
        device_id=dev,
        gateway=True,
    )


def network(*tunnels: Tunnel, **kw: Any) -> Network:
    values: dict[str, Any] = {
        "sites": [SITE],
        "devices": [device("fw", name="Router"), device("fw2", name="Branch")],
        "segments": [Segment(id=segment_id(SITE.id, None), site_id=SITE.id)],
        "tunnels": list(tunnels),
    }
    return Network(**(values | kw))


def run(rule: Any, net: Network) -> list[Finding]:
    return [f for f in evaluate(net, [rule]) if f.rule_id == rule.id]


def test_rules_are_registered() -> None:
    assert {r.id for r in RULES} <= {r.id for r in BUILTIN}
    assert len(RULES) == 6


# --- vpn.weak-crypto -----------------------------------------------------------------------


def test_weak_proposals_are_reported() -> None:
    weak = [
        CryptoProposal(encryption="3des", integrity="md5", dh_group=2),
        CryptoProposal(encryption="aes256", integrity="hmac-sha1-96", dh_group=19),
    ]
    (f,) = run(weak_crypto, network(ipsec(proposals=weak)))
    assert f.severity is Severity.WARNING and f.objects == ["fw/tunnel/ipsec-a"]
    assert "3des" in f.message and "md5" in f.message and "DH group 2" in f.message
    assert "sha1" in f.message
    assert "203.0.113.50" not in f.message


def test_strong_proposals_and_unknown_ones_are_quiet() -> None:
    assert not run(weak_crypto, network(ipsec()))
    assert not run(weak_crypto, network(ipsec(proposals=[])))
    gcm = [CryptoProposal(encryption="aes128gcm16", dh_group=19)]
    assert not run(weak_crypto, network(ipsec(proposals=gcm)))
    weak = [CryptoProposal(encryption="3des")]
    assert not run(weak_crypto, network(ipsec(proposals=weak, enabled=False)))


def test_group_14_is_the_default_limit() -> None:
    group5 = [CryptoProposal(dh_group=5)]
    assert run(weak_crypto, network(ipsec(proposals=group5)))
    assert not run(weak_crypto, network(ipsec(proposals=[CryptoProposal(dh_group=14)])))


def test_aggressive_mode_without_certificates() -> None:
    for auth, count in ((TunnelAuth.PSK, 1), (None, 1), (TunnelAuth.CERTIFICATE, 0)):
        found = run(weak_crypto, network(ipsec(ike_version=1, aggressive=True, auth=auth)))
        assert len(found) == count
    assert not run(weak_crypto, network(ipsec(ike_version=1, aggressive=False)))
    assert not run(weak_crypto, network(ipsec(ike_version=2, aggressive=True)))


def test_weak_openvpn_cipher() -> None:
    (f,) = run(weak_crypto, network(openvpn(cipher="AES-256-GCM,BF-CBC")))
    assert "BF-CBC" in f.message and "AES-256-GCM" not in f.message
    assert run(weak_crypto, network(openvpn(cipher="blowfish128,aes256")))
    assert not run(weak_crypto, network(openvpn(cipher="AES-256-GCM:CHACHA20-POLY1305")))
    assert not run(weak_crypto, network(openvpn(cipher=None)))


def test_model_weaknesses() -> None:
    assert CryptoProposal(encryption="3des-cbc", integrity="HMAC-MD5-96").weaknesses() == [
        "encryption:3des",
        "integrity:md5",
    ]
    assert CryptoProposal(dh_group=14).weaknesses(15) == ["dh:14"]
    assert CryptoProposal(encryption="aes256", integrity="sha256", dh_group=19).weaknesses() == []


# --- vpn.tunnel-down -----------------------------------------------------------------------


def test_tunnel_to_a_fixed_gateway_that_is_down() -> None:
    (f,) = run(tunnel_down, network(ipsec(up=False)))
    assert f.severity is Severity.WARNING and "203.0.113.50" not in f.message


def test_tunnel_down_from_children_when_the_state_is_not_known() -> None:
    kids = [child("192.0.2.0/24", "198.51.100.0/24", established=False)]
    assert run(tunnel_down, network(ipsec(up=None, children=kids)))
    ok = [child("192.0.2.0/24", "198.51.100.0/24", established=True)]
    assert not run(tunnel_down, network(ipsec(up=None, children=ok)))
    assert not run(tunnel_down, network(ipsec(up=None, children=[])))


def test_tunnel_down_stays_quiet_for_roadwarrior_and_disabled() -> None:
    assert not run(tunnel_down, network(ipsec(up=False, remote_gateway=None)))
    assert not run(tunnel_down, network(ipsec(up=False, enabled=False)))
    assert not run(tunnel_down, network(ipsec(up=True)))
    assert not run(tunnel_down, network(ipsec(up=False, observed_at=None)))


def test_openvpn_client_down_but_not_the_server() -> None:
    assert run(tunnel_down, network(openvpn(TunnelRole.CLIENT, up=False)))
    assert not run(tunnel_down, network(openvpn(TunnelRole.CLIENT, up=True)))
    assert not run(tunnel_down, network(openvpn(TunnelRole.CLIENT, up=None)))
    assert not run(tunnel_down, network(openvpn(TunnelRole.SERVER, up=False)))


# --- vpn.child-down ------------------------------------------------------------------------


def test_child_not_established_while_the_connection_is_up() -> None:
    kids = [
        child("192.0.2.0/24", "198.51.100.0/24", established=False),
        TunnelChild(name="c2", established=True),
    ]
    (f,) = run(child_down, network(ipsec(children=kids)))
    assert "child c1" in f.message
    assert not run(child_down, network(ipsec(up=False, children=kids)))
    assert not run(child_down, network(ipsec(up=None, children=kids)))
    unknown = [TunnelChild(name="c3", established=None)]
    assert not run(child_down, network(ipsec(children=unknown)))
    disabled = [TunnelChild(name="c4", established=False, enabled=False)]
    assert not run(child_down, network(ipsec(children=disabled)))


# --- vpn.openvpn-no-tls-auth ---------------------------------------------------------------


def test_openvpn_without_tls_auth() -> None:
    (f,) = run(openvpn_no_tls_auth, network(openvpn(tls_auth=False)))
    assert f.severity is Severity.WARNING
    (c,) = run(openvpn_no_tls_auth, network(openvpn(TunnelRole.CLIENT, tls_auth=False)))
    assert c.severity is Severity.INFO
    assert not run(openvpn_no_tls_auth, network(openvpn(tls_auth=True)))
    assert not run(openvpn_no_tls_auth, network(openvpn(tls_auth=None)))
    assert not run(openvpn_no_tls_auth, network(openvpn(tls_auth=False, enabled=False)))


# --- vpn.selector-overlap-local ------------------------------------------------------------


def test_remote_network_overlapping_a_local_one() -> None:
    kids = [child("192.0.2.0/24", "192.0.2.128/25")]
    net = network(ipsec(children=kids), subnets=[subnet("192.0.2.1/24", "fw")])
    (f,) = run(selector_overlap_local, net)
    assert "192.0.2.128/25" in f.message and "192.0.2.0/24" in f.message


def test_no_overlap_cases() -> None:
    far = [child("192.0.2.0/24", "198.51.100.0/24")]
    local = [subnet("192.0.2.1/24", "fw")]
    assert not run(selector_overlap_local, network(ipsec(children=far), subnets=local))
    everything = [child("192.0.2.0/24", "0.0.0.0/0")]
    assert not run(selector_overlap_local, network(ipsec(children=everything), subnets=local))
    clash = [child("192.0.2.0/24", "192.0.2.0/24")]
    assert not run(selector_overlap_local, network(ipsec(children=clash)))  # no local networks
    server = openvpn(pushed_routes=[iface("192.0.2.0/24").network])
    assert not run(selector_overlap_local, network(server, subnets=local))


def test_openvpn_client_route_overlapping_a_local_network() -> None:
    client = openvpn(TunnelRole.CLIENT, pushed_routes=[iface("192.0.2.0/24").network])
    assert run(selector_overlap_local, network(client, subnets=[subnet("192.0.2.1/24", "fw")]))


# --- vpn.selector-mismatch -----------------------------------------------------------------


def ends(a_remote: str = "198.51.100.0/24", b_local: str = "198.51.100.0/24") -> Network:
    a = ipsec("fw", remote_gateway="203.0.113.2", children=[child("192.0.2.0/24", a_remote)])
    b = ipsec("fw2", remote_gateway="203.0.113.1", children=[child(b_local, "192.0.2.0/24")])
    return network(
        a,
        b,
        uplinks=[
            uplink("fw", addresses=[iface("203.0.113.1/24")]),
            uplink("fw2", addresses=[iface("203.0.113.2/24")]),
        ],
    )


def test_mirrored_selectors_are_quiet() -> None:
    assert not run(selector_mismatch, ends())


def test_selectors_that_do_not_mirror() -> None:
    (f,) = run(selector_mismatch, ends(b_local="198.51.100.0/25"))
    assert f.objects == ["fw/tunnel/ipsec-a", "fw2/tunnel/ipsec-a"]
    assert "198.51.100.0/24" in f.message and "203.0.113" not in f.message


def test_mismatch_needs_both_ends() -> None:
    a = ipsec(
        "fw", remote_gateway="203.0.113.2", children=[child("192.0.2.0/24", "198.51.100.0/24")]
    )
    only_one = network(a, uplinks=[uplink("fw2", addresses=[iface("203.0.113.2/24")])])
    assert not run(selector_mismatch, only_one)
    unknown_gateway = ends().model_copy(update={"uplinks": []})
    assert not run(selector_mismatch, unknown_gateway)
    nobody = [t.model_copy(update={"children": []}) for t in ends().tunnels]
    assert not run(selector_mismatch, ends().model_copy(update={"tunnels": nobody}))
