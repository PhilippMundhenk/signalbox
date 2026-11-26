"""WireGuard tunnels in the desired state (#152, ADR 0034): syntax, planner, ownership, the two
steps of a new tunnel, removals, lockout protection, the predicted network and drift. Signalbox
never handles a private or pre-shared key: the model has no field for one, and only public keys
travel from one end's interface to the other end's peer."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from factories import SITE, device, iface, ip
from signalbox.changes import (
    ChangeKind,
    PlanError,
    TunnelPeerValue,
    TunnelValue,
    apply_change,
    changes_for,
    plan,
    predict,
)
from signalbox.deploy import current_value, matches
from signalbox.desired import DesiredError, drift_rules, dump, from_network, parse
from signalbox.model import DeviceStatus, Network, Tunnel, TunnelPeer, object_id
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES


def key(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


HOME_KEY, OFFICE_KEY, ROAMING_KEY = key(1), key(2), key(3)


def net_(text: str) -> Any:
    from ipaddress import ip_network

    return ip_network(text)


def wg(device_id: str, name: str, public_key: str | None = None, **kw: Any) -> Tunnel:
    return Tunnel(
        id=object_id(device_id, "tunnel", name),
        device_id=device_id,
        name=name,
        public_key=public_key,
        **kw,
    )


def network(*tunnels: Tunnel, **kw: Any) -> Network:
    values: dict[str, Any] = {
        "sites": [SITE],
        "devices": [
            device("home-gw", name="Home", management_address="192.0.2.1"),
            device("office-gw", name="Office", management_address="198.51.100.1"),
        ],
        "tunnels": list(tunnels),
    }
    return Network(**(values | kw))


def end(device_id: str, interface: str, **kw: Any) -> str:
    lines = [f"          - device: {device_id}", f"            interface: {interface}"]
    lines += [f"            {k}: {v}" for k, v in kw.items()]
    return "\n".join(lines) + "\n"


HOME = end(
    "home-gw",
    "wg_office",
    listen_port=51820,
    addresses="[203.0.113.253/30]",
    endpoint="203.0.113.10",
    networks="[192.0.2.128/25]",
)
OFFICE = end(
    "office-gw",
    "wg_home",
    listen_port=51821,
    addresses="[203.0.113.254/30]",
    networks="[198.51.100.128/25]",
    keepalive=25,
)


def text(home: str = HOME, office: str = OFFICE, name: str = "office") -> str:
    return f"sites:\n  home:\n    tunnels:\n      - name: {name}\n        ends:\n{home}{office}"


def built() -> Network:
    """Both interfaces exist (created by Signalbox, tagged), keys generated on the devices."""
    return network(
        wg(
            "home-gw",
            "wg_office",
            HOME_KEY,
            signalbox_key="office",
            listen_port=51820,
            addresses=[iface("203.0.113.253/30")],
        ),
        wg(
            "office-gw",
            "wg_home",
            OFFICE_KEY,
            signalbox_key="office",
            listen_port=51821,
            addresses=[iface("203.0.113.254/30")],
        ),
    )


# --- syntax -------------------------------------------------------------------------------------


def test_syntax_round_trips() -> None:
    state = parse(text())
    [t] = state.sites["home"].tunnels
    a, b = t.ends
    assert (t.name, a.device, a.interface, a.listen_port) == (
        "office",
        "home-gw",
        "wg_office",
        51820,
    )
    assert a.endpoint_parts() == ("203.0.113.10", 51820)
    assert b.endpoint_parts() == (None, None) and b.keepalive == 25
    assert parse(dump(state)) == state


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (text(office=end("home-gw", "wg_other")), "different devices"),
        (text(home=end("home-gw", "wg_office", endpoint="203.0.113.10")), "needs a port"),
        (text(home=end("home-gw", "wg_office", endpoint="'203.0.113.10:99999'")), "port"),
        (text(home=end("home-gw", "wg_office", private_key="x")), "private_key"),
        (text(home=end("home-gw", "wg_office", preshared_key="x")), "preshared_key"),
        (text(home=end("home-gw", "this-name-is-too-long")), "interface"),
        (
            "sites:\n  home:\n    tunnels:\n      - name: x\n        ends:\n" + HOME,
            "ends",
        ),
    ],
)
def test_wrong_tunnels_are_refused(body: str, message: str) -> None:
    with pytest.raises(DesiredError, match=message):
        parse(body)


def test_endpoint_forms() -> None:
    state = parse(
        text(
            home=end("home-gw", "wg_office", endpoint="vpn.example.org:51000"),
            office=end("office-gw", "wg_home", endpoint="'[2001:db8::1]:51001'"),
        )
    )
    a, b = state.sites["home"].tunnels[0].ends
    assert a.endpoint_parts() == ("vpn.example.org", 51000)
    assert b.endpoint_parts() == ("2001:db8::1", 51001)


def test_a_tunnel_and_an_interface_are_declared_once() -> None:
    a = parse(text())
    with pytest.raises(DesiredError, match="tunnel declared twice: office"):
        parse(dump(a.merged(parse(text()))))
    other = parse(text(name="other"))
    with pytest.raises(DesiredError, match="interface declared twice: home-gw/wg_office"):
        parse(dump(a.merged(other)))


# --- planner: a new tunnel in two steps ---------------------------------------------------------


def test_a_new_tunnel_creates_both_interfaces_and_waits_for_the_keys() -> None:
    p = plan(parse(text()), network(), RULES)
    assert [(c.kind, c.device_id, c.key, c.action) for c in p.changes] == [
        (ChangeKind.TUNNEL, "home-gw", "tunnel/office", "create"),
        (ChangeKind.TUNNEL, "office-gw", "tunnel/office", "create"),
    ]
    assert p.changes[0].new == TunnelValue(
        interface="wg_office", listen_port=51820, addresses=[iface("203.0.113.253/30")]
    )
    assert len(p.pending) == 2
    assert "waits for the public key of wg_home on office-gw" in p.pending[0]
    assert p.lockouts == []


def test_the_second_step_gives_each_side_the_other_sides_public_key() -> None:
    changes = changes_for(parse(text()), built())
    peers = {c.device_id: c.new for c in changes if c.kind is ChangeKind.TUNNEL_PEER}
    assert [c.kind for c in changes] == [ChangeKind.TUNNEL_PEER, ChangeKind.TUNNEL_PEER]
    assert peers["home-gw"] == TunnelPeerValue(
        interface="wg_office",
        public_key=OFFICE_KEY,
        allowed_ips=[net_("198.51.100.128/25"), net_("203.0.113.254/32")],
    )
    assert peers["office-gw"] == TunnelPeerValue(
        interface="wg_home",
        public_key=HOME_KEY,
        endpoint_host="203.0.113.10",
        endpoint_port=51820,
        allowed_ips=[net_("192.0.2.128/25"), net_("203.0.113.253/32")],
        keepalive=25,
    )
    p = plan(parse(text()), built(), RULES)
    assert p.pending == [] and p.lockouts == []


def test_one_end_existing_gets_its_peer_at_once() -> None:
    only_office = network(built().tunnels[1])
    p = plan(parse(text()), only_office, RULES)
    assert [(c.kind, c.device_id, c.action) for c in p.changes] == [
        (ChangeKind.TUNNEL, "home-gw", "create"),
        (ChangeKind.TUNNEL_PEER, "home-gw", "create"),
    ]
    assert isinstance(p.changes[1].new, TunnelPeerValue)
    assert p.changes[1].new.public_key == OFFICE_KEY
    [waiting] = p.pending
    assert waiting.startswith("office-gw: the peer of tunnel office waits")


def test_a_converged_tunnel_plans_nothing() -> None:
    done = predict(built(), changes_for(parse(text()), built()))
    assert changes_for(parse(text()), done) == []
    assert not [f for f in evaluate(done, drift_rules(parse(text()))) if f.problem]


def test_an_undeclared_endpoint_is_not_compared() -> None:
    peers = [
        TunnelPeer(
            public_key=HOME_KEY,
            signalbox_key="office",
            endpoint_host="203.0.113.10",  # where the peer was last seen
            endpoint_port=51820,
            allowed_ips=[net_("192.0.2.128/25"), net_("203.0.113.253/32")],
            keepalive_seconds=25,
        )
    ]
    office = built().tunnels[1].model_copy(update={"peers": peers})
    seen = network(built().tunnels[0], office)
    state = parse(text(home=HOME.replace("            endpoint: 203.0.113.10\n", "")))
    assert [c for c in changes_for(state, seen) if c.device_id == "office-gw"] == []


# --- ownership ----------------------------------------------------------------------------------


def test_the_devices_own_interface_needs_adopt() -> None:
    own = network(wg("home-gw", "wg_office", HOME_KEY, listen_port=51820))
    with pytest.raises(PlanError, match="adopt: true") as exc:
        changes_for(parse(text()), own)
    assert exc.value.message_id == "plan.tunnelAdopt"
    found = [f for f in evaluate(own, drift_rules(parse(text()))) if f.rule_id == "drift.tunnel"]
    assert found  # drift still compares it


def test_an_adopted_interface_keeps_its_other_peers() -> None:
    roaming = TunnelPeer(public_key=ROAMING_KEY, name="phone", allowed_ips=[net_("192.0.2.200/32")])
    old_office = TunnelPeer(public_key=OFFICE_KEY, allowed_ips=[net_("198.51.100.0/24")])
    home = wg(
        "home-gw",
        "wg_office",
        HOME_KEY,
        listen_port=51820,
        addresses=[iface("203.0.113.253/30")],
        peers=[roaming, old_office],
    )
    current = network(home, built().tunnels[1])
    adopted = HOME + "            adopt: true\n"
    changes = changes_for(parse(text(home=adopted)), current)
    [peer] = [c for c in changes if c.device_id == "home-gw"]
    assert (peer.kind, peer.adopt, peer.action) == (ChangeKind.TUNNEL_PEER, "wg_office", "update")
    assert isinstance(peer.old, TunnelPeerValue) and peer.old.public_key == OFFICE_KEY
    after = apply_change(current, peer)
    [t] = after.tunnels_of("home-gw")
    assert [p.public_key for p in t.peers] == [ROAMING_KEY, OFFICE_KEY]
    assert t.peers[0] == roaming
    assert t.peers[1].signalbox_key == "office"


def test_a_renamed_interface_is_refused() -> None:
    moved = network(wg("home-gw", "wg_old", HOME_KEY, signalbox_key="office"))
    with pytest.raises(PlanError) as exc:
        changes_for(parse(text()), moved)
    assert exc.value.message_id == "plan.tunnelRename"


def test_tunnels_that_are_no_longer_declared_are_removed() -> None:
    gone = (
        built()
        .tunnels[0]
        .model_copy(update={"peers": [TunnelPeer(public_key=OFFICE_KEY, signalbox_key="office")]})
    )
    own = wg("home-gw", "wg_own", ROAMING_KEY)
    current = network(gone, own)
    changes = changes_for(parse("sites:\n  home: {}\n"), current)
    assert [(c.kind, c.device_id, c.action) for c in changes] == [
        (ChangeKind.TUNNEL_PEER, "home-gw", "remove"),
        (ChangeKind.TUNNEL, "home-gw", "remove"),
    ]
    after = predict(current, changes)
    assert [t.name for t in after.tunnels] == ["wg_own"]
    # a site that is not declared at all is not touched
    assert changes_for(parse("sites:\n  other: {}\n"), current) == []


# --- lockout ------------------------------------------------------------------------------------


def test_a_peer_that_carries_management_traffic_needs_the_override() -> None:
    wide = OFFICE.replace("198.51.100.128/25", "198.51.100.0/24")
    p = plan(parse(text(office=wide)), built(), RULES)
    [cut] = p.lockouts
    assert cut.startswith("Home: the tunnel-peer change of tunnel office")
    assert "Office (198.51.100.1)" in cut


def test_signalbox_own_address_counts_too() -> None:
    p = plan(parse(text()), built(), RULES, signalbox_address=ip("192.0.2.130"))
    assert [x for x in p.lockouts if "Signalbox (192.0.2.130)" in x]


def test_removing_a_tunnel_that_carries_a_device_is_a_lockout() -> None:
    peer = TunnelPeer(
        public_key=OFFICE_KEY, signalbox_key="office", allowed_ips=[net_("198.51.100.0/24")]
    )
    current = network(built().tunnels[0].model_copy(update={"peers": [peer]}))
    p = plan(parse("sites:\n  home: {}\n"), current, RULES)
    assert p.lockouts and all("Office (198.51.100.1)" in x for x in p.lockouts)


# --- predicted network, verification ------------------------------------------------------------


def test_the_predicted_network_and_the_verification_agree() -> None:
    current = built()
    for c in changes_for(parse(text()), current):
        after = apply_change(current, c)
        assert current_value(after, c) == c.new
        assert matches(after, c, c.new, {})
        assert matches(current, c, c.old, {})


def test_a_created_interface_is_verified_without_a_key() -> None:
    [c, _] = changes_for(parse(text()), network())
    after = apply_change(network(), c)
    [t] = after.tunnels_of("home-gw")
    assert t.public_key is None and t.signalbox_key == "office"
    assert matches(after, c, c.new, {})


# --- drift and import ---------------------------------------------------------------------------


def drift(state: str, net: Network) -> list[str]:
    return sorted(
        f.message for f in evaluate(net, drift_rules(parse(state))) if f.rule_id == "drift.tunnel"
    )


def test_drift_reports_missing_interfaces_and_waiting_peers() -> None:
    assert drift(text(), network()) == [
        "Tunnel office on home-gw: the interface is missing",
        "Tunnel office on home-gw: the peer is missing; it waits for the other end's public key",
        "Tunnel office on office-gw: the interface is missing",
        "Tunnel office on office-gw: the peer is missing; it waits for the other end's public key",
    ]


def test_drift_names_differing_fields() -> None:
    done = predict(built(), changes_for(parse(text()), built()))
    changed = text(home=HOME.replace("51820", "51900"))
    found = drift(changed, done)
    assert "Tunnel office on home-gw: interface: listen port: should be 51900, is 51820" in found
    assert any(
        "Tunnel office on office-gw: peer: endpoint port: should be 51900" in f for f in found
    )


def test_unread_devices_are_incomplete() -> None:
    down = built().model_copy(update={"statuses": {"office-gw": DeviceStatus.UNREACHABLE}})
    [f] = [f for f in evaluate(down, drift_rules(parse(text()))) if f.rule_id == "drift.tunnel"]
    assert f.incomplete and not f.problem


def test_import_writes_no_tunnels() -> None:
    assert from_network(built(), "home").sites["home"].tunnels == []


# --- keys ---------------------------------------------------------------------------------------


def test_no_value_or_spec_has_a_field_for_a_private_or_preshared_key() -> None:
    from signalbox.desired import TunnelEndSpec, TunnelSpec

    for model in (TunnelValue, TunnelPeerValue, TunnelEndSpec, TunnelSpec, Tunnel, TunnelPeer):
        fields = set(model.model_fields)
        assert not {f for f in fields if "private" in f}
        assert "preshared_key" not in fields or model is TunnelPeer  # TunnelPeer: a flag only
