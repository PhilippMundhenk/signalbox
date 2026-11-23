"""VPN tunnels (#239): model, merge, site links in the topology, contract checks, recordings."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from factories import SITE, T0, device, peer, port, site_link, snapshot, tunnel, wg_key
from signalbox.adapters import (
    Adapter,
    AdapterContext,
    Capability,
    Manifest,
    Observation,
    SystemInfo,
)
from signalbox.adapters import AdapterConfig as _Config
from signalbox.merge import merge
from signalbox.model import (
    WIREGUARD_KEY,
    DeviceRole,
    LinkKind,
    LinkOrigin,
    Network,
    Site,
    Snapshot,
    TunnelPeer,
)
from signalbox.recording import Neutraliser
from signalbox.rules import evaluate
from signalbox.rules.builtin import RULES
from signalbox.testing import problems, secret_problems
from signalbox.topology import discovered_links, remote_id, tunnel_links, view

AWAY = Site(id="away", name="Away")


def two_sites(one_sided: bool = False) -> Network:
    a, b = site_link()
    if one_sided:
        b = b.model_copy(update={"peers": []})
    snaps = [
        snapshot(device("fw"), tunnels=[a]),
        snapshot(device("pi", site_id=AWAY.id), tunnels=[b]),
    ]
    net = merge([SITE, AWAY], snaps)
    return merge([SITE, AWAY], snaps, discovered_links(net))


# --- model ---------------------------------------------------------------------------------


def test_keys_must_look_like_wireguard_keys() -> None:
    assert re.fullmatch(WIREGUARD_KEY, wg_key("x"))
    for bad in ("", "short=", wg_key("x")[:-2] + "B=", "x" * 44):
        with pytest.raises(ValidationError):
            TunnelPeer(public_key=bad)


def test_private_key_fields_do_not_exist() -> None:
    with pytest.raises(ValidationError):
        tunnel("fw", private_key=wg_key("secret"))
    with pytest.raises(ValidationError):
        TunnelPeer(public_key=wg_key("p"), preshared_key_value=wg_key("psk"))  # type: ignore[call-arg]


def test_remote_networks_leave_out_the_tunnel_transit() -> None:
    a, _ = site_link()
    (p,) = a.peers
    assert [str(n) for n in a.remote_networks(p)] == ["198.51.100.0/24"]
    phone = peer("phone", "2001:db8:ff::3/128")
    full = peer("vpn-provider", "0.0.0.0/0", "::/0")
    t = a.model_copy(update={"peers": [p, phone, full]})
    assert t.remote_networks(phone) == []
    assert [str(n) for n in t.remote_networks(full)] == ["0.0.0.0/0", "::/0"]
    assert [x.name for x in t.site_peers()] == ["pi", "vpn-provider"]
    assert t.peer(wg_key("phone")) is phone and t.peer(wg_key("nobody")) is None


def test_host_routes_are_no_remote_networks() -> None:
    """FreeBSD reports the tunnel address as /128: the peer's own address is still transit."""
    t = tunnel(
        "fw",
        peer("pi", "2001:db8:ff::2/128", "2001:db8:20::/64", "192.0.2.9/32"),
        addresses=["2001:db8:ff::1/128"],
    )
    assert [str(n) for n in t.remote_networks(t.peers[0])] == ["2001:db8:20::/64"]


def test_handshake_age_and_naive_times() -> None:
    p = peer("x", latest_handshake=T0.replace(tzinfo=None))
    assert p.latest_handshake == T0
    assert p.handshake_age(T0 + timedelta(seconds=90)) == 90
    assert peer("y").handshake_age(T0) is None


def test_tunnel_ends_match_both_ways_across_sites() -> None:
    net = two_sites()
    fw, pi = net.tunnel("fw/tunnel/wg0"), net.tunnel("pi/tunnel/wg0")
    assert fw is not None and pi is not None
    assert net.tunnel_end(fw, fw.peers[0]) is pi
    assert net.tunnel_end(pi, pi.peers[0]) is fw
    assert net.remote_sites() == []
    assert [t.id for t in net.tunnels_of("pi")] == ["pi/tunnel/wg0"]
    assert net.knows("fw/tunnel/wg0")
    (link,) = net.links
    assert (link.a, link.b, link.kind, link.origin) == (
        "fw/tunnel/wg0",
        "pi/tunnel/wg0",
        LinkKind.VPN,
        LinkOrigin.TUNNEL,
    )
    assert link.id == "tunnel:fw/tunnel/wg0~pi/tunnel/wg0"


def test_one_sided_peer_is_a_remote_site() -> None:
    net = two_sites(one_sided=True)
    fw = net.tunnel("fw/tunnel/wg0")
    assert fw is not None
    assert net.tunnel_end(fw, fw.peers[0]) is None  # the Pi does not name the firewall
    assert net.tunnel_with_key(wg_key("pi")) is net.tunnel("pi/tunnel/wg0")
    assert net.links == []
    assert [(t.id, p.name) for t, p in net.remote_sites()] == [("fw/tunnel/wg0", "pi")]


def test_tunnel_without_public_key_has_no_end() -> None:
    a, b = site_link()
    net = merge(
        [SITE],
        [
            snapshot(device("fw"), tunnels=[a.model_copy(update={"public_key": None})]),
            snapshot(device("pi"), tunnels=[b]),
        ],
    )
    assert list(tunnel_links(net)) == []


# --- topology view -------------------------------------------------------------------------


def test_view_has_the_vpn_edge_with_both_ends() -> None:
    net = two_sites()
    data = view(net)
    (edge,) = data["edges"]
    assert edge["kind"] == "vpn" and edge["origin"] == "tunnel"
    assert edge["a"]["device_id"] == "fw" and edge["a"]["port"] == "wg0" and edge["a"]["tunnel"]
    assert edge["b"]["device_id"] == "pi"
    assert edge["vpn"]["a"]["networks"] == ["198.51.100.0/24"]
    assert edge["vpn"]["b"]["networks"] == ["192.0.2.0/24"]
    assert edge["vpn"]["a"]["handshake_age"] == 30
    assert data["remotes"] == []


def test_view_shows_an_unmanaged_remote_site() -> None:
    a, _ = site_link()
    phone = peer("phone", "2001:db8:ff::3/128")
    t = a.model_copy(update={"peers": [*a.peers, phone]})
    net = merge([SITE], [snapshot(device("fw"), tunnels=[t])])
    data = view(net)
    (remote,) = data["remotes"]  # the phone routes no network: no site
    assert remote["id"] == remote_id(t, a.peers[0]) and remote["networks"] == ["198.51.100.0/24"]
    assert (remote["name"], remote["site_id"], remote["tunnel_id"]) == ("pi", "home", t.id)
    (edge,) = data["edges"]
    assert edge["b"]["remote"] and edge["b"]["device_id"] == remote["id"]
    assert edge["vpn"]["b"] is None


def test_unnamed_remote_site_is_named_after_the_tunnel() -> None:
    t = tunnel("fw", peer("x", "198.51.100.0/24", label=None), description="s2s")
    net = merge([SITE], [snapshot(device("fw"), tunnels=[t])])
    assert view(net)["remotes"][0]["name"] == "behind s2s"


def test_vpn_links_cause_no_findings() -> None:
    """Link rules work on ports: a link between tunnels must not confuse them."""
    net = two_sites()
    for result in evaluate(net, RULES):
        assert not any("tunnel" in o for o in result.objects), result


def test_discovered_links_keep_cables_and_add_tunnels() -> None:
    net = two_sites()
    assert [link.kind for link in discovered_links(net)] == [LinkKind.VPN]


# --- contract ------------------------------------------------------------------------------


class _Cfg(_Config):
    pass


class _Vpn(Adapter):
    manifest = Manifest(
        id="vpntest",
        name="VPN test",
        version="0",
        api_version="1.3",
        vendor="test",
        roles=frozenset({DeviceRole.GATEWAY}),
        capabilities=frozenset({Capability.VPN, Capability.INTERFACES}),
        config=_Cfg,
    )
    tunnels: list[Any] = []

    async def read_system(self) -> SystemInfo:
        return SystemInfo()

    async def read_interfaces(self) -> Observation:
        return Observation(ports=[port("gw", "wg0")])

    async def read_vpn(self) -> Observation:
        return Observation(tunnels=self.tunnels)


def _adapter() -> _Vpn:
    return _Vpn(
        AdapterContext(
            site_id="home",
            device_id="gw",
            device_name="gw",
            role=DeviceRole.GATEWAY,
            config=_Cfg(),
        )
    )


async def _problems(*tunnels: Any) -> list[str]:
    a = _adapter()
    a.tunnels = list(tunnels)
    return problems(a, await a.observe())


async def test_contract_accepts_a_good_tunnel() -> None:
    t = tunnel("gw", peer("pi", "198.51.100.0/24"), port_id="gw/port/wg0")
    assert await _problems(t) == []


async def test_contract_refuses_broken_tunnels() -> None:
    good = tunnel("gw", peer("pi", "198.51.100.0/24"))
    found = await _problems(
        good.model_copy(update={"id": "gw/tunnel/other"}),
        tunnel("gw", name="wg1", port_id="gw/port/wg1"),
        tunnel("gw", peer("a"), peer("a"), name="wg2"),
        tunnel("gw", peer("self", public_key=wg_key("gw")), name="wg3"),
        tunnel("gw", peer("e", endpoint_port=51820), name="wg4"),
        tunnel("gw", peer("e"), name="wg5"),
        tunnel("gw", peer("e"), name="wg5"),
    )
    text = "\n".join(found)
    assert "gw/tunnel/other is not gw/tunnel/wg0" in text
    assert "on unknown port gw/port/wg1" in text
    assert "lists a peer twice" in text
    assert "has itself as a peer" in text
    assert "endpoint port without host" in text
    assert "tunnel gw/tunnel/wg5 reported twice" in text


def test_tunnels_need_the_vpn_capability() -> None:
    class NoVpn(_Vpn):
        manifest = _Vpn.manifest.model_copy(
            update={"capabilities": frozenset({Capability.INTERFACES})}
        )

    a = NoVpn(_adapter().context)
    dev = device("gw", capabilities=["interfaces"], adapter="vpntest")
    snap = snapshot(dev, tunnels=[tunnel("gw")])
    assert "tunnels reported without declaring vpn" in problems(a, snap)


def test_no_private_keys_in_vendor_extra() -> None:
    t = tunnel(
        "gw",
        peer("pi"),
        vendor_extra={"privkey": "x", "nested": [{"note": f"key {wg_key('leak')}"}]},
    )
    ok = tunnel("gw", peer("pi"), name="wg1", vendor_extra={"peer": wg_key("pi")})
    found = secret_problems(snapshot(device("gw"), tunnels=[t, ok]))
    assert found == [
        "gw/tunnel/wg0: vendor_extra field 'privkey' looks like a secret",
        "gw/tunnel/wg0: vendor_extra holds a key that is no public key of the snapshot",
    ]
    dev = device("gw", vendor_extra={"preshared_key": "x"})
    assert secret_problems(Snapshot(device=dev, observed_at=T0)) == [
        "gw: vendor_extra field 'preshared_key' looks like a secret"
    ]


# --- recordings ----------------------------------------------------------------------------


def test_recordings_replace_keys_consistently() -> None:
    n = Neutraliser()
    key, other = wg_key("real"), wg_key("other")
    first = n.addresses(f"if wg0 {key} peer {other}")
    again = n.addresses(key)
    assert key not in first and other not in first
    new = first.split()[2]
    assert re.fullmatch(WIREGUARD_KEY, new) and again == new
    assert n.addresses(new) == new  # a placeholder stays
    assert n.field("privkey", key).startswith("redacted-secret-")
    assert n.field("preshared-key", "abc").startswith("redacted-secret-")


def test_network_json_adds_networks_other_end_and_age() -> None:
    from signalbox.web.app import public_network

    data = public_network(two_sites())
    fw = next(t for t in data["tunnels"] if t["device_id"] == "fw")
    (p,) = fw["peers"]
    assert (p["networks"], p["other_end"], p["handshake_age"]) == (
        ["198.51.100.0/24"],
        "pi/tunnel/wg0",
        30,
    )
