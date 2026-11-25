"""Mesh and wireless backhaul (#171): the model, the merge, the topology and the five checks."""

from typing import Any

import pytest

from factories import SITE, device, port, snapshot
from signalbox.merge import merge
from signalbox.model import (
    Band,
    DeviceRole,
    Link,
    LinkKind,
    LinkOrigin,
    MeshLinkKind,
    MeshMembership,
    MeshPeer,
    MeshPeerRole,
    MeshRole,
    MeshUplink,
    Network,
    PortKind,
    Radio,
    WirelessLinkInfo,
    object_id,
)
from signalbox.rules import Finding, Rule, RuleSettings, Severity, evaluate
from signalbox.rules.mesh_checks import (
    MAX_WIRELESS_HOPS,
    RULES,
    WEAK_RATE_MBPS,
    WEAK_SIGNAL_DBM,
    backhaul_2_4,
    chain_too_long,
    channel_locked,
    weak_backhaul,
    wired_possible,
)
from signalbox.topology import discovered_links, mesh_peer_links

GOOD = {"signal_dbm": -55, "tx_rate_mbps": 866.0, "rx_rate_mbps": 780.0}


def info(**kw: Any) -> WirelessLinkInfo:
    values: dict[str, Any] = {"band": Band.GHZ_5, "channel": 36} | GOOD | kw
    return WirelessLinkInfo(**values)


def mesh_link(up: str, node: str, **kw: Any) -> Link:
    """A backhaul link: ``a`` the upstream node's port, ``b`` the node's uplink port."""
    a, b = f"{up}/port/mesh-{node}", f"{node}/port/uplink"
    return Link(
        id=f"mesh:{a}~{b}",
        a=a,
        b=b,
        kind=LinkKind.WIRELESS,
        origin=LinkOrigin.MESH,
        wireless=info(**kw),
    )


def mesh_net(
    *chain: tuple[str, str],
    radios: tuple[str, ...] = (),
    extra: list[Link] | None = None,
    **kw: Any,
) -> Network:
    """Devices ``gw`` and every node of the (upstream, node) pairs, with their wireless ports
    and links. ``radios``: devices that have a 5 GHz radio. ``kw`` goes to every link."""
    ids = ["gw", *dict.fromkeys(n for _, n in chain)]
    ports = {}
    for up, node in chain:
        for p in (
            port(up, f"mesh-{node}", kind=PortKind.WIRELESS),
            port(node, "uplink", kind=PortKind.WIRELESS),
        ):
            ports[p.id] = p
    snaps = [
        snapshot(
            device(i, DeviceRole.GATEWAY if i == "gw" else DeviceRole.AP),
            ports=[p for p in ports.values() if p.device_id == i],
            radios=[Radio(id=object_id(i, "radio", "r5"), device_id=i, name="r5", band=Band.GHZ_5)]
            if i in radios
            else [],
        )
        for i in ids
    ]
    links = [mesh_link(up, node, **kw) for up, node in chain] + (extra or [])
    return merge([SITE], snaps, links)


def run(r: Rule, net: Network, raw: dict[str, Any] | None = None) -> list[Finding]:
    settings = {k: RuleSettings.model_validate(v) for k, v in (raw or {}).items()}
    return [f for f in evaluate(net, [r], settings) if f.rule_id == r.id]


def test_rules_are_exported() -> None:
    assert [r.id for r in RULES] == [
        "mesh.weak-backhaul",
        "mesh.backhaul-2-4",
        "mesh.chain-too-long",
        "mesh.wired-possible",
        "mesh.channel-locked",
    ]


# model and merge ------------------------------------------------------------------------------


def test_wireless_links_of_a_snapshot_reach_the_network() -> None:
    gw, node = device("gw"), device("r1", DeviceRole.AP, mesh=MeshMembership(role=MeshRole.AGENT))
    link = mesh_link("gw", "r1")
    net = merge(
        [SITE],
        [
            snapshot(gw, ports=[port("gw", "mesh-r1", kind=PortKind.WIRELESS)]),
            snapshot(
                node,
                ports=[port("r1", "uplink", kind=PortKind.WIRELESS)],
                wireless_links=[link, link.model_copy()],
            ),
        ],
    )
    assert [x.id for x in net.links] == [link.id]  # reported twice: once
    assert net.device("r1") is not None and net.device("r1").mesh.role is MeshRole.AGENT  # type: ignore[union-attr]
    assert net.links[0].wireless == link.wireless


def test_a_manual_link_between_the_same_ports_wins() -> None:
    link = mesh_link("gw", "r1")
    manual = Link(id="manual-1", a=link.a, b=link.b, origin=LinkOrigin.MANUAL)
    net = merge(
        [SITE],
        [snapshot(device("gw"), wireless_links=[link])],
        [manual],
    )
    assert [x.id for x in net.links] == ["manual-1"]


# topology -------------------------------------------------------------------------------------


def peer_net(role: MeshPeerRole, mac: str = "02:00:00:00:00:77") -> Network:
    mine = port("r1", "phy1-mesh0", kind=PortKind.WIRELESS)
    theirs = port("gw", "phy0-mesh0", kind=PortKind.WIRELESS, mac="02:00:00:00:00:77")
    peer = MeshPeer(
        id="r1/meshpeer/phy1-mesh0-" + mac,
        device_id="r1",
        port_id=mine.id,
        peer_mac=mac,
        role=role,
        wireless=info(kind=MeshLinkKind.IEEE80211S),
    )
    return merge(
        [SITE],
        [
            snapshot(device("r1", DeviceRole.AP), ports=[mine], mesh_peers=[peer]),
            snapshot(device("gw"), ports=[theirs]),
        ],
    )


@pytest.mark.parametrize(
    ("role", "up", "down"),
    [
        (MeshPeerRole.UPLINK, "gw/port/phy0-mesh0", "r1/port/phy1-mesh0"),
        (MeshPeerRole.DOWNLINK, "r1/port/phy1-mesh0", "gw/port/phy0-mesh0"),
        (MeshPeerRole.PEER, "gw/port/phy0-mesh0", "r1/port/phy1-mesh0"),  # by port id
    ],
)
def test_a_peer_by_mac_becomes_a_mesh_link(role: MeshPeerRole, up: str, down: str) -> None:
    (link,) = mesh_peer_links(peer_net(role))
    assert (link.a, link.b) == (up, down)
    assert (link.kind, link.origin) == (LinkKind.WIRELESS, LinkOrigin.MESH)
    assert link.wireless is not None and link.wireless.kind is MeshLinkKind.IEEE80211S
    assert [x.id for x in discovered_links(peer_net(role))] == [link.id]


def test_a_peer_that_is_no_known_device_is_not_drawn() -> None:
    assert list(mesh_peer_links(peer_net(MeshPeerRole.PEER, mac="02:00:00:00:00:99"))) == []


def test_a_peer_is_found_by_the_bssid_of_an_ssid() -> None:
    net = peer_net(MeshPeerRole.UPLINK, mac="02:00:00:00:00:88")
    ap_port = port("gw", "phy0-ap0", kind=PortKind.WIRELESS)
    wlan = {
        "id": "gw/wlan/x",
        "device_id": "gw",
        "ssid": "x",
        "radio_id": "gw/radio/r",
        "security": "wpa2-psk",
        "bssid": "02:00:00:00:00:88",
        "port_id": ap_port.id,
    }
    from signalbox.model import Wlan

    net = net.model_copy(update={"ports": [*net.ports, ap_port], "wlans": [Wlan(**wlan)]})
    (link,) = mesh_peer_links(net)
    assert (link.a, link.b) == (ap_port.id, "r1/port/phy1-mesh0")


def test_mesh_links_keep_other_discovery_off_their_ports() -> None:
    from signalbox.model import Neighbour

    net = mesh_net(("gw", "r1"))
    lldp = Neighbour(
        id="gw/neighbour/x",
        local_port_id="gw/port/mesh-r1",
        chassis_id="02:00:00:00:00:01",
        system_name="r1",
        wireless=True,
    )
    net = net.model_copy(update={"neighbours": [lldp]})
    assert [x.id for x in discovered_links(net) if x.origin is LinkOrigin.LLDP] == []


# mesh.weak-backhaul ---------------------------------------------------------------------------


def test_weak_signal_is_found() -> None:
    (f,) = run(weak_backhaul, mesh_net(("gw", "r1"), signal_dbm=-80))
    assert f.severity is Severity.WARNING and f.message_id == "mesh.weakBackhaul"
    assert f.params["node"] == "r1" and f.params["parent"] == "gw"
    assert "-80 dBm" in str(f.params["detail"])
    assert f.objects[0] == "r1"


def test_low_rate_is_found_from_the_lower_direction() -> None:
    (f,) = run(weak_backhaul, mesh_net(("gw", "r1"), tx_rate_mbps=500.0, rx_rate_mbps=40.0))
    assert "40 Mbit/s" in str(f.params["detail"])


def test_good_unknown_and_borderline_links_stay_quiet() -> None:
    assert (WEAK_SIGNAL_DBM, WEAK_RATE_MBPS) == (-75, 100)
    assert run(weak_backhaul, mesh_net(("gw", "r1"))) == []
    assert run(weak_backhaul, mesh_net(("gw", "r1"), signal_dbm=-75, rx_rate_mbps=100.0)) == []
    unknown = {"signal_dbm": None, "tx_rate_mbps": None, "rx_rate_mbps": None}
    assert run(weak_backhaul, mesh_net(("gw", "r1"), **unknown)) == []
    assert run(weak_backhaul, mesh_net()) == []


def test_weak_backhaul_thresholds_are_rule_parameters() -> None:
    net = mesh_net(("gw", "r1"), signal_dbm=-80)
    assert run(weak_backhaul, net, {"mesh.weak-backhaul": {"params": {"signal_dbm": -85}}}) == []
    strict = {"mesh.weak-backhaul": {"params": {"signal_dbm": -50}}}
    assert len(run(weak_backhaul, mesh_net(("gw", "r1")), strict)) == 1  # -55 dBm now weak
    by_rate = {"mesh.weak-backhaul": {"params": {"rate_mbps": 900}}}
    assert len(run(weak_backhaul, mesh_net(("gw", "r1")), by_rate)) == 1
    scoped = {
        "mesh.weak-backhaul": {
            "scopes": [{"match": {"device": "r1"}, "params": {"signal_dbm": -90}}]
        }
    }
    assert run(weak_backhaul, net, scoped) == []


# mesh.backhaul-2-4 ----------------------------------------------------------------------------


def test_2_4_ghz_backhaul_with_5_ghz_radios_is_found() -> None:
    net = mesh_net(("gw", "r1"), radios=("gw", "r1"), band=Band.GHZ_2_4, channel=6)
    (f,) = run(backhaul_2_4, net)
    assert f.message_id == "mesh.backhaul24" and f.objects[0] == "r1"


def test_2_4_ghz_backhaul_quiet_without_a_5_ghz_radio_or_on_5_ghz() -> None:
    low = {"band": Band.GHZ_2_4, "channel": 6}
    assert run(backhaul_2_4, mesh_net(("gw", "r1"), radios=("gw",), **low)) == []  # r1 unknown
    assert run(backhaul_2_4, mesh_net(("gw", "r1"), **low)) == []
    assert run(backhaul_2_4, mesh_net(("gw", "r1"), radios=("gw", "r1"))) == []
    assert run(backhaul_2_4, mesh_net(("gw", "r1"), radios=("gw", "r1"), band=None)) == []


# mesh.chain-too-long --------------------------------------------------------------------------


def test_three_wireless_hops_are_too_many() -> None:
    net = mesh_net(("gw", "r1"), ("r1", "r2"), ("r2", "r3"))
    (f,) = run(chain_too_long, net)
    assert f.message_id == "mesh.chainTooLong"
    assert f.params == {"node": "r3", "hops": 3} and f.objects == ["r3"]


def test_two_hops_are_fine_and_the_limit_is_a_parameter() -> None:
    assert MAX_WIRELESS_HOPS == 2
    net = mesh_net(("gw", "r1"), ("r1", "r2"))
    assert run(chain_too_long, net) == []
    assert len(run(chain_too_long, net, {"mesh.chain-too-long": {"params": {"max_hops": 1}}})) == 1


def test_a_reported_hop_count_counts_too() -> None:
    far = device("far", DeviceRole.AP, mesh=MeshMembership(role=MeshRole.REPEATER, hop=4))
    net = merge([SITE], [snapshot(device("gw")), snapshot(far)])
    (f,) = run(chain_too_long, net)
    assert f.params == {"node": "far", "hops": 4}


def test_a_loop_of_links_does_not_hang() -> None:
    net = mesh_net(("r1", "r2"), ("r2", "r1"))
    assert run(chain_too_long, net) == []


# mesh.wired-possible --------------------------------------------------------------------------


def cable(a: str, b: str) -> Link:
    return Link(id=f"c:{a}~{b}", a=a, b=b, origin=LinkOrigin.LLDP)


def test_a_cable_next_to_a_wireless_backhaul_is_found() -> None:
    net = mesh_net(("gw", "r1"), extra=[cable("r1/port/lan1", "sw/port/1")])
    net = net.model_copy(
        update={
            "ports": [*net.ports, port("r1", "lan1"), port("sw", "1")],
            "devices": [*net.devices, device("sw", DeviceRole.SWITCH)],
        }
    )
    (f,) = run(wired_possible, net)
    assert f.severity is Severity.INFO and f.message_id == "mesh.wiredPossible"
    assert f.objects[0] == "r1"


def test_a_node_declared_wireless_with_a_cable_is_found() -> None:
    node = device(
        "r1", DeviceRole.AP, mesh=MeshMembership(role=MeshRole.REPEATER, uplink=MeshUplink.WIRELESS)
    )
    sw = device("sw", DeviceRole.SWITCH)
    net = merge(
        [SITE],
        [snapshot(node, ports=[port("r1", "lan1")]), snapshot(sw, ports=[port("sw", "1")])],
        [cable("r1/port/lan1", "sw/port/1")],
    )
    assert [f.objects for f in run(wired_possible, net)] == [["r1"]]


def test_wired_possible_quiet_without_a_cable_or_with_a_wired_uplink() -> None:
    assert run(wired_possible, mesh_net(("gw", "r1"))) == []
    wired = device(
        "r1", DeviceRole.AP, mesh=MeshMembership(role=MeshRole.AGENT, uplink=MeshUplink.WIRED)
    )
    sw = device("sw", DeviceRole.SWITCH)
    net = merge(
        [SITE],
        [snapshot(wired, ports=[port("r1", "lan1")]), snapshot(sw, ports=[port("sw", "1")])],
        [cable("r1/port/lan1", "sw/port/1")],
    )
    assert run(wired_possible, net) == []
    assert MeshUplink.WIRELESS.value == "wireless"


# mesh.channel-locked --------------------------------------------------------------------------


def test_one_channel_for_a_mesh_of_three_is_reported_once() -> None:
    (f,) = run(channel_locked, mesh_net(("gw", "r1"), ("gw", "r2")))
    assert f.severity is Severity.INFO and f.message_id == "mesh.channelLocked"
    assert f.params == {"nodes": "gw, r1, r2", "channel": 36, "band": "5 GHz"}
    assert len(f.objects) == 2


def test_channel_locked_quiet_for_small_mixed_or_unknown_channels() -> None:
    assert run(channel_locked, mesh_net(("gw", "r1"))) == []  # two nodes
    mixed = mesh_net(("gw", "r1"), ("gw", "r2"))
    other = mesh_link("gw", "r2", channel=40)
    links = [x for x in mixed.links if "r2" not in x.b] + [other]
    assert run(channel_locked, mixed.model_copy(update={"links": links})) == []
    assert run(channel_locked, mesh_net(("gw", "r1"), ("gw", "r2"), channel=None)) == []


# SSID rules skip backhaul SSIDs ----------------------------------------------------------------


def test_backhaul_ssids_are_left_out_of_the_ssid_checks() -> None:
    from signalbox.rules.wifi_roaming import ft_mobility_domain_mismatch
    from test_rules_wifi_roaming import ft_ap

    both = [ft_ap("ap1", "a1b2"), ft_ap("ap2", "c3d4")]
    assert len(run(ft_mobility_domain_mismatch, merge([SITE], both))) == 1
    skipped = [ft_ap("ap1", "a1b2", backhaul=True), ft_ap("ap2", "c3d4", backhaul=True)]
    assert run(ft_mobility_domain_mismatch, merge([SITE], skipped)) == []


def test_topology_marks_weak_backhaul_with_the_rule_parameters() -> None:
    """#459: the topology flags a link the rule would call weak, with the configured limit."""
    from signalbox.topology import view

    net = mesh_net(("gw", "r1"), signal_dbm=-78)
    (edge,) = [e for e in view(net)["edges"] if e["origin"] == "mesh"]
    assert edge["weak"] is True
    ok = mesh_net(("gw", "r1"))
    assert [e["weak"] for e in view(ok)["edges"] if e["origin"] == "mesh"] == [False]
    # a lower limit for this site: the same -78 dBm is no longer weak
    raw = {"mesh.weak-backhaul": {"params": {"signal_dbm": -85}}}
    settings = {k: RuleSettings.model_validate(v) for k, v in raw.items()}
    assert [e["weak"] for e in view(net, settings)["edges"] if e["origin"] == "mesh"] == [False]
    off = {"mesh.weak-backhaul": RuleSettings.model_validate({"enabled": False})}
    assert [e["weak"] for e in view(net, off)["edges"] if e["origin"] == "mesh"] == [False]
