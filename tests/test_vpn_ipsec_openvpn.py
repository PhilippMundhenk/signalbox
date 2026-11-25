"""IPsec and OpenVPN tunnels (#153): the readers of OPNsense, MikroTik and OpenWrt against their
simulators, the parsers, and that no secret reaches the model."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, ipsec
from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
from signalbox.adapters.mikrotik import vpn as mikrotik_vpn
from signalbox.adapters.openwrt import OpenWrtAdapter, OpenWrtConfig
from signalbox.adapters.openwrt import openvpn as openwrt_openvpn
from signalbox.adapters.opnsense import OpnsenseAdapter, OpnsenseConfig
from signalbox.adapters.opnsense import vpn as opnsense_vpn
from signalbox.model import (
    DeviceRole,
    Snapshot,
    Tunnel,
    TunnelAuth,
    TunnelKind,
    TunnelRole,
)
from signalbox.sim.mikrotik import IPSEC_SECRET as MK_SECRET
from signalbox.sim.mikrotik import PASSWORD as MK_PASSWORD
from signalbox.sim.mikrotik import MikrotikSimulator
from signalbox.sim.mikrotik import vpn_data as mikrotik_data
from signalbox.sim.openwrt import OPENVPN_SECRET, OpenWrtSim, create_app
from signalbox.sim.opnsense import IPSEC_PSK, KEY, SECRET, OpnsenseSimulator
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve
from signalbox.testing import SIM_SECRET_MARKER, assert_contract

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)

# --- shared parsers -----------------------------------------------------------------------


def test_strongswan_proposals() -> None:
    p = ipsec.proposal("aes256-sha256-modp2048")
    assert p is not None and (p.encryption, p.integrity, p.dh_group) == ("aes256", "sha256", 14)
    p = ipsec.proposal("3des-md5-modp1024")
    assert p is not None and p.weaknesses() == ["encryption:3des", "integrity:md5", "dh:2"]
    p = ipsec.proposal("aes128gcm16-prfsha256-ecp256")
    assert p is not None and (p.encryption, p.integrity, p.dh_group) == ("aes128gcm16", None, 19)
    assert ipsec.proposal("default") is None
    assert len(ipsec.proposals("aes256-sha256,aes256-sha256,aes128-sha1")) == 2


def test_routeros_algorithm_lists_become_one_entry_each() -> None:
    parts = ipsec.parts(["aes-256", "3des"], ["sha1"], ["modp1024", "ecp256", "none"])
    assert [(p.encryption, p.integrity, p.dh_group) for p in parts] == [
        ("aes-256", None, None),
        ("3des", None, None),
        (None, "sha1", None),
        (None, None, 2),
        (None, None, 19),
    ]


def test_networks_and_gateways() -> None:
    assert [str(n) for n in ipsec.networks("192.0.2.0/24, 198.51.100.0/24;dynamic")] == [
        "192.0.2.0/24",
        "198.51.100.0/24",
    ]
    assert ipsec.gateway("203.0.113.5") == "203.0.113.5"
    assert ipsec.gateway("%any") is None and ipsec.gateway("") is None
    assert ipsec.gateway("0.0.0.0/0") is None


# --- OPNsense ------------------------------------------------------------------------------

OPN = OpnsenseSimulator()


@pytest.fixture(scope="module")
def opn_url() -> Iterator[str]:
    with serve(OPN.app()) as url:
        yield url


@pytest.fixture
def opn() -> OpnsenseSimulator:
    OPN.__dict__.update(OpnsenseSimulator(vpn=True).__dict__)
    return OPN


def opn_adapter(url: str) -> OpnsenseAdapter:
    return OpnsenseAdapter(
        AdapterContext(
            site_id="home",
            device_id="fw",
            device_name="Firewall",
            role=DeviceRole.GATEWAY,
            config=OpnsenseConfig(
                url=url,
                api_key=SecretStr(KEY),
                api_secret=SecretStr(SECRET),
                allow_insecure_http=True,
            ),
            timeout=5.0,
        )
    )


async def opn_observe(url: str) -> Snapshot:
    a = opn_adapter(url)
    try:
        return await a.observe()
    finally:
        await a.close()


def by_name(snap: Snapshot) -> dict[str, Tunnel]:
    return {t.description or t.name: t for t in snap.tunnels}


async def test_opnsense_ipsec_connection(opn_url: str, opn: OpnsenseSimulator) -> None:
    snap = await opn_observe(opn_url)
    t = by_name(snap)["site-c"]
    assert t.kind is TunnelKind.IPSEC and t.id == "fw/tunnel/ipsec-7f1c2a10"
    assert (t.up, t.enabled, t.ike_version, t.aggressive) == (True, True, 2, False)
    assert (t.auth, t.remote_gateway, t.dpd) == (TunnelAuth.PSK, "203.0.113.50", True)
    assert [(p.encryption, p.integrity, p.dh_group) for p in t.proposals] == [
        ("aes256", "sha256", 14)
    ]
    (c,) = t.children
    assert c.name == "lan-to-site-c" and c.established is True and c.rekey_seconds == 3600
    assert [str(n) for n in c.local_networks] == ["192.0.2.0/24"]
    assert [str(n) for n in c.remote_networks] == ["198.18.99.0/24"]
    assert c.last_rekey is not None
    assert [str(n) for n in t.all_remote_networks()] == ["198.18.99.0/24"]


async def test_opnsense_openvpn_instances(opn_url: str, opn: OpnsenseSimulator) -> None:
    snap = await opn_observe(opn_url)
    server = by_name(snap)["road-warrior"]
    assert server.kind is TunnelKind.OPENVPN and server.role is TunnelRole.SERVER
    assert (server.protocol, server.listen_port, server.tls_auth) == ("udp", 1194, True)
    assert str(server.tunnel_network) == "198.18.77.0/24"
    assert server.cipher == "AES-256-GCM,AES-128-GCM"
    assert [str(n) for n in server.pushed_routes] == ["192.0.2.0/24"]
    assert server.sessions is not None
    (s,) = server.sessions
    assert s.common_name == "laptop" and str(s.virtual_address) == "198.18.77.2"
    assert s.connected_since == datetime(2026, 11, 22, 8, 0, tzinfo=UTC)
    client = by_name(snap)["to-provider"]
    assert (client.role, client.up, client.protocol) == (TunnelRole.CLIENT, True, "tcp")
    assert client.listen_port is None and client.remote_gateway == "203.0.113.60"


async def test_opnsense_vpn_secrets_never_leave(opn_url: str, opn: OpnsenseSimulator) -> None:
    assert IPSEC_PSK in str(opn.data) and SIM_SECRET_MARKER in IPSEC_PSK
    a = opn_adapter(opn_url)
    try:
        snap = await assert_contract(a)
        assert IPSEC_PSK not in snap.model_dump_json()
        assert not any(IPSEC_PSK in path for path in opn.requests)
    finally:
        await a.close()


async def test_opnsense_without_the_vpn_api(opn_url: str, opn: OpnsenseSimulator) -> None:
    for path in [p for p in opn.data if p.startswith(("/api/ipsec", "/api/openvpn"))]:
        del opn.data[path]
    snap = await opn_observe(opn_url)
    assert [t.kind for t in snap.tunnels] == [TunnelKind.WIREGUARD]
    assert not [e for e in snap.errors if e.capability == "vpn"]


async def test_opnsense_privilege_gap_is_optional(opn_url: str, opn: OpnsenseSimulator) -> None:
    from signalbox.sim.opnsense import INTERFACES

    opn.data[INTERFACES]["rows"].append({"device": "ovpns1", "status": "up", "ipv4": []})
    opn.fail["/api/ipsec/connections/search_connection"] = 403
    opn.fail["/api/openvpn/service/search_sessions"] = 403
    snap = await opn_observe(opn_url)
    gaps = [e for e in snap.errors if e.capability == "vpn"]
    assert [g.params["what"] for g in gaps] == ["OpenVPN sessions"] and gaps[0].optional
    kinds = {t.kind for t in snap.tunnels}
    assert TunnelKind.IPSEC not in kinds and TunnelKind.OPENVPN in kinds
    openvpn = by_name(snap)["to-provider"]
    assert openvpn.up is None  # sessions not readable: unknown, not down


async def test_opnsense_refused_vpn_without_a_trace_is_no_gap(
    opn_url: str, opn: OpnsenseSimulator
) -> None:
    """The user of the automatic setup has no VPN privilege: that is no gap on every firewall."""
    opn.fail["/api/ipsec/connections/search_connection"] = 403
    opn.fail["/api/openvpn/instances/search"] = 403
    snap = await opn_observe(opn_url)
    assert [t.kind for t in snap.tunnels] == [TunnelKind.WIREGUARD]
    assert not [e for e in snap.errors if e.capability == "vpn"]


async def test_opnsense_sessions_unreadable_leave_the_state_unknown(
    opn_url: str, opn: OpnsenseSimulator
) -> None:
    opn.fail["/api/ipsec/sessions/search_phase1"] = 403
    t = by_name(await opn_observe(opn_url))["site-c"]
    assert t.up is None and [c.established for c in t.children] == [None]


def test_opnsense_parsers_are_defensive() -> None:
    rows = [{"uuid": "abcdef012345", "enabled": "1", "version": "0", "remote_addrs": "%any"}]
    (t,) = opnsense_vpn.ipsec_tunnels("fw", rows, [], [], [], [], NOW)
    assert (t.ike_version, t.remote_gateway, t.up, t.children, t.dpd) == (
        None,
        None,
        False,
        [],
        None,
    )
    (c,) = opnsense_vpn.ipsec_tunnels(
        "fw",
        [{"uuid": "u1", "version": "IKEv1", "aggressive": "1", "dpd_delay": "0"}],
        [{"connection": "u1", "uuid": "k1", "enabled": "1", "rekey_time": "1h"}],
        [{"connection": "u1", "auth": "eap-mschapv2"}],
        None,
        None,
        NOW,
    )
    assert (c.ike_version, c.aggressive, c.auth, c.up, c.dpd) == (
        1,
        True,
        TunnelAuth.EAP,
        None,
        False,
    )
    assert c.children[0].rekey_seconds == 3600 and c.children[0].established is None
    (o,) = opnsense_vpn.openvpn_tunnels(
        "fw", [{"uuid": "x", "role": "", "port": "99999", "proto": "icmp"}], None, NOW
    )
    assert (o.role, o.listen_port, o.protocol, o.tls_auth, o.sessions) == (
        None,
        None,
        None,
        None,
        None,
    )


# --- MikroTik ------------------------------------------------------------------------------

MK = MikrotikSimulator()


@pytest.fixture(scope="module")
def mk_url() -> Iterator[str]:
    with serve(MK.app()) as url:
        yield url


@pytest.fixture
def mk() -> MikrotikSimulator:
    MK.__dict__.update(MikrotikSimulator().__dict__)
    MK.data.update(mikrotik_data())
    return MK


async def mk_observe(url: str) -> Snapshot:
    a = MikrotikAdapter(
        AdapterContext(
            site_id="home",
            device_id="rt",
            device_name="Router",
            role=DeviceRole.GATEWAY,
            config=MikrotikConfig(
                url=url, password=SecretStr(MK_PASSWORD), allow_insecure_http=True
            ),
            timeout=5.0,
        )
    )
    try:
        return await a.observe()
    finally:
        await a.close()


async def test_mikrotik_ipsec_peer(mk_url: str, mk: MikrotikSimulator) -> None:
    snap = await mk_observe(mk_url)
    t = by_name(snap)["site C"]
    assert t.kind is TunnelKind.IPSEC and t.name == "ipsec-site-c"
    assert (t.up, t.ike_version, t.aggressive, t.auth) == (True, 2, False, TunnelAuth.PSK)
    assert (t.remote_gateway, t.dpd) == ("203.0.113.50", True)
    assert ("aes-256", None, None) in [(p.encryption, p.integrity, p.dh_group) for p in t.proposals]
    assert (None, "sha256", None) in [(p.encryption, p.integrity, p.dh_group) for p in t.proposals]
    (c,) = t.children
    assert c.established is True and c.rekey_seconds == 1800
    assert [str(n) for n in c.remote_networks] == ["198.18.88.0/24"]
    assert c.last_rekey is not None


async def test_mikrotik_openvpn(mk_url: str, mk: MikrotikSimulator) -> None:
    snap = await mk_observe(mk_url)
    server = by_name(snap)["OpenVPN server"]
    assert server.role is TunnelRole.SERVER and server.listen_port == 1194
    assert server.protocol == "tcp" and server.tls_auth is None  # RouterOS has no tls-auth
    assert server.cipher == "aes256-cbc,aes256-gcm" and server.sessions is not None
    assert [s.common_name for s in server.sessions] == ["laptop"]
    client = snap_tunnel(snap, "ovpn-out1")
    assert (client.role, client.up, client.remote_gateway) == (
        TunnelRole.CLIENT,
        True,
        "203.0.113.60",
    )


def snap_tunnel(snap: Snapshot, name: str) -> Tunnel:
    return next(t for t in snap.tunnels if t.name == name)


async def test_mikrotik_secrets_never_leave(mk_url: str, mk: MikrotikSimulator) -> None:
    assert MK_SECRET in str(mk.data) and SIM_SECRET_MARKER in MK_SECRET
    snap = await mk_observe(mk_url)
    assert MK_SECRET not in snap.model_dump_json()


async def test_mikrotik_default_sample_has_no_vpn(mk_url: str, mk: MikrotikSimulator) -> None:
    for path in [p for p in mk.data if "ipsec/peer" in p or "ovpn" in p]:
        del mk.data[path]
    snap = await mk_observe(mk_url)
    assert [t.kind for t in snap.tunnels] == [TunnelKind.WIREGUARD]
    assert not [e for e in snap.errors if e.capability == "vpn"]


async def test_mikrotik_needs_the_read_policy(mk_url: str, mk: MikrotikSimulator) -> None:
    mk.no_policy = {"/rest/ip/ipsec/active-peers"}
    snap = await mk_observe(mk_url)
    t = by_name(snap)["site C"]
    assert t.up is None
    (gap,) = [e for e in snap.errors if e.capability == "vpn"]
    assert gap.optional and "active-peers" in gap.message


async def test_mikrotik_server_switched_off_is_no_tunnel(
    mk_url: str, mk: MikrotikSimulator
) -> None:
    mk.data["/rest/interface/ovpn-server/server"][0]["enabled"] = "false"
    mk.data["/rest/interface/ovpn-server"] = []
    names = {t.name for t in (await mk_observe(mk_url)).tunnels}
    assert "ovpn-server" not in names and "ovpn-out1" in names


def test_mikrotik_clean_drops_secrets() -> None:
    rows = mikrotik_vpn.clean(
        [{"peer": "a", "secret": "x", "password": "y", "eap-password": "z", "key": "k"}]
    )
    assert rows == [{"peer": "a", "secret-set": True}]
    assert mikrotik_vpn.clean([{"peer": "b"}]) == [{"peer": "b", "secret-set": False}]


def test_mikrotik_older_peer_holds_its_own_algorithms() -> None:
    peers = [
        {
            "name": "old",
            "address": "203.0.113.9",
            "exchange-mode": "aggressive",
            "enc-algorithm": "3des,aes-128",
            "hash-algorithm": "md5",
            "dh-group": "modp1024",
        }
    ]
    (t,) = mikrotik_vpn.ipsec_tunnels("rt", peers, [], [], [], [], None, NOW)
    assert (t.ike_version, t.aggressive, t.up, t.auth) == (1, True, None, None)
    weak = [w for p in t.proposals for w in p.weaknesses()]
    assert weak == ["encryption:3des", "integrity:md5", "dh:2"]


def test_mikrotik_duration() -> None:
    assert mikrotik_vpn._duration("1h2m3s") == 3723
    assert mikrotik_vpn._duration("1d00:00:10") == 86410
    assert mikrotik_vpn._duration("45") == 45 and mikrotik_vpn._duration("soon") is None


# --- OpenWrt -------------------------------------------------------------------------------

WRT = OpenWrtSim()


@pytest.fixture(scope="module")
def wrt_cert(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"), "openwrt")


@pytest.fixture(scope="module")
def wrt_url(wrt_cert: TlsFiles) -> Iterator[str]:
    with serve(create_app(WRT), tls=wrt_cert) as url:
        yield url


@pytest.fixture
def wrt() -> OpenWrtSim:
    WRT.reset()
    return WRT


@pytest.fixture
async def wrt_adapter(
    wrt: OpenWrtSim, wrt_url: str, wrt_cert: TlsFiles
) -> AsyncIterator[OpenWrtAdapter]:
    a = OpenWrtAdapter(
        AdapterContext(
            site_id="home",
            device_id="gw",
            device_name="Gateway",
            role=DeviceRole.GATEWAY,
            config=OpenWrtConfig(url=f"{wrt_url}/ubus", password=SecretStr(WRT.password)),
            pinned_fingerprint=wrt_cert.fingerprint,
        )
    )
    yield a
    await a.close()


async def test_openwrt_openvpn_from_uci(wrt: OpenWrtSim, wrt_adapter: OpenWrtAdapter) -> None:
    wrt.packages = {"openvpn"}
    obs = await wrt_adapter.read_vpn()
    ts = {t.description: t for t in obs.tunnels}
    server = ts["road_warrior"]
    assert server.kind is TunnelKind.OPENVPN and server.id == "gw/tunnel/openvpn-road_warrior"
    assert (server.role, server.protocol, server.listen_port) == (TunnelRole.SERVER, "udp", 1194)
    assert server.tls_auth is True and str(server.tunnel_network) == "198.18.77.0/24"
    assert server.cipher == "AES-256-GCM,AES-128-GCM"
    assert [str(n) for n in server.pushed_routes] == ["192.0.2.0/24"]
    assert server.up is None and server.sessions is None
    client = ts["to_provider"]
    assert (client.role, client.protocol, client.listen_port) == (TunnelRole.CLIENT, "tcp", None)
    assert (client.remote_gateway, client.cipher) == ("203.0.113.60", "BF-CBC")
    assert client.tls_auth is None  # a static key (secret) tunnel does not use TLS
    assert not obs.incomplete


async def test_openwrt_openvpn_keys_never_leave(
    wrt: OpenWrtSim, wrt_adapter: OpenWrtAdapter
) -> None:
    wrt.packages = {"openvpn"}
    assert SIM_SECRET_MARKER in OPENVPN_SECRET
    obs = await wrt_adapter.read_vpn()
    assert OPENVPN_SECRET not in obs.model_dump_json()


async def test_openwrt_without_the_package(wrt: OpenWrtSim, wrt_adapter: OpenWrtAdapter) -> None:
    obs = await wrt_adapter.read_vpn()
    assert [t for t in obs.tunnels if t.kind is TunnelKind.OPENVPN] == [] and not obs.incomplete


async def test_openwrt_old_acl_is_an_optional_gap(
    wrt: OpenWrtSim, wrt_adapter: OpenWrtAdapter
) -> None:
    wrt.packages = {"openvpn"}
    wrt.denied = {"uci:openvpn"}
    obs = await wrt_adapter.read_vpn()
    (gap,) = obs.incomplete
    assert gap.optional and "OpenVPN" in gap.message


def test_openwrt_scrub_keeps_flags_only() -> None:
    answer = {
        "values": {
            "a": {
                ".type": "openvpn",
                "tls_crypt": "/etc/k",
                "secret": "/etc/s",
                "key": "/etc/key",
                "auth_user_pass": "/etc/pw",
            }
        }
    }
    openwrt_openvpn.scrub(answer)
    assert answer["values"]["a"] == {
        ".type": "openvpn",
        "tls_crypt_set": "1",
        "secret_set": "1",
    }


def test_openwrt_server_without_tls_crypt_and_unknown_role() -> None:
    uci: dict[str, Any] = {
        "values": {
            "s": {
                ".type": "openvpn",
                "server": "10.8.0.0 255.255.255.0",
                "ca": "x",
                "port": "1195",
            },
            "odd name!": {".type": "openvpn", "enabled": "0"},
            "x": {".type": "other"},
        }
    }
    odd, s = openwrt_openvpn.tunnels(uci, "gw")
    assert (odd.name, odd.enabled, odd.up, odd.role) == ("openvpn-odd_name_", False, False, None)
    assert (s.tls_auth, s.listen_port, str(s.tunnel_network)) == (False, 1195, "10.8.0.0/24")
