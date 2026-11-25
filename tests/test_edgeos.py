"""Ubiquiti EdgeRouter (EdgeOS) and VyOS integration (#403) against the SSH simulator, for EdgeOS
2.0 and 1.10 and VyOS 1.3 and 1.4: contract, mapped values, secrets, trust and error paths."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import asyncssh
import pytest
from pydantic import SecretStr, ValidationError

from signalbox.adapters import AdapterContext, load_adapters
from signalbox.adapters.edgeos import (
    EdgeosAdapter,
    EdgeosConfig,
    _endpoint,
    _pools,
    collect,
    firewall,
    parse,
    tree,
)
from signalbox.adapters.edgeos.collect import split
from signalbox.adapters.ssh import sha256_hex
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    LeaseState,
    Membership,
    PortKind,
    PortRole,
    RouteKind,
    RouteOrigin,
    Snapshot,
    UplinkKind,
)
from signalbox.sim import edgeos as sim
from signalbox.sim.edgeos import EdgeosSim, serve_ssh
from signalbox.testing import assert_contract

KEY = asyncssh.generate_private_key("ssh-ed25519")
PRIVATE = KEY.export_private_key().decode()
PUBLIC = KEY.export_public_key("openssh").decode().strip()
DEV = "er1"


def box(profile: str = "edgeos-2.0", **changes: Any) -> EdgeosSim:
    return EdgeosSim(profile=profile, keys=[PUBLIC], **changes)


@asynccontextmanager
async def adapter_for(
    device: EdgeosSim,
    *,
    role: DeviceRole = DeviceRole.GATEWAY,
    pin: str | None = "auto",
    **cfg: Any,
) -> AsyncIterator[EdgeosAdapter]:
    async with serve_ssh(device) as (port, fingerprint):
        settings: dict[str, Any] = {
            "host": "127.0.0.1",
            "port": port,
            "username": "signalbox",
            "private_key": PRIVATE,
        } | cfg
        ctx = AdapterContext(
            site_id="home",
            device_id=DEV,
            device_name=DEV,
            role=role,
            config=EdgeosConfig(**settings),
            pinned_fingerprint=sha256_hex(fingerprint) if pin == "auto" else pin,
            timeout=5,
        )
        adapter = EdgeosAdapter(ctx)
        try:
            yield adapter
        finally:
            await adapter.close()


async def contract(profile: str, **changes: Any) -> tuple[Snapshot, EdgeosSim]:
    device = box(profile, **changes)
    async with adapter_for(device) as adapter:
        return await assert_contract(adapter), device


async def observed(profile: str, **changes: Any) -> Snapshot:
    async with adapter_for(box(profile, **changes)) as adapter:
        return await adapter.observe()


def test_registered_and_manifest() -> None:
    cls = load_adapters()["edgeos"]
    assert cls is EdgeosAdapter
    assert not cls.manifest.writes
    assert {r.value for r in cls.manifest.roles} == {"gateway", "other"}
    assert {c.value for c in cls.manifest.capabilities} >= {
        "interfaces",
        "dhcp",
        "dns",
        "neighbours",
        "vpn",
        "firewall",
    }


# --- EdgeOS 2.0 (EdgeRouter X) --------------------------------------------------------------


async def test_edgeos_20_system_ports_and_networks() -> None:
    snap, device = await contract("edgeos-2.0")
    d = snap.device
    assert (d.vendor, d.model) == ("Ubiquiti", "EdgeRouter X 5-Port")
    assert d.firmware is not None and d.firmware.current == "v2.0.9-hotfix.7"
    assert d.transport_encrypted is True and d.hostname == "er-sim"
    assert d.os == "EdgeOS"
    ports = {p.name: p for p in snap.ports}
    assert "lo" not in ports
    assert set(ports) == {
        "eth0",
        "eth1",
        "eth2",
        "eth3",
        "eth4",
        "switch0",
        "switch0.20",
        "wg0",
    }
    assert ports["eth0"].role is PortRole.JACK and ports["eth0"].speed_mbps == 1000
    assert ports["eth0"].description == "Internet" and ports["eth0"].up is True
    assert ports["eth3"].admin_up is False and ports["eth3"].up is False  # disabled
    assert ports["eth4"].admin_up is True and ports["eth4"].up is False  # no cable
    assert ports["switch0"].role is PortRole.BRIDGE and ports["switch0"].kind is PortKind.BRIDGE
    assert ports["switch0"].lower == [f"{DEV}/port/eth{n}" for n in (1, 2, 3, 4)]
    assert ports["switch0.20"].role is PortRole.VLAN
    assert ports["switch0.20"].lower == [f"{DEV}/port/switch0"]
    assert ports["wg0"].role is PortRole.TUNNEL and ports["wg0"].mtu == 1420
    assert ports["eth1"].mac == "02:5e:00:00:00:01"

    segs = {s.id: s for s in snap.segments}
    native = segs["home/segment/native"]
    assert {(m.port_id, m.mode) for m in native.members} == {
        (f"{DEV}/port/eth{n}", Membership.UNTAGGED) for n in (1, 2, 3, 4)
    }
    vlan = segs["home/segment/20"]
    assert vlan.vlan == 20
    assert {(m.port_id, m.mode) for m in vlan.members} == {
        (f"{DEV}/port/eth{n}", Membership.TAGGED) for n in (1, 2, 3, 4)
    }
    assert {str(s.interface) for s in snap.subnets} == {"192.0.2.1/25", "192.0.2.129/26"}
    assert all(s.gateway for s in snap.subnets)

    (uplink,) = snap.uplinks
    assert uplink.name == "eth0" and uplink.kind is UplinkKind.DHCP and uplink.up is True
    assert str(uplink.upstream_gateway) == "203.0.113.1"
    assert [str(a) for a in uplink.addresses] == ["203.0.113.10/24"]

    services = {s.kind.value: s for s in snap.services}
    assert set(services) == {"ssh", "https", "http"}
    assert services["ssh"].port == 22 and services["ssh"].password_login is True
    assert services["https"].port == 443 and services["http"].port == 80
    # the commands that were sent only read (checked by the words, not by the device)
    for script in device.scripts:
        assert not any(word in script for word in collect.FORBIDDEN), script


async def test_edgeos_20_routes() -> None:
    snap, _ = await contract("edgeos-2.0")
    routes = {(str(r.destination), r.kind): r for r in snap.routes}
    default = routes[("0.0.0.0/0", RouteKind.UNICAST)]
    assert default.origin is RouteOrigin.DHCP and str(default.gateway) == "203.0.113.1"
    assert default.interface == f"{DEV}/port/eth0" and default.active is True
    static = routes[("192.0.2.192/26", RouteKind.UNICAST)]
    assert static.origin is RouteOrigin.STATIC and str(static.gateway) == "192.0.2.10"
    assert static.metric == 1 and static.active is True
    hole = routes[("192.0.2.224/27", RouteKind.BLACKHOLE)]
    assert hole.origin is RouteOrigin.STATIC and hole.gateway is None
    # configured, not installed: kept, but not active
    pending = routes[("192.0.2.240/28", RouteKind.UNICAST)]
    assert pending.active is False and pending.origin is RouteOrigin.STATIC
    # connected networks come from the subnets
    assert ("192.0.2.0/25", RouteKind.UNICAST) not in routes


async def test_edgeos_20_dhcp_dns_neighbours() -> None:
    snap, _ = await contract("edgeos-2.0")
    servers = {s.vendor_extra["shared_network"]: s for s in snap.dhcp_servers}
    lan, iot = servers["LAN"], servers["IOT"]
    assert lan.enabled and lan.segment_id == "home/segment/native"
    assert [(str(p.start), str(p.end)) for p in lan.pools] == [("192.0.2.20", "192.0.2.99")]
    assert lan.lease_seconds == 86400 and str(lan.router) == "192.0.2.1"
    assert [str(a) for a in lan.dns_servers] == ["192.0.2.1"] and lan.domain == "lan.example"
    assert [str(a) for a in lan.ntp_servers] == ["192.0.2.1"] and lan.authoritative is True
    (res,) = lan.reservations
    assert (res.mac, str(res.address), res.hostname) == (
        "02:00:00:00:00:50",
        "192.0.2.50",
        "printer",
    )
    assert lan.leases is not None
    leases = {str(x.address): x for x in lan.leases}
    assert set(leases) == {"192.0.2.21", "192.0.2.50"}
    assert leases["192.0.2.50"].reserved is True and leases["192.0.2.21"].reserved is False
    assert leases["192.0.2.21"].hostname == "laptop"
    assert leases["192.0.2.21"].state is LeaseState.ACTIVE
    assert leases["192.0.2.21"].expires is not None
    assert iot.segment_id == "home/segment/20" and iot.authoritative is False
    assert iot.leases is not None and [str(x.address) for x in iot.leases] == ["192.0.2.151"]

    (dns,) = snap.dns_services
    assert [str(a) for a in dns.listen] == ["192.0.2.1", "192.0.2.129"]
    assert [str(f) for f in dns.forwarders] == ["203.0.113.53", "203.0.113.54"]
    assert [(r.name, str(r.address)) for r in dns.host_records] == [
        ("nas.lan.example", "192.0.2.60")
    ]

    nb = {n.local_port_id: n for n in snap.neighbours}
    switch = nb[f"{DEV}/port/eth1"]
    assert (switch.chassis_id, switch.system_name) == ("02:5e:11:00:00:01", "es-sim")
    assert switch.remote_port == "0/1" and switch.management_address == "192.0.2.2"
    assert switch.capabilities == ["bridge"]
    ap = nb[f"{DEV}/port/eth2"]
    assert ap.description == "Access point firmware 6.6.1"
    assert ap.capabilities == ["bridge", "wlan-access-point"]
    assert ap.remote_port == "02:5e:22:00:00:02"


async def test_edgeos_20_wireguard() -> None:
    snap, _ = await contract("edgeos-2.0")
    (tunnel,) = snap.tunnels
    assert tunnel.id == f"{DEV}/tunnel/wg0" and tunnel.port_id == f"{DEV}/port/wg0"
    assert tunnel.public_key == sim.GW_KEY and tunnel.listen_port == 51820 and tunnel.up
    assert tunnel.mtu == 1420 and [str(a) for a in tunnel.addresses] == ["198.51.100.254/30"]
    peers = {p.public_key: p for p in tunnel.peers}
    site = peers[sim.SITE_KEY]
    assert (site.endpoint_host, site.endpoint_port) == ("203.0.113.77", 51820)
    assert [str(n) for n in site.allowed_ips] == ["198.51.100.253/32", "198.51.100.0/25"]
    assert site.keepalive_seconds == 25 and site.name == "Second site"
    phone = peers[sim.PHONE_KEY]
    assert phone.endpoint_host is None and phone.keepalive_seconds is None


async def test_edgeos_20_firewall_nat_and_port_forward() -> None:
    snap, _ = await contract("edgeos-2.0")
    (fw,) = snap.firewalls
    assert fw.enabled and fw.rules_complete and fw.port_forwards_complete
    assert {z.name for z in fw.zones} == {"eth0", "switch0.20"}
    # the router itself first, then forwarded traffic; rules that only accept established or
    # related connections, or drop invalid ones, are no rules for new connections
    assert [r.name for r in fw.rules] == [
        "SSH from the admin network",
        "Rate limited ping",
        "WAN_LOCAL default",
        "Web server",
        "WAN_IN default",
        "IoT must not reach the LAN",
        "IOT_IN default",
    ]
    ssh, ping, local_default, web, wan_default, iot, iot_default = fw.rules
    assert ssh.chain is FirewallChain.INPUT and ssh.action is FirewallAction.ACCEPT
    assert [str(p) for p in ssh.destination.ports] == ["22"]
    assert [str(n) for n in ssh.source.networks] == ["198.51.100.0/25"]
    assert ssh.source.zones == ["eth0"] and ssh.protocols == [FirewallProtocol.TCP]
    assert ssh.exact is True and ping.exact is False
    assert (
        local_default.action is FirewallAction.DROP and local_default.chain is FirewallChain.INPUT
    )
    assert web.chain is FirewallChain.FORWARD and web.action is FirewallAction.ACCEPT
    assert [str(p) for p in web.destination.ports] == ["80", "443"]
    assert [str(n) for n in web.destination.networks] == ["192.0.2.50/32"]
    assert wan_default.action is FirewallAction.DROP and wan_default.source.zones == ["eth0"]
    assert iot.action is FirewallAction.DROP and iot.source.zones == ["switch0.20"]
    assert iot_default.action is FirewallAction.ACCEPT

    masq, snat = fw.nat
    assert masq.masquerade and masq.zones == ["eth0"] and masq.to_address is None
    assert not snat.masquerade and str(snat.to_address) == "203.0.113.12"
    assert [str(n) for n in snat.sources] == ["192.0.2.40/32"]
    (forward,) = fw.port_forwards
    assert forward.zones == ["eth0"] and forward.protocols == [FirewallProtocol.TCP]
    assert [str(p) for p in forward.external_ports] == ["8080"]
    assert str(forward.target_address) == "192.0.2.50" and forward.target_port == 80
    assert forward.passes_filter is True and forward.reflection is True
    zones = {z.name: z for z in fw.zones}
    assert zones["eth0"].uplinks == [f"{DEV}/uplink/eth0"]
    assert zones["switch0.20"].segments == ["home/segment/20"]


async def test_edgeos_20_health_and_time() -> None:
    snap, _ = await contract("edgeos-2.0")
    health = snap.device.health
    assert health is not None
    assert health.uptime_seconds == 263700 and health.load_average == (0.08, 0.05, 0.01)
    assert health.cpu_count == 2 and health.memory_total_bytes == 504852 * 1024
    assert health.temperatures[0].value_c == 48
    value = snap.device.time
    assert value is not None and value.timezone == "UTC"
    assert value.clock is not None and int(value.clock.timestamp()) == sim.NOW
    assert value.ntp_client is not None and value.ntp_client.servers == ["ntp.example.org"]


async def test_no_secret_reaches_the_snapshot() -> None:
    """The simulator prints private keys, hashes, communities and pre-shared keys as a device
    does without the read script's filter: none of them is kept."""
    for profile in sim.PROFILES:
        snap = await observed(profile)
        text = snap.model_dump_json()
        for secret in (
            "notarealhash",
            "SIMULATOR-NOT-A-REAL-PSK",
            "wg.key",
            "SIMULATOR-PUBLIC-KEY",
            "simulator-not-real",
            "authorization",
        ):
            assert secret not in text, (profile, secret)


async def test_the_script_filters_and_only_reads() -> None:
    _, device = await contract("edgeos-2.0")
    assert device.scripts and all(s.startswith("# signalbox-") for s in device.scripts)
    read = device.scripts[0]
    assert "show configuration commands | grep -v -i -E" in read
    for word in ("private-key", "preshared-key", "plaintext-password", "community"):
        assert word in collect.SECRET_FILTER


# --- EdgeOS 1.10 (EdgeRouter Lite) -------------------------------------------------------------


async def test_edgeos_110() -> None:
    snap, _ = await contract("edgeos-1.10")
    d = snap.device
    assert d.model == "EdgeRouter Lite 3-Port"
    assert d.firmware is not None and d.firmware.current == "v1.10.11"
    ports = {p.name: p for p in snap.ports}
    assert ports["pppoe0"].role is PortRole.TUNNEL
    assert ports["eth1.30"].role is PortRole.VLAN and ports["eth1.30"].lower == [f"{DEV}/port/eth1"]
    assert ports["br0"].role is PortRole.BRIDGE and ports["br0"].lower == [f"{DEV}/port/eth2"]
    (uplink,) = snap.uplinks
    assert uplink.name == "pppoe0" and uplink.kind is UplinkKind.PPPOE
    assert [str(a) for a in uplink.addresses] == ["203.0.113.77/32"]
    assert {str(s.interface) for s in snap.subnets} == {"192.0.2.1/26", "198.51.100.1/26"}
    services = {s.kind.value: s for s in snap.services}
    assert services["ssh"].password_login is False and "telnet" in services
    # no WireGuard and no LLDP in this version: nothing read, LLDP an optional finding
    assert snap.tunnels == [] and snap.neighbours == []
    assert any(e.optional and e.capability == "neighbours" for e in snap.errors)
    (fw,) = snap.firewalls
    assert [r.name for r in fw.rules] == ["WAN_LOCAL default", "WAN_IN default"]
    assert fw.nat[0].zones == ["pppoe0"]
    assert {z.name: z.uplinks for z in fw.zones}["pppoe0"] == [f"{DEV}/uplink/pppoe0"]
    assert snap.device.time is not None and snap.device.time.timezone == "Europe/Berlin"
    (server,) = snap.dhcp_servers
    assert [(str(p.start), str(p.end)) for p in server.pools] == [("192.0.2.10", "192.0.2.60")]


# --- VyOS ----------------------------------------------------------------------------------------


async def test_vyos_13() -> None:
    snap, _ = await contract("vyos-1.3")
    d = snap.device
    assert (d.vendor, d.model) == ("VyOS", "Standard PC (Q35 + ICH9, 2009)")
    assert d.firmware is not None and d.firmware.current == "VyOS 1.3.3" and d.os == "VyOS"
    ports = {p.name: p for p in snap.ports}
    assert ports["bond0"].role is PortRole.LAG and ports["bond0"].kind is PortKind.LAG
    assert ports["bond0"].lower == [f"{DEV}/port/eth2", f"{DEV}/port/eth3"]
    assert ports["eth2"].lag == "bond0" and ports["eth3"].lag == "bond0"
    assert ports["br0"].lower == [f"{DEV}/port/eth1"]
    assert ports["eth0.100"].role is PortRole.VLAN
    (server,) = snap.dhcp_servers
    assert [(str(p.start), str(p.end)) for p in server.pools] == [("192.0.2.100", "192.0.2.199")]
    assert server.domain == "lan.example" and [str(a) for a in server.dns_servers] == ["192.0.2.1"]
    (res,) = server.reservations
    assert (res.mac, str(res.address), res.hostname) == ("02:00:00:00:00:60", "192.0.2.60", "nas")
    # `show dhcp server leases`: with a state and a start
    assert server.leases is not None
    leases = {str(x.address): x for x in server.leases}
    assert leases["192.0.2.60"].reserved is True and leases["192.0.2.60"].starts is not None
    assert leases["192.0.2.101"].state is LeaseState.EXPIRED
    assert leases["192.0.2.100"].hostname == "laptop"
    (tunnel,) = snap.tunnels
    (peer,) = tunnel.peers
    assert peer.public_key == sim.SITE_KEY and peer.name == "site2"
    assert (peer.endpoint_host, peer.endpoint_port) == ("203.0.113.77", 51820)
    assert tunnel.listen_port == 51820
    (fw,) = snap.firewalls
    assert [r.name for r in fw.rules] == ["WAN_IN 20", "WAN_IN default"]
    masq, *_ = fw.nat
    assert masq.masquerade and masq.zones == ["eth0"]
    assert [str(n) for n in masq.sources] == ["192.0.2.0/24"]
    (forward,) = fw.port_forwards
    assert [str(p) for p in forward.external_ports] == ["8443"] and forward.target_port == 443
    assert str(forward.target_address) == "192.0.2.50"
    static = next(r for r in snap.routes if str(r.destination) == "192.0.2.192/26")
    assert static.origin is RouteOrigin.STATIC and static.active is True
    (neighbour,) = snap.neighbours
    assert neighbour.system_name == "sw-sim" and neighbour.remote_port == "Gi1/0/3"
    assert snap.device.time is not None
    assert snap.device.time.ntp_client is not None
    assert snap.device.time.ntp_client.servers == ["ntp.example.org"]


async def test_vyos_14_firewall_is_a_gap_naming_the_version() -> None:
    """VyOS 1.4 renamed the firewall (#389): its rules are not read, a gap names the version;
    everything else, NAT and DHCP with their 1.4 spellings included, is read."""
    snap = await observed("vyos-1.4")
    assert snap.device.firmware is not None and snap.device.firmware.current == "VyOS 1.4.0"
    gaps = [e for e in snap.errors if e.capability == "firewall"]
    assert len(gaps) == 1 and "VyOS 1.4.0" in gaps[0].message and not gaps[0].optional
    assert gaps[0].message_id == "edgeos.firewallVyos14"
    (fw,) = snap.firewalls
    assert fw.rules == [] and fw.rules_complete is False and fw.enabled is True
    masq, *_ = fw.nat
    assert masq.masquerade and masq.zones == ["eth0"]  # outbound-interface name eth0
    (forward,) = fw.port_forwards
    assert forward.zones == ["eth0"] and forward.target_port == 443
    (server,) = snap.dhcp_servers
    assert str(server.router) == "192.0.2.1" and [str(a) for a in server.dns_servers] == [
        "192.0.2.1"
    ]
    assert server.domain == "lan.example"
    (res,) = server.reservations
    assert res.mac == "02:00:00:00:00:60"
    (tunnel,) = snap.tunnels
    assert tunnel.peers[0].public_key == sim.SITE_KEY  # public-key (1.4), pubkey (1.3)
    assert snap.status is DeviceStatus.PARTIAL


# --- other shapes of the configuration -----------------------------------------------------------


async def test_zone_policy_is_a_gap() -> None:
    snap = await observed("edgeos-2.0", extra_config="set zone-policy zone LAN interface switch0\n")
    (fw,) = snap.firewalls
    assert fw.rules_complete is False
    gap = next(e for e in snap.errors if e.message_id == "edgeos.firewallUnsupported")
    assert "zone-policy" in gap.message


async def test_unknown_rule_set_is_a_gap() -> None:
    extra = "set interfaces ethernet eth4 firewall in name MISSING\n"
    snap = await observed("edgeos-2.0", extra_config=extra)
    gap = next(e for e in snap.errors if e.message_id == "edgeos.ruleSetMissing")
    assert gap.params == {"interface": "eth4", "name": "MISSING"}
    (fw,) = snap.firewalls
    assert fw.rules_complete is False


async def test_lldp_off_and_unknown_version_are_optional_gaps() -> None:
    config = sim.EDGEOS_20_CONFIG.replace("set service lldp interface all\n", "")
    snap = await observed(
        "edgeos-2.0", sections={"config": config, "version": "Uptime: 1 day\n", "lldp": ""}
    )
    assert snap.neighbours == []
    ids = {e.message_id: e for e in snap.errors}
    assert ids["edgeos.lldpOff"].optional and ids["edgeos.versionUnknown"].optional
    assert snap.status is DeviceStatus.OK
    assert snap.device.vendor == "Ubiquiti" and snap.device.firmware is None


async def test_empty_configuration_is_reported() -> None:
    snap = await observed("edgeos-2.0", sections={"config": ""})
    assert any(e.message_id == "edgeos.configEmpty" and not e.optional for e in snap.errors)
    assert snap.status is DeviceStatus.PARTIAL


async def test_a_switch_role_has_no_uplink() -> None:
    device = box()
    async with adapter_for(device, role=DeviceRole.OTHER) as adapter:
        snap = await adapter.observe()
    assert snap.uplinks == []
    assert not any(s.gateway for s in snap.subnets)
    assert "203.0.113.10/24" in {str(s.interface) for s in snap.subnets}


# --- trust, login and errors ---------------------------------------------------------------------


async def test_untrusted_host_key_then_trusted() -> None:
    device = box()
    async with adapter_for(device, pin=None) as adapter:
        snap = await adapter.observe()
        assert snap.status is DeviceStatus.UNTRUSTED
        presented = adapter.presented_fingerprint
        assert presented is not None and len(presented) == 64
        assert "ssh-keygen" in snap.errors[0].message
    async with adapter_for(device, pin="0" * 64) as adapter:
        snap = await adapter.observe()
        assert snap.status is DeviceStatus.UNTRUSTED
        assert "different" in snap.errors[0].message
    assert device.scripts == []  # nothing was sent to an untrusted host


async def test_wrong_key_and_password_login() -> None:
    device = box()
    other = asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()
    async with adapter_for(device, private_key=other) as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.AUTH_FAILED and "signalbox" in snap.errors[0].message
    device.password = "example-read-password"
    async with adapter_for(device, private_key=None, password="example-read-password") as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK


async def test_bad_key_and_incomplete_answer() -> None:
    async with adapter_for(box(), private_key="not a key") as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.UNREACHABLE and "private key" in snap.errors[0].message
    assert "not a key" not in snap.errors[0].message
    async with adapter_for(box(truncate=True)) as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.UNREACHABLE and "completely" in snap.errors[0].message


def test_config() -> None:
    cfg = EdgeosConfig(host="ssh://192.0.2.1/", password=SecretStr("x"))
    assert cfg.host == "192.0.2.1" and cfg.port == 22 and cfg.username == "signalbox"
    with pytest.raises(ValidationError):
        EdgeosConfig(host="192.0.2.1")
    with pytest.raises(ValidationError):
        EdgeosConfig(host=" ", password=SecretStr("x"))


# --- parsers ----------------------------------------------------------------------------


def test_tree_parses_quotes_and_drops_secrets() -> None:
    root = tree.parse(
        "set system host-name 'er sim'\n"
        "set interfaces ethernet eth0 description 'it'\\''s the WAN'\n"
        "set interfaces ethernet eth0 address 192.0.2.1/24\n"
        "set interfaces ethernet eth0 address 2001:db8::1/64\n"
        "set interfaces wireguard wg0 private-key /config/auth/wg.key\n"
        "set service snmp community private authorization rw\n"
        "set system login user a authentication plaintext-password hunter2\n"
        "set system login user a authentication public-keys k key AAAA\n"
        "delete foo\n"
        "set\n"
    )
    assert root.first("system", "host-name") == "er sim"
    assert root.first("interfaces", "ethernet", "eth0", "description") == "it's the WAN"
    assert root.keys("interfaces", "ethernet", "eth0", "address") == [
        "192.0.2.1/24",
        "2001:db8::1/64",
    ]
    assert not root.has("interfaces", "wireguard") and not root.has("service")
    assert not root.has("system", "login") and root.get("nothing", "here") is None
    assert tree.split_line("show foo") is None and tree.split_line("set 'a b") == ["'a", "b"]


def test_version_parser() -> None:
    edge = parse.version(split("@@version\nVersion:      v2.0.9-hotfix.7\nHW model: ER\n@@end\n"))
    assert (edge.flavor, edge.major, edge.minor, edge.patch) == ("edgeos", 2, 0, 9)
    assert edge.at_least(1, 10) and edge.name == "EdgeOS" and not edge.vyos
    old = parse.version(split("@@version\nVersion: v1.9.7+hotfix.4\n@@end\n"))
    assert (old.major, old.minor) == (1, 9) and not old.at_least(1, 10)
    vyos = parse.version(split("@@version\nVersion: VyOS 1.4.0\nRelease train: sagitta\n@@end\n"))
    assert vyos.vyos and vyos.at_least(1, 4) and vyos.name == "VyOS"
    rolling = parse.version(split("@@version\nVersion: VyOS 1.5-rolling-202411\n@@end\n"))
    assert rolling.vyos and rolling.at_least(1, 4)
    none = parse.version(split("@@version\n@@end\n"))
    assert none.flavor == "unknown" and none.text is None and not none.at_least(1, 0)
    odd = parse.version(split("@@version\nVersion: nightly\n@@end\n"))
    assert odd.flavor == "edgeos" and odd.major is None


def test_lease_parser() -> None:
    edge = parse.dhcp_leases(
        split(
            "@@dhcp-leases\nIP address Hardware address Lease expiration Pool Client Name\n"
            "---- ---- ---- ---- ----\n"
            "192.0.2.9  02:00:00:00:00:09  2026/11/23 08:15:00  LAN  my phone\n"
            "bad line\n"
            "192.0.2.10  not-a-mac  2026/11/23 08:15:00  LAN\n"
            "@@end\n"
        )
    )
    assert edge is not None and len(edge) == 1
    assert edge[0].pool == "LAN" and edge[0].lease.hostname == "my phone"
    assert edge[0].lease.starts is None and edge[0].lease.expires is not None
    assert parse.dhcp_leases(split("@@dhcp-leases\n@@end\n")) is None
    empty = parse.dhcp_leases(split("@@dhcp-leases\nIP address Hardware address\n@@end\n"))
    assert empty == []


def test_lldp_details() -> None:
    first, second = parse.lldp(split("@@lldp\n" + sim.EDGEOS_LLDP + "@@end\n"))
    assert (first.via, first.chassis_kind, first.age) == ("LLDP", "mac", 11564)
    assert (first.ttl, first.max_frame_size, first.port_vlan) == (120, 1522, 1)
    assert first.vlans == [1, 20] and first.port_description == "0/1"
    assert first.med_device_type and second.ttl is None and second.vlans == []


def test_lldp_parser_skips_neighbours_without_chassis() -> None:
    neighbours = parse.lldp(
        split(
            "@@lldp\nInterface:    eth9, via: LLDP, RID: 1, Time: 0 day, 00:00:01\n"
            "  Chassis:\n    SysName:      nobody\n"
            "Interface:    eth8, via: LLDP, RID: 2, Time: 0 day, 00:00:01\n"
            "  Chassis:\n    ChassisID:    ip 192.0.2.77\n    Capability:   Station, on\n"
            "  Port:\n    PortDescr:    port one\n@@end\n"
        )
    )
    (n,) = neighbours
    assert (n.interface, n.chassis, n.port, n.capabilities) == (
        "eth8",
        "192.0.2.77",
        "port one",
        ["station"],
    )


def test_route_and_address_parsers() -> None:
    a = split(
        "@@route\ndefault via 192.0.2.254 dev eth0 proto dhcp metric 10\n"
        "unreachable 198.51.100.0/24 proto static\nbroken line\nnot-a-prefix dev eth1\n"
        "@@route6\ndefault via fe80::1 dev eth0 proto ra metric 1024\n"
        "@@addr\n2: eth0    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0\\ x\n"
        "2: eth0    inet6 fe80::1/64 scope link \\ x\n"
        "3: eth1    inet6 2001:db8::5/64 scope global \\ x\n"
        "1: lo    inet 127.0.0.1/8 scope host lo\\ x\n@@end\n"
    )
    routes = parse.routes(a)
    assert [(str(r.destination), r.kind) for r in routes] == [
        ("0.0.0.0/0", "unicast"),
        ("198.51.100.0/24", "unreachable"),
        ("::/0", "unicast"),
    ]
    assert routes[0].metric == 10 and str(routes[2].gateway) == "fe80::1"
    assert {k: [str(x) for x in v] for k, v in parse.addresses(a).items()} == {
        "eth0": ["192.0.2.5/24"],
        "eth1": ["2001:db8::5/64"],
    }


def test_firewall_helpers() -> None:
    assert firewall._ports("22,80-90,ssh") == (
        [
            firewall.PortRange(start=22),
            firewall.PortRange(start=80, end=90),
            firewall.PortRange(start=22),
        ],
        True,
    )
    ports, exact = firewall._ports("!22,nonsense")
    assert ports == [] and exact is False
    assert firewall._ports(None) == ([], True)
    nets, negated, ok = firewall._networks("!192.0.2.0/24")
    assert [str(n) for n in nets] == ["192.0.2.0/24"] and negated and ok
    assert firewall._networks("192.0.2.1-192.0.2.9")[2] is False
    assert _endpoint("[2001:db8::1]:51820") == ("2001:db8::1", 51820)
    assert _endpoint("vpn.example:51820") == ("vpn.example", 51820)
    assert _endpoint("vpn.example") == ("vpn.example", None)
    assert _endpoint(None) == (None, None)


def test_rule_options_make_a_rule_inexact_or_unusable() -> None:
    root = tree.parse(
        "set firewall name X default-action reject\n"
        "set firewall name X rule 1 action inspect\n"
        "set firewall name X rule 2 action drop\n"
        "set firewall name X rule 2 protocol !tcp\n"
        "set firewall name X rule 2 disable\n"
        "set firewall name X rule 3 action accept\n"
        "set firewall name X rule 3 protocol 47\n"
        "set firewall name X rule 3 source group address-group G\n"
        "set firewall name X rule 4 action accept\n"
        "set firewall name X rule 4 destination port 53\n"
        "set firewall name X rule 5 action accept\n"
        "set firewall name X rule 5 protocol icmp\n"
        "set firewall name X rule 5 state new enable\n"
        "set firewall name X rule 5 state established enable\n"
        "set interfaces ethernet eth1 firewall out name X\n"
        "set interfaces ethernet eth1 vif 5 firewall local name X\n"
        "set service nat rule 1 type destination\n"
        "set service nat rule 2 type source\n"
        "set service nat rule 2 source address !192.0.2.0/24\n"
    )
    found = firewall.filter_rules(root, vyos_14=False)
    by_name = {r.name: r for r in found.rules}
    assert "X 1" not in by_name  # inspect is no allow or deny
    two = by_name["X 2"]
    assert two.enabled is False and two.exact is False
    three = by_name["X 3"]
    assert three.protocols == [FirewallProtocol.OTHER] and three.exact is False
    four = by_name["X 4"]  # ports without a protocol: TCP and UDP
    assert four.protocols == [FirewallProtocol.TCP, FirewallProtocol.UDP]
    assert by_name["X 5"].exact is False  # new and established
    assert by_name["X default"].action is FirewallAction.REJECT
    # `out` puts the interface into the destination of the rule
    assert by_name["X 4"].destination.zones == ["eth1"]
    assert found.zone_names == {"eth1", "eth1.5"}
    nat = firewall.nat(root)
    assert nat.complete is False and nat.forwards == [] and nat.nat == []
    assert firewall.filter_rules(root, vyos_14=True).complete is False


def test_pools_of_both_spellings() -> None:
    root = tree.parse(
        "set a start 192.0.2.10 stop 192.0.2.20\n"
        "set a range 0 start 192.0.2.30\n"
        "set a range 0 stop 192.0.2.40\n"
        "set a range 1 start 192.0.2.50\n"
        "set a range 2 start 192.0.2.60 \n"
        "set a range 2 stop 2001:db8::1\n"
    )
    pools = _pools(root.get("a") or tree.Node())
    assert [(str(p.start), str(p.end)) for p in pools] == [
        ("192.0.2.10", "192.0.2.20"),
        ("192.0.2.30", "192.0.2.40"),
    ]
