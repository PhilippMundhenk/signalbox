"""Linux gateway integration (#240) against the SSH simulator."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

import asyncssh
import pytest
from pydantic import SecretStr, ValidationError

from signalbox.adapters import AdapterContext, load_adapters
from signalbox.adapters.linux import (
    LinuxAdapter,
    LinuxConfig,
    collect,
    dhcp,
    parse,
    syslog,
    wireguard,
)
from signalbox.adapters.linux.collect import FORBIDDEN, split
from signalbox.adapters.linux.setup import SUDOERS_PATH, sudoers
from signalbox.adapters.ssh import host_key_sha256, load_private_key, sha256_hex
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    LeaseState,
    Membership,
    PortKind,
    PortRole,
    RaMode,
    StorageKind,
    UplinkKind,
)
from signalbox.sim import linux as sim
from signalbox.sim.linux import LinuxSim, User, serve_ssh
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
async def adapter_for(
    box: LinuxSim,
    *,
    role: DeviceRole = DeviceRole.GATEWAY,
    pin: str | None = "auto",
    **cfg: Any,
) -> AsyncIterator[LinuxAdapter]:
    async with serve_ssh(box) as (port, fingerprint):
        settings: dict[str, Any] = {
            "host": "127.0.0.1",
            "port": port,
            "username": "signalbox",
            "private_key": PRIVATE,
        } | cfg
        ctx = AdapterContext(
            site_id="home",
            device_id="gw2",
            device_name="gw2",
            role=role,
            config=LinuxConfig(**settings),
            pinned_fingerprint=sha256_hex(fingerprint) if pin == "auto" else pin,
            timeout=5,
        )
        adapter = LinuxAdapter(ctx)
        try:
            yield adapter
        finally:
            await adapter.close()


async def test_registered() -> None:
    assert load_adapters()["linux"] is LinuxAdapter


async def test_contract_and_values() -> None:
    box = device()
    async with adapter_for(box) as adapter:
        snap = await assert_contract(adapter)
    d = snap.device
    assert d.model == "Raspberry Pi 5 Model B Rev 1.0" and d.vendor == "Raspberry Pi"
    assert d.firmware is not None and d.firmware.current == "Debian GNU/Linux 12 (bookworm)"
    assert d.transport_encrypted is True
    # br0's table (#160): no multicast, no entries of a port's own list, no unknown port
    assert [(e.port_id, e.mac, e.kind.value, e.age_seconds) for e in snap.fdb] == [
        ("gw2/port/br0", "02:5b:00:00:00:02", "self", None),
        ("gw2/port/eth1", "02:00:00:00:00:10", "dynamic", 4),
        ("gw2/port/eth1", "02:00:00:00:00:44", "static", None),
        ("gw2/port/eth1", "02:5b:00:00:00:02", "self", None),
        ("gw2/port/wlan0", "02:00:00:00:00:21", "dynamic", 31),
    ]
    ports = {p.name: p for p in snap.ports}
    assert "lo" not in ports
    assert ports["eth0"].role is PortRole.JACK and ports["eth0"].speed_mbps == 1000
    assert ports["br0"].role is PortRole.BRIDGE and ports["br0"].kind is PortKind.BRIDGE
    assert ports["br0"].lower == ["gw2/port/eth1", "gw2/port/wlan0"]
    assert ports["wlan0"].role is PortRole.WIRELESS
    assert ports["eth1.30"].role is PortRole.VLAN and ports["eth1.30"].lower == ["gw2/port/eth1"]
    assert ports["wg0"].role is PortRole.TUNNEL and ports["wg0"].up is True
    (tunnel,) = snap.tunnels
    assert tunnel.id == "gw2/tunnel/wg0" and tunnel.port_id == "gw2/port/wg0"
    assert tunnel.public_key == sim.GW_KEY and tunnel.listen_port == 51820 and tunnel.up
    assert [str(a) for a in tunnel.addresses] == ["203.0.113.250/30"] and tunnel.mtu == 1420
    peers = {p.public_key: p for p in tunnel.peers}
    site = peers[sim.PEER_KEY]
    assert (site.endpoint_host, site.endpoint_port) == ("203.0.113.1", 51820)
    assert [str(n) for n in site.allowed_ips] == ["203.0.113.249/32", "198.51.100.128/25"]
    assert site.latest_handshake == datetime.fromtimestamp(sim.NOW - 42, UTC)
    assert (site.rx_bytes, site.tx_bytes, site.keepalive_seconds) == (123456, 654321, 25)
    assert site.preshared_key is None  # never read
    phone = peers[sim.PHONE_KEY]
    assert phone.endpoint_host is None and phone.latest_handshake is None
    assert phone.keepalive_seconds == 0
    assert [str(n) for n in tunnel.remote_networks(site)] == ["198.51.100.128/25"]
    segs = {s.id: s for s in snap.segments}
    native = segs["home/segment/native"]
    assert {(m.port_id, m.mode) for m in native.members} == {
        ("gw2/port/eth1", Membership.UNTAGGED),
        ("gw2/port/wlan0", Membership.UNTAGGED),
    }
    assert [(m.port_id, m.mode) for m in segs["home/segment/30"].members] == [
        ("gw2/port/eth1", Membership.TAGGED)
    ]
    assert {str(s.interface) for s in snap.subnets} == {
        "192.0.2.1/25",
        "2001:db8:1::1/64",
        "192.0.2.129/26",
    }
    assert all(s.gateway for s in snap.subnets)
    (up,) = snap.uplinks
    assert up.kind is UplinkKind.DHCP and up.port_id == "gw2/port/eth0"
    assert up.upstream_gateway == ip_address("198.51.100.1")
    assert [str(a) for a in up.addresses] == ["198.51.100.2/24"]
    (ssh,) = snap.services
    assert ssh.enabled and ssh.port == 22 and ssh.password_login is False
    assert ssh.root_login is True and ssh.root_password_login is False
    servers = {s.segment_id: s for s in snap.dhcp_servers}
    lan = servers["home/segment/native"]
    assert lan.enabled and lan.lease_seconds == 43200 and lan.authoritative is True
    assert lan.router == ip_address("192.0.2.1") and lan.domain == "home.example"
    assert lan.ntp_servers == [ip_address("192.0.2.1")]
    assert lan.search_domains == ["home.example", "lab.example"]
    assert [(o.code, o.value) for o in lan.options] == [(252, "http://192.0.2.1/wpad.dat")]
    assert [str(r.address) for r in lan.reservations] == ["192.0.2.10"]
    assert lan.leases is not None and {str(x.address): x.reserved for x in lan.leases} == {
        "192.0.2.10": True,
        "192.0.2.61": False,
    }
    iot = servers["home/segment/30"]
    assert iot.router == ip_address("192.0.2.129") and iot.lease_seconds == 3600
    assert [str(x.address) for x in iot.leases or []] == ["192.0.2.141"]
    dns = {s.name: s for s in snap.dns_services}
    assert set(dns) == {"dnsmasq"}
    assert [str(f) for f in dns["dnsmasq"].forwarders] == ["203.0.113.53"]
    assert {h.name for h in dns["dnsmasq"].host_records} == {
        "nas.home.example",
        "router.home.example",
    }
    health = d.health
    assert health is not None and health.cpu_count == 4 and health.uptime_seconds == 273906
    assert health.memory_used_bytes == (8245136 - 7012345) * 1024
    kinds = {s.name: s.kind for s in health.storage}
    assert kinds == {
        "/": StorageKind.SYSTEM,
        "/dev/shm": StorageKind.TEMPORARY,
        "/run": StorageKind.TEMPORARY,
        "/boot/firmware": StorageKind.OTHER,
    } or kinds == {
        "/": StorageKind.SYSTEM,
        "/run": StorageKind.TEMPORARY,
        "/boot/firmware": StorageKind.OTHER,
    }
    assert health.temperatures[0].value_c == 48.25
    t = d.time
    assert t is not None and t.timezone == "Europe/Berlin"
    assert t.clock == datetime.fromtimestamp(sim.NOW + 0.25, UTC)
    assert t.ntp_client is not None and t.ntp_client.synchronised is True
    assert t.ntp_client.servers == ["2.debian.pool.ntp.org", "203.0.113.123"]
    assert t.ntp_client.current_server == "203.0.113.123" and t.ntp_client.stratum == 2
    assert t.ntp_server is not None and t.ntp_server.enabled is True
    # nothing that prints a private key was sent
    assert box.scripts and not any(w in s for s in box.scripts for w in FORBIDDEN)


async def test_wireguard_without_sudoers_is_a_gap() -> None:
    box = device()
    box.sudoers_files.clear()
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL
    err = next(e for e in snap.errors if e.capability == "vpn")
    assert "wg show" in err.message and err.fix and "sudoers" in err.fix
    assert {e.capability for e in snap.errors} == {"vpn", "firewall"}
    assert snap.firewalls == []  # not read: never "filters nothing"
    (tunnel,) = snap.tunnels
    assert tunnel.public_key is None and tunnel.peers == [] and tunnel.up is True


async def test_wireguard_with_the_sudoers_rule() -> None:
    box = device()
    async with adapter_for(box) as adapter:
        snap = await assert_contract(adapter)
    (tunnel,) = snap.tunnels
    assert len(tunnel.peers) == 2 and tunnel.listen_port == 51820


async def test_role_other_has_no_uplink_and_eth0_is_a_network() -> None:
    async with adapter_for(device(), role=DeviceRole.OTHER) as adapter:
        snap = await assert_contract(adapter)
    assert snap.uplinks == []
    assert "198.51.100.2/24" in {str(s.interface) for s in snap.subnets}
    assert not any(s.gateway for s in snap.subnets)


async def test_untrusted_host_key_then_trusted() -> None:
    box = device()
    async with adapter_for(box, pin=None) as adapter:
        snap = await adapter.observe()
        assert snap.status is DeviceStatus.UNTRUSTED
        presented = adapter.presented_fingerprint
        assert presented is not None and len(presented) == 64
        assert "ssh-keygen" in snap.errors[0].message
    async with adapter_for(box, pin="0" * 64) as adapter:
        snap = await adapter.observe()
        assert snap.status is DeviceStatus.UNTRUSTED
        assert "different" in snap.errors[0].message
    assert box.scripts == []  # nothing was sent to an untrusted host


async def test_wrong_key_and_password_login() -> None:
    box = device()
    other = asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()
    async with adapter_for(box, private_key=other) as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.AUTH_FAILED and "signalbox" in snap.errors[0].message
    box.users["signalbox"].password = "example-read-password"
    async with adapter_for(box, private_key=None, password="example-read-password") as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.OK


async def test_bad_key_and_incomplete_answer() -> None:
    async with adapter_for(device(), private_key="not a key") as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.UNREACHABLE and "private key" in snap.errors[0].message
    assert "not a key" not in snap.errors[0].message

    class Broken(LinuxSim):
        def read(self, user: str, script: str) -> str:
            return "@@os\n"

    box = Broken()
    box.users["signalbox"] = User(keys=[PUBLIC])
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.UNREACHABLE and "completely" in snap.errors[0].message


def test_config() -> None:
    cfg = LinuxConfig(host="ssh://192.0.2.1/", password=SecretStr("x"))
    assert cfg.host == "192.0.2.1" and cfg.port == 22
    with pytest.raises(ValidationError):
        LinuxConfig(host="192.0.2.1")
    with pytest.raises(ValidationError):
        LinuxConfig(host=" ", password=SecretStr("x"))


def test_key_without_line_breaks() -> None:
    flat = PRIVATE.replace("\n", "")
    assert load_private_key(flat).public_data == KEY.public_data
    spaced = PRIVATE.replace("\n", " ")
    assert load_private_key(spaced).public_data == KEY.public_data
    with pytest.raises(ValueError, match="cannot be read"):
        load_private_key("-----BEGIN OPENSSH PRIVATE KEY-----abc-----END OPENSSH PRIVATE KEY-----")


def test_fingerprint_forms() -> None:
    fp = KEY.get_fingerprint("sha256")
    assert sha256_hex(fp) == host_key_sha256(KEY)
    assert sha256_hex("abc") is None and sha256_hex("SHA256:!!") is None


def test_read_script_never_prints_keys() -> None:
    for script in (collect.READ, collect.TIME):
        assert not any(w in script for w in FORBIDDEN)
    for f in collect.WG_FIELDS:
        assert f"show all {f}" in collect.READ


# --- parsers ---------------------------------------------------------------------------------


def answer(**sections: str) -> collect.Answer:
    return split(
        "".join(f"@@{k.replace('_', '-')}\n{v}\n" for k, v in sections.items()) + "@@end\n"
    )


def test_answer_files_and_unreadable() -> None:
    a = split("@@kea\n@@@ /a\none\ntwo\n@@! /b\n@@end\n")
    assert a.files("kea") == {"/a": "one\ntwo\n"} and a.unreadable("kea") == ["/b"]
    assert a.complete() and not split("@@x\n").complete()


def test_roles_of_other_links() -> None:
    import json

    rows = [
        {"ifname": "eth0", "link_type": "ether", "flags": ["UP"], "operstate": "UP"},
        {
            "ifname": "lan1",
            "link_type": "ether",
            "linkinfo": {"info_kind": "dsa", "info_data": {"conduit": "eth0"}},
        },
        {"ifname": "bond0", "linkinfo": {"info_kind": "bond"}},
        {"ifname": "eth2", "master": "bond0"},
        {"ifname": "veth1", "link_netnsid": 0},
        {"ifname": "dummy0", "linkinfo": {"info_kind": "dummy"}},
        {"ifname": "ppp0", "link_type": "ppp"},
        {"ifname": "odd", "linkinfo": {"info_kind": "something"}},
        {"ifname": "plain", "link_type": "ether"},
    ]
    a = answer(link=json.dumps(rows), sysnet="eth2 1 0 - -")
    links = parse.links(a)
    sys = parse.sysnet(a)
    conduits = {"eth0"}
    roles = {n: parse.role_of(x, sys.get(n), conduits)[0] for n, x in links.items()}
    assert roles == {
        "eth0": PortRole.CPU,
        "lan1": PortRole.JACK,
        "bond0": PortRole.LAG,
        "eth2": PortRole.JACK,
        "veth1": PortRole.VIRTUAL,
        "dummy0": PortRole.VIRTUAL,
        "ppp0": PortRole.TUNNEL,
        "odd": PortRole.VIRTUAL,
        "plain": None,
    }
    assert links["lan1"].parent == "eth0"


def test_bridge_vlans_both_shapes() -> None:
    new = (
        '[{"ifname":"eth1","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]},'
        '{"vlan":20,"vlanEnd":21}]}]'
    )
    old = '{"eth1":[{"vlan":1,"flags":["PVID","Egress Untagged"]}]}'
    assert parse.bridge_vlans(answer(bridge_vlan=new)) == {
        "eth1": [(1, True, True), (20, False, False), (21, False, False)]
    }
    assert parse.bridge_vlans(answer(bridge_vlan=old)) == {"eth1": [(1, True, True)]}


async def test_vlan_filtering_bridge() -> None:
    import json

    box = device()
    links = sim.default_links()
    for row in links:
        if row["ifname"] == "br0":
            row["linkinfo"]["info_data"]["vlan_filtering"] = 1
        if row["ifname"] == "eth1.30":
            row["ifname"] = "br0.30"
            row["link"] = "br0"
    box.sections["link"] = json.dumps(links)
    addrs = sim.default_addresses()
    for row in addrs:
        if row["ifname"] == "eth1.30":
            row["ifname"] = "br0.30"
    box.sections["addr"] = json.dumps(addrs)
    box.sections["bridge-vlan"] = json.dumps(
        [
            {
                "ifname": "eth1",
                "vlans": [{"vlan": 1, "flags": ["PVID", "Egress Untagged"]}, {"vlan": 30}],
            },
            {"ifname": "wlan0", "vlans": [{"vlan": 1, "flags": ["PVID", "Egress Untagged"]}]},
            {"ifname": "br0", "vlans": [{"vlan": 1, "flags": ["PVID", "Egress Untagged"]}]},
        ]
    )
    async with adapter_for(box) as adapter:
        snap = await assert_contract(adapter)
    segs = {s.id: s for s in snap.segments}
    assert [(m.port_id, m.mode) for m in segs["home/segment/30"].members] == [
        ("gw2/port/eth1", Membership.TAGGED)
    ]
    assert {m.port_id for m in segs["home/segment/native"].members} == {
        "gw2/port/eth1",
        "gw2/port/wlan0",
    }


def test_listeners_and_running() -> None:
    a = answer(
        listen="tcp LISTEN 0 128 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 128 [::]:2222 [::]:*\n"
        "tcp LISTEN 0 1 x:y 0:0\nudp UNCONN 0 0 bad:53 *:*\nraw x",
        units="ssh inactive disabled\nchronyd active alias",
        procs="sshd\nAdGuardHome",
    )
    ls = parse.listeners(a)
    assert [(x.address, x.port) for x in ls] == [(ip_address("127.0.0.53"), 53), (None, 2222)]
    assert parse.services_running(a) == {"chrony", "ssh", "AdGuardHome"}


def test_sshd_include_first_value_and_match() -> None:
    a = answer(
        sshd="@@@ /etc/ssh/sshd_config\nPort 22\nPort 2222\nInclude sshd_config.d/*.conf\n"
        "PasswordAuthentication no\nListenAddress 192.0.2.1:22\nMatch User x\n"
        "PermitRootLogin no\n@@@ /etc/ssh/sshd_config.d/a.conf\nPasswordAuthentication yes\n"
        "PermitRootLogin yes\n"
    )
    s = parse.sshd_settings(a)
    assert s["port"] == ["22", "2222"] and s["passwordauthentication"] == ["yes"]
    assert s["permitrootlogin"] == ["yes"] and s["listenaddress"] == ["192.0.2.1:22"]


async def test_ssh_on_two_ports_with_root_password() -> None:
    box = device()
    box.sections["sshd"] = (
        "@@@ /etc/ssh/sshd_config\nPort 22\nPort 2222\nPermitRootLogin yes\n"
        "ListenAddress 192.0.2.1\nListenAddress [2001:db8:1::1]:22\n"
    )
    async with adapter_for(box) as adapter:
        obs = await adapter.read_system() and await adapter.read_interfaces()
    by = {s.id: s for s in obs.services}
    assert set(by) == {"gw2/service/ssh", "gw2/service/ssh-2222"}
    ssh = by["gw2/service/ssh"]
    assert ssh.root_password_login is True and ssh.password_login is True
    assert ssh.listen == [ip_address("192.0.2.1"), ip_address("2001:db8:1::1")]
    assert by["gw2/service/ssh-2222"].enabled  # ssh.service is active


def test_health_parsers_edge_cases() -> None:
    a = answer(
        uptime="x", loadavg="1", meminfo="MemTotal: 100 kB", df="", thermal="z\nt x\nt 1000\nt 2000"
    )
    assert parse.uptime(a) is None and parse.load_average(a) is None
    assert parse.memory(a) == (102400, None)
    assert [t.name for t in parse.temperatures(a)] == ["t", "t-2"]
    assert parse.forwarding(answer()) is None


def test_hardware_from_dmi_and_resolvers() -> None:
    a = answer(
        model="@@@ /sys/class/dmi/id/sys_vendor\nExample Corp\n"
        "@@@ /sys/class/dmi/id/product_name\nMini PC\n",
        resolv="@@@ /etc/resolv.conf\nnameserver 127.0.0.53\nnameserver 192.0.2.53\n"
        "nameserver fe80::1%eth0\nnameserver bad\n",
    )
    assert parse.hardware(a) == ("Example Corp", "Mini PC")
    assert parse.resolvers(a) == [ip_address("192.0.2.53"), ip_address("fe80::1")]


def test_dnsmasq_parser_details() -> None:
    conf = (
        "port=5353\n# c\ndhcp-range=interface:eth1,192.0.2.10,static,255.255.255.0\n"
        "dhcp-range=192.0.2.100,192.0.2.150,infinite\ndhcp-range=::100,::1ff,constructor:eth1\n"
        "dhcp-range=198.51.100.10,198.51.100.20,30m\n"
        "dhcp-option=3,192.0.2.254\ndhcp-option=option:dns-server,192.0.2.53,192.0.2.54\n"
        "dhcp-option=option:classless-static-route,198.51.100.0/24,192.0.2.1\n"
        "dhcp-option=option6:dns-server,[2001:db8::1]\ndhcp-option=option:unknownname,1\n"
        "dhcp-option=999,x\ndhcp-option=26,1400\ndhcp-option=15,example.net\n"
        "dhcp-host=02:00:00:00:00:01,192.0.2.11,cam,infinite\ndhcp-host=bad,192.0.2.12\n"
        "host-record=a.example,b.example,192.0.2.5\naddress=/#/0.0.0.0\n"
    )
    m = dhcp.parse_dnsmasq({"/etc/dnsmasq.conf": conf})
    assert m.port == 5353
    assert [s.key for s in m.scopes] == ["dnsmasq-0", "dnsmasq-1", "dnsmasq-3"]
    static, endless, short = m.scopes
    assert static.pools == [] and static.interface == "eth1"
    assert static.network == ip_network("192.0.2.0/24")
    assert endless.lease_seconds is None and short.lease_seconds == 1800
    assert endless.router == ip_address("192.0.2.254")
    assert endless.dns == [ip_address("192.0.2.53"), ip_address("192.0.2.54")]
    assert [str(r.destination) for r in endless.routes] == ["198.51.100.0/24"]
    assert [(o.code, o.value) for o in endless.options] == [(26, "1400")]
    assert endless.domain == "example.net"
    assert [r.hostname for r in endless.reservations] == ["cam"]
    assert [h.name for h in m.hosts] == ["a.example"]
    assert dhcp.duration("2w") == 1209600 and dhcp.duration("x") is None


def test_dnsmasq_leases_ipv6_and_junk() -> None:
    text = (
        "0 02:00:00:00:00:01 192.0.2.5 * *\nx y z\n1 bad 192.0.2.6 * *\n"
        "1 02:00:00:00:00:02 bad * *\n"
        "duid 00:01:00:01\n1795400000 12345 2001:db8:1::50 host 00:01:00:01:aa\n"
    )
    leases = dhcp.dnsmasq_leases(text)
    assert [(str(x.address), x.expires, x.client_id) for x in leases] == [
        ("192.0.2.5", None, None),
        ("2001:db8:1::50", datetime.fromtimestamp(1795400000, UTC), "00:01:00:01:aa"),
    ]


KEA = """// Kea, comment
{ "Dhcp4": {
  # another comment
  "interfaces-config": {"interfaces": ["eth1/192.0.2.1"]},
  "valid-lifetime": 7200, /* block
  comment */
  "option-data": [{"name": "domain-name-servers", "data": "192.0.2.1, 192.0.2.2"}],
  "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_ha.so", "parameters": {
     "high-availability": [{"this-server-name": "gw2", "peers": [
        {"name": "gw2", "role": "primary"}, {"name": "gw3", "role": "standby"}]}]}}],
  "subnet4": [{"id": 1, "subnet": "192.0.2.0/25", "pools": [{"pool": "192.0.2.50 - 192.0.2.99"},
     {"pool": "192.0.2.112/28"}],
     "option-data": [{"name": "routers", "data": "192.0.2.1"}, {"code": 252, "data": "http://x//y"},
       {"name": "domain-search", "data": "home.example"}, {"space": "x", "name": "y", "data": "z"}],
     "reservations": [{"hw-address": "02:00:00:00:00:10", "ip-address": "192.0.2.10",
       "hostname": "printer"},
       {"hw-address": "zz"}]},
    {"subnet": "nonsense"}],
  "shared-networks": [{"interface": "eth1.30", "authoritative": true,
     "subnet4": [{"id": 2, "subnet": "192.0.2.128/26"}]}]
}}"""

KEA_LEASES = (
    "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,"
    "state,user_context\n"
    """192.0.2.50,02:00:00:00:00:21,,7200,1795407200,1,0,0,laptop.,0,
192.0.2.51,02:00:00:00:00:22,,7200,1795407200,1,0,0,,1,
192.0.2.50,02:00:00:00:00:21,,7200,1795409000,1,0,0,laptop,0,
192.0.2.52,,,7200,1795407200,1,0,0,,0,
bad,,,,,,,,,,
192.0.2.140,02:00:00:00:00:31,,3600,0,2,0,0,,2,
"""
)


def test_kea() -> None:
    k = dhcp.parse_kea(KEA)
    assert k.error is None and k.interfaces == ["eth1"]
    one, two = k.scopes
    assert one.pools == [
        (ip_address("192.0.2.50"), ip_address("192.0.2.99")),
        (ip_address("192.0.2.112"), ip_address("192.0.2.127")),
    ]
    assert one.lease_seconds == 7200 and one.router == ip_address("192.0.2.1")
    assert one.dns == [ip_address("192.0.2.1"), ip_address("192.0.2.2")]
    assert [(o.code, o.value) for o in one.options] == [(252, "http://x//y")]
    assert one.search == ["home.example"] and one.failover_peer == "gw3"
    assert [r.hostname for r in one.reservations] == ["printer"]
    assert two.interface == "eth1.30" and two.authoritative is True
    rows = dhcp.kea_leases(KEA_LEASES)
    by = {str(x.address): (sid, x) for sid, x in rows}
    assert set(by) == {"192.0.2.50", "192.0.2.51", "192.0.2.140"}
    assert by["192.0.2.50"][1].expires == datetime.fromtimestamp(1795409000, UTC)
    assert by["192.0.2.51"][1].state is LeaseState.DECLINED
    assert by["192.0.2.140"][1].state is LeaseState.EXPIRED and by["192.0.2.140"][0] == 2
    assert dhcp.parse_kea("{").error and dhcp.parse_kea("{}").error


ISC = """# ISC dhcpd
authoritative;
default-lease-time 600;
option domain-name "home.example";
failover peer "dhcp-failover" { primary; address 192.0.2.1; }
subnet 192.0.2.0 netmask 255.255.255.128 {
  range 192.0.2.50 192.0.2.99;
  option routers 192.0.2.1;
  option domain-name-servers 192.0.2.1, 192.0.2.2;
  option ntp-servers 192.0.2.1;
  pool { failover peer "dhcp-failover"; range 192.0.2.100 192.0.2.110; }
  host printer { hardware ethernet 02:00:00:00:00:10; fixed-address 192.0.2.10; }
}
shared-network iot {
  subnet 192.0.2.128 netmask 255.255.255.192 { range 192.0.2.140; not authoritative; }
}
subnet bad netmask x { }
group { host cam { hardware ethernet 02:00:00:00:00:11; fixed-address 192.0.2.141; } }
"""

ISC_LEASES = """# leases
lease 192.0.2.60 {
  starts 1 2026/11/23 10:00:00;
  ends 1 2026/11/23 10:10:00;
  binding state active;
  hardware ethernet 02:00:00:00:00:21;
  client-hostname "laptop";
}
lease 192.0.2.61 { starts epoch 1795400000; ends never; binding state free; uid "\\001\\002"; }
lease 192.0.2.62 { binding state abandoned; }
lease bad { hardware ethernet 02:00:00:00:00:22; }
"""


def test_isc() -> None:
    lan, iot = dhcp.parse_isc(ISC)
    assert lan.authoritative is True and lan.lease_seconds == 600
    assert lan.pools == [
        (ip_address("192.0.2.50"), ip_address("192.0.2.99")),
        (ip_address("192.0.2.100"), ip_address("192.0.2.110")),
    ]
    assert lan.failover_peer == "dhcp-failover" and lan.domain == "home.example"
    assert lan.dns == [ip_address("192.0.2.1"), ip_address("192.0.2.2")]
    assert [r.hostname for r in lan.reservations] == [None]
    assert iot.authoritative is False and iot.pools == [(ip_address("192.0.2.140"),) * 2]
    assert [str(r.address) for r in iot.reservations] == ["192.0.2.141"]
    leases = {str(x.address): x for x in dhcp.isc_leases(ISC_LEASES)}
    assert set(leases) == {"192.0.2.60", "192.0.2.61"}
    assert leases["192.0.2.60"].hostname == "laptop" and leases["192.0.2.60"].expires
    assert leases["192.0.2.61"].state is LeaseState.EXPIRED and leases["192.0.2.61"].expires is None


def test_networkd() -> None:
    files = {
        "/etc/systemd/network/10-lan.network": "[Match]\nName=br*\n[Network]\nAddress=fd00::1/64\n"
        "Address=192.0.2.1/25\nDHCPServer=yes\n[DHCPServer]\nPoolOffset=50\nPoolSize=40\n"
        "DefaultLeaseTimeSec=12h\nDNS=192.0.2.53\nEmitNTP=no\n[DHCPServerStaticLease]\n"
        "MACAddress=02:00:00:00:00:10\nAddress=192.0.2.10\n",
        "/run/systemd/network/10-lan.network": "[Network]\nDHCPServer=yes\n"
        "Address=198.51.100.1/24\n",
        "/etc/systemd/network/20-iot.network": "# c\n[Match]\nName=eth1.30\n[Network]\n"
        "Address=192.0.2.129/26\nDHCPServer=true\n[DHCPServer]\nEmitRouter=no\n",
        "/etc/systemd/network/30-wan.network": "[Network]\nDHCP=yes\n",
        "/etc/systemd/network/40-x.network": "[Network]\nDHCPServer=yes\n",
    }
    lan, iot = dhcp.parse_networkd(files, ["br0", "eth1.30"])
    assert lan.interface == "br0" and lan.lease_seconds == 43200
    assert lan.pools == [(ip_address("192.0.2.50"), ip_address("192.0.2.89"))]
    assert lan.router == ip_address("192.0.2.1") and lan.dns == [ip_address("192.0.2.53")]
    assert [str(r.address) for r in lan.reservations] == ["192.0.2.10"]
    assert iot.router is None and iot.pools == [
        (ip_address("192.0.2.129"), ip_address("192.0.2.190"))
    ]


async def test_kea_isc_networkd_on_the_device() -> None:
    box = device()
    box.sections["dnsmasq"] = ""
    box.sections["dnsmasq-leases"] = ""
    box.sections["kea"] = f"@@@ /etc/kea/kea-dhcp4.conf\n{KEA}\n"
    box.sections["kea-leases"] = "@@! /var/lib/kea/kea-leases4.csv\n"
    box.sections["units"] += "kea-dhcp4-server active enabled\n"
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    servers = {s.id: s for s in snap.dhcp_servers}
    assert set(servers) == {"gw2/dhcp/kea-1", "gw2/dhcp/kea-2"}
    assert servers["gw2/dhcp/kea-2"].segment_id == "home/segment/30"
    assert servers["gw2/dhcp/kea-1"].leases is None
    assert any("kea-leases4.csv" in e.message for e in snap.errors)

    box.sections["kea"] = ""
    box.sections["kea-leases"] = ""
    box.sections["isc"] = f"@@@ /etc/dhcp/dhcpd.conf\n{ISC}\n"
    box.sections["isc-leases"] = f"@@@ /var/lib/dhcp/dhcpd.leases\n{ISC_LEASES}\n"
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    isc = {s.id: s for s in snap.dhcp_servers}
    assert [str(x.address) for x in isc["gw2/dhcp/isc-0"].leases or []] == [
        "192.0.2.60",
        "192.0.2.61",
    ]
    assert isc["gw2/dhcp/isc-0"].enabled is False  # isc-dhcp-server is not running

    box.sections["isc"] = box.sections["isc-leases"] = ""
    box.sections["networkd"] = (
        "@@@ /etc/systemd/network/br0.network\n[Match]\nName=br0\n[Network]\nAddress=192.0.2.1/25\n"
        "DHCPServer=yes\n@@@ /etc/systemd/network/x.network\n[Network]\nAddress=203.0.113.9/24\n"
        "DHCPServer=yes\n"
    )
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    (nd,) = snap.dhcp_servers
    assert nd.segment_id == "home/segment/native" and nd.leases is None
    assert any("on no network" in e.message for e in snap.errors)


async def test_dns_services_recognised() -> None:
    box = device()
    box.sections["procs"] += "AdGuardHome\npihole-FTL\n"
    box.sections["present"] = "/etc/unbound/unbound.conf\n"
    box.sections["dnsmasq"] = "@@@ /etc/dnsmasq.conf\nserver=192.0.2.53#5353\nserver=bad\n"
    box.sections["resolv"] = "@@@ /etc/resolv.conf\nnameserver 192.0.2.53\nnameserver 192.0.2.54\n"
    box.sections["units"] = box.sections["units"].replace("dnsmasq active", "dnsmasq inactive")
    box.sections["procs"] = box.sections["procs"].replace("dnsmasq\n", "")
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_dns()
        dhcp_obs = await adapter.read_dhcp()
    by = {s.name: s for s in obs.dns_services}
    assert set(by) == {"adguardhome", "pihole", "unbound"}  # Pi-hole runs its own dnsmasq
    assert not by["adguardhome"].config_read and by["adguardhome"].enabled
    assert by["unbound"].enabled is False
    assert dhcp_obs.dhcp_servers == []
    box.sections["procs"] = "dnsmasq\n"
    box.sections["present"] = ""
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_dns()
    (masq,) = obs.dns_services
    assert [str(f) for f in masq.forwarders] == ["192.0.2.53:5353", "192.0.2.53", "192.0.2.54"]


async def test_timesyncd_and_no_ntp() -> None:
    box = device()
    box.time.update(
        tracking="",
        sources="",
        chrony="",
        timedatectl="Timezone=UTC\nNTP=yes\nNTPSynchronized=no\n",
        timesync="SystemNTPServers=\nFallbackNTPServers=0.debian.pool.ntp.org\n"
        "ServerName=0.debian.pool.ntp.org\nServerAddress=203.0.113.5\n",
        timesyncd="@@@ /etc/systemd/timesyncd.conf\n[Time]\n#NTP=\n",
    )
    box.sections["units"] = box.sections["units"].replace("chrony active", "chrony inactive")
    box.sections["units"] = box.sections["units"].replace("chronyd active", "chronyd inactive")
    box.sections["procs"] = "sshd\n"
    async with adapter_for(box) as adapter:
        snap = await assert_contract(adapter)
    t = snap.device.time
    assert t is not None and t.timezone == "UTC" and t.ntp_server is None
    assert t.ntp_client is not None and t.ntp_client.synchronised is False
    assert t.ntp_client.servers == ["0.debian.pool.ntp.org"]
    assert t.ntp_client.current_server == "203.0.113.5"
    box.time.update(timesyncd="@@@ /etc/systemd/timesyncd.conf\nNTP=192.0.2.1 192.0.2.2\n")
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_time()
    nc = obs.time["gw2"].ntp_client
    assert nc is not None and nc.servers == ["192.0.2.1", "192.0.2.2"]
    box.time.update(timedatectl="NTP=no\n", timezone="/usr/share/zoneinfo/Asia/Tokyo\n", clock="x")
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_time()
    value = obs.time["gw2"]
    assert value.timezone == "Asia/Tokyo" and value.clock is None
    assert value.ntp_client is not None and value.ntp_client.enabled is False
    box.time.update(timedatectl="", timezone="")
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_time()
    assert obs.time["gw2"].ntp_client is None and obs.time["gw2"].timezone is None


def test_wireguard_parser() -> None:
    a = answer(
        wg_public_key=f"wg0\t{sim.GW_KEY}\nwg1\tnot-a-key\n\t\n",
        wg_listen_port="wg0\t51820\nwg1\tx\nwg2\t0",
        wg_endpoints=f"wg0\t{sim.PEER_KEY}\t[2001:db8::1]:51820\nwg0\tbad\t1.2.3.4:1\n"
        f"wg0\t{sim.PHONE_KEY}\t192.0.2.1:x",
        wg_allowed_ips=f"wg0\t{sim.PEER_KEY}\t198.51.100.0/24 bad",
        wg_latest_handshakes=f"wg0\t{sim.PEER_KEY}\tx",
        wg_transfer=f"wg0\t{sim.PEER_KEY}\t1\tx",
        wg_persistent_keepalive=f"wg0\t{sim.PEER_KEY}\tx\nwg0\t{sim.PHONE_KEY}\t70000",
    )
    ifaces, denied = wireguard.read(a)
    assert not denied
    wg0 = ifaces["wg0"]
    assert wg0.public_key == sim.GW_KEY and wg0.listen_port == 51820
    assert ifaces["wg1"].public_key is None and ifaces["wg2"].listen_port is None
    peer = wg0.peers[sim.PEER_KEY]
    assert (peer.endpoint_host, peer.endpoint_port) == ("2001:db8::1", 51820)
    assert peer.allowed_ips == [ip_network("198.51.100.0/24")] and peer.rx_bytes is None
    assert wg0.peers[sim.PHONE_KEY].endpoint_host is None
    assert wg0.peers[sim.PHONE_KEY].keepalive_seconds is None
    assert wireguard.endpoint("(none)") == (None, None)
    assert wireguard.endpoint("h:99999") == ("h", None)


def test_global_addresses_and_network_of() -> None:
    link = parse.Link("x", {}, addresses=[ip_interface("127.0.0.1/8"), ip_interface("fe80::1/64")])
    assert parse.global_addresses(link) == []
    assert parse.network_of([ip_interface("192.0.2.1/24")], ip_address("2001:db8::1")) is None


# --- discovery -----------------------------------------------------------------------------


@asynccontextmanager
async def banner_server(line: bytes | None) -> AsyncIterator[int]:
    import asyncio

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if line is not None:
            writer.write(line)
            await writer.drain()
        else:
            await asyncio.sleep(3)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()


@pytest.mark.parametrize(
    ("line", "vendor"),
    [
        (b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n", "Debian"),
        (b"SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3\r\n", "Raspberry Pi OS"),
        (b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", "Ubuntu"),
        (b"SSH-2.0-dropbear_2024.86\r\n", None),
        (b"SSH-2.0-OpenSSH_9.7 FreeBSD-20240318\r\n", None),
        (b"", None),
    ],
)
async def test_discovery_banner(line: bytes, vendor: str | None) -> None:
    from signalbox.discovery import HostProbe, RateLimiter

    async with banner_server(line) as port:
        probe = HostProbe(
            "127.0.0.1", timeout=2, limiter=RateLimiter(1000), extra={"ports": {"linux.ssh": port}}
        )
        found = await LinuxAdapter.discover(probe)
        again = await probe.banner(port)  # cached: no second connection
        await probe.close()
    if vendor is None:
        assert found is None
    else:
        assert found is not None and found.vendor == vendor
        assert found.config == {"host": "127.0.0.1", "port": port}
        assert found.role is DeviceRole.OTHER and again and again.startswith("SSH-2.0")


async def test_discovery_silent_and_closed() -> None:
    from signalbox.discovery import HostProbe, RateLimiter
    from signalbox.sim.server import free_port

    async with banner_server(None) as port:
        probe = HostProbe(
            "127.0.0.1",
            timeout=0.3,
            limiter=RateLimiter(1000),
            extra={"ports": {"linux.ssh": port}},
        )
        assert await probe.banner(port) is None
        assert await probe.banner(port) is None
    closed = free_port()
    probe = HostProbe("127.0.0.1", timeout=1, limiter=RateLimiter(1000))
    assert await probe.banner(closed) is None
    probe.silent = True
    assert await probe.banner(free_port()) is None


# --- remote syslog (#180) --------------------------------------------------------------------


async def test_log_targets_from_rsyslog() -> None:
    async with adapter_for(device()) as adapter:
        await adapter.read_system()
        obs = await adapter.read_interfaces()
    (t,) = obs.log_targets["gw2"]
    assert (t.endpoint(), t.transport.value, t.topics, t.name) == (
        "192.0.2.5:514",
        "udp",
        ["*.info"],
        "rsyslog",
    )


async def test_log_targets_unreadable_or_not_collected() -> None:
    box = device()
    box.sections["syslog"] = "@@! /etc/rsyslog.conf\n"
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_interfaces()
    assert obs.log_targets == {}
    (gap,) = [g for g in obs.incomplete if g.message.startswith("log targets")]
    assert gap.optional
    box.sections["syslog"] = ""  # read, nothing configured (journald only)
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        assert (await adapter.read_interfaces()).log_targets == {"gw2": []}
        adapter._answer = split("@@os\n@@end\n")  # an answer without the section: not read
        assert adapter._log_targets([]) == {}


def test_rsyslog_and_syslog_ng_forms() -> None:
    rs = {
        "/etc/rsyslog.d/a.conf": "auth.* @@(o)[2001:db8::5]:1514\n# *.* @192.0.2.9\n"
        "*.* @@logs.example\n"
        'action(type="omfwd" target="192.0.2.7" port="6514" protocol="tcp" '
        'StreamDriver="gtls" StreamDriverMode="1")\n'
        'action(type="omfwd" target="192.0.2.8" protocol="tcp")\n'
        'action(type="omfwd" target="192.0.2.10")\n'
        'action(type="omfwd" port="1")\n',
    }
    got = [(t.endpoint(), t.transport.value) for t in syslog.targets(rs)]
    assert got == [
        ("[2001:db8::5]:1514", "tcp"),
        ("logs.example:514", "tcp"),
        ("192.0.2.7:6514", "tls"),
        ("192.0.2.8:514", "tcp"),
        ("192.0.2.10:514", "udp"),
    ]
    ng = {
        "/etc/syslog-ng/conf.d/remote.conf": 'destination d_net { network("192.0.2.5" '
        'transport("tls") port(6514)); };\n'
        'destination d_tcp { tcp("192.0.2.6"); };\n'
        'destination d_sys { syslog("192.0.2.7"); };\n'
        'destination d_udp { udp("192.0.2.8" port(1514)); };\n'
        'destination d_file { file("/var/log/x"); };\n'
        "log { source(s_src); destination(d_net); destination(d_udp); };\n"
    }
    got = [(t.name, t.endpoint(), t.transport.value, t.enabled) for t in syslog.targets(ng)]
    assert got == [
        ("d_net", "192.0.2.5:6514", "tls", True),
        ("d_tcp", "192.0.2.6:514", "tcp", False),
        ("d_sys", "192.0.2.7:514", "tcp", False),
        ("d_udp", "192.0.2.8:1514", "udp", True),
    ]


async def test_radvd_conf_is_read_as_router_advertisements() -> None:
    box = device()
    async with adapter_for(box) as adapter:
        await adapter.read_system()
        obs = await adapter.read_dhcp()
    [ra] = obs.router_adverts
    assert ra.mode is RaMode.STATELESS and ra.managed is False and ra.other is True
    assert ra.router_lifetime == 1800 and ra.dnssl == ["home.example"]
    assert [str(x) for x in ra.rdnss] == ["2001:db8:1::1"]
    [prefix] = ra.prefixes
    assert str(prefix.prefix) == "2001:db8:1::/64" and prefix.autonomous and prefix.on_link
    assert obs.dhcp6_servers == []


def test_radvd_and_dnsmasq_parsers() -> None:
    from signalbox.adapters.linux import ipv6

    [off] = ipv6.parse_radvd("interface eth0 { AdvSendAdvert off; };  # nothing\ninterface bad;\n")
    assert off.name == "eth0" and ipv6.mode_of(off) is RaMode.OFF
    [managed] = ipv6.parse_radvd(
        "interface eth1 {AdvSendAdvert on; AdvManagedFlag on; AdvOtherConfigFlag on;"
        " prefix 2001:db8:5::/64 { AdvAutonomous off; }; RDNSS 2001:db8:5::1 2001:db8:5::2 {};"
        " DNSSL a.example b.example {}; };"
    )
    assert ipv6.mode_of(managed) is RaMode.STATEFUL
    assert [(str(p), a, o) for p, o, a in managed.prefixes] == [("2001:db8:5::/64", False, True)]
    assert len(managed.rdnss) == 2 and managed.dnssl == ["a.example", "b.example"]
    conf = {
        "/etc/dnsmasq.conf": "enable-ra\n"
        "dhcp-range=::,constructor:eth0,ra-stateless,64,12h\n"
        "dhcp-range=2001:db8:6::100,2001:db8:6::1ff,64,1h\n"
        "dhcp-range=::,constructor:eth2,ra-only\n"
        "dhcp-option=option6:dns-server,[2001:db8:6::1]\n"
        "dhcp-range=192.0.2.50,192.0.2.100,12h\n"
    }
    stateless, stateful, only = ipv6.parse_dnsmasq6(conf)
    assert stateless.name == "eth0" and stateless.dhcpv6 and not stateless.dhcpv6_stateful
    assert ipv6.mode_of(stateless) is RaMode.STATELESS and stateless.lease_seconds == 43200
    assert stateful.name is None and str(stateful.network) == "2001:db8:6::/64"
    assert stateful.dhcpv6_stateful and stateful.pool is not None
    assert ipv6.mode_of(stateful) is RaMode.STATEFUL
    assert only.name == "eth2" and not only.dhcpv6 and ipv6.mode_of(only) is RaMode.SLAAC
    assert [str(a) for a in only.rdnss] == ["2001:db8:6::1"]
    [quiet] = ipv6.parse_dnsmasq6(
        {"/etc/dnsmasq.conf": "dhcp-range=::,constructor:eth0,ra-stateless"}
    )
    assert not quiet.send and ipv6.mode_of(quiet) is RaMode.OFF
