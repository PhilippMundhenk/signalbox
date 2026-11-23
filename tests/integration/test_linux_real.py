"""The Linux integration (#240) against a real Debian 12 (a container with sshd, iproute2,
dnsmasq, chrony and a WireGuard interface; tools/integration/linux).

The read user ``signalbox`` was created with the commands of the setup guide, including the
sudoers rule for ``wg show``. The tests read the container as that user, then without the rule,
and run the automatic setup as root and as a sudo user that needs its password.

    IT_LINUX_URL              ssh://127.0.0.1:<port>
    IT_LINUX_USER             the read user
    IT_LINUX_KEY_FILE         its private key
    IT_LINUX_ROOT_PASSWORD    root's password
    IT_LINUX_ADMIN_USER       a sudo user, and IT_LINUX_ADMIN_PASSWORD
    IT_LINUX_CONTAINER        the container (docker exec for the test without the rule)
    IT_LINUX_WG_PUBLIC        wg0's public key, IT_LINUX_HOST_KEY the ed25519 host key
"""

from __future__ import annotations

import dataclasses
import subprocess
from collections.abc import Callable
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext, SetupRequest, StepState
from signalbox.adapters.linux import LinuxAdapter, LinuxConfig
from signalbox.adapters.linux.setup import SUDOERS_PATH, sudoers, sudoers_path
from signalbox.adapters.ssh import sha256_hex
from signalbox.model import (
    DeviceRole,
    DeviceStatus,
    FirewallAction,
    Membership,
    PortRole,
    Snapshot,
)
from signalbox.testing import assert_contract

from .conftest import Target

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def lx(target: Callable[[str], Target]) -> Target:
    t = target("linux")
    for key in ("KEY_FILE", "ROOT_PASSWORD", "ADMIN_USER", "CONTAINER", "HOST_KEY"):
        assert t.extra.get(key), f"IT_LINUX_{key}"
    return t


def port(t: Target) -> int:
    return int(t.url.rsplit(":", 1)[1])


def context(t: Target, **cfg: Any) -> AdapterContext:
    settings: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port(t),
        "username": t.username,
        "private_key": Path(t.extra["KEY_FILE"]).read_text(),
    } | cfg
    return AdapterContext(
        site_id="it",
        device_id="gw2",
        device_name="gw2",
        role=DeviceRole.GATEWAY,
        config=LinuxConfig(**settings),
        pinned_fingerprint=sha256_hex(t.extra["HOST_KEY"]),
        timeout=20,
    )


async def observe(ctx: AdapterContext, contract: bool = True) -> Snapshot:
    adapter = LinuxAdapter(ctx)
    try:
        return await (assert_contract(adapter) if contract else adapter.observe())
    finally:
        await adapter.close()


def docker(t: Target, *args: str) -> None:
    subprocess.run(["docker", "exec", t.extra["CONTAINER"], *args], check=True)


async def test_untrusted_first(lx: Target) -> None:
    adapter = LinuxAdapter(dataclasses.replace(context(lx), pinned_fingerprint=None))
    try:
        snap = await adapter.observe()
    finally:
        await adapter.close()
    assert snap.status is DeviceStatus.UNTRUSTED
    assert adapter.presented_fingerprint == sha256_hex(lx.extra["HOST_KEY"])


async def test_read_as_the_documented_user(lx: Target) -> None:
    snap = await observe(context(lx))
    d = snap.device
    assert d.firmware is not None and "Debian GNU/Linux 12" in (d.firmware.current or "")
    ports = {p.name: p for p in snap.ports}
    assert ports["br0"].role is PortRole.BRIDGE
    assert ports["br0"].lower == ["gw2/port/lan1", "gw2/port/lan2"]
    assert ports["lan0.30"].role is PortRole.VLAN and ports["lan0.30"].lower == ["gw2/port/lan0"]
    assert ports["lan1"].role is PortRole.VIRTUAL  # dummies
    assert ports["wg0"].role is PortRole.TUNNEL
    (tunnel,) = snap.tunnels
    assert tunnel.public_key == lx.extra["WG_PUBLIC"] and tunnel.listen_port == 51820
    assert tunnel.port_id == "gw2/port/wg0" and tunnel.up is True
    assert [str(a) for a in tunnel.addresses] == ["203.0.113.250/30"]
    (peer,) = tunnel.peers
    assert (peer.endpoint_host, peer.endpoint_port) == ("203.0.113.1", 51820)
    assert {str(n) for n in peer.allowed_ips} == {"203.0.113.249/32", "198.51.100.128/25"}
    assert peer.latest_handshake is None and peer.keepalive_seconds == 25
    assert peer.rx_bytes == 0 and peer.preshared_key is None
    segs = {s.id: s for s in snap.segments}
    assert [(m.port_id, m.mode) for m in segs["it/segment/30"].members] == [
        ("gw2/port/lan0", Membership.TAGGED)
    ]
    assert {m.port_id for m in segs["it/segment/native"].members} >= {
        "gw2/port/lan1",
        "gw2/port/lan2",
    }
    subnets = {str(s.interface) for s in snap.subnets}
    assert {"192.0.2.1/25", "192.0.2.129/26"} <= subnets
    (up,) = snap.uplinks
    assert up.port_id == "gw2/port/eth0" and up.upstream_gateway is not None
    ssh = next(s for s in snap.services if s.id == "gw2/service/ssh")
    assert ssh.enabled and ssh.port == 22 and ssh.password_login is True
    assert ssh.root_password_login is True
    (lan,) = [s for s in snap.dhcp_servers if s.segment_id == "it/segment/native"]
    assert lan.enabled and lan.lease_seconds == 43200 and lan.authoritative is True
    assert [str(r.address) for r in lan.reservations] == ["192.0.2.10"]
    assert [str(x.address) for x in lan.leases or []] == ["192.0.2.61"]
    (dns,) = snap.dns_services
    assert (
        dns.name == "dnsmasq"
        and dns.enabled
        and [str(f) for f in dns.forwarders] == ["203.0.113.53"]
    )
    assert dns.listen == [ip_address("192.0.2.1")]
    assert d.health is not None and d.health.memory_total_bytes and d.health.cpu_count
    assert any(s.name == "/" for s in d.health.storage)
    assert d.time is not None and d.time.clock is not None
    assert abs(d.time.offset_seconds() or 0) < 5
    nc = d.time.ntp_client
    assert nc is not None and nc.enabled and nc.servers == ["203.0.113.123"]
    assert nc.synchronised is False  # the server does not exist
    assert d.time.ntp_server is not None and d.time.ntp_server.enabled


async def test_firewall_from_the_real_nft(lx: Target) -> None:
    """The rules start.sh loads with nft -f (#135), read through the documented sudoers rule."""
    snap = await observe(context(lx))
    (fw,) = snap.firewalls
    assert fw.id == "gw2/firewall" and fw.enabled and fw.rules_complete
    assert [e for e in snap.errors if e.capability == "firewall"] == []
    assert fw.input_policy is FirewallAction.DROP and fw.forward_policy is FirewallAction.DROP
    zones = {z.name: z for z in fw.zones}
    assert zones["br0"].segments == ["it/segment/native"]
    assert zones["eth0"].uplinks == ["gw2/uplink/eth0"] and zones["wg0"].tunnels
    web = next(r for r in fw.rules if r.name == "web from the office")
    assert [str(n) for n in web.source.networks] == ["203.0.113.0/24"]
    assert [str(p) for p in web.destination.ports] == ["8080"] and web.exact
    # ct state accepts are left out, the jump to from_vpn is flattened
    vpn = next(r for r in fw.rules if r.source.zones == ["wg0"])
    assert [str(n) for n in vpn.destination.networks] == ["192.0.2.20/32"]
    assert [str(p) for p in vpn.destination.ports] == ["80", "443"]
    assert any(r.forwarded for r in fw.rules)
    (fwd,) = fw.port_forwards
    assert fwd.name == "nas" and fwd.zones == ["eth0"] and str(fwd.target_address) == "192.0.2.20"
    assert fwd.target_port == 443 and [str(p) for p in fwd.external_ports] == ["8443"]
    (nat,) = fw.nat
    assert nat.masquerade and nat.zones == ["eth0"]


async def test_without_the_sudoers_rule_wireguard_is_a_gap(lx: Target) -> None:
    docker(lx, "mv", SUDOERS_PATH, "/root/sudoers.saved")
    try:
        snap = await observe(context(lx), contract=False)
    finally:
        docker(lx, "mv", "/root/sudoers.saved", SUDOERS_PATH)
    assert snap.status is DeviceStatus.PARTIAL
    assert sorted(e.capability for e in snap.errors) == ["firewall", "vpn"]
    assert any("wg show" in e.message for e in snap.errors) and snap.firewalls == []


@pytest.mark.parametrize("who", ["root", "admin"])
async def test_automatic_setup(lx: Target, who: str) -> None:
    user = "root" if who == "root" else lx.extra["ADMIN_USER"]
    secret = lx.extra["ROOT_PASSWORD"] if who == "root" else lx.extra["ADMIN_PASSWORD"]
    login = f"signalbox-{who}"

    def request(trust: str | None, **kw: Any) -> SetupRequest:
        return SetupRequest(
            config={"host": "127.0.0.1", "username": login},
            admin_user=user,
            admin_secret=SecretStr(secret),
            port=port(lx),
            trust=trust,
            timeout=30,
            **kw,
        )

    first = await LinuxAdapter.plan_setup(request(None))
    assert not first.trusted and first.fingerprint == lx.extra["HOST_KEY"]
    fp = first.fingerprint
    plan = await LinuxAdapter.plan_setup(request(fp))
    assert [s.state for s in plan.steps][:3] == [StepState.TODO] * 3
    result = await LinuxAdapter.apply_setup(request(fp))
    assert result.ok, result.steps
    assert result.certificate == sha256_hex(fp)
    key = result.secrets["private_key"].get_secret_value()
    snap = await observe(context(lx, username=login, private_key=key))
    assert snap.tunnels[0].public_key == lx.extra["WG_PUBLIC"] and snap.firewalls
    # the rule on the device is the documented one for this login, in a file of its own
    out = subprocess.run(
        ["docker", "exec", lx.extra["CONTAINER"], "cat", sudoers_path(login)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert out == sudoers(login)
    again = await LinuxAdapter.apply_setup(request(fp))
    assert {s.id: s.state for s in again.steps}["user"] is StepState.UNCHANGED
    removed = await LinuxAdapter.apply_setup(request(fp, remove=True))
    assert removed.ok, removed.steps
    for args in (["getent", "passwd", login], ["test", "-e", sudoers_path(login)]):
        gone = subprocess.run(["docker", "exec", lx.extra["CONTAINER"], *args], check=False)
        assert gone.returncode != 0, args
    # the documented user's rule is untouched
    docker(lx, "test", "-e", SUDOERS_PATH)
