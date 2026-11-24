"""Linux distributions (#302): an Arch Linux ARM Raspberry Pi 2 (single NIC, legacy iptables, no
nft, no wg) is read completely, the setup offers the missing tools with the device's package
manager, and *Fix it* installs nftables. The Debian simulator stays the reference."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import asyncssh
import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    AdapterContext,
    AdapterError,
    RemedyRequest,
    SetupRequest,
    StepState,
)
from signalbox.adapters.linux import LinuxAdapter, LinuxConfig, distro
from signalbox.adapters.linux.setup import SUDOERS_PATH, sudoers
from signalbox.adapters.ssh import sha256_hex
from signalbox.model import DeviceRole, DeviceStatus, PortRole
from signalbox.sim.linux import ROOT_PASSWORD, LinuxSim, User, arch_sim, serve_ssh

KEY = asyncssh.generate_private_key("ssh-ed25519")
PRIVATE = KEY.export_private_key().decode()
PUBLIC = KEY.export_public_key("openssh").decode().strip()


def with_login(box: LinuxSim) -> LinuxSim:
    box.users["signalbox"] = User(keys=[PUBLIC], system=True)
    return box


@asynccontextmanager
async def adapter_for(box: LinuxSim) -> AsyncIterator[LinuxAdapter]:
    async with serve_ssh(box) as (port, fingerprint):
        ctx = AdapterContext(
            site_id="home",
            device_id="alarm",
            device_name="alarm",
            role=DeviceRole.GATEWAY,
            config=LinuxConfig(
                host="127.0.0.1", port=port, username="signalbox", private_key=SecretStr(PRIVATE)
            ),
            pinned_fingerprint=sha256_hex(fingerprint),
            timeout=5,
        )
        adapter = LinuxAdapter(ctx)
        try:
            yield adapter
        finally:
            await adapter.close()


def request(port: int, trust: str | None, **kw: Any) -> SetupRequest:
    return SetupRequest(
        config={"host": "127.0.0.1", "username": "signalbox"},
        admin_user="root",
        admin_secret=SecretStr(ROOT_PASSWORD),
        port=port,
        trust=trust,
        timeout=10,
        **kw,
    )


# the distribution table ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("release", "manager", "command"),
    [
        (
            {"ID": "debian"},
            "apt",
            "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nftables",
        ),
        ({"ID": "raspbian", "ID_LIKE": "debian"}, "apt", None),
        ({"ID": "ubuntu", "ID_LIKE": "debian"}, "apt", None),
        ({"ID": "archarm", "ID_LIKE": "arch"}, "pacman", "pacman -S --needed --noconfirm nftables"),
        ({"ID": "arch"}, "pacman", None),
        ({"ID": "endeavouros", "ID_LIKE": "arch"}, "pacman", None),
        ({"ID": "fedora"}, "dnf", "dnf install -y nftables"),
        ({"ID": "alpine"}, "apk", "apk add nftables"),
    ],
)
def test_detect(release: dict[str, str], manager: str, command: str | None) -> None:
    found = distro.detect(release)
    assert found.manager == manager
    if command:
        assert found.install("nftables") == command


def test_unknown_distribution_and_package_names() -> None:
    nothing = distro.detect({"ID": "plan9"})
    assert nothing.manager is None and nothing.install("nftables") is None
    assert "nftables" in nothing.hint("nftables") and "as root" not in nothing.hint("nftables")
    arch = distro.detect({"ID": "arch"})
    assert arch.install("iproute2", "tracepath", "wireguard") == (
        "pacman -S --needed --noconfirm iproute2 iputils wireguard-tools"
    )
    assert distro.detect({"ID": "fedora"}).install("iproute2") == "dnf install -y iproute"
    assert distro.detect({"ID": "alpine"}).package("tracepath") == "iputils-tracepath"


# reading an Arch Linux ARM host ---------------------------------------------------------------


async def test_arch_host_is_read_with_its_network() -> None:
    box = with_login(arch_sim())
    box.sudoers_files[SUDOERS_PATH] = sudoers("signalbox")
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    assert snap.status is DeviceStatus.PARTIAL  # only the firewall is not readable
    assert snap.device.log_targets == []  # journald only: nothing forwarded (#180)
    assert {p.name for p in snap.ports} == {"eth0", "wlan0"}
    wlan = next(p for p in snap.ports if p.name == "wlan0")
    assert wlan.role is PortRole.WIRELESS and not wlan.up and wlan.admin_up is False
    # the single NIC carries the default route and is the host's network (#302)
    assert [str(s.interface) for s in snap.subnets] == ["192.0.2.20/24"]
    assert not any(s.gateway for s in snap.subnets)  # IP forwarding is off
    assert len(snap.segments) == 1 and snap.segments[0].members
    assert [u.name for u in snap.uplinks] == ["eth0"]
    assert snap.device.firmware is not None and snap.device.firmware.current == "Arch Linux ARM"
    assert snap.device.vendor_extra["os_id"] == "archarm"
    assert snap.device.vendor_extra["package_manager"] == "pacman"
    assert any(s.name == "sshd" for s in snap.services)
    err = next(e for e in snap.errors if e.capability == "firewall")
    assert "legacy iptables" in err.message
    assert err.remedy == "nftables"
    assert "pacman -S --needed --noconfirm nftables" in (err.fix or "")
    assert snap.firewalls[0].rules_complete is False


async def test_debian_hint_uses_apt() -> None:
    box = with_login(LinuxSim(nft_installed=False))
    box.sections["iptables"] = "iptables v1.8.9 (legacy)\n"
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    err = next(e for e in snap.errors if e.capability == "firewall")
    assert "apt-get" in (err.fix or "") and err.remedy == "nftables"


async def test_router_with_one_network_keeps_its_wan_out_of_the_subnets() -> None:
    box = with_login(LinuxSim())  # Debian gateway: eth0 is the WAN, br0 the LAN
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    assert "198.51.100.2/24" not in {str(s.interface) for s in snap.subnets}
    # but a forwarding host whose only address is on the uplink still shows its network
    one = with_login(arch_sim())
    one.sections["forward"] = "1\n1\n"
    async with adapter_for(one) as adapter:
        snap = await adapter.observe()
    assert [str(s.interface) for s in snap.subnets] == ["192.0.2.20/24"]


async def test_ip_without_json_is_named() -> None:
    box = with_login(arch_sim(ip_json=False))
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    assert not snap.ports
    err = next(e for e in snap.errors if e.capability == "interfaces")
    assert "ip -j" in err.message and "pacman -S --needed --noconfirm iproute2" in (err.fix or "")


# the setup's optional installs -----------------------------------------------------------------

ALL = ["iproute2", "nftables", "tracepath", "wireguard"]


async def test_setup_offers_the_installs_unticked_and_runs_the_managers_own() -> None:
    box = arch_sim()  # ip -j works here: iproute2 is already there
    async with serve_ssh(box) as (port, fp):
        plain = await LinuxAdapter.plan_setup(request(port, fp))
        assert not [s for s in plain.steps if s.id.startswith("install-")]
        assert {s.id: s.state for s in plain.steps}["sudoers"] is StepState.UNCHANGED
        plan = await LinuxAdapter.plan_setup(request(port, fp, extras=ALL))
        steps = {s.id: s for s in plan.steps}
        assert [s.id for s in plan.steps][:2] == ["user", "key"]
        assert steps["install-iproute2"].state is StepState.UNCHANGED
        assert all(
            steps[f"install-{t}"].state is StepState.TODO
            for t in ("nftables", "tracepath", "wireguard")
        )
        # the plan shows the exact command, verbatim
        assert "pacman -S --needed --noconfirm nftables" in steps["install-nftables"].detail
        assert "pacman -S --needed --noconfirm iputils" in steps["install-tracepath"].detail
        assert "apt-get" not in "".join(s.detail for s in plan.steps)
        assert steps["sudoers"].state is StepState.TODO  # nft and wg will exist
        assert box.installed == []  # the plan changed nothing
        done = await LinuxAdapter.apply_setup(request(port, fp, extras=ALL))
        assert done.ok, done.steps
        assert len(box.installed) == 3 and all(c.startswith("pacman") for c in box.installed)
        assert box.nft_installed and box.wg_installed and box.trace_tool == "tracepath"
        assert box.sudoers_files[SUDOERS_PATH] == sudoers("signalbox")
        again = await LinuxAdapter.plan_setup(request(port, fp, extras=ALL))
        assert {s.state for s in again.steps if s.id.startswith("install-")} == {
            StepState.UNCHANGED
        }


async def test_setup_on_debian_uses_apt_and_removal_keeps_packages() -> None:
    box = LinuxSim(nft_installed=False)
    async with serve_ssh(box) as (port, fp):
        done = await LinuxAdapter.apply_setup(request(port, fp, extras=["nftables"]))
        assert done.ok and box.installed[0].startswith("apt-get update && ")
        assert box.nft_installed
        gone = await LinuxAdapter.plan_setup(request(port, fp, remove=True, extras=["nftables"]))
        assert not [s for s in gone.steps if s.id.startswith("install-")]


async def test_unknown_distribution_cannot_install() -> None:
    box = arch_sim()
    box.sections["os"] = "@@@ /etc/os-release\nID=plan9\n"
    async with serve_ssh(box) as (port, fp):
        with pytest.raises(AdapterError, match="plan9"):
            await LinuxAdapter.plan_setup(request(port, fp, extras=["nftables"]))
        ok = await LinuxAdapter.plan_setup(request(port, fp))  # without the extra: as before
        assert ok.steps


async def test_a_failing_install_stops_the_setup() -> None:
    box = arch_sim(install_fails=True)
    async with serve_ssh(box) as (port, fp):
        result = await LinuxAdapter.apply_setup(request(port, fp, extras=["nftables"]))
    states = {s.id: s.state for s in result.steps}
    assert not result.ok and states["install-nftables"] is StepState.FAILED
    assert states["sudoers"] is StepState.SKIPPED and "signalbox" in box.users


async def test_iproute2_is_installed_when_ip_has_no_json() -> None:
    box = arch_sim(ip_json=False)
    async with serve_ssh(box) as (port, fp):
        done = await LinuxAdapter.apply_setup(request(port, fp, extras=["iproute2"]))
    assert done.ok and box.installed == ["pacman -S --needed --noconfirm iproute2"] and box.ip_json


# fix it ----------------------------------------------------------------------------------------


def fix(port: int, trust: str | None, **kw: Any) -> RemedyRequest:
    return RemedyRequest(
        remedy=kw.pop("remedy", "nftables"),
        config={"host": "127.0.0.1", "username": "signalbox"},
        secrets={"private_key": SecretStr(PRIVATE)},
        admin_user="root",
        admin_secret=SecretStr(ROOT_PASSWORD),
        port=port,
        trust=trust,
        timeout=10,
        **kw,
    )


async def test_fix_it_installs_nftables_then_the_firewall_is_read() -> None:
    box = with_login(arch_sim())
    async with serve_ssh(box) as (port, fp):
        plan = await LinuxAdapter.plan_remedy(fix(port, fp))
        assert [(s.id, s.state) for s in plan.steps] == [
            ("install-nftables", StepState.TODO),
            ("sudoers", StepState.TODO),
        ]
        assert "pacman -S --needed --noconfirm nftables" in plan.steps[0].detail
        assert not box.nft_installed
        done = await LinuxAdapter.apply_remedy(fix(port, fp))
        assert done.ok and not done.settings and not done.secrets
    assert box.nft_installed and box.installed == ["pacman -S --needed --noconfirm nftables"]
    box.sections["iptables"] = ""
    async with adapter_for(box) as adapter:
        snap = await adapter.observe()
    assert snap.firewalls[0].rules and not [e for e in snap.errors if e.capability == "firewall"]


async def test_unknown_remedy() -> None:
    with pytest.raises(AdapterError, match="no remedy"):
        await LinuxAdapter.plan_remedy(fix(22, None, remedy="nothing"))
