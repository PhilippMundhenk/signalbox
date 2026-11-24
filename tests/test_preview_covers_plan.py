"""The credential-free preview of every integration lists every step the real plan can have
(#290): the preview is static, so a new or renamed step in a plan builder must also be added to
``AdminLogin.preview`` / ``Remedy.preview``, or the user is surprised by a 409 ``plan_changed``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from signalbox.adapters import (
    Adapter,
    PreviewStep,
    RemedyRequest,
    SetupPlan,
    SetupRequest,
)
from signalbox.adapters.linux import LinuxAdapter
from signalbox.adapters.mikrotik import MikrotikAdapter
from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.adapters.opnsense import OpnsenseAdapter
from signalbox.sim.linux import ROOT_PASSWORD as LINUX_ROOT
from signalbox.sim.linux import LinuxSim, arch_sim
from signalbox.sim.linux import serve_ssh as linux_ssh
from signalbox.sim.mikrotik import MikrotikSimulator
from signalbox.sim.mikrotik_ssh import ADMIN_PASSWORD as MT_SSH_PASSWORD
from signalbox.sim.mikrotik_ssh import MikrotikSsh
from signalbox.sim.mikrotik_ssh import serve_ssh as mikrotik_ssh
from signalbox.sim.openwrt import OpenWrtSim
from signalbox.sim.openwrt_ssh import ROOT_PASSWORD as OPENWRT_ROOT
from signalbox.sim.openwrt_ssh import OpenWrtSsh
from signalbox.sim.openwrt_ssh import serve_ssh as openwrt_ssh
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.opnsense_ssh import ROOT_PASSWORD as OPN_ROOT
from signalbox.sim.opnsense_ssh import OpnsenseSsh, serve_ssh_in_thread
from signalbox.sim.server import TlsFiles, self_signed_certificate, serve

ADMIN = "admin-password"


def covers(
    preview: list[PreviewStep],
    plan: SetupPlan,
    *,
    remove: bool = False,
    extras: tuple[str, ...] = (),
) -> None:
    shown = {p.id for p in preview if p.remove == remove and (not p.extra or p.extra in extras)}
    assert plan.trusted, "the scenario must reach the plan"
    assert plan.steps, "the scenario must produce steps"
    missing = [s.id for s in plan.steps if s.id not in shown]
    assert not missing, f"not in the preview: {missing} (preview: {sorted(shown)})"


def setup_preview(adapter: type[Adapter]) -> list[PreviewStep]:
    assert adapter.manifest.admin_login is not None
    return adapter.manifest.admin_login.preview


def remedy_preview(adapter: type[Adapter], remedy: str) -> list[PreviewStep]:
    return next(r.preview for r in adapter.manifest.remedies if r.id == remedy)


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TlsFiles:
    return self_signed_certificate(tmp_path_factory.mktemp("tls"))


# --- Linux -------------------------------------------------------------------------------------


async def test_linux() -> None:
    preview = setup_preview(LinuxAdapter)
    async with linux_ssh(LinuxSim()) as (port, fp):

        def req(**kw: Any) -> SetupRequest:
            return SetupRequest(
                config={"host": "127.0.0.1", "username": "signalbox"},
                admin_user="root",
                admin_secret=SecretStr(LINUX_ROOT),
                port=port,
                trust=fp,
                timeout=10,
                **kw,
            )

        covers(preview, await LinuxAdapter.plan_setup(req()))
        every = ("nftables", "iproute2", "wireguard", "tracepath")
        covers(preview, await LinuxAdapter.plan_setup(req(extras=list(every))), extras=every)
        assert (await LinuxAdapter.apply_setup(req())).ok
        covers(preview, await LinuxAdapter.plan_setup(req()))
        covers(preview, await LinuxAdapter.plan_setup(req(remove=True)), remove=True)
        assert (await LinuxAdapter.apply_setup(req(remove=True))).ok

    # fix it: nftables, on a device that has only legacy iptables
    async with linux_ssh(arch_sim()) as (port, fp):
        request = RemedyRequest(
            remedy="nftables",
            config={"host": "127.0.0.1", "username": "signalbox"},
            secrets={"private_key": SecretStr("stored")},
            admin_user="root",
            admin_secret=SecretStr(LINUX_ROOT),
            port=port,
            trust=fp,
            timeout=10,
        )
        covers(remedy_preview(LinuxAdapter, "nftables"), await LinuxAdapter.plan_remedy(request))
        covers(preview, await LinuxAdapter.plan_setup(req(remove=True)), remove=True)


# --- OpenWrt -----------------------------------------------------------------------------------


@pytest.fixture
async def openwrt() -> AsyncIterator[tuple[OpenWrtSsh, int, str]]:
    device = OpenWrtSsh(http=OpenWrtSim(), certificate=b"\x30\x82fake-der")
    async with openwrt_ssh(device) as (port, fp):
        yield device, port, fp


async def test_openwrt_setup(openwrt: tuple[OpenWrtSsh, int, str]) -> None:
    _, port, fp = openwrt
    preview = setup_preview(OpenWrtAdapter)

    def req(**kw: Any) -> SetupRequest:
        return SetupRequest(
            config={"url": "127.0.0.1", "username": "signalbox"},
            admin_user="root",
            admin_secret=SecretStr(OPENWRT_ROOT),
            port=port,
            trust=fp,
            timeout=10,
            **kw,
        )

    both = ("lldp",)
    for writes in (False, True):
        covers(preview, await OpenWrtAdapter.plan_setup(req(allow_writes=writes)))
    covers(preview, await OpenWrtAdapter.plan_setup(req(extras=["lldp"])), extras=both)
    assert (await OpenWrtAdapter.apply_setup(req(extras=["lldp"]))).ok
    covers(preview, await OpenWrtAdapter.plan_setup(req(extras=["lldp"])), extras=both)
    covers(preview, await OpenWrtAdapter.plan_setup(req()))
    covers(
        preview,
        await OpenWrtAdapter.plan_setup(req(remove=True, extras=["lldp"])),
        remove=True,
        extras=both,
    )
    covers(preview, await OpenWrtAdapter.plan_setup(req(remove=True)), remove=True)


async def test_openwrt_fix(openwrt: tuple[OpenWrtSsh, int, str]) -> None:
    device, port, fp = openwrt
    assert device.http is not None
    device.rpcd["cfg02"] = {
        "type": "login",
        "options": {"username": ["signalbox"], "password": ["$1$x$y"], "read": ["signalbox"]},
    }
    device.lldpd_running = False
    device.http.lldpd = False
    for remedy in ("access", "lldp"):
        request = RemedyRequest(
            remedy=remedy,
            config={"url": "127.0.0.1", "username": "signalbox"},
            secrets={"password": SecretStr("stored")},
            admin_user="root",
            admin_secret=SecretStr(OPENWRT_ROOT),
            port=port,
            allow_writes=True,
            trust=fp,
            timeout=10,
        )
        covers(remedy_preview(OpenWrtAdapter, remedy), await OpenWrtAdapter.plan_remedy(request))


# --- MikroTik ----------------------------------------------------------------------------------


@pytest.fixture
def mikrotik(tls: TlsFiles) -> Iterator[str]:
    sim = MikrotikSimulator(username="admin", password=ADMIN)
    with serve(sim.app(), tls=tls) as url:
        yield url


async def test_mikrotik(tls: TlsFiles, mikrotik: str) -> None:
    url = mikrotik
    preview = setup_preview(MikrotikAdapter)

    def req(**kw: Any) -> SetupRequest:
        return SetupRequest(
            config={"url": url, "username": "signalbox"},
            admin_user="admin",
            admin_secret=SecretStr(ADMIN),
            trust=tls.fingerprint,
            timeout=5,
            **kw,
        )

    covers(preview, await MikrotikAdapter.plan_setup(req()))
    covers(preview, await MikrotikAdapter.plan_setup(req(allow_writes=True)))
    assert (await MikrotikAdapter.apply_setup(req())).ok
    covers(preview, await MikrotikAdapter.plan_setup(req()))
    covers(preview, await MikrotikAdapter.plan_setup(req(allow_writes=True)))
    covers(preview, await MikrotikAdapter.plan_setup(req(remove=True)), remove=True)
    # fix it: the group's policies
    request = RemedyRequest(
        remedy="policies",
        config={"url": url, "username": "signalbox"},
        secrets={"password": SecretStr("stored")},
        admin_user="admin",
        admin_secret=SecretStr(ADMIN),
        allow_writes=True,
        trust=tls.fingerprint,
        timeout=5,
    )
    covers(remedy_preview(MikrotikAdapter, "policies"), await MikrotikAdapter.plan_remedy(request))


async def test_mikrotik_rest_service_fix() -> None:
    async with mikrotik_ssh(MikrotikSsh()) as (port, fp):
        request = RemedyRequest(
            remedy="rest-service",
            config={"url": "https://127.0.0.1", "username": "signalbox"},
            secrets={"password": SecretStr("stored")},
            admin_user="admin",
            admin_secret=SecretStr(MT_SSH_PASSWORD),
            port=port,
            trust=fp,
            timeout=5,
        )
        covers(
            remedy_preview(MikrotikAdapter, "rest-service"),
            await MikrotikAdapter.plan_remedy(request),
        )


# --- OPNsense, with the optional ISC SSH script --------------------------------------------------


async def test_opnsense(tls: TlsFiles) -> None:
    preview = setup_preview(OpnsenseAdapter)
    with (
        serve(OpnsenseSimulator().app(), tls=tls) as url,
        serve_ssh_in_thread(OpnsenseSsh()) as (port, ssh_fp),
    ):

        def req(**kw: Any) -> SetupRequest:
            return SetupRequest(
                config={"url": url},
                admin_user=KEY,
                admin_secret=SecretStr(SECRET),
                trust=tls.fingerprint,
                timeout=5,
                **kw,
            )

        def with_ssh(**kw: Any) -> SetupRequest:
            return req(
                ssh_step=True,
                ssh_secret=SecretStr(OPN_ROOT),
                ssh_port=port,
                ssh_trust=ssh_fp,
                **kw,
            )

        ssh = ("ssh",)
        covers(preview, await OpnsenseAdapter.plan_setup(req()))
        covers(preview, await OpnsenseAdapter.plan_setup(req(allow_writes=True, traces=True)))
        covers(preview, await OpnsenseAdapter.plan_setup(with_ssh()), extras=ssh)
        assert (await OpnsenseAdapter.apply_setup(with_ssh())).ok
        covers(preview, await OpnsenseAdapter.plan_setup(with_ssh()), extras=ssh)
        covers(preview, await OpnsenseAdapter.plan_setup(req(remove=True)), remove=True)
        covers(
            preview,
            await OpnsenseAdapter.plan_setup(with_ssh(remove=True)),
            remove=True,
            extras=ssh,
        )
        done = await OpnsenseAdapter.apply_setup(req())
        key = done.secrets["api_key"].get_secret_value()
        fix = RemedyRequest(
            remedy="privileges",
            config={"url": url},
            secrets={"api_key": SecretStr(key), "api_secret": SecretStr("stored")},
            admin_user=KEY,
            admin_secret=SecretStr(SECRET),
            allow_writes=True,
            trust=tls.fingerprint,
            timeout=5,
        )
        covers(
            remedy_preview(OpnsenseAdapter, "privileges"), await OpnsenseAdapter.plan_remedy(fix)
        )
