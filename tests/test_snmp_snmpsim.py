"""The ``snmp`` adapter over real UDP against snmpsim, with the committed recording.

snmpsim (https://github.com/lextudio/snmpsim) serves ``tests/fixtures/snmp/managed-switch.snmprec``
as an SNMP agent: v2c under a community made up for the run, v3 authPriv (SHA-256 and AES-128,
user and passwords made up for the run) under a context name. The adapter then runs with pysnmp
like against a real switch; what it reads must equal the snapshot of the in-process replay.
Part of the dev extra; skipped without snmpsim unless ``REQUIRE_SWITCH_TESTS`` is set (CI sets it).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import SecretStr

from signalbox.adapters import AdapterContext
from signalbox.adapters.snmp import SnmpAdapter, SnmpConfig
from signalbox.adapters.snmp.client import PysnmpTransport, SnmpError
from signalbox.model import DeviceRole, DeviceStatus
from signalbox.recording import stable
from signalbox.sim.server import free_port
from signalbox.testing import assert_contract

try:
    import pysnmp  # noqa: F401
    import snmpsim  # noqa: F401
except ImportError:  # pragma: no cover - depends on the installation
    HAVE_SNMPSIM = False
    if os.environ.get("REQUIRE_SWITCH_TESTS"):
        raise
else:
    HAVE_SNMPSIM = True

pytestmark = pytest.mark.skipif(
    not HAVE_SNMPSIM, reason="snmpsim is not installed: pip install -e '.[dev]'"
)

RECORDING = Path(__file__).parent / "fixtures" / "snmp" / "managed-switch.snmprec"
EXPECTED = json.loads(RECORDING.with_suffix(".snapshot.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Agent:
    port: int
    community: str
    context: str
    user: str
    auth_password: str
    priv_password: str


def _config(agent: Agent, version: str) -> SnmpConfig:
    if version == "v2c":
        return SnmpConfig(
            address="127.0.0.1",
            port=agent.port,
            version="v2c",
            community=SecretStr(agent.community),
        )
    return SnmpConfig(
        address="127.0.0.1",
        port=agent.port,
        version="v3",
        username=agent.user,
        auth_password=SecretStr(agent.auth_password),
        priv_password=SecretStr(agent.priv_password),
        context_name=agent.context,
    )


def _adapter(agent: Agent, version: str, timeout: float = 10.0) -> SnmpAdapter:
    return SnmpAdapter(
        AdapterContext(
            site_id="home",
            device_id="switch",
            device_name="Switch",
            role=DeviceRole.SWITCH,
            config=_config(agent, version),
            timeout=timeout,
        )
    )


async def _wait_until_answering(agent: Agent) -> None:
    transport = PysnmpTransport(_config(agent, "v2c"), timeout=2.0)  # 0.5 s per try
    try:
        for _ in range(60):
            try:
                if await transport.get("1.3.6.1.2.1.1.1.0"):
                    return
            except SnmpError:
                time.sleep(0.2)
        raise AssertionError("snmpsim does not answer")
    finally:
        await transport.close()


@pytest.fixture
async def agent(tmp_path: Path) -> AsyncIterator[Agent]:
    import secrets

    me = Agent(
        port=free_port(),
        community=f"c{secrets.token_hex(6)}",
        context=f"x{secrets.token_hex(4)}",
        user="signalbox",
        auth_password=secrets.token_hex(10),
        priv_password=secrets.token_hex(10),
    )
    data = tmp_path / "data"
    data.mkdir()
    for name in (me.community, me.context):  # v2c: by community, v3: by context name
        shutil.copy(RECORDING, data / f"{name}.snmprec")
    exe = Path(sys.executable).parent / "snmpsim-command-responder"
    command = [
        str(exe) if exe.exists() else "snmpsim-command-responder",
        f"--data-dir={data}",
        f"--cache-dir={tmp_path / 'cache'}",
        f"--agent-udpv4-endpoint=127.0.0.1:{me.port}",
        f"--v3-user={me.user}",
        f"--v3-auth-key={me.auth_password}",
        "--v3-auth-proto=SHA256",
        f"--v3-priv-key={me.priv_password}",
        "--v3-priv-proto=AES128",
        "--quiet",
    ]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        await _wait_until_answering(me)
        yield me
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()


@pytest.mark.parametrize("version", ["v2c", "v3"])
async def test_the_adapter_reads_snmpsim_like_the_replay(agent: Agent, version: str) -> None:
    adapter = _adapter(agent, version)
    try:
        snapshot = await assert_contract(adapter)
    finally:
        await adapter.close()
    assert snapshot.status is DeviceStatus.OK
    got = stable(snapshot)
    for key in ("ports", "segments", "fdb", "neighbours"):
        assert got[key] == EXPECTED[key], key
    assert got["device"]["stp_bridges"] == EXPECTED["device"]["stp_bridges"]
    assert got["device"]["model"] == "EX-8G-SW" and got["device"]["mac"] == "02:00:00:00:01:00"
    assert got["device"]["transport_encrypted"] is (version == "v3")


async def test_a_wrong_community_gets_no_answer(agent: Agent) -> None:
    other = Agent(**{**agent.__dict__, "community": agent.community + "x"})
    adapter = _adapter(other, "v2c", timeout=4.0)
    try:
        snapshot = await adapter.observe()
    finally:
        await adapter.close()
    assert snapshot.status is DeviceStatus.UNREACHABLE
    assert snapshot.errors[0].message_id in ("snmp.noAnswer", "snmp.authFailed")


async def test_a_wrong_v3_password_is_refused(agent: Agent) -> None:
    other = Agent(**{**agent.__dict__, "auth_password": agent.auth_password[::-1]})
    adapter = _adapter(other, "v3", timeout=4.0)
    try:
        snapshot = await adapter.observe()
    finally:
        await adapter.close()
    assert snapshot.status in (DeviceStatus.AUTH_FAILED, DeviceStatus.UNREACHABLE)
