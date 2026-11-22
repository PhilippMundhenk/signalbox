"""The pinned Switchyard against published captures of real switches (tests/fixtures/switches).

Switchyard's simulators are the reference for ProSAFE Plus and Easy Smart (ADR 0003); these
tests make sure the pinned commit still decodes and produces what real switches send, byte for
byte, so a pin bump that changes the wire format fails here.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
CAPTURES: dict[str, Any] = json.loads((ROOT / "tests/fixtures/switches/captures.json").read_text())
REPLIES = CAPTURES["easysmart"]["replies"]

try:
    from switchyard.easysmart.packet import Op, Packet, scramble
    from switchyard.easysmart.sim import SimEasySmart
    from switchyard.nsdp.packet import format_mac
except ImportError:  # pragma: no cover - depends on the installation
    if os.environ.get("REQUIRE_SWITCH_TESTS"):
        raise
    pytest.skip(
        "Switchyard is not installed: pip install -e '.[dev,switches]'", allow_module_level=True
    )


def test_captures_belong_to_the_pinned_commit() -> None:
    pin = CAPTURES["switchyard"]
    assert f"switchyard@{pin}" in (ROOT / "pyproject.toml").read_text().replace(
        "switchyard @ git+https://github.com/PhilippMundhenk/switchyard@", "switchyard@"
    )


def test_static_keystream() -> None:
    assert scramble(bytes(16)).hex() == CAPTURES["easysmart"]["keystream_first_16"]


@pytest.mark.parametrize("capture", REPLIES, ids=[r["name"] for r in REPLIES])
def test_captured_reply_decodes_and_re_encodes(capture: dict[str, Any]) -> None:
    cipher = bytes.fromhex(capture["cipher"])
    packet = Packet.decode(cipher)
    expect = capture["expect"]
    assert (packet.op, packet.seq, packet.error, packet.token) == (
        expect["op"],
        expect["seq"],
        expect["error"],
        expect["token"],
    )
    assert packet.tlvs == [(t, bytes.fromhex(v)) for t, v in expect["tlvs"]]
    assert packet.encode() == cipher


@pytest.mark.parametrize("capture", REPLIES, ids=[r["name"] for r in REPLIES])
def test_simulator_answers_like_the_captured_switch(capture: dict[str, Any]) -> None:
    """The same request to Switchyard's simulator of that switch gives the captured reply.

    Except the token: a Gen A switch puts its session token into every reply (the capture
    has 17956), Switchyard's simulator only into the answer to the token request. The adapter
    does not depend on it; it is compared separately.
    """
    real = Packet.decode(bytes.fromhex(capture["cipher"]))
    sim = SimEasySmart(
        format_mac(real.switch_mac),
        model="TL-SG105E",
        hardware="TL-SG105E 3.0",
        firmware="1.0.0 Build 20160715",
        generation="A",
        ports=5,
    )
    request = capture["request"]
    reply = sim.handle(
        Packet(
            request["op"],
            real.switch_mac,
            real.host_mac,
            real.seq,
            tlvs=[(t, bytes.fromhex(v)) for t, v in request["tlvs"]],
        )
    )
    assert reply is not None and reply.op == Op.REPLY
    assert (reply.switch_mac, reply.host_mac, reply.seq, reply.error, reply.tlvs) == (
        real.switch_mac,
        real.host_mac,
        real.seq,
        real.error,
        real.tlvs,
    )
    reply.token = real.token
    assert reply.encode() == bytes.fromhex(capture["cipher"])
