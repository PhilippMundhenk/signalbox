"""The Wi-Fi map layout (#366): signal is the attraction, deterministic, no DOM.

The layout is plain JavaScript (static/wifimaplayout.js); these tests run it with node.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

NODE = shutil.which("node")
SCRIPT = Path(__file__).parent / "js" / "wifimap_check.mjs"
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def own(id_: str, band: str = "5", channel: int = 36, group: str = "a") -> dict[str, Any]:
    return {"id": id_, "kind": "own", "band": band, "channel": channel, "group": group}


def neighbour(id_: str, band: str = "5", channel: int = 36, dbm: int = -70) -> dict[str, Any]:
    return {"id": id_, "kind": "neighbour", "band": band, "channel": channel, "signal_dbm": dbm}


def run(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    done = subprocess.run(
        [str(NODE), str(SCRIPT)],
        input=json.dumps({"nodes": nodes, "edges": edges}),
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    out: dict[str, Any] = json.loads(done.stdout)
    return out


def test_stronger_signal_is_closer() -> None:
    nodes = [own("a"), own("b"), own("c"), neighbour("n1"), neighbour("n2")]
    edges = [
        {"a": "a", "b": "b", "signal_dbm": -45},
        {"a": "a", "b": "c", "signal_dbm": -85},
        {"a": "a", "b": "n1", "signal_dbm": -50},
        {"a": "a", "b": "n2", "signal_dbm": -88},
    ]
    out = run(nodes, edges)
    d = out["distances"]
    assert d["a|b"] < d["a|c"]
    assert d["a|n1"] < d["a|n2"]
    # a strong signal means overlapping bubbles
    assert d["a|b"] < 2 * 46


def test_no_signal_no_overlap() -> None:
    nodes = [own("a"), own("b"), own("c")]
    out = run(nodes, [{"a": "a", "b": "b", "signal_dbm": -50}])
    lay = out["layout"]["nodes"]
    for x, y in (("a", "c"), ("b", "c")):
        gap = ((lay[x]["x"] - lay[y]["x"]) ** 2 + (lay[x]["y"] - lay[y]["y"]) ** 2) ** 0.5
        assert gap >= lay[x]["r"] + lay[y]["r"] - 1


def test_deterministic_and_independent_of_input_order() -> None:
    nodes = [own(f"r{i}", channel=36 if i % 2 else 40) for i in range(8)]
    edges = [{"a": f"r{i}", "b": f"r{i + 1}", "signal_dbm": -50 - 4 * i} for i in range(7)]
    out = run(nodes, edges)
    assert out["deterministic"]
    assert out["sameForShuffledInput"]


def test_fits_in_the_box_and_handles_empty_and_unlinked() -> None:
    out = run([], [])
    assert out["layout"]["nodes"] == {}
    out = run([own("a"), own("b"), own("c", group="b")], [])
    lay = out["layout"]
    for n in lay["nodes"].values():
        assert n["x"] - n["r"] >= 0
        assert n["y"] - n["r"] >= 0
        assert n["x"] + n["r"] <= lay["width"] + 0.01
        assert n["y"] + n["r"] <= lay["height"] + 0.01


def test_co_channel_overlap_is_reported() -> None:
    nodes = [own("a", channel=36), own("b", channel=36), own("c", channel=100)]
    edges = [
        {"a": "a", "b": "b", "signal_dbm": -45},
        {"a": "a", "b": "c", "signal_dbm": -45},
    ]
    out = run(nodes, edges)
    assert out["layout"]["overlaps"] == [["a", "b"]]


def test_helpers() -> None:
    out = run([], [])
    assert out["factors"]["strong"] < out["factors"]["mid"] < out["factors"]["weak"]
    assert out["factors"]["weak"] == pytest.approx(1.0)
    assert out["radii"]["loud"] > out["radii"]["quiet"]
    c = out["overlapCases"]
    assert c["sameFive"] and c["near24"]
    assert not (c["otherFive"] or c["far24"] or c["bands"] or c["unknown"])
    col = out["colors"]
    assert col["a"] == col["b"]
    assert len({col["a"], col["c"], col["d"], col["e"]}) == 4
