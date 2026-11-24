"""The layered topology layout (#303): fewer crossings than the old rows, deterministic, fast.

The layout is plain JavaScript without DOM (static/topolayout.js); these tests run it with node.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest

NODE = shutil.which("node")
SCRIPT = Path(__file__).parent / "js" / "layout_check.mjs"
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def dev(id_: str, name: str, role: str) -> dict[str, Any]:
    return {"id": id_, "name": name, "role": role, "site": "home"}


def cable(a: str, b: str, up: str | None = None, n: int = 0) -> dict[str, Any]:
    return {"id": f"{a}-{b}-{n}", "a": a, "b": b, "kind": "cable", "up": up}


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


def home() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Two ISP routers, a firewall, a gateway with a WireGuard arc, two switches, five APs."""
    nodes = [
        dev("isp-a", "ISP router A", "gateway"),
        dev("isp-b", "ISP router B", "gateway"),
        dev("fw", "Firewall", "gateway"),
        dev("pi", "Pi gateway", "gateway"),
        dev("sw-core", "Switch Core", "switch"),
        dev("sw-office", "Switch Office", "switch"),
        dev("ap-attic", "AP Attic", "ap"),
        dev("ap-garage", "AP Garage", "ap"),
        dev("ap-hall", "AP Hall", "ap"),
        dev("ap-office", "AP Office", "ap"),
        dev("ap-patio", "AP Patio", "ap"),
        {**dev("remote", "Branch office", "remote"), "site": "home"},
    ]
    edges = [
        cable("isp-a", "fw", up="b"),
        cable("isp-b", "pi", up="b"),
        cable("fw", "sw-office"),
        cable("fw", "sw-office", n=1),  # a second cable between the same two devices
        cable("pi", "sw-core"),
        cable("sw-core", "sw-office"),
        cable("sw-core", "ap-garage"),
        cable("sw-core", "ap-office"),
        cable("sw-office", "ap-attic"),
        cable("sw-office", "ap-hall"),
        cable("sw-office", "ap-patio"),
        {"id": "wg", "a": "pi", "b": "fw", "kind": "vpn", "up": None},
        {"id": "wg2", "a": "remote", "b": "pi", "kind": "vpn", "up": None},
    ]
    return nodes, edges


def test_layers_follow_role_and_uplink() -> None:
    r = run(*home())["ranks"]
    assert r["isp-a"] == r["isp-b"] == 1  # remote site on top, then the ISP routers
    assert r["remote"] == 0
    assert r["fw"] == r["pi"] == 2  # behind an ISP router: their WAN port is an uplink
    assert r["sw-core"] == r["sw-office"] == 3
    assert {r[a] for a in ("ap-attic", "ap-garage", "ap-hall", "ap-office", "ap-patio")} == {4}


def test_fewer_crossings_than_before() -> None:
    out = run(*home())
    assert out["previous"] >= 3  # the old rows do cross on this network
    assert out["crossings"] < out["previous"]
    assert out["crossings"] <= 1


def test_deterministic_and_independent_of_input_order() -> None:
    out = run(*home())
    assert out["deterministic"]
    assert out["sameForShuffledInput"]
    assert run(*home())["boxes"] == out["boxes"]


def test_parallel_links_are_one_pair() -> None:
    pairs = {p["key"]: p["edges"] for p in run(*home())["pairs"]}
    assert len(pairs["fw|sw-office"]) == 2


def test_devices_of_a_layer_do_not_overlap() -> None:
    out = run(*home())
    by_row: dict[float, list[list[float]]] = {}
    for x, y, w, _h in out["boxes"]:
        by_row.setdefault(y, []).append([x, w])
    for row in by_row.values():
        row.sort()
        for (x1, w1), (x2, _w2) in pairwise(row):
            assert x1 + w1 <= x2


def test_big_network_is_fast() -> None:
    """50 devices and 200 links."""
    nodes = [dev("gw", "Gateway", "gateway")]
    nodes += [dev(f"sw{i}", f"Switch {i:02d}", "switch") for i in range(8)]
    nodes += [dev(f"ap{i}", f"AP {i:02d}", "ap") for i in range(41)]
    edges = [cable("gw", f"sw{i}") for i in range(8)]
    edges += [
        cable(f"sw{i}", f"sw{(i * 3 + 1) % 8}", n=i) for i in range(8) if (i * 3 + 1) % 8 != i
    ]
    n = 0
    for i in range(41):
        for k in range(1 + i % 5):  # up to five cables or radios per AP
            edges.append(cable(f"sw{(i + k * 3) % 8}", f"ap{i}", n=n))
            n += 1
    while len(edges) < 200:
        edges.append(cable("gw", "sw0", n=n))
        n += 1
    assert len(nodes) == 50
    started = time.monotonic()
    out = run(nodes, edges)
    assert time.monotonic() - started < 20
    assert out["deterministic"]
    assert out["crossings"] <= out["previous"]


def test_two_sites_side_by_side() -> None:
    nodes = [
        {**dev("a", "A", "gateway"), "site": "one"},
        {**dev("b", "B", "gateway"), "site": "two"},
        {**dev("s", "S", "switch"), "site": "two"},
    ]
    out = run(nodes, [cable("b", "s")])
    xs = sorted(x for x, _y, _w, _h in out["boxes"])
    assert xs[0] < xs[1]
    assert out["ranks"] == {"a": 0, "b": 0, "s": 1}
