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


def own(
    id_: str, band: str = "5", channel: int = 36, group: str = "a", ap: str | None = None
) -> dict[str, Any]:
    return {
        "id": id_,
        "kind": "own",
        "band": band,
        "channel": channel,
        "group": group,
        "ap": ap or id_,
        "label": ap or id_,
    }


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
    assert d["a|b"] < 2 * 34


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


def dist(lay: dict[str, Any], a: str, b: str) -> float:
    return float(((lay[a]["x"] - lay[b]["x"]) ** 2 + (lay[a]["y"] - lay[b]["y"]) ** 2) ** 0.5)


def two_sites() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = [
        own("a1", group="a", ap="apA1"),
        own("a2", band="2.4", channel=6, group="a", ap="apA1"),
        own("a3", group="a", ap="apA2"),
        own("b1", group="b", ap="apB1"),
        own("b2", band="2.4", channel=6, group="b", ap="apB1"),
        neighbour("n1", dbm=-60),
        neighbour("n2", dbm=-75),
    ]
    edges = [
        {"a": "a1", "b": "a3", "signal_dbm": -55},
        {"a": "a1", "b": "n1", "signal_dbm": -55},
        {"a": "b1", "b": "n2", "signal_dbm": -70},
        # the sites cannot hear each other: such a signal must not pull them together
        {"a": "a1", "b": "b1", "signal_dbm": -40},
        {"a": "a3", "b": "n2", "signal_dbm": -90},
    ]
    return nodes, edges


def test_no_cross_site_attraction_sites_side_by_side() -> None:
    nodes, edges = two_sites()
    lay = run(nodes, edges)["layout"]
    frames = {f["id"]: f for f in lay["sites"]}
    assert set(frames) == {"a", "b"}
    fa, fb = frames["a"], frames["b"]
    assert fa["x"] + fa["width"] < fb["x"]  # side by side, not overlapping
    # every radio sits inside the frame of its own site
    for id_, f in (("a1", fa), ("a2", fa), ("a3", fa), ("n1", fa), ("b1", fb), ("b2", fb)):
        n = lay["nodes"][id_]
        assert f["x"] <= n["x"] - n["r"] and n["x"] + n["r"] <= f["x"] + f["width"]
        assert f["y"] <= n["y"] - n["r"] and n["y"] + n["r"] <= f["y"] + f["height"]
    # the neighbour heard best by site B belongs to B, the cross-site edge is not drawn
    nb = lay["nodes"]["n2"]
    assert fb["x"] <= nb["x"] <= fb["x"] + fb["width"]
    assert {"a": "a1", "b": "b1"} not in lay["links"]


def test_labels_do_not_overlap_each_other_or_other_bubbles() -> None:
    nodes, edges = two_sites()
    lay = run(nodes, edges)["layout"]
    labels = lay["labels"]
    assert sorted(label["id"] for label in labels) == ["apA1", "apA2", "apB1"]  # one per AP
    for i, p in enumerate(labels):
        for q in labels[i + 1 :]:
            apart = (
                p["x"] + p["w"] <= q["x"]
                or q["x"] + q["w"] <= p["x"]
                or p["y"] + p["h"] <= q["y"]
                or q["y"] + q["h"] <= p["y"]
            )
            assert apart, (p["id"], q["id"])
    mine = {"apA1": {"a1", "a2"}, "apA2": {"a3"}, "apB1": {"b1", "b2"}}
    for label in labels:
        for id_, n in lay["nodes"].items():
            if id_ in mine[label["id"]]:
                continue
            gx = max(label["x"] - n["x"], 0, n["x"] - (label["x"] + label["w"]))
            gy = max(label["y"] - n["y"], 0, n["y"] - (label["y"] + label["h"]))
            assert (gx * gx + gy * gy) ** 0.5 >= n["r"] - 0.5, (label["id"], id_)


def test_radios_of_one_ap_are_adjacent() -> None:
    nodes, edges = two_sites()
    lay = run(nodes, edges)["layout"]["nodes"]
    for a, b in (("a1", "a2"), ("b1", "b2")):
        gap = dist(lay, a, b) - lay[a]["r"] - lay[b]["r"]
        assert -0.5 <= gap <= 8


def test_radios_that_do_not_hear_each_other_keep_a_distance() -> None:
    nodes, edges = two_sites()
    lay = run(nodes, edges)["layout"]["nodes"]
    heard = {frozenset((e["a"], e["b"])) for e in edges}
    same_ap = {frozenset(("a1", "a2")), frozenset(("b1", "b2"))}
    site = {"a1": "a", "a2": "a", "a3": "a", "n1": "a", "b1": "b", "b2": "b", "n2": "b"}
    ids = sorted(lay)
    for i, a in enumerate(ids):
        for b in ids[i + 1 :]:
            if site[a] == site[b] and frozenset((a, b)) not in heard | same_ap:
                assert dist(lay, a, b) >= lay[a]["r"] + lay[b]["r"] + 13, (a, b)


def test_neighbours_are_smaller_than_own_radios() -> None:
    out = run([], [])
    assert out["radii"]["loud"] < out["radii"]["own"]
