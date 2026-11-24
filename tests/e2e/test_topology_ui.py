"""The topology diagram (#303): legend, device links, wires to ports, zoom, full screen, themes."""

from __future__ import annotations

import re
from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import add_lab, add_site, add_switch, api, observe

pytestmark = pytest.mark.e2e


def go(page: Any, hash_: str) -> None:
    page.goto(f"{page.server.url}/{hash_}")
    page.reload()
    page.locator("main h1").first.wait_for()


def cable(app: Any, a: str, b: str) -> None:
    api(app, "POST", "/links", {"a": a, "b": b, "kind": "cable"})


def setup(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    add_switch(app, "Core switch")
    observe(app)
    cable(app, "router/port/lan2", "core-switch/port/p1")
    go(app, "#/topology")
    expect(app.get_by_test_id("topo-node")).to_have_count(2)


def box(locator: Any) -> dict[str, float]:
    result: dict[str, float] = locator.bounding_box()
    return result


def test_legend_is_visible_and_collapsible(app: Any) -> None:
    setup(app)
    legend = app.get_by_test_id("topo-legend")
    expect(legend).to_be_visible()
    for text in (
        "Carries the selected VLAN",
        "Ends disagree",
        "VPN tunnel",
        "Inferred from the MAC table",
    ):
        expect(legend).to_contain_text(text)
    for text in ("Partly read", "Unmanaged remote site", "Internal port"):
        expect(legend).to_contain_text(text)
    legend.locator("summary").click()
    expect(legend).not_to_have_attribute("open", re.compile("."))
    expect(legend.get_by_text("Partly read")).to_be_hidden()
    legend.locator("summary").click()
    expect(legend.get_by_text("Partly read")).to_be_visible()


def test_device_name_opens_the_device_page(app: Any) -> None:
    setup(app)
    app.locator(
        '[data-testid="topo-node"][data-id="router"] [data-testid="topo-device-link"]'
    ).click()
    expect(app).to_have_url(re.compile(r"#/device/router$"))
    expect(app.locator("main h1").first).to_contain_text("Router")


def test_wires_end_at_port_squares(app: Any) -> None:
    setup(app)
    edge = app.get_by_test_id("topo-edge")
    d = edge.get_attribute("d")
    assert d is not None
    numbers = [float(x) for x in re.findall(r"-?\d+(?:\.\d+)?", d)]
    start, end = (numbers[0], numbers[1]), (numbers[-2], numbers[-1])
    ends = []
    for attr in ("data-a", "data-b"):
        rect = app.locator(f'[data-testid="topo-port"][data-id="{edge.get_attribute(attr)}"]')
        ends.append(
            tuple(float(rect.get_attribute(k) or 0) for k in ("x", "y", "width", "height")),
        )
    # one end is at the lower edge of the upper device's port, the other at the top of the lower one
    for point, (x, y, w, h) in zip((start, end), sorted(ends, key=lambda r: r[1]), strict=True):
        assert x <= point[0] <= x + w
        assert abs(point[1] - y) <= 0.5 or abs(point[1] - (y + h)) <= 0.5
    # and both ports are drawn, with the wire between the boxes
    assert start[1] < end[1]


def test_hover_highlights_links_and_neighbours(app: Any) -> None:
    setup(app)
    svg = app.get_by_test_id("topology-graph")
    app.locator('[data-testid="topo-node"][data-id="router"] .box').hover()
    expect(svg).to_have_class(re.compile("hovering"))
    expect(app.get_by_test_id("topo-edge")).to_have_class(re.compile("hot"))
    expect(app.locator('[data-testid="topo-node"][data-id="core-switch"]')).to_have_class(
        re.compile("near")
    )
    app.mouse.move(2, 2)
    expect(svg).not_to_have_class(re.compile("hovering"))


def test_zoom_buttons_and_reset(app: Any) -> None:
    setup(app)
    svg = app.get_by_test_id("topology-graph")
    before = float(svg.get_attribute("data-zoom") or 0)
    app.get_by_test_id("topo-zoom-in").click()
    zoomed = float(svg.get_attribute("data-zoom") or 0)
    assert zoomed > before
    app.get_by_test_id("topo-zoom-out").click()
    app.get_by_test_id("topo-zoom-out").click()
    assert float(svg.get_attribute("data-zoom") or 0) < zoomed
    app.get_by_test_id("topo-zoom-reset").click()
    assert float(svg.get_attribute("data-zoom") or 0) == before
    # the wheel zooms, a drag on the background pans
    wrap = box(app.locator(".topo-wrap"))
    app.mouse.move(wrap["x"] + 30, wrap["y"] + 30)
    app.mouse.wheel(0, -300)
    assert float(svg.get_attribute("data-zoom") or 0) > before
    transform = app.locator(".topo .viewport").get_attribute("transform")
    app.mouse.down()
    app.mouse.move(wrap["x"] + 90, wrap["y"] + 80, steps=4)
    app.mouse.up()
    assert app.locator(".topo .viewport").get_attribute("transform") != transform


def test_full_screen_toggles(app: Any) -> None:
    setup(app)
    card = app.get_by_test_id("topo-card")
    button = app.get_by_test_id("topo-full")
    expect(card).to_have_attribute("data-full", "false")
    small = box(card)
    button.click()
    expect(card).to_have_attribute("data-full", "true")
    expect(button).to_have_attribute("aria-pressed", "true")
    app.wait_for_timeout(300)
    large = box(card)
    assert large["width"] > small["width"]  # the card fills the window
    assert large["x"] == 0 and large["y"] == 0
    expect(app.get_by_test_id("topo-legend")).to_be_visible()
    button.click()
    expect(card).to_have_attribute("data-full", "false")
    expect(button).to_have_attribute("aria-pressed", "false")


def test_parallel_cables_are_bundled_and_expand(app: Any) -> None:
    setup(app)
    cable(app, "router/port/lan3", "core-switch/port/p2")
    go(app, "#/topology")
    expect(app.get_by_test_id("topo-edge")).to_have_count(1)
    badge = app.get_by_test_id("topo-bundle")
    expect(badge).to_have_attribute("data-count", "2")
    expect(app.get_by_test_id("topo-edge")).to_have_attribute("data-count", "2")
    badge.click()
    expect(app.get_by_test_id("topo-edge")).to_have_count(2)
    app.get_by_test_id("topo-bundle").click()
    expect(app.get_by_test_id("topo-edge")).to_have_count(1)


def test_port_click_and_both_themes(app: Any) -> None:
    setup(app)
    app.locator('[data-testid="topo-port"][data-id="router/port/lan1"]').click()
    expect(app.get_by_test_id("port-panel")).to_be_visible()
    html = app.locator("html")
    for theme in ("light", "dark"):
        app.evaluate(f"document.documentElement.setAttribute('data-theme', '{theme}')")
        for testid in ("topo-legend", "topology-graph"):
            expect(app.get_by_test_id(testid)).to_be_visible()
        stroke = app.locator(".topo .box").first.evaluate("e => getComputedStyle(e).fill")
        assert stroke
    fills = {}
    for theme in ("light", "dark"):
        app.evaluate(f"document.documentElement.setAttribute('data-theme', '{theme}')")
        fills[theme] = app.locator(".topo .box").first.evaluate("e => getComputedStyle(e).fill")
    assert fills["light"] != fills["dark"]
    expect(html).to_have_attribute("data-theme", "dark")
