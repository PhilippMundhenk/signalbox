"""The topology diagram (#303): legend, device links, wires to ports, zoom, full screen, themes."""

from __future__ import annotations

import re
from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import add_lab, add_site, add_switch, api, observe, topology_state

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
    expect(app.get_by_test_id("topo-node")).to_have_count(3)


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
        "Inferred from addresses",  # a router behind another one (#375)
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
    app.locator('[data-testid="topo-node"][data-id="router"] .box').hover(
        position={"x": 140, "y": 30}
    )
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


def test_a_lag_is_one_bundled_link(app: Any) -> None:
    """#157: the cables of a LAG on both switches are one LAG bundle with both LAG names; the
    device page names the LAG of each member and its LACP state."""
    add_site(app)
    a = api(
        app,
        "POST",
        "/devices",
        {
            "name": "Core",
            "site_id": "home",
            "role": "switch",
            "adapter": "labswitch",
            "config": {"address": "192.0.2.2", "lag": True},
        },
    )
    b = api(
        app,
        "POST",
        "/devices",
        {
            "name": "Edge",
            "site_id": "home",
            "role": "switch",
            "adapter": "labswitch",
            "config": {"address": "192.0.2.3", "lag": True},
        },
    )
    observe(app)
    cable(app, f"{a['id']}/port/p3", f"{b['id']}/port/p3")
    cable(app, f"{a['id']}/port/p4", f"{b['id']}/port/p4")
    go(app, "#/topology")
    edge = app.get_by_test_id("topo-edge")
    expect(edge).to_have_count(1)
    expect(edge).to_have_attribute("data-lag", "ae1")
    expect(edge).to_have_class(re.compile(r"\blag\b"))
    badge = app.get_by_test_id("topo-bundle")
    expect(badge).to_have_attribute("data-lag", "true")
    expect(badge).to_have_attribute(
        "aria-label", re.compile(r"Link aggregation ae1 ↔ ae1 \(LACP \(active\)\)")
    )
    badge.click()
    expect(app.get_by_test_id("topo-edge")).to_have_count(2)
    go(app, f"#/device/{a['id']}")
    member = app.locator('[data-testid="port-node"][data-id$="/port/p3"]')
    expect(member).to_contain_text("member of ae1")
    expect(member).to_contain_text("aggregating")
    lag = app.locator('[data-testid="port-node"][data-id$="/port/ae1"]')
    expect(lag).to_contain_text("LACP (active)")
    expect(lag).to_contain_text("hash l3+l4")


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


def add_service(app: Any, name: str, url: str, **extra: Any) -> dict[str, Any]:
    body = {
        "name": name,
        "site_id": "home",
        "role": "other",
        "adapter": "labservice",
        "config": {"url": url},
        **extra,
    }
    result: dict[str, Any] = api(app, "POST", "/devices", body)
    return result


def test_a_service_at_the_address_of_a_device_is_drawn_inside_its_box(app: Any) -> None:
    """#387: a service on the router's address (another port) is a row in the router's box,
    a link to its page, never a box under "Not cabled"; the settings can name the host of a
    service on another address."""
    add_site(app)
    add_lab(app, "Router")
    add_service(app, "DNS filter", "https://192.0.2.1:3000")
    add_service(app, "Other filter", "https://192.0.2.99:3000", hosted_on="router")
    observe(app)
    go(app, "#/topology")
    expect(app.get_by_test_id("topo-node")).to_have_count(2)
    expect(app.get_by_test_id("topo-uncabled")).to_have_count(0)
    rows = app.locator('[data-testid="topo-node"][data-id="router"] [data-testid="topo-hosted"]')
    expect(rows).to_have_count(2)
    first = rows.and_(app.locator('[data-id="dns-filter"]'))
    expect(first).to_contain_text("Lab DNS filter:3000")
    expect(first).to_have_attribute("data-status", "ok")
    expect(app.get_by_test_id("topo-legend")).to_contain_text("Service running on a device")
    first.click()
    expect(app).to_have_url(re.compile(r"#/device/dns-filter$"))
    expect(app.get_by_test_id("runs-on")).to_have_text("Router")
    app.get_by_test_id("runs-on").click()
    expect(app).to_have_url(re.compile(r"#/device/router$"))
    expect(app.get_by_test_id("also-runs-here")).to_contain_text("DNS filter")
    expect(app.get_by_test_id("also-runs-here")).to_contain_text("Other filter")


def test_the_host_of_a_service_is_set_in_the_device_settings(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    add_service(app, "Resolver", "https://192.0.2.50:3000")
    observe(app)
    go(app, "#/topology")
    expect(app.get_by_test_id("topo-hosted")).to_have_count(0)
    go(app, "#/device/resolver/settings")
    app.get_by_test_id("device-hosted-on").select_option("router")
    app.get_by_test_id("device-save").click()
    # saved once the device page opens; leaving earlier cancels the request (#485). The settings
    # page shows the same title, so wait for the redirect itself: navigating away before it
    # lands lets the late redirect take the browser back off the topology (seen in CI)
    expect(app).to_have_url(re.compile(r"#/device/resolver$"))
    expect(app.get_by_test_id("device-title")).to_have_text("Resolver")
    assert api(app, "GET", "/devices/resolver")["hosted_on"] == "router"
    go(app, "#/topology")
    try:
        expect(app.get_by_test_id("topo-hosted")).to_have_count(1)
    except AssertionError as exc:
        raise AssertionError(f"{exc}\n{topology_state(app)}") from exc
    expect(app.get_by_test_id("topo-uncabled")).to_have_count(0)


def add_wan_router(
    app: Any, name: str, site: str, lan: str, wan: str = "203.0.113.30/24", up: bool = True
) -> None:
    api(
        app,
        "POST",
        "/devices",
        {
            "name": name,
            "site_id": site,
            "role": "gateway",
            "adapter": "labwan",
            "config": {"lan": lan, "wan": wan, "up": up},
        },
    )


def test_one_gateway_has_one_edge_to_the_internet_cloud(app: Any) -> None:
    add_site(app)
    add_wan_router(app, "Router", "home", "192.0.2.1/24")
    observe(app)
    go(app, "#/topology")
    cloud = app.locator('[data-testid="topo-node"][data-id="internet"]')
    expect(cloud).to_have_count(1)
    expect(cloud.get_by_test_id("topo-device-link")).to_have_count(0)  # not a device
    wan = app.get_by_test_id("topo-wan")
    expect(wan).to_have_count(1)
    expect(wan).to_have_attribute("data-nat", "public")
    expect(wan).to_have_attribute("data-state", "online")
    expect(wan.locator("title")).to_contain_text("Internet connection wan")
    expect(wan.locator("title")).to_contain_text("203.0.113.30")
    # the cloud sits above the border router
    assert box(cloud)["y"] < box(app.locator('[data-testid="topo-node"][data-id="router"]'))["y"]
    expect(app.get_by_test_id("topo-legend")).to_contain_text("Internet connection of a router")
    # the cloud is no device
    assert "internet" not in {d["id"] for d in api(app, "GET", "/network")["devices"]}


def test_a_router_behind_another_router_has_no_cloud_edge(app: Any) -> None:
    add_site(app)
    add_wan_router(app, "Outer", "home", "192.0.2.1/24")
    add_wan_router(app, "Inner", "home", "198.51.100.1/24", wan="192.0.2.7/24")
    observe(app)
    go(app, "#/topology")
    expect(app.get_by_test_id("topo-wan")).to_have_count(1)
    expect(app.get_by_test_id("topo-wan")).to_have_attribute("data-a", "outer/uplink/wan")
    expect(app.locator('[data-testid="topo-edge"][data-id^="address:"]')).to_have_count(1)


def test_two_sites_share_one_cloud(app: Any) -> None:
    add_site(app, "Home")
    add_site(app, "Office")
    add_wan_router(app, "Home router", "home", "192.0.2.1/24")
    add_wan_router(app, "Office router", "office", "198.51.100.1/24", wan="203.0.113.77/24")
    observe(app)
    go(app, "#/topology")
    expect(app.locator('[data-testid="topo-node"][data-id="internet"]')).to_have_count(1)
    expect(app.get_by_test_id("topo-wan")).to_have_count(2)


def test_a_down_uplink_is_drawn_down(app: Any) -> None:
    add_site(app)
    add_wan_router(app, "Router", "home", "192.0.2.1/24", up=False)
    observe(app)
    go(app, "#/topology")
    wan = app.get_by_test_id("topo-wan")
    expect(wan).to_have_attribute("data-down", "true")
    expect(wan).to_have_class(re.compile("wan-down"))
    expect(wan.locator("title")).to_contain_text("down")
    for theme in ("light", "dark"):
        app.evaluate(f"document.documentElement.setAttribute('data-theme', '{theme}')")
        expect(app.locator("[data-testid=topology-graph] .node.role-internet .box")).to_have_count(
            1
        )
        assert wan.evaluate("e => getComputedStyle(e).stroke") != "rgb(0, 0, 0)"
