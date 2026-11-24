"""The Wi-Fi map (#366): bubbles per radio and anonymous neighbour, band filter, legend, full
screen, click-through to the device, and that no foreign name reaches the page."""

from __future__ import annotations

import re
from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import add_lab, add_site, api, observe

pytestmark = pytest.mark.e2e


def setup(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    observe(app)
    app.goto(f"{app.server.url}/#/wireless/map")
    app.reload()
    expect(app.get_by_test_id("wifimap-graph")).to_be_visible()


def test_map_shows_own_radios_and_anonymous_neighbours(app: Any) -> None:
    setup(app)
    expect(app.get_by_test_id("wireless-tab-map")).to_have_attribute("aria-current", "page")
    bubbles = app.get_by_test_id("wifimap-bubble")
    expect(bubbles).to_have_count(4)
    expect(app.locator('[data-testid="wifimap-bubble"][data-kind="own"]')).to_have_count(2)
    neighbours = app.locator('[data-testid="wifimap-bubble"][data-kind="neighbour"]')
    expect(neighbours).to_have_count(2)
    expect(neighbours.first).to_contain_text("Neighbour 1")
    expect(neighbours.first).to_contain_text("channel 6")
    expect(app.get_by_test_id("wifimap-inferred")).to_contain_text("not real geometry")
    expect(app.get_by_test_id("wifimap-noscan")).to_have_count(0)
    expect(app.get_by_test_id("wifimap-overlaps")).to_contain_text(re.compile(r"overlaps: [1-9]"))
    # the privacy rule: no foreign SSID or BSSID anywhere on the page or in the data
    text = app.locator("body").inner_text()
    for foreign in ("Neighbour-A", "02:5e:00:00:01"):
        assert foreign not in text
        assert foreign not in app.content()
    raw = app.request.get(f"{app.server.url}/api/wifi-map").text()
    assert "Neighbour-A" not in raw
    assert "02:5e" not in raw
    assert "bssid" not in raw


def test_band_filter_and_legend(app: Any) -> None:
    setup(app)
    legend = app.get_by_test_id("wifimap-legend")
    expect(legend).to_be_visible()
    expect(legend).to_contain_text("Co-channel overlap")
    expect(legend).to_contain_text("2.4 GHz, channel 6")
    app.get_by_test_id("wifimap-band").select_option("5")
    expect(app.get_by_test_id("wifimap-bubble")).to_have_count(1)
    expect(app.locator('[data-testid="wifimap-bubble"]').first).to_have_attribute("data-band", "5")
    app.get_by_test_id("wifimap-band").select_option("")
    expect(app.get_by_test_id("wifimap-bubble")).to_have_count(4)


def test_click_through_to_the_device(app: Any) -> None:
    setup(app)
    app.get_by_test_id("wifimap-device-link").first.click()
    expect(app).to_have_url(re.compile(r"#/device/router$"))


def test_full_screen_and_zoom(app: Any) -> None:
    setup(app)
    svg = app.get_by_test_id("wifimap-graph")
    before = svg.get_attribute("data-zoom")
    app.get_by_test_id("wifimap-zoom-in").click()
    assert svg.get_attribute("data-zoom") != before
    card = app.get_by_test_id("wifimap-card")
    app.get_by_test_id("wifimap-full").click()
    expect(card).to_have_attribute("data-full", "true")
    expect(app.get_by_test_id("wifimap-legend")).to_be_visible()
    app.get_by_test_id("wifimap-full").click()
    expect(card).to_have_attribute("data-full", "false")


def test_networks_tab_is_unchanged(app: Any) -> None:
    setup(app)
    app.get_by_test_id("wireless-tab-networks").click()
    expect(app.get_by_test_id("ssid").first).to_be_visible()
    assert api(app, "GET", "/wifi-map")["has_scan"] is True
