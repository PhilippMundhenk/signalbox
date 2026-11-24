"""Translations (#204): the language comes from the browser or the setting, German is complete."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import PASSWORD, add_lab, add_site, observe

pytestmark = pytest.mark.e2e


def login(page: Any, server: Any) -> None:
    page.set_default_timeout(15000)
    page.server = server
    page.goto(server.url)
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    page.get_by_test_id("logout").wait_for()


def test_german_from_the_setting_on_the_main_pages(page: Any, server: Any) -> None:
    page.add_init_script("localStorage.setItem('lang', 'de')")
    page.set_default_timeout(15000)
    page.goto(server.url)
    expect(page.locator("html")).to_have_attribute("lang", "de")
    expect(page.get_by_test_id("login-submit")).to_have_text("Anmelden")
    expect(page.get_by_test_id("disclaimer")).to_contain_text("unabhängiges Open-Source-Projekt")
    login(page, server)
    add_site(page)
    add_lab(page, "Gateway")
    observe(page)
    expected = {
        "#/": "Befunde",
        "#/devices": "Geräte",
        "#/segments": "Segmente",
        "#/dhcp-dns": "DHCP",
        "#/settings": "Einstellungen",
        "#/desired": "Soll-Zustand",
        "#/changes": "Änderungen",
    }
    for hash_, heading in expected.items():
        page.goto(f"{server.url}/{hash_}")
        page.reload()
        expect(page.locator("main h1").first).to_contain_text(heading)
    expect(page.get_by_test_id("nav-findings")).to_contain_text("Befunde")
    page.goto(f"{server.url}/#/devices/new")
    page.reload()
    expect(page.locator("main")).to_contain_text("Gerät")
    expect(page.locator("main")).not_to_contain_text("Add a device")


def test_browser_language_and_override_in_settings(browser: Any, server: Any) -> None:
    context = browser.new_context(locale="de-DE")
    page = context.new_page()
    try:
        login(page, server)
        expect(page.locator("html")).to_have_attribute("lang", "de")
        expect(page.get_by_test_id("nav-settings")).to_contain_text("Einstellungen")
        page.goto(f"{server.url}/#/settings")
        page.get_by_test_id("language").select_option("en")
        expect(page.get_by_test_id("nav-settings")).to_contain_text("Settings")
        expect(page.locator("html")).to_have_attribute("lang", "en")
        page.reload()
        expect(page.get_by_test_id("nav-settings")).to_contain_text("Settings")
    finally:
        context.close()


def test_unknown_language_falls_back_to_english(browser: Any, server: Any) -> None:
    context = browser.new_context(locale="sv-SE")
    page = context.new_page()
    try:
        login(page, server)
        expect(page.locator("html")).to_have_attribute("lang", "en")
        expect(page.get_by_test_id("nav-findings")).to_contain_text("Findings")
    finally:
        context.close()


def _catalogue_languages() -> list[dict[str, str]]:
    index = Path(__file__).parents[2] / "src/signalbox/web/static/i18n/index.json"
    entries: list[dict[str, str]] = json.loads(index.read_text(encoding="utf-8"))
    return entries


def test_language_picker_lists_every_index_entry(page: Any, server: Any) -> None:
    login(page, server)
    page.goto(f"{server.url}/#/settings")
    options = page.get_by_test_id("language").locator("option")
    expected = [e["name"] for e in _catalogue_languages()]
    expect(options).to_have_count(len(expected) + 1)  # plus "automatic"
    assert options.all_inner_texts()[1:] == expected
    assert [o.get_attribute("value") for o in options.all()][1:] == [
        e["code"] for e in _catalogue_languages()
    ]


#: A catalogue key shown instead of a text: "nav.findings", "devices.col.name", ...
KEY_SHOWN = re.compile(
    r"\b(?:nav|devices|findings|settings|common|overview|segments|ack|clients|changes|msg|rule)"
    r"\.[A-Za-z][A-Za-z0-9_.]*"
)


@pytest.mark.parametrize("code", ["es", "fr", "pt"])
def test_overview_and_device_page_render_in_each_new_language(
    page: Any, server: Any, code: str
) -> None:
    """Smoke test (#204): no catalogue key shown for a missing text, no overflowing nav."""
    page.add_init_script(f"localStorage.setItem('lang', '{code}')")
    login(page, server)
    expect(page.locator("html")).to_have_attribute("lang", code)
    add_site(page)
    device = add_lab(page, "Gateway")
    observe(page)
    for hash_ in ("#/", "#/devices", f"#/device/{device['id']}"):
        page.goto(f"{server.url}/{hash_}")
        page.reload()
        page.locator("main h1").first.wait_for()
        text = page.locator("body").inner_text()
        assert not KEY_SHOWN.findall(text), (code, hash_, KEY_SHOWN.findall(text))
        assert "Add a device" not in text
        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
        )
        assert not overflow, f"{code} {hash_}: page scrolls horizontally"
