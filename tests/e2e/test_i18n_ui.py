"""Translations (#204): the language comes from the browser or the setting, German is complete."""

from __future__ import annotations

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
