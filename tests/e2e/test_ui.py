"""The web interface, end to end in Chromium against fake adapters."""

from __future__ import annotations

import re
from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import PASSWORD, add_lab, add_site, add_switch, api, observe
from .fakes import FINGERPRINT

pytestmark = pytest.mark.e2e

VIEWS = ["#/", "#/devices", "#/topology", "#/segments", "#/wireless", "#/dhcp-dns", "#/clients"]


def go(page: Any, hash_: str) -> None:
    """Open a view and wait until it has rendered (a fresh page load, like a bookmark)."""
    page.goto(f"{page.server.url}/{hash_}")
    page.reload()
    page.locator("main h1").first.wait_for()


def test_refused_and_successful_login_and_logout(page: Any, server: Any) -> None:
    page.set_default_timeout(15000)
    page.goto(server.url)
    expect(page.get_by_test_id("disclaimer")).to_contain_text("not affiliated with")
    page.get_by_test_id("login-password").fill("wrong-password")
    page.get_by_test_id("login-submit").click()
    expect(page.get_by_test_id("login-error")).to_contain_text("Wrong password")
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    expect(page.get_by_test_id("nav-findings")).to_have_attribute("aria-current", "page")
    expect(page.get_by_test_id("version")).to_contain_text("Signalbox ")
    page.get_by_test_id("logout").click()
    expect(page.get_by_test_id("login-submit")).to_be_visible()
    page.reload()
    expect(page.get_by_test_id("login-submit")).to_be_visible()


def test_first_start_create_site_and_add_device_from_schema(app: Any) -> None:
    expect(app.get_by_test_id("empty")).to_contain_text("No devices yet")
    app.get_by_test_id("empty-add-device").click()
    # no site yet: offered inline
    expect(app.get_by_test_id("first-site")).to_be_visible()
    expect(app.get_by_test_id("device-save")).to_be_disabled()
    expect(app.get_by_test_id("first-site-name")).to_have_value("Home")
    app.get_by_test_id("first-site-create").click()
    expect(app.get_by_test_id("device-site")).to_have_value("home")

    app.get_by_test_id("device-adapter").select_option("lab")
    roles = app.get_by_test_id("device-role").locator("option")
    expect(roles).to_have_count(2)  # the adapter's roles only
    expect(app.get_by_test_id("device-role")).not_to_contain_text("Switch")
    # form from the JSON schema: defaults, types, enum, secret
    expect(app.get_by_test_id("cfg-port")).to_have_value("443")
    expect(app.get_by_test_id("cfg-port")).to_have_attribute("type", "number")
    expect(app.get_by_test_id("cfg-verify_tls")).to_be_checked()
    expect(app.get_by_test_id("cfg-mode").locator("option")).to_have_count(2)
    expect(app.get_by_test_id("cfg-password")).to_have_attribute("type", "password")
    expect(app.get_by_test_id("config-form")).to_contain_text("Address or name of the device")

    app.get_by_test_id("device-save").click()
    expect(app.get_by_test_id("form-errors")).to_contain_text("Give the device a name")
    expect(app.get_by_test_id("form-errors")).to_contain_text("Password is required")
    app.get_by_test_id("device-name").fill("Main router")
    app.get_by_test_id("cfg-host").fill("192.0.2.1")
    app.get_by_test_id("cfg-port").fill("8443")
    app.get_by_test_id("cfg-mode").select_option("basic")
    app.get_by_test_id("cfg-password").fill("device-secret")
    app.get_by_test_id("device-save").click()

    # the new device's page tests the connection right away
    expect(app.get_by_test_id("device-title")).to_have_text("Main router")
    expect(app.get_by_test_id("test-result").get_by_test_id("status")).to_have_attribute(
        "data-status", "ok"
    )
    expect(app.get_by_test_id("test-counts")).to_contain_text("3 ports")
    app.get_by_test_id("test").click()
    expect(app.get_by_test_id("test-counts")).to_contain_text("3 SSIDs")

    stored = api(app, "GET", "/devices/main-router")
    assert stored["config"]["port"] == 8443 and stored["config"]["mode"] == "basic"
    assert stored["secrets_set"] == ["password"] and "device-secret" not in str(stored)

    # edit: the secret is stored and kept when left empty
    app.get_by_test_id("tab-settings").click()
    expect(app.get_by_test_id("cfg-password")).to_have_attribute(
        "placeholder", "stored — leave empty to keep"
    )
    expect(app.get_by_test_id("cfg-port")).to_have_value("8443")
    app.get_by_test_id("device-name").fill("Router")
    app.get_by_test_id("device-save").click()
    expect(app.get_by_test_id("device-title")).to_have_text("Router")
    assert api(app, "GET", "/devices/main-router")["secrets_set"] == ["password"]

    app.get_by_test_id("nav-devices").click()
    row = app.get_by_test_id("device-row")
    expect(row).to_have_count(1)
    expect(row).to_contain_text("Lab router")
    expect(row.get_by_test_id("status")).to_have_attribute("data-status", "ok")


def test_untrusted_certificate_trust_flow(app: Any) -> None:
    add_site(app)
    add_lab(app, "Edge", host="untrusted.example")
    go(app, "#/device/edge")
    app.get_by_test_id("test").click()
    expect(app.get_by_test_id("test-result").get_by_test_id("status")).to_have_attribute(
        "data-status", "untrusted-certificate"
    )
    fp = app.get_by_test_id("fingerprint")
    grouped = ":".join(FINGERPRINT.upper()[i : i + 2] for i in range(0, 64, 2))
    expect(fp).to_have_text(grouped)
    expect(app.get_by_test_id("untrusted")).to_contain_text("compare this SHA-256 fingerprint")
    app.get_by_test_id("trust").click()
    expect(app.get_by_test_id("test-result").get_by_test_id("status")).to_have_attribute(
        "data-status", "ok"
    )
    expect(app.get_by_test_id("untrusted")).to_have_count(0)
    assert api(app, "GET", "/devices/edge")["pinned_fingerprint"] == FINGERPRINT


def test_unreachable_device_and_findings_with_fix(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    add_lab(app, "Cellar", host="down.example")
    go(app, "#/")
    expect(app.get_by_test_id("not-read")).to_be_visible()
    app.get_by_test_id("observe").click()
    open_wifi = app.locator('[data-testid="finding"][data-rule="lab.open-wifi"]')
    expect(open_wifi).to_have_count(1)
    expect(open_wifi.get_by_test_id("finding-fix")).to_contain_text("Use WPA3 Personal")
    expect(open_wifi.get_by_test_id("object-ref")).to_contain_text("Router · SSID Guest")
    expect(open_wifi.get_by_test_id("finding-since")).to_contain_text("Since")
    unreachable = app.locator('[data-testid="finding"][data-rule="signalbox.read"]')
    expect(unreachable).to_contain_text("Cellar is unreachable")
    expect(unreachable.get_by_test_id("finding-fix")).to_contain_text("Check that the device is on")
    # severity filter
    app.get_by_test_id("filter-severity").select_option("error")
    expect(open_wifi).to_have_count(0)
    app.get_by_test_id("filter-severity").select_option("")
    expect(open_wifi).to_have_count(1)
    # device list status
    app.get_by_test_id("nav-devices").click()
    cellar = app.locator('[data-testid="device-row"][data-id="cellar"]')
    expect(cellar.get_by_test_id("status")).to_have_attribute("data-status", "unreachable")

    # resolve: delete the unreachable device, read again, show resolved
    api(app, "DELETE", "/devices/cellar")
    observe(app)
    go(app, "#/")
    expect(unreachable).to_have_count(0)
    app.get_by_test_id("show-resolved").check()
    expect(unreachable.get_by_test_id("resolved")).to_be_visible()


def test_concept_views_show_the_network(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    observe(app)
    go(app, "#/devices")
    expect(app.get_by_test_id("device-first-seen")).to_have_count(1)
    expect(app.get_by_test_id("device-last-ok")).to_have_count(1)
    go(app, "#/segments")
    expect(app.get_by_test_id("segment")).to_have_count(2)
    office = app.locator('[data-testid="segment"][data-id="home/segment/10"]')
    expect(office).to_contain_text("Office")
    expect(office.get_by_test_id("segment-member")).to_contain_text("lan1")
    expect(office.get_by_test_id("subnet")).to_contain_text("192.0.2.1/24")

    go(app, "#/wireless")
    expect(app.get_by_test_id("ssid")).to_have_count(2)
    home = app.get_by_test_id("ssid").filter(has_text="Home")
    expect(home.get_by_test_id("wlan-row")).to_have_count(2)
    expect(home).to_contain_text("WPA3 Personal")
    expect(home).to_contain_text("802.11r on")
    expect(app.get_by_test_id("radio-row")).to_have_count(2)
    expect(app.get_by_test_id("radios")).to_contain_text("80 MHz")

    go(app, "#/dhcp-dns")
    expect(app.get_by_test_id("dhcp-server")).to_have_count(2)
    expect(app.get_by_test_id("reservation")).to_contain_text("printer")
    expect(app.get_by_test_id("host-record")).to_contain_text("printer.lan")

    go(app, "#/clients")
    expect(app.get_by_test_id("client-row")).to_have_count(2)
    expect(app.get_by_test_id("client-first-seen")).to_have_count(2)  # observation history
    app.get_by_test_id("client-filter").fill("laptop")
    expect(app.get_by_test_id("client-row")).to_have_count(1)
    expect(app.get_by_test_id("client-row")).to_contain_text("Router · SSID Home")

    go(app, "#/device/router/advanced")
    expect(app.get_by_test_id("raw-port")).to_have_count(3)
    expect(app.get_by_test_id("raw-port-table")).to_contain_text('"led":"green"')


def test_topology_manual_link_and_vlan_highlight(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    add_switch(app, "Core switch")
    observe(app)
    go(app, "#/topology")
    expect(app.get_by_test_id("topo-node")).to_have_count(2)
    expect(app.get_by_test_id("no-links")).to_be_visible()

    app.get_by_test_id("link-a-device").select_option("router")
    app.get_by_test_id("link-a-port").select_option("router/port/lan2")
    app.get_by_test_id("link-b-device").select_option("core-switch")
    app.get_by_test_id("link-b-port").select_option("core-switch/port/p1")
    app.get_by_test_id("link-add").click()
    row = app.get_by_test_id("link-row")
    expect(row).to_have_count(1)
    expect(row).to_contain_text("entered")
    expect(app.get_by_test_id("topo-edge")).to_have_count(1)

    # VLAN 10 is tagged on both ends, VLAN 20 only on the router
    edge = app.get_by_test_id("topo-edge")
    app.get_by_test_id("topo-segment").select_option("home/segment/10")
    expect(edge).to_have_attribute("data-state", "carry")
    expect(app.get_by_test_id("bad-end")).to_have_count(0)
    app.get_by_test_id("topo-segment").select_option("home/segment/20")
    expect(edge).to_have_attribute("data-state", "inconsistent")
    expect(app.get_by_test_id("bad-end")).to_have_count(1)
    expect(edge).to_have_class(re.compile("inconsistent"))

    # clients under their port
    app.locator('[data-testid="topo-port"][data-id="router/port/lan1"]').click()
    expect(app.get_by_test_id("port-client")).to_contain_text("printer")

    app.get_by_test_id("link-delete").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("no-links")).to_be_visible()
    assert api(app, "GET", "/links") == []


def test_settings_sites_rules_and_delete_device(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    go(app, "#/settings")
    expect(app.get_by_test_id("site-row")).to_have_count(1)
    app.get_by_test_id("site-name").fill("Office")
    app.get_by_test_id("site-add").click()
    expect(app.get_by_test_id("site-row")).to_have_count(2)
    office = app.get_by_test_id("site-row").filter(has_text="Office")
    office.get_by_test_id("site-rename").click()
    app.get_by_test_id("site-rename-name").fill("Branch")
    app.get_by_test_id("site-rename-save").click()
    expect(app.get_by_test_id("sites")).to_contain_text("Branch")
    home = app.get_by_test_id("site-row").filter(has_text="Home")
    expect(home.get_by_test_id("site-delete")).to_be_disabled()  # has a device
    app.get_by_test_id("site-row").filter(has_text="Branch").get_by_test_id("site-delete").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("site-row")).to_have_count(1)
    # password fixed by the environment
    expect(app.get_by_test_id("password-fixed")).to_be_visible()
    expect(app.get_by_test_id("pw-new")).to_have_count(0)
    expect(app.locator('[data-testid="rule"][data-id="lab.open-wifi"]')).to_contain_text(
        "Open Wi-Fi network"
    )
    expect(app.get_by_test_id("rules")).to_contain_text("dhcp.one-server")

    go(app, "#/device/router")
    app.get_by_test_id("delete-device").click()
    app.get_by_test_id("confirm-cancel").click()
    expect(app.get_by_test_id("device-title")).to_be_visible()
    app.get_by_test_id("delete-device").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("empty")).to_contain_text("No devices yet")


def test_theme_toggle_persists(app: Any) -> None:
    html = app.locator("html")
    expect(app.get_by_test_id("theme")).to_have_text("Theme: auto")
    app.get_by_test_id("theme").click()
    expect(html).to_have_attribute("data-theme", "light")
    app.get_by_test_id("theme").click()
    expect(html).to_have_attribute("data-theme", "dark")
    app.reload()
    expect(html).to_have_attribute("data-theme", "dark")
    expect(app.get_by_test_id("theme")).to_have_text("Theme: dark")
    app.get_by_test_id("theme").click()
    expect(html).not_to_have_attribute("data-theme", re.compile("."))


def test_keyboard_login_and_navigation(page: Any, server: Any) -> None:
    page.set_default_timeout(15000)
    page.goto(server.url)
    expect(page.get_by_test_id("login-password")).to_be_focused()
    page.keyboard.type(PASSWORD)
    page.keyboard.press("Enter")
    expect(page.get_by_test_id("logout")).to_be_visible()
    page.get_by_test_id("nav-devices").focus()
    page.keyboard.press("Enter")
    expect(page.get_by_test_id("nav-devices")).to_have_attribute("aria-current", "page")


@pytest.mark.parametrize(
    "hash_",
    [
        *VIEWS,
        "#/settings",
        "#/desired",
        "#/changes",
        "#/change/new",
        "#/devices/new",
        "#/device/router",
    ],
)
def test_phone_has_no_horizontal_scroll(page: Any, server: Any, hash_: str) -> None:
    page.set_viewport_size({"width": 375, "height": 740})
    page.set_default_timeout(15000)
    page.goto(server.url)
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    page.get_by_test_id("logout").wait_for()
    page.server = server
    add_site(page)
    add_lab(page, "Router")
    add_switch(page, "Core switch with a rather long name")
    observe(page)
    api(
        page,
        "POST",
        "/links",
        {"a": "router/port/lan2", "b": "core-switch-with-a-rather-long-name/port/p1"},
    )
    go(page, hash_)
    page.locator("main h1").first.wait_for()
    page.wait_for_load_state("networkidle")
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    assert overflow <= 0, f"{hash_} scrolls sideways by {overflow}px"


def test_desired_state_import_edit_save_and_drift(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    observe(app)
    go(app, "#/desired")
    expect(app.get_by_test_id("desired-status")).to_contain_text("Nothing declared")
    app.get_by_test_id("desired-import").click()
    editor = app.get_by_test_id("desired-yaml")
    expect(editor).to_have_value(re.compile("sites:"))
    # invalid YAML is refused with the reason, nothing saved
    editor.fill("sites: [")
    app.get_by_test_id("desired-save").click()
    expect(app.get_by_test_id("desired-status")).to_contain_text("not valid YAML")
    # a segment that does not exist becomes a drift finding
    editor.fill("sites:\n  home:\n    segments:\n      - vlan: 42\n        name: Lab\n")
    app.get_by_test_id("desired-message").fill("plan the lab VLAN")
    app.get_by_test_id("desired-save").click()
    expect(app.get_by_test_id("desired-status")).to_contain_text("Valid. Sites: home")
    go(app, "#/")
    expect(app.locator("main")).to_contain_text("Segment 42 (Lab) does not exist")
    # secrets: stored, listed by name only, deleted
    go(app, "#/desired")
    app.get_by_test_id("secret-name").fill("main-wifi")
    app.get_by_test_id("secret-value").fill("a long passphrase")
    app.get_by_test_id("secret-add").click()
    expect(app.get_by_test_id("secret-row")).to_have_count(1)
    expect(app.locator("main")).not_to_contain_text("a long passphrase")
    app.get_by_test_id("secret-delete").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("secret-row")).to_have_count(0)


def test_plan_shows_the_changes_in_order(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    observe(app)
    api(
        app,
        "PUT",
        "/desired",
        {"yaml": "sites:\n  home:\n    segments:\n      - vlan: native\n        name: Main LAN\n"},
    )
    go(app, "#/desired")
    app.get_by_test_id("plan-make").click()
    expect(app.get_by_test_id("plan")).to_contain_text(re.compile("change|Nothing to change"))


def test_change_plan_approve_deploy_and_revert(app: Any) -> None:
    from test_deploy import WANT
    from writable import Writable

    Writable.reset()
    add_site(app)
    for dev, role in (("gw", "gateway"), ("ap", "ap")):
        body = {
            "name": dev,
            "site_id": "home",
            "role": role,
            "adapter": "w",
            "allow_writes": True,
            "config": {"host": "192.0.2.9", "password": "pw"},
        }
        api(app, "POST", "/devices", body)
    api(app, "POST", "/links", {"a": "gw/port/lan", "b": "ap/port/lan"})
    api(app, "PUT", "/secrets/psk", {"value": "the new passphrase"})
    observe(app)
    api(app, "PUT", "/desired", {"yaml": WANT})
    go(app, "#/changes")
    expect(app.get_by_test_id("no-changes")).to_be_visible()
    app.get_by_test_id("change-new").click()
    expect(app.get_by_test_id("plan-changes")).to_contain_text("create router")
    app.get_by_test_id("change-reason").fill("add the IoT network")
    app.get_by_test_id("change-create").click()
    expect(app.get_by_test_id("change-status")).to_contain_text("planned")
    app.get_by_test_id("change-approve").click()
    expect(app.get_by_test_id("change-status")).to_contain_text("approved")
    app.get_by_test_id("change-deploy").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("change-status")).to_contain_text("applied", timeout=20000)
    expect(app.get_by_test_id("change-device")).to_have_count(2)
    expect(app.get_by_test_id("change-events")).to_contain_text("confirmed")
    app.get_by_test_id("change-revert").click()
    app.get_by_test_id("reason").fill("not needed after all")
    app.get_by_test_id("reason-ok").click()
    expect(app.get_by_test_id("change-status")).to_contain_text("planned")
    expect(app.locator("main")).to_contain_text("Reverts")
    go(app, "#/changes")
    expect(app.get_by_test_id("change-row")).to_have_count(2)
    expect(app.get_by_test_id("backup-row")).to_have_count(2)
