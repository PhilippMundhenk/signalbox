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
    # health and time of the last reading (#178, #179)
    app.reload()
    health = app.get_by_test_id("device-health")
    expect(health).to_contain_text("3 d 4 h")
    expect(health).to_contain_text("96 MiB of 256 MiB (38 %)")
    expect(health).to_contain_text("52 °C (limit 95 °C)")
    expect(app.get_by_test_id("device-time")).to_contain_text("7 min behind")
    expect(app.get_by_test_id("device-time")).to_contain_text("off")

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
    # purposes: reported by the device, or guessed from the name (marked with "?")
    expect(office.get_by_test_id("purpose")).to_have_text("main")
    expect(office.get_by_test_id("purpose")).to_have_attribute("data-source", "reported")
    guests = app.locator('[data-testid="segment"][data-id="home/segment/20"]')
    expect(guests.get_by_test_id("purpose")).to_have_text("guest?")
    expect(guests.get_by_test_id("segment-isolated")).to_have_count(0)

    go(app, "#/wireless")
    expect(app.get_by_test_id("ssid")).to_have_count(2)
    home = app.get_by_test_id("ssid").filter(has_text="Home")
    expect(home.get_by_test_id("wlan-row")).to_have_count(2)
    expect(home).to_contain_text("WPA3 Personal")
    expect(home).to_contain_text("802.11r on")
    details = home.get_by_test_id("wlan-security-details")  # only the 5 GHz WLAN reports them
    expect(details).to_have_count(1)
    expect(details).to_contain_text("CCMP")
    expect(details).to_contain_text("SAE H2E")
    expect(details).to_contain_text("WPS on (push-button)")
    expect(details).to_contain_text("beacon protection on")
    expect(details).to_contain_text("rekey 3600 s")
    guest = app.get_by_test_id("ssid").filter(has_text="Guest")
    expect(guest.get_by_test_id("purpose")).to_have_text("guest?")
    expect(guest.get_by_test_id("client-isolation")).to_have_text("on")
    expect(home.get_by_test_id("purpose").first).to_have_text("main")
    expect(app.get_by_test_id("radio-row")).to_have_count(2)
    expect(app.get_by_test_id("radios")).to_contain_text("80 MHz")
    expect(app.get_by_test_id("radios")).to_contain_text("WPA2/WPA3 Personal")

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

    # the uplink (#148): a summary, the addresses only after a click
    go(app, "#/device/router")
    summary = app.get_by_test_id("uplink-summary")
    expect(summary).to_contain_text("PPPoE · up for 3 h")
    expect(summary).to_contain_text("public IPv4 · IPv6 /56 delegated")
    expect(summary).to_contain_text("100 Mbit/s down / 40 Mbit/s up")
    expect(app.get_by_text("203.0.113.23/32")).not_to_be_visible()
    app.get_by_test_id("uplink-addresses").locator("summary").click()
    expect(app.get_by_test_id("uplink-addresses")).to_contain_text("2001:db8:100::/56 (delegated)")
    expect(app.get_by_text("203.0.113.23/32")).to_be_visible()

    # management services (#173): where they listen, who reaches them, what is insecure
    card = app.get_by_test_id("device-management")
    expect(card).to_contain_text("Signalbox reads it")
    expect(card.get_by_test_id("service")).to_have_count(5)  # telnet is off
    rows = card.get_by_test_id("service-summary")
    ssh = rows.filter(has_text="port 22")
    expect(ssh).to_contain_text("only from 192.0.2.0/24 · reachable from VLAN 10 (Office)")
    expect(ssh).not_to_contain_text("Guests")
    expect(ssh).to_contain_text("internet: the firewall decides")
    expect(rows.filter(has_text="port 80")).to_contain_text("redirects to HTTPS")
    expect(rows.filter(has_text="port 443")).to_contain_text("on VLAN 10 (Office)")
    expect(card.get_by_test_id("service-plaintext")).to_have_count(1)  # SNMP v2c
    expect(card.get_by_test_id("service-internet")).to_have_count(1)  # remote HTTPS
    expect(card.get_by_test_id("service-root-password")).to_have_count(1)
    expect(card).to_contain_text("default community")
    expect(card).to_contain_text("off")

    go(app, "#/device/router/advanced")
    expect(app.get_by_test_id("raw-services")).to_contain_text("services (6)")
    expect(app.get_by_test_id("raw-uplinks")).to_contain_text("uplinks (1)")
    expect(app.get_by_test_id("raw-port")).to_have_count(3)
    expect(app.get_by_test_id("raw-port-table")).to_contain_text('"led":"green"')
    lan1 = app.get_by_test_id("raw-port").filter(has_text="lan1")
    expect(lan1).to_contain_text("Desk")
    expect(lan1).to_contain_text("1 Gbit/s of 2.5 Gbit/s")
    expect(lan1).to_contain_text("PVID 20 · MTU 1500")
    expect(app.get_by_test_id("raw-port").filter(has_text="lan3")).to_contain_text("disabled")


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
    expect(app.get_by_test_id("port-description")).to_have_text("Desk")
    facts = app.get_by_test_id("port-facts")
    expect(facts).to_contain_text("1 Gbit/s of 2.5 Gbit/s · PVID 20 · MTU 1500")
    expect(facts).to_contain_text("untagged frames in: Guests")

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
    page.get_by_test_id("logout").wait_for(state="attached")
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
    editor.fill(
        "sites:\n  home:\n    segments:\n      - vlan: 42\n        name: Lab\n"
        "      - vlan: 20\n        purpose: iot\n"
    )
    app.get_by_test_id("desired-message").fill("plan the lab VLAN")
    app.get_by_test_id("desired-save").click()
    expect(app.get_by_test_id("desired-status")).to_contain_text("Valid. Sites: home")
    go(app, "#/")
    expect(app.locator("main")).to_contain_text("Segment 42 (Lab) does not exist")
    # a declared purpose beats the guess from the name ("Guests") in every view
    go(app, "#/segments")
    guests = app.locator('[data-testid="segment"][data-id="home/segment/20"]')
    expect(guests.get_by_test_id("purpose")).to_have_text("iot")
    expect(guests.get_by_test_id("purpose")).to_have_attribute("data-source", "declared")
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


def test_device_form_guides_and_tests_before_saving(app: Any) -> None:
    """Setup steps and commands in the form; Test connection with unsaved settings, a fix for
    each problem, the certificate trusted in the form and pinned on save."""
    add_site(app)
    go(app, "#/devices/new")
    app.get_by_test_id("device-adapter").select_option("lab")
    setup = app.get_by_test_id("setup")
    expect(setup).to_have_attribute("open", "")
    expect(app.get_by_test_id("setup-steps").locator("li")).to_have_count(2)
    expect(app.get_by_test_id("setup-commands")).to_have_text("echo prepared\n")
    expect(app.get_by_test_id("setup-guide")).to_have_attribute("href", re.compile("ADAPTERS.md$"))

    # nothing filled in: the test says what is missing
    app.get_by_test_id("form-test-button").click()
    expect(app.get_by_test_id("form-errors")).to_contain_text("Password is required")

    app.get_by_test_id("cfg-password").fill("device-secret")
    app.get_by_test_id("cfg-host").fill("nodns.example")
    app.get_by_test_id("form-test-button").click()
    result = app.get_by_test_id("form-test").get_by_test_id("test-result")
    expect(result.get_by_test_id("status")).to_have_attribute("data-status", "partial")
    expect(result).to_contain_text("Example, LR-1, firmware 1.2.3")
    fix = result.get_by_test_id("error-fix")
    expect(fix).to_contain_text("What to do: Allow DNS reading")
    expect(fix.locator("a")).to_have_text("docs/ADAPTERS.md")
    assert api(app, "GET", "/devices") == []  # nothing stored by a test

    app.get_by_test_id("cfg-host").fill("untrusted.example")
    app.get_by_test_id("form-test-button").click()
    expect(result.get_by_test_id("status")).to_have_attribute(
        "data-status", "untrusted-certificate"
    )
    expect(app.get_by_test_id("untrusted")).to_contain_text("Trusted when you add the device")
    app.get_by_test_id("trust").click()
    expect(result.get_by_test_id("status")).to_have_attribute("data-status", "ok")
    app.get_by_test_id("device-name").fill("Edge")
    app.get_by_test_id("device-save").click()
    expect(app.get_by_test_id("device-title")).to_have_text("Edge")
    expect(app.get_by_test_id("test-result").get_by_test_id("status")).to_have_attribute(
        "data-status", "ok"
    )
    assert api(app, "GET", "/devices/edge")["pinned_fingerprint"] == FINGERPRINT


def test_optional_secret_can_be_removed(app: Any) -> None:
    add_site(app)
    body = {
        "name": "Edge",
        "site_id": "home",
        "role": "gateway",
        "adapter": "lab",
        "config": {"host": "192.0.2.1", "password": "device-secret", "api_token": "t"},
    }
    api(app, "POST", "/devices", body)
    assert api(app, "GET", "/devices/edge")["secrets_set"] == ["api_token", "password"]
    go(app, "#/device/edge")
    app.get_by_test_id("tab-settings").click()
    expect(app.get_by_test_id("cfg-password-clear")).to_have_count(0)  # required: not removable
    app.get_by_test_id("cfg-api_token-clear").check()
    expect(app.get_by_test_id("cfg-api_token")).to_be_disabled()
    app.get_by_test_id("device-save").click()
    expect(app.get_by_test_id("device-title")).to_have_text("Edge")
    assert api(app, "GET", "/devices/edge")["secrets_set"] == ["password"]


def test_find_devices_and_add_one_through_the_prefilled_form(app: Any) -> None:
    """#203: the search covers the router's subnets and an entered address; a found device
    opens the form prefilled; device-provided text stays text; added ones are marked."""
    add_site(app)
    add_lab(app, "Main router")
    observe(app)  # the router's subnets 192.0.2.0/24 and 198.51.100.0/24 are now known
    go(app, "#/devices")
    panel = app.get_by_test_id("discovery")
    expect(panel).to_be_hidden()
    app.get_by_test_id("find-devices").first.click()
    expect(panel).to_be_visible()
    expect(app.get_by_test_id("discovery-known")).to_be_checked()
    app.get_by_test_id("discovery-ranges").fill("203.0.113.5, 203.0.113.8-9")
    app.get_by_test_id("discovery-start").click()
    rows = app.get_by_test_id("candidate")
    expect(rows).to_have_count(3)
    expect(app.get_by_test_id("discovery-done")).to_contain_text("511 checked, 3 found")
    lab = rows.filter(has_text="192.0.2.7")
    expect(lab.get_by_test_id("candidate-model")).to_have_text(
        "LR-2 <img src=x onerror=alert(1)> (2.0)"
    )
    expect(app.get_by_test_id("candidates").locator("img")).to_have_count(0)
    # #224: the AP answered on 203.0.113.5 too: one entry, both addresses, the one in a known
    # network is offered and the other is listed
    expect(lab.get_by_test_id("candidate-address")).to_have_text("192.0.2.7")
    expect(lab.get_by_test_id("candidate-other-addresses")).to_contain_text("203.0.113.5")
    expect(rows.filter(has_text="192.0.2.1").get_by_test_id("candidate-added")).to_have_attribute(
        "href", "#/device/main-router"
    )
    # ignore the switch: hidden, and can be shown again
    rows.filter(has_text="198.51.100.20").get_by_test_id("candidate-ignore").click()
    expect(rows).to_have_count(2)
    app.get_by_test_id("discovery-show-ignored").click()
    expect(
        rows.filter(has_text="198.51.100.20").get_by_test_id("candidate-unignore")
    ).to_be_visible()

    lab.get_by_test_id("candidate-add").click()
    expect(app.get_by_test_id("prefill-notice")).to_contain_text("Found by Find devices")
    expect(app.get_by_test_id("prefill-note")).to_have_text("Switch on the API first.")
    expect(app.get_by_test_id("device-adapter")).to_have_value("lab")
    expect(app.get_by_test_id("device-role")).to_have_value("ap")
    expect(app.get_by_test_id("cfg-host")).to_have_value("192.0.2.7")
    expect(app.get_by_test_id("cfg-port")).to_have_value("8443")
    expect(app.get_by_test_id("cfg-password")).to_have_value("")
    app.get_by_test_id("device-name").fill("Office AP")
    app.get_by_test_id("cfg-password").fill("device-secret")
    app.get_by_test_id("device-save").click()
    expect(app.get_by_test_id("device-title")).to_have_text("Office AP")
    stored = api(app, "GET", "/devices/office-ap")
    assert stored["config"]["host"] == "192.0.2.7" and stored["config"]["port"] == 8443
    assert stored["role"] == "ap" and stored["pinned_fingerprint"] is None

    go(app, "#/devices")
    expect(rows.filter(has_text="192.0.2.7").get_by_test_id("candidate-added")).to_be_visible()
    status = api(app, "GET", "/discovery")
    assert status["scope"][0] == "203.0.113.5: 1 address(es) you entered"


def test_acknowledge_a_finding_and_annotate_objects(app: Any) -> None:
    """#186: accept a known false positive with a reason; notes on a device and a client."""
    add_site(app)
    add_lab(app, "Router")
    add_lab(app, "Cellar", host="down.example")
    observe(app)
    go(app, "#/")
    open_wifi = app.locator('[data-testid="finding"][data-rule="lab.open-wifi"]')
    expect(open_wifi).to_have_count(1)
    expect(app.get_by_test_id("group-acknowledged")).to_have_count(0)
    # cancel changes nothing
    open_wifi.get_by_test_id("acknowledge").click()
    app.get_by_test_id("ack-cancel").click()
    expect(app.get_by_test_id("modal")).to_have_count(0)
    open_wifi.get_by_test_id("acknowledge").click()
    app.get_by_test_id("ack-reason").fill("café hotspot, open on purpose")
    app.get_by_test_id("ack-scope").select_option(index=1)
    app.get_by_test_id("ack-save").click()
    expect(app.get_by_test_id("toast").first).to_contain_text("Finding acknowledged")
    acked = app.get_by_test_id("group-acknowledged")
    expect(acked).to_contain_text("Acknowledged (1)")
    # not counted as a problem: the card moved into the closed section
    expect(open_wifi).not_to_be_visible()
    acked.locator("summary").click()
    expect(acked.get_by_test_id("ack-info")).to_contain_text("café hotspot, open on purpose")
    expect(acked.get_by_test_id("acknowledge")).to_have_count(0)
    # kept across a new observation round
    observe(app)
    go(app, "#/")
    expect(app.get_by_test_id("group-acknowledged")).to_contain_text("Acknowledged (1)")
    findings = api(app, "GET", "/findings")
    wifi = next(r["finding"] for r in findings if r["finding"]["rule_id"] == "lab.open-wifi")
    assert wifi["acknowledged"]["target"] and wifi["acknowledged"]["reason"]
    # remove the acknowledgement: it counts again
    acked = app.get_by_test_id("group-acknowledged")
    acked.locator("summary").click()
    acked.get_by_test_id("ack-remove").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("group-acknowledged")).to_have_count(0)
    expect(open_wifi.get_by_test_id("acknowledge")).to_be_visible()
    # an end date in the past is refused with a message
    open_wifi.get_by_test_id("acknowledge").click()
    app.get_by_test_id("ack-until").fill("2020-01-01")
    app.get_by_test_id("ack-save").click()
    expect(app.get_by_test_id("toast").last).to_contain_text("in the past")
    app.get_by_test_id("ack-cancel").click()

    # notes on a device
    go(app, "#/device/cellar")
    app.get_by_test_id("notes").get_by_test_id("edit-notes").click()
    app.get_by_test_id("note-label").fill("cellar switch")
    app.get_by_test_id("note-owner").fill("Example Owner")
    app.get_by_test_id("note-may_be_unreachable").check()
    app.get_by_test_id("note-save").click()
    expect(app.get_by_test_id("notes")).to_contain_text("cellar switch")
    expect(app.get_by_test_id("notes")).to_contain_text("Example Owner")
    note = api(app, "GET", "/annotations")["annotations"][0]
    assert note["target"] == "cellar" and note["expected"]["may_be_unreachable"] is True

    # notes on a client: the label replaces the reported name in the list
    go(app, "#/clients")
    row = app.get_by_test_id("client-row").filter(has_text="laptop")
    row.get_by_test_id("client-notes").click()
    app.get_by_test_id("note-label").fill("work laptop")
    app.get_by_test_id("note-category").select_option("computer")
    app.get_by_test_id("note-save").click()
    expect(app.get_by_test_id("client-label")).to_contain_text("work laptop")
    app.get_by_test_id("client-filter").fill("work")
    expect(app.get_by_test_id("client-row")).to_have_count(1)
    app.get_by_test_id("client-notes").click()
    app.get_by_test_id("note-remove").click()
    expect(app.get_by_test_id("client-label")).to_have_count(0)


def _login(page: Any, server: Any, width: int, height: int) -> None:
    page.set_viewport_size({"width": width, "height": height})
    page.set_default_timeout(15000)
    page.goto(server.url)
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    page.get_by_test_id("nav-findings").wait_for(state="attached")
    page.server = server


def _too_wide(page: Any) -> list[str]:
    result: list[str] = page.evaluate(
        """() => [...document.querySelectorAll('body *')]
          .filter((e) => { const r = e.getBoundingClientRect();
            return r.width > 0 && getComputedStyle(e).visibility !== 'hidden'
              && !e.closest('.table-wrap, .topo-wrap, pre, svg')
              && r.right > window.innerWidth + 1; })
          .map((e) => e.tagName + '.' + e.className)"""
    )
    return result


def _no_wrapped_labels(page: Any) -> None:
    heights = page.evaluate(
        "[...document.querySelectorAll('.nav a')].map((a) => a.getBoundingClientRect().height)"
    )
    assert max(heights) - min(heights) < 2, heights


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("size", [(390, 844), (320, 640), (820, 1180)])
def test_narrow_screens_use_a_drawer(
    page: Any, server: Any, size: tuple[int, int], theme: str
) -> None:
    _login(page, server, *size)
    page.evaluate(f"localStorage.setItem('theme', '{theme}')")
    page.reload()
    menu = page.get_by_test_id("nav-menu")
    expect(menu).to_be_visible()
    expect(menu).to_have_attribute("aria-expanded", "false")
    expect(page.get_by_test_id("logout")).to_be_hidden()
    expect(page.get_by_test_id("nav-current")).to_have_text("Findings")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert page.locator("header.topbar").bounding_box()["height"] < 70  # one row

    menu.click()
    expect(menu).to_have_attribute("aria-expanded", "true")
    expect(page.locator("nav[aria-label=Main]")).to_be_visible()
    expect(page.get_by_test_id("nav-findings")).to_be_focused()
    expect(page.get_by_test_id("theme")).to_be_visible()
    expect(page.get_by_test_id("logout")).to_be_visible()
    _no_wrapped_labels(page)
    assert _too_wide(page) == []
    expect(page.get_by_test_id("theme")).to_have_text(f"Theme: {theme}")
    page.get_by_test_id("theme").click()
    expect(page.get_by_test_id("theme")).not_to_have_text(f"Theme: {theme}")

    page.keyboard.press("Escape")  # Esc closes and gives the focus back
    expect(menu).to_have_attribute("aria-expanded", "false")
    expect(menu).to_be_focused()
    expect(page.get_by_test_id("logout")).to_be_hidden()

    menu.click()  # a tap outside closes
    page.get_by_test_id("nav-scrim").click(position={"x": size[0] - 5, "y": 300})
    expect(menu).to_have_attribute("aria-expanded", "false")

    menu.click()  # focus stays inside the drawer
    for _ in range(14):
        page.keyboard.press("Tab")
        assert page.evaluate("!!document.activeElement.closest('.sidebar')")

    page.get_by_test_id("nav-services").click()  # closes on navigation
    expect(page.get_by_test_id("nav-current")).to_have_text("DHCP & DNS")
    expect(menu).to_have_attribute("aria-expanded", "false")
    expect(page.get_by_test_id("logout")).to_be_hidden()
    menu.click()
    expect(page.get_by_test_id("nav-services")).to_have_attribute("aria-current", "page")
    page.get_by_test_id("nav-services").click()  # same page: still closes
    expect(menu).to_have_attribute("aria-expanded", "false")
    menu.click()
    page.get_by_test_id("logout").click()
    expect(page.get_by_test_id("login-submit")).to_be_visible()


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("size", [(1280, 800), (1440, 900), (1100, 700)])
def test_wide_screens_have_a_side_bar(
    page: Any, server: Any, size: tuple[int, int], theme: str
) -> None:
    _login(page, server, *size)
    page.evaluate(f"localStorage.setItem('theme', '{theme}')")
    page.reload()
    expect(page.get_by_test_id("nav-menu")).to_be_hidden()
    for key in [
        "findings", "devices", "topology", "segments", "wireless",
        "services", "clients", "desired", "changes", "settings",
    ]:  # fmt: skip
        expect(page.get_by_test_id(f"nav-{key}")).to_be_visible()
    expect(page.get_by_test_id("theme")).to_be_visible()
    expect(page.get_by_test_id("logout")).to_be_visible()
    _no_wrapped_labels(page)
    assert _too_wide(page) == []
    box = page.locator(".sidebar").bounding_box()
    main = page.locator("main").bounding_box()
    assert box["x"] == 0 and main["x"] >= box["width"]
    page.get_by_test_id("nav-services").click()
    expect(page.get_by_test_id("nav-services")).to_have_attribute("aria-current", "page")
    expect(page.get_by_test_id("nav-findings")).not_to_have_attribute("aria-current", "page")
    page.get_by_test_id("logout").click()
    expect(page.get_by_test_id("login-submit")).to_be_visible()


def test_drawer_closes_when_the_screen_gets_wide(page: Any, server: Any) -> None:
    _login(page, server, 800, 900)
    page.get_by_test_id("nav-menu").click()
    page.set_viewport_size({"width": 1280, "height": 900})
    expect(page.get_by_test_id("nav-menu")).to_be_hidden()
    expect(page.get_by_test_id("logout")).to_be_visible()
    page.get_by_test_id("nav-devices").click()
    expect(page.get_by_test_id("nav-devices")).to_have_attribute("aria-current", "page")
