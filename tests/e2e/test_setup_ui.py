"""The device form's "Set up automatically" (#231) with the simulated OpenWrt (SSH and ubus)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import expect

from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.openwrt_ssh import ROOT_PASSWORD, OpenWrtSsh, serve_ssh_in_thread
from signalbox.sim.server import self_signed_certificate, serve

from .conftest import LiveServer, add_site, api

pytestmark = pytest.mark.e2e


@pytest.fixture
def server(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(tmp_path / "data", adapters={"openwrt": OpenWrtAdapter})
    yield srv
    srv.stop()


@pytest.fixture
def router(tmp_path: Path) -> Iterator[tuple[str, int, OpenWrtSsh]]:
    tls = self_signed_certificate(tmp_path / "tls")
    http = OpenWrtSim()
    device = OpenWrtSsh(http=http, certificate=tls.cert.read_bytes())
    with serve(create_app(http), tls=tls) as url, serve_ssh_in_thread(device) as (port, _):
        yield url, port, device


def test_set_up_openwrt_automatically(app: Any, router: tuple[str, int, OpenWrtSsh]) -> None:
    url, port, device = router
    add_site(app)
    app.goto(app.server.url + "/#/devices/new")
    app.get_by_test_id("device-name").fill("Access point")
    app.get_by_test_id("cfg-url").fill(url)
    box = app.get_by_test_id("auto-setup")
    box.locator("summary").click()
    # 1. what it does: no credential field exists yet, nothing is sent
    expect(app.get_by_test_id("setup-admin-secret")).to_have_count(0)
    expect(app.get_by_test_id("setup-admin-port")).to_have_value("22")
    app.get_by_test_id("setup-admin-port").fill(str(port))
    app.get_by_test_id("setup-plan").click()
    expect(app.get_by_test_id("setup-plan-steps")).to_contain_text("Install the packages")
    expect(app.get_by_test_id("setup-admin-secret")).to_have_count(0)
    assert device.scripts == []
    # 2. the device's identity, still without a password
    app.get_by_test_id("setup-continue").click()
    expect(app.get_by_test_id("setup-fingerprint")).to_contain_text("SHA256:")
    expect(app.get_by_test_id("setup-admin-secret")).to_have_count(0)
    assert device.scripts == []
    app.get_by_test_id("setup-trust").click()
    # 3. only now the temporary password, right before Run
    expect(app.get_by_test_id("setup-temporary-note")).to_contain_text("never saved")
    secret = app.get_by_test_id("setup-admin-secret")
    expect(secret).to_have_value("")
    expect(secret).to_have_attribute("autocomplete", "new-password")
    expect(app.get_by_test_id("setup-admin-user")).to_have_value("root")
    app.get_by_test_id("setup-apply").click()
    expect(app.get_by_test_id("setup-error")).to_contain_text("root password")
    assert device.scripts == []  # Run without a password sends nothing
    expect(secret).to_have_value("")
    secret.fill(ROOT_PASSWORD)
    app.get_by_test_id("setup-apply").click()
    # saved and read with the new login over the certificate read through SSH
    expect(app.get_by_test_id("toast").first).to_contain_text("Access point set up.")
    expect(app.get_by_test_id("test-result")).to_contain_text("OK", timeout=20000)
    assert any(s["options"].get("username") == ["signalbox"] for s in device.rpcd.values())
    assert ROOT_PASSWORD not in app.content()


def test_lldp_is_an_unticked_extra_of_the_plan(
    app: Any, router: tuple[str, int, OpenWrtSsh]
) -> None:
    url, port, _device = router
    add_site(app)
    app.goto(app.server.url + "/#/devices/new")
    app.get_by_test_id("device-name").fill("Access point")
    app.get_by_test_id("cfg-url").fill(url)
    app.get_by_test_id("auto-setup").locator("summary").click()
    extra = app.get_by_test_id("setup-extra-lldp")
    expect(extra).not_to_be_checked()
    app.get_by_test_id("setup-admin-port").fill(str(port))
    app.get_by_test_id("setup-plan").click()
    steps = app.get_by_test_id("setup-plan-steps").get_by_test_id("setup-step")
    expect(steps).to_have_count(5)  # no LLDP step unless ticked
    extra.check()  # changing the ticks starts over
    expect(app.get_by_test_id("setup-plan-steps")).to_have_count(0)
    app.get_by_test_id("setup-plan").click()
    expect(
        app.get_by_test_id("setup-plan-steps").locator("[data-step=lldp-packages]")
    ).to_have_count(1)


def to_password_step(app: Any, url: str, port: int, name: str = "Access point") -> None:
    """Fill the device form, then preview and confirm the identity up to the password."""
    app.goto(app.server.url + "/#/devices/new")
    app.get_by_test_id("device-name").fill(name)
    app.get_by_test_id("cfg-url").fill(url)
    app.get_by_test_id("auto-setup").locator("summary").click()
    app.get_by_test_id("setup-admin-port").fill(str(port))
    app.get_by_test_id("setup-plan").click()
    app.get_by_test_id("setup-continue").click()
    app.get_by_test_id("setup-trust").click()
    expect(app.get_by_test_id("setup-admin-secret")).to_be_visible()


def test_enter_in_the_password_runs_the_setup_and_does_not_save_the_form(
    app: Any, router: tuple[str, int, OpenWrtSsh]
) -> None:
    url, port, _device = router
    add_site(app)
    to_password_step(app, url, port)
    secret = app.get_by_test_id("setup-admin-secret")
    secret.fill("not-the-password")
    secret.press("Enter")
    # Enter ran the setup (it failed on the password); it did not save the device form
    expect(app.get_by_test_id("setup-error")).to_be_visible()
    assert api(app, "GET", "/devices") == []
    # Enter in the other fields of the setup box does not save the form either
    app.get_by_test_id("setup-admin-user").press("Enter")
    app.get_by_test_id("setup-admin-port").press("Enter")
    assert api(app, "GET", "/devices") == []
    expect(app.get_by_test_id("device-form")).to_be_visible()
    # the right password, Enter again: set up and saved
    secret = app.get_by_test_id("setup-admin-secret")
    secret.fill(ROOT_PASSWORD)
    secret.press("Enter")
    expect(app.get_by_test_id("toast").first).to_contain_text("Access point set up.")
    assert [d["name"] for d in api(app, "GET", "/devices")] == ["Access point"]


def test_failed_admin_login_returns_to_the_password_step(
    app: Any, router: tuple[str, int, OpenWrtSsh]
) -> None:
    url, port, device = router
    add_site(app)
    to_password_step(app, url, port)
    app.get_by_test_id("setup-admin-user").fill("operator")
    app.get_by_test_id("setup-admin-secret").fill("wrong")
    app.get_by_test_id("setup-apply").click()
    # back at the password step with the error; nothing was lost
    expect(app.get_by_test_id("setup-error")).to_be_visible()
    expect(app.get_by_test_id("setup-admin-secret")).to_have_value("")
    expect(app.get_by_test_id("setup-admin-user")).to_have_value("operator")
    expect(app.get_by_test_id("setup-kept-steps")).to_contain_text("Install the packages")
    expect(app.get_by_test_id("setup-kept-fingerprint")).to_contain_text("SHA256:")
    expect(app.get_by_test_id("setup-continue")).to_have_count(0)  # not at the start again
    expect(app.get_by_test_id("setup-trust")).to_have_count(0)  # identity stays confirmed
    app.get_by_test_id("setup-admin-user").fill("root")
    app.get_by_test_id("setup-admin-secret").fill(ROOT_PASSWORD)
    app.get_by_test_id("setup-apply").click()
    expect(app.get_by_test_id("toast").first).to_contain_text("Access point set up.")
    assert any(s["options"].get("username") == ["signalbox"] for s in device.rpcd.values())


def test_connection_fields_come_before_the_setup_box(
    app: Any, router: tuple[str, int, OpenWrtSsh]
) -> None:
    url, _port, _device = router
    add_site(app)
    app.goto(app.server.url + "/#/devices/new")
    address = app.get_by_test_id("cfg-url").bounding_box()
    box = app.get_by_test_id("auto-setup").bounding_box()
    assert address["y"] < box["y"]
    app.get_by_test_id("cfg-url").fill(url)
    app.get_by_test_id("auto-setup").locator("summary").click()
    # the address is filled in above the button: no scrolling back up to enter it
    assert (
        app.get_by_test_id("cfg-url").bounding_box()["y"]
        < app.get_by_test_id("setup-plan").bounding_box()["y"]
    )
    app.get_by_test_id("setup-plan").click()
    expect(app.get_by_test_id("setup-plan-steps")).to_be_visible()


def test_progress_shows_a_spinner_while_the_setup_runs(
    app: Any, router: tuple[str, int, OpenWrtSsh]
) -> None:
    url, port, _device = router
    add_site(app)
    held: list[Any] = []
    app.route("**/api/devices/setup/apply", lambda route: held.append(route))
    to_password_step(app, url, port)
    app.get_by_test_id("setup-admin-secret").fill(ROOT_PASSWORD)
    app.get_by_test_id("setup-apply").click()
    progress = app.get_by_test_id("setup-progress")
    expect(progress).to_be_visible()
    expect(progress.locator(".spinner")).to_be_visible()
    expect(progress).to_contain_text("Setting up the device")
    expect(progress.get_by_test_id("setup-progress-steps")).to_contain_text("Install the packages")
    assert progress.bounding_box()["height"] > 40
    expect(app.get_by_test_id("setup-admin-secret")).to_have_count(0)
    app.wait_for_timeout(200)
    held[0].continue_()
    expect(app.get_by_test_id("toast").first).to_contain_text("Access point set up.")


def test_an_admin_login_in_the_settings_is_replaced_not_refused(
    app: Any, router: tuple[str, int, OpenWrtSsh]
) -> None:
    url, port, device = router
    add_site(app)
    app.goto(app.server.url + "/#/devices/new")
    app.get_by_test_id("device-name").fill("Access point")
    app.get_by_test_id("cfg-url").fill(url)
    app.get_by_test_id("cfg-username").fill("root")
    app.get_by_test_id("auto-setup").locator("summary").click()
    # said before anything runs
    expect(app.get_by_test_id("setup-login-replaced")).to_contain_text("will replace the user name")
    app.get_by_test_id("setup-admin-port").fill(str(port))
    app.get_by_test_id("setup-plan").click()
    expect(app.get_by_test_id("setup-plan-steps")).to_be_visible()
    expect(app.get_by_test_id("cfg-username")).to_have_value("signalbox")
    expect(app.get_by_test_id("setup-login-replaced")).to_contain_text("is now signalbox")
    app.get_by_test_id("setup-continue").click()
    app.get_by_test_id("setup-trust").click()
    app.get_by_test_id("setup-admin-secret").fill(ROOT_PASSWORD)
    app.get_by_test_id("setup-admin-secret").press("Enter")
    expect(app.get_by_test_id("toast").first).to_contain_text("Access point set up.")
    assert any(s["options"].get("username") == ["signalbox"] for s in device.rpcd.values())
