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

from .conftest import LiveServer, add_site

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
