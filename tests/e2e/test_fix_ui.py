"""*Fix it* on the device page (#215) with the simulated OpenWrt: LLDP is missing, the read
error offers the remedy, the plan is shown after the host key is trusted, then it runs."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import expect

from signalbox.adapters.openwrt import OpenWrtAdapter
from signalbox.sim.openwrt import OpenWrtSim, create_app
from signalbox.sim.openwrt_ssh import LLDP_PACKAGES, ROOT_PASSWORD, OpenWrtSsh, serve_ssh_in_thread
from signalbox.sim.server import self_signed_certificate, serve

from .conftest import LiveServer, add_site, api

pytestmark = pytest.mark.e2e


@pytest.fixture
def server(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(tmp_path / "data", adapters={"openwrt": OpenWrtAdapter})
    yield srv
    srv.stop()


@pytest.fixture
def router(tmp_path: Path) -> Iterator[tuple[str, int, str, OpenWrtSsh]]:
    tls = self_signed_certificate(tmp_path / "tls")
    http = OpenWrtSim()
    device = OpenWrtSsh(http=http, certificate=tls.cert.read_bytes())
    with serve(create_app(http), tls=tls) as url, serve_ssh_in_thread(device) as (port, key):
        yield url, port, key, device


def set_up(app: Any, url: str, port: int, key: str, writes: bool) -> None:
    body = {
        "device": {
            "name": "Access point",
            "site_id": "home",
            "role": "ap",
            "adapter": "openwrt",
            "allow_writes": writes,
            "config": {"url": url, "username": "signalbox", "password": ""},
        },
        "admin": {"user": "root", "secret": ROOT_PASSWORD, "port": port},
        "trust": key,
    }
    assert api(app, "POST", "/devices/setup/apply", body)["ok"]


def without_lldp(device: OpenWrtSsh) -> None:
    device.installed -= LLDP_PACKAGES
    device.lldpd_running = False
    assert device.http is not None
    device.http.lldpd = False


def test_fix_it_installs_lldp(app: Any, router: tuple[str, int, str, OpenWrtSsh]) -> None:
    url, port, key, device = router
    add_site(app)
    set_up(app, url, port, key, writes=True)
    without_lldp(device)
    # LLDP is optional: the device stays ok and the note is muted (#278)
    assert api(app, "POST", "/devices/access-point/test")["status"] == "ok"
    app.goto(app.server.url + "/#/device/access-point")
    expect(app.get_by_test_id("device-errors-optional")).to_contain_text("Optional, not available")
    expect(app.get_by_test_id("device-errors").locator("ul.error")).to_have_count(0)
    errors = app.get_by_test_id("device-errors")
    expect(errors).to_contain_text("LLDP is not installed")
    expect(errors.get_by_test_id("error-fix")).to_contain_text("lldpd")  # manual way stays
    errors.locator("[data-testid=fix-it][data-remedy=lldp]").click()
    panel = app.get_by_test_id("fix-panel")
    expect(panel).to_contain_text("Install LLDP")
    # 1. what it does, with no credential field yet
    expect(app.get_by_test_id("fix-admin-secret")).to_have_count(0)
    app.get_by_test_id("fix-admin-port").fill(str(port))
    scripts = len(device.scripts)
    app.get_by_test_id("fix-plan").click()
    expect(app.get_by_test_id("fix-plan-steps")).to_contain_text("Install lldpd")
    expect(app.get_by_test_id("fix-admin-secret")).to_have_count(0)
    # 2. the identity, still without a password: the host key confirmed by the setup is
    # known (#526), so there is nothing to compare and the step list says since when
    app.get_by_test_id("fix-continue").click()
    expect(app.get_by_test_id("fix-host-key-known")).to_contain_text(key)
    expect(app.get_by_test_id("fix-trust")).to_have_count(0)
    assert len(device.scripts) == scripts  # nothing sent with the identity
    # 3. the temporary password, right before Run
    expect(app.get_by_test_id("fix-temporary-note")).to_contain_text("never saved")
    expect(app.get_by_test_id("fix-admin-user")).to_have_value("root")
    secret = app.get_by_test_id("fix-admin-secret")
    expect(secret).to_have_value("")
    secret.fill(ROOT_PASSWORD)
    assert len(device.scripts) == scripts  # typing it sends nothing
    # cancelled: nothing runs
    app.get_by_test_id("fix-apply").click()
    app.get_by_test_id("confirm-cancel").click()
    assert not device.installed >= LLDP_PACKAGES
    expect(secret).to_have_value("")  # cancelled: the password does not stay in the field
    secret.fill(ROOT_PASSWORD)
    app.get_by_test_id("fix-apply").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("fix-outcome")).to_contain_text("Done", timeout=20000)
    expect(panel.get_by_test_id("test-result")).to_contain_text("OK")
    assert device.installed >= LLDP_PACKAGES and device.lldpd_running
    assert ROOT_PASSWORD not in app.content()


def test_fix_it_for_read_side_remedies_needs_no_allow_changes(
    app: Any, router: tuple[str, int, str, OpenWrtSsh]
) -> None:
    url, port, key, device = router
    add_site(app)
    set_up(app, url, port, key, writes=False)
    without_lldp(device)
    api(app, "POST", "/devices/access-point/test")
    app.goto(app.server.url + "/#/device/access-point")
    expect(app.get_by_test_id("fix-needs-writes")).to_have_count(0)
    expect(app.get_by_test_id("fix-it")).to_have_count(1)
