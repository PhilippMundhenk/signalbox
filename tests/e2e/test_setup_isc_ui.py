"""The optional ISC DHCP script of the OPNsense setup (#242) in the device form."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import expect

from signalbox.adapters.opnsense import OpnsenseAdapter
from signalbox.adapters.opnsense.provision import SCRIPT_PATH
from signalbox.sim.opnsense import KEY, SECRET, OpnsenseSimulator
from signalbox.sim.opnsense_ssh import ROOT_PASSWORD, OpnsenseSsh, serve_ssh_in_thread
from signalbox.sim.server import self_signed_certificate, serve

from .conftest import LiveServer, add_site

pytestmark = pytest.mark.e2e


@pytest.fixture
def server(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(tmp_path / "data", adapters={"opnsense": OpnsenseAdapter})
    yield srv
    srv.stop()


@pytest.fixture
def firewall(tmp_path: Path) -> Iterator[tuple[str, int, OpnsenseSsh]]:
    tls = self_signed_certificate(tmp_path / "tls")
    device = OpnsenseSsh()
    with serve(OpnsenseSimulator().app(), tls=tls) as url, serve_ssh_in_thread(device) as (port, _):
        yield url, port, device


def test_script_is_off_until_ticked_and_both_keys_are_confirmed(
    app: Any, firewall: tuple[str, int, OpnsenseSsh]
) -> None:
    url, port, device = firewall
    add_site(app)
    app.goto(app.server.url + "/#/devices/new")
    app.get_by_test_id("device-name").fill("Firewall")
    app.get_by_test_id("cfg-url").fill(url)
    app.get_by_test_id("auto-setup").locator("summary").click()
    ticked = app.get_by_test_id("setup-ssh")
    expect(ticked).not_to_be_checked()  # off by default
    expect(app.get_by_test_id("setup-ssh-fields")).to_be_hidden()
    ticked.check()
    app.get_by_test_id("setup-plan").click()
    expect(app.get_by_test_id("setup-plan-steps")).to_contain_text("DHCP script")
    app.get_by_test_id("setup-continue").click()
    app.get_by_test_id("setup-trust").click()  # the certificate
    # the API key and the SSH password are asked for last
    app.get_by_test_id("setup-admin-user").fill(KEY)
    app.get_by_test_id("setup-admin-secret").fill(SECRET)
    app.get_by_test_id("setup-ssh-secret").fill(ROOT_PASSWORD)
    app.get_by_test_id("setup-ssh-port").fill(str(port))
    app.get_by_test_id("setup-apply").click()
    # the SSH host key is confirmed before the SSH password is sent
    expect(app.get_by_test_id("setup-ssh-fingerprint")).to_contain_text("SHA256:")
    assert device.scripts == []
    app.get_by_test_id("setup-trust-ssh").click()
    expect(app.get_by_test_id("setup-ssh-secret")).to_have_value("")  # cleared, asked again
    app.get_by_test_id("setup-admin-user").fill(KEY)
    app.get_by_test_id("setup-admin-secret").fill(SECRET)
    app.get_by_test_id("setup-ssh-secret").fill(ROOT_PASSWORD)
    app.get_by_test_id("setup-ssh-port").fill(str(port))
    app.get_by_test_id("setup-apply").click()
    expect(app.get_by_test_id("toast").first).to_contain_text("Firewall set up.")
    assert SCRIPT_PATH in device.files and len(device.key_lines()) == 1
    assert ROOT_PASSWORD not in app.content()


def test_unticked_runs_no_ssh(app: Any, firewall: tuple[str, int, OpnsenseSsh]) -> None:
    url, _, device = firewall
    add_site(app)
    app.goto(app.server.url + "/#/devices/new")
    app.get_by_test_id("device-name").fill("Firewall")
    app.get_by_test_id("cfg-url").fill(url)
    app.get_by_test_id("auto-setup").locator("summary").click()
    app.get_by_test_id("setup-plan").click()
    app.get_by_test_id("setup-continue").click()
    app.get_by_test_id("setup-trust").click()
    app.get_by_test_id("setup-admin-user").fill(KEY)
    app.get_by_test_id("setup-admin-secret").fill(SECRET)
    app.get_by_test_id("setup-apply").click()
    expect(app.get_by_test_id("toast").first).to_contain_text("Firewall set up.")
    assert device.scripts == [] and device.files == {}
