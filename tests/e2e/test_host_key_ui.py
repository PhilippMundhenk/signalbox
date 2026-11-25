"""SSH host keys per device in the browser (#526): a device set up before needs no prompt; after
a reinstall (a new host key) the setup shows the distinct warning with the old and the new key,
sends no password, and goes on only after the new key is trusted by name."""

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
def router(tmp_path: Path) -> Iterator[tuple[str, int, str, OpenWrtSsh]]:
    tls = self_signed_certificate(tmp_path / "tls")
    http = OpenWrtSim()
    device = OpenWrtSsh(http=http, certificate=tls.cert.read_bytes())
    with serve(create_app(http), tls=tls) as url, serve_ssh_in_thread(device) as (port, key):
        yield url, port, key, device


def set_up(app: Any, url: str, port: int, key: str) -> None:
    body = {
        "device": {
            "name": "Access point",
            "site_id": "home",
            "role": "ap",
            "adapter": "openwrt",
            "allow_writes": False,
            "config": {"url": url, "username": "signalbox", "password": ""},
        },
        "admin": {"user": "root", "secret": ROOT_PASSWORD, "port": port},
        "trust": key,
    }
    assert api(app, "POST", "/devices/setup/apply", body)["ok"]


def to_identity(app: Any, port: int) -> None:
    """The stored device's setup box, up to the identity (no password asked yet)."""
    app.goto(app.server.url + "/#/device/access-point/settings")
    app.reload()  # the same address again renders the page afresh
    expect(app.get_by_test_id("auto-setup")).to_be_visible()
    app.get_by_test_id("auto-setup").locator("summary").click()
    app.get_by_test_id("setup-admin-port").fill(str(port))
    app.get_by_test_id("setup-plan").click()
    app.get_by_test_id("setup-continue").click()


def test_known_key_needs_no_prompt_and_a_changed_key_warns(
    app: Any, router: tuple[str, int, str, OpenWrtSsh]
) -> None:
    url, port, key, device = router
    add_site(app)
    set_up(app, url, port, key)
    # the device page shows the confirmed key
    app.goto(app.server.url + "/#/device/access-point")
    expect(app.get_by_test_id("device-host-key")).to_have_text(key)

    # the same key again: straight to the password, the step list says it was confirmed
    to_identity(app, port)
    expect(app.get_by_test_id("setup-admin-secret")).to_be_visible()
    expect(app.get_by_test_id("setup-trust")).to_have_count(0)
    expect(app.get_by_test_id("setup-host-key-known")).to_contain_text(key)
    expect(app.get_by_test_id("setup-host-key-known")).to_contain_text("as confirmed on")

    # the router is reinstalled: a new host key on the same device
    with serve_ssh_in_thread(device) as (port2, key2):
        device.passwords.clear()
        scripts = len(device.scripts)
        to_identity(app, port2)
        warning = app.get_by_test_id("setup-host-key-changed")
        expect(warning).to_be_visible()
        expect(warning).to_contain_text("The SSH host key of Access point has changed")
        expect(warning.get_by_test_id("setup-host-key-changed-old")).to_have_text(key)
        expect(warning.get_by_test_id("setup-host-key-changed-new")).to_have_text(key2)
        assert "error" in (warning.get_attribute("class") or "")
        # no way to a password, no plain "trust" button: only the one naming the new key
        expect(app.get_by_test_id("setup-admin-secret")).to_have_count(0)
        expect(app.get_by_test_id("setup-trust")).to_have_count(0)
        retrust = warning.get_by_test_id("setup-host-key-changed-retrust")
        expect(retrust).to_contain_text(key2)
        assert device.passwords == [] and len(device.scripts) == scripts
        # the finding is there until the key is decided
        findings = api(app, "GET", "/findings")
        assert any(r["finding"]["rule_id"] == "ssh.host-key-changed" for r in findings)
        # the device page warns too
        app.goto(app.server.url + "/#/device/access-point")
        expect(app.get_by_test_id("device-host-key-changed")).to_contain_text(key2)

        # trusting the new key by name: the setup goes on with it, without a prompt
        to_identity(app, port2)
        app.get_by_test_id("setup-host-key-changed-retrust").click()
        expect(app.get_by_test_id("setup-admin-secret")).to_be_visible()
        expect(app.get_by_test_id("setup-host-key-known")).to_contain_text(key2)
        assert device.passwords == []
        app.get_by_test_id("setup-admin-secret").fill(ROOT_PASSWORD)
        app.get_by_test_id("setup-apply").click()
        expect(app.get_by_test_id("toast").first).to_contain_text("Access point set up.")
        assert ROOT_PASSWORD in device.passwords
        keys = api(app, "GET", "/devices")[0]["ssh_host_key"]
        assert keys["pin"]["fingerprint"] == key2
        assert [p["fingerprint"] for p in keys["history"]] == [key]
        assert ROOT_PASSWORD not in app.content()


def test_forget_the_key_asks_again(app: Any, router: tuple[str, int, str, OpenWrtSsh]) -> None:
    url, port, key, _device = router
    add_site(app)
    set_up(app, url, port, key)
    app.goto(app.server.url + "/#/device/access-point")
    app.get_by_test_id("device-host-key-forget").click()
    app.get_by_test_id("confirm-ok").click()
    expect(app.get_by_test_id("device-host-key-history")).to_contain_text(key)
    to_identity(app, port)
    expect(app.get_by_test_id("setup-fingerprint")).to_contain_text(key)
    expect(app.get_by_test_id("setup-trust")).to_be_visible()
