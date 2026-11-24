"""The Fixes view (#376) with two simulated OpenWrt routers that both lack LLDP: one list, a
count on the devices page, a confirmation per device (one is unticked), identities before any
login, one run, the summary, and the device that was left out is untouched. CI only."""

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

Router = tuple[str, int, str, OpenWrtSsh]


@pytest.fixture
def server(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(tmp_path / "data", adapters={"openwrt": OpenWrtAdapter})
    yield srv
    srv.stop()


def router(tmp_path: Path) -> Iterator[Router]:
    tls = self_signed_certificate(tmp_path)
    http = OpenWrtSim()
    device = OpenWrtSsh(http=http, certificate=tls.cert.read_bytes())
    with serve(create_app(http), tls=tls) as url, serve_ssh_in_thread(device) as (port, key):
        yield url, port, key, device


@pytest.fixture
def routers(tmp_path: Path) -> Iterator[tuple[Router, Router]]:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first, second = router(tmp_path / "a"), router(tmp_path / "b")
    with_first = next(first)
    with_second = next(second)
    try:
        yield with_first, with_second
    finally:
        for gen in (second, first):
            gen.close()


def set_up(app: Any, name: str, r: Router) -> None:
    url, port, key, device = r
    body = {
        "device": {
            "name": name,
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
    device.installed -= LLDP_PACKAGES
    device.lldpd_running = False
    assert device.http is not None
    device.http.lldpd = False


def test_fix_several_devices_together(app: Any, routers: tuple[Router, Router]) -> None:
    first, second = routers
    add_site(app)
    set_up(app, "Router one", first)
    set_up(app, "Router two", second)
    for slug in ("router-one", "router-two"):
        assert api(app, "POST", f"/devices/{slug}/test")["status"] == "ok"

    # the count with a link on the devices page
    app.goto(app.server.url + "/#/devices")
    expect(app.get_by_test_id("fixes-count")).to_contain_text("2 fixes available (0 mandatory)")
    app.get_by_test_id("fixes-link").click()
    expect(app.get_by_test_id("fixes-device")).to_have_count(2)
    expect(app.get_by_test_id("fix-kind").first).to_have_attribute("data-kind", "optional")
    expect(app.get_by_test_id("fixes-run")).to_be_disabled()
    # the filter: mandatory only shows nothing here
    app.get_by_test_id("fixes-filter").select_option("mandatory")
    expect(app.get_by_test_id("fixes-none-filtered")).to_be_visible()
    app.get_by_test_id("fixes-filter").select_option("all")
    for box in app.get_by_test_id("fix-select").all():
        box.check()
    expect(app.get_by_test_id("fixes-run")).to_contain_text("2")

    # the confirmation lists every device and what changes; one is unticked
    scripts = len(first[3].scripts), len(second[3].scripts)
    app.get_by_test_id("fixes-run").click()
    dialog = app.get_by_test_id("fixes-dialog")
    expect(dialog.get_by_test_id("fixes-review-item")).to_have_count(2)
    expect(dialog).to_contain_text("Router one")
    expect(dialog).to_contain_text("Install lldpd")
    ports = {"router-one": first[1], "router-two": second[1]}
    for item in dialog.get_by_test_id("fixes-review-item").all():
        item.get_by_test_id("fixes-port").fill(str(ports[item.get_attribute("data-device")]))
    dialog.locator("[data-device=router-two] [data-testid=fixes-review-tick]").uncheck()
    dialog.get_by_test_id("fixes-continue").click()

    # identities first, no password field yet, nothing sent
    expect(dialog.get_by_test_id("fixes-identity")).to_have_count(1)
    expect(dialog.get_by_test_id("fixes-fingerprint")).to_contain_text("SHA256:")
    expect(app.get_by_test_id("fixes-admin-secret")).to_have_count(0)
    assert (len(first[3].scripts), len(second[3].scripts)) == scripts
    dialog.get_by_test_id("fixes-trust").click()

    # the login last; a missing password is refused
    expect(dialog.get_by_test_id("fixes-temporary-note")).to_contain_text("never saved")
    dialog.get_by_test_id("fixes-apply").click()
    expect(app.get_by_test_id("fixes-error")).to_be_visible()
    assert not first[3].installed >= LLDP_PACKAGES
    secret = dialog.get_by_test_id("fixes-admin-secret")
    secret.fill(ROOT_PASSWORD)
    dialog.get_by_test_id("fixes-apply").click()

    # the summary, the device read again, the other device untouched
    expect(app.get_by_test_id("fixes-summary")).to_contain_text("1 done, 0 failed", timeout=30000)
    expect(app.get_by_test_id("fixes-run-reading")).to_contain_text("Read again")
    assert first[3].installed >= LLDP_PACKAGES and first[3].lldpd_running
    assert not second[3].installed >= LLDP_PACKAGES
    assert ROOT_PASSWORD not in app.content()
    app.get_by_test_id("fixes-close").click()

    # the list shrank: only the left-out device is still offered
    expect(app.get_by_test_id("fixes-device")).to_have_count(1)
    expect(app.get_by_test_id("fixes-device")).to_contain_text("Router two")
