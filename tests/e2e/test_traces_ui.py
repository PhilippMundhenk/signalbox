"""Routed paths on the topology page (#253): off by default, Trace now with progress, results."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from .conftest import PASSWORD, LiveServer, add_site, api, observe
from .fakes import Tracing

pytestmark = pytest.mark.e2e


@pytest.fixture
def tracing(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(
        tmp_path,
        adapters={"labtrace": Tracing},
        env={
            "SIGNALBOX_TRACES_ENABLED": "true",
            "SIGNALBOX_TRACES_FROM_SIGNALBOX": "false",
            "SIGNALBOX_TRACES_INTERNET_TARGET": "198.51.100.99",
            "SIGNALBOX_TRACES_MIN_GAP_SECONDS": "0",
        },
    )
    yield srv
    srv.stop()


def login(page: Any, server: LiveServer) -> Any:
    page.set_default_timeout(15000)
    page.goto(server.url)
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    page.get_by_test_id("logout").wait_for()
    page.server = server
    return page


def add_router(page: Any, name: str, site: str, lan: str) -> None:
    body = {
        "name": name,
        "site_id": site,
        "role": "gateway",
        "adapter": "labtrace",
        "config": {"lan": lan},
    }
    api(page, "POST", "/devices", body)


def test_trace_now_shows_the_routed_paths(page: Any, tracing: LiveServer) -> None:
    app = login(page, tracing)
    add_site(app, "Home")
    add_site(app, "Office")
    add_router(app, "Home router", "home", "10.1.0.1/24")
    add_router(app, "Office router", "office", "10.2.0.1/24")
    observe(app)
    app.goto(f"{tracing.url}/#/topology")
    card = app.get_by_test_id("routed-paths")
    card.get_by_test_id("no-traces").wait_for()
    assert "Home router" in card.get_by_test_id("trace-sources").inner_text()
    card.get_by_test_id("trace-now").click()
    rows = card.get_by_test_id("trace-row")
    rows.nth(3).wait_for()
    assert rows.count() == 4  # two routers, each to the other and to the internet target
    progress = card.get_by_test_id("trace-progress")
    assert progress.get_attribute("data-running") == "no"
    assert "4 traces" in progress.inner_text()
    home = card.locator('[data-testid="trace-row"][data-id="trace/home-router/10.2.0.1"]')
    hops = home.get_by_test_id("hop")
    assert [hops.nth(i).inner_text() for i in range(hops.count())] == [
        "192.168.100.1",
        "203.0.113.1",
        "Office router",
    ]
    assert hops.nth(0).get_attribute("data-kind") == "private"
    assert hops.nth(2).get_attribute("data-kind") == "device"
    front = card.get_by_test_id("in-front-row")
    assert "an unknown router (192.168.100.1, private address) is in front of Home router" in [
        front.nth(i).inner_text() for i in range(front.count())
    ]
    # only from one router to one address
    card.get_by_test_id("trace-source").select_option("home-router")
    card.get_by_test_id("trace-target").select_option("address")
    card.get_by_test_id("trace-address").fill("198.51.100.7")
    card.get_by_test_id("trace-now").click()
    card.locator('[data-testid="trace-row"][data-id="trace/home-router/198.51.100.7"]').wait_for()
    assert "1 traces" in card.get_by_test_id("trace-progress").inner_text()
    # the extra NAT router on the way to the internet is a finding
    findings = api(app, "GET", "/findings")
    assert any(f["finding"]["rule_id"] == "trace.extra-nat" for f in findings)


def test_routed_paths_are_off_by_default(app: Any) -> None:
    add_site(app, "Home")
    api(
        app,
        "POST",
        "/devices",
        {
            "name": "Lab",
            "site_id": "home",
            "role": "gateway",
            "adapter": "lab",
            "config": {"host": "192.0.2.1", "password": "device-secret"},
        },
    )
    observe(app)
    app.goto(f"{app.server.url}/#/topology")
    off = app.get_by_test_id("traces-off")
    off.wait_for()
    assert "traces.enabled" in off.inner_text()
    assert app.get_by_test_id("trace-now").count() == 0
    r = app.request.fetch(
        f"{app.server.url}/api/traces",
        method="POST",
        data="{}",
        headers={"Content-Type": "application/json"},
    )
    assert r.status == 403
