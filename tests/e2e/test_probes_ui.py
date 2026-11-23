"""DHCP servers and routers answering, on the segments page (#184, #61): off by default,
Probe now with a fake socket layer, a foreign server and its finding."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from test_probes import ETH0, FakeSockets, rogue_offer

from .conftest import PASSWORD, LiveServer, add_site, api, observe
from .fakes import Tracing

pytestmark = pytest.mark.e2e


def _fake(app: Any) -> None:
    fake = FakeSockets([ETH0])
    fake.dhcp_servers["eth0"] = [rogue_offer()]
    app.state.prober.sockets = fake


@pytest.fixture
def probing(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(
        tmp_path,
        adapters={"labtrace": Tracing},
        env={"SIGNALBOX_PROBES_ENABLED": "true", "SIGNALBOX_PROBES_WAIT_SECONDS": "1"},
        app_hook=_fake,
    )
    yield srv
    srv.stop()


@pytest.fixture
def quiet(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(tmp_path, adapters={"labtrace": Tracing})
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


def setup(app: Any) -> None:
    add_site(app, "Home")
    body = {
        "name": "Router",
        "site_id": "home",
        "role": "gateway",
        "adapter": "labtrace",
        "config": {"lan": "192.0.2.1/24"},
    }
    api(app, "POST", "/devices", body)
    observe(app)


def test_probe_now_lists_the_foreign_server(page: Any, probing: LiveServer) -> None:
    app = login(page, probing)
    setup(app)
    page.goto(f"{probing.url}/#/segments")
    card = page.get_by_test_id("foreign-servers")
    card.get_by_test_id("no-servers").wait_for()
    card.get_by_test_id("probe-now").click()
    row = card.locator("[data-testid=server-row][data-known=no]")
    row.wait_for()
    assert "192.0.2.254" in row.inner_text() and "foreign" in row.inner_text()
    assert "eth0: done" in card.get_by_test_id("probe-legs").inner_text()
    findings = api(app, "GET", "/findings")
    assert "dhcp.foreign-server" in [f["finding"]["rule_id"] for f in findings]


def test_probes_off_says_what_it_would_do(page: Any, quiet: LiveServer) -> None:
    app = login(page, quiet)
    setup(app)
    page.goto(f"{quiet.url}/#/segments")
    card = page.get_by_test_id("foreign-servers")
    card.get_by_test_id("probes-off").wait_for()
    assert card.get_by_test_id("probe-now").count() == 0
