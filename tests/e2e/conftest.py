"""Browser tests: the real app served by uvicorn in a thread, with fake adapters, in Chromium."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from signalbox.rules import load_rules
from signalbox.service import Services, build
from signalbox.web.app import create_app
from writable import Writable

from .fakes import Gate, Lab, Resolver, Service, Switch, open_wifi

PASSWORD = "e2e-password-1"
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost")


class LiveServer:
    def __init__(
        self,
        data: Path,
        adapters: dict[str, Any] | None = None,
        env: dict[str, str] | None = None,
        app_hook: Any = None,
    ) -> None:
        self.services: Services = build(
            data,
            env={
                "SIGNALBOX_AUTH_PASSWORD": PASSWORD,
                "SIGNALBOX_DEPLOY_ENABLED": "true",
                **(env or {}),
            },
            adapters=adapters
            or {
                "lab": Lab,
                "labswitch": Switch,
                "labresolver": Resolver,
                "labvpn": Gate,
                "labservice": Service,
                "w": Writable,
            },
            rules=[*load_rules(), open_wifi],
        )
        # Keep the listening socket open from the start (no close-then-rebind race with other
        # xdist workers, which could answer the health check for a server that never started).
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.port: int = self.sock.getsockname()[1]
        app = create_app(self.services)
        if app_hook is not None:
            app_hook(app)  # replace parts of the app (the probe's socket layer, #184)
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True
        )
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(150):
            try:
                opener.open(self.url + "/health", timeout=1).read()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(10)
        self.sock.close()
        self.services.close()


@pytest.fixture
def server(tmp_path: Path) -> Iterator[LiveServer]:
    srv = LiveServer(tmp_path)
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict[str, Any]) -> dict[str, Any]:
    args = {**browser_type_launch_args, "args": ["--no-sandbox", "--disable-gpu"]}
    if os.environ.get("SIGNALBOX_CHROMIUM"):
        args["executable_path"] = os.environ["SIGNALBOX_CHROMIUM"]
    return args


@pytest.fixture
def browser_context_args(browser_context_args: dict[str, Any]) -> dict[str, Any]:
    return {**browser_context_args, "viewport": {"width": 1280, "height": 900}}


@pytest.fixture(autouse=True)
def no_browser_errors(request: pytest.FixtureRequest) -> Iterator[list[str]]:
    """Fail a test on any console error or uncaught exception (CSP violations included).

    Failed requests the test provokes on purpose (a wrong password: 401) are logged by
    Chromium as "Failed to load resource"; those are expected and not counted.
    """
    if "page" not in request.fixturenames:
        yield []
        return
    page = request.getfixturevalue("page")
    errors: list[str] = []
    page.on(
        "console",
        lambda m: (
            errors.append(f"console: {m.text}")
            if m.type == "error" and not m.text.startswith("Failed to load resource")
            else None
        ),
    )
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    yield errors
    assert errors == []


@pytest.fixture
def app(page: Any, server: LiveServer) -> Any:
    """A page that is logged in."""
    page.set_default_timeout(15000)
    page.goto(server.url)
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    page.get_by_test_id("logout").wait_for()
    page.server = server
    return page


def api(page: Any, method: str, path: str, body: Any = None) -> Any:
    r = page.request.fetch(
        f"{page.server.url}/api{path}",
        method=method,
        data=json.dumps(body) if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    assert r.ok, r.text()
    return r.json() if r.status != 204 else None


def add_site(page: Any, name: str = "Home") -> dict[str, Any]:
    result: dict[str, Any] = api(page, "POST", "/sites", {"name": name})
    return result


def add_lab(
    page: Any, name: str, host: str = "192.0.2.1", site: str = "home", role: str = "gateway"
) -> dict[str, Any]:
    body = {
        "name": name,
        "site_id": site,
        "role": role,
        "adapter": "lab",
        "config": {"host": host, "password": "device-secret"},
    }
    result: dict[str, Any] = api(page, "POST", "/devices", body)
    return result


def add_switch(page: Any, name: str = "Core switch", site: str = "home") -> dict[str, Any]:
    body = {
        "name": name,
        "site_id": site,
        "role": "switch",
        "adapter": "labswitch",
        "config": {"address": "192.0.2.2"},
    }
    result: dict[str, Any] = api(page, "POST", "/devices", body)
    return result


def observe(page: Any, timeout: float = 60.0) -> None:
    """Read every device now (POST /api/observe) and wait until the round has finished and every
    enabled device is in the merged network (#485). Raises with the missing ids after ``timeout``
    seconds instead of going on with half the devices."""
    before = api(page, "GET", "/health")["last_run"]
    api(page, "POST", "/observe", {})
    deadline = time.monotonic() + timeout
    while api(page, "GET", "/health")["last_run"] == before:
        if time.monotonic() > deadline:
            raise AssertionError("observation round did not finish")
        time.sleep(0.1)
    while not _all_read(page):
        if time.monotonic() > deadline:
            raise AssertionError(f"devices not read after {timeout:.0f} s: {_unread(page)}")
        time.sleep(0.2)


def _unread(page: Any) -> list[str]:
    wanted = {d["id"] for d in api(page, "GET", "/devices") if d.get("enabled", True)}
    return sorted(wanted - {d["id"] for d in api(page, "GET", "/network")["devices"]})


def topology_state(page: Any) -> str:
    """Device ids of /api/network, node ids and hosted rows of /api/topology: for assertion
    messages, so a CI annotation shows what the server had (#485)."""
    net = api(page, "GET", "/network")
    topo = api(page, "GET", "/topology")
    devices = {d["id"]: d.get("hosted_on") for d in net["devices"]}
    nodes = {n["id"]: [h["id"] for h in n.get("hosted", [])] for n in topo["nodes"]}
    stored = {d["id"]: d.get("hosted_on") for d in api(page, "GET", "/devices")}
    return (
        f"/api/devices (hosted_on)={stored} /api/network devices (hosted_on)={devices} "
        f"/api/topology nodes (hosted rows)={nodes}"
    )


def _all_read(page: Any) -> bool:
    """Every enabled device is in the merged network (#485). A round that was already running
    when the devices were added also moves ``last_run``, but did not read them."""
    wanted = {d["id"] for d in api(page, "GET", "/devices") if d.get("enabled", True)}
    return wanted <= {d["id"] for d in api(page, "GET", "/network")["devices"]}
