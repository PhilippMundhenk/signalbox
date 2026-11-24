"""Setup jobs: POST /api/devices/setup/jobs and GET .../jobs/{id} report the running step (#316)."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from factories import SITE
from signalbox.adapters import (
    AdapterError,
    AdminLogin,
    AuthFailed,
    SetupRequest,
    SetupResult,
)
from signalbox.adapters.provision import Redactor, Step, run_steps
from signalbox.service import Services, build
from signalbox.web.app import create_app as web_app
from test_runner import Dev

PW = "correct-horse-battery"
ADMIN_SECRET = "admin-secret-xyz"
GATE = threading.Event()


class Stepper(Dev):
    """Four steps; the second waits for the test, the third can fail with the secret in it."""

    manifest = Dev.manifest.model_copy(
        update={"id": "stepper", "admin_login": AdminLogin(transport="none")}
    )

    @classmethod
    async def plan_setup(cls, request: SetupRequest) -> Any:
        raise NotImplementedError

    @classmethod
    async def apply_setup(cls, request: SetupRequest) -> SetupResult:
        secret = request.admin_secret.get_secret_value()
        if request.admin_user == "wrong":
            raise AuthFailed("The admin login was refused.", fix="Check the password.")

        async def slow() -> str:
            await asyncio.to_thread(GATE.wait, 10)
            return "waited"

        async def boom() -> str:
            raise AdapterError(f"device said no to {secret}")

        redact = Redactor()
        redact.add(secret)
        failing = request.admin_user == "failing"
        steps = [
            Step("one", "First", action=_ok),
            Step("two", "Second", action=slow),
            Step("three", "Third", action=boom if failing else _ok),
            Step("four", "Fourth", action=_ok),
        ]
        ok, done = await run_steps(steps, redact)
        return SetupResult(
            ok=ok, steps=done, settings={"url": "x"}, secrets={"password": SecretStr("generated")}
        )


async def _ok() -> str | None:
    return None


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    svc = build(
        tmp_path,
        env={"SIGNALBOX_AUTH_PASSWORD": PW},
        adapters={"stepper": Stepper},
        rules=[],
        link_sources=[],
    )
    svc.store.put_site(SITE)
    yield svc
    svc.close()


@pytest.fixture
def client(services: Services) -> Iterator[TestClient]:
    GATE.clear()
    with TestClient(web_app(services, run_background=False)) as c:
        assert c.post("/api/login", json={"password": PW}).status_code == 200
        yield c
    GATE.set()


def request_body(user: str = "root") -> dict[str, Any]:
    device = {
        "name": "Box",
        "site_id": "home",
        "role": "gateway",
        "adapter": "stepper",
        "config": {"url": "u", "password": ""},
    }
    return {
        "device": device,
        "admin": {"user": user, "secret": ADMIN_SECRET},
        "trust": "SHA256:" + "A" * 43,
    }


def wait_for(client: TestClient, job: str, done: Any) -> dict[str, Any]:
    end = time.monotonic() + 10
    while time.monotonic() < end:
        view = client.get(f"/api/devices/setup/jobs/{job}").json()
        if done(view):
            return view  # type: ignore[no-any-return]
        time.sleep(0.02)
    raise AssertionError("timeout")


def states(view: dict[str, Any]) -> dict[str, str]:
    return {s["id"]: s["state"] for s in view["steps"]}


def test_progress_follows_the_steps_and_the_run_is_done_with_the_device(
    client: TestClient,
) -> None:
    started = client.post("/api/devices/setup/jobs", json=request_body())
    assert started.status_code == 202
    job = started.json()["id"]
    # the first step is finished, the second one is the one running right now
    view = wait_for(client, job, lambda v: v["current"] == "two")
    assert view["state"] == "running" and view["result"] is None
    assert states(view) == {"one": "done", "two": "todo"}
    GATE.set()
    view = wait_for(client, job, lambda v: v["state"] == "finished")
    assert view["current"] is None and view["status"] == 200, view["result"]
    assert view["result"]["ok"] is True and view["result"]["device"]["name"] == "Box"
    assert states(view) == {"one": "done", "two": "done", "three": "done", "four": "done"}
    assert ADMIN_SECRET not in str(view)


def test_failed_step_is_reported_with_its_message_and_without_the_secret(
    client: TestClient, services: Services
) -> None:
    GATE.set()
    job = client.post("/api/devices/setup/jobs", json=request_body("failing")).json()["id"]
    view = wait_for(client, job, lambda v: v["state"] == "finished")
    assert states(view) == {"one": "done", "two": "done", "three": "failed", "four": "skipped"}
    failed = next(s for s in view["steps"] if s["id"] == "three")
    assert failed["message"] == "device said no to ***"
    assert view["status"] == 200 and view["result"]["ok"] is False
    assert view["result"]["device"] is None and services.store.devices() == []
    assert ADMIN_SECRET not in str(view)


def test_refused_login_is_the_jobs_error_as_apply_answers_it(client: TestClient) -> None:
    job = client.post("/api/devices/setup/jobs", json=request_body("wrong")).json()["id"]
    view = wait_for(client, job, lambda v: v["state"] == "finished")
    assert view["status"] == 422 and view["steps"] == []
    assert view["result"]["error"] == "auth_failed"
    assert view["result"]["fix"] == "Check the password."
    assert ADMIN_SECRET not in str(view)


def test_start_refuses_what_apply_refuses_and_unknown_jobs_are_404(client: TestClient) -> None:
    no_secret = request_body()
    del no_secret["admin"]["secret"]
    assert client.post("/api/devices/setup/jobs", json=no_secret).status_code == 422
    no_trust = request_body()
    del no_trust["trust"]
    assert client.post("/api/devices/setup/jobs", json=no_trust).json()["error"] == "invalid"
    assert client.get("/api/devices/setup/jobs/nope").status_code == 404
