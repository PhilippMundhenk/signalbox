"""One notice component for every page (#311): shown once, replaced by the newer result,
cleared when resolved, and the same look everywhere."""

from __future__ import annotations

import json
from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import PASSWORD, add_lab, add_site, api, observe
from .test_ui import go

pytestmark = pytest.mark.e2e


def fail_plan(app: Any, message: str) -> None:
    app.route(
        "**/api/plan",
        lambda route: route.fulfill(
            status=500,
            content_type="application/json",
            body=json.dumps({"error": "boom", "message": message}),
        ),
    )


def test_error_is_shown_once_replaced_and_cleared_by_a_success(app: Any) -> None:
    add_site(app)
    api(app, "PUT", "/desired", {"yaml": "sites:\n  home:\n    segments: []\n", "message": ""})
    go(app, "#/desired")
    fail_plan(app, "Planning exploded")
    app.get_by_test_id("plan-make").click()
    err = app.get_by_test_id("page-error")
    expect(err).to_have_count(1)
    expect(err).to_contain_text("Planning exploded")
    # the same failure again does not stack a second notice, a different one replaces it
    app.get_by_test_id("plan-make").click()
    expect(err).to_have_count(1)
    app.unroute("**/api/plan")
    fail_plan(app, "Still broken")
    app.get_by_test_id("plan-make").click()
    expect(err).to_have_count(1)
    expect(err).to_contain_text("Still broken")
    expect(err).not_to_contain_text("Planning exploded")
    # a later success clears it
    app.unroute("**/api/plan")
    app.get_by_test_id("plan-make").click()
    expect(err).to_have_count(0)
    expect(app.get_by_test_id("plan")).not_to_contain_text("Compute what would change")
    # errors are never toasts
    expect(app.locator("#toasts .toast.error")).to_have_count(0)


def test_page_error_is_dismissible_and_gone_after_navigation(app: Any) -> None:
    go(app, "#/desired")
    fail_plan(app, "Planning exploded")
    app.get_by_test_id("plan-make").click()
    expect(app.get_by_test_id("page-error")).to_have_count(1)
    app.get_by_test_id("notice-dismiss").click()
    expect(app.get_by_test_id("page-error")).to_have_count(0)
    app.get_by_test_id("plan-make").click()
    expect(app.get_by_test_id("page-error")).to_have_count(1)
    app.unroute("**/api/plan")
    go(app, "#/segments")
    expect(app.get_by_test_id("page-error")).to_have_count(0)


def test_form_error_is_replaced_and_cleared_by_a_valid_test(app: Any) -> None:
    add_site(app)
    add_lab(app, "Router")
    observe(app)
    go(app, "#/devices/new")
    app.get_by_test_id("device-adapter").select_option("lab")
    app.get_by_test_id("form-test-button").click()
    expect(app.get_by_test_id("form-errors")).to_have_count(1)
    expect(app.get_by_test_id("form-errors")).to_contain_text("Password is required")
    app.get_by_test_id("form-test-button").click()
    expect(app.get_by_test_id("form-errors")).to_have_count(1)
    app.get_by_test_id("cfg-password").fill("device-secret")
    app.get_by_test_id("cfg-host").fill("192.0.2.9")
    app.get_by_test_id("form-test-button").click()
    expect(app.get_by_test_id("form-test").get_by_test_id("test-result")).to_be_visible()
    expect(app.get_by_test_id("form-errors")).to_have_count(0)


def test_errors_look_the_same_on_every_page(page: Any, server: Any) -> None:
    page.set_default_timeout(15000)
    looks: dict[str, dict[str, str]] = {}

    def look(testid: str, key: str) -> None:
        el = page.get_by_test_id(testid)
        expect(el).to_have_count(1)
        expect(el).to_have_class("notice error")
        expect(el).to_have_attribute("role", "alert")
        looks[key] = el.evaluate(
            "e => { const c = getComputedStyle(e);"
            " return { border: c.borderLeftColor, bg: c.backgroundColor,"
            " radius: c.borderRadius }; }"
        )

    page.goto(server.url)
    page.get_by_test_id("login-password").fill("wrong-password")
    page.get_by_test_id("login-submit").click()
    look("login-error", "login")
    page.get_by_test_id("login-password").fill(PASSWORD)
    page.get_by_test_id("login-submit").click()
    page.get_by_test_id("logout").wait_for()
    page.server = server
    add_site(page)

    go(page, "#/desired")
    fail_plan(page, "Planning exploded")
    page.get_by_test_id("plan-make").click()
    look("page-error", "page")
    page.unroute("**/api/plan")

    go(page, "#/devices/new")
    page.get_by_test_id("device-adapter").select_option("lab")
    page.get_by_test_id("form-test-button").click()
    look("form-errors", "form")

    assert looks["login"] == looks["page"] == looks["form"]
    assert looks["page"]["border"] != looks["page"]["bg"]
