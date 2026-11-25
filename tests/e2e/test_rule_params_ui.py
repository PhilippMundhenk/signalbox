"""Rule parameters and scopes edited on the settings page (#454)."""

from __future__ import annotations

import time
from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import add_site, api
from .test_ui import go

pytestmark = pytest.mark.e2e

RULE = "health.storage-full"


def scopes_of(app: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = next(r for r in api(app, "GET", "/rules") if r["id"] == RULE)[
        "parameters"
    ]["scopes"]
    return out


def wait_scopes(app: Any, count: int) -> list[dict[str, Any]]:
    for _ in range(100):
        found = scopes_of(app)
        if len(found) == count:
            return found
        time.sleep(0.1)
    raise AssertionError(f"expected {count} scopes, found {scopes_of(app)}")


def open_rule(app: Any) -> Any:
    go(app, "#/settings")
    rule = app.locator(f'[data-testid="rule"][data-id="{RULE}"]')
    rule.locator("summary").click()
    return rule


def test_edit_a_parameter_save_and_reset(app: Any) -> None:
    rule = open_rule(app)
    row = rule.locator('[data-testid="rule-param"][data-name="warn_pct"]')
    expect(row).to_have_attribute("data-source", "default")
    expect(row.get_by_test_id("param-reset")).to_be_hidden()
    row.get_by_test_id("param-input").fill("71")
    rule.get_by_test_id("params-save").click()
    expect(app.get_by_test_id("toast").first).to_be_visible()
    row = rule.locator('[data-testid="rule-param"][data-name="warn_pct"]')
    expect(row).to_have_attribute("data-source", "ui")
    expect(row.get_by_test_id("param-input")).to_have_value("71")
    values = next(r for r in api(app, "GET", "/rules") if r["id"] == RULE)["parameters"]["values"]
    assert values["warn_pct"] == 71
    row.get_by_test_id("param-reset").click()
    expect(rule.locator('[data-testid="rule-param"][data-name="warn_pct"]')).to_have_attribute(
        "data-source", "default"
    )
    values = next(r for r in api(app, "GET", "/rules") if r["id"] == RULE)["parameters"]["values"]
    assert values["warn_pct"] == 90


def test_a_value_out_of_range_is_refused_with_its_path(app: Any) -> None:
    rule = open_rule(app)
    row = rule.locator('[data-testid="rule-param"][data-name="warn_pct"]')
    row.get_by_test_id("param-input").evaluate("el => { el.removeAttribute('max'); }")
    row.get_by_test_id("param-input").fill("500")
    rule.get_by_test_id("params-save").click()
    expect(rule.get_by_test_id("error")).to_contain_text(f"rules.{RULE}.params.warn_pct")


def test_add_a_scope_with_pickers_and_remove_it(app: Any) -> None:
    add_site(app, "Lab")
    rule = open_rule(app)
    rule.get_by_test_id("scope-add").click()
    scope = rule.get_by_test_id("ui-scope")
    expect(scope).to_have_count(1)
    scope.locator('[data-testid="scope-select"][data-kind="site"]').select_option("lab")
    scope.locator('[data-testid="scope-param-set"][data-name="warn_pct"]').check()
    scope.locator('[data-testid="scope-param-input"][data-name="warn_pct"]').fill("97")
    rule.get_by_test_id("params-save").click()
    expect(rule.get_by_test_id("ui-scope")).to_have_count(1)
    shown = wait_scopes(app, 1)
    assert shown[0]["source"] == "ui" and shown[0]["match"] == {"site": "lab"}
    assert shown[0]["values"]["warn_pct"] == 97
    # it survives a reload, with the picker on the saved value
    go(app, "#/settings")
    rule = app.locator(f'[data-testid="rule"][data-id="{RULE}"]')
    rule.locator("summary").click()
    expect(rule.locator('[data-testid="scope-select"][data-kind="site"]')).to_have_value("lab")
    rule.get_by_test_id("scope-remove").click()
    rule.get_by_test_id("params-save").click()
    expect(rule.get_by_test_id("ui-scope")).to_have_count(0)
    wait_scopes(app, 0)
