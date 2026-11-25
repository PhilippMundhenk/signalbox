"""Web Push (#372): the service worker registers on a button press only, under the strict CSP.

Headless Chromium has no push service (FCM), so ``pushManager.subscribe`` is replaced by a fake
that returns a subscription; the service worker registration, its file and headers, the API and
the settings UI are the real ones."""

from __future__ import annotations

from typing import Any

import pytest
from playwright.sync_api import expect

from .conftest import api
from .test_ui import go

pytestmark = pytest.mark.e2e

REGISTRATIONS = "navigator.serviceWorker.getRegistrations().then(r => r.map(x => x.scope))"
FAKE_PUSH = """
PushManager.prototype.getSubscription = async () => null;
PushManager.prototype.subscribe = async () => ({
  toJSON: () => ({
    endpoint: 'https://push.example.net/send/e2e-token',
    keys: { p256dh: 'B'.repeat(87), auth: 'a'.repeat(22) },
  }),
  unsubscribe: async () => true,
});
"""


def test_subscribe_and_unsubscribe_on_a_button_press(app: Any) -> None:
    app.add_init_script(FAKE_PUSH)
    app.context.grant_permissions(["notifications"])
    go(app, "#/settings")
    expect(app.get_by_test_id("notify-push")).to_contain_text("Web Push")
    # opt-in: opening the page registers nothing and subscribes nobody
    assert app.evaluate(REGISTRATIONS) == []
    assert api(app, "GET", "/notifications/webpush")["subscriptions"] == []
    app.get_by_test_id("notify-push-on").click()
    expect(app.get_by_test_id("notify-push-item")).to_have_count(1)
    assert app.evaluate(REGISTRATIONS) == [f"{app.server.url}/"]
    listed = api(app, "GET", "/notifications/webpush")["subscriptions"]
    assert [s["host"] for s in listed] == ["push.example.net"]
    app.get_by_test_id("notify-push-off").click()
    expect(app.get_by_test_id("notify-push-item")).to_have_count(0)
    assert api(app, "GET", "/notifications/webpush")["subscriptions"] == []


def test_the_worker_file_has_the_scope_header_and_the_strict_csp(app: Any) -> None:
    res = app.request.get(f"{app.server.url}/sw.js")
    assert res.ok
    assert res.headers["service-worker-allowed"] == "/"
    csp = res.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
