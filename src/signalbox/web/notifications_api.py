"""API of the notification channels (#367): list, create, change, delete, test.

Secrets are write-only: a response says only whether one is stored. Channels set in the
configuration file are shown (``source: config``) and can be tested, not changed here.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from signalbox import webpush
from signalbox.config import KINDS_LIST, ChannelSpec
from signalbox.notifications import NAME, Notifier, apprise_available
from signalbox.webpush import SubscriptionIn, WebPushError

CONFIG_FILE = "This channel is set in the configuration file."


class ChannelBody(ChannelSpec):
    #: Remove the stored secret (an empty ``secret`` keeps it).
    clear_secret: bool = False


def _public(name: str, source: str, spec: ChannelSpec, notifier: Notifier) -> dict[str, Any]:
    status = notifier.status.get(name)
    return {
        "name": name,
        "source": source,
        **spec.model_dump(mode="json", exclude={"secret"}),
        "secret_set": bool(spec.secret and spec.secret.get_secret_value()),
        "last_ok": status.last_ok if status else None,
        "last_error": status.last_error if status else None,
    }


def router(notifier: Notifier) -> APIRouter:
    api = APIRouter(prefix="/api/notifications")

    @api.get("")
    def state() -> dict[str, Any]:
        kinds = [k for k in KINDS_LIST if k != "apprise" or apprise_available()]
        return {
            "kinds": kinds,
            "language": notifier.config.language,
            "channels": [
                _public(n, src, spec, notifier)
                for n, (src, spec) in notifier.all_channels().items()
            ],
        }

    @api.put("/channels/{name}", response_model=None)
    def put(name: str, body: ChannelBody) -> dict[str, Any] | JSONResponse:
        if not NAME.match(name):
            return JSONResponse(
                {"error": "invalid", "message": "name: lower case letters, digits, - and _"}, 422
            )
        existing = notifier.all_channels().get(name)
        if existing and existing[0] == "config":
            return JSONResponse({"error": "conflict", "message": CONFIG_FILE}, 409)
        try:
            spec = ChannelSpec.model_validate(body.model_dump(exclude={"clear_secret", "secret"}))
        except ValidationError as exc:
            return JSONResponse({"error": "invalid", "message": str(exc.errors()[0]["msg"])}, 422)
        spec.secret = body.secret
        notifier.channels.put(name, spec, keep_secret=not body.clear_secret)
        saved = notifier.channels.get(name)
        assert saved is not None
        return _public(name, "ui", saved, notifier)

    @api.delete("/channels/{name}", status_code=204, response_model=None)
    def delete(name: str) -> JSONResponse | None:
        existing = notifier.all_channels().get(name)
        if existing and existing[0] == "config":
            return JSONResponse({"error": "conflict", "message": CONFIG_FILE}, 409)
        notifier.channels.delete(name)
        return None

    @api.post("/channels/{name}/test", response_model=None)
    async def test(name: str) -> dict[str, Any] | JSONResponse:
        if name not in notifier.all_channels():
            return JSONResponse({"error": "not_found", "message": "No such channel."}, 404)
        problem = await asyncio.to_thread(notifier.test, name)
        return {"ok": problem is None, "error": problem}

    @api.get("/browser")
    def browser(after: int = 0) -> list[dict[str, Any]]:
        """Messages for the browser channels newer than ``after`` (the page polls this)."""
        return [vars(m) for m in notifier.browser_since(after)]

    # Web Push (#372): the public key and the subscriptions of browsers. The private key and the
    # endpoints are never returned.

    @api.get("/webpush")
    def push_state() -> dict[str, Any]:
        on = webpush.available()
        return {
            "available": on,
            "public_key": notifier.webpush.public_key() if on else "",
            "subscriptions": [
                {"id": s.id, "host": s.host, "label": s.label, "created": s.created}
                for s in notifier.webpush.subscriptions()
            ],
        }

    @api.post("/webpush/subscriptions", response_model=None)
    def push_subscribe(body: SubscriptionIn) -> dict[str, Any] | JSONResponse:
        if not webpush.available():
            return JSONResponse(
                {"error": "unavailable", "message": "The pywebpush package is not installed."},
                409,
            )
        try:
            sub = notifier.webpush.add(body)
        except WebPushError as exc:
            return JSONResponse({"error": "invalid", "message": str(exc)}, 422)
        return {"id": sub.id, "host": sub.host, "label": sub.label, "created": sub.created}

    @api.delete("/webpush/subscriptions/{sid}", status_code=204, response_model=None)
    def push_unsubscribe(sid: str) -> JSONResponse | None:
        if not notifier.webpush.remove(sid):
            return JSONResponse({"error": "not_found", "message": "No such subscription."}, 404)
        return None

    return api
