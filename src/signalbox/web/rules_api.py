"""API of the rule settings (#454): list with the source of every value, save the parameters and
scopes made in the UI, reset. The UI's settings live in the store (ADR 0027 addendum); what
``signalbox.yaml`` or the environment sets stays read-only here (409, as for notification
channels). A saved change applies at once: the shared ``rules:`` mapping is replaced and the
rules are evaluated again."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from signalbox import rule_overlay
from signalbox.model import DeviceRole, SegmentPurpose
from signalbox.rule_overlay import RuleOverlay
from signalbox.rules import ENGINE_RULES, describe, parameter_models, rule_enabled
from signalbox.service import Services

CONFIG_FILE = "This setting is set in the configuration file or the environment."


def router(services: Services) -> APIRouter:
    api = APIRouter(prefix="/api")
    config, store, runner = services.config, services.store, services.runner

    def all_rules() -> list[Any]:
        return [*ENGINE_RULES, *services.rules]

    def error(status: int, code: str, message: str) -> JSONResponse:
        return JSONResponse({"error": code, "message": message}, status_code=status)

    @api.get("/rules")
    def rules() -> list[dict[str, Any]]:
        """All rules with severity, enabled state and parameters (schema, defaults, values with
        their source default/file/ui, scopes with theirs)."""
        out = []
        for r in all_rules():
            s = config.rules.get(r.id)
            file_s = services.file_rules.get(r.id)
            ui = services.overlay.get(r.id)
            params = describe(r.params, s)
            file_params = set(file_s.params) if file_s else set()
            ui_params = set(ui.params) if ui else set()
            n_file = len(file_s.scopes) if file_s else 0
            params["sources"] = {
                n: "file" if n in file_params else "ui" if n in ui_params else "default"
                for n in (params["schema"] or {}).get("properties", {})
            }
            for i, sc in enumerate(params["scopes"]):
                sc["source"] = "file" if i < n_file else "ui"
            out.append(
                {
                    "id": r.id,
                    "title": r.title,
                    "explanation": r.explanation,
                    "severity": (s.severity if s and s.severity else r.severity).value,
                    "enabled": rule_enabled(r, config.rules),
                    "parameters": params,
                }
            )
        return out

    @api.get("/rules/scope-options")
    def scope_options() -> dict[str, Any]:
        """What the scope pickers offer, from the inventory (ids and names are untrusted text)."""
        net = runner.network()
        tags = sorted({t for a in store.annotations() for t in a.tags})
        return {
            "site": [{"value": s.id, "label": s.name} for s in net.sites],
            "device": [{"value": d.id, "label": d.name or d.id} for d in net.devices],
            "device_role": [{"value": r.value, "label": r.value} for r in DeviceRole],
            "segment": [
                {"value": g.id, "label": g.name or (f"VLAN {g.vlan}" if g.vlan else g.id)}
                for g in net.segments
            ],
            "segment_purpose": [{"value": p.value, "label": p.value} for p in SegmentPurpose],
            "tag": [{"value": t, "label": t} for t in tags],
        }

    def _apply() -> None:
        rule_overlay.apply(
            config.rules, rule_overlay.effective(services.file_rules, services.overlay)
        )
        runner.evaluate()

    @api.put("/rules/{rule_id}/settings", response_model=None)
    def put_settings(rule_id: str, body: dict[str, Any]) -> dict[str, Any] | JSONResponse:
        """Replace the parameters and scopes the UI sets for a rule."""
        try:
            overlay = RuleOverlay.model_validate(body)
        except ValidationError as exc:
            e = exc.errors()[0]
            loc = "".join(f"[{x}]" if isinstance(x, int) else f".{x}" for x in e["loc"])
            return error(422, "invalid", f"rules.{rule_id}{loc}: {e['msg']}")
        models = parameter_models(all_rules())
        known = {r.id for r in all_rules()}
        file_s = services.file_rules.get(rule_id)
        fixed = rule_overlay.fixed_params(file_s, set(overlay.params))
        if fixed:
            return error(409, "config_file", f"rules.{rule_id}.params.{fixed[0]}: {CONFIG_FILE}")
        problems = rule_overlay.validate(rule_id, overlay, models, known, file_s)
        if problems:
            return error(422, "invalid", "; ".join(problems))
        if overlay.empty():
            services.overlay.pop(rule_id, None)
        else:
            services.overlay[rule_id] = overlay
        rule_overlay.save(store, services.overlay)
        _apply()
        return {"saved": True}

    @api.delete("/rules/{rule_id}/settings", status_code=204, response_model=None)
    def reset_settings(rule_id: str) -> None:
        """Remove what the UI set for a rule (back to the file's or the defaults)."""
        if services.overlay.pop(rule_id, None) is not None:
            rule_overlay.save(store, services.overlay)
            _apply()

    return api
