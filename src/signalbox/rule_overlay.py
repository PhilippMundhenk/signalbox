"""Rule settings made in the UI (#454, ADR 0027 addendum).

The UI saves ``params`` and ``scopes`` of a rule in the store, never in ``signalbox.yaml``. The
effective ``rules:`` configuration is layered: defaults < UI < signalbox.yaml < environment. A
parameter the file (or the environment) sets stays read-only in the UI; scopes of the file stay
as they are and the UI's scopes follow them.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from signalbox.rules import RuleScope, RuleSettings
from signalbox.rules._params import RuleParams, check_settings
from signalbox.store import Store

SETTING_KEY = "rule-overlay"
MAX_PARAMS = 50
MAX_SCOPES = 50
MAX_TEXT = 200


class RuleOverlay(BaseModel):
    """What the UI set for one rule: parameters for the whole rule and scopes."""

    model_config = ConfigDict(extra="forbid")

    params: dict[str, Any] = Field(default_factory=dict)
    scopes: list[RuleScope] = Field(default_factory=list)

    def empty(self) -> bool:
        return not self.params and not self.scopes


class OverlayError(ValueError):
    """The settings are invalid; the message names the setting path."""


def load(store: Store) -> dict[str, RuleOverlay]:
    raw = store.get_setting(SETTING_KEY)
    if not raw:
        return {}
    out: dict[str, RuleOverlay] = {}
    for rule_id, data in json.loads(raw).items():
        try:
            out[rule_id] = RuleOverlay.model_validate(data)
        except ValidationError:  # stale after an upgrade: skip rather than fail to start
            continue
    return out


def save(store: Store, overlay: Mapping[str, RuleOverlay]) -> None:
    data = {
        k: v.model_dump(mode="json", exclude_none=True) for k, v in overlay.items() if not v.empty()
    }
    if data:
        store.set_setting(SETTING_KEY, json.dumps(data, sort_keys=True))
    else:
        store.delete_setting(SETTING_KEY)


def effective(
    file_rules: Mapping[str, RuleSettings], overlay: Mapping[str, RuleOverlay]
) -> dict[str, RuleSettings]:
    """File (and environment) settings over the UI's: per parameter name the file wins; scopes
    of the file come first, then those of the UI."""
    out: dict[str, RuleSettings] = {k: v.model_copy(deep=True) for k, v in file_rules.items()}
    for rule_id, o in overlay.items():
        base = out.get(rule_id) or RuleSettings()
        out[rule_id] = base.model_copy(
            update={
                "params": {**o.params, **base.params},
                "scopes": [*base.scopes, *(s.model_copy(deep=True) for s in o.scopes)],
            }
        )
    return out


def apply(target: dict[str, RuleSettings], new: Mapping[str, RuleSettings]) -> None:
    """Replace the content of the live ``rules:`` mapping in place (the runner shares it)."""
    target.clear()
    target.update(new)


def validate(
    rule_id: str,
    body: RuleOverlay,
    models: Mapping[str, type[RuleParams]],
    known: set[str],
    file_settings: RuleSettings | None,
) -> list[str]:
    """Problems of the UI settings of one rule, each naming its path (empty: fine)."""
    where = f"rules.{rule_id}"
    if rule_id not in known:
        return [f"{where}: not an installed rule"]
    errors: list[str] = []
    if len(body.params) > MAX_PARAMS:
        errors.append(f"{where}.params: at most {MAX_PARAMS} parameters")
    if len(body.scopes) > MAX_SCOPES:
        errors.append(f"{where}.scopes: at most {MAX_SCOPES} scopes")
    for i, sc in enumerate(body.scopes):
        for k, v in sc.match.selectors().items():
            if len(v) > MAX_TEXT:
                errors.append(f"{where}.scopes[{i}].match.{k}: at most {MAX_TEXT} characters")
        if len(sc.params) > MAX_PARAMS:
            errors.append(f"{where}.scopes[{i}].params: at most {MAX_PARAMS} parameters")
    for source, params in [(f"{where}.params", body.params)] + [
        (f"{where}.scopes[{i}].params", sc.params) for i, sc in enumerate(body.scopes)
    ]:
        for k, v in params.items():
            if isinstance(v, str) and len(v) > MAX_TEXT:
                errors.append(f"{source}.{k}: at most {MAX_TEXT} characters")
    if errors:
        return errors
    model = models.get(rule_id)
    if model is None:
        return (
            [f"{where}.params: {rule_id} has no parameters"]
            if (body.params or any(s.params for s in body.scopes))
            else []
        )
    merged = effective({rule_id: file_settings or RuleSettings()}, {rule_id: body})
    n_file = len(file_settings.scopes) if file_settings else 0
    lines = check_settings({rule_id: model}, merged, known)

    def rename(line: str) -> str:
        return re.sub(
            rf"^{re.escape(where)}\.scopes\.(\d+)\.params",
            lambda m: f"{where}.scopes[{int(m.group(1)) - n_file}].params",
            line,
        )

    return [rename(line) for line in lines]


def fixed_params(file_settings: RuleSettings | None, names: set[str]) -> list[str]:
    """The parameters among ``names`` that the file (or the environment) sets."""
    return sorted(names & set(file_settings.params)) if file_settings else []
