"""Typed rule parameters and per-scope rule settings (#187, ADR 0027).

A rule that has thresholds declares them as a :class:`RuleParams` model next to the rule and
names it in the decorator (``@rule(..., params=StorageParams)``). The rule reads its values
through :data:`ctx`, for the object the values apply to::

    p = ctx.params(StorageParams, dev)
    if used >= p.warn_pct: ...

Outside :func:`signalbox.rules.evaluate` (a rule called directly in a test) ``ctx.params``
returns the defaults. Inside it the configuration applies: ``rules.<id>.params`` and then the
matching ``rules.<id>.scopes`` from the least to the most specific.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from signalbox.model import (
    Device,
    DeviceRole,
    MessageValue,
    Network,
    Segment,
    SegmentPurpose,
    Site,
)


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class RuleParams(BaseModel):
    """Base of a rule's parameter model: every field has a default, a unit and a description.

    Declare fields with :func:`param`; :func:`signalbox.rules.rule` binds the model to its rule.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: The rule this model belongs to; set by ``@rule(..., params=...)``.
    rule_id: ClassVar[str] = ""


P = TypeVar("P", bound=RuleParams)


def param(
    default: float,
    *,
    unit: str,
    description: str,
    ge: float | None = None,
    le: float | None = None,
) -> Any:
    """A rule parameter: its default, its unit (``%``, ``°C``, ``s``, ``min``, ``d``, ``dBm``,
    ``count``) and what it means. ``ge``/``le`` bound what the configuration may set."""
    return Field(default, description=description, json_schema_extra={"unit": unit}, ge=ge, le=le)


def unit_of(model: type[RuleParams], name: str) -> str:
    extra = model.model_fields[name].json_schema_extra
    return str(extra.get("unit", "")) if isinstance(extra, dict) else ""


def bind(model: type[RuleParams], rule_id: str) -> None:
    """Attach a parameter model to its rule: one model per rule, every field documented."""
    if model.rule_id and model.rule_id != rule_id:
        raise ValueError(f"{model.__name__} already belongs to rule {model.rule_id}")
    for name, info in model.model_fields.items():
        if info.is_required() or not info.description or not unit_of(model, name):
            raise TypeError(f"{model.__name__}.{name}: declare it with param() (default, unit)")
    model()  # the defaults must be valid
    model.rule_id = rule_id


# --- scopes ---------------------------------------------------------------------------------

#: How specific a selector is: a device beats a network, a network beats a tag, a tag beats a
#: role or purpose, those beat a site.
SPECIFICITY = {
    "device": 5,
    "segment": 4,
    "tag": 3,
    "device_role": 2,
    "segment_purpose": 2,
    "site": 1,
}


class ScopeMatch(BaseModel):
    """Which objects a scope applies to; every selector given must match (and)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    site: str | None = Field(None, description="Site id or name.")
    device: str | None = Field(None, description="Device id or name.")
    device_role: DeviceRole | None = Field(None, description="Role of the device.")
    segment: str | None = Field(None, description="Network (segment) id, name or VLAN id.")
    segment_purpose: SegmentPurpose | None = Field(None, description="Purpose of the network.")
    tag: str | None = Field(None, description="A tag of the object's annotation (#186).")

    @model_validator(mode="after")
    def _some(self) -> ScopeMatch:
        if not self.model_fields_set or all(getattr(self, k) is None for k in SPECIFICITY):
            raise ValueError("a scope needs at least one selector: " + ", ".join(SPECIFICITY))
        return self

    def selectors(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for k in SPECIFICITY:
            v = getattr(self, k)
            if v is not None:
                out[k] = v.value if isinstance(v, StrEnum) else str(v)
        return out

    def specificity(self) -> tuple[int, int]:
        keys = self.selectors()
        return max(SPECIFICITY[k] for k in keys), len(keys)

    def label(self) -> str:
        return ", ".join(f"{k}={v}" for k, v in self.selectors().items())

    def matches(self, facts: ScopeFacts) -> bool:
        return all(
            (
                (k == "site" and v in facts.site)
                or (k == "device" and v in facts.device)
                or (k == "device_role" and facts.device_role is not None and v == facts.device_role)
                or (k == "segment" and v in facts.segment)
                or (
                    k == "segment_purpose"
                    and facts.segment_purpose is not None
                    and v == facts.segment_purpose
                )
                or (k == "tag" and v in facts.tags)
            )
            for k, v in self.selectors().items()
        )


class RuleScope(BaseModel):
    """``{match: {...}, enabled, severity, params}``: settings for the objects that match."""

    model_config = ConfigDict(extra="forbid")

    match: ScopeMatch
    enabled: bool | None = None
    severity: Severity | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class RuleSettings(BaseModel):
    """Per-rule configuration: ``rules: {dhcp.one-server: {enabled: false}}``.

    ``params`` sets the rule's parameters (#187), ``scopes`` changes them, ``enabled`` or
    ``severity`` for some sites, devices or networks only.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    severity: Severity | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    scopes: list[RuleScope] = Field(default_factory=list)


@dataclass(frozen=True)
class ScopeFacts:
    """What the scope selectors are compared with, for one object."""

    site: frozenset[str] = frozenset()
    device: frozenset[str] = frozenset()
    device_role: DeviceRole | None = None
    segment: frozenset[str] = frozenset()
    segment_purpose: SegmentPurpose | None = None
    tags: frozenset[str] = frozenset()


NO_FACTS = ScopeFacts()


def _index(net: Network) -> dict[str, object]:
    out: dict[str, object] = {}
    for name in type(net).model_fields:
        value = getattr(net, name)
        if not isinstance(value, list):
            continue
        for item in value:
            key = getattr(item, "id", None)
            if isinstance(key, str):
                out.setdefault(key, item)
    return out


def facts_of(net: Network, obj: object, index: Mapping[str, object] | None = None) -> ScopeFacts:
    """The site, device, network and tags of a model object or a model id.

    A port or a server counts for its device (and network, where it has one); tags are those of
    the object's own annotation and of its device's and network's.
    """
    if obj is None:
        return NO_FACTS
    if isinstance(obj, str):
        found = (index if index is not None else _index(net)).get(obj)
        if found is None:
            return NO_FACTS
        obj = found
    device_id = getattr(obj, "device_id", None)
    segment_id = getattr(obj, "segment_id", None)
    dev = obj if isinstance(obj, Device) else None
    if dev is None and isinstance(device_id, str):
        dev = net.device(device_id)
    seg = obj if isinstance(obj, Segment) else None
    if seg is None and isinstance(segment_id, str):
        seg = net.segment(segment_id)
    own_site = getattr(obj, "site_id", None)
    site_id: str | None = own_site if isinstance(own_site, str) else None
    if isinstance(obj, Site):
        site_id = obj.id
    site_id = site_id or (dev.site_id if dev else None) or (seg.site_id if seg else None)
    sites = {s.id: s.name for s in net.sites}
    seg_names: set[str] = set()
    if seg is not None:
        seg_names = {seg.id, *([seg.name] if seg.name else []), *seg.names_by_device.values()}
        if seg.vlan is not None:
            seg_names.add(str(seg.vlan))
    tags: set[str] = set()
    for target in {getattr(obj, "id", None), dev.id if dev else None, seg.id if seg else None}:
        if isinstance(target, str):
            ann = net.annotation(target)
            if ann is not None:
                tags.update(ann.tags)
    return ScopeFacts(
        site=frozenset({site_id, sites.get(site_id) or site_id}) if site_id else frozenset(),
        device=frozenset({dev.id, dev.name}) if dev else frozenset(),
        device_role=dev.role if dev else None,
        segment=frozenset(seg_names),
        segment_purpose=seg.purpose if seg else None,
        tags=frozenset(tags),
    )


# --- explainability -------------------------------------------------------------------------


class ParamOrigin(StrEnum):
    DEFAULT = "default"
    #: ``rules.<id>.params``
    RULE = "rule"
    #: one of ``rules.<id>.scopes``
    SCOPE = "scope"


class AppliedParam(BaseModel):
    """One parameter value a finding was judged with, and where it came from."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    value: MessageValue
    unit: str
    origin: ParamOrigin = ParamOrigin.DEFAULT
    #: The scope's selectors (``site=lab``) when ``origin`` is ``scope``.
    scope: str | None = None


# --- resolution -----------------------------------------------------------------------------


def _ordered(settings: RuleSettings | None, facts: ScopeFacts) -> list[RuleScope]:
    """The matching scopes in the order they apply: least specific first; among equally
    specific ones the first listed is applied last, so it wins."""
    if settings is None or not settings.scopes:
        return []
    hits = [(s.match.specificity(), -i, s) for i, s in enumerate(settings.scopes)]
    return [s for spec, _, s in sorted(hits, key=lambda x: (x[0], x[1])) if s.match.matches(facts)]


def merged(
    model: type[P], settings: RuleSettings | None, facts: ScopeFacts
) -> tuple[P, dict[str, tuple[ParamOrigin, str | None]]]:
    """The model's values for an object, and where each one came from."""
    values: dict[str, Any] = {}
    origin: dict[str, tuple[ParamOrigin, str | None]] = {}
    if settings is not None:
        for k, v in settings.params.items():
            values[k], origin[k] = v, (ParamOrigin.RULE, None)
        for scope in _ordered(settings, facts):
            for k, v in scope.params.items():
                values[k], origin[k] = v, (ParamOrigin.SCOPE, scope.match.label())
    return model.model_validate(values), origin


class Resolver:
    """The configuration of one :func:`~signalbox.rules.evaluate` run, with caches."""

    def __init__(
        self,
        net: Network,
        settings: Mapping[str, RuleSettings],
        models: Mapping[str, type[RuleParams]],
    ) -> None:
        self.net = net
        self.settings = settings
        self.models = models
        self._index: dict[str, object] | None = None
        self._facts: dict[str, ScopeFacts] = {}
        self._cache: dict[tuple[str, ScopeFacts], Any] = {}

    def facts(self, obj: object) -> ScopeFacts:
        if obj is None:
            return NO_FACTS
        if not isinstance(obj, str):
            return facts_of(self.net, obj)
        if obj not in self._facts:
            if self._index is None:
                self._index = _index(self.net)
            self._facts[obj] = facts_of(self.net, obj, self._index)
        return self._facts[obj]

    def has_scopes(self, rule_id: str) -> bool:
        s = self.settings.get(rule_id)
        return bool(s and s.scopes)

    def params(self, model: type[P], obj: object) -> P:
        s = self.settings.get(model.rule_id)
        if s is None or (not s.params and not s.scopes):
            return model()
        facts = self.facts(obj) if s.scopes else NO_FACTS
        key = (model.rule_id, facts)
        if key not in self._cache:
            self._cache[key] = merged(model, s, facts)
        value: P = self._cache[key][0]
        return value

    def applied(self, rule_id: str, obj: object) -> list[AppliedParam]:
        """What a finding about ``obj`` was judged with (empty for a rule without params)."""
        model = self.models.get(rule_id)
        if model is None:
            return []
        s = self.settings.get(rule_id)
        facts = self.facts(obj) if s is not None and s.scopes else NO_FACTS
        values, origin = merged(model, s, facts)
        return [
            AppliedParam(
                name=k,
                value=getattr(values, k),
                unit=unit_of(model, k),
                origin=origin.get(k, (ParamOrigin.DEFAULT, None))[0],
                scope=origin.get(k, (ParamOrigin.DEFAULT, None))[1],
            )
            for k in model.model_fields
        ]

    def scoped(self, rule_id: str, obj: object) -> tuple[bool | None, Severity | None]:
        """``enabled`` and ``severity`` the matching scopes set for ``obj`` (None: not set)."""
        enabled: bool | None = None
        severity: Severity | None = None
        for scope in _ordered(self.settings.get(rule_id), self.facts(obj)):
            if scope.enabled is not None:
                enabled = scope.enabled
            if scope.severity is not None:
                severity = scope.severity
        return enabled, severity


_ACTIVE: ContextVar[Resolver | None] = ContextVar("signalbox_rule_params", default=None)


@contextmanager
def active(resolver: Resolver) -> Iterator[None]:
    token = _ACTIVE.set(resolver)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


class RuleContext:
    """What a rule may ask the engine while it runs (see the module docstring)."""

    def params(self, model: type[P], scope: object = None) -> P:
        """The parameters of ``model``'s rule for ``scope`` (a model object or id, or None for
        the rule-wide values). Defaults when no configuration is active."""
        if not model.rule_id:
            raise TypeError(f"{model.__name__} is not bound to a rule (@rule(..., params=...))")
        resolver = _ACTIVE.get()
        return model() if resolver is None else resolver.params(model, scope)


ctx = RuleContext()


def _error_lines(where: str, exc: ValidationError) -> list[str]:
    return [
        f"{where}.{'.'.join(map(str, e['loc']))}: {e['msg']}"
        if e["loc"]
        else f"{where}: {e['msg']}"
        for e in exc.errors()
    ]


def check_settings(
    models: Mapping[str, type[RuleParams]],
    settings: Mapping[str, RuleSettings],
    known: set[str],
) -> list[str]:
    """Problems of the ``rules:`` configuration: parameters the rule does not have, values of
    the wrong type or out of range (each scope merged on top of the rule-wide values).

    Rule ids that are not installed are not reported (a plugin may be missing for a while),
    unless they set parameters.
    """
    errors: list[str] = []
    for rule_id, s in sorted(settings.items()):
        where = f"rules.{rule_id}"
        uses_params = bool(s.params) or any(sc.params for sc in s.scopes)
        model = models.get(rule_id)
        if model is None:
            if uses_params:
                what = "has no parameters" if rule_id in known else "is not an installed rule"
                errors.append(f"{where}.params: {rule_id} {what}")
            continue
        try:
            model.model_validate(s.params)
        except ValidationError as exc:
            errors += _error_lines(f"{where}.params", exc)
            continue
        for i, sc in enumerate(s.scopes):
            try:
                model.model_validate({**s.params, **sc.params})
            except ValidationError as exc:
                errors += _error_lines(f"{where}.scopes.{i}.params", exc)
    return errors


def params_schema(models: Mapping[str, type[RuleParams]]) -> dict[str, Any]:
    """JSON Schema of the ``rules:`` section with every rule's parameter model."""
    defs: dict[str, Any] = {}
    rules: dict[str, Any] = {}
    for rule_id in sorted(models):
        model = models[rule_id]
        schema = model.model_json_schema()
        schema["title"] = rule_id
        defs[rule_id] = schema
        ref = {"$ref": f"#/$defs/{rule_id}"}
        rules[rule_id] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enabled": {"type": "boolean"},
                "severity": {"enum": [s.value for s in Severity]},
                "params": ref,
                "scopes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["match"],
                        "properties": {
                            "match": {"$ref": "#/$defs/ScopeMatch"},
                            "enabled": {"type": "boolean"},
                            "severity": {"enum": [s.value for s in Severity]},
                            "params": ref,
                        },
                    },
                },
            },
        }
    match = ScopeMatch.model_json_schema()
    match.pop("$defs", None)
    defs["ScopeMatch"] = match
    for enum in (DeviceRole, SegmentPurpose):
        defs[enum.__name__] = {"enum": [e.value for e in enum], "type": "string"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Signalbox rule parameters",
        "description": "The rules: section of signalbox.yaml (ADR 0027). Rules without "
        "parameters accept enabled, severity and scopes without params.",
        "type": "object",
        "properties": rules,
        "additionalProperties": {"$ref": "#/$defs/RuleSettings"},
        "$defs": {
            **defs,
            "RuleSettings": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "enabled": {"type": "boolean"},
                    "severity": {"enum": [s.value for s in Severity]},
                    "scopes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["match"],
                            "properties": {
                                "match": {"$ref": "#/$defs/ScopeMatch"},
                                "enabled": {"type": "boolean"},
                                "severity": {"enum": [s.value for s in Severity]},
                            },
                        },
                    },
                },
            },
        },
    }
