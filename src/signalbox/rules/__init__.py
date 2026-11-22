"""Rules check the merged network and return findings.

A rule is a plain function over a :class:`~signalbox.model.Network` that yields
:class:`Result` objects (built with :func:`found` or :func:`incomplete`), wrapped by the
:func:`rule` decorator::

    @rule("dhcp.one-server", "One DHCP server per segment", Severity.ERROR,
          "Two DHCP servers on one network hand out conflicting addresses.")
    def one_server(net: Network) -> Iterator[Result]:
        ...
        yield found(f"{n} DHCP servers on {seg}", [seg.id, *ids], fix="Disable all but one.")

A rule that needs the past (first/last seen, status and link changes) uses
:func:`history_rule` and receives a read-only :class:`~signalbox.sightings.History` as a second
argument.

Rules are discovered through the ``signalbox.rules`` entry point group; a target is a
:class:`Rule` or a list of them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from importlib.metadata import entry_points

from pydantic import BaseModel, ConfigDict, Field

from signalbox.model import DeviceStatus, Network
from signalbox.sightings import History


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


SEVERITY_ORDER = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Stable across runs: the same problem on the same objects keeps its id.
    id: str
    rule_id: str
    severity: Severity
    title: str
    message: str
    objects: list[str] = Field(default_factory=list)
    fix: str | None = None
    #: True when the rule could not check something (missing data), not a confirmed problem.
    incomplete: bool = False


@dataclass(frozen=True)
class Result:
    message: str
    objects: tuple[str, ...]
    fix: str | None = None
    severity: Severity | None = None
    incomplete: bool = False
    key: str = ""


def found(
    message: str,
    objects: Iterable[str],
    *,
    fix: str | None = None,
    severity: Severity | None = None,
    key: str = "",
) -> Result:
    """A problem. ``key`` distinguishes several findings of one rule on the same objects."""
    return Result(message, tuple(objects), fix, severity, False, key)


def incomplete(message: str, objects: Iterable[str], *, key: str = "") -> Result:
    """Something the rule could not check, for example because a device did not report it."""
    return Result(message, tuple(objects), None, Severity.INFO, True, key)


Check = Callable[[Network], Iterable[Result]]
HistoryCheck = Callable[[Network, History], Iterable[Result]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    explanation: str
    check: Check = field(compare=False)
    #: False for an opt-in rule: it runs only when the configuration sets ``enabled: true``.
    default_enabled: bool = True
    #: Set for a rule that needs the observation history (see :func:`history_rule`).
    history_check: HistoryCheck | None = field(default=None, compare=False)


def rule(
    id: str, title: str, severity: Severity, explanation: str, *, enabled: bool = True
) -> Callable[[Check], Rule]:
    def wrap(fn: Check) -> Rule:
        return Rule(id, title, severity, explanation, fn, enabled)

    return wrap


def history_rule(
    id: str, title: str, severity: Severity, explanation: str, *, enabled: bool = True
) -> Callable[[HistoryCheck], Rule]:
    """Like :func:`rule` for a check of ``(net, history)``.

    The history is read-only and empty where none exists (desired or predicted state, a fresh
    installation): such a rule must stay silent then. Called as ``rule.check(net)`` it sees an
    empty history.
    """

    def wrap(fn: HistoryCheck) -> Rule:
        return Rule(
            id,
            title,
            severity,
            explanation,
            lambda net: fn(net, History.empty()),
            enabled,
            fn,
        )

    return wrap


class RuleSettings(BaseModel):
    """Per-rule configuration: ``rules: {dhcp.one-server: {enabled: false}}``."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    severity: Severity | None = None


def finding_id(rule_id: str, objects: Iterable[str], key: str = "") -> str:
    text = "\x00".join([rule_id, key, *sorted(objects)])
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _finding(r: Rule, res: Result, severity: Severity) -> Finding:
    return Finding(
        id=finding_id(r.id, res.objects, res.key + ("\x00incomplete" if res.incomplete else "")),
        rule_id=r.id,
        severity=Severity.INFO if res.incomplete else (res.severity or severity),
        title=r.title,
        message=res.message,
        objects=list(res.objects),
        fix=res.fix,
        incomplete=res.incomplete,
    )


READ_ERRORS = Rule(
    "signalbox.read",
    "Device could not be read completely",
    Severity.WARNING,
    "A device did not answer, refused the login, presented an untrusted certificate, or one of "
    "its capabilities failed. Checks that need this data are incomplete until it is fixed.",
    lambda net: (),
)

_STATUS_TEXT = {
    DeviceStatus.UNREACHABLE: "is unreachable",
    DeviceStatus.AUTH_FAILED: "refused the login",
    DeviceStatus.UNTRUSTED: "presented a certificate that is not trusted",
}
_STATUS_FIX = {
    DeviceStatus.UNREACHABLE: "Check that the device is on and its address is right.",
    DeviceStatus.AUTH_FAILED: "Check the user name and password or API key of the device.",
    DeviceStatus.UNTRUSTED: "Compare the fingerprint with the device and trust it if it matches.",
}


def _read_findings(net: Network, severity: Severity) -> list[Finding]:
    out = []
    for err in net.errors:
        dev = net.device(err.device_id)
        name = dev.name if dev else err.device_id
        status = net.statuses.get(err.device_id, DeviceStatus.PARTIAL)
        if err.capability == "system" and status in _STATUS_TEXT:
            message = f"{name} {_STATUS_TEXT[status]}: {err.message}"
            fix = _STATUS_FIX[status]
        else:
            message = f"{name}: could not read {err.capability}: {err.message}"
            fix = None
        fix = err.fix or fix
        res = Result(message, (err.device_id,), fix, None, False, err.capability)
        out.append(_finding(READ_ERRORS, res, severity))
    return out


def rule_enabled(r: Rule, settings: Mapping[str, RuleSettings]) -> bool:
    """The configured ``enabled`` setting, else the rule's default (opt-in rules are off)."""
    s = settings.get(r.id)
    if s is None or "enabled" not in s.model_fields_set:
        return r.default_enabled
    return s.enabled


def evaluate(
    net: Network,
    rules: Iterable[Rule],
    settings: Mapping[str, RuleSettings] | None = None,
    history: History | None = None,
) -> list[Finding]:
    """Run every enabled rule. A rule that crashes becomes an error finding, never a silent gap.

    ``history`` reaches the rules made with :func:`history_rule`; without it they see an empty
    history (the desired or predicted state).
    """
    settings = settings or {}
    past = history or History.empty()

    def severity_of(r: Rule) -> Severity:
        s = settings.get(r.id)
        return s.severity if s and s.severity else r.severity

    def enabled(r: Rule) -> bool:
        return rule_enabled(r, settings)

    findings: dict[str, Finding] = {}
    if enabled(READ_ERRORS):
        for f in _read_findings(net, severity_of(READ_ERRORS)):
            findings[f.id] = f
    for r in rules:
        if not enabled(r):
            continue
        try:
            results = list(r.history_check(net, past) if r.history_check else r.check(net))
        except Exception as exc:  # a broken rule must be visible
            results = [
                Result(f"rule failed: {type(exc).__name__}: {exc}", (), None, Severity.ERROR)
            ]
        for res in results:
            f = _finding(r, res, severity_of(r))
            findings.setdefault(f.id, f)
    return sorted(
        findings.values(), key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.message)
    )


def load_rules(group: str = "signalbox.rules") -> list[Rule]:
    """All installed rules. Duplicate ids or targets that are not rules raise."""
    out: dict[str, Rule] = {}
    for ep in entry_points(group=group):
        target = ep.load()
        items = target if isinstance(target, list | tuple) else [target]
        for item in items:
            if not isinstance(item, Rule):
                raise TypeError(f"entry point {ep.name}: {item!r} is not a Rule")
            if item.id in out or item.id == READ_ERRORS.id:
                raise ValueError(f"two rules with id {item.id}")
            out[item.id] = item
    return sorted(out.values(), key=lambda r: r.id)


def all_rule_ids(rules: Iterable[Rule]) -> Iterator[str]:
    yield READ_ERRORS.id
    yield from (r.id for r in rules)
