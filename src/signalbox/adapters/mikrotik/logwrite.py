"""MikroTik RouterOS 7 (write): remote syslog targets and the SNMP agent (#327, ADR 0021).

A syslog target is a ``/system/logging/action`` with ``target=remote`` plus the logging rules
(``/system/logging``) that send topics to it. Signalbox creates actions named
``signalbox<address>`` (``192.0.2.5``: ``signalbox192x0x2x5``) and one rule per topic (``info``,
``warning``, ``error``, ``critical``:
RouterOS matches a rule when a message has *all* its topics, so each is a rule of its own). Only
actions with that name prefix, and the device's own action at an address the change adopts, are
changed or removed (with the rules that use it); every other action and rule is left alone.

The SNMP agent is the ``enabled`` flag of ``/snmp``; Signalbox switches it off (and on again to
revert it). Communities and passwords are never read or written.

Both are protected by the scheduler entry of the firewall changes (``fwwrite``): the script it
runs undoes exactly these changes.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from signalbox.adapters import logging_errors
from signalbox.adapters.mikrotik.fwwrite import Revert, ros_quote
from signalbox.changes import Change, LogTargetValue, SnmpPolicyValue
from signalbox.model import LogTransport

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.mikrotik.write import _Config

#: Name prefix that marks an action as Signalbox's.
PREFIX = "signalbox"
#: One rule per topic: the messages Signalbox sends on.
TOPICS = ("info", "warning", "error", "critical")
_ACTION_CLI = "/system logging action"
_RULE_CLI = "/system logging"
#: Properties of an action that a re-created one gets back (the others are the device's own
#: business or computed).
_ACTION_PROPS = (
    "name",
    "target",
    "remote",
    "remote-port",
    "remote-protocol",
    "src-address",
    "bsd-syslog",
    "syslog-facility",
    "syslog-severity",
    "syslog-time-format",
    "remote-log-format",
)
_RULE_PROPS = ("topics", "action", "prefix", "disabled")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def action_name(address: str) -> str:
    # RouterOS accepts only letters and numbers in the name of an action
    return PREFIX + (re.sub(r"[^a-z0-9]+", "x", address.lower()).strip("x")[:32] or "x")


def _ours(cfg: _Config, address: str, adopt: str | None) -> dict[str, Any] | None:
    """The remote action at ``address`` that is Signalbox's (or adopted)."""
    from signalbox.adapters import mikrotik as m

    for row in cfg.static(m.LOG_ACTION):
        if _text(row.get("target")) != "remote" or _text(row.get("remote")) != address:
            continue
        if _text(row.get("name")).startswith(PREFIX) or adopt == address:
            return row
    return None


def _rules(cfg: _Config, name: str) -> list[dict[str, Any]]:
    from signalbox.adapters import mikrotik as m

    return [r for r in cfg.static(m.LOG_RULES) if _text(r.get("action")) == name]


def _action_body(v: LogTargetValue, name: str) -> dict[str, str]:
    return {
        "name": name,
        "target": "remote",
        "remote": v.address,
        "remote-port": str(v.port),
        "remote-protocol": v.transport.value,
    }


def _set_line(cli: str, find: str, values: dict[str, str]) -> str:
    return f"{cli} set {find} " + " ".join(f"{k}={ros_quote(v)}" for k, v in values.items())


def log_target(cfg: _Config, c: Change, revert: Revert) -> None:
    """Create, change or remove one remote syslog target."""
    from signalbox.adapters import mikrotik as m

    address = c.key.partition("/")[2]
    label = f"syslog target {address}"
    row = _ours(cfg, address, c.adopt)
    new = c.new if isinstance(c.new, LogTargetValue) else None
    if new is None:
        if row is None:
            return  # gone already
        name = _text(row.get("name"))
        lines = []
        for rule in _rules(cfg, name):
            values = {k: _text(rule[k]) for k in _RULE_PROPS if _text(rule.get(k))}
            cfg.delete(m.LOG_RULES, rule, f"{label}: remove the logging rule {rule.get('topics')}")
            lines.append(
                f"{_RULE_CLI} add " + " ".join(f"{k}={ros_quote(v)}" for k, v in values.items())
            )
        if lines:  # one block: the rules come back in their order
            revert.add(*lines)
        values = {k: _text(row[k]) for k in _ACTION_PROPS if _text(row.get(k))}
        cfg.delete(m.LOG_ACTION, row, f"{label}: remove")
        revert.add(
            f"{_ACTION_CLI} add " + " ".join(f"{k}={ros_quote(v)}" for k, v in values.items())
        )
        return
    if new.transport not in (LogTransport.UDP, LogTransport.TCP):
        raise logging_errors.transport(new.transport.value)
    if row is None:
        taken = {_text(r.get("name")) for r in cfg.rows(m.LOG_ACTION)}
        name, n = action_name(address), 2
        while name in taken:
            name, n = f"{action_name(address)}-{n}", n + 1
        cfg.put(m.LOG_ACTION, _action_body(new, name), f"{label}: create the logging action")
        revert.add(f"{_ACTION_CLI} remove [find where name={ros_quote(name)}]")
        _rules_on(cfg, name, label, revert)
        return
    name = _text(row.get("name"))
    want = _action_body(new, name)
    old = {k: _text(row.get(k)) for k in ("remote-port", "remote-protocol")}
    changed = {k: want[k] for k in old if old[k] != want[k]}
    if changed:
        cfg.patch(m.LOG_ACTION, row, changed, f"{label}: change the logging action")
        revert.add(
            _set_line(
                _ACTION_CLI,
                f"[find where name={ros_quote(name)}]",
                {k: old[k] for k in changed if old[k]},
            )
        )
    rules = _rules(cfg, name)
    if new.enabled and not rules:
        _rules_on(cfg, name, label, revert)
    else:
        disabled = "false" if new.enabled else "true"
        flipped = [r for r in rules if (not _flag(r.get("disabled"))) != new.enabled]
        for r in flipped:
            cfg.patch(m.LOG_RULES, r, {"disabled": disabled}, f"{label}: switch the rule")
        if flipped:
            back = "no" if new.enabled else "yes"
            revert.add(
                _set_line(_RULE_CLI, f"[find where action={ros_quote(name)}]", {"disabled": back})
            )


def _rules_on(cfg: _Config, name: str, label: str, revert: Revert) -> None:
    from signalbox.adapters import mikrotik as m

    for topic in TOPICS:
        cfg.put(
            m.LOG_RULES,
            {"topics": topic, "action": name},
            f"{label}: send {topic} messages",
        )
    revert.add(f"{_RULE_CLI} remove [find where action={ros_quote(name)}]")


def snmp_policy(c: Change, enabled_now: bool, revert: Revert) -> dict[str, str] | None:
    """The body of the ``PATCH /rest/snmp`` for a policy change; ``None``: nothing to do."""
    mode = c.new.mode if isinstance(c.new, SnmpPolicyValue) else "off"
    if mode == "v3-only":
        raise logging_errors.v3_only()
    want = mode != "off"
    if want == enabled_now:
        return None
    revert.add(f"/snmp set enabled={'yes' if enabled_now else 'no'}")
    return {"enabled": "true" if want else "false"}
