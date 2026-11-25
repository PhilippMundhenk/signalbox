"""OpenWrt (write): tiers, weights and monitors of an mwan3 policy (#463, ADR 0032).

A gateway group is a ``policy`` section of the ``mwan3`` config; its ``use_member`` list names
``member`` sections (``interface``, ``metric``, ``weight``), and the monitor of a line is the
``track_ip`` list of the mwan3 ``interface`` section of that name. Signalbox never creates or
removes policies, members or interfaces:

- the tier becomes the member's ``metric``: when the order of the tiers changes, every member of
  the policy gets its tier number as metric (metric 1 is the first choice); the weight becomes
  ``weight``;
- a member section that another policy also uses is not changed: a copy of it
  (``sb_<policy>_<interface>``, option ``signalbox '1'``) with the new values takes its place in
  this policy's ``use_member`` list, so the other policies keep theirs;
- the monitor is ``track_ip`` of the interface, the line's monitor in every policy it is in; an
  empty monitor removes the option.

Everything is staged with the other changes of the device and applied by ``uci apply`` with its
confirm timer. *Guess (#21)*: that ``uci apply`` makes mwan3 reload (its init script registers a
config trigger on every 2.x release).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, Described, Label
from signalbox.changes import Change, GatewayGroupValue

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.openwrt.write import Configs

#: Option Signalbox puts on the member sections it adds.
TAG = "signalbox"


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)] if value not in (None, "") else []


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _ranks(values: list[int]) -> list[int]:
    order = sorted(set(values))
    return [order.index(v) + 1 for v in values]


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:20] or "x"


def no_mwan3() -> AdapterError:
    return AdapterError(
        "The router has no mwan3 configuration to change (the mwan3 package is not installed, "
        "or the login may not use it).",
        message_id="openwrt.noMwan3",
    )


def _by_name(cfg: Configs, kind: str) -> dict[str, dict[str, Any]]:
    return dict(cfg.sections("mwan3", kind))


def gateway_group(cfg: Configs, c: Change) -> None:
    """Give the members of one mwan3 policy the tiers, weights and monitors of ``c.new``."""
    if "mwan3" not in cfg.data:
        raise no_mwan3()
    name = c.key.partition("/")[2]
    label = Label(f"gateway group {name}", "gatewayGroup", name)
    policies = _by_name(cfg, "policy")
    if name not in policies or not isinstance(c.new, GatewayGroupValue):
        raise AdapterError(
            f"The router has no mwan3 policy {name}.",
            message_id="openwrt.noPolicy",
            params={"group": name},
        )
    members = _by_name(cfg, "member")
    use = _list(policies[name].get("use_member"))
    of_line = {
        str(members[m].get("interface", "")): m for m in use if m in members
    }  # line -> member section of this policy
    entries = []
    for want in c.new.members:
        section = of_line.get(want.name)
        if section is None:
            raise AdapterError(
                f"The mwan3 policy {name} has no member for the line {want.name}.",
                message_id="openwrt.noPolicyMember",
                params={"group": name, "member": want.name},
            )
        entries.append((want, section))
    metrics = [_int(members[s].get("metric")) or 1 for _, s in entries]
    reorder = _ranks(metrics) != [w.tier for w, _ in entries]
    shared = {
        m for p, s in policies.items() if p != name for m in _list(s.get("use_member"))
    }  # member sections other policies use
    replaced: dict[str, str] = {}
    for want, section in entries:
        values: dict[str, str] = {}
        if reorder and _int(members[section].get("metric")) != want.tier:
            values["metric"] = str(want.tier)
        if want.weight is not None and _int(members[section].get("weight")) != want.weight:
            values["weight"] = str(want.weight)
        if values:
            shown = " ".join(f"{k}={v}" for k, v in values.items())
            if section in shared:
                own = {k: v for k, v in members[section].items() if not k.startswith(".")}
                copy = cfg.add(
                    "mwan3",
                    "member",
                    f"sb_{_slug(name)}_{_slug(want.name)}",
                    {**own, **values, TAG: "1"},
                    Described(
                        f"{label}: line {want.name}: a member of its own ({shown}), the others "
                        f"keep {section}",
                        "plan.openwrt.memberCopy",
                        label=label,
                        member=want.name,
                        options=shown,
                        section=section,
                    ),
                )
                replaced[section] = copy
            else:
                cfg.set(
                    "mwan3",
                    section,
                    values,
                    Described(
                        f"{label}: line {want.name}: {shown}",
                        "plan.openwrt.memberSet",
                        label=label,
                        member=want.name,
                        options=shown,
                    ),
                )
        _monitor(cfg, label, want.name, want.monitor)
    if replaced:
        cfg.set(
            "mwan3",
            name,
            {"use_member": [replaced.get(m, m) for m in use]},
            Described(f"{label}: use its own members", "plan.openwrt.memberUse", label=label),
        )


def _monitor(cfg: Configs, label: str, line: str, monitor: list[Any]) -> None:
    interfaces = _by_name(cfg, "interface")
    section = interfaces.get(line)
    have = sorted({str(a) for a in _list(section.get("track_ip"))}) if section else []
    enabled = section is not None and str(section.get("enabled", "1")) != "0"
    seen = have if enabled else []
    want = [str(a) for a in monitor]
    if sorted(want) == sorted(seen):
        return
    if section is None or not enabled:
        raise AdapterError(
            f"mwan3 has no enabled interface {line} to set the monitor on.",
            message_id="openwrt.noTrackInterface",
            params={"member": line},
        )
    if want:
        cfg.set(
            "mwan3",
            line,
            {"track_ip": want},
            Described(
                f"{label}: line {line}: ping {', '.join(want)}",
                "plan.openwrt.trackSet",
                label=label,
                member=line,
                addresses=", ".join(want),
            ),
        )
    else:
        cfg.drop(
            "mwan3",
            line,
            ["track_ip"],
            Described(
                f"{label}: line {line}: no monitor",
                "plan.openwrt.trackOff",
                label=label,
                member=line,
            ),
        )
