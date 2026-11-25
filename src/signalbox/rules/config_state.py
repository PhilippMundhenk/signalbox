"""Configuration state and backups (issue #181).

"The switch loses its VLANs after the next power cut because nobody pressed save" and "the
router has no backup at all" are invisible without what the device says about its configuration.
Every rule stays quiet where the device does not say (``None``), and treats ``False`` as fine.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from signalbox.model import Network
from signalbox.rules import (
    Result,
    Rule,
    RuleParams,
    Severity,
    ctx,
    found,
    history_rule,
    param,
    rule,
)
from signalbox.sightings import History

#: A backup older than this, of a configuration that changed after it, counts as missing.
BACKUP_MAX_AGE = timedelta(days=30)


@rule(
    "config.unsaved",
    "Running configuration is not saved",
    Severity.WARNING,
    "The device runs a configuration that differs from the one it saved, so the next restart "
    "or power cut reverts the changes (a switch loses its VLANs). Save the configuration on "
    "the device. Devices that save every change at once (RouterOS) are never reported.",
)
def unsaved(net: Network) -> Iterator[Result]:
    for d in net.devices:
        if d.config_state and d.config_state.unsaved:
            yield found(
                f"{d.name} runs a configuration that is not saved; a restart loses the changes",
                [d.id],
                fix=f"Save the running configuration of {d.name}, or revert the change.",
                mid="config.unsaved",
                fix_id="config.unsaved.fix",
                params={"name": d.name},
            )


@rule(
    "config.pending",
    "Configuration changes are staged but not applied",
    Severity.WARNING,
    "Changes were made and not applied (OpenWrt UCI changes that were not committed). They "
    "do nothing yet and are lost or applied by surprise later. Apply or revert them.",
)
def pending(net: Network) -> Iterator[Result]:
    for d in net.devices:
        if d.config_state and d.config_state.pending:
            yield found(
                f"{d.name} has configuration changes that are staged and not applied",
                [d.id],
                fix=f"Apply the staged changes on {d.name}, or revert them.",
                mid="config.pending",
                fix_id="config.pending.fix",
                params={"name": d.name},
            )


@history_rule(
    "backup.none",
    "No backup of the device",
    Severity.INFO,
    "Neither the device nor Signalbox holds a backup of its configuration (or the newest is "
    f"older than {BACKUP_MAX_AGE.days} days and the configuration changed after it), so a "
    "failed device or a bad change cannot be undone. Only devices that say what backups they "
    "keep are checked. Signalbox takes a backup before every change it deploys.",
)
def no_backup(net: Network, history: History) -> Iterator[Result]:
    now = history.now
    if now is None:
        return
    for d in net.devices:
        local = d.local_backups
        if local is None or local.count is None:
            continue
        mine = d.signalbox_backup_newest
        if mine is not None and now - mine <= BACKUP_MAX_AGE:
            continue
        changed = d.config_state.last_changed if d.config_state else None
        fix = (
            "Download a backup from the device, or deploy a change through Signalbox, "
            "which takes one first, and keep it somewhere safe."
        )
        if local.count == 0:
            yield found(
                f"{d.name} has no backup of its configuration, and Signalbox has none either",
                [d.id],
                fix=fix,
                mid="backup.none",
                fix_id="backup.none.fix",
                params={"name": d.name},
            )
        elif (
            local.newest is not None
            and now - local.newest > BACKUP_MAX_AGE
            and changed is not None
            and changed > local.newest
        ):
            yield found(
                f"{d.name} has no backup newer than {BACKUP_MAX_AGE.days} days and changed "
                "since, and Signalbox has none either",
                [d.id],
                fix=fix,
                mid="backup.stale",
                fix_id="backup.none.fix",
                params={"name": d.name, "days": BACKUP_MAX_AGE.days},
            )


class OutsideParams(RuleParams):
    days: int = param(
        7, unit="d", ge=1, le=365, description="Report changes made in the last this many days."
    )
    minutes: int = param(
        30,
        unit="min",
        ge=1,
        le=1440,
        description="A change that follows Signalbox's own backup within this time is Signalbox's.",
    )


@history_rule(
    "config.changed-outside",
    "Configuration changed outside Signalbox",
    Severity.INFO,
    "The device's own record says its configuration changed recently, and Signalbox did not "
    "make the change (Signalbox takes a backup right before every change it deploys; a change "
    "that does not follow one is somebody else's). Fine when it was you in the device's own "
    "interface; worth a look when it was not. Only for devices that record the time of the "
    "last change (MikroTik, OPNsense); the user the device logs is on the device page. The "
    "parameters are the days to look back and the minutes a deployment may take.",
    params=OutsideParams,
)
def changed_outside(net: Network, history: History) -> Iterator[Result]:
    now = history.now
    if now is None:
        return
    for d in net.devices:
        changed = d.config_state.last_changed if d.config_state else None
        if changed is None:
            continue
        p = ctx.params(OutsideParams, d)
        if now - changed > timedelta(days=p.days) or changed > now:
            continue
        mine = d.signalbox_backup_newest
        if mine is not None and timedelta(0) <= changed - mine <= timedelta(minutes=p.minutes):
            continue
        yield found(
            f"The configuration of {d.name} was changed in the last {p.days} days, and not "
            "through Signalbox",
            [d.id],
            fix="If you made the change in the device's own interface, nothing to do. If not, "
            "check who has access to the device (the device page shows the user it logged).",
            mid="config.changedOutside",
            fix_id="config.changedOutside.fix",
            params={"name": d.name, "days": p.days},
        )


RULES: list[Rule] = [unsaved, pending, no_backup, changed_outside]
