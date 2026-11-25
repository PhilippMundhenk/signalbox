"""Configuration state and backups (issue #181).

"The switch loses its VLANs after the next power cut because nobody pressed save" and "the
router has no backup at all" are invisible without what the device says about its configuration.
Every rule stays quiet where the device does not say (``None``), and treats ``False`` as fine.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from signalbox.model import Network
from signalbox.rules import Result, Rule, Severity, found, history_rule, rule
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


RULES: list[Rule] = [unsaved, pending, no_backup]
