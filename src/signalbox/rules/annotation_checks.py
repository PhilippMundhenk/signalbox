"""Checks of the user's own annotations and acknowledgements (#186).

``annotations.stale`` covers the main risk of annotations: ids that change (a renamed port, a
VLAN that moved, a device that was removed) silently orphan a note or an acknowledgement.
``ack.expired`` is produced by the rule engine itself (:data:`signalbox.rules.ACK_EXPIRED`).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from signalbox.model import (
    Annotation,
    Device,
    DeviceStatus,
    Network,
    TargetKind,
    target_kind,
)
from signalbox.rules import Result, Rule, Severity, found, history_rule
from signalbox.sightings import History


def device_of(net: Network, target: str) -> Device | None:
    """The device a target belongs to (the longest device id that is the target or its
    prefix; managed devices have ids like ``<controller>/<device>``)."""
    best: Device | None = None
    for dev in net.devices:
        if (target == dev.id or target.startswith(f"{dev.id}/")) and (
            best is None or len(dev.id) > len(best.id)
        ):
            best = dev
    return best


#: Why a target looks gone: (reason id, values, English text).
Gone = tuple[str, dict[str, str | int], str]


def _gone(net: Network, history: History, target: str, note: Annotation | None) -> Gone | None:
    """Why the target looks gone, or None when it exists or that cannot be told."""
    kind = target_kind(target)
    if kind is TargetKind.CLIENT:
        mac = target.split("/", 1)[1]
        if any(c.mac == mac for c in net.clients) or any(
            n.chassis_id.lower() == mac for n in net.neighbours
        ):
            return None
        if note is not None and (note.expected.known_neighbour or note.expected.may_be_unreachable):
            return None  # not one of our clients, or off on purpose
        if mac in history.clients or not history.covers(timedelta(days=history.days)):
            return None
        return (
            "notSeen",
            {"days": history.days},
            f"has not been seen for {history.days} days",
        )
    if kind is TargetKind.SEGMENT:
        site = target.split("/", 1)[0]
        if net.knows(target):
            return None
        if site not in {s.id for s in net.sites}:
            return (
                "noSite",
                {"site": site},
                f"belongs to a site that does not exist ({site})",
            )
        devices = [d for d in net.devices if d.site_id == site]
        if devices and all(net.statuses.get(d.id) is DeviceStatus.OK for d in devices):
            return "notReportedBySite", {}, "is not reported by any device of the site"
        return None
    dev = device_of(net, target)
    if dev is None:
        return "noDevice", {}, "belongs to no device in Signalbox (removed or disabled)"
    if kind is TargetKind.DEVICE or net.knows(target):
        return None
    if net.statuses.get(dev.id) is DeviceStatus.OK:
        return "notReportedBy", {"device": dev.name}, f"is not reported by {dev.name}"
    return None


#: Message ids per reason (#204): one text each for a note and for an acknowledgement.
_NOTE_MIDS = {
    "notSeen": "annotations.stale.notSeen",
    "noSite": "annotations.stale.noSite",
    "notReportedBySite": "annotations.stale.notReportedBySite",
    "noDevice": "annotations.stale.noDevice",
    "notReportedBy": "annotations.stale.notReportedBy",
}
_ACK_MIDS = {
    "notSeen": "annotations.staleAck.notSeen",
    "noSite": "annotations.staleAck.noSite",
    "notReportedBySite": "annotations.staleAck.notReportedBySite",
    "noDevice": "annotations.staleAck.noDevice",
    "notReportedBy": "annotations.staleAck.notReportedBy",
}


@history_rule(
    "annotations.stale",
    "Annotation for an object that is gone",
    Severity.INFO,
    "A note or an acknowledgement names an object by its id. When a port is renamed, a VLAN "
    "moves or a device is removed, the id no longer exists and the note silently stops "
    "applying. Clients count as gone when not seen for the whole history period.",
)
def stale(net: Network, history: History) -> Iterator[Result]:
    if not history.observations:
        return  # nothing read yet; the desired and predicted states have no history either
    for note in net.annotations:
        gone = _gone(net, history, note.target, note)
        if gone:
            reason, values, why = gone
            target = f"{note.target}{f' ({note.label})' if note.label else ''}"
            yield found(
                f"{target} has an annotation but {why}",
                [note.target],
                fix="If the object was renamed, move the annotation to its new id; if it is "
                "gone, remove the annotation.",
                key="annotation",
                mid=_NOTE_MIDS[reason],
                fix_id="annotations.stale.fix",
                params={"target": target, **values},
            )
    for ack in net.acknowledgements:
        if ack.target is None:
            continue
        gone = _gone(net, history, ack.target, net.annotation(ack.target))
        if gone:
            reason, values, why = gone
            yield found(
                f"{ack.target} has an acknowledgement of {ack.rule_id} but {why}",
                [ack.target],
                fix="If the object was renamed, acknowledge the finding again; if it is gone, "
                "remove the acknowledgement.",
                key=f"ack:{ack.id}",
                mid=_ACK_MIDS[reason],
                fix_id="annotations.staleAck.fix",
                params={"target": ack.target, "rule": ack.rule_id, **values},
            )


RULES: list[Rule] = [stale]
