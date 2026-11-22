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


def _gone(net: Network, history: History, target: str, note: Annotation | None) -> str | None:
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
        return f"has not been seen for {history.days} days"
    if kind is TargetKind.SEGMENT:
        site = target.split("/", 1)[0]
        if net.knows(target):
            return None
        if site not in {s.id for s in net.sites}:
            return f"belongs to a site that does not exist ({site})"
        devices = [d for d in net.devices if d.site_id == site]
        if devices and all(net.statuses.get(d.id) is DeviceStatus.OK for d in devices):
            return "is not reported by any device of the site"
        return None
    dev = device_of(net, target)
    if dev is None:
        return "belongs to no device in Signalbox (removed or disabled)"
    if kind is TargetKind.DEVICE or net.knows(target):
        return None
    if net.statuses.get(dev.id) is DeviceStatus.OK:
        return f"is not reported by {dev.name}"
    return None


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
        why = _gone(net, history, note.target, note)
        if why:
            yield found(
                f"{note.target}{f' ({note.label})' if note.label else ''} has an annotation "
                f"but {why}",
                [note.target],
                fix="If the object was renamed, move the annotation to its new id; if it is "
                "gone, remove the annotation.",
                key="annotation",
            )
    for ack in net.acknowledgements:
        if ack.target is None:
            continue
        why = _gone(net, history, ack.target, net.annotation(ack.target))
        if why:
            yield found(
                f"{ack.target} has an acknowledgement of {ack.rule_id} but {why}",
                [ack.target],
                fix="If the object was renamed, acknowledge the finding again; if it is gone, "
                "remove the acknowledgement.",
                key=f"ack:{ack.id}",
            )


RULES: list[Rule] = [stale]
