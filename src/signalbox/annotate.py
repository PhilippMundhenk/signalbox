"""Annotations and acknowledged findings: the user's own layer over the network (#186).

Two sources, one result on every :class:`~signalbox.model.Network` the runner builds:

- **declared** in the desired state (``sites.<site>.annotations`` and ``acknowledgements``):
  reviewable, in git, read-only in the UI;
- **stored** in the database, set in the web interface (the acknowledge button, the notes of a
  device or client).

Per target, a declared annotation replaces a stored one as a whole (the UI refuses to edit a
declared one). Acknowledgements of both sources apply. Nothing here writes to a device.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import yaml

from signalbox.desired import DesiredState
from signalbox.model import (
    Acknowledgement,
    Annotation,
    AnnotationSource,
    Network,
    TargetKind,
    target_kind,
)


def declared(state: DesiredState | None) -> tuple[list[Annotation], list[Acknowledgement]]:
    """The annotations and acknowledgements the desired state declares."""
    if state is None:
        return [], []
    notes = [a.annotation() for spec in state.sites.values() for a in spec.annotations]
    acks = [
        ack.acknowledgement(site_id)
        for site_id, spec in state.sites.items()
        for ack in spec.acknowledgements
    ]
    return notes, acks


def combine(
    state: DesiredState | None,
    stored: Iterable[Annotation],
    stored_acks: Iterable[Acknowledgement],
) -> tuple[list[Annotation], list[Acknowledgement]]:
    """Declared and stored annotations (declared wins per target) and all acknowledgements."""
    notes, acks = declared(state)
    taken = {a.target for a in notes}
    notes += [a for a in stored if a.target not in taken]
    acks += list(stored_acks)
    return sorted(notes, key=lambda a: a.target), sorted(acks, key=lambda a: a.id)


def apply(
    net: Network,
    state: DesiredState | None,
    stored: Iterable[Annotation] = (),
    stored_acks: Iterable[Acknowledgement] = (),
) -> Network:
    """The network with the user's annotations and acknowledgements."""
    notes, acks = combine(state, stored, stored_acks)
    if not notes and not acks:
        return net
    return net.model_copy(update={"annotations": notes, "acknowledgements": acks})


def target_site(net: Network, target: str) -> str | None:
    """The site an object belongs to: its device's, a segment's own, or where a client was
    seen. None when the network does not know it."""
    kind = target_kind(target)
    if kind is TargetKind.SEGMENT:
        return target.split("/", 1)[0]
    if kind is TargetKind.CLIENT:
        mac = target.split("/", 1)[1]
        client = next((c for c in net.clients if c.mac == mac), None)
        source = client.source.device_id if client and client.source else ""
        target = (client.seen_on if client else None) or source
    for dev in sorted(net.devices, key=lambda d: -len(d.id)):
        if target == dev.id or target.startswith(f"{dev.id}/"):
            return dev.site_id
    return None


def export(net: Network, notes: Iterable[Annotation], acks: Iterable[Acknowledgement]) -> str:
    """Stored annotations and acknowledgements as desired-state YAML, to move them into git.

    Objects of no known site go to the first site (or ``default``).
    """
    fallback = net.sites[0].id if net.sites else "default"
    sites: dict[str, dict[str, list[dict[str, Any]]]] = {}

    def site_of(target: str | None) -> dict[str, list[dict[str, Any]]]:
        site = (target_site(net, target) if target else None) or fallback
        return sites.setdefault(site, {})

    for a in notes:
        if a.source is AnnotationSource.DECLARED:
            continue
        data = a.model_dump(
            mode="json", exclude={"source", "updated_at"}, exclude_none=True, exclude_defaults=True
        )
        data["target"] = a.target
        if a.expected.model_dump(exclude_none=True):
            data["expected"] = a.expected.model_dump(mode="json", exclude_none=True)
        site_of(a.target).setdefault("annotations", []).append(data)
    for ack in acks:
        if ack.source is AnnotationSource.DECLARED:
            continue
        raw = {
            "rule": ack.rule_id,
            "finding": ack.finding_id,
            "target": ack.target,
            "reason": ack.reason,
            "by": ack.by,
            "at": ack.at.isoformat() if ack.at else None,
            "until": ack.until.isoformat() if ack.until else None,
            "fingerprint": ack.fingerprint,
        }
        entry = {k: v for k, v in raw.items() if v is not None}
        site_of(ack.target).setdefault("acknowledgements", []).append(entry)
    if not sites:
        return ""
    return yaml.safe_dump({"sites": sites}, sort_keys=False, allow_unicode=True)
