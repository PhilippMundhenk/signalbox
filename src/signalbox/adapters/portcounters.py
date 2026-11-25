"""Shared helpers of the adapters that read port counters (#158).

Adapters return the totals as the device reports them; the read time is stamped by the
framework and the deltas are computed in the core (:mod:`signalbox.counters`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from signalbox.model import COUNTER_FIELDS, PortCounters


def count(value: object) -> int | None:
    """A counter value: an int, or a number as text (RouterOS, sysfs); None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 else None
    if isinstance(value, str):
        text = value.strip()
        return int(text) if text.isdigit() else None
    return None


def counters_of(
    raw: Mapping[str, Any], names: Mapping[str, str | Sequence[str]]
) -> PortCounters | None:
    """The counters from a device's mapping: ``names`` maps a model field to the device's key
    (or to several keys, of which the first one present wins, for other software versions).
    None when the device reports none of them."""
    values: dict[str, int] = {}
    for field, keys in names.items():
        if field not in COUNTER_FIELDS:
            raise ValueError(field)
        for key in (keys,) if isinstance(keys, str) else keys:
            number = count(raw.get(key))
            if number is not None:
                values[field] = number
                break
    return PortCounters(**values) if values else None
