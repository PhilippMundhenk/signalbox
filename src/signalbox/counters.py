"""Port counters over time (component "history", issues #158, #115).

Adapters return the totals a device reports (:class:`~signalbox.model.PortCounters`). The core
keeps the last value per port and the delta to the read before it, so a rule or the UI sees what
happened between two reads, not the lifetime totals. A counter that goes down is a reset (a
reboot, a cleared statistic), not a negative number: the delta of that round is unknown. A
32-bit counter that wrapped (it was close to 2**32 and is small now) is counted through.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from signalbox.model import COUNTER_FIELDS, Model, PortCounters

WRAP_32 = 2**32
#: A counter below ``WRAP_32`` that dropped from within this share of the top is a wrap.
WRAP_MARGIN = WRAP_32 // 8
#: Reads further apart than this do not give a rate worth judging (a device that was away).
MAX_GAP_SECONDS = 24 * 3600


class CounterDelta(Model):
    """What a port's counters did between two reads. ``None``: not reported or unknown."""

    seconds: float
    #: The counters went down since the read before (reboot, reset): the deltas are unknown.
    reset: bool = False
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    rx_crc_errors: int | None = None
    rx_drops: int | None = None
    tx_drops: int | None = None
    collisions: int | None = None
    link_downs: int | None = None

    @property
    def packets(self) -> int | None:
        parts = [v for v in (self.rx_packets, self.tx_packets) if v is not None]
        return sum(parts) if parts else None

    @property
    def errors(self) -> int | None:
        """Receive and transmit errors; the CRC errors are part of ``rx_errors`` on most
        devices, so they only count on their own where no error total is reported."""
        parts = [v for v in (self.rx_errors, self.tx_errors) if v is not None]
        if parts:
            return sum(parts)
        return self.rx_crc_errors

    @property
    def drops(self) -> int | None:
        parts = [v for v in (self.rx_drops, self.tx_drops) if v is not None]
        return sum(parts) if parts else None


class CounterRecord(Model):
    """The last reading of a port and its delta to the one before (what the store keeps)."""

    last: PortCounters
    delta: CounterDelta | None = None


class CounterBucket(Model):
    """The traffic of one port in one hour (the series behind #471).

    ``seconds`` is the time the reads in the hour cover (a partial hour has less), so
    ``rx_bytes * 8 / seconds`` is the average rate of the part that was observed.
    """

    at: datetime
    seconds: float
    rx_bytes: int = 0
    tx_bytes: int = 0

    @property
    def rx_bps(self) -> float:
        return self.rx_bytes * 8 / self.seconds if self.seconds > 0 else 0.0

    @property
    def tx_bps(self) -> float:
        return self.tx_bytes * 8 / self.seconds if self.seconds > 0 else 0.0


def bucket_start(at: datetime) -> datetime:
    """The start of the hour (UTC) a read at ``at`` belongs to."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile (``pct`` in 1..100) of a non-empty list."""
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))  # ceil
    return ordered[min(len(ordered), int(rank)) - 1]


def counter_delta(old: PortCounters, new: PortCounters) -> CounterDelta | None:
    """The change from ``old`` to ``new``; None when the reads have no usable time base
    (the same read twice, no timestamps, a gap of more than a day)."""
    if old.read_at is None or new.read_at is None:
        return None
    seconds = (new.read_at - old.read_at).total_seconds()
    if seconds <= 0 or seconds > MAX_GAP_SECONDS:
        return None
    if (
        old.counters_since is not None
        and new.counters_since is not None
        and abs((new.counters_since - old.counters_since).total_seconds()) > 120
    ):
        return CounterDelta(seconds=seconds, reset=True)  # the device says it was reset
    values: dict[str, int | None] = {}
    for name in COUNTER_FIELDS:
        a, b = getattr(old, name), getattr(new, name)
        if a is None or b is None:
            values[name] = None
        elif b >= a:
            values[name] = b - a
        elif a < WRAP_32 and a >= WRAP_32 - WRAP_MARGIN and b < WRAP_MARGIN:
            values[name] = b + WRAP_32 - a  # a 32-bit counter that wrapped
        else:
            return CounterDelta(seconds=seconds, reset=True)
    return CounterDelta(seconds=seconds, **values)


def counter_value(old: str | None, new: PortCounters) -> str | None:
    """The stored value after a read: the new counters and their delta to the stored ones.

    None keeps the stored value: the same read again (a device that did not answer this
    round carries its old snapshot), so the delta of the last real read stays.
    """
    previous = _load(old)
    if previous is not None and (
        new.read_at is None
        or (previous.last.read_at is not None and new.read_at <= previous.last.read_at)
    ):
        return None
    delta = counter_delta(previous.last, new) if previous is not None else None
    return CounterRecord(last=new, delta=delta).model_dump_json(exclude_none=True)


def _load(value: str | None) -> CounterRecord | None:
    if not value:
        return None
    try:
        return CounterRecord.model_validate(json.loads(value))
    except ValueError:
        return None  # a record of another version


def counter_record(value: str | None) -> CounterRecord | None:
    """The record in a stored value."""
    return _load(value)
