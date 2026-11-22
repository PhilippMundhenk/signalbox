"""Observation history (component "history", issue #185).

The runner records, after every observation round, what it saw: per device its status (and when
it last answered), per client MAC address its network, per client and network when it was seen
there, and per port whether the link was up. Value changes are kept as events. The store keeps
this for ``history.days`` and gives rules a read-only :class:`History`.

Rules that need the past are written with :func:`signalbox.rules.history_rule` and receive the
history as a second argument. Rules evaluated on the desired or the predicted state of a plan get
:meth:`History.empty` and stay silent. Client sightings are a presence log of the people in a
household: they are never exported (MQTT) and are deleted after ``history.days``.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import Field

from signalbox.model import DeviceStatus, Model, Network, PortKind

#: Statuses in which a device answered (it was read, perhaps not completely).
ANSWERED = frozenset({DeviceStatus.OK, DeviceStatus.PARTIAL})

#: Sighting kinds in the store.
DEVICE, CLIENT, CLIENT_SEGMENT, PORT = "device", "client", "client-segment", "port"


class StatusChange(Model):
    at: datetime
    old: DeviceStatus
    new: DeviceStatus


class DeviceHistory(Model):
    first_seen: datetime
    #: Last observation round that included the device (in any status).
    last_seen: datetime
    #: Last time the device answered (status ok or partial); None if it never did.
    last_ok: datetime | None = None
    status: DeviceStatus
    #: When the device entered its current status.
    status_since: datetime
    changes: list[StatusChange] = Field(default_factory=list)

    def outages(self, since: datetime) -> int:
        """How often the device stopped answering since ``since``."""
        return sum(
            1 for c in self.changes if c.at >= since and c.old in ANSWERED and c.new not in ANSWERED
        )


class SegmentSighting(Model):
    segment_id: str
    first_seen: datetime
    last_seen: datetime


class SegmentChange(Model):
    at: datetime
    old: str
    new: str


class ClientHistory(Model):
    mac: str
    first_seen: datetime
    last_seen: datetime
    #: The last network the client was seen on (None if never known).
    segment_id: str | None = None
    segments: list[SegmentSighting] = Field(default_factory=list)
    moves: list[SegmentChange] = Field(default_factory=list)


class LinkChange(Model):
    at: datetime
    up: bool


class PortHistory(Model):
    first_seen: datetime
    last_seen: datetime
    up: bool
    #: When the link entered its current state (the last change, or the first sighting).
    since: datetime
    changes: list[LinkChange] = Field(default_factory=list)

    def downs(self, since: datetime) -> int:
        """How often the link went down since ``since``."""
        return sum(1 for c in self.changes if c.at >= since and not c.up)


class History(Model):
    """What Signalbox observed before, as far back as the retention allows."""

    #: The time of the evaluation: rules compare against this, never against the clock.
    now: datetime | None = None
    #: First recorded observation round (None: no history yet).
    since: datetime | None = None
    #: Number of recorded observation rounds.
    observations: int = 0
    #: Retention in days: sightings and changes older than this are deleted.
    days: int = 30
    devices: dict[str, DeviceHistory] = Field(default_factory=dict)
    #: By MAC address.
    clients: dict[str, ClientHistory] = Field(default_factory=dict)
    ports: dict[str, PortHistory] = Field(default_factory=dict)

    @classmethod
    def empty(cls) -> History:
        return cls()

    @property
    def covered_since(self) -> datetime | None:
        """From when on the history is complete: the first round, at most ``days`` ago."""
        if self.since is None or self.now is None:
            return None
        return max(self.since, self.now - timedelta(days=self.days))

    def covers(self, period: timedelta) -> bool:
        """True when the history reaches back at least ``period`` without gaps by retention."""
        start = self.covered_since
        return start is not None and self.now is not None and self.now - start >= period


def observed_values(net: Network) -> dict[tuple[str, str], str | None]:
    """What one round saw, as ``(kind, key) -> value`` for the store.

    A value of None records the sighting but keeps the stored value (a client whose network is
    unknown this round). Client networks are only trusted when every device answered and no
    device failed to report its clients: otherwise a client could seem to move because the
    device that knew it better was missing.
    """
    out: dict[tuple[str, str], str | None] = {}
    for dev_id, status in net.statuses.items():
        out[(DEVICE, dev_id)] = status.value
    reliable = all(s in ANSWERED for s in net.statuses.values()) and not any(
        e.capability == "clients" for e in net.errors
    )
    for client in net.clients:
        out[(CLIENT, client.mac)] = client.segment_id if reliable else None
        if client.segment_id is not None:
            out[(CLIENT_SEGMENT, f"{client.mac} {client.segment_id}")] = None
    for port in net.ports:
        if port.up is not None and port.kind in (PortKind.ETHERNET, PortKind.LAG):
            out[(PORT, port.id)] = "up" if port.up else "down"
    return out
