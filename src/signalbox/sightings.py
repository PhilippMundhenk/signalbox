"""Observation history (component "history", issue #185).

The runner records, after every observation round, what it saw: per device its status (and when
it last answered), per client MAC address its network, per client and network when it was seen
there, per port whether the link was up, and per device its boot time and whether its CPU load
was high (issues #130, #131). Value changes are kept as events. The store keeps
this for ``history.days`` and gives rules a read-only :class:`History`.

Rules that need the past are written with :func:`signalbox.rules.history_rule` and receive the
history as a second argument. Rules evaluated on the desired or the predicted state of a plan get
:meth:`History.empty` and stay silent. Client sightings are a presence log of the people in a
household: they are never exported (MQTT) and are deleted after ``history.days``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import Field

from signalbox.counters import CounterRecord
from signalbox.fdb import fdb_access_ports, managed_sightings
from signalbox.model import Client, DeviceStatus, Model, Network, PortKind

#: Statuses in which a device answered (it was read, perhaps not completely).
ANSWERED = frozenset({DeviceStatus.OK, DeviceStatus.PARTIAL})

#: Sighting kinds in the store.
DEVICE, CLIENT, CLIENT_SEGMENT, PORT = "device", "client", "client-segment", "port"
#: Per device: its boot time rounded to the minute and the reboot reason (``BOOT``), and
#: whether its CPU load was high (``CPU``, see :data:`CPU_HIGH_PCT`).
BOOT, CPU = "boot", "cpu"
#: Per device: its serial number and its base MAC address (``device.replaced``, #427). Recorded
#: only in a round that reports them, so a read that lacks the field keeps the stored value.
SERIAL, BASE_MAC = "serial", "base-mac"
#: Per gateway group: the member that carries the traffic (``wan.on-backup``, failover counts,
#: #150). A change is a failover or a failback.
GATEWAY = "gateway"
#: Per MAC address: the access port its device-table entries put it behind (``mac.flapping``,
#: #298), as the id of the port.
FDB = "fdb"
#: Per port and MAC address of a managed device: it was seen there (``<port id> <mac>``, the
#: value is the :class:`~signalbox.model.EvidenceSource`), for the link inference (#378).
MAC_PORT = "mac-port"
#: Per port: its last counters and their delta to the read before (a JSON value, #158). Only the
#: last value is kept: no change log.
COUNTERS = "counters"
#: How long such a sighting still counts after it was last seen.
MAC_HOLD = timedelta(hours=24)
#: Kinds whose key is a device id (deleted with the device).
DEVICE_KINDS = (DEVICE, PORT, BOOT, CPU, SERIAL, BASE_MAC, MAC_PORT, COUNTERS, GATEWAY)
#: Kinds whose value changes with every round: the changes are not logged.
UNLOGGED_KINDS = (COUNTERS,)
#: CPU load (percent) from which an observation counts as high for ``device.resources``.
CPU_HIGH_PCT = 90.0


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


class ValueChange(Model):
    at: datetime
    old: str
    new: str


class ValueHistory(Model):
    """A value recorded per round (a boot time, a CPU state) and its changes."""

    first_seen: datetime
    last_seen: datetime
    value: str | None = None
    #: When the value was first seen with its current value.
    since: datetime
    changes: list[ValueChange] = Field(default_factory=list)


def boot_value(boot_time: datetime, reason: str | None) -> str:
    """``2026-01-12T12:00:00+00:00 power``: the boot time rounded to the minute and the reason.

    A boot time derived from the uptime jitters by about a second per round; rounding keeps it
    stable (a change of one minute at a rounding boundary is ignored by ``device.reboot``).
    """
    minute = (boot_time.astimezone(UTC) + timedelta(seconds=30)).replace(second=0, microsecond=0)
    return f"{minute.isoformat()} {reason or '-'}"


def parse_boot(value: str) -> tuple[datetime, str | None]:
    """The boot time and the reason (None: not reported) of :func:`boot_value`."""
    stamp, _, reason = value.partition(" ")
    return datetime.fromisoformat(stamp), None if reason in ("", "-") else reason


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
    #: By device id: boot times (``boot_value``) and whether the CPU load was high.
    boots: dict[str, ValueHistory] = Field(default_factory=dict)
    cpu: dict[str, ValueHistory] = Field(default_factory=dict)
    #: By device id: the serial number and the base MAC address it reported (#427).
    serials: dict[str, ValueHistory] = Field(default_factory=dict)
    base_macs: dict[str, ValueHistory] = Field(default_factory=dict)
    #: By gateway group id: the member that carried the traffic and when it changed (#150).
    gateway_actives: dict[str, ValueHistory] = Field(default_factory=dict)
    #: By MAC address: the access port its MAC address table entries put it behind.
    fdb: dict[str, ValueHistory] = Field(default_factory=dict)
    #: By port id: the last counters and the delta to the read before (#158).
    counters: dict[str, CounterRecord] = Field(default_factory=dict)

    @classmethod
    def empty(cls) -> History:
        return cls()

    def failovers(self, group_id: str, since: datetime) -> int:
        """How often the member that carries a gateway group's traffic changed since ``since``
        (a failover or a failback; 0 where nothing is recorded)."""
        value = self.gateway_actives.get(group_id)
        return 0 if value is None else sum(1 for c in value.changes if c.at >= since)

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


def client_segment(net: Network, client: Client) -> str | None:
    """A client's network: as reported, else the one its switches learned it in (#85)."""
    if client.segment_id is not None:
        return client.segment_id
    learned = {e.segment_id for e in net.fdb_of(client.mac) if e.segment_id is not None}
    return next(iter(learned)) if len(learned) == 1 else None


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
        segment = client_segment(net, client)
        out[(CLIENT, client.mac)] = segment if reliable else None
        if segment is not None:
            out[(CLIENT_SEGMENT, f"{client.mac} {segment}")] = None
    if net.fdb:
        fdb_ok = reliable and not any(e.optional for e in net.errors)
        for mac, port_id in fdb_access_ports(net).items():
            out[(FDB, mac)] = port_id if fdb_ok else None
    for port_id, mac, source in managed_sightings(net):
        out[(MAC_PORT, f"{port_id} {mac}")] = source.value
    for port in net.ports:
        if port.up is not None and port.kind in (PortKind.ETHERNET, PortKind.LAG):
            out[(PORT, port.id)] = "up" if port.up else "down"
    for port in net.ports:
        if port.counters is not None and port.counters.has_values():
            out[(COUNTERS, port.id)] = port.counters.model_dump_json(exclude_none=True)
    for dev in net.devices:
        if net.statuses.get(dev.id, DeviceStatus.OK) in ANSWERED:
            if dev.serial:
                out[(SERIAL, dev.id)] = dev.serial
            if dev.mac:
                out[(BASE_MAC, dev.id)] = dev.mac
    for group in net.gateway_groups:
        if (
            group.active is not None
            and net.statuses.get(group.device_id, DeviceStatus.OK) in ANSWERED
        ):
            out[(GATEWAY, group.id)] = group.active
    for dev in net.devices:
        h = dev.health
        if h is None or net.statuses.get(dev.id, DeviceStatus.OK) not in ANSWERED:
            continue
        if h.boot_time is not None:
            reason = h.last_reboot_reason.value if h.last_reboot_reason else None
            out[(BOOT, dev.id)] = boot_value(h.boot_time, reason)
        if h.cpu_load_pct is not None:
            out[(CPU, dev.id)] = "high" if h.cpu_load_pct >= CPU_HIGH_PCT else "ok"
    return out
