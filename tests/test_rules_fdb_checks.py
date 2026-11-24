"""MAC address table rules (#298) and the FDB data in #85, #112, #113."""

from __future__ import annotations

from datetime import timedelta
from itertools import pairwise
from typing import Any

from factories import SITE, T0, client, device, port
from signalbox.adapters import Capability
from signalbox.fdb import fdb_access_ports
from signalbox.model import (
    FDB_LIMIT,
    DeviceRole,
    DeviceStatus,
    FdbEntry,
    FdbKind,
    Network,
    PortKind,
    fdb_id,
    port_id,
)
from signalbox.rules import evaluate
from signalbox.rules.fdb_checks import mac_flapping, static_stale, table_full
from signalbox.sightings import (
    FDB,
    ClientHistory,
    History,
    ValueChange,
    ValueHistory,
    observed_values,
)

M1, M2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def entry(dev: str, name: str, mac: str, kind: FdbKind = FdbKind.DYNAMIC, **kw: Any) -> FdbEntry:
    return FdbEntry(
        id=fdb_id(dev, name, mac),
        device_id=dev,
        port_id=port_id(dev, name),
        mac=mac,
        kind=kind,
        **kw,
    )


def base(*entries: FdbEntry, clients: list[Any] | None = None) -> Network:
    devs = [
        device("sw1", DeviceRole.SWITCH, capabilities={Capability.CLIENTS}),
        device("sw2", DeviceRole.SWITCH),
    ]
    ports = [port(d, n) for d in ("sw1", "sw2") for n in ("1", "2")]
    return Network(
        sites=[SITE],
        devices=devs,
        ports=ports,
        fdb=list(entries),
        clients=clients or [],
        statuses={"sw1": DeviceStatus.OK, "sw2": DeviceStatus.OK},
    )


def hist(mac: str, *ports: str, hours: float = 1, **kw: Any) -> History:
    ch = [
        ValueChange(at=T0 - timedelta(hours=hours) + timedelta(minutes=i), old=a, new=b)
        for i, (a, b) in enumerate(pairwise(ports))
    ]
    return History(
        now=T0,
        since=T0 - timedelta(days=40),
        observations=100,
        fdb={
            mac: ValueHistory(
                first_seen=T0 - timedelta(days=1),
                last_seen=T0,
                value=ports[-1],
                since=T0,
                changes=ch,
            )
        },
        **kw,
    )


P = [port_id("sw1", "1"), port_id("sw2", "1")]


def test_flapping_found_and_quiet() -> None:
    n = base(entry("sw1", "1", M1))
    (f,) = evaluate(n, [mac_flapping], None, hist(M1, P[0], P[1], P[0], P[1]))
    assert "moved 3 times" in f.message and f.rule_id == "mac.flapping"
    assert evaluate(n, [mac_flapping], None, hist(M1, P[0], P[1])) == []  # one move
    assert evaluate(n, [mac_flapping], None, hist(M1, P[0], P[1], P[0], P[1], hours=30)) == []
    assert evaluate(n, [mac_flapping], None, History.empty()) == []
    assert evaluate(base(), [mac_flapping], None, hist(M1, P[0], P[1], P[0], P[1])) == []


def test_flapping_ignores_wireless_and_uplinks() -> None:
    n = base(entry("sw1", "1", M1))
    wifi = n.model_copy(update={"ports": [port("sw1", "1", kind=PortKind.WIRELESS), *n.ports[1:]]})
    assert fdb_access_ports(wifi) == {}
    both = base(
        entry("sw1", "1", M1), entry("sw2", "1", M1), entry("sw2", "2", "02:00:00:00:00:09")
    )
    assert M1 in fdb_access_ports(both)


def test_static_stale() -> None:
    n = base(entry("sw1", "1", M1, FdbKind.STATIC))
    old = History(
        now=T0,
        since=T0 - timedelta(days=40),
        observations=9,
        clients={
            M1: ClientHistory(
                mac=M1, first_seen=T0 - timedelta(days=40), last_seen=T0 - timedelta(days=20)
            )
        },
    )
    (f,) = evaluate(n, [static_stale], None, old)
    assert "since" in f.message
    never = History(now=T0, since=T0 - timedelta(days=20), observations=9)
    assert len(evaluate(n, [static_stale], None, never)) == 1
    assert evaluate(n, [static_stale], None, History(now=T0, since=T0, observations=1)) == []
    recent = old.model_copy(
        update={
            "clients": {
                M1: old.clients[M1].model_copy(update={"last_seen": T0 - timedelta(days=2)})
            }
        }
    )
    assert evaluate(n, [static_stale], None, recent) == []
    assert evaluate(n, [static_stale], None, History.empty()) == []
    present = base(entry("sw1", "1", M1, FdbKind.STATIC), clients=[client(M1)])
    assert evaluate(present, [static_stale], None, old) == []
    dyn = base(entry("sw1", "1", M1))
    assert evaluate(dyn, [static_stale], None, old) == []
    own = base(entry("sw1", "1", M1, FdbKind.STATIC), entry("sw1", "2", M1, FdbKind.SELF))
    assert evaluate(own, [static_stale], None, old) == []
    nosite = n.model_copy(
        update={"devices": [d.model_copy(update={"capabilities": set()}) for d in n.devices]}
    )
    assert evaluate(nosite, [static_stale], None, old) == []


def test_table_full() -> None:
    full = [entry("sw1", "1", f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}") for i in range(FDB_LIMIT)]
    (f,) = evaluate(base(*full), [table_full], None)
    assert f.rule_id == "mac.table-full" and str(FDB_LIMIT) in f.message
    near = full[: FDB_LIMIT * 9 // 10]
    assert len(evaluate(base(*near), [table_full], None)) == 1
    assert evaluate(base(*full[: FDB_LIMIT // 2]), [table_full], None) == []
    assert evaluate(base(), [table_full], None) == []


def test_history_records_access_port() -> None:
    n = base(entry("sw1", "1", M1), entry("sw1", "2", M2))
    seen = observed_values(n)
    assert seen[(FDB, M1)] == P[0]
    assert (
        observed_values(
            base(entry("sw1", "1", M1)).model_copy(
                update={"statuses": {"sw1": DeviceStatus.UNREACHABLE}}
            )
        )[(FDB, M1)]
        is None
    )
