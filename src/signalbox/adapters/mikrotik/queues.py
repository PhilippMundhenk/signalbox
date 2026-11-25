"""MikroTik queues (#166): ``/queue/simple``, ``/queue/tree`` and ``/queue/type``.

- ``/rest/queue/type``: ``name``, ``kind`` (``pfifo``, ``bfifo``, ``red``, ``sfq``, ``pcq``,
  ``fq-codel``, ``cake``, ``mq-pfifo``; ``cake`` and ``fq-codel`` need RouterOS 7.1 and later).
- ``/rest/queue/simple``: ``name``, ``target`` (addresses, networks or interfaces, comma
  separated), ``max-limit`` (``upload/download``, bit/s or ``100M``), ``queue`` (the type per
  direction, ``cake-default/cake-default``), ``disabled``, ``dynamic``.
- ``/rest/queue/tree``: ``name``, ``parent`` (an interface, ``global`` or another queue),
  ``max-limit`` (one value, the direction of the parent), ``queue`` (the type), ``disabled``.

A simple queue whose target is an interface of the WAN list is read from that interface's side:
the first value of ``max-limit`` is what the interface sends in (our download), the second what
leaves on it (our upload). A queue for a network or an address is read from the client's side
(upload first). A tree queue with a
WAN interface as parent limits what leaves on it (the upload), with any other interface as parent
what leaves towards the LAN (the download); a child of another queue is not an interface shaper.
Dynamic queues (hotspot, PPP) and queues of ``0`` (unlimited) report no rate. RouterOS 6.49 and
7.x have the menus; the type kinds ``cake`` and ``fq-codel`` exist from 7.1 (6.49 reports plain
types only). All of this is a *guess* until seen on a device (#21).
"""

from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from signalbox.adapters.shaping import kbps, kind_of, uplink_for
from signalbox.model import IPNetwork, Shaper, ShaperKind, Uplink, object_id

SIMPLE = "/rest/queue/simple"
TREE = "/rest/queue/tree"
TYPES = "/rest/queue/type"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _yes(value: Any) -> bool:
    return _text(value).lower() in ("yes", "true")


def _kind(types: dict[str, str], queue: str) -> ShaperKind:
    """The kind of the type named by a ``queue`` value (``a/b``: the first that is not plain)."""
    kinds = [kind_of(types.get(n.strip(), n.strip())) for n in queue.split("/") if n.strip()]
    for k in kinds:
        if k is not ShaperKind.OTHER:
            return k
    return ShaperKind.SIMPLE_QUEUE


def _networks(target: str) -> tuple[list[IPNetwork], list[str]]:
    nets: list[IPNetwork] = []
    names: list[str] = []
    for part in (p.strip() for p in target.split(",")):
        if not part:
            continue
        try:
            nets.append(ip_network(part, strict=False))
        except ValueError:
            names.append(part)
    return nets, names


def shapers(
    device_id: str,
    types: list[dict[str, Any]],
    simple: list[dict[str, Any]],
    tree: list[dict[str, Any]],
    uplinks: list[Uplink],
    wan: set[str],
) -> list[Shaper]:
    """One shaper per static queue. ``wan``: the interfaces of the WAN list."""
    by_type = {_text(t.get("name")): _text(t.get("kind")) for t in types}
    out: list[Shaper] = []
    seen: set[str] = set()

    def key(base: str, n: int) -> str:
        k = base or str(n)
        if k in seen:
            k = f"{k}-{n}"
        seen.add(k)
        return k

    for n, q in enumerate(simple):
        if _yes(q.get("dynamic")):
            continue
        name = _text(q.get("name"))
        nets, names = _networks(_text(q.get("target")))
        first, _, second = _text(q.get("max-limit")).partition("/")
        a, b = kbps(first), kbps(second)
        wan_names = [i for i in names if i in wan]
        upload, download = (b, a) if wan_names else (a, b)
        if nets and wan_names:  # mixed targets: not one shaper of one direction
            continue
        iface = wan_names[0] if wan_names else (names[0] if names else None)
        up = uplink_for(uplinks, iface)
        out.append(
            Shaper(
                id=object_id(device_id, "shaper", f"simple-{key(name, n)}"),
                device_id=device_id,
                name=name or f"simple queue {n + 1}",
                kind=_kind(by_type, _text(q.get("queue"))),
                interface=iface,
                uplink_id=up.id if up else None,
                download_kbps=download,
                upload_kbps=upload,
                enabled=not _yes(q.get("disabled")),
                addresses=nets,
            )
        )
    queue_names = {_text(q.get("name")) for q in tree}
    for n, q in enumerate(tree):
        parent = _text(q.get("parent"))
        if _yes(q.get("dynamic")) or not parent or parent == "global" or parent in queue_names:
            continue
        rate = kbps(q.get("max-limit"))
        name = _text(q.get("name"))
        on_wan = parent in wan
        out.append(
            Shaper(
                id=object_id(device_id, "shaper", f"tree-{key(name, n)}"),
                device_id=device_id,
                name=name or f"queue tree {n + 1}",
                kind=_kind(by_type, _text(q.get("queue"))),
                interface=parent,
                uplink_id=(up.id if (up := uplink_for(uplinks, parent)) else None),
                download_kbps=None if on_wan else rate,
                upload_kbps=rate if on_wan else None,
                enabled=not _yes(q.get("disabled")),
            )
        )
    return out
