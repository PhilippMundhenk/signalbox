"""Traceroute through the RouterOS REST API (#253).

``POST /rest/tool/traceroute`` with ``{"address", "count": "1", "max-hops", "timeout",
"use-dns": "no"}`` runs the console command ``/tool/traceroute`` once and answers its table:
one row per hop (``address``, ``loss``, ``sent``, ``last``, ``avg``, ``best``, ``worst``,
``status``), as several ``.section`` s when the tool printed more than one round (the last one
counts). The group needs the policy ``test`` (RouterOS: "ping, traceroute, bandwidth test");
without it RouterOS answers HTTP 500 ``not enough permissions``.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from signalbox.adapters import AdapterError, TraceAnswer
from signalbox.model import TraceHop

TRACEROUTE = "/rest/tool/traceroute"
_TIME = re.compile(r"(\d+(?:\.\d+)?)(ms|us)")


def request_body(target: IPv4Address | IPv6Address, max_hops: int, wait: float) -> dict[str, str]:
    millis = max(100, int(wait * 1000))
    return {
        "address": str(target),
        "count": "1",
        "max-hops": str(max_hops),
        "timeout": f"{millis}ms",
        "use-dns": "no",
    }


def _rtt(value: Any) -> float | None:
    """``last``: ``1.2ms``, ``850us``, ``1ms200us``; None for none."""
    total, found = 0.0, False
    for number, unit in _TIME.findall(str(value or "")):
        total += float(number) / (1000 if unit == "us" else 1)
        found = True
    return round(total, 3) if found else None


def parse(answer: Any, target: IPv4Address | IPv6Address, max_hops: int) -> TraceAnswer:
    if not isinstance(answer, list):
        raise AdapterError(
            f"{TRACEROUTE}: unexpected answer",
            message_id="transport.unexpectedShort",
            params={"endpoint": TRACEROUTE},
        )
    rows = [r for r in answer if isinstance(r, dict)]
    sections = [str(r.get(".section", "")) for r in rows]
    if sections and any(sections):
        last = sections[-1]
        rows = [r for r, s in zip(rows, sections, strict=True) if s == last]
    hops = []
    for ttl, row in enumerate(rows[:max_hops], start=1):
        try:
            address = ip_address(str(row.get("address") or "").strip())
        except ValueError:
            address = None
        hops.append(
            TraceHop(ttl=ttl, address=address, rtt_ms=_rtt(row.get("last")) if address else None)
        )
    reached = any(h.address == target for h in hops)
    if reached:
        hops = hops[: next(i for i, h in enumerate(hops) if h.address == target) + 1]
    else:
        while hops and hops[-1].address is None:
            hops.pop()
    return TraceAnswer(hops=hops, reached=reached)
