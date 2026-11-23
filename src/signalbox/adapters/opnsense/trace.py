"""Traceroute through the OPNsense diagnostics API (#253).

``POST /api/diagnostics/traceroute/set`` with ``{"traceroute": {"settings": {hostname, ipproto,
protocol, source_address}}}`` validates the settings and runs configd's ``interface
traceroute`` (``/usr/local/opnsense/scripts/interfaces/traceroute.py``: ``traceroute -a -w 2
-q 1`` with ``-I`` for ICMP, 20 s at most) and answers ``{"result": "ok", "response": {"rows":
[{ttl, AS, host, address, probes}], "error"?, "notice"?}}`` (opnsense/core,
``Diagnostics/Api/TracerouteController.php``). The privilege is *Diagnostics: Traceroute*
(``page-diagnostics-traceroute``: ``api/diagnostics/traceroute/*``). The script leaves out the
lines of hops that did not answer (``2  *``): their TTLs are filled in as unanswered hops.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from signalbox.adapters import AdapterError, TraceAnswer
from signalbox.model import TraceHop

TRACEROUTE = "/api/diagnostics/traceroute/set"
PRIVILEGE = "page-diagnostics-traceroute"
_RTT = re.compile(r"(\d+(?:\.\d+)?)\s*ms")


def request_body(target: IPv4Address | IPv6Address) -> dict[str, Any]:
    return {
        "traceroute": {
            "settings": {
                "hostname": str(target),
                "ipproto": "inet6" if target.version == 6 else "inet",
                "protocol": "icmp",
                "source_address": "",
            }
        }
    }


def _address(row: dict[str, Any]) -> IPv4Address | IPv6Address | None:
    for key in ("address", "host"):
        text = str(row.get(key) or "").strip().strip("()")
        try:
            return ip_address(text)
        except ValueError:
            continue
    return None


def parse(answer: Any, target: IPv4Address | IPv6Address, max_hops: int) -> TraceAnswer:
    if not isinstance(answer, dict):
        raise AdapterError(f"{TRACEROUTE}: unexpected answer")
    if answer.get("result") == "failed":
        detail = answer.get("validations") or {}
        raise AdapterError(f"{TRACEROUTE}: the firewall refused the trace ({detail})")
    response = answer.get("response")
    if not isinstance(response, dict):
        raise AdapterError(f"{TRACEROUTE}: no traceroute result (is configd running?)")
    rows = response.get("rows")
    if not isinstance(rows, list):
        raise AdapterError(f"{TRACEROUTE}: unexpected answer")
    found: dict[int, TraceHop] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            ttl = int(str(row.get("ttl", "")).strip())
        except ValueError:
            continue
        if not 1 <= ttl <= max_hops or ttl in found:
            continue  # a second probe line of the same TTL: the first answer counts
        rtt = _RTT.search(str(row.get("probes") or ""))
        found[ttl] = TraceHop(
            ttl=ttl, address=_address(row), rtt_ms=float(rtt.group(1)) if rtt else None
        )
    if not found:
        if response.get("error"):
            raise AdapterError(f"traceroute on the firewall: {response['error']}")
        return TraceAnswer()
    hops = [found.get(t, TraceHop(ttl=t)) for t in range(1, max(found) + 1)]
    return TraceAnswer(hops=hops, reached=hops[-1].address == target)
