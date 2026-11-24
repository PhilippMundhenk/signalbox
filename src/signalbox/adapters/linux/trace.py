"""Traceroute on a Linux device over SSH with the read user (#253).

``tracepath`` (iputils, Debian package ``iputils-tracepath``) needs no root: it sends UDP with
``IP_RECVERR``, like Signalbox's own host does. Where it is missing, ``traceroute`` (the
``traceroute`` package or BusyBox) in its default UDP mode, which needs no root either. Numeric
output only (``-n``): the device looks nothing up. The script sends nothing else; with
neither tool installed the trace says so.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv6Address, ip_address

from signalbox.adapters import AdapterError, TraceAnswer
from signalbox.model import TraceHop

MARK = "# signalbox-trace"
INSTALL_FIX = (
    "Install tracepath on the device (Debian, Raspberry Pi OS: apt install iputils-tracepath); "
    "it needs no root."
)
_TRACEPATH = re.compile(r"^\s*(\d+)\??:\s+(\S+)(?:\s+(\d+(?:\.\d+)?)ms)?(.*)$")
_TRACEROUTE = re.compile(r"^\s*(\d+)\s+(\S+)(?:\s+(\d+(?:\.\d+)?)\s*ms)?")


def script(target: IPv4Address | IPv6Address, max_hops: int, wait: float) -> str:
    seconds = max(1, round(wait))
    return f"""{MARK}
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
if command -v tracepath >/dev/null 2>&1; then
  echo @@tracepath
  tracepath -n -m {max_hops} {target} 2>&1
elif command -v traceroute >/dev/null 2>&1; then
  echo @@traceroute
  traceroute -n -q 1 -w {seconds} -m {max_hops} {target} 2>&1
else
  echo @@none
fi
echo @@end
"""


def _ip(text: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(text)
    except ValueError:
        return None


def parse(text: str, target: IPv4Address | IPv6Address, max_hops: int) -> TraceAnswer:
    lines = text.splitlines()
    if "@@end" not in lines:
        raise AdapterError(
            "the device did not finish the traceroute", message_id="linux.traceUnfinished"
        )
    if "@@none" in lines:
        raise AdapterError(
            "neither tracepath nor traceroute is installed",
            fix=INSTALL_FIX,
            message_id="linux.traceNone",
            fix_id="linux.traceNone.fix",
        )
    tool = "tracepath" if "@@tracepath" in lines else "traceroute"
    pattern = _TRACEPATH if tool == "tracepath" else _TRACEROUTE
    found: dict[int, TraceHop] = {}
    reached = False
    for line in lines:
        m = pattern.match(line)
        if m is None or "LOCALHOST" in line:
            continue
        ttl = int(m.group(1))
        if not 1 <= ttl <= max_hops:
            continue
        address = _ip(m.group(2))
        if address is None and ttl in found:
            continue
        if ttl in found and found[ttl].address is not None:
            continue  # tracepath prints a hop again for a second probe: the first counts
        rtt = float(m.group(3)) if m.group(3) and address is not None else None
        found[ttl] = TraceHop(ttl=ttl, address=address, rtt_ms=rtt)
        if address == target or (tool == "tracepath" and "reached" in line):
            reached = True
            break
    if not found:
        detail = " ".join(line.strip() for line in lines if not line.startswith("@@"))[-200:]
        if not detail:
            raise AdapterError(
                f"{tool} on the device printed no hops",
                message_id="linux.traceNoHops",
                params={"tool": tool},
            )
        raise AdapterError(
            f"{tool} on the device printed no hops: {detail}",
            message_id="linux.traceNoHopsDetail",
            params={"tool": tool, "detail": detail},
        )
    hops = [found.get(t, TraceHop(ttl=t)) for t in range(1, max(found) + 1)]
    if not reached:
        while hops and hops[-1].address is None:
            hops.pop()
    return TraceAnswer(hops=hops, reached=reached)
