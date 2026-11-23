"""Discovery probe of the Linux integration (#240), without credentials.

Reads the SSH server's identification line (``SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3``),
which it sends before anything else, and sends nothing itself. Only Debian-based systems are
reported (``Debian``, ``Raspbian``, ``Ubuntu`` in the line): Dropbear (OpenWrt), RouterOS and
FreeBSD (OPNsense) are left to their own integrations.
"""

from __future__ import annotations

import re

from signalbox.discovery import Candidate, HostProbe
from signalbox.model import DeviceRole

BANNER = re.compile(r"^SSH-2\.0-OpenSSH_(\S+)\s+(Debian|Raspbian|Ubuntu)\S*", re.I)


async def discover(probe: HostProbe) -> Candidate | None:
    port = probe.port("linux.ssh", 22)
    line = await probe.banner(port)
    match = BANNER.match(line or "")
    if not match:
        return None
    system = {"raspbian": "Raspberry Pi OS", "ubuntu": "Ubuntu"}.get(
        match.group(2).lower(), "Debian"
    )
    return Candidate(
        address=probe.host,
        role=DeviceRole.OTHER,
        config={"host": probe.host, "port": port},
        vendor=system,
        evidence=f"OpenSSH {match.group(1)} on port {port} ({system})",
        note="Needs a login of its own for Signalbox (see the setup guide, or set it up "
        "automatically with root or a sudo user).",
    )
