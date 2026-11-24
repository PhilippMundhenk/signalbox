"""Discovery probe of Pi-hole v6 (#314), without credentials.

1. ``GET /api/info/login`` over ``https`` (443), then plain ``http`` (80): Pi-hole v6 answers
   it without a session with JSON that has a boolean ``dns``. Public API description; the exact
   answer needs a real device (#21).
2. Otherwise ``GET /admin/`` (Pi-hole's page, v5 and v6): ``Pi-hole`` in the page. The
   candidate then says that Signalbox needs v6.

The candidate's URL is always https (the adapter's default); Pi-hole's own https port is used
when the plain http answer names a valid one.
"""

from __future__ import annotations

from signalbox.discovery import Candidate, HostProbe
from signalbox.model import DeviceRole

LOGIN_INFO = "/api/info/login"
ADMIN = "/admin/"
V6 = "Create an app password first (Settings > Web interface / API); Pi-hole v6 is needed."
V6_UNSURE = (
    "The page does not tell the version: Pi-hole v6 needs the app password, Pi-hole v5 the API "
    "token (Settings > API > Show API token)."
)


def _candidate(probe: HostProbe, port: int, evidence: str, note: str) -> Candidate:
    return Candidate(
        address=probe.host,
        role=DeviceRole.OTHER,
        config={"url": probe.origin("https", port)},
        vendor="Pi-hole",
        model="Pi-hole",
        name="Pi-hole",
        evidence=evidence,
        note=note,
    )


async def discover(probe: HostProbe) -> Candidate | None:
    https = probe.port("pihole.https", 443)
    http = probe.port("pihole.http", 80)
    for scheme, port in (("https", https), ("http", http)):
        answer = await probe.get(scheme, port, LOGIN_INFO)
        data = answer.json() if answer is not None and answer.status == 200 else None
        if isinstance(data, dict) and isinstance(data.get("dns"), bool):
            shown = https if scheme == "http" else port
            tls = data.get("https_port")
            if scheme == "http" and isinstance(tls, int) and 1 <= tls <= 65535:
                shown = tls
            return _candidate(probe, shown, f"Pi-hole API on {scheme} port {port}", V6)
    for scheme, port in (("https", https), ("http", http)):
        page = await probe.get(scheme, port, ADMIN)
        if page is not None and page.status == 200 and "pi-hole" in page.text().lower():
            return _candidate(probe, https, f"Pi-hole page on {scheme} port {port}", V6_UNSURE)
    return None
