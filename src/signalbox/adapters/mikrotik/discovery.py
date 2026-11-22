"""Discovery probe of MikroTik RouterOS (#203), without credentials.

1. ``GET https://<host>/rest/system/resource`` (the ``www-ssl`` service): RouterOS 7 answers a
   request without credentials with ``401`` and ``WWW-Authenticate: Basic realm="RouterOS"``.
   No credentials are sent, so the model is not known yet.
2. Otherwise the same on plain ``http`` (the ``www`` service), then WebFig's page at ``/``
   (title with ``RouterOS``): the candidate then says to switch on ``www-ssl``.
"""

from __future__ import annotations

from signalbox.discovery import Candidate, HostProbe, ProbeResponse
from signalbox.model import DeviceRole

REST = "/rest/system/resource"
WWW_SSL = (
    "Switch on the www-ssl service with a certificate (IP > Services) so that Signalbox can "
    "use the REST API over HTTPS."
)


def _routeros(answer: ProbeResponse | None) -> bool:
    if answer is None or answer.status != 401:
        return False
    return "routeros" in answer.headers.get("www-authenticate", "").lower()


async def discover(probe: HostProbe) -> Candidate | None:
    https = probe.port("mikrotik.https", 443)
    http = probe.port("mikrotik.http", 80)
    found: tuple[str, int, str] | None = None
    if _routeros(await probe.get("https", https, REST)):
        found = ("https", https, "REST API")
    elif _routeros(await probe.get("http", http, REST)):
        found = ("http", http, "REST API")
    else:
        for scheme, port in (("https", https), ("http", http)):
            page = await probe.get(scheme, port, "/")
            if page is not None and page.status == 200 and "routeros" in page.text().lower():
                found = (scheme, port, "WebFig page")
                break
    if found is None:
        return None
    scheme, port, what = found
    rest_over_https = scheme == "https" and what == "REST API"
    return Candidate(
        address=probe.host,
        role=DeviceRole.GATEWAY,
        config={"url": probe.origin("https", https)},
        vendor="MikroTik",
        name="MikroTik",
        evidence=f"RouterOS {what} on {scheme} port {port}",
        note=None if rest_over_https else WWW_SSL,
    )
