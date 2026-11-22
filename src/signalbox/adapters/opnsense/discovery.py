"""Discovery probe of OPNsense (#203), without credentials.

``GET https://<host>/``: the web interface answers with its login page. ``OPNsense`` in the page
together with the login form's fields (``usernamefld``/``passwordfld``) makes it a candidate;
pfSense, which shares the field names, does not say OPNsense. The login page tells no model or
version.
"""

from __future__ import annotations

from signalbox.discovery import Candidate, HostProbe
from signalbox.model import DeviceRole

MARKERS = ("usernamefld", "passwordfld")


async def discover(probe: HostProbe) -> Candidate | None:
    port = probe.port("opnsense.https", 443)
    page = await probe.get("https", port, "/")
    if page is None or page.status != 200:
        return None
    text = page.text()
    if "opnsense" not in text.lower() or not any(m in text for m in MARKERS):
        return None
    return Candidate(
        address=probe.host,
        role=DeviceRole.GATEWAY,
        config={"url": probe.origin("https", port)},
        vendor="Deciso",
        name="OPNsense",
        evidence=f"OPNsense login page on https port {port}",
        note="Create an API key for a user with the privileges in the setup guide.",
    )
