"""Discovery probe of AdGuard Home (#314), without credentials.

``GET /control/status`` over ``https`` (port 443), then plain ``http`` on port 3000 (the setup
wizard's and the default web port) and 80. Recognised, per the public API description (guess:
the exact answer of a login-protected instance needs a real device, #21):

- ``200`` with JSON that has ``dns_port`` and ``version`` (AdGuard Home without a login);
- ``401`` with ``WWW-Authenticate: Basic`` whose realm names AdGuard Home.

Nothing else counts: a bare 401 or 403 is too common to name a product. The candidate's URL is
the one that answered; for plain http the note says to tick *Allow plain http* in the form.
"""

from __future__ import annotations

from signalbox.discovery import Candidate, HostProbe, ProbeResponse, clean
from signalbox.model import DeviceRole

STATUS = "/control/status"
PLAIN_HTTP = (
    "This address serves plain http: tick Allow plain http only on a network you trust, or "
    "set up HTTPS in AdGuard Home (Settings > Encryption). Add a user for Signalbox first "
    "(see the setup guide)."
)
LOGIN = "Add a user for Signalbox in AdGuardHome.yaml first (see the setup guide)."


def _info(answer: ProbeResponse | None) -> tuple[bool, str | None]:
    """(is AdGuard Home, version if told)."""
    if answer is None:
        return False, None
    if answer.status == 401:
        realm = answer.headers.get("www-authenticate", "").lower()
        return realm.startswith("basic") and "adguard" in realm, None
    data = answer.json() if answer.status == 200 else None
    if isinstance(data, dict) and isinstance(data.get("dns_port"), int):
        version = data.get("version")
        if isinstance(version, str) and version.strip():
            return True, clean(version.strip().lstrip("v"))
    return False, None


async def discover(probe: HostProbe) -> Candidate | None:
    for scheme, port in (
        ("https", probe.port("adguardhome.https", 443)),
        ("http", probe.port("adguardhome.http", 3000)),
        ("http", probe.port("adguardhome.http80", 80)),
    ):
        found, version = _info(await probe.get(scheme, port, STATUS))
        if not found:
            continue
        return Candidate(
            address=probe.host,
            role=DeviceRole.OTHER,
            config={"url": probe.origin(scheme, port)},
            vendor="AdGuard",
            model="AdGuard Home",
            name="AdGuard Home",
            firmware=version,
            evidence=f"AdGuard Home status on {scheme} port {port}",
            note=PLAIN_HTTP if scheme == "http" else LOGIN,
        )
    return None
