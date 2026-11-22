"""Discovery probe of the Omada controller (#203), without credentials.

``GET https://<host>:8043/api/info`` (software controller), then ``https://<host>/api/info``
(OC200/OC300): the controller answers without login with ``errorCode 0`` and a result that
holds ``omadacId`` and ``controllerVer``. Both are needed for a candidate; the version is shown.
"""

from __future__ import annotations

from signalbox.discovery import Candidate, HostProbe
from signalbox.model import DeviceRole

INFO = "/api/info"


async def discover(probe: HostProbe) -> Candidate | None:
    for port in (probe.port("omada.https", 8043), probe.port("omada.hardware", 443)):
        answer = await probe.get("https", port, INFO)
        data = answer.json() if answer is not None and answer.status == 200 else None
        if not isinstance(data, dict) or data.get("errorCode") != 0:
            continue
        info = data.get("result")
        if not isinstance(info, dict) or not info.get("omadacId"):
            continue
        version = info.get("controllerVer")
        return Candidate(
            address=probe.host,
            role=DeviceRole.OTHER,
            config={"url": probe.origin("https", port)},
            vendor="TP-Link",
            model="Omada Controller",
            name="Omada Controller",
            firmware=version if isinstance(version, str) else None,
            evidence=f"Omada controller information on https port {port}",
            note="Create an Open API client (viewer role) in the controller first.",
        )
    return None
