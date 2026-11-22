"""Discovery probe of the Fritz!Box (#203), without credentials.

1. ``GET http://<host>:49000/tr64desc.xml``: the TR-064 device description every box serves on
   plain HTTP to the home network. AVM as manufacturer (or a model name starting with
   ``FRITZ!``) makes it a candidate; it tells the model and the FRITZ!OS version.
2. ``POST http://<host>:49000/upnp/control/deviceinfo`` ``DeviceInfo:1 GetSecurityPort``: the
   TR-064 HTTPS port, which AVM answers without authentication (as the adapter's
   ``security_port``). The candidate's address is ``https://<host>:<that port>``.

Both answers are parsed with :func:`~signalbox.adapters.fritzbox.soap.parse_xml`, which refuses
DTDs and entities.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from signalbox.adapters import AdapterError
from signalbox.adapters.fritzbox.soap import (
    SERVICES,
    UPNP_PORT,
    envelope,
    parse_answer,
    parse_xml,
)
from signalbox.discovery import Candidate, HostProbe
from signalbox.model import DeviceRole

#: TR-064 over HTTPS when the box does not tell its port.
HTTPS_PORT = 49443


def _text(root: ET.Element, tag: str) -> str | None:
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == tag and element.text and element.text.strip():
            return element.text.strip()
    return None


def _https(host: str, port: int) -> str:
    netloc = f"[{host}]" if ":" in host else host
    return f"https://{netloc}:{port}"


async def discover(probe: HostProbe) -> Candidate | None:
    port = probe.port("fritzbox.upnp", UPNP_PORT)
    answer = await probe.get("http", port, "/tr64desc.xml")
    if answer is None or answer.status != 200 or answer.truncated:
        return None
    try:
        root = parse_xml(answer.body, "tr64desc.xml")
    except AdapterError:
        return None
    manufacturer = _text(root, "manufacturer") or ""
    model = _text(root, "modelName") or _text(root, "friendlyName")
    if "AVM" not in manufacturer.upper() and not (model or "").upper().startswith("FRITZ!"):
        return None
    secure = await _security_port(probe, port)
    return Candidate(
        address=probe.host,
        role=DeviceRole.GATEWAY,
        config={"url": _https(probe.host, secure or HTTPS_PORT)},
        vendor="AVM",
        model=model,
        name=model,
        firmware=_text(root, "Display"),
        evidence=f"TR-064 description on port {port}"
        + (f", TR-064 over HTTPS on port {secure}" if secure else ""),
        note=None
        if secure
        else "The box did not tell its TR-064 HTTPS port: switch on 'Allow access for "
        "applications' (Home Network > Network > Network Settings).",
    )


async def _security_port(probe: HostProbe, port: int) -> int | None:
    service_type, path = SERVICES["DeviceInfo1"]
    answer = await probe.post(
        "http",
        port,
        path,
        content=envelope(service_type, "GetSecurityPort", {}),
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f"{service_type}#GetSecurityPort",
        },
    )
    if answer is None or answer.truncated:
        return None
    try:
        value = int(
            parse_answer(answer.body, "GetSecurityPort", "GetSecurityPort")["NewSecurityPort"]
        )
    except (AdapterError, KeyError, ValueError):
        return None
    return value if 0 < value < 65536 else None
