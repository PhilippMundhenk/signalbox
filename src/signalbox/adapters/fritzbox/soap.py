"""Minimal TR-064 (SOAP over HTTPS) client for the Fritz!Box.

Every action is a ``POST`` to the control URL of its service with a ``SOAPAction`` header
``<service type>#<action>`` and a small envelope::

    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <s:Body><u:GetInfo xmlns:u="urn:dslforum-org:service:DeviceInfo:1"/></s:Body>
    </s:Envelope>

The answer holds ``<u:GetInfoResponse>`` with one element per output argument
(``<NewModelName>``...), or, with HTTP 500, a SOAP fault whose ``<UPnPError>`` carries an
``errorCode`` (401 invalid action, 402 invalid arguments, 606 not authorised, 820 internal
error, ...). Authentication is HTTP Digest; requests go through
:class:`~signalbox.adapters.https.DeviceHttp`, so the certificate is pinned before the first
credential (digest response) leaves the machine.

Answers are parsed with :mod:`xml.etree.ElementTree` only after refusing any document type
declaration or entity: a device answer never needs one, and refusing them rules out entity
expansion attacks.
"""

from __future__ import annotations

import re
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

import httpx

from signalbox.adapters import AdapterError
from signalbox.adapters.https import DeviceHttp

SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP_ENC = "http://schemas.xmlsoap.org/soap/encoding/"
URN = "urn:dslforum-org:service:"

#: service name (as used in this adapter) -> (service type, control URL); from AVM's TR-064
#: documentation (``tr64desc.xml`` of FRITZ!OS 7).
SERVICES: dict[str, tuple[str, str]] = {
    "DeviceInfo1": (f"{URN}DeviceInfo:1", "/upnp/control/deviceinfo"),
    "LANHostConfigManagement1": (
        f"{URN}LANHostConfigManagement:1",
        "/upnp/control/lanhostconfigmgm",
    ),
    "LANEthernetInterfaceConfig1": (
        f"{URN}LANEthernetInterfaceConfig:1",
        "/upnp/control/lanethernetifcfg",
    ),
    "Hosts1": (f"{URN}Hosts:1", "/upnp/control/hosts"),
    **{
        f"WLANConfiguration{n}": (f"{URN}WLANConfiguration:{n}", f"/upnp/control/wlanconfig{n}")
        for n in range(1, 5)
    },
}

#: UPnP error codes (UPnP Device Architecture, TR-064) and what they mean for the user.
FAULTS: dict[int, str] = {
    401: "action not supported by this FRITZ!OS",
    402: "invalid arguments",
    600: "argument value invalid",
    601: "argument value out of range",
    501: "action failed",
    606: "not authorised: the Fritz!Box user lacks the right for this action",
    713: "no such entry",
    714: "no such entry",
    820: "internal error of the Fritz!Box",
}

_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class SoapFault(AdapterError):
    """The device answered with a UPnP error."""

    def __init__(self, what: str, code: int | None, description: str) -> None:
        self.code = code
        meaning = FAULTS.get(code, "") if code is not None else ""
        text = f"{what}: UPnP error {code if code is not None else '?'}"
        if description:
            text += f" ({description})"
        if meaning:
            text += f": {meaning}"
        super().__init__(text)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_xml(body: bytes, what: str) -> ET.Element:
    """Parse a device answer; refuses DTDs and entities, maps parse errors to AdapterError."""
    if _DTD.search(body):
        raise AdapterError(f"{what}: answer refused, it contains a DTD or entity declaration")
    try:
        return ET.fromstring(body)
    except ET.ParseError as exc:
        raise AdapterError(f"{what}: answer is not valid XML ({exc})") from exc


def envelope(service_type: str, action: str, args: dict[str, str | int]) -> bytes:
    inner = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in args.items())
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="{SOAP_ENV}" s:encodingStyle="{SOAP_ENC}">'
        f'<s:Body><u:{action} xmlns:u="{service_type}">{inner}</u:{action}></s:Body>'
        "</s:Envelope>"
    ).encode()


def parse_answer(body: bytes, action: str, what: str) -> dict[str, str]:
    """Output arguments of a SOAP answer; raises SoapFault for a fault."""
    root = parse_xml(body, what)
    soap_body = next((e for e in root.iter() if _local(e.tag) == "Body"), None)
    if soap_body is None:
        raise AdapterError(f"{what}: unexpected answer (no SOAP body)")
    for element in soap_body:
        name = _local(element.tag)
        if name == "Fault":
            code_text = _text_of(element, "errorCode")
            code = int(code_text) if code_text and code_text.isdigit() else None
            description = _text_of(element, "errorDescription") or _text_of(element, "faultstring")
            raise SoapFault(what, code, description or "")
        if name == f"{action}Response":
            return {_local(child.tag): (child.text or "").strip() for child in element}
    raise AdapterError(f"{what}: unexpected answer (no {action}Response)")


def _text_of(element: ET.Element, name: str) -> str | None:
    found = next((e for e in element.iter() if _local(e.tag) == name), None)
    return (found.text or "").strip() if found is not None else None


#: Plain-HTTP UPnP port of the box; it tells its TR-064 HTTPS port there without credentials.
UPNP_PORT = 49000


async def security_port(host: str, timeout: float, port: int | None = None) -> int | None:
    """The TR-064 HTTPS port the box reports (``DeviceInfo GetSecurityPort`` on port 49000).

    No credentials are sent: AVM answers this one action without authentication. None if the
    box does not answer it.
    """
    service_type, path = SERVICES["DeviceInfo1"]
    netloc = f"[{host}]" if ":" in host else host
    url = f"http://{netloc}:{port or UPNP_PORT}{path}"
    try:
        async with httpx.AsyncClient(
            timeout=timeout, trust_env=False, follow_redirects=False
        ) as client:
            response = await client.post(
                url,
                content=envelope(service_type, "GetSecurityPort", {}),
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": f"{service_type}#GetSecurityPort",
                },
            )
        found = parse_answer(response.content, "GetSecurityPort", "DeviceInfo1 GetSecurityPort")
        return int(found["NewSecurityPort"])
    except (httpx.HTTPError, AdapterError, KeyError, ValueError, OSError):
        return None


class Tr064:
    def __init__(self, http: DeviceHttp) -> None:
        self.http = http

    async def call(self, service: str, action: str, **args: str | int) -> dict[str, str]:
        """Call ``service action``; returns the output arguments by name (``NewSSID``...)."""
        service_type, path = SERVICES[service]
        what = f"{service} {action}"
        response = await self.http.request(
            "POST",
            path,
            accept={500},
            content=envelope(service_type, action, args),
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{service_type}#{action}"',
                "Accept": "text/xml",
            },
        )
        return parse_answer(response.content, action, what)

    async def get_xml(self, path: str, what: str) -> ET.Element:
        """GET an XML document the device pointed to (a path on the same host, never a URL)."""
        if not path.startswith("/") or path.startswith("//"):
            raise AdapterError(f"{what}: refused to follow {path!r}, not a path on the device")
        response = await self.http.request("GET", path, headers={"Accept": "text/xml"})
        return parse_xml(response.content, what)
