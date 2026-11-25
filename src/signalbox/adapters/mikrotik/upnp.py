"""UPnP of RouterOS (#176, ADR 0029).

``/ip/upnp`` has ``enabled``; ``/ip/upnp/interfaces`` lists the interfaces with ``type``
``internal`` (where it listens) or ``external``. A mapping a client opened is a dynamic
``dstnat`` rule of ``/ip/firewall/nat`` (``dynamic=true``) with ``protocol``, ``dst-port``,
``to-addresses`` and ``to-ports`` and a comment that starts with ``upnp``. RouterOS answers
UPnP IGD only (no NAT-PMP or PCP), has no secure mode and no permission rules, and reports no
lease time. *(Guess, #21: the exact comment of dynamic rows; the rows are recognised by
``dynamic`` and the word ``upnp`` in the comment.)*
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from signalbox.model import (
    DeviceUpnp,
    DynamicPortMapping,
    ManagementService,
    MappingOrigin,
    ServiceKind,
    UpnpProtocol,
    object_id,
)

UPNP = "/rest/ip/upnp"
UPNP_INTERFACES = "/rest/ip/upnp/interfaces"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _yes(value: Any) -> bool:
    return _text(value).lower() in ("true", "yes", "on")


def mappings(rows: list[dict[str, Any]]) -> list[DynamicPortMapping]:
    out: list[DynamicPortMapping] = []
    for r in rows:
        comment = _text(r.get("comment"))
        if (
            not _yes(r.get("dynamic"))
            or _yes(r.get("disabled"))
            or _text(r.get("action")) != "dst-nat"
            or "upnp" not in comment.lower()
        ):
            continue
        proto = _text(r.get("protocol")).lower()
        try:
            address = ip_address(_text(r.get("to-addresses")))
            external = int(_text(r.get("dst-port")))
            internal = int(_text(r.get("to-ports")) or external)
        except ValueError:
            continue  # a range or a name: not a single mapping
        if proto not in ("tcp", "udp") or not (1 <= external <= 65535 and 1 <= internal <= 65535):
            continue
        description = comment[4:].lstrip(" :-") if comment.lower().startswith("upnp") else comment
        out.append(
            DynamicPortMapping(
                protocol="tcp" if proto == "tcp" else "udp",
                external_port=external,
                internal_address=address,
                internal_port=internal,
                description=description or None,
                created_by=MappingOrigin.UPNP,
            )
        )
    return out


def state(
    device_id: str,
    settings: dict[str, Any],
    interfaces: list[dict[str, Any]],
    nat_rows: list[dict[str, Any]] | None,
    segment_of: dict[str, str],
) -> tuple[ManagementService, DeviceUpnp]:
    """The service with the networks of its internal interfaces, and the state. ``nat_rows``
    is ``None`` when the NAT rules could not be read."""
    internal = [
        _text(r.get("interface"))
        for r in interfaces
        if _text(r.get("type")) == "internal" and not _yes(r.get("disabled"))
    ]
    segments = sorted({segment_of[n] for n in internal if n in segment_of})
    service = ManagementService(
        id=object_id(device_id, "service", "upnp"),
        device_id=device_id,
        kind=ServiceKind.UPNP,
        name="upnp",
        enabled=_yes(settings.get("enabled")),
        segments=segments if internal and len(segments) == len(set(internal)) else [],
    )
    return service, DeviceUpnp(
        protocols=[UpnpProtocol.IGD],
        mappings=mappings(nat_rows or []),
        mappings_complete=nat_rows is not None,
    )
