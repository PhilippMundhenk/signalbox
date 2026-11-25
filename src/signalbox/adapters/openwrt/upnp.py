"""UPnP IGD / NAT-PMP of miniupnpd on OpenWrt (#176, ADR 0029).

UCI ``upnpd`` (package ``miniupnpd``): the section ``upnpd`` named ``config`` has ``enabled``,
``enable_upnp`` and ``enable_natpmp`` (both default on), ``secure_mode`` (default on),
``internal_iface`` (networks it listens on; ``lan`` when unset) and ``upnp_lease_file``; each
``perm_rule`` section is one permission rule (``action``, ``ext_ports``, ``int_addr``,
``int_ports``). The active mappings are the lease file (``/var/run/miniupnpd.leases``, read
through ``file read``). The ``luci.upnp`` ubus object is not used: its fields are not documented.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from signalbox.adapters.upnp import acl_rule
from signalbox.model import (
    DeviceUpnp,
    ManagementService,
    ServiceKind,
    UpnpAclRule,
    UpnpProtocol,
    object_id,
)

CONFIG = "upnpd"
LEASES = "/var/run/miniupnpd.leases"


def _flag(value: Any, default: bool) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value).split() if isinstance(value, str) else []


def state(
    device_id: str,
    main: list[tuple[str, dict[str, Any]]],
    perms: list[tuple[str, dict[str, Any]]],
    segment_of: Callable[[str], str | None],
) -> tuple[ManagementService, DeviceUpnp] | None:
    """The service and its state; ``None`` without a ``upnpd`` section (package not installed).
    ``segment_of`` maps a UCI network name to the segment id of its network."""
    if not main:
        return None
    s = main[0][1]
    protocols: list[UpnpProtocol] = []
    if _flag(s.get("enable_upnp"), True):
        protocols.append(UpnpProtocol.IGD)
    if _flag(s.get("enable_natpmp"), True):
        protocols.append(UpnpProtocol.NAT_PMP)
    if _flag(s.get("enable_pcp_pmp"), False):  # newer miniupnpd builds (*guess*)
        protocols.append(UpnpProtocol.PCP)
    names = _list(s.get("internal_iface")) or ["lan"]
    segments = sorted({seg for n in names if (seg := segment_of(n)) is not None})
    rules: list[UpnpAclRule] = []
    for _, p in perms:
        rule = acl_rule(p.get("action"), p.get("ext_ports"), p.get("int_addr"), p.get("int_ports"))
        if rule is not None:
            rules.append(rule)
    service = ManagementService(
        id=object_id(device_id, "service", "upnp"),
        device_id=device_id,
        kind=ServiceKind.UPNP,
        name="upnp",
        enabled=_flag(s.get("enabled"), True) and bool(protocols),
        segments=segments if len(segments) == len(names) else [],
    )
    return service, DeviceUpnp(
        protocols=protocols,
        secure_mode=_flag(s.get("secure_mode"), True),
        allow_rules=rules,
    )
