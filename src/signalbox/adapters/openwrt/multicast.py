"""Multicast of OpenWrt bridges and the services that reflect it (#161, ADR 0028).

The setting is the bridge ``device`` section of UCI ``network`` (``option igmp_snooping '1'``,
``option multicast_querier '1'``, ``option igmp_version``, ``option mld_version``). The kernel's
running values are in sysfs, read with ``file read`` where the read ACL allows
``/sys/class/net/*/bridge/*`` (``multicast_snooping``, ``multicast_querier``,
``multicast_igmp_version``, ``multicast_mld_version``) and ``/sys/class/net/*/brport/*``
(``multicast_fast_leave``, ``multicast_flood``); they win over UCI. ``igmpproxy`` has its own
UCI config (``phyint`` sections with ``network`` and ``direction``); the Avahi reflector is
``enable-reflector`` in ``/etc/avahi/avahi-daemon.conf``. Both packages are optional.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from signalbox.model import (
    MulticastSettings,
    ReflectorKind,
    ServiceReflector,
    UnknownMulticast,
)

BRIDGE_FILES = (
    "multicast_snooping",
    "multicast_querier",
    "multicast_igmp_version",
    "multicast_mld_version",
)
PORT_FILES = ("multicast_fast_leave", "multicast_flood")
AVAHI_CONF = "/etc/avahi/avahi-daemon.conf"


def _flag(value: Any) -> bool | None:
    text = str(value if value is not None else "").strip().lower()
    if text in ("1", "on", "true", "yes", "enabled"):
        return True
    if text in ("0", "off", "false", "no", "disabled"):
        return False
    return None


def _version(value: Any, top: int) -> int | None:
    try:
        number = int(str(value).strip())
    except ValueError:
        return None
    return number if 1 <= number <= top else None


def settings(
    name: str,
    uci: dict[str, Any],
    files: dict[str, str],
    members: list[dict[str, str]],
    segment_id: str | None,
) -> MulticastSettings:
    """One bridge (or one VLAN of it) from its UCI section, the sysfs values read (empty: not
    read) and the ``brport`` values of its members."""
    snooping = _flag(files.get("multicast_snooping"))
    if snooping is None:
        snooping = _flag(uci.get("igmp_snooping"))
    querier = _flag(files.get("multicast_querier"))
    if querier is None:
        querier = _flag(uci.get("multicast_querier"))
    version = _version(files.get("multicast_igmp_version") or uci.get("igmp_version"), 3)
    fast = {v for m in members if (v := _flag(m.get("multicast_fast_leave"))) is not None}
    flood = {v for m in members if (v := _flag(m.get("multicast_flood"))) is not None}
    unknown: UnknownMulticast | None = None
    if len(flood) == 1:
        unknown = UnknownMulticast.FLOOD if flood.pop() else UnknownMulticast.DROP
    return MulticastSettings(
        name=name,
        segment_id=segment_id,
        igmp_snooping=snooping,
        mld_snooping=snooping,
        querier=querier,
        querier_version=version if querier else None,
        fast_leave=fast.pop() if len(fast) == 1 else None,
        unknown_multicast=unknown,
    )


def _segments(names: list[str], segment_of: Callable[[str], str | None]) -> list[str]:
    return sorted({s for n in names if (s := segment_of(n)) is not None})


def igmpproxy(
    uci_sections: list[dict[str, Any]], segment_of: Callable[[str], str | None]
) -> ServiceReflector | None:
    """The IGMP proxy from its ``phyint`` sections (``direction`` upstream or downstream; a
    ``disabled`` one is left out). None without any."""
    live = [
        s
        for s in uci_sections
        if str(s.get("direction", "")).lower() in ("upstream", "downstream") and s.get("network")
    ]
    if not live:
        return None
    names = [str(s["network"]) for s in live]
    up = next((str(s["network"]) for s in live if str(s["direction"]).lower() == "upstream"), None)
    return ServiceReflector(
        kind=ReflectorKind.IGMP_PROXY,
        interfaces=names,
        segments=_segments(names, segment_of),
        upstream_interface=up,
        upstream_segment_id=segment_of(up) if up else None,
    )


def avahi(text: str, segment_of: Callable[[str], str | None]) -> ServiceReflector | None:
    """The reflector of ``avahi-daemon.conf`` (``[reflector] enable-reflector=yes``, the
    interfaces of ``[server] allow-interfaces``; none named: all). None when it is off."""
    section = ""
    values: dict[tuple[str, str], str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
        elif "=" in line:
            key, _, value = line.partition("=")
            values[(section, key.strip().lower())] = value.strip()
    if _flag(values.get(("reflector", "enable-reflector"))) is not True:
        return None
    names = [n.strip() for n in values.get(("server", "allow-interfaces"), "").split(",")]
    names = [n for n in names if n]
    return ServiceReflector(
        kind=ReflectorKind.MDNS, interfaces=names, segments=_segments(names, segment_of)
    )
