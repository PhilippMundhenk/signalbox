"""OpenWrt log and monitoring targets (#180) and the net-snmp agent (#173) from UCI.

- ``system``: ``log_ip``, ``log_port`` (514), ``log_proto`` (``udp``/``tcp``) and ``log_remote``
  (on unless ``0``) of the first ``system`` section: logd's remote syslog target.
- ``snmpd`` (package ``snmpd``, if installed): ``com2sec``/``com2sec6`` communities (only whether
  one is ``public`` or ``private`` is kept), ``group`` versions, ``access`` write rights,
  ``agentaddress`` port, ``general.enabled``, and ``trapsink``/``trap2sink``/``informsink``.
- ``luci_statistics`` (collectd through luci-app-statistics, if installed): the network plugin
  ``collectd_network`` and its ``collectd_network_server`` sections.
- ``softflowd`` (if installed): ``host_port`` and ``export_version`` (10 is IPFIX).

The section layouts of ``snmpd``, ``luci_statistics`` and ``softflowd`` are the packages'
default files; they are not installed in CI (*guess* until confirmed on a device, #21).
"""

from __future__ import annotations

import contextlib
from ipaddress import ip_network
from typing import Any

from signalbox.model import (
    LOG_PORTS,
    SERVICE_PORTS,
    IPNetwork,
    LogKind,
    LogTarget,
    LogTransport,
    ManagementService,
    ServiceKind,
    SnmpSettings,
    SnmpVersion,
    object_id,
)

#: Community names that are factory defaults; the configured name itself is never kept.
DEFAULT_COMMUNITIES = ("public", "private")
_VERSIONS = {"v1": SnmpVersion.V1, "v2c": SnmpVersion.V2C, "usm": SnmpVersion.V3}
_TRAPS = (("trapsink", "v1"), ("trap2sink", "v2c"), ("informsink", "inform"))


def sections(uci: dict[str, Any], *kinds: str) -> list[tuple[str, dict[str, Any]]]:
    """Sections of the given types, in file order (an empty config: none)."""
    values = uci.get("values")
    if not isinstance(values, dict):
        return []
    found = [
        (str(s.get(".name", name)), s)
        for name, s in values.items()
        if isinstance(s, dict) and s.get(".type") in kinds
    ]
    return sorted(found, key=lambda item: _int(item[1].get(".index")) or 0)


def _int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).strip() if value is not None else ""


def _off(value: Any) -> bool:
    return _text(value).lower() in ("0", "false", "no", "off", "disabled")


def _port(value: Any) -> int | None:
    port = _int(_text(value))
    return port if port is not None and 1 <= port <= 65535 else None


def host_port(text: str) -> tuple[str, int | None]:
    """``192.0.2.5:9995``, ``[2001:db8::5]:9995``, ``collector``: host and port."""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, _port(rest.removeprefix(":"))
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, _port(port)
    return text, None


def system_targets(system: dict[str, Any]) -> list[LogTarget]:
    """logd's remote target from the first ``system`` section (none without ``log_ip``)."""
    first = next(iter(sections(system, "system")), None)
    if first is None:
        return []
    s = first[1]
    out: list[LogTarget] = []
    raw = s.get("log_ip")
    for address in raw if isinstance(raw, list) else [raw]:
        if not _text(address):
            continue
        proto = _text(s.get("log_proto")).lower()
        out.append(
            LogTarget(
                kind=LogKind.SYSLOG,
                address=_text(address),
                port=_port(s.get("log_port")) or LOG_PORTS[LogKind.SYSLOG],
                transport=LogTransport.TCP if proto == "tcp" else LogTransport.UDP,
                enabled=not _off(s.get("log_remote")),
                name="logd",
            )
        )
    return out


def snmpd(device_id: str, uci: dict[str, Any]) -> tuple[ManagementService | None, list[LogTarget]]:
    """The agent as a management service and its trap targets; (None, []) without ``snmpd``."""
    if not uci.get("values"):
        return None, []
    communities = [
        (_text(s.get("community")), _text(s.get("source")))
        for _, s in sections(uci, "com2sec", "com2sec6")
    ]
    versions = {
        _VERSIONS[v]
        for _, s in sections(uci, "group")
        if (v := _text(s.get("version")).lower()) in _VERSIONS
    }
    if communities and not versions:
        versions = {SnmpVersion.V1, SnmpVersion.V2C}
    allowed: list[IPNetwork] = []
    for _, source in communities:
        if source.lower() in ("", "default"):
            allowed = []
            break
        net = "127.0.0.1/32" if source.lower() == "localhost" else source
        with contextlib.suppress(ValueError):
            allowed.append(ip_network(net, strict=False))
    write = any(
        _text(s.get("write")).lower() not in ("", "none") for _, s in sections(uci, "access")
    )
    general = next((s for _, s in sections(uci, "snmpd")), {})
    agent = next((s for _, s in sections(uci, "agent")), {})
    port = None
    for part in _text(agent.get("agentaddress")).split(","):
        port = port or _port(part.rpartition(":")[2])
    names = [c.lower() for c, _ in communities]
    service = ManagementService(
        id=object_id(device_id, "service", "snmp"),
        device_id=device_id,
        kind=ServiceKind.SNMP,
        name="snmpd",
        enabled=not _off(general.get("enabled")),
        port=port or SERVICE_PORTS[ServiceKind.SNMP],
        allowed_from=allowed,
        snmp=SnmpSettings(
            versions=sorted(versions),
            default_community=any(n in DEFAULT_COMMUNITIES for n in names) if names else None,
            write_access=write,
        ),
    )
    traps: list[LogTarget] = []
    for kind, version in _TRAPS:
        for _, s in sections(uci, kind):
            host = _text(s.get("host"))
            if host:
                traps.append(
                    LogTarget(
                        kind=LogKind.SNMP_TRAP,
                        address=host,
                        port=_port(s.get("port")) or LOG_PORTS[LogKind.SNMP_TRAP],
                        transport=LogTransport.UDP,
                        enabled=service.enabled,
                        name=kind,
                        topics=[version],
                    )
                )
    return service, traps


def collectd(uci: dict[str, Any]) -> list[LogTarget]:
    """Servers of collectd's network plugin (luci-app-statistics)."""
    plugin = next((s for n, s in sections(uci, "statistics") if n == "collectd_network"), None)
    if plugin is None:
        return []
    enabled = _text(plugin.get("enable")) == "1"
    return [
        LogTarget(
            kind=LogKind.METRICS,
            address=_text(s.get("host")),
            port=_port(s.get("port")) or LOG_PORTS[LogKind.METRICS],
            transport=LogTransport.UDP,
            enabled=enabled,
            name="collectd",
        )
        for _, s in sections(uci, "collectd_network_server")
        if _text(s.get("host"))
    ]


def softflowd(uci: dict[str, Any]) -> list[LogTarget]:
    out: list[LogTarget] = []
    for name, s in sections(uci, "softflowd"):
        host, port = host_port(_text(s.get("host_port")))
        if not host:
            continue
        version = _text(s.get("export_version")) or "5"
        kind = LogKind.IPFIX if version == "10" else LogKind.NETFLOW
        out.append(
            LogTarget(
                kind=kind,
                address=host,
                port=port or LOG_PORTS[kind],
                transport=LogTransport.UDP,
                enabled=_text(s.get("enabled")) == "1",
                name=f"softflowd {name}" if not name.startswith("cfg") else "softflowd",
                topics=[] if kind is LogKind.IPFIX else [f"v{version}"],
            )
        )
    return out
