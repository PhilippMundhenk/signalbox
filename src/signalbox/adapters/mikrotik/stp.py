"""Spanning tree of RouterOS bridges (#155, ADR 0023).

``/interface/bridge`` has the configuration (``protocol-mode``, ``priority``), the bridge
ports ``/interface/bridge/port`` theirs (``edge``, ``path-cost``, ``bpdu-guard``,
``restricted-role``). The running state (root bridge, port roles) comes from the ``monitor``
commands with ``once``, which only read; RouterOS 7 also puts the port state into the print of
the bridge ports, which is used first. Loop protection is a setting of the Ethernet interface
(``loop-protect``).
"""

from __future__ import annotations

from typing import Any

from signalbox.model import (
    SPANNING_TREE,
    StpBridge,
    StpPort,
    StpPortRole,
    StpPortState,
    StpProtocol,
    normalise_mac,
    parse_stp_bridge_id,
    stp_bridge_id,
)

BRIDGE_MONITOR = "/rest/interface/bridge/monitor"
BRIDGE_PORT_MONITOR = "/rest/interface/bridge/port/monitor"

_PROTOCOLS = {
    "none": StpProtocol.NONE,
    "stp": StpProtocol.STP,
    "rstp": StpProtocol.RSTP,
    "mstp": StpProtocol.MSTP,
}
_ROLES = {
    "root-port": StpPortRole.ROOT,
    "designated-port": StpPortRole.DESIGNATED,
    "alternate-port": StpPortRole.ALTERNATE,
    "backup-port": StpPortRole.BACKUP,
    "disabled-port": StpPortRole.DISABLED,
}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _bool(value: Any) -> bool | None:
    text = _text(value).lower() if not isinstance(value, bool) else str(value).lower()
    if text in ("true", "yes", "on"):
        return True
    if text in ("false", "no", "off"):
        return False
    return None


def _number(value: Any, base: int = 10) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = _text(value).lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text, base)
    except ValueError:
        return None


def protocol(row: dict[str, Any]) -> StpProtocol | None:
    """``protocol-mode`` of a bridge (RouterOS' default is ``rstp``)."""
    return _PROTOCOLS.get(_text(row.get("protocol-mode")).lower() or "rstp")


def bridge(
    row: dict[str, Any], monitor: dict[str, Any], port_ids: dict[str, str]
) -> StpBridge | None:
    """One bridge from its row, its monitor (empty when not read) and port name -> id."""
    name = _text(row.get("name"))
    proto = protocol(row)
    if not name or proto is None:
        return None
    priority = _number(row.get("priority"), 16)
    if priority is not None and not 0 <= priority <= 0xFFFF:
        priority = None
    mac = _text(monitor.get("current-mac-address")) or _text(row.get("mac-address"))
    own: str | None = None
    if priority is not None and mac:
        try:
            own = stp_bridge_id(priority, normalise_mac(mac))
        except ValueError:
            own = None
    root_id: str | None = None
    root_port: str | None = None
    cost: int | None = None
    if proto in SPANNING_TREE and monitor:
        root_id = parse_stp_bridge_id(monitor.get("root-bridge-id"))
        if root_id is None and _bool(monitor.get("root-bridge")) is True:
            root_id = own
        root_port = port_ids.get(_text(monitor.get("root-port")))
        cost = _number(monitor.get("root-path-cost"))
    return StpBridge(
        name=name,
        port_id=port_ids.get(name),
        protocol=proto,
        priority=priority,
        bridge_id=own,
        root_bridge_id=root_id,
        root_port_id=root_port,
        root_path_cost=cost if cost is None or cost >= 0 else None,
    )


def _edge(config: Any, actual: Any) -> bool | None:
    """``edge-port`` (the running state) first, else the setting ``edge`` (``auto``: unknown)."""
    running = _bool(actual)
    if running is not None:
        return running
    text = _text(config).lower()
    if text in ("yes", "yes-discover"):
        return True
    if text in ("no", "no-discover"):
        return False
    return None


def port(
    row: dict[str, Any],
    monitor: dict[str, Any],
    proto: StpProtocol,
    ethernet: dict[str, Any] | None,
) -> StpPort:
    """One bridge port: its row, its monitor (or the same row in RouterOS 7, which prints the
    running state), the bridge's protocol and the Ethernet row of the interface."""
    state_of = monitor or row
    role = _ROLES.get(_text(state_of.get("role")).lower())
    status = _text(state_of.get("status")).lower()
    forwarding, learning = _bool(state_of.get("forwarding")), _bool(state_of.get("learning"))
    state: StpPortState | None = None
    if _bool(row.get("inactive")) is True or status == "inactive" or role is StpPortRole.DISABLED:
        state = StpPortState.DISABLED
    elif forwarding is True:
        state = StpPortState.FORWARDING
    elif learning is True:
        state = StpPortState.LEARNING
    elif forwarding is False and proto in SPANNING_TREE:
        state = StpPortState.BLOCKING if proto is StpProtocol.STP else StpPortState.DISCARDING
    loop: bool | None = None
    if ethernet is not None:
        mode = _text(ethernet.get("loop-protect")).lower()
        loop = True if mode == "on" else False if mode in ("off", "default") else None
        if _text(ethernet.get("loop-protect-status")).lower() == "disable":
            state = StpPortState.DISABLED  # loop protection shut the port down
    cost = _number(state_of.get("actual-path-cost")) or _number(row.get("path-cost"))
    spanning = proto in SPANNING_TREE
    return StpPort(
        state=state,
        role=role if spanning else None,
        edge=_edge(row.get("edge"), state_of.get("edge-port")) if spanning else None,
        path_cost=cost if spanning and cost is not None and cost >= 0 else None,
        bpdu_guard=_bool(row.get("bpdu-guard")),
        root_guard=_bool(row.get("restricted-role")),
        loop_protect=loop,
    )


def needs_monitor(rows: list[dict[str, Any]]) -> bool:
    """True when the print of the bridge ports has no running state (RouterOS 6, some 7.x)."""
    return bool(rows) and not any("role" in r or "forwarding" in r for r in rows)


def monitor_rows(answer: Any) -> list[dict[str, Any]]:
    if isinstance(answer, dict):
        answer = [answer]
    return [r for r in answer if isinstance(r, dict)] if isinstance(answer, list) else []
