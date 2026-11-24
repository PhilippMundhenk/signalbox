"""Spanning tree of OpenWrt bridges (#155, ADR 0023).

The setting is the bridge ``device`` section of UCI ``network`` (``option stp '1'``,
``option priority``; netifd's default is off and 32767) and, on OpenWrt 22.03 and later,
``bridge-attributes`` of ``network.device status`` (``stp``, ``priority``). netifd uses the
kernel's 802.1D STP. The running state is only in sysfs, read with ``file read`` where the
read ACL allows ``/sys/class/net/*/bridge/*`` and ``/sys/class/net/*/brport/*``:
``bridge_id``, ``root_id``, ``root_port``, ``root_path_cost`` of the bridge and ``state``,
``port_no``, ``path_cost``, ``bpdu_guard``, ``root_block`` of each member.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from signalbox.model import (
    StpBridge,
    StpPort,
    StpPortRole,
    StpPortState,
    StpProtocol,
    parse_stp_bridge_id,
    stp_bridge_id,
)

#: ``brport/state`` of the kernel (``BR_STATE_*``).
_STATES = {
    0: StpPortState.DISABLED,
    1: StpPortState.LISTENING,
    2: StpPortState.LEARNING,
    3: StpPortState.FORWARDING,
    4: StpPortState.BLOCKING,
}
#: netifd's default bridge priority (``system-linux.c``) when UCI sets none.
DEFAULT_PRIORITY = 0x7FFF

BRIDGE_FILES = ("bridge_id", "root_id", "root_port", "root_path_cost")
PORT_FILES = ("state", "port_no", "path_cost", "bpdu_guard", "root_block")


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value if value is not None else "").strip().lower()
    if text in ("1", "on", "true", "yes", "enabled"):
        return True
    if text in ("0", "off", "false", "no", "disabled"):
        return False
    return None


def _number(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


@dataclass
class Setting:
    """What UCI and netifd say about one bridge."""

    name: str
    on: bool
    priority: int | None
    mac: str | None
    members: list[str] = field(default_factory=list)


def settings(uci_devices: list[dict[str, Any]], status: dict[str, Any]) -> list[Setting]:
    """One :class:`Setting` per bridge: the UCI ``device`` sections of type bridge, the
    running ``bridge-attributes`` first."""
    out: list[Setting] = []
    for s in uci_devices:
        name = s.get("name")
        if s.get("type") != "bridge" or not isinstance(name, str) or not name:
            continue
        st = _obj(status.get(name))
        attrs = _obj(st.get("bridge-attributes"))
        on = _flag(attrs.get("stp"))
        if on is None:
            on = _flag(s.get("stp")) or False
        prio = _number(attrs.get("priority"))
        if prio is None:
            prio = _number(s.get("priority"))
        if prio is None:
            prio = DEFAULT_PRIORITY
        members = st.get("bridge-members")
        out.append(
            Setting(
                name=name,
                on=on,
                priority=prio if 0 <= prio <= 0xFFFF else None,
                mac=st.get("macaddr") if isinstance(st.get("macaddr"), str) else None,
                members=[m for m in members if isinstance(m, str)]
                if isinstance(members, list)
                else [],
            )
        )
    return out


def bridge(
    setting: Setting, files: dict[str, str], port_ids: dict[str, str], numbers: dict[int, str]
) -> StpBridge:
    """The bridge from its setting and the sysfs values read (empty: not read)."""
    own = parse_stp_bridge_id(files.get("bridge_id"))
    if own is None and setting.priority is not None and setting.mac:
        try:
            own = stp_bridge_id(setting.priority, setting.mac)
        except ValueError:
            own = None
    root_no = _number(files.get("root_port"))
    cost = _number(files.get("root_path_cost"))
    on = setting.on
    return StpBridge(
        name=setting.name,
        port_id=port_ids.get(setting.name),
        protocol=StpProtocol.STP if on else StpProtocol.NONE,
        priority=setting.priority,
        bridge_id=own,
        root_bridge_id=parse_stp_bridge_id(files.get("root_id")) if on else None,
        root_port_id=port_ids.get(numbers.get(root_no or 0, "")) if on else None,
        root_path_cost=cost if on and cost is not None and cost >= 0 else None,
    )


def port(files: dict[str, str], root_no: int | None) -> StpPort:
    """One member from its ``brport`` values; the kernel has no roles: the root port follows
    from the bridge's ``root_port``, a blocking port is an alternate one."""
    raw_state = _number(files.get("state"))
    state = _STATES.get(raw_state) if raw_state is not None else None
    no = _number(files.get("port_no"))
    role: StpPortRole | None = None
    if state is StpPortState.DISABLED:
        role = StpPortRole.DISABLED
    elif root_no and no == root_no:
        role = StpPortRole.ROOT
    elif state is StpPortState.BLOCKING:
        role = StpPortRole.ALTERNATE
    cost = _number(files.get("path_cost"))
    return StpPort(
        state=state,
        role=role,
        path_cost=cost if cost is not None and cost >= 0 else None,
        bpdu_guard=_flag(files.get("bpdu_guard")),
        root_guard=_flag(files.get("root_block")),
    )
