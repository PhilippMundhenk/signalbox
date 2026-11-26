"""MikroTik RouterOS (write): PoE-out per port (#484, ADR 0036).

``poe-out`` of the port's row in ``/interface/ethernet/poe`` switches it: ``auto-on`` (802.3af/at
detection, plus RouterOS's own passive detection where the board has it) or ``off``. Signalbox
never writes ``forced-on``, which powers a device that did not ask for it; a port on
``forced-on`` already counts as on and is not changed. ``poe-priority`` and the other columns
are left alone (ADR 0036: the priority is not written yet).

Every change is undone by the scheduler entry of the firewall changes (``fwwrite``) unless it is
confirmed; the backup keeps ``poe-out`` of every row and a restore sets it back. The REST
``PATCH`` of a row of this menu is a *guess* until a real device confirms it (#21): CHR has no
PoE, so it is tested against the simulator only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, Described
from signalbox.adapters.mikrotik.fwwrite import Revert, ros_quote
from signalbox.changes import Change, PoeValue

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.mikrotik.write import _Config

#: The PoE-out menu of the ethernet ports (the reader's ``ETHERNET_POE``).
ETHERNET_POE = "/rest/interface/ethernet/poe"
ON, OFF = "auto-on", "off"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def poe(cfg: _Config, c: Change, revert: Revert) -> None:
    """Set ``poe-out`` of the port of the change."""
    if not isinstance(c.new, PoeValue):  # pragma: no cover - PoE is never removed
        return
    name = c.key.rsplit("/port/", 1)[-1]
    row = next((r for r in cfg.rows(ETHERNET_POE) if _text(r.get("name")) == name), None)
    if row is None:
        raise AdapterError(
            f"PoE: the router has no PoE-out on {name}",
            message_id="mikrotik.noPoePort",
            params={"interface": name},
        )
    now = _text(row.get("poe-out"))
    if c.new.enabled == (now not in ("", OFF)):
        return
    want = ON if c.new.enabled else OFF
    cfg.patch(
        ETHERNET_POE,
        row,
        {"poe-out": want},
        Described(f"PoE of {name}: on", "plan.mikrotik.poeOn", interface=name)
        if c.new.enabled
        else Described(f"PoE of {name}: off", "plan.mikrotik.poeOff", interface=name),
    )
    revert.add(
        f"/interface ethernet poe set [find where name={ros_quote(name)}] "
        f"poe-out={ros_quote(now or ON)}"
    )


def backup_rows(rows: list[dict[str, Any]]) -> dict[str, str]:
    """What the backup keeps: ``poe-out`` per port name."""
    return {
        _text(r.get("name")): _text(r.get("poe-out"))
        for r in rows
        if _text(r.get("name")) and _text(r.get("poe-out"))
    }


def restore_rows(cfg: _Config, saved: Any) -> None:
    """Set ``poe-out`` back as the backup has it."""
    if not isinstance(saved, dict):
        return
    for row in cfg.rows(ETHERNET_POE):
        name = _text(row.get("name"))
        want = saved.get(name)
        if isinstance(want, str) and want and _text(row.get("poe-out")) != want:
            cfg.patch(
                ETHERNET_POE,
                row,
                {"poe-out": want},
                Described(f"restore: PoE of {name}", "plan.mikrotik.restorePoe", interface=name),
            )
