"""MikroTik RouterOS (write): the UPnP service (#513, ADR 0035).

``/ip/upnp`` ``enabled`` switches it; the networks it answers in are the ``internal`` rows of
``/ip/upnp/interfaces`` (the layer-3 interface of each declared segment, the first by name):
an internal row of another network is disabled, a disabled one of a declared network enabled,
a missing one added; ``external`` rows are left alone. RouterOS answers UPnP IGD only and has
no secure mode and no permission rules: a change of those is refused.

Signalbox does not remove open mappings (the dynamic ``dst-nat`` rows): they end with their
lease, and RouterOS may drop them itself when the service stops (*guess*, #21). Every change is
undone by the scheduler entry of the firewall changes (``fwwrite``) unless it is confirmed;
the backup keeps ``enabled`` and the interface rows, and a restore sets them back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, Described
from signalbox.adapters.mikrotik.fwwrite import Revert, ros_quote
from signalbox.adapters.mikrotik.upnp import UPNP as UPNP
from signalbox.adapters.mikrotik.upnp import UPNP_INTERFACES as UPNP_INTERFACES
from signalbox.changes import Change, UpnpValue

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.mikrotik.write import _Config


#: The plan text of switching UPnP off (ADR 0035: open mappings are left to expire).
UPNP_OFF = (
    "UPnP: off (Signalbox does not remove open mappings: they end with their lease, "
    "and the router may drop them as the service stops)"
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def refuse_unsupported(c: Change) -> None:
    """RouterOS has no secure mode and no permission rules (ADR 0035)."""
    old, new = c.old, c.new
    if not isinstance(new, UpnpValue):
        return
    was = old if isinstance(old, UpnpValue) else None
    if new.secure_mode is not None and (was is None or was.secure_mode != new.secure_mode):
        raise AdapterError(
            "RouterOS has no UPnP secure mode; remove secure_mode from the entry.",
            message_id="mikrotik.upnpNoSecureMode",
        )
    if new.rules and (was is None or was.rules != new.rules):
        raise AdapterError(
            "RouterOS has no UPnP permission rules; remove allow from the entry (limit the "
            "networks instead).",
            message_id="mikrotik.upnpNoRules",
        )


def switch(c: Change, enabled_now: bool, revert: Revert) -> dict[str, str] | None:
    """The body of ``POST /rest/ip/upnp/set``; ``None``: nothing to switch."""
    if not isinstance(c.new, UpnpValue) or c.new.enabled == enabled_now:
        return None
    revert.add(f"/ip upnp set enabled={'yes' if enabled_now else 'no'}")
    return {"enabled": "true" if c.new.enabled else "false"}


def switch_note(enabled: bool) -> Described:
    if enabled:
        return Described("UPnP: on", "plan.mikrotik.upnpOn")
    return Described(UPNP_OFF, "plan.mikrotik.upnpOff")


def networks(cfg: _Config, c: Change, l3: dict[str, str], revert: Revert) -> None:
    """Make the enabled ``internal`` rows of ``/ip/upnp/interfaces`` those of the declared
    networks."""
    if not isinstance(c.new, UpnpValue) or not c.new.networks:
        return
    old = c.old if isinstance(c.old, UpnpValue) else None
    if old is not None and old.networks == c.new.networks:
        return
    wanted: list[str] = []
    for sid in c.new.networks:
        name = next((n for n in sorted(l3) if l3[n] == sid), None)
        if name is None:
            raise AdapterError(
                f"UPnP: the router has no interface in {sid}; UPnP can only answer in a "
                "network the router has",
                message_id="mikrotik.upnpNoInterface",
                params={"segment": sid},
            )
        wanted.append(name)
    rows = [r for r in cfg.static(UPNP_INTERFACES) if _text(r.get("type")) == "internal"]
    for row in rows:
        name = _text(row.get("interface"))
        ref = _text(row.get(".id"))
        off = _flag(row.get("disabled"))
        if name in wanted and off:
            cfg.patch(
                UPNP_INTERFACES,
                row,
                {"disabled": "false"},
                Described(
                    f"UPnP: answer on {name}", "plan.mikrotik.upnpInterfaceOn", interface=name
                ),
            )
            revert.add(f"/ip upnp interfaces set {ref} disabled=yes")
        elif name not in wanted and not off:
            cfg.patch(
                UPNP_INTERFACES,
                row,
                {"disabled": "true"},
                Described(
                    f"UPnP: no longer on {name}",
                    "plan.mikrotik.upnpInterfaceOff",
                    interface=name,
                ),
            )
            revert.add(f"/ip upnp interfaces set {ref} disabled=no")
    have = {_text(r.get("interface")) for r in rows}
    for name in wanted:
        if name in have:
            continue
        cfg.put(
            UPNP_INTERFACES,
            {"interface": name, "type": "internal"},
            Described(f"UPnP: answer on {name}", "plan.mikrotik.upnpInterfaceOn", interface=name),
        )
        revert.add(
            f"/ip upnp interfaces remove [find where interface={ros_quote(name)} and type=internal]"
        )
