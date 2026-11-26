"""OpenWrt (write): PoE per port with the ``realtek-poe`` daemon (#484, ADR 0036).

UCI ``poe`` has one ``port`` section per PoE port (``id``, ``name``, ``enable``, ``priority``,
``poe_plus``; OpenWrt 23.05, 24.10 and 25.12). The section whose ``name`` is the port gets
``enable '1'`` or ``enable '0'``; ``priority`` and ``poe_plus`` are left alone (ADR 0036). The
daemon's init script reloads the ports when the config changes (``procd_add_config_trigger
"config.change" "poe" ubus call poe reload``), so the change is staged with the other changes
of the device and applied by ``uci apply`` with its confirm timer. *Guess (#21)*: that the
reload powers a port down and up as the option says on every release.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from signalbox.adapters import AdapterError, Described
from signalbox.changes import Change, PoeValue

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.openwrt.write import Configs

CONFIG = "poe"


def no_poe_config() -> AdapterError:
    return AdapterError(
        "The router has no poe configuration to change (the realtek-poe package is not "
        "installed, or the login may not use it: set up the login with write access again).",
        message_id="openwrt.noPoeConfig",
    )


def poe(cfg: Configs, c: Change) -> None:
    """Set ``enable`` of the port's ``port`` section."""
    if CONFIG not in cfg.data:
        raise no_poe_config()
    if not isinstance(c.new, PoeValue):  # pragma: no cover - PoE is never removed
        return
    name = c.key.rsplit("/port/", 1)[-1]
    section = next((n for n, s in cfg.sections(CONFIG, "port") if s.get("name") == name), None)
    if section is None:
        raise AdapterError(
            f"PoE: the poe configuration has no port section for {name}",
            message_id="openwrt.noPoePort",
            params={"interface": name},
        )
    on = c.new.enabled
    cfg.set(
        CONFIG,
        section,
        {"enable": "1" if on else "0"},
        Described(f"PoE of {name}: on", "plan.openwrt.poeOn", interface=name)
        if on
        else Described(f"PoE of {name}: off", "plan.openwrt.poeOff", interface=name),
    )
