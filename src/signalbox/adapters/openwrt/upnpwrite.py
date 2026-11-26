"""OpenWrt (write): the miniupnpd service in UCI ``upnpd`` (#513, ADR 0035).

The ``upnpd`` section (named ``config``) gets ``enabled``, ``secure_mode`` and
``internal_iface`` (the UCI networks of the declared segments, space separated, as LuCI and the
init script read it); a declared permission list replaces every ``perm_rule`` section with one
``allow`` rule per entry and a final ``deny`` of everything else (``action``, ``ext_ports``,
``int_addr``, ``int_ports``, ``comment 'Signalbox'``). Fields that are not declared keep what
the router has, and turning the service on is only written when the change says so.

Signalbox does not remove open mappings: they end with their lease, and miniupnpd removes its
port forwards when it stops (*guess*, #21). Everything is staged with the other changes of the
device and applied by ``uci apply`` with its confirm timer. *Guess (#21)*: that ``uci apply``
restarts miniupnpd (its init script registers a config trigger for ``upnpd``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from signalbox.adapters import AdapterError, Described
from signalbox.adapters import openwrt as h  # the read helpers (circular, used at run time)
from signalbox.changes import Change, UpnpValue
from signalbox.model import UpnpAclRule, segment_id

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.openwrt.write import Configs

CONFIG = "upnpd"
#: The ``comment`` of the permission rules Signalbox writes.
COMMENT = "Signalbox"


#: The plan text of switching UPnP off (ADR 0035: open mappings are left to expire).
UPNP_OFF = (
    "UPnP: off (Signalbox does not remove open mappings: they end with their lease, "
    "and miniupnpd may remove them as it stops)"
)


def no_upnpd() -> AdapterError:
    return AdapterError(
        "The router has no upnpd configuration to change (the miniupnpd package is not "
        "installed, or the login may not use it: set up the login with write access again).",
        message_id="openwrt.noUpnpd",
    )


def _flag(value: bool) -> str:
    return "1" if value else "0"


def _ports(first: int, last: int) -> str:
    return str(first) if first == last else f"{first}-{last}"


def _rule_values(r: UpnpAclRule) -> dict[str, str]:
    return {
        "action": "allow" if r.allow else "deny",
        "ext_ports": _ports(r.external_first, r.external_last),
        "int_addr": str(r.internal_network),
        "int_ports": _ports(r.internal_first, r.internal_last),
        "comment": COMMENT,
    }


def _interfaces(cfg: Configs, site: str, segments: list[str]) -> list[str]:
    """The UCI networks of the segments (one per segment, the first by name)."""
    view = cfg.view()
    out = []
    for sid in segments:
        name = next(
            (
                n
                for n in sorted(view.devices)
                if (vid := view.vlan_of_interface(n)) is not None
                and segment_id(site, None if vid == h._NATIVE else vid) == sid
            ),
            None,
        )
        if name is None:
            raise AdapterError(
                f"UPnP: the router has no interface in {sid}; UPnP can only answer in a network "
                "the router has",
                message_id="openwrt.upnpNoInterface",
                params={"segment": sid},
            )
        out.append(name)
    return out


def upnp(cfg: Configs, c: Change, site: str) -> None:
    """Give miniupnpd the state of ``c.new``; only the fields that differ are written."""
    if CONFIG not in cfg.data:
        raise no_upnpd()
    found = cfg.sections(CONFIG, "upnpd")
    if not found or not isinstance(c.new, UpnpValue):
        raise no_upnpd()
    name, s = found[0]
    new = c.new
    old = c.old if isinstance(c.old, UpnpValue) else None
    values: dict[str, str] = {}
    if new.secure_mode is not None and (old is None or old.secure_mode != new.secure_mode):
        values["secure_mode"] = _flag(new.secure_mode)
    if new.networks and (old is None or old.networks != new.networks):
        values["internal_iface"] = " ".join(_interfaces(cfg, site, new.networks))
    if values:
        cfg.set(
            CONFIG,
            name,
            values,
            Described(
                f"UPnP: {', '.join(sorted(values))}",
                "plan.openwrt.upnpOptions",
                options=", ".join(sorted(values)),
            ),
        )
    if old is None or old.rules != new.rules:
        for rule_name, _ in cfg.sections(CONFIG, "perm_rule"):
            cfg.delete(
                CONFIG,
                rule_name,
                Described(
                    f"UPnP: remove permission rule {rule_name}",
                    "plan.openwrt.upnpRuleRemove",
                    name=rule_name,
                ),
            )
        for i, r in enumerate(new.rules, 1):
            values_r = _rule_values(r)
            text = f"{values_r['action']} {values_r['ext_ports']} {values_r['int_addr']} "
            text += values_r["int_ports"]
            cfg.add(
                CONFIG,
                "perm_rule",
                f"sb_upnp_{i}",
                values_r,
                Described(f"UPnP: permission rule {text}", "plan.openwrt.upnpRule", rule=text),
            )
    if old is None or old.enabled != new.enabled:
        if new.enabled and all(
            s.get(o) in ("0", 0, False) for o in ("enable_upnp", "enable_natpmp")
        ):
            raise AdapterError(
                "UPnP: the router has both UPnP IGD and NAT-PMP switched off (enable_upnp, "
                "enable_natpmp); switch one of them on in LuCI first",
                message_id="openwrt.upnpNoProtocol",
            )
        if new.enabled:
            note = Described("UPnP: on", "plan.openwrt.upnpOn")
        else:
            note = Described(UPNP_OFF, "plan.openwrt.upnpOff")
        cfg.set(CONFIG, name, {"enabled": _flag(new.enabled)}, note)
