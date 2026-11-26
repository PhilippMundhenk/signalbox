"""OpenWrt (write): WireGuard tunnels (#152, ADR 0034).

A tunnel's end is a ``proto wireguard`` interface of the ``network`` config (``listen_port``,
``addresses``, ``mtu``), its peer a ``wireguard_<interface>`` section (``public_key``,
``allowed_ips``, ``route_allowed_ips '1'`` so that netifd routes the other end's networks,
``endpoint_host``, ``endpoint_port``, ``persistent_keepalive``). What Signalbox creates carries
the option ``signalbox`` with the tunnel's name; an adopted interface or peer keeps its own
sections and is found by its name or the other end's public key.

No key ever passes through here: the configs are read without ``private_key`` and
``preshared_key`` (:func:`signalbox.adapters.openwrt.wireguard.drop_keys`), a new interface is
staged without a key, and after ``uci apply`` the key helper on the router
(``/usr/libexec/signalbox-wg-key``, docs/adapters/openwrt.md) generates it with ``wg genkey``
and prints nothing. A peer's pre-shared key is never touched.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, Described, Label
from signalbox.changes import Change, TunnelPeerValue, TunnelValue

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.openwrt.write import Configs

#: Option with the tunnel name on the sections Signalbox creates.
TAG = "signalbox"
#: The helper that generates a new interface's private key on the router.
KEY_HELPER = "/usr/libexec/signalbox-wg-key"
#: UCI section names: what the helper and netifd accept for an interface Signalbox creates.
SECTION_NAME = re.compile(r"^[A-Za-z0-9_]{1,15}$")


def _interface(cfg: Configs, name: str, adopt: str | None) -> tuple[str, dict[str, Any]] | None:
    found = [
        (n, s) for n, s in cfg.sections("network", "interface") if s.get("proto") == "wireguard"
    ]
    mine = next(((n, s) for n, s in found if s.get(TAG) == name), None)
    if mine is None and adopt:
        mine = next(((n, s) for n, s in found if n == adopt and not s.get(TAG)), None)
    return mine


def _peer(
    cfg: Configs, name: str, interface: str, keys: list[str]
) -> tuple[str, dict[str, Any]] | None:
    found = cfg.sections("network", f"wireguard_{interface}")
    mine = next(((n, s) for n, s in found if s.get(TAG) == name), None)
    if mine is None:
        mine = next(
            ((n, s) for k in keys for n, s in found if not s.get(TAG) and s.get("public_key") == k),
            None,
        )
    return mine


def tunnel(cfg: Configs, c: Change) -> str | None:
    """Stage the interface of ``c.new`` (``None``: remove Signalbox's, with its peers). Returns
    the name of an interface that is created and needs its key pair from the helper."""
    name = c.key.partition("/")[2]
    label = Label(f"tunnel {name}", "tunnel", name)
    found = _interface(cfg, name, c.adopt)
    v = c.new if isinstance(c.new, TunnelValue) else None
    if v is None:
        if found is not None:
            section = found[0]
            for peer, _ in cfg.sections("network", f"wireguard_{section}"):
                cfg.delete(
                    "network",
                    peer,
                    Described(
                        f"{label}: remove the peer {peer}",
                        "plan.openwrt.wgPeerRemove",
                        label=label,
                        section=peer,
                    ),
                )
            cfg.delete(
                "network",
                section,
                Described(
                    f"{label}: remove the WireGuard interface {section}",
                    "plan.openwrt.wgRemove",
                    label=label,
                    interface=section,
                ),
            )
        return None
    values: dict[str, Any] = {}
    if v.listen_port is not None:
        values["listen_port"] = str(v.listen_port)
    if v.mtu is not None:
        values["mtu"] = str(v.mtu)
    addresses = [str(a) for a in v.addresses]
    if found is None:
        if not SECTION_NAME.match(v.interface):
            raise AdapterError(
                f"{label}: OpenWrt interface names are letters, digits and _ (at most 15); "
                f"{v.interface!r} cannot be created",
                message_id="openwrt.tunnelName",
                params={"label": label, "interface": v.interface},
            )
        if v.interface in cfg.values("network"):
            raise AdapterError(
                f"{label}: the router already has a section {v.interface} that Signalbox did "
                "not create (adopt it in the desired state)",
                message_id="openwrt.tunnelExists",
                params={"label": label, "interface": v.interface},
            )
        created = {"proto": "wireguard", **values, TAG: name}
        if addresses:
            created["addresses"] = addresses
        cfg.add(
            "network",
            "interface",
            v.interface,
            created,
            Described(
                f"{label}: create the WireGuard interface {v.interface} (the router generates "
                "its key pair)",
                "plan.openwrt.wgCreate",
                label=label,
                interface=v.interface,
            ),
        )
        return v.interface
    section, _ = found
    note = Described(
        f"{label}: set the WireGuard interface {section}",
        "plan.openwrt.wgSet",
        label=label,
        interface=section,
    )
    if addresses:
        values["addresses"] = addresses
    cfg.set("network", section, values, note)
    if not addresses:
        cfg.drop("network", section, ["addresses", "ipaddr", "netmask"], note)
    return None


def peer(cfg: Configs, c: Change) -> None:
    """Stage the peer of the other end (``None``: remove Signalbox's)."""
    name = c.key.partition("/")[2]
    label = Label(f"tunnel {name}", "tunnel", name)
    values_of = [x for x in (c.new, c.old) if isinstance(x, TunnelPeerValue)]
    interface = values_of[0].interface
    found = _peer(cfg, name, interface, [x.public_key for x in values_of])
    v = c.new if isinstance(c.new, TunnelPeerValue) else None
    if v is None:
        if found is not None and found[1].get(TAG) == name:
            cfg.delete(
                "network",
                found[0],
                Described(
                    f"{label}: remove the peer {found[0]}",
                    "plan.openwrt.wgPeerRemove",
                    label=label,
                    section=found[0],
                ),
            )
        return
    values: dict[str, Any] = {
        "public_key": v.public_key,
        "allowed_ips": [str(n) for n in v.allowed_ips],
        "route_allowed_ips": "1",
    }
    if v.endpoint_host:
        values["endpoint_host"] = v.endpoint_host
        if v.endpoint_port:
            values["endpoint_port"] = str(v.endpoint_port)
    if v.keepalive is not None:
        values["persistent_keepalive"] = str(v.keepalive)
    if found is None:
        cfg.add(
            "network",
            f"wireguard_{interface}",
            f"sb_{interface}",
            {**values, "description": name, TAG: name},
            Described(
                f"{label}: add the peer of the other end to {interface}",
                "plan.openwrt.wgPeerCreate",
                label=label,
                interface=interface,
            ),
        )
        return
    cfg.set(
        "network",
        found[0],
        values,
        Described(
            f"{label}: change the peer {found[0]}",
            "plan.openwrt.wgPeerSet",
            label=label,
            section=found[0],
        ),
    )
