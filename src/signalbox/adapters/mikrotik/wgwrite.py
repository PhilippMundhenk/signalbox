"""MikroTik RouterOS (write): WireGuard tunnels (#152, ADR 0034).

What Signalbox creates carries the comment ``signalbox:wg/<tunnel>``: the interface
(``/interface/wireguard``), its tunnel addresses (``/ip/address``, ``/ipv6/address``), the peer
(``/interface/wireguard/peers``) and a static route per network behind the other end
(``/ip/route``, ``/ipv6/route``: RouterOS does not route allowed addresses by itself). An
adopted interface or peer keeps its own comment and is found by its name or the other end's
public key.

No key is ever sent or read: an interface is added without ``private-key``, so RouterOS
generates the key pair itself; the snapshot drops ``private-key`` and ``preshared-key`` the
moment the menus are read (:func:`signalbox.adapters.mikrotik.wireguard_rows`), and a peer's
pre-shared key is never touched. Every change is undone by the scheduler entry of the firewall
changes unless it is confirmed; undoing the removal of an interface adds a new one, with a new
key pair. The backup keeps the rows without keys (:func:`backup_rows`).
"""

from __future__ import annotations

from ipaddress import ip_interface, ip_network
from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, Described, Label
from signalbox.adapters.mikrotik.fwwrite import Revert, ros_quote
from signalbox.adapters.mikrotik.routes import IP_ROUTE as IP_ROUTE
from signalbox.adapters.mikrotik.routes import IPV6_ROUTE as IPV6_ROUTE
from signalbox.changes import Change, TunnelPeerValue, TunnelValue
from signalbox.model import IPNetwork

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.mikrotik.write import _Config

WIREGUARD = "/rest/interface/wireguard"
WIREGUARD_PEERS = "/rest/interface/wireguard/peers"
IP_ADDRESS = "/rest/ip/address"
IPV6_ADDRESS = "/rest/ipv6/address"
#: The comment prefix of what Signalbox creates for a tunnel (``WG_TAG`` of the reader).
TAG = "signalbox:wg/"
#: Properties the backup keeps (never a key).
INTERFACE_PROPS = ("name", "listen-port", "mtu", "comment", "disabled")
PEER_PROPS = (
    "interface",
    "public-key",
    "endpoint-address",
    "endpoint-port",
    "allowed-address",
    "persistent-keepalive",
    "comment",
    "disabled",
)
ROUTE_PROPS = ("dst-address", "gateway", "comment", "disabled")
ADDRESS_PROPS = ("address", "interface", "comment", "disabled")
#: Menus of the backup's ``wireguard_rows``, in the order rows are added back (IPv4 addresses
#: are in the general snapshot already; of the others only Signalbox's tagged rows are kept).
MENUS = (WIREGUARD, WIREGUARD_PEERS, IPV6_ADDRESS, IP_ROUTE, IPV6_ROUTE)
_CLI = {
    WIREGUARD: "/interface wireguard",
    WIREGUARD_PEERS: "/interface wireguard peers",
    IP_ADDRESS: "/ip address",
    IPV6_ADDRESS: "/ipv6 address",
    IP_ROUTE: "/ip route",
    IPV6_ROUTE: "/ipv6 route",
}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def tag(name: str) -> str:
    return f"{TAG}{name}"


def tagged(row: dict[str, Any]) -> str | None:
    """The tunnel name of a row Signalbox created, else ``None``."""
    from signalbox.adapters.mikrotik import wg_tagged

    return wg_tagged(row)


def _seconds(value: int) -> str:
    return f"{value}s" if value else "0"


def _find(menu: str, comment: str) -> str:
    return f"{_CLI[menu]} remove [find where comment={ros_quote(comment)}]"


def _add(menu: str, body: dict[str, str]) -> str:
    return f"{_CLI[menu]} add " + " ".join(f"{k}={ros_quote(v)}" for k, v in body.items())


def _set(menu: str, row: dict[str, Any], body: dict[str, str]) -> str:
    ref = _text(row.get(".id"))
    return f"{_CLI[menu]} set {ref} " + " ".join(f"{k}={ros_quote(v)}" for k, v in body.items())


def _interface(cfg: _Config, name: str, adopt: str | None) -> dict[str, Any] | None:
    rows = cfg.static(WIREGUARD)
    mine = next((r for r in rows if tagged(r) == name), None)
    if mine is None and adopt:
        mine = next((r for r in rows if tagged(r) is None and _text(r.get("name")) == adopt), None)
    return mine


def _address_menu(text: str) -> str:
    return IPV6_ADDRESS if ":" in text else IP_ADDRESS


def _route_menu(net: IPNetwork) -> str:
    return IPV6_ROUTE if net.version == 6 else IP_ROUTE


def tunnel(cfg: _Config, c: Change, revert: Revert) -> None:
    """The interface and its tunnel addresses of ``c.new`` (``None``: remove what is ours)."""
    name = c.key.partition("/")[2]
    label = Label(f"tunnel {name}", "tunnel", name)
    row = _interface(cfg, name, c.adopt)
    v = c.new if isinstance(c.new, TunnelValue) else None
    if v is None:
        if row is not None:
            _remove_interface(cfg, row, name, label, revert)
        return
    if row is None:
        if any(_text(r.get("name")) == v.interface for r in cfg.rows(WIREGUARD)):
            raise AdapterError(
                f"{label}: the router already has an interface {v.interface} that Signalbox "
                "did not create (adopt it in the desired state)",
                message_id="mikrotik.tunnelExists",
                params={"label": label, "interface": v.interface},
            )
        body = {"name": v.interface, "comment": tag(name)}
        if v.listen_port is not None:
            body["listen-port"] = str(v.listen_port)
        if v.mtu is not None:
            body["mtu"] = str(v.mtu)
        row = cfg.put(
            WIREGUARD,
            body,
            Described(
                f"{label}: create the WireGuard interface {v.interface} (the router generates "
                "its key pair)",
                "plan.mikrotik.wgCreate",
                label=label,
                interface=v.interface,
            ),
        )
        revert.add(_find(WIREGUARD, tag(name)))
    else:
        body = {}
        if v.listen_port is not None:
            body["listen-port"] = str(v.listen_port)
        if v.mtu is not None:
            body["mtu"] = str(v.mtu)
        old = {k: _text(row.get(k)) for k in body if _text(row.get(k)) != body[k]}
        if old:
            options = " ".join(f"{k}={body[k]}" for k in old)
            cfg.patch(
                WIREGUARD,
                row,
                {k: body[k] for k in old},
                Described(
                    f"{label}: set {v.interface}: {options}",
                    "plan.mikrotik.wgSet",
                    label=label,
                    interface=v.interface,
                    options=options,
                ),
            )
            back = {k: o for k, o in old.items() if o}
            if back:
                revert.add(_set(WIREGUARD, row, back))
    _addresses(cfg, v, name, revert)


def _addresses(cfg: _Config, v: TunnelValue, name: str, revert: Revert) -> None:
    """The interface's addresses become the declared ones."""
    want = {str(a) for a in v.addresses}
    for menu in (IP_ADDRESS, IPV6_ADDRESS):
        for row in list(cfg.static(menu)):
            text = _text(row.get("address"))
            if _text(row.get("interface")) != v.interface or text in want:
                want.discard(text)
                continue
            cfg.delete(
                menu,
                row,
                Described(
                    f"remove {text} from {v.interface}",
                    "plan.mikrotik.addressRemove",
                    address=text,
                    interface=v.interface,
                ),
            )
            kept = {k: _text(row.get(k)) for k in ("address", "interface", "comment") if row.get(k)}
            revert.add(_add(menu, kept))
    for text in sorted(want):
        menu = _address_menu(text)
        cfg.put(
            menu,
            {"address": text, "interface": v.interface, "comment": tag(name)},
            Described(
                f"add {text} to {v.interface}",
                "plan.mikrotik.addressAdd",
                address=text,
                interface=v.interface,
            ),
        )
        revert.add(f"{_CLI[menu]} remove [find where address={ros_quote(text)}]")


def _remove_interface(
    cfg: _Config, row: dict[str, Any], name: str, label: str, revert: Revert
) -> None:
    """Remove an interface Signalbox created, with its peers, addresses and routes."""
    interface = _text(row.get("name"))
    for p in [p for p in cfg.static(WIREGUARD_PEERS) if _text(p.get("interface")) == interface]:
        _remove_peer(cfg, p, interface, label, revert)
    _routes(cfg, interface, name, [], label, revert)
    for menu in (IP_ADDRESS, IPV6_ADDRESS):
        for a in [a for a in cfg.static(menu) if _text(a.get("interface")) == interface]:
            text = _text(a.get("address"))
            cfg.delete(
                menu,
                a,
                Described(
                    f"remove {text} from {interface}",
                    "plan.mikrotik.addressRemove",
                    address=text,
                    interface=interface,
                ),
            )
            revert.add(_add(menu, {"address": text, "interface": interface, "comment": tag(name)}))
    cfg.delete(
        WIREGUARD,
        row,
        Described(
            f"{label}: remove the WireGuard interface {interface}",
            "plan.mikrotik.wgRemove",
            label=label,
            interface=interface,
        ),
    )
    # undone: a new interface with a new key pair (the old private key was never read)
    revert.add(_add(WIREGUARD, {k: _text(row.get(k)) for k in INTERFACE_PROPS if row.get(k)}))


def _peer_row(cfg: _Config, name: str, interface: str, keys: list[str]) -> dict[str, Any] | None:
    rows = [r for r in cfg.static(WIREGUARD_PEERS) if _text(r.get("interface")) == interface]
    mine = next((r for r in rows if tagged(r) == name), None)
    if mine is None:
        mine = next(
            (
                r
                for k in keys
                for r in rows
                if tagged(r) is None and _text(r.get("public-key")) == k
            ),
            None,
        )
    return mine


def peer(cfg: _Config, c: Change, revert: Revert) -> None:
    """The peer of the other end and the routes to its networks (``None``: remove ours)."""
    name = c.key.partition("/")[2]
    label = Label(f"tunnel {name}", "tunnel", name)
    values = [x for x in (c.new, c.old) if isinstance(x, TunnelPeerValue)]
    interface = values[0].interface
    row = _peer_row(cfg, name, interface, [x.public_key for x in values])
    v = c.new if isinstance(c.new, TunnelPeerValue) else None
    if v is None:
        if row is not None and tagged(row) == name:
            _remove_peer(cfg, row, interface, label, revert)
        _routes(cfg, interface, name, [], label, revert)
        return
    body = {
        "public-key": v.public_key,
        "allowed-address": ",".join(str(n) for n in v.allowed_ips),
    }
    if v.endpoint_host:
        body["endpoint-address"] = v.endpoint_host
        if v.endpoint_port:
            body["endpoint-port"] = str(v.endpoint_port)
    if v.keepalive is not None:
        body["persistent-keepalive"] = _seconds(v.keepalive)
    if row is None:
        created = {"interface": interface, **body, "comment": tag(name)}
        cfg.put(
            WIREGUARD_PEERS,
            created,
            Described(
                f"{label}: add the peer of the other end to {interface}",
                "plan.mikrotik.wgPeerCreate",
                label=label,
                interface=interface,
            ),
        )
        revert.add(_find(WIREGUARD_PEERS, tag(name)))
    else:
        old = {k: _text(row.get(k)) for k in body if _text(row.get(k)) != body[k]}
        if old:
            options = ", ".join(sorted(old))
            cfg.patch(
                WIREGUARD_PEERS,
                row,
                {k: body[k] for k in old},
                Described(
                    f"{label}: change the peer on {interface}: {options}",
                    "plan.mikrotik.wgPeerSet",
                    label=label,
                    interface=interface,
                    options=options,
                ),
            )
            back = {k: o for k, o in old.items() if o}
            if back:
                revert.add(_set(WIREGUARD_PEERS, row, back))
    _routes(cfg, interface, name, _routed(cfg, interface, v.allowed_ips), label, revert)


def _remove_peer(
    cfg: _Config, row: dict[str, Any], interface: str, label: str, revert: Revert
) -> None:
    cfg.delete(
        WIREGUARD_PEERS,
        row,
        Described(
            f"{label}: remove the peer from {interface}",
            "plan.mikrotik.wgPeerRemove",
            label=label,
            interface=interface,
        ),
    )
    revert.add(_add(WIREGUARD_PEERS, {k: _text(row.get(k)) for k in PEER_PROPS if row.get(k)}))


def _routed(cfg: _Config, interface: str, allowed: list[IPNetwork]) -> list[IPNetwork]:
    """The allowed networks that need a route: not a single address (the other end's tunnel
    address is on the link) and not inside the interface's own tunnel networks."""
    own = []
    for menu in (IP_ADDRESS, IPV6_ADDRESS):
        for a in cfg.rows(menu):
            if _text(a.get("interface")) == interface:
                try:
                    own.append(ip_interface(_text(a.get("address"))).network)
                except ValueError:
                    continue
    return [
        n
        for n in allowed
        if n.num_addresses > 1 and not any(n.version == o.version and n.subnet_of(o) for o in own)  # type: ignore[arg-type]
    ]


def _routes(
    cfg: _Config,
    interface: str,
    name: str,
    want: list[IPNetwork],
    label: str,
    revert: Revert,
) -> None:
    """Signalbox's routes into the interface become ``want`` (one per network); a route the
    owner already has for a network is used, not doubled."""
    left = list(want)
    for menu in (IP_ROUTE, IPV6_ROUTE):
        for row in list(cfg.static(menu)):
            if _text(row.get("gateway")) != interface:
                continue
            try:
                dst = ip_network(_text(row.get("dst-address")), strict=False)
            except ValueError:
                continue
            if dst in left:
                left.remove(dst)
                continue
            if tagged(row) != name:
                continue
            cfg.delete(
                menu,
                row,
                Described(
                    f"{label}: remove the route {dst} into {interface}",
                    "plan.mikrotik.wgRouteRemove",
                    label=label,
                    network=str(dst),
                    interface=interface,
                ),
            )
            revert.add(_add(menu, {k: _text(row.get(k)) for k in ROUTE_PROPS if row.get(k)}))
    for net in left:
        menu = _route_menu(net)
        cfg.put(
            menu,
            {"dst-address": str(net), "gateway": interface, "comment": tag(name)},
            Described(
                f"{label}: route {net} into {interface}",
                "plan.mikrotik.wgRouteAdd",
                label=label,
                network=str(net),
                interface=interface,
            ),
        )
        revert.add(f"{_CLI[menu]} remove [find where dst-address={ros_quote(str(net))}]")


# --- backup and restore -------------------------------------------------------------------------


def _keep(menu: str, row: dict[str, Any]) -> bool:
    if _flag(row.get("dynamic")) or not _text(row.get(".id")):
        return False
    return menu in (WIREGUARD, WIREGUARD_PEERS) or tagged(row) is not None


def _props(menu: str) -> tuple[str, ...]:
    return {
        WIREGUARD: INTERFACE_PROPS,
        WIREGUARD_PEERS: PEER_PROPS,
        IPV6_ADDRESS: ADDRESS_PROPS,
    }.get(menu, ROUTE_PROPS)


def backup_rows(menus: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, dict[str, str]]]:
    """What the backup keeps of the WireGuard interfaces and peers (no key: the rows come from
    :func:`signalbox.adapters.mikrotik.wireguard_rows`, and only these properties are kept) and
    of Signalbox's routes into them, by ``.id``."""
    out: dict[str, dict[str, dict[str, str]]] = {}
    for menu in MENUS:
        out[menu] = {
            _text(r.get(".id")): {k: _text(r.get(k)) for k in _props(menu) if _text(r.get(k))}
            for r in menus.get(menu) or []
            if _keep(menu, r)
        }
    return out


def restore_rows(cfg: _Config, saved: Any) -> None:
    """Put the interfaces, peers and Signalbox's routes back as the backup has them. A row
    that is gone is added again: an interface added back has a new key pair."""
    if not isinstance(saved, dict):
        return
    for menu in reversed(MENUS):  # dependants first
        want = saved.get(menu)
        if not isinstance(want, dict):
            continue
        for row in [r for r in cfg.static(menu) if _keep(menu, r)]:
            if _text(row.get(".id")) not in want:
                item = _text(row.get("name")) or _text(row.get("comment")) or menu
                cfg.delete(
                    menu,
                    row,
                    Described(
                        f"restore: remove {menu} {item}",
                        "plan.mikrotik.restoreRemove",
                        menu=menu,
                        item=item,
                    ),
                )
    for menu in MENUS:
        want = saved.get(menu)
        if not isinstance(want, dict):
            continue
        by_id = {_text(r.get(".id")): r for r in cfg.static(menu)}
        for ref, values in want.items():
            if not isinstance(values, dict):
                continue
            body = {k: str(v) for k, v in values.items() if k in _props(menu)}
            item = body.get("name") or body.get("comment") or ref
            have = by_id.get(ref)
            if have is None:
                cfg.put(
                    menu,
                    body,
                    Described(
                        f"restore: add {menu} {item}",
                        "plan.mikrotik.restoreAdd",
                        menu=menu,
                        item=item,
                    ),
                )
                continue
            cfg.patch(
                menu,
                have,
                body,
                Described(
                    f"restore: set {menu} {item} back",
                    "plan.mikrotik.restoreSet",
                    menu=menu,
                    item=item,
                ),
            )
