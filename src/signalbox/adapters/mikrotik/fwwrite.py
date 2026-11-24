"""MikroTik RouterOS 7 (write): firewall rules, port forwards and zone policies (#295, ADR 0017).

What the integration writes is tagged by its comment (``signalbox:<key>[ <name>]``, zone policies
``signalbox:policy/<from>/<to|device>``, see ``firewall.py``). Only rows with the tag are changed
or removed; the device's own rows only when the change says ``adopt`` (the row is changed in
place: it keeps its place and every property the writer does not model, e.g. ``log``); a tagged
row that is no longer declared is removed.

Mapping: a rule is a row of ``/ip/firewall/filter`` (``family: 4``) or ``/ipv6/firewall/filter``
(``family: 6``), a port forward a ``dst-nat`` row of ``/ip/firewall/nat``, a zone policy a tagged
rule on interface lists (in both filters when the router has IPv6). Zones are interface lists.
Rules go before the first row of the chain that is not Signalbox's (so the device's own default
rules do not shadow them), zone policies at the end of their chain (they are fallbacks).

Backstop: RouterOS safe mode belongs to an interactive terminal, the REST API has no session for
it. While the rows are changed a ``/system/scheduler`` entry (``signalbox-revert``) waits to run
a script that undoes exactly these changes; ``confirm`` removes it after the verification. The
script is built here, line by line, with every change (see ``Revert``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import TYPE_CHECKING, Any

from signalbox.adapters import AdapterError, Described, Label
from signalbox.adapters.mikrotik.firewall import POLICY_MARK, TAG, describe, split_mark, tagged
from signalbox.changes import Change, FirewallRuleValue, PortForwardValue, ZonePolicyValue
from signalbox.model import FirewallAction, FirewallChain, FirewallProtocol, PortRange

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters.mikrotik.write import _Config

#: Name of the scheduler entry that undoes the change unless it is confirmed.
REVERT_NAME = "signalbox-revert"
#: The policies the revert entry runs with: change the filter and NAT rows, read them (to find
#: them); nothing else.
REVERT_POLICY = "read,write"

_ACTIONS = {
    FirewallAction.ACCEPT: "accept",
    FirewallAction.DROP: "drop",
    FirewallAction.REJECT: "reject",
}
_PROTOCOL_NAMES = {
    FirewallProtocol.TCP: "tcp",
    FirewallProtocol.UDP: "udp",
    FirewallProtocol.ESP: "ipsec-esp",
    FirewallProtocol.GRE: "gre",
}
#: Properties the writer sets (and clears when a declared rule no longer has them).
_RULE_PROPS = (
    "chain",
    "action",
    "protocol",
    "in-interface-list",
    "out-interface-list",
    "src-address",
    "dst-address",
    "dst-port",
    "disabled",
    "comment",
)
_FORWARD_PROPS = (
    "chain",
    "action",
    "protocol",
    "in-interface-list",
    "dst-port",
    "to-addresses",
    "to-ports",
    "disabled",
    "comment",
)
#: Other ways to say what the declared zones and networks say (a plain interface, an address
#: list): an adopted row's are replaced by the declaration, not kept next to it.
_ALIASES = ("in-interface", "out-interface", "src-address-list", "dst-address-list")
_CLI = {
    "/rest/ip/firewall/filter": "/ip firewall filter",
    "/rest/ipv6/firewall/filter": "/ipv6 firewall filter",
    "/rest/ip/firewall/nat": "/ip firewall nat",
}


def ros_quote(text: str) -> str:
    """A string for a RouterOS script (``\\``, ``"``, ``$`` and ``?`` are special in it)."""
    out = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("?", "\\?")
    return '"' + out.replace("\n", "\\n").replace("\r", "\\r") + '"'


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


@dataclass
class Revert:
    """The script that undoes a deployment: one block per change, run in reverse order."""

    blocks: list[str] = field(default_factory=list)

    def add(self, *lines: str) -> None:
        self.blocks.append("\n".join(lines))

    def script(self) -> str:
        """The script; its last line removes the scheduler entry that runs it."""
        done = f"/system scheduler remove [find where name={ros_quote(REVERT_NAME)}]"
        return "\n".join([*reversed(self.blocks), done])

    def __bool__(self) -> bool:
        return bool(self.blocks)


def _value(menu: str, row: dict[str, Any]) -> str:
    from signalbox.adapters.mikrotik.write import _writable

    return " ".join(f"{k}={ros_quote(v)}" for k, v in _writable(menu, row).items())


def _find(comment: str) -> str:
    return f"[find where comment={ros_quote(comment)}]"


def _zone(cfg: _Config, name: str | None, label: str, what: str) -> str | None:
    """An interface list (``LAN``, ``!WAN``) as ``in-interface-list``: ``None``: any."""
    from signalbox.adapters import mikrotik as m

    if not name:
        return None
    wanted = name.removeprefix("!")
    if "," in wanted:
        raise AdapterError(
            f"{label}: give one {what}, RouterOS matches one interface list per rule",
            message_id="mikrotik.oneInterfaceList",
            params={"label": label, "what": what},
        )
    known = sorted(str(r.get("name")) for r in cfg.rows(m.INTERFACE_LIST) if r.get("name"))
    if wanted not in known:
        lists = ", ".join(known) or Label("none", "none")
        raise AdapterError(
            f"{label}: the router has no interface list {wanted!r} ({what}s are interface "
            f"lists: {lists})",
            message_id="mikrotik.noInterfaceList",
            params={"label": label, "name": repr(wanted), "what": what, "lists": lists},
        )
    return name


def _address(nets: list[Any], family: int | None, label: str, what: str) -> str | None:
    if not nets:
        return None
    if len(nets) > 1:
        raise AdapterError(
            f"{label}: give one {what} network, RouterOS matches one per rule",
            message_id="mikrotik.oneNetwork",
            params={"label": label, "what": what},
        )
    net = ip_network(nets[0], strict=False)
    if family is not None and net.version != family:
        raise AdapterError(
            f"{label}: {net} is not an IPv{family} network",
            message_id="mikrotik.wrongFamily",
            params={"label": label, "network": str(net), "family": family},
        )
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def _protocol(protocols: list[FirewallProtocol], family: int, label: str) -> str | None:
    kinds = list(dict.fromkeys(protocols))
    if not kinds:
        return None
    if len(kinds) > 1:
        names = ", ".join(sorted(p.value for p in kinds))
        raise AdapterError(
            f"{label}: RouterOS matches one protocol per rule, not {names}: declare one rule each",
            message_id="mikrotik.oneProtocol",
            params={"label": label, "protocols": names},
        )
    kind = kinds[0]
    if kind is FirewallProtocol.ICMP:
        return "icmp" if family == 4 else "icmpv6"
    found = _PROTOCOL_NAMES.get(kind)
    if found is None:
        raise AdapterError(
            f"{label}: RouterOS cannot match the protocol {kind.value} here",
            message_id="mikrotik.protocolUnsupported",
            params={"label": label, "protocol": kind.value},
        )
    return found


def _ports(ports: list[PortRange]) -> str | None:
    return ",".join(str(p) for p in ports) or None


def _clean(body: dict[str, str | None]) -> dict[str, str]:
    return {k: v for k, v in body.items() if v is not None}


# --- rows ---------------------------------------------------------------------------------------


def _ours(cfg: _Config, menus: tuple[str, ...], key: str) -> tuple[str, dict[str, Any]] | None:
    """The row Signalbox created for the rule or forward ``key`` (zone policies are tagged
    differently)."""
    for menu in menus:
        for row in cfg.static(menu):
            mark = tagged(row)
            if mark is not None and not mark.startswith(POLICY_MARK) and split_mark(mark)[0] == key:
                return menu, row
    return None


def _adopted(cfg: _Config, menu: str, name: str, what: str, label: str) -> dict[str, Any]:
    """The device's own row that a change adopts (exactly one, by its comment)."""
    own = [r for r in cfg.static(menu) if _text(r.get("comment")) == name and tagged(r) is None]
    if len(own) == 1:
        return own[0]
    found = "no" if not own else "several"
    raise AdapterError(
        f"{label}: the router has {found} {what} commented {name!r} to adopt",
        message_id="mikrotik.adoptNone" if not own else "mikrotik.adoptSeveral",
        params={"label": label, "what": what, "name": repr(name)},
    )


def _anchor(cfg: _Config, menu: str, chain: str) -> dict[str, Any] | None:
    """The row a new rule goes before: the first of the chain that is not Signalbox's."""
    return next(
        (
            r
            for r in cfg.static(menu)
            if _text(r.get("chain")) == chain and tagged(r) is None and not _flag(r.get("invalid"))
        ),
        None,
    )


def _create(
    cfg: _Config,
    menu: str,
    body: dict[str, str],
    before: dict[str, Any] | None,
    revert: Revert,
    label: str,
) -> None:
    """Add a tagged row before ``before`` (an existing row), or at the end."""
    sent = {**body, "place-before": str(before[".id"])} if before is not None else dict(body)
    row = cfg.put(menu, sent, Described(f"{label}: create", "plan.mikrotik.fwCreate", label=label))
    row.pop("place-before", None)
    rows = cfg.rows(menu)
    rows.remove(row)
    rows.insert(rows.index(before) if before is not None else len(rows), row)
    revert.add(f"{_CLI[menu]} remove {_find(body['comment'])}")


def _update(
    cfg: _Config,
    menu: str,
    row: dict[str, Any],
    want: dict[str, str],
    props: tuple[str, ...],
    revert: Revert,
    label: str,
    what: str | None = None,
) -> None:
    """Set the properties of a tagged row to ``want``; what it has and ``want`` lacks is cleared
    (of the properties the writer models; every other property of the row stays)."""
    old = {k: _text(row.get(k)) for k in props}
    comment = want["comment"]
    cfg.patch(
        menu,
        row,
        {k: v for k, v in want.items() if k in props},
        what or Described(f"{label}: update", "plan.mikrotik.fwUpdate", label=label),
    )
    undo_unset: list[str] = []
    undo_set: dict[str, str] = {}
    for k in props:
        if k in want:
            if old[k] != want[k]:
                if old[k]:
                    undo_set[k] = old[k]
                else:
                    undo_unset.append(k)
        elif old[k]:
            cfg.unset(
                menu,
                row,
                k,
                Described(f"{label}: clear {k}", "plan.mikrotik.fwClear", label=label, prop=k),
            )
            undo_set[k] = old[k]
    lines = [f"{_CLI[menu]} unset {_find(comment)} {k}" for k in undo_unset]
    if undo_set:
        values = " ".join(f"{k}={ros_quote(v)}" for k, v in undo_set.items())
        lines.append(f"{_CLI[menu]} set {_find(comment)} {values}")
    if lines:
        revert.add(*lines)


def _delete(
    cfg: _Config, menu: str, row: dict[str, Any], revert: Revert, label: str
) -> dict[str, Any] | None:
    """Delete a row; the revert adds it again before the row that followed it, found by its
    comment or, without one, by its row id (a deployment deletes only rows with a comment, so a
    row without one is still there, with the same id, when the script runs). Returns the row
    that followed it."""
    rows = cfg.rows(menu)
    after = next(
        (r for r in rows[rows.index(row) + 1 :] if not _flag(r.get("dynamic"))),
        None,
    )
    line = f"{_CLI[menu]} add {_value(menu, row)}"
    if after is not None and _text(after.get("comment")):
        line += f" place-before={_find(_text(after['comment']))}"
    elif after is not None and _text(after.get(".id")):
        line += f" place-before={_text(after['.id'])}"
    cfg.delete(menu, row, Described(f"{label}: remove", "plan.mikrotik.fwRemove", label=label))
    revert.add(line)
    return after


def _kept(
    menu: str, row: dict[str, Any], body: dict[str, str], props: tuple[str, ...]
) -> dict[str, str]:
    """The properties of an adopted row that the declaration does not model: they stay."""
    from signalbox.adapters.mikrotik.write import _writable

    return {k: v for k, v in _writable(menu, row).items() if k not in props and k not in body}


def _refuse_kept(kept: dict[str, str], body: dict[str, str], label: str) -> None:
    """A kept property the declared fields cannot live with: refuse, naming all kept ones."""
    clash = []
    if "reject-with" in kept and body.get("action") != "reject":
        clash.append("reject-with (only for reject)")
    if "jump-target" in kept:
        clash.append("jump-target (only for the action jump)")
    if {"src-port", "dst-port"} & kept.keys() and body.get("protocol") not in ("tcp", "udp"):
        clash.append("the port match (needs the protocol tcp or udp)")
    if clash:
        everything = ", ".join(f"{k}={v}" for k, v in kept.items())
        raise AdapterError(
            f"{label}: the router's row has properties the declaration does not model and "
            f"that do not fit it: {'; '.join(clash)}. Adopting would keep: {everything}. "
            "Change the declaration or the row on the router",
            message_id="mikrotik.keptClash",
            params={"label": label, "clash": "; ".join(clash), "kept": everything},
        )


def _write(
    cfg: _Config,
    menu: str,
    ours: tuple[str, dict[str, Any]] | None,
    adopted: dict[str, Any] | None,
    body: dict[str, str] | None,
    props: tuple[str, ...],
    before: dict[str, Any] | None,
    revert: Revert,
    label: str,
) -> None:
    """The calls for one rule, forward or policy: ``body`` ``None`` removes it."""
    if ours is not None and (body is None or ours[0] != menu):
        _delete(cfg, ours[0], ours[1], revert, label)
        ours = None
    if body is None:
        return
    if ours is not None:
        _update(cfg, menu, ours[1], body, props, revert, label)
        return
    if adopted is not None:
        # in place: the row keeps its position and every property the writer does not model
        props = (*props, *(a for a in _ALIASES if a not in props))
        kept = _kept(menu, adopted, body, props)
        _refuse_kept(kept, body, label)
        shown = ", ".join(f"{k}={v}" for k, v in kept.items())
        if shown:
            what: str = Described(
                f"{label}: adopt the device's own row in place (keeps {shown})",
                "plan.adoptRowKeeps",
                label=label,
                kept=shown,
            )
        else:
            what = Described(
                f"{label}: adopt the device's own row in place", "plan.adoptRow", label=label
            )
        _update(cfg, menu, adopted, body, props, revert, label, what)
        return
    _create(cfg, menu, body, before, revert, label)


# --- the three kinds ----------------------------------------------------------------------------


def firewall_rule(cfg: _Config, c: Change, revert: Revert) -> None:
    from signalbox.adapters import mikrotik as m

    key = c.key.partition("/")[2]
    label = Label(f"firewall rule {key}", "fwRule", key)
    ours = _ours(cfg, (m.FW_FILTER, m.FW_FILTER6), key)
    v = c.new if isinstance(c.new, FirewallRuleValue) else None
    if v is None:
        _write(cfg, m.FW_FILTER, ours, None, None, _RULE_PROPS, None, revert, label)
        return
    if v.family is None:
        raise AdapterError(
            f"{label}: RouterOS has separate IPv4 and IPv6 filters: "
            "give `family: 4` or `family: 6`",
            message_id="mikrotik.familyNeeded",
            params={"label": label},
        )
    menu = m.FW_FILTER if v.family == 4 else m.FW_FILTER6
    if v.chain not in (FirewallChain.INPUT, FirewallChain.FORWARD):  # pragma: no cover
        raise AdapterError(
            f"{label}: rules for the router's own traffic are not written",
            message_id="write.ownTraffic",
            params={"subject": label},
        )
    if v.chain is FirewallChain.INPUT and v.destination_zone:
        raise AdapterError(
            f"{label}: a rule to the router itself has no destination zone (RouterOS refuses "
            "out-interface in the input chain)",
            message_id="mikrotik.inputNoDestination",
            params={"label": label},
        )
    protocol = _protocol(v.protocols, v.family, label)
    ports = _ports(v.destination_ports)
    if ports and protocol not in ("tcp", "udp"):
        raise AdapterError(
            f"{label}: ports need the protocol tcp or udp",
            message_id="write.portProtocol",
            params={"subject": label, "protocols": "tcp or udp"},
        )
    body = _clean(
        {
            "chain": v.chain.value,
            "action": _ACTIONS[v.action],
            "protocol": protocol,
            "in-interface-list": _zone(
                cfg, v.source_zone, label, Label("source zone", "sourceZone")
            ),
            "out-interface-list": _zone(
                cfg, v.destination_zone, label, Label("destination zone", "destinationZone")
            ),
            "src-address": _address(
                v.source_networks, v.family, label, Label("source", "sourceSide")
            ),
            "dst-address": _address(
                v.destination_networks, v.family, label, Label("destination", "destinationSide")
            ),
            "dst-port": ports,
            "disabled": "false" if v.enabled else "true",
            "comment": describe(key, v.name),
        }
    )
    adopted = None
    if ours is None and c.adopt:
        adopted = _adopted(cfg, menu, c.adopt, "rule", label)
    _write(
        cfg,
        menu,
        ours,
        adopted,
        body,
        _RULE_PROPS,
        _anchor(cfg, menu, v.chain.value),
        revert,
        label,
    )


def zone_policy(cfg: _Config, c: Change, revert: Revert) -> None:
    from signalbox.adapters import mikrotik as m

    _, source, dest_text = c.key.split("/", 2)
    dest = None if dest_text == "device" else dest_text
    label = Label(f"zone policy {source} to {dest_text}", "zonePolicy", source, dest_text)
    mark = f"{TAG}{POLICY_MARK}{source}/{dest_text}"
    new = c.new if isinstance(c.new, ZonePolicyValue) else None
    menus = [m.FW_FILTER]
    # the IPv6 filter gets the same rule when the router has the package
    if m.FW_FILTER6 not in cfg.absent:
        menus.append(m.FW_FILTER6)
    if new is not None:
        _zone(cfg, source, label, Label("zone", "zone"))
        if dest is not None:
            _zone(cfg, dest, label, Label("zone", "zone"))
    chain = "input" if dest is None else "forward"
    for menu in (m.FW_FILTER, m.FW_FILTER6):
        row = next((r for r in cfg.static(menu) if _text(r.get("comment")) == mark), None)
        ours = (menu, row) if row is not None else None
        if menu not in menus and ours is None:
            continue
        body = None
        # the chains accept what no rule matches: an accepting policy is having no rule of ours
        if new is not None and new.action is not FirewallAction.ACCEPT:
            body = _clean(
                {
                    "chain": chain,
                    "action": _ACTIONS[new.action],
                    "in-interface-list": source,
                    "out-interface-list": dest,
                    "disabled": "false",
                    "comment": mark,
                }
            )
        # a fallback: at the end of the chain, after everything else
        _write(cfg, menu, ours, None, body, _POLICY_PROPS, None, revert, label)


_POLICY_PROPS = (
    "chain",
    "action",
    "in-interface-list",
    "out-interface-list",
    "disabled",
    "comment",
)


def port_forward(cfg: _Config, c: Change, revert: Revert) -> None:
    from signalbox.adapters import mikrotik as m

    key = c.key.partition("/")[2]
    label = Label(f"port forward {key}", "portForward", key)
    ours = _ours(cfg, (m.FW_NAT,), key)
    v = c.new if isinstance(c.new, PortForwardValue) else None
    if v is None:
        _write(cfg, m.FW_NAT, ours, None, None, _FORWARD_PROPS, None, revert, label)
        return
    protocol = _protocol(v.protocols, 4, label)
    if protocol not in ("tcp", "udp"):
        raise AdapterError(
            f"{label}: a port forward needs the protocol tcp or udp",
            message_id="write.forwardProtocol",
            params={"subject": label, "protocols": "tcp or udp"},
        )
    if len(v.external_ports) != 1:
        raise AdapterError(
            f"{label}: give one external port or one range",
            message_id="write.oneExternalPort",
            params={"subject": label},
        )
    if v.target_address.version != 4:
        raise AdapterError(
            f"{label}: only IPv4 targets are written",
            message_id="write.ipv4TargetsOnly",
            params={"subject": label},
        )
    external = v.external_ports[0]
    to_ports = None
    if v.target_port is not None:
        last = v.target_port + external.last - external.start
        to_ports = str(v.target_port) if last == v.target_port else f"{v.target_port}-{last}"
    body = _clean(
        {
            "chain": "dstnat",
            "action": "dst-nat",
            "protocol": protocol,
            "in-interface-list": _zone(cfg, v.zone, label, Label("zone", "zone")),
            "dst-port": str(external),
            "to-addresses": str(v.target_address),
            "to-ports": to_ports,
            "disabled": "false" if v.enabled else "true",
            "comment": describe(key, v.name),
        }
    )
    adopted = None
    if ours is None and c.adopt:
        adopted = _adopted(cfg, m.FW_NAT, c.adopt, "port forward", label)
    _write(
        cfg,
        m.FW_NAT,
        ours,
        adopted,
        body,
        _FORWARD_PROPS,
        _anchor(cfg, m.FW_NAT, "dstnat"),
        revert,
        label,
    )
