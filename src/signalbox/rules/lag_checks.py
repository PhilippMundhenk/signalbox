"""Link aggregation rules that need the LAG details of #157 (ADR 0022): the mode of both ends,
the LACP state of the members and their LACP partners.

Members, speeds, VLANs and whether the far end forms a LAG at all are checked by
``lag.consistent`` (:mod:`signalbox.rules.topology_checks`). The rules here stay quiet where a
device does not report the mode or the LACP state (``None``), which is the case for most
switches without LACP.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import LagGroup, LagMode, Network, Port
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import device_name

#: How a mode is named in findings.
MODE_NAMES = {
    LagMode.STATIC: "static",
    LagMode.LACP_ACTIVE: "LACP (active)",
    LagMode.LACP_PASSIVE: "LACP (passive)",
    LagMode.ACTIVE_BACKUP: "active-backup",
    LagMode.BALANCE_RR: "balance-rr",
    LagMode.BALANCE_XOR: "balance-xor",
    LagMode.BROADCAST: "broadcast",
    LagMode.BALANCE_TLB: "balance-tlb",
    LagMode.BALANCE_ALB: "balance-alb",
    LagMode.OTHER: "other",
}


def _label(net: Network, group: LagGroup, device: str) -> str:
    return f"{device_name(net, device)} {group.name}"


def _peers(net: Network) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for link in net.links:
        out.setdefault(link.a, []).append(link.b)
        out.setdefault(link.b, []).append(link.a)
    return out


def _far_group(
    net: Network,
    group: LagGroup,
    device: str,
    peers: dict[str, list[str]],
    lag_of: dict[str, tuple[str, str]],
) -> tuple[str, str] | None:
    """The one LAG all known cables of ``group`` end in on one other device; None when the
    far end is unknown, not a LAG or several (``lag.consistent`` reports those)."""
    far: set[tuple[str, str] | None] = set()
    for m in group.members:
        for r in peers.get(m.id, []):
            port = net.port(r)
            if port is not None and port.device_id != device:
                far.add(lag_of.get(r))
    if len(far) != 1:
        return None
    return far.pop()


def _mismatch(a: LagMode, b: LagMode) -> bool:
    """Two ends that do not form one LAG: LACP against a static mode, two passive LACP ends,
    or a mode that needs no LAG on the far end against one that does."""
    if LagMode.OTHER in (a, b):
        return False
    if a.lacp != b.lacp:
        return True
    if a is LagMode.LACP_PASSIVE and b is LagMode.LACP_PASSIVE:
        return True
    return a.needs_far_lag != b.needs_far_lag


@rule(
    "lag.mode-mismatch",
    "The two ends of a link aggregation use different modes",
    Severity.ERROR,
    "Both ends of a LAG must agree on how it works: LACP on both (at least one of them "
    "active), or static on both. LACP on one end and a static LAG on the other forms no "
    "aggregation on the LACP side and sends frames over every cable on the static side: "
    "loops, duplicated frames or silent loss follow. Two passive LACP ends never start. A "
    "Linux bond in active-backup, balance-tlb or balance-alb mode works towards single "
    "switch ports, not towards a LAG. Checked where both devices report the mode and every "
    "known cable of the LAG ends in one LAG of one other device.",
)
def mode_mismatch(net: Network) -> Iterator[Result]:
    groups = net.lag_groups()
    lag_of = {m.id: key for key, g in groups.items() for m in g.members}
    peers = _peers(net)
    for (dev, name), group in groups.items():
        far_key = _far_group(net, group, dev, peers, lag_of)
        if far_key is None or far_key < (dev, name):
            continue  # unknown, or reported from the other end
        far = groups[far_key]
        a, b = group.mode, far.mode
        if a is None or b is None or not _mismatch(a, b):
            continue
        here, there = _label(net, group, dev), _label(net, far, far_key[0])
        yield found(
            f"{here} is {MODE_NAMES[a]}, but the other end {there} is {MODE_NAMES[b]}.",
            [dev, far_key[0], *(p.id for p in (group.port, far.port) if p is not None)],
            fix="Set both ends to LACP (at least one of them active) or both to a static LAG.",
            key=f"{dev}\x00{name}",
            mid="lag.modeMismatch",
            fix_id="lag.modeMismatch.fix",
            params={"lag": here, "mode": MODE_NAMES[a], "far": there, "farMode": MODE_NAMES[b]},
        )


def _lacp_members(net: Network) -> Iterator[tuple[str, LagGroup, Port]]:
    for (dev, _), group in net.lag_groups().items():
        if group.mode is not None and not group.mode.lacp:
            continue
        for m in group.members:
            yield dev, group, m


@rule(
    "lag.member-not-selected",
    "A LAG member is up but does not carry traffic",
    Severity.WARNING,
    "LACP aggregates a member only when the far end answers on that cable with the same "
    "system and key as on the other members. A member that is up but not collecting and "
    "distributing usually goes to the wrong device or port, or its far end is not in the "
    "LAG, or it runs at another speed or duplex. The LAG works without it, with less "
    "bandwidth and no redundancy for that cable. Checked where the device reports the LACP "
    "state of its members.",
)
def member_not_selected(net: Network) -> Iterator[Result]:
    for dev, group, m in _lacp_members(net):
        state = m.lag_member_state
        if m.up is not True or state is None:
            continue
        if group.mode is None and state.collecting_distributing is None:
            continue  # not known to be LACP (a backup member of active-backup is normal)
        if state.collecting_distributing is not False and state.selected is not False:
            continue
        label = _label(net, group, dev)
        yield found(
            f"{label}: member {m.label()} is up but LACP does not aggregate it.",
            [dev, m.id, *([group.port.id] if group.port is not None else [])],
            fix=f"Check that the cable of {m.name} goes to the same device as the other "
            "members, and that the port there is in the same LACP LAG with the same speed.",
            key=m.id,
            mid="lag.memberNotSelected",
            fix_id="lag.memberNotSelected.fix",
            params={"lag": label, "port": m.label(), "name": m.name},
        )


@rule(
    "lag.partner-mismatch",
    "The members of a LAG lead to different LACP partners",
    Severity.WARNING,
    "Every member of one LAG must reach the same LACP partner: the same system (its system "
    "MAC address) and the same key. Members with different partners are cabled to two "
    "devices, or to ports of two LAGs on the far end; LACP then uses only the members of one "
    "partner. Switch stacks and MLAG pairs present one system id and do not trigger this. "
    "Checked where the device reports the partner of its members.",
)
def partner_mismatch(net: Network) -> Iterator[Result]:
    for (dev, name), group in net.lag_groups().items():
        partners: dict[tuple[str, int | None], list[Port]] = {}
        for m in group.members:
            st = m.lag_member_state
            if st is None or st.partner_system_id is None:
                continue
            partners.setdefault((st.partner_system_id, st.partner_key), []).append(m)
        if len(partners) < 2:
            continue
        label = _label(net, group, dev)
        text = "; ".join(
            f"{', '.join(p.name for p in ports)}: {system}"
            + (f" key {key}" if key is not None else "")
            for (system, key), ports in sorted(partners.items(), key=lambda i: str(i[0]))
        )
        yield found(
            f"{label}: the members reach different LACP partners ({text}).",
            [dev, *group.member_ids],
            fix="Connect all members to ports of one LAG on one device (or one switch stack).",
            key=f"{dev}\x00{name}",
            mid="lag.partnerMismatch",
            fix_id="lag.partnerMismatch.fix",
            params={"lag": label, "partners": text},
        )


RULES: list[Rule] = [mode_mismatch, member_not_selected, partner_mismatch]
