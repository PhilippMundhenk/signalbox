"""The Linux bonding driver's view of a LAG, shared by the Linux and OpenWrt integrations (#157).

Two sources say the same thing: ``/proc/net/bonding/<bond>`` (one text file per bond, read
by the Linux integration's script) and the sysfs attributes ``/sys/class/net/<bond>/bonding/*``
and ``/sys/class/net/<member>/bonding_slave/*`` (one value per file, read by OpenWrt through
rpcd ``file read``). Both are mapped here onto :class:`Bond`, which the integrations copy into
the LAG port (``lag_mode``, ``hash_policy``, ``min_links``, ``lacp_rate``) and its members
(``Port.lag``, ``lag_member_state``).

Mode names are the kernel's (``Documentation/networking/bonding.rst``): ``balance-rr``,
``active-backup``, ``balance-xor``, ``broadcast``, ``802.3ad``, ``balance-tlb``,
``balance-alb``. A member collects and distributes when bits 4 and 5 of its own (actor) LACP
port state are set (IEEE 802.1AX: activity 0, timeout 1, aggregation 2, synchronization 3,
collecting 4, distributing 5, defaulted 6, expired 7).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from signalbox.model import LacpRate, LagHashPolicy, LagMemberState, LagMode, normalise_mac

#: Kernel mode names -> model (802.3ad depends on ``lacp_active``).
MODES = {
    "balance-rr": LagMode.BALANCE_RR,
    "active-backup": LagMode.ACTIVE_BACKUP,
    "balance-xor": LagMode.BALANCE_XOR,
    "broadcast": LagMode.BROADCAST,
    "balance-tlb": LagMode.BALANCE_TLB,
    "balance-alb": LagMode.BALANCE_ALB,
}
#: The texts of ``Bonding Mode:`` in /proc/net/bonding -> kernel mode names.
_PROC_MODES = {
    "load balancing (round-robin)": "balance-rr",
    "fault-tolerance (active-backup)": "active-backup",
    "load balancing (xor)": "balance-xor",
    "fault-tolerance (broadcast)": "broadcast",
    "ieee 802.3ad dynamic link aggregation": "802.3ad",
    "transmit load balancing": "balance-tlb",
    "adaptive load balancing": "balance-alb",
}
HASHES = {
    "layer2": LagHashPolicy.L2,
    "layer2+3": LagHashPolicy.L2_L3,
    "layer3+4": LagHashPolicy.L3_L4,
}
#: Actor port state bits: collecting and distributing.
COLLECTING_DISTRIBUTING = 0x10 | 0x20
_NO_PARTNER = "00:00:00:00:00:00"


@dataclass
class Member:
    name: str
    aggregator: int | None = None
    #: ``active`` / ``backup`` (sysfs ``state``), or None
    state: str | None = None
    actor_state: int | None = None
    partner_mac: str | None = None
    partner_port: int | None = None
    partner_key: int | None = None


@dataclass
class Bond:
    name: str
    mode: str | None = None  # kernel mode name
    hash_policy: str | None = None
    lacp_rate: str | None = None
    lacp_active: bool | None = None
    min_links: int | None = None
    active_aggregator: int | None = None
    active_member: str | None = None
    partner_mac: str | None = None
    members: dict[str, Member] = field(default_factory=dict)

    def lag_mode(self) -> LagMode | None:
        if self.mode is None:
            return None
        if self.mode == "802.3ad":
            return LagMode.LACP_PASSIVE if self.lacp_active is False else LagMode.LACP_ACTIVE
        return MODES.get(self.mode, LagMode.OTHER)

    def hash(self) -> LagHashPolicy | None:
        if self.hash_policy is None or self.mode not in ("802.3ad", "balance-xor", "balance-tlb"):
            return None
        return HASHES.get(self.hash_policy, LagHashPolicy.OTHER)

    def rate(self) -> LacpRate | None:
        if self.mode != "802.3ad" or self.lacp_rate not in ("slow", "fast"):
            return None
        return LacpRate(self.lacp_rate)

    def details(self) -> dict[str, object]:
        """The LAG port's fields (``None`` values left out)."""
        out = {
            "lag_mode": self.lag_mode(),
            "hash_policy": self.hash(),
            "min_links": self.min_links if self.mode == "802.3ad" else None,
            "lacp_rate": self.rate(),
        }
        return {k: v for k, v in out.items() if v is not None}

    def member_state(self, name: str) -> LagMemberState | None:
        m = self.members.get(name)
        if m is None:
            return None
        if self.mode == "802.3ad":
            selected = (
                None
                if m.aggregator is None or self.active_aggregator is None
                else m.aggregator == self.active_aggregator
            )
            cd = (
                None
                if m.actor_state is None
                else m.actor_state & COLLECTING_DISTRIBUTING == COLLECTING_DISTRIBUTING
            )
            partner = m.partner_mac or (self.partner_mac if selected else None)
            return LagMemberState(
                selected=selected,
                collecting_distributing=cd,
                partner_system_id=_mac(partner),
                partner_port=m.partner_port if _mac(partner) else None,
                partner_key=m.partner_key if _mac(partner) else None,
            )
        if self.mode == "active-backup":
            if self.active_member is not None:
                return LagMemberState(selected=name == self.active_member)
            if m.state in ("active", "backup"):
                return LagMemberState(selected=m.state == "active")
        return None


def _mac(value: str | None) -> str | None:
    if not value or value == _NO_PARTNER:
        return None
    try:
        return normalise_mac(value)
    except ValueError:
        return None


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    word = value.strip().split(" ")[0]
    return int(word) if word.isdigit() else None


def _word(value: str | None) -> str | None:
    """First word of a sysfs value (``802.3ad 4`` -> ``802.3ad``)."""
    if value is None:
        return None
    words = value.split()
    return words[0] if words else None


def parse_proc(name: str, text: str) -> Bond:
    """``/proc/net/bonding/<name>``."""
    bond = Bond(name)
    member: Member | None = None
    section = ""  # "", "active", "actor", "partner"
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        key, sep, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not sep:
            continue
        if key == "slave interface":
            member = bond.members.setdefault(value, Member(value))
            section = ""
            continue
        if key in ("details actor lacp pdu", "details partner lacp pdu"):
            section = "actor" if "actor" in key else "partner"
            continue
        if key == "active aggregator info":
            section = "active"
            continue
        if member is None:
            if key == "bonding mode":
                bond.mode = _PROC_MODES.get(value.lower(), value.lower() or None)
            elif key == "transmit hash policy":
                bond.hash_policy = _word(value)
            elif key == "lacp rate":
                bond.lacp_rate = _word(value)
            elif key == "lacp active":
                bond.lacp_active = value.lower() in ("on", "1")
            elif key == "min links":
                bond.min_links = _int(value)
            elif key == "currently active slave" and value.lower() != "none":
                bond.active_member = value
            elif section == "active" and key == "aggregator id":
                bond.active_aggregator = _int(value)
            elif section == "active" and key == "partner mac address":
                bond.partner_mac = value
            continue
        if section == "" and key == "aggregator id":
            member.aggregator = _int(value)
        elif section == "actor" and key == "port state":
            member.actor_state = _int(value)
        elif section == "partner" and key == "system mac address":
            member.partner_mac = value
        elif section == "partner" and key == "port number":
            member.partner_port = _int(value)
        elif section == "partner" and key == "oper key":
            member.partner_key = _int(value)
    return bond


def parse_sysfs(name: str, values: dict[str, str], members: dict[str, dict[str, str]]) -> Bond:
    """``/sys/class/net/<name>/bonding/<attr>`` values by attribute and the members'
    ``bonding_slave/<attr>`` values by member name and attribute (missing files left out)."""
    lacp_active = _word(values.get("lacp_active"))
    bond = Bond(
        name,
        mode=_word(values.get("mode")),
        hash_policy=_word(values.get("xmit_hash_policy")),
        lacp_rate=_word(values.get("lacp_rate")),
        lacp_active=None if lacp_active is None else lacp_active in ("on", "1"),
        min_links=_int(values.get("min_links")),
        active_aggregator=_int(values.get("ad_aggregator")),
        active_member=_word(values.get("active_slave")),
        partner_mac=_word(values.get("ad_partner_mac")),
    )
    names = (values.get("slaves") or "").split() or sorted(members)
    for member in names:
        attrs = members.get(member, {})
        bond.members[member] = Member(
            member,
            aggregator=_int(attrs.get("ad_aggregator_id")),
            state=_word(attrs.get("state")),
            actor_state=_int(attrs.get("ad_actor_oper_port_state")),
        )
    return bond


#: sysfs attributes of a bond and of its members that OpenWrt reads.
BOND_ATTRS = (
    "mode",
    "xmit_hash_policy",
    "lacp_rate",
    "lacp_active",
    "min_links",
    "slaves",
    "ad_aggregator",
    "ad_partner_mac",
    "active_slave",
)
MEMBER_ATTRS = ("state", "ad_aggregator_id", "ad_actor_oper_port_state")

_BOND_FILE = re.compile(r"^/proc/net/bonding/([^/]+)$")


def bond_name(path: str) -> str | None:
    """``/proc/net/bonding/bond0`` -> ``bond0``."""
    found = _BOND_FILE.match(path)
    return found.group(1) if found else None
