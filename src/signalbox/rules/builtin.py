"""The rules that ship with Signalbox (registered as the ``builtin`` entry point)."""

from __future__ import annotations

from signalbox.rules import Rule
from signalbox.rules.dhcp import RULES as DHCP_RULES
from signalbox.rules.vlan import RULES as VLAN_RULES
from signalbox.rules.wireless import RULES as WIRELESS_RULES
from signalbox.topology import RULES as TOPOLOGY_RULES

RULES: list[Rule] = [*DHCP_RULES, *WIRELESS_RULES, *VLAN_RULES, *TOPOLOGY_RULES]
