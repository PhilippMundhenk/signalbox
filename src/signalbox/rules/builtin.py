"""The rules that ship with Signalbox (registered as the ``builtin`` entry point)."""

from __future__ import annotations

from signalbox.rules import Rule
from signalbox.rules.dhcp import RULES as DHCP_RULES
from signalbox.rules.vlan import RULES as VLAN_RULES
from signalbox.rules.wireless import RULES as WIRELESS_RULES

RULES: list[Rule] = [*VLAN_RULES]
RULES += DHCP_RULES
RULES += WIRELESS_RULES
