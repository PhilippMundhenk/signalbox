"""The rules that ship with Signalbox (registered as the ``builtin`` entry point)."""

from __future__ import annotations

from signalbox.rules import Rule
from signalbox.rules.vlan import RULES as VLAN_RULES

RULES: list[Rule] = [*VLAN_RULES]
