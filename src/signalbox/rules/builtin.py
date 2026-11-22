"""The rules that ship with Signalbox (registered as the ``builtin`` entry point)."""

from __future__ import annotations

from signalbox.rules import Rule
from signalbox.rules.addressing import RULES as ADDRESSING_RULES
from signalbox.rules.clients import RULES as CLIENT_RULES
from signalbox.rules.dhcp import RULES as DHCP_RULES
from signalbox.rules.dns import RULES as DNS_RULES
from signalbox.rules.firmware import RULES as FIRMWARE_RULES
from signalbox.rules.health import RULES as HEALTH_RULES
from signalbox.rules.history_checks import RULES as HISTORY_RULES
from signalbox.rules.ipv6 import RULES as IPV6_RULES
from signalbox.rules.networks import RULES as NETWORK_RULES
from signalbox.rules.time_checks import RULES as TIME_RULES
from signalbox.rules.topology_checks import RULES as TOPOLOGY_CHECK_RULES
from signalbox.rules.vlan import RULES as VLAN_RULES
from signalbox.rules.wifi_hygiene import RULES as WIFI_HYGIENE_RULES
from signalbox.rules.wireless import RULES as WIRELESS_RULES
from signalbox.topology import RULES as TOPOLOGY_RULES

RULES: list[Rule] = [
    *DHCP_RULES,
    *WIRELESS_RULES,
    *VLAN_RULES,
    *TOPOLOGY_RULES,
    *FIRMWARE_RULES,
    *IPV6_RULES,
    *DNS_RULES,
    *CLIENT_RULES,
    *WIFI_HYGIENE_RULES,
    *ADDRESSING_RULES,
    *TOPOLOGY_CHECK_RULES,
    *HISTORY_RULES,
    *NETWORK_RULES,
    *HEALTH_RULES,
    *TIME_RULES,
]
