"""What to run on an OpenWrt router once so Signalbox can read it (shown in the device form).

``READ_ACL`` must equal the read-only ACL in docs/adapters/openwrt.md (checked by a test), which
the integration test image installs, so the commands users paste are the tested ones.
"""

from __future__ import annotations

import json
from typing import Any

READ_ACL: dict[str, Any] = {
    "signalbox": {
        "description": "Signalbox: read-only network inventory",
        "read": {
            "ubus": {
                "system": ["board", "info"],
                "network.device": ["status"],
                "network.interface": ["dump"],
                "network.wireless": ["status"],
                "uci": ["get"],
                "hostapd.*": ["get_clients"],
                "luci-rpc": ["getDHCPLeases", "getWirelessDevices", "getNetworkDevices"],
                "luci": ["getFeatures"],
                "rpc-sys": ["packagelist"],
                "file": ["read"],
                "luci.lldpd": ["getStatus"],
                "luci.wireguard": ["getWgInstances"],
            },
            "uci": [
                "network",
                "wireless",
                "dhcp",
                "system",
                "dropbear",
                "uhttpd",
                "firewall",
                "snmpd",
                "luci_statistics",
                "softflowd",
                "rpcd",
            ],
            "file": {
                "/tmp/dhcp.leases": ["read"],
                "/sys/class/thermal/thermal_zone*/temp": ["read"],
                "/sys/class/thermal/thermal_zone*/type": ["read"],
            },
        },
    }
}

#: The ACL with write access of docs/adapters/openwrt.md ("Login with write access").
WRITE_ACL: dict[str, Any] = {
    "signalbox": {
        "description": (
            "Signalbox: network inventory, changes to network, wireless, dhcp and firewall"
        ),
        "read": READ_ACL["signalbox"]["read"],
        "write": {
            "ubus": {
                "uci": [
                    "set",
                    "add",
                    "delete",
                    "order",
                    "revert",
                    "changes",
                    "apply",
                    "confirm",
                    "rollback",
                ]
            },
            "uci": ["network", "wireless", "dhcp", "firewall"],
        },
    }
}

PACKAGES = "uhttpd uhttpd-mod-ubus rpcd rpcd-mod-file rpcd-mod-luci"
#: Optional: LLDP neighbours (ubus object ``luci.lldpd``), installed by *Fix it* (#215).
LLDP_PACKAGES = "lldpd luci-app-lldpd"


def commands() -> str:
    """Shell commands for the router (OpenWrt 24.10 with opkg, 25.12 and later with apk)."""
    acl = json.dumps(READ_ACL, indent=2)
    return f"""# 1. packages Signalbox reads through (most come with LuCI)
if command -v apk >/dev/null; then apk update && apk add {PACKAGES}
else opkg update && opkg install {PACKAGES}; fi
# 2. Signalbox's read-only permissions
cat > /usr/share/rpcd/acl.d/signalbox.json <<'END'
{acl}
END
# 3. a login of its own: replace CHOOSE-A-PASSWORD (root also works after step 2)
uci add rpcd login
uci set rpcd.@login[-1].username='signalbox'
uci set rpcd.@login[-1].password="$(uhttpd -m 'CHOOSE-A-PASSWORD')"
uci add_list rpcd.@login[-1].read='signalbox'
uci commit rpcd
service rpcd restart
# optional: LLDP shows which device is plugged into which port
#   apk add lldpd luci-app-lldpd   (24.10: opkg install lldpd luci-app-lldpd)
"""
