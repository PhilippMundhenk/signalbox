"""The OIDs the adapter reads (numeric: no MIB files are needed).

Every one is read-only data of a standard MIB: SNMPv2-MIB, ENTITY-MIB, IF-MIB, EtherLike-MIB,
BRIDGE-MIB, RSTP-MIB, Q-BRIDGE-MIB, LLDP-MIB and IEEE8023-LAG-MIB.
"""

from __future__ import annotations

# SNMPv2-MIB (system group)
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"  # TimeTicks, hundredths of a second
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# ENTITY-MIB entPhysicalEntry
ENT_PHYSICAL = "1.3.6.1.2.1.47.1.1.1.1"
ENT_DESCR, ENT_CLASS, ENT_NAME = 2, 5, 7
ENT_HARDWARE_REV, ENT_FIRMWARE_REV, ENT_SOFTWARE_REV = 8, 9, 10
ENT_SERIAL, ENT_MFG, ENT_MODEL = 11, 12, 13
ENT_CLASS_CHASSIS = 3

# IF-MIB ifTable / ifXTable
IF_TABLE = "1.3.6.1.2.1.2.2.1"
IF_DESCR, IF_TYPE, IF_MTU, IF_SPEED, IF_PHYS, IF_ADMIN, IF_OPER = 2, 3, 4, 5, 6, 7, 8
IF_X_TABLE = "1.3.6.1.2.1.31.1.1.1"
IF_NAME, IF_HIGH_SPEED, IF_ALIAS = 1, 15, 18
# counters: ifTable (32 bit: octets, unicast packets, discards, errors; in then out) and ifXTable
# (64 bit "HC" counters, multicast and broadcast packets)
IF_IN_OCTETS, IF_IN_UCAST, IF_IN_DISCARDS, IF_IN_ERRORS = 10, 11, 13, 14
IF_OUT_OCTETS, IF_OUT_UCAST, IF_OUT_DISCARDS, IF_OUT_ERRORS = 16, 17, 19, 20
IF_IN_MCAST, IF_IN_BCAST, IF_OUT_MCAST, IF_OUT_BCAST = 2, 3, 12, 13
IF_HC_IN_OCTETS, IF_HC_IN_UCAST, IF_HC_IN_MCAST, IF_HC_IN_BCAST = 6, 7, 8, 9
IF_HC_OUT_OCTETS, IF_HC_OUT_UCAST, IF_HC_OUT_MCAST, IF_HC_OUT_BCAST = 10, 11, 12, 13
IF_STACK_STATUS = "1.3.6.1.2.1.31.1.2.1.3"  # index: higher.lower

# EtherLike-MIB dot3StatsDuplexStatus (index: ifIndex): 2 half, 3 full
DOT3_DUPLEX = "1.3.6.1.2.1.10.7.2.1.19"

# EtherLike-MIB dot3StatsFCSErrors (index: ifIndex): frames received with a bad checksum
DOT3_FCS_ERRORS = "1.3.6.1.2.1.10.7.2.1.3"

# BRIDGE-MIB
BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1.0"
BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # bridge port -> ifIndex
STP_PROTOCOL = "1.3.6.1.2.1.17.2.1.0"  # 3: IEEE 802.1D
STP_PRIORITY = "1.3.6.1.2.1.17.2.2.0"
STP_TOP_CHANGES = "1.3.6.1.2.1.17.2.4.0"
STP_DESIGNATED_ROOT = "1.3.6.1.2.1.17.2.5.0"  # 8 octets: priority, MAC
STP_ROOT_COST = "1.3.6.1.2.1.17.2.6.0"
STP_ROOT_PORT = "1.3.6.1.2.1.17.2.7.0"
STP_VERSION = "1.3.6.1.2.1.17.2.16.0"  # RSTP-MIB: 0 STP compatible, 2 RSTP
STP_PORT_TABLE = "1.3.6.1.2.1.17.2.15.1"
STP_PORT_STATE, STP_PORT_ENABLE, STP_PORT_PATH_COST = 3, 4, 5
RSTP_PORT_TABLE = "1.3.6.1.2.1.17.2.19.1"
RSTP_PORT_OPER_EDGE = 3
# dot1dTpFdbTable (index: MAC)
TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
TP_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"

# Q-BRIDGE-MIB
VLAN_STATIC = "1.3.6.1.2.1.17.7.1.4.3.1"  # index: VLAN
VLAN_NAME, VLAN_EGRESS, VLAN_FORBIDDEN, VLAN_UNTAGGED = 1, 2, 3, 4
VLAN_CURRENT = "1.3.6.1.2.1.17.7.1.4.2.1"  # index: time mark.VLAN
VLAN_CURRENT_EGRESS, VLAN_CURRENT_UNTAGGED = 4, 5
PORT_VLAN = "1.3.6.1.2.1.17.7.1.4.5.1"  # index: bridge port
PVID, ACCEPTABLE_FRAMES, INGRESS_FILTER = 1, 2, 3
Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # index: FDB id.MAC
Q_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"

# LLDP-MIB (iso.0.8802.1.1.2)
LLDP_LOC_CHASSIS = "1.0.8802.1.1.2.1.3.2.0"
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"  # index: local port number
LLDP_LOC_PORT_SUBTYPE, LLDP_LOC_PORT_ID, LLDP_LOC_PORT_DESC = 2, 3, 4
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"  # index: time mark.local port.remote index
REM_CHASSIS_SUBTYPE, REM_CHASSIS_ID, REM_PORT_SUBTYPE, REM_PORT_ID = 4, 5, 6, 7
REM_PORT_DESC, REM_SYS_NAME, REM_SYS_DESC, REM_CAP_SUPPORTED, REM_CAP_ENABLED = 8, 9, 10, 11, 12
LLDP_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1.3"  # index: ...remote index.subtype.length.address

# IEEE8023-LAG-MIB
LAG_AGG = "1.2.840.10006.300.43.1.1.1.1"  # index: aggregator ifIndex
LAG_PORT = "1.2.840.10006.300.43.1.2.1.1"  # index: member ifIndex
LAG_PORT_ADMIN_STATE, LAG_PORT_OPER_STATE = 21, 22
LAG_PORT_SELECTED, LAG_PORT_ATTACHED = 12, 13
LAG_PORT_PARTNER_SYSTEM, LAG_PORT_PARTNER_KEY, LAG_PORT_PARTNER_PORT = 9, 11, 17

# POWER-ETHERNET-MIB (RFC 3621)
PETH_PORT = "1.3.6.1.2.1.105.1.1.1"  # index: group.port
PETH_PORT_ADMIN, PETH_PORT_DETECTION, PETH_PORT_PRIORITY, PETH_PORT_CLASS = 3, 6, 7, 10
PETH_MAIN = "1.3.6.1.2.1.105.1.3.1.1"  # index: group
PETH_MAIN_POWER, PETH_MAIN_CONSUMPTION = 2, 4  # watts

#: enterprise numbers (under 1.3.6.1.4.1) of common switch vendors: the vendor name when the
#: device does not say it in ENTITY-MIB
ENTERPRISES = {
    9: "Cisco",
    11: "HPE",
    171: "D-Link",
    674: "Dell",
    890: "Zyxel",
    1916: "Extreme Networks",
    2011: "Huawei",
    2021: "net-snmp",
    2636: "Juniper",
    4526: "NETGEAR",
    6486: "Alcatel-Lucent",
    11863: "TP-Link",
    14988: "MikroTik",
    25506: "H3C",
    30065: "Arista",
    41112: "Ubiquiti",
}
