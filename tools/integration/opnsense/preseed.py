"""Preseed /conf/config.xml of the OPNsense test VM (runs ON the firewall, its own python3).

    python3 preseed.py /conf/config.xml seed.json

Sets the interface assignment (WAN vtnet0 by DHCP, LAN vtnet1 192.0.2.1/24 and
2001:db8:1::1/64, VLAN 20 "IoT" on the trunk vtnet2 as opt1 198.51.100.1/24), switches the
default dnsmasq DHCP off (Kea serves the LAN, set up through the API after the reboot) and adds
the API users of docs/adapters/opnsense.md with their keys (stored as SHA-512 crypt hashes, as
OPNsense stores them). Everything else stays as the image made it.
"""

import json
import sys
import uuid
import xml.etree.ElementTree as ET


def child(parent, tag):
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    return el


def put(parent, tag, text):
    child(parent, tag).text = text


def interface(ifs, name, values, drop=()):
    el = child(ifs, name)
    for tag in drop:
        for old in el.findall(tag):
            el.remove(old)
    for tag, text in values.items():
        put(el, tag, text)


def main(path, seed_path):
    with open(seed_path) as f:
        seed = json.load(f)
    tree = ET.parse(path)
    root = tree.getroot()

    trigger = root.find("trigger_initial_wizard")
    if trigger is not None:
        root.remove(trigger)

    ifs = child(root, "interfaces")
    v6 = ("ipaddrv6", "subnetv6", "track6-interface", "track6-prefix-id", "dhcp6-ia-pd-len")
    interface(ifs, "wan", {"enable": "1", "if": "vtnet0", "ipaddr": "dhcp", "descr": "WAN"}, v6)
    interface(
        ifs,
        "lan",
        {
            "enable": "1",
            "if": "vtnet1",
            "descr": "LAN",
            "ipaddr": "192.0.2.1",
            "subnet": "24",
            "ipaddrv6": "2001:db8:1::1",
            "subnetv6": "64",
        },
        v6,
    )
    interface(
        ifs,
        "opt1",
        {
            "enable": "1",
            "if": "vlan0.20",
            "descr": "IoT",
            "ipaddr": "198.51.100.1",
            "subnet": "24",
        },
    )

    vlans = child(root, "vlans")
    for old in vlans.findall("vlan"):
        vlans.remove(old)
    vlan = ET.SubElement(vlans, "vlan", {"uuid": str(uuid.uuid4())})
    for tag, text in (
        ("if", "vtnet2"),
        ("tag", "20"),
        ("pcp", "0"),
        ("proto", ""),
        ("descr", "IoT"),
        ("vlanif", "vlan0.20"),
    ):
        put(vlan, tag, text)

    dnsmasq = root.find("dnsmasq")
    if dnsmasq is not None:
        for old in dnsmasq.findall("dhcp_ranges"):
            dnsmasq.remove(old)
        put(dnsmasq, "enable", "0")

    system = child(root, "system")
    users = seed["users"]
    for user in system.findall("user"):
        if user.findtext("name") == "root":
            put(user, "apikeys", users["root"]["key"] + "|" + users["root"]["hash"])
    uid = 2000
    for name, privs in sorted(seed["privileges"].items()):
        for old in [u for u in system.findall("user") if u.findtext("name") == name]:
            system.remove(old)
        user = ET.SubElement(system, "user", {"uuid": str(uuid.uuid4())})
        for tag, text in (
            ("uid", str(uid)),
            ("name", name),
            ("descr", "Signalbox integration test"),
            ("scope", "user"),
            ("groupname", ""),
            ("password", "*"),
            ("priv", ",".join(privs)),
            ("apikeys", users[name]["key"] + "|" + users[name]["hash"]),
        ):
            put(user, tag, text)
        uid += 1
    put(system, "nextuid", str(uid))
    put(system, "hostname", "signalbox-it")
    put(system, "domain", "home.example")

    tree.write(path, encoding="utf-8", xml_declaration=True)
    print("preseeded", path)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
