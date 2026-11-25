# Maturity

What every adapter reads, and how well that is tested. *Simulator* means the adapter
passes the contract checks against its built-in simulator in CI; the API shapes the
simulator answers with come from the vendors' documentation. *Confirmed* means a user
reported it working on a real device (`docs/hardware-reports.json`). Please report your
device in [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).

*writes* lists the kinds of change an adapter can deploy ([CHANGES.md](CHANGES.md));
they are tested against the simulators.

*Emulated*: verified against the real device software in CI, reads and writes
([TESTING.md](TESTING.md)):

- VyOS: rolling 2026.11.25 (1.5 development), official ISO in QEMU, read only; EdgeOS itself is simulator-only ([details](adapters/edgeos.md#integration-tests))
- Linux gateway: Debian 11, 12 and 13 in containers (sshd, iproute2, dnsmasq, chrony, WireGuard), read only ([details](adapters/linux.md#integration-tests))
- MikroTik: RouterOS 7.25.1, official CHR image in QEMU, without Wi-Fi ([details](adapters/mikrotik.md#integration-tests))
- TP-Link Omada: Software Controller 6.3.0.111, 5.15.24.19, 5.14.32.4 and 5.13.30.8, official Linux package in Docker, without managed devices ([details](adapters/omada.md#integration-tests))
- OpenWrt: 23.05.6, 24.10.8 and 25.12.6, official x86-64 images in QEMU ([details](adapters/openwrt.md#verified-against-the-real-openwrt))
- OPNsense: 26.7.9 and 25.1, official nano images in QEMU (25.1 read only) ([details](adapters/opnsense.md#versions-390))
- UniFi: Network application 8.6.9, 9.5.21 and 10.6.109 in Docker with MongoDB, without adopted devices ([details](adapters/unifi.md#integration-tests))

Generated from the adapter manifests by `tools/gen_docs.py`.

| Adapter | interfaces | dhcp | dns | wireless | clients | neighbours | health | time | vpn | firewall | writes | Confirmed on |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AdGuard Home (`adguardhome`) | - | simulator | simulator | - | simulator | - | - | - | - | - | - | nothing yet |
| TP-Link Easy Smart (`easysmart`) | simulator | - | - | - | - | - | - | - | - | - | port | nothing yet |
| Ubiquiti EdgeRouter (EdgeOS) and VyOS (`edgeos`) | simulator | simulator | simulator | - | - | simulator | simulator | simulator | simulator | simulator | - | nothing yet |
| AVM Fritz!Box (`fritzbox`) | simulator | simulator | - | simulator | simulator | - | simulator | simulator | - | simulator | dhcp, wlan | nothing yet |
| Linux (Debian, Raspberry Pi OS, Arch Linux ARM) (`linux`) | simulator | simulator | simulator | - | - | - | simulator | simulator | simulator | simulator | - | nothing yet |
| MikroTik RouterOS (`mikrotik`) | simulator | simulator | simulator | simulator | simulator | simulator | simulator | simulator | simulator | simulator | router, dhcp, reservation, port, wlan, zone-policy, firewall-rule, port-forward, log-target, snmp-policy | nothing yet |
| TP-Link Omada (`omada`) | simulator | simulator | - | simulator | simulator | simulator | simulator | simulator | - | simulator | router, dhcp, port, wlan | nothing yet |
| OpenWrt (`openwrt`) | simulator | simulator | simulator | simulator | simulator | simulator | simulator | simulator | simulator | simulator | dhcp, reservation, port, wlan, zone-policy, firewall-rule, port-forward, log-target, snmp-policy | nothing yet |
| OPNsense (`opnsense`) | simulator | simulator | simulator | - | simulator | simulator | simulator | simulator | simulator | simulator | router, dhcp, reservation, port, zone-policy, firewall-rule, port-forward | nothing yet |
| Pi-hole (`pihole`) | - | simulator | simulator | - | simulator | - | - | - | - | - | - | nothing yet |
| NETGEAR ProSAFE Plus (`prosafe`) | simulator | - | - | - | - | - | - | - | - | - | port | nothing yet |
| SNMP switch (generic, read only) (`snmp`) | simulator | - | - | - | - | simulator | simulator | - | - | - | - | nothing yet |
| Ubiquiti UniFi (`unifi`) | simulator | simulator | - | simulator | simulator | simulator | simulator | simulator | simulator | - | - | nothing yet |
