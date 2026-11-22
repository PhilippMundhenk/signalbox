# Maturity

What every adapter reads, and how well that is tested. *Simulator* means the adapter
passes the contract checks against its built-in simulator in CI; the API shapes the
simulator answers with come from the vendors' documentation. *Confirmed* means a user
reported it working on a real device (`docs/hardware-reports.json`). Please report your
device in [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).

*writes* lists the kinds of change an adapter can deploy ([CHANGES.md](CHANGES.md));
they are tested against the simulators only.

Generated from the adapter manifests by `tools/gen_docs.py`.

| Adapter | interfaces | dhcp | dns | wireless | clients | neighbours | writes | Confirmed on |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TP-Link Easy Smart (`easysmart`) | simulator | - | - | - | - | - | port | nothing yet |
| AVM Fritz!Box (`fritzbox`) | simulator | simulator | - | simulator | simulator | - | - | nothing yet |
| MikroTik RouterOS (`mikrotik`) | simulator | simulator | simulator | simulator | simulator | simulator | router, dhcp, reservation, port, wlan | nothing yet |
| TP-Link Omada (`omada`) | simulator | simulator | - | simulator | simulator | - | router, dhcp, port, wlan | nothing yet |
| OpenWrt (`openwrt`) | simulator | simulator | - | simulator | simulator | simulator | dhcp, reservation, port, wlan | nothing yet |
| OPNsense (`opnsense`) | simulator | simulator | simulator | - | simulator | - | router, dhcp, reservation, port | nothing yet |
| NETGEAR ProSAFE Plus (`prosafe`) | simulator | - | - | - | - | - | port | nothing yet |
