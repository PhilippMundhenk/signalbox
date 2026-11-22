# Maturity

What every adapter reads, and how well that is tested. *Simulator* means the adapter
passes the contract checks against its built-in simulator in CI; the API shapes the
simulator answers with come from the vendors' documentation. *Confirmed* means a user
reported it working on a real device (`docs/hardware-reports.json`). Please report your
device in [#21](https://github.com/PhilippMundhenk/signalbox/issues/21).

Generated from the adapter manifests by `tools/gen_docs.py`.

| Adapter | interfaces | dhcp | dns | wireless | clients | neighbours | Confirmed on |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AVM Fritz!Box (`fritzbox`) | simulator | simulator | - | simulator | simulator | - | nothing yet |
| OpenWrt (`openwrt`) | simulator | simulator | - | simulator | simulator | simulator | nothing yet |
| OPNsense (`opnsense`) | simulator | simulator | simulator | - | simulator | - | nothing yet |
