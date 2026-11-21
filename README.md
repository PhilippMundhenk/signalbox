# Signalbox

One place to see and configure every device in a small office or home network: router,
firewall, switches, access points. Signalbox reads each device through an adapter into one
vendor-neutral model, shows how everything is wired (ports, cables, VLANs), and checks that the
devices agree with each other: one DHCP server per network, the same Wi-Fi settings on every
access point, every VLAN carried on every link it needs.

**Status:** in development, nothing to install yet. The plan is in [docs/DESIGN.md](docs/DESIGN.md), progress in the [issues](https://github.com/PhilippMundhenk/signalbox/issues).

## Planned device support

| Device | How | Phase |
| --- | --- | --- |
| OPNsense | REST API | 1 |
| OpenWrt | ubus/rpcd over HTTPS, or SSH and UCI | 1 |
| NETGEAR ProSAFE Plus switches | NSDP, via [Switchyard](https://github.com/PhilippMundhenk/switchyard) | 2 |
| AVM Fritz!Box | TR-064 | later |

Adapters are plugins, so other devices can be added without changing the core.

> Signalbox is an independent open-source project, not affiliated with any of the vendors named
> here. Product names are used only to say what it works with.

## License

MIT, see [LICENSE](LICENSE).
