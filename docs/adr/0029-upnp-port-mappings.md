# 0029: UPnP, NAT-PMP and PCP state and dynamic port mappings (#176)

## Context

UPnP lets any device on the LAN open ports to the internet, so a compromised camera can expose
itself. Whether UPnP is on, and where it listens, was already a management service of kind
`upnp` (#124, `security.upnp`). What was missing is what the protocols did: which mappings are
open, for which device, and how the daemon is set up (secure mode, permission rules).

## Decision

- **`Device.upnp: DeviceUpnp | None`**, read with `interfaces` (`Observation.upnp` per device
  id). `None` is "not read". The on/off state and the networks stay on the `ManagementService`
  of kind `upnp`; no second object repeats them.
- **`DeviceUpnp`**: the protocols the gateway answers (`upnp-igd`, `nat-pmp`, `pcp`),
  `secure_mode` (mappings only for the asking host; `None` where the device does not say), the
  permission rules (`UpnpAclRule`: allow or deny, external ports, internal network and ports)
  and the `mappings`.
- **`DynamicPortMapping`**: protocol, external port, internal address and port, description,
  `lease_seconds` (remaining; `0` never ends; `None` not reported), `created_by`, and a remote
  host limit. The device behind a mapping is found through the clients by address, not stored.
- **`mappings_complete`**: `False` where the device does not list every mapping (OPNsense has
  no API for them; a Fritz!Box does not say who created a port sharing entry). Rules never
  read an empty list as "no mappings" without it.
- Static port forwards stay `PortForward` (#135); a mapping is never a `PortForward`, so
  firewall checks keep their meaning. The "open to the internet" view combines both later.
- Descriptions of mappings carry names of apps and devices. They stay local and are not part of
  findings.
- Read-only: turning UPnP off or limiting its networks is a later write (the issue's desired
  state).

## Consequences

- The checks (`upnp.*`) read mappings against the networks Signalbox knows, so a mapping to an
  address in no known network is not judged.
- RouterOS answers UPnP IGD only, has no secure mode and no permission rules; its mappings are
  the dynamic `dst-nat` rows of the firewall.
- The Fritz!Box lists UPnP mappings among its port sharing. A mapping with a finite lease is
  taken as UPnP (a guess, #21); permanent ones are read as port sharing and missed.
