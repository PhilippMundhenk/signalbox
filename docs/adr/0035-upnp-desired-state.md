# 0035. UPnP, NAT-PMP and PCP in the desired state: off, secure mode, declared networks

Date: 2026-11-26 · Status: accepted

## Context

[ADR 0029](0029-upnp-port-mappings.md) reads the UPnP IGD, NAT-PMP and PCP service of a gateway:
whether it is on and in which networks it answers (the `ManagementService` of kind `upnp`), its
secure mode and permission rules, and the mappings clients opened (`Device.upnp`); the `upnp.*`
and `security.upnp` checks judge them. #513 asks for the writes the checks point to: switch the
service off (or on), turn on secure mode, and limit it to the networks the owner declares,
through the existing transaction of [DESIRED.md](../DESIRED.md) and
[DESIGN.md](../DESIGN.md#changing-configuration): explicit start, plan, approval per device,
*Changes allowed*, lock and re-read, backup, apply, verify, confirm or roll back, as
[ADR 0032](0032-gateway-group-desired-state.md) to [ADR 0034](0034-wireguard-tunnels-desired-state.md)
did for gateway groups, Wi-Fi roaming and tunnels.

UPnP differs from those objects:

- Every change in one direction makes the network safer (off, secure mode on, fewer networks,
  fewer clients that may open ports), every change in the other direction lets any device in a
  network open ports to the internet. A plan must never widen it unless the owner wrote exactly
  that.
- The service is the device's own and exists once per gateway; there is nothing to create, tag
  or remove.
- The mappings are the clients' state, not configuration: they end with their lease, and a
  device may drop them itself when the service stops.

## Decision

- **Syntax** (docs/DESIRED.md, `upnp:` of a site): one entry per gateway with `device` and the
  fields to set: `enabled` (on or off; it covers every protocol the device answers, UPnP IGD,
  NAT-PMP and PCP), `secure_mode` (mappings only for the asking host), `networks` (the segments
  it answers in: `native`, a VLAN id or `native-<router>`; at least one) and `allow` (the client
  networks that may open ports, each with optional `ports`, default `1024-65535`, the range
  miniupnpd allows by default). Only what is written is compared, like every other field of the
  desired state; a device may be declared once. Devices without an entry are never touched.
- **`allow` is the whole permission list**: it becomes one allow rule per entry (the same port
  range outside and inside, in the declared order) followed by a rule that denies everything
  else; the device's other permission rules are replaced. Without `allow` the rules are left as
  they are.
- **No widening as a side effect.** A change widens the service when it turns it on, turns
  secure mode off, adds a network or lets more clients or ports map. Such a change only comes
  from a field the owner declared with that value; every other field of the change keeps the
  device's value, and a writer never turns the service on to change its other settings (a
  device whose service is off gets its secure mode, networks and rules written while it stays
  off). A widening change carries the risk "widens UPnP" in the plan, so the approval sees it.
  The undo of a deployment and a restore put back what the device had before, which can mean on
  again: that is the state before the owner's own deployment, not a side effect.
- **Mappings are not removed by Signalbox.** Open mappings end with their lease. The plan text
  says so, and that the device may remove them itself when the service stops (miniupnpd removes
  its rules when it stops; RouterOS drops the dynamic NAT rows of a disabled service: guesses,
  #21). A mapping still open after the change is reported by the `upnp.*` checks as before.
- **One change kind** `upnp` (key `upnp`), applied after the tunnels. Its value holds the whole
  state as the change leaves it: `enabled`, `secure_mode`, the networks (segment ids, sorted)
  and the permission rules, so the verification sees side effects on the fields that were not
  declared too. A device without a UPnP service Signalbox could read satisfies `enabled: false`
  (nothing answers); any other declaration for it is a planning error (Signalbox does not
  install the service).
- **Drift** (`drift.upnp`) is the planner's comparison, so drift and plan agree; a device that
  was not read gives an incomplete finding. *Import what the devices report* writes `enabled`
  and, where the device reports it, `secure_mode`; networks and rules are the owner's decision.
- **Writers** (each documented in the integration's page):
  - **OpenWrt** (UCI `upnpd` through rpcd, inside the existing `uci apply` with its confirm
    timer; `upnpd` added to the write ACL and the backup, a login with an older ACL is refused
    with the reason and the other kinds keep working): `enabled` of the `upnpd` section,
    `secure_mode`, `internal_iface` (the UCI networks of the declared segments), and the
    `perm_rule` sections (`action`, `ext_ports`, `int_addr`, `int_ports`, `comment`), replaced
    as a whole. A router without the `upnpd` config (package `miniupnpd` not installed) refuses
    every declaration but `enabled: false`.
  - **MikroTik** (REST): `enabled` of `/ip/upnp`, and the `internal` rows of
    `/ip/upnp/interfaces` for the declared networks (the VLAN or bridge interface of each
    segment; rows of other networks are disabled, missing ones added, `external` rows left
    alone); armed by the scheduler revert of the firewall changes. RouterOS has no secure mode,
    no NAT-PMP or PCP and no permission rules, so `secure_mode` and `allow` are refused.
  - **FRITZ!Box** (TR-064): only `enabled`, through `X_AVM-DE_UPnP` `SetConfig` (`NewEnable`,
    with `NewUPnPMediaServer` as `GetInfo` reported it), the switch the reader already reads.
    The FRITZ!Box has no secure mode, network limit or permission rules for this switch;
    those fields are refused.
  - **OPNsense** (os-upnp) and the other integrations refuse a plan with UPnP changes for now:
    os-upnp's settings endpoint and its privilege are not documented, and are not confirmed on
    a device (#21); this stays a leftover of #513.

## Consequences

- UPnP can be switched off or narrowed from the desired state on the gateways that have most of
  it, with the usual plan, approval and rollback; it is only opened up where the file says so,
  and the plan names it as a widening.
- Mappings that are open when the service is narrowed stay until they expire or the device drops
  them; the checks keep reporting them.
- The `upnpd` option spellings in a write (`internal_iface` as a list, `secure_mode`), the
  RouterOS interface rows and the FRITZ!Box `SetConfig` arguments are guesses until a real device
  confirms them (#21).
