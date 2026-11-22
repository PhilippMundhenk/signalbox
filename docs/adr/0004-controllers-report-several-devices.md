# 0004. Controllers report the devices they manage (adapter API 1.1)

Date: 2026-11-22 · Status: accepted

## Context

Some integrations observe a controller that manages many devices: an Omada controller (gateway,
switches, access points), later UniFi or a Fritz!Box mesh. Adapter API 1.0 returned one device per
snapshot, so Omada reported every port and radio as belonging to the controller (#46): rules that
reason per device, the topology and links could not see the managed devices.

## Decision

Adapter API 1.1 (backwards compatible) adds `Observation.devices` and
`Observation.device_status`. `observe()` collects them into `Snapshot.extra_devices` and
`Snapshot.extra_status`, fills in site, adapter and `managed_by`, and the contract requires their
ids to start with `<configured device>/`. Objects may belong to the configured device or to one
of its managed devices. `merge` adds managed devices to the network like any other device. The
inventory does not store them (no credentials, no certificate); writes to a managed device go
through its controller (`Deployer.owner`).

## Consequences

- Rules, topology, drift and plans work per managed device without change.
- Ids of managed devices are stable as long as the controller reports the same identity (Omada:
  type and MAC).
- An adapter written for 1.0 keeps working (major version unchanged).
