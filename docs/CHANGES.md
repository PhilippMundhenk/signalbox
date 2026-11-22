# Changing devices

Signalbox reads by default. Deploying changes needs three things:

1. `deploy.enabled: true` in the configuration (`SIGNALBOX_DEPLOY_ENABLED=true`)
2. *Allow changes* on every device that should be changed (device settings)
3. an integration that can write what the plan changes (see [MATURITY.md](MATURITY.md))

## The flow

1. **Declare** what the network should look like under *Desired state* ([DESIRED.md](DESIRED.md)).
2. **Plan**: *Changes*, *New change from desired state*. Signalbox lists every change in the order
   it will apply them (router interfaces, DHCP, reservations, ports from the gateway outwards,
   Wi-Fi; removals the other way round), flags changes that could cut off a device, and runs all
   checks on the network as it would be afterwards. A plan that creates errors can only be
   approved with a written override.
3. **Record** the change with a reason. Each integration lists the exact calls it will make.
4. **Approve**, then **Deploy**. Per device, one after another:
   - read the device again; if what the plan changes is no longer as it was planned, stop
   - back up the whole configuration (kept encrypted with the change)
   - apply; devices that can roll back by themselves (a confirm timer) get
     `deploy.confirm_seconds`
   - read again and verify: every change is there, the device answers, no new errors
   - confirm, or roll this device back
5. If a device fails, every device already changed in this deployment is rolled back, last first:
   the inverse changes, or the backup if that does not work. The change ends as *rolled-back*,
   or *failed* if a device could not be restored; then act at once: the change page says which
   device and why.

## Tracking

The *Changes* page is the change log: who, when, why, the desired-state version (git commit),
the plan, the calls per device, the backups and every step with its time. Records are never
deleted.

## Undo

- **Revert** an applied change: Signalbox plans the inverse changes as a new change (checked and
  approved like any other). It refuses when the devices were changed since, so a revert never
  overwrites newer changes silently.
- **Restore a backup**: the last resort for one device; also a tracked change. Later changes on
  that device are lost.
