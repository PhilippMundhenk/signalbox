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
     (unless it is already as the plan wants it: an object several devices share, such as an
     SSID of a controller's WLAN group, changed through an earlier device of this deployment)
   - back up the whole configuration (kept encrypted with the change)
   - apply; devices that can roll back by themselves (a confirm timer) get
     `deploy.confirm_seconds`
   - read again and verify: every change is there, the device answers, no new errors
   - confirm, or roll this device back
5. If a device fails, every device already changed in this deployment is rolled back, last first:
   the inverse changes, or the backup if that does not work. The change ends as *rolled-back*,
   or *failed* if a device could not be restored; then act at once: the change page says which
   device and why.

## Firewall changes and management access

A firewall change can cut Signalbox off from the device it changes or from devices behind
it. For every plan with firewall changes Signalbox asks its reachability model
(`signalbox.firewall.reach`) whether each device of the site stays reachable at its
management address and port, before and after the plan: from `deploy.signalbox_address`
(Signalbox's own address as the devices see it), or, without it, from the network of the
management address. Where the answer gets worse (allowed becomes denied or "cannot tell",
"cannot tell" becomes denied), the plan shows a red **May cut Signalbox off** list and can only
be approved with the explicit override *Allow losing management access* (`allow_lockout` in
`POST /api/changes/<id>/approve`). The change log keeps the override and the reasons. The
device's confirm timer is still the last safeguard: a change that cuts the access undoes itself.

## Logging and SNMP changes

The kinds `log-target` (key `syslog/<address>`: address, port, transport, sent at all) and
`snmp-policy` (key `snmp`: `on`, `v3-only` or `off`) change where a device logs to and whether
its SNMP agent runs ([DESIRED.md](DESIRED.md#logging-and-snmp), ADR 0021). The plan shows old and
new values; an SNMP community never appears in them. They are applied last, after the network and
firewall kinds. OpenWrt uses the `uci apply` confirm timer, MikroTik its scheduler revert; both
undo a change that is not confirmed, and a failed deployment restores the backup.

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

### Wi-Fi passphrases

A change only names the secret with the new passphrase, and devices report at most a
fingerprint of the one they have. So before it replaces a passphrase (or removes an SSID), the
deployment looks for the current one among what Signalbox knows:

1. the passphrase Signalbox itself last deployed to that SSID
2. the value the named secret had before it was last replaced (storing a secret under
   *Desired state, Secrets* keeps the previous value, encrypted)
3. every other stored secret

The fingerprint the device reports decides which one it is. A device that reports no
fingerprint (for example Omada SSIDs whose key the controller does not return) is trusted only
with the passphrase Signalbox deployed itself.

The passphrase found is kept as an encrypted **secret version** named `<secret>@<change id>`
(the change log shows the name, never the value; versions are not listed as secrets). The
inverse of the change sets that version, so a **revert** or a rollback brings the old
passphrase back. If the old passphrase is not known, the change log says so (event
*passphrase-unknown*): a revert then leaves the new passphrase, and only restoring the backup
of that change brings the old one back.

Versions are pruned with the change history of their SSID: one lives as long as the latest
applied change of that SSID needs it (an older change cannot be reverted any more, see above),
and a deployment that does not apply keeps none.
