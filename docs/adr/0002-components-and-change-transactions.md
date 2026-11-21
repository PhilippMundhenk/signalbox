# 0002. Explicit components, and changes as tracked transactions

Date: 2026-11-21 · Status: accepted

## Context

Signalbox reads many kinds of devices and will change their configuration. Controllers that grow
per-vendor code paths through the whole stack become hard to review and to trust, and a change
that leaves a network half-configured is worse than no change. Writing to routers and access
points can also cut off the path to the device itself.

## Decision

Signalbox is built from separate components with narrow contracts: network model, integrations
(adapters), inventory, observation, checks (rules), topology, desired state, planner,
deployment, change tracking, rollback, interfaces. Only integrations know vendors; checks are
pure functions of the model and run unchanged on observed, desired and predicted state.

Every write is a change set produced by the planner from the desired state, checked on its
predicted state, approved by a person, and applied by the deployment component as one
transaction: per device lock, backup, stage, apply, verify, then commit or roll back; across
devices, a failure rolls back the devices already changed in reverse order. Every deployment is
an immutable change record and can be reverted as a new, tracked deployment.

## Consequences

- Adding a device type means writing one integration; nothing else changes.
- Integrations need a write capability that can return the vendor calls before applying and can
  restore a backup; devices without any transaction support get backup-and-restore only.
- Writes are slower than direct configuration (observe, backup, verify), which is intended.
- Writing is off by default and enabled per site and adapter.
