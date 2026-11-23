# 0012. Fix it: known remedies for read problems, run like the automatic setup

Date: 2026-11-23 · Status: accepted

## Context

Many read problems have a known cause that Signalbox's own setup created or would create: an
OpenWrt router without the LLDP packages, a permission file from an older Signalbox version
that does not allow a newer call, an OPNsense user that lacks a privilege added since (#215).
Each already has a fix text ("What to do"), but the user has to log in to the device and do it
by hand, although the automatic setup (ADR 0009) can do exactly these steps safely. At the
same time Philipp's requirement for everything that installs or changes something on a device
for Signalbox's own sake holds: fully optional, manual instructions stay first-class, nothing
without the user starting it for that device and confirming the plan, a switch turns it off.

## Decision

- **A remedy is structured, not text.** An integration declares its remedies in
  `Manifest.remedies` (`Remedy`: `id`, `title`, `description`). A read gap (`Gap.remedy`) or a
  read error (`AdapterError(..., remedy=...)`) names one by id; `observe()` copies it to
  `ReadError.remedy`, and the read finding (`signalbox.read`) carries it as `Finding.remedy`.
  The fix text stays next to it unchanged, so the manual way is always shown.
- **Only what the setup owns.** A remedy may install the packages Signalbox reads through and
  give its own login the documented permissions, nothing else; network settings stay with the
  desired state and deployments. Built in:
  - OpenWrt `access` (any refused ubus call, the port structure gap, wireless on 25.12 without
    rpcd-mod-luci): missing packages of the setup, the ACL file as in the setup guide (with the
    write part when changes are allowed), the ACL group in the stored login's rpcd section
    (the password is not touched), rpcd restarted.
  - OpenWrt `lldp` (LLDP not installed or not running): `lldpd` and `luci-app-lldpd` if missing,
    lldpd enabled and started, then the same permission steps.
  - OPNsense `privileges` (an HTTP 403 while reading): the user the stored API key belongs to
    (`search_api_key`) gets the documented privileges it lacks; its other privileges, groups,
    password and keys stay. Root and system users are refused.
  - MikroTik: none yet (the group policy is the setup's; a re-run of the setup repairs it).
- **The same hooks and rules as the setup.** `plan_remedy(RemedyRequest) -> SetupPlan` and
  `apply_remedy(RemedyRequest) -> SetupResult` (checked by `load_adapters` together with
  `admin_login`): pinned channel first (SSH host key or certificate, confirmed by the user, 409
  when it changed), plan without changes, steps `todo`/`unchanged`, stop at the first failure,
  every text through the redactor (the admin secret and the device's stored secrets).
- **The admin login is always asked for.** The stored login is least privilege by design, so
  it can never install a package or widen its own permissions; the form asks for the admin
  login of the setup (`Manifest.admin_login`) for this one request and keeps it nowhere.
- **Only on request, per device.** `POST /api/devices/{id}/fix` returns the plan;
  `POST /api/devices/{id}/fix/apply` runs it after the user confirmed it in a dialog, then
  reads the device again and returns that reading (and triggers a run for the findings). Only
  for a stored device with *Allow changes* (as #215 asks), only for a remedy its integration
  declares, never from discovery, a read or a background job. The UI shows *Fix it* next to
  the read error on the device page (and a link from the finding); on a device without *Allow
  changes* it says that the fix needs it.
- **Off with the setup, or on its own.** `setup.fixes: false` turns Fix it off, and so does
  `setup.enabled: false`: both endpoints answer 403 `disabled` and `/api/adapters` lists no
  remedies, so the UI shows only the manual instructions.

## Consequences

- A newer Signalbox that needs one more call on OpenWrt, or one more privilege on OPNsense,
  shows *Fix it* instead of asking the user to paste the setup commands again.
- `Gap`, `AdapterError`, `ReadError` and `Finding` have an optional `remedy`; the adapter API
  stays 1.2 (the hooks have defaults, like the setup's).
- Verified in CI against the real software: OpenWrt (24.10, 25.12) with an outdated ACL file
  repaired and lldpd started again; OPNsense 26.7 with a privilege removed and added back.
  Installing packages from the feeds is offline in CI and covered by the simulator only (#21).
