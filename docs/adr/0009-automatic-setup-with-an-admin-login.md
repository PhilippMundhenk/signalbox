# 0009. Automatic setup with an admin login, used once and never kept

Date: 2026-11-22 · Status: accepted

## Context

Preparing a device by hand is the most tedious part of adding it (#231): on OpenWrt packages,
an rpcd ACL file and a login; on OPNsense a user, nine privileges and an API key; on MikroTik a
user group with the right policies and a user. Users are willing to give the admin login once;
Signalbox should then create its own least-privilege access, exactly as the setup guides
describe it, and fill in the device settings. This is the first time Signalbox handles an admin
credential, and the first time it changes accounts and permissions on a device. The design
therefore has to make sure the admin login is used only for that one step, reaches only the
device the user confirmed, and that the result is no more than the documented access.

## Decision

- **Optional, and only on request.** The manual setup guides stay the first-class path and
  describe the same result. The setup runs only when the user starts it in the form of one
  device and confirms the plan; never from discovery, an observation or any background job.
  `setup.enabled: false` turns it off completely: both endpoints answer 403 `disabled` and
  `/api/adapters` reports no `admin_login`, so the form does not offer it.
- **Transport per platform, chosen for what is robust and testable on the real software:**
  - *OpenWrt*: SSH as root (dropbear) running the same steps as the commands of the setup guide
    (`setup.commands()`): missing packages with `apk` or `opkg`, the ACL file, an rpcd login.
    SSH is on by default on OpenWrt; rpcd has no API to manage its own logins or ACL files.
  - *OPNsense*: its API with an API key of root (or another administrator), through the user
    manager the web interface itself uses (`/api/auth/user/*`: add or set the user with a
    scrambled password, the documented privileges and no groups; `add_api_key`; older keys of
    that user deleted). Chosen over SSH with a PHP script: SSH and root login are off by default
    on OPNsense, a script would depend on internal classes, while the API is versioned, already
    pinned like every other OPNsense request, and the CI image has a root key.
  - *MikroTik*: the REST API as admin (`/user/group`, `/user`). It needs `www-ssl` with a
    certificate first, as reading does; that step stays manual.
- **Pinned before any credential.** SSH: the host key fingerprint (`SHA256:…`, as `ssh-keygen
  -l` prints it) is shown and must be confirmed; it is compared inside the key exchange
  (`signalbox.adapters.ssh.PinnedSsh`), the handshake is aborted otherwise, and nothing from the
  local machine is used (no `~/.ssh/config`, `known_hosts`, agent or keys). HTTPS: the existing
  certificate pinning (`DeviceHttp`). The setup is stateless: the plan returns the presented
  fingerprint, the apply request carries the confirmed one and fails with 409 if the device
  presents another. Plain `http://` is refused for the admin login.
  On OpenWrt the web server certificate is read over the pinned SSH connection and pinned for
  reading, so the user confirms one fingerprint, not two.
- **Plan first, then apply.** `POST /api/devices/setup` inspects the device and returns the
  steps (`todo` / `unchanged`) with what is sent, secrets as `***`; it changes nothing.
  `POST /api/devices/setup/apply` runs them in order, stops at the first failure (the rest are
  `skipped`) and reports each. Only after every step succeeded is the device saved (added, or
  updated when editing) with the new login; the rest of the form is validated before anything
  runs on the device.
- **Generated credentials.** 32 random characters of `[A-Za-z0-9]` (about 190 bits; OPNsense
  generates its API key itself). They go into the device's encrypted settings like any other
  secret and are never part of an answer: the UI never sees them. On OpenWrt the password is
  hashed (md5-crypt, what `uhttpd -m` does) before it is sent, so only the hash reaches the
  router; every script goes over standard input of `sh -s`, so nothing appears in a process
  list. Every re-run sets a new password or key (the old one is not known to the setup).
- **The admin login is used for this request only.** It is a `SecretStr` in the request, not
  stored, not logged (the log line names device, integration and outcome), not in the change
  log (the setup is not a deployment), and every text that leaves an integration (step details,
  messages, errors) passes a redactor that knows it and every generated secret, so a device that
  echoes a value cannot leak it. Validation errors of the API never echo input.
- **Least privilege exactly as documented, and tested so.** The ACL (`READ_ACL`, `WRITE_ACL`),
  the privileges (`READ_PRIVILEGES`, `WRITE_PRIVILEGES`) and the policies (`READ_POLICY`,
  `WRITE_POLICY`) are constants checked by tests against the setup guides and the CI images'
  files. Write access only with *Allow changes*; without it a second run takes write access away
  again. Signalbox refuses to set up the admin login itself (`root`, `admin`, a system user).
- **Idempotent, and removable.** A re-run repairs a partial setup and upgrades permissions (a
  new ACL entry after an update); steps that are already right are `unchanged`. *Remove* deletes
  the login (and on OPNsense its keys), and the ACL file or user group only when no other login
  uses it; packages stay.
- **An optional adapter hook.** `Manifest.admin_login` (what to ask for: labels, default user,
  SSH port, a note) and two class methods `plan_setup(SetupRequest) -> SetupPlan` and
  `apply_setup(SetupRequest) -> SetupResult`, checked when adapters are loaded. Like discovery
  (ADR 0006) they have defaults, so the adapter API stays 1.2 and third-party integrations can
  join.

## Consequences

- Adding an OpenWrt, OPNsense or MikroTik device needs no shell or web interface session on the
  device; the manual setup guides stay valid and describe the same result.
- An attacker in the network path cannot get the admin login without the user confirming a
  wrong fingerprint; the UI tells the user to compare it with the device first.
- The admin login travels from the browser to Signalbox in the request body: Signalbox should be
  reached over HTTPS (docs/DEPLOYMENT.md), as for every other device password.
- OPNsense: the root API key the user created for this step remains on the firewall; the form
  and the guide say to delete it afterwards (Signalbox does not delete the key it was given).
- New dependency `asyncssh` (pure Python on `cryptography`, already a dependency).
- Verified against the real software in CI (OpenWrt 24.10 and 25.12, OPNsense 26.7, RouterOS
  CHR); details that differ on real hardware are tracked in #21.

## Note (#279): the admin password comes last

In the UI (setup and *Fix it*) the order is: what it does (the integration's static `preview`,
no credential, nothing sent), the device's identity (SSH host key or certificate, fetched with
the plan endpoint called **without** `admin.secret`, which sends no credential), and only then a
small temporary password step right before *Run* ("used once for this step, never saved",
autocomplete off, cleared right after the request, on cancel, on navigation and after two idle
minutes). *Apply* takes the password once and, with `plan_ids` (the steps the user saw), first
plans with it: a step that was not among them stops the run with 409 `plan_changed` and the real
plan, to be confirmed again; an unconfirmed SSH host key of the optional SSH step answers 409
`untrusted_ssh` before the SSH password is used. API clients that send no `plan_ids` keep the
old behaviour. Nothing stores the password, as before.

## Note (#290): the preview cannot drift, and both identities come first

Every integration's static `preview` is covered by `tests/test_preview_covers_plan.py`: the
real plan (fresh, set up, removal, with the optional extras and the optional SSH step, and each
*Fix it* remedy) may only contain step ids the preview lists. The test found three drifts that
are fixed (MikroTik removal groups and REST-service certificate steps, OpenWrt removal
`packages`). With the optional SSH step (OPNsense ISC script) the plan endpoint called without
a password (`SetupRequest.identity_only`) now returns the HTTPS certificate **and** the SSH host
key (the SSH port is asked before, no secret); one confirmation trusts both, and the passwords
(API secret, SSH password) are asked once, together, right before *Run*.
