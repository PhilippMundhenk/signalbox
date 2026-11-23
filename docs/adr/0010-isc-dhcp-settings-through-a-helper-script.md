# 0010. ISC DHCP settings of OPNsense through an optional, forced-command script

Date: 2026-11-23 · Status: accepted

## Context

The ISC DHCP plugin of OPNsense has an API for leases and the service state only (#242).
Ranges, options, static maps and failover are in `/conf/config.xml`; the only API that returns
that file is the backup privilege, which exposes every secret of the firewall. Reading it would
turn a read-only integration into one that holds the keys to everything. Without it, the ISC
server in Signalbox has no pool, router, DNS or reservations, and rules that need them are blind
on those interfaces.

## Decision

- **A script, not the backup.** A small root-owned script,
  `/usr/local/sbin/signalbox-isc-dhcp`, prints the `<dhcpd>` and `<dhcpdv6>` sections as JSON,
  through a whitelist of fields each checked against its format. Nothing else of the file can
  appear, whatever it contains (tested with planted secrets). The script is a file of the
  Signalbox package (`adapters/opnsense/isc_script.py`, standard library only); the setup installs
  it verbatim and a test pins that.
- **Reached by an SSH key with a forced command.** `command="<script>",restrict` in root's
  `authorized_keys`. Chosen over `sudo`/`doas` for a dedicated user (not in the base system, and
  a shell login there is administrators-only) and over a group-readable file (the file is
  `root:wheel`): no extra package, and the key can do exactly one thing even if it leaks. The cost,
  *Permit root user login* in the SSH settings, is stated in the setup guide.
- **Fully optional, as ADR 0009 requires.** Off by default; installed only when the user ticks
  *Also read the ISC DHCP settings* in the plan and confirms it for that device
  (`SetupRequest.ssh_step`, `AdminLogin.ssh_option`); `setup.enabled: false` refuses it;
  *Remove* deletes the script and the key line (other keys stay). Manual installation is
  documented first-class.
- **Pinned before any credential.** The SSH host key is confirmed in its own step (the plan
  returns `ssh_fingerprint`, `ssh_trusted`); root's SSH password is sent only after it and is
  never stored or logged. The adapter stores the confirmed host key (`isc_ssh_host_key`) and the
  generated private key (`isc_ssh_key`, encrypted); without the host key nothing is read.
- **Never fatal.** A script that cannot be run (key refused, host key changed, python missing,
  malformed output) leaves the lease-only read in place with a note on the server.
- **Kea first, ISC as fallback**, as before: ISC settings fill only interfaces no enabled Kea
  server serves.

## Consequences

- Users who tick the box allow root SSH logins by key on the firewall; the setup says so, and
  the manual path lets them judge the short script first.
- The CI image has no `os-isc-dhcp`, so the script, the adapter and the setup are tested against
  the simulators (`signalbox.sim.opnsense_ssh` runs the installed script against a `config.xml`
  with secrets); what differs on a real firewall is tracked in #21.
- The adapter keeps working unchanged for everyone who does not install the script.
