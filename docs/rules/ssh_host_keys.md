<!-- rules of src/signalbox/rules/ssh_host_keys.py; part of the rules documentation (docs/RULES.md lists all) -->

# SSH host keys

Signalbox stores the SSH host key confirmed for each device the first time a setup or Fix it
connects over SSH (issue #526, ADR 0031) and compares every later contact with it before any
password is sent. These rules report a key that changed.

## `ssh.host-key-changed`

- **Severity:** warning
- **Checks:** the SSH host key a setup, a Fix it or a read over SSH saw is the one confirmed
  for the device. A different key means the device was reset or reinstalled, got a new key, or
  someone is in between. Signalbox refused the connection before sending a password; the
  finding stays until the new key is trusted (the action names it, the old key stays in the
  history) or the confirmed key is forgotten. Acknowledging the finding hides it as usual.
- **Fix:** compare the new key with the one the device itself shows
  (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` or the device's own page). Only if it
  matches, trust the new key on the device page; otherwise check the network path first.
