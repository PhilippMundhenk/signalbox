<!-- rules of src/signalbox/rules/annotation_checks.py and the engine's ack.expired; part of the rules documentation (docs/RULES.md lists all) -->

# Annotations and acknowledgements

Annotations (a label, purpose, owner, notes and expectations of an object) and acknowledged
findings are the user's own data ([DESIRED.md](../DESIRED.md#annotations-and-acknowledgements)).
They name objects by id; these rules report when that goes wrong.

## `annotations.stale`

- **Severity:** info
- **Checks:** every annotation and every acknowledgement with a target names an object that
  still exists: a device that is in Signalbox, a port, subnet or other object its (fully read)
  device still reports, a network some device of a fully read site reports, a client MAC
  address seen during the whole history period (default 30 days).
- **Stays quiet** before the first observation round, for objects of a device that was not
  read completely, for clients the annotation calls a known neighbour or allows to be
  unreachable, and while the history is shorter than its period.
- **Fix:** if the object was renamed (a port, a VLAN), move the annotation or acknowledgement
  to its new id; if it is gone, remove it.

## `ack.expired`

- **Severity:** info
- **Checks:** an acknowledgement whose end date (`until`) has passed. The finding it covered
  counts as a problem again if it still exists. Produced by the rule engine itself.
- **Fix:** acknowledge the finding again if it is still accepted, or fix it; then remove the
  expired acknowledgement (under Findings, or from the desired state).
