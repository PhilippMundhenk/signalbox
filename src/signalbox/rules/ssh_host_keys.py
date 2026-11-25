"""SSH host key rules (#526, ADR 0031).

They read :attr:`~signalbox.model.Device.ssh_host_key_change`, which core fills from the store
when a setup, a Fix it or a read over SSH saw another host key than the one confirmed for the
device. It stays until the user trusts the new key (naming it) or forgets the pin; an
acknowledgement of the finding hides it as for every finding.
"""

from __future__ import annotations

from collections.abc import Iterator

from signalbox.model import Network
from signalbox.rules import Result, Rule, Severity, found, rule


@rule(
    "ssh.host-key-changed",
    "SSH host key changed",
    Severity.WARNING,
    "Signalbox stores the SSH host key confirmed for a device and checks it before any password "
    "is sent. A device that presents another key was reset or reinstalled, got a new key, or "
    "someone is in between and wants the admin password. Signalbox sends nothing over SSH to "
    "it until the new key is trusted on the device page; compare it with the key the device "
    "itself shows first.",
)
def host_key_changed(net: Network) -> Iterator[Result]:
    for dev in sorted(net.devices, key=lambda d: d.id):
        change = dev.ssh_host_key_change
        if change is None:
            continue
        date = change.pinned_since.strftime("%Y-%m-%d")
        yield found(
            f"The SSH host key of {dev.name} has changed since {date}: old {change.pinned}, "
            f"new {change.presented}",
            [dev.id],
            fix="Compare the new key with the one the device itself shows. Only if it matches, "
            "trust the new key on the device page; otherwise check the network path first.",
            mid="hostKey.changed.finding",
            fix_id="hostKey.changed.fix",
            params={
                "device": dev.name,
                "date": date,
                "old": change.pinned,
                "new": change.presented,
            },
        )


RULES: list[Rule] = [host_key_changed]
