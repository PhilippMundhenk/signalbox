"""SSH host keys confirmed per device, for the setup and Fix it (#526, docs/adr/0031).

The first contact is trust on first use: the plan shows the presented key and nothing is sent
until the user confirms it; a run with the confirmed key stores it as the device's pin. Later
plans say whether the presented key is that pin (``known``: no prompt) or another one
(``changed``: a warning, and a run with it is refused before the adapter is called, so no
password is sent). Only :meth:`~signalbox.store.Store.retrust_ssh_host_key`, which names the
new key, or forgetting the pin ends a change. The HTTPS certificate pin
(``DeviceRecord.pinned_fingerprint``) is separate and unchanged.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from signalbox.adapters.provision import same_fingerprint
from signalbox.store import SshHostKeyPin, SshHostKeys, Store


def is_ssh(fingerprint: str | None) -> bool:
    """An SSH host key fingerprint (``SHA256:<base64>``), not a certificate's hex SHA-256."""
    return bool(fingerprint) and str(fingerprint).strip().upper().startswith("SHA256:")


def _day(pin: SshHostKeyPin) -> str:
    return pin.confirmed_at.strftime("%Y-%m-%d")


def state(keys: SshHostKeys, presented: str | None) -> dict[str, Any] | None:
    """How a presented SSH host key compares with the pin, for the UI; None: not an SSH key.

    ``new``: nothing confirmed yet (compare and confirm); ``known``: the confirmed key, with
    when and by what it was confirmed; ``changed``: another key, with the pinned one.
    """
    if not is_ssh(presented):
        return None
    pin = keys.pin
    if pin is None:
        return {"state": "new", "fingerprint": presented}
    out = {
        "fingerprint": presented,
        "pinned": pin.fingerprint,
        "algorithm": pin.algorithm,
        "confirmed_at": pin.confirmed_at.isoformat(),
        "action": pin.action,
    }
    if same_fingerprint(pin.fingerprint, presented):
        return {"state": "known", **out}
    return {"state": "changed", **out}


def view(keys: SshHostKeys) -> dict[str, Any] | None:
    """The device's SSH host key for the device page; None: none confirmed, changed or old."""
    if keys.pin is None and keys.changed is None and not keys.history:
        return None
    return {
        "pin": keys.pin.model_dump(mode="json") if keys.pin else None,
        "changed": keys.changed.model_dump(mode="json") if keys.changed else None,
        "history": [p.model_dump(mode="json") for p in keys.history[:10]],
    }


def changed_answer(name: str, keys: SshHostKeys, presented: str) -> dict[str, Any]:
    """The body of a ``host_key_changed`` refusal (409): what was pinned, what was presented."""
    pin = keys.pin
    assert pin is not None
    date = _day(pin)
    return {
        "error": "host_key_changed",
        "message": (
            f"The SSH host key of {name} has changed since {date}: old {pin.fingerprint}, new "
            f"{presented}. This happens after a reset or reinstall, or if someone is in between. "
            "No password was sent to the device."
        ),
        "fix": (
            "Compare the new key with the one the device itself shows. Only if it matches, "
            "trust the new key on the device page; otherwise check the network path first."
        ),
        "message_id": "hostKey.changed",
        "fix_id": "hostKey.changed.fix",
        "params": {"device": name, "date": date, "old": pin.fingerprint, "new": presented},
        "host_key": state(keys, presented),
    }


def refused(
    store: Store, device_id: str | None, name: str, trusts: Iterable[str | None]
) -> dict[str, Any] | None:
    """The refusal for a run whose confirmed SSH host key is not the device's pin, or None.

    Checked before the adapter is called: with a changed key no password is sent.
    """
    if not device_id:
        return None
    keys = store.ssh_host_keys(device_id)
    if keys.pin is None:
        return None
    for trust in trusts:
        if not is_ssh(trust) or same_fingerprint(trust, keys.pin.fingerprint):
            continue
        if keys.changed is not None:
            return changed_answer(name, keys, keys.changed.fingerprint)
        # no other key was seen: the request names a key the device did not present
        return {
            "error": "untrusted",
            "message": "The SSH host key in this request is not the one confirmed for the "
            "device; nothing was sent. Fetch the device's identity again.",
            "fingerprint": keys.pin.fingerprint,
        }
    return None


def notice(
    store: Store,
    device_id: str | None,
    presented: Iterable[str | None],
    seen: Mapping[str, str],
    action: str,
) -> bool:
    """Record a presented SSH host key that differs from the pin; returns whether one did."""
    if not device_id:
        return False
    changed = False
    for fingerprint in presented:
        if is_ssh(fingerprint):
            assert fingerprint is not None
            changed |= store.note_ssh_host_key_change(
                device_id, fingerprint, algorithm(seen, fingerprint), action
            )
    return changed


def remember(
    store: Store, device_id: str, trusts: Iterable[str | None], seen: Mapping[str, str], action: str
) -> None:
    """After a run: store the confirmed SSH host keys the device presented in it (first trust).

    Only a key the run actually saw is stored, and only while the device has no pin (a pinned
    key stays; another one was refused before the run)."""
    for trust in trusts:
        if not is_ssh(trust) or not _seen(seen, trust):
            continue
        assert trust is not None
        if store.ssh_host_keys(device_id).pin is None:
            store.pin_ssh_host_key(device_id, trust, algorithm(seen, trust), action)


def _seen(seen: Mapping[str, str], fingerprint: str | None) -> bool:
    return any(same_fingerprint(k, fingerprint) for k in seen)


def algorithm(seen: Mapping[str, str], fingerprint: str | None) -> str | None:
    """The algorithm of a presented key (``ssh-ed25519``), when the run saw it."""
    return next((v for k, v in seen.items() if same_fingerprint(k, fingerprint)), None)
