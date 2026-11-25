"""Device identities confirmed per device, for the setup and Fix it (#526, #535, docs/adr/0031).

**SSH host keys.** The first contact is trust on first use: the plan shows the presented key
(and the other key types the device offers) and nothing is sent until the user confirms it; a
run with the confirmed key stores it, with those other types, as the device's pin. Later plans
say whether the presented key is pinned (``known``: no prompt) or another one (``changed``: a
warning, and a run with it is refused before the adapter is called, so no password is sent).
Only :meth:`~signalbox.store.Store.retrust_ssh_host_key`, which names the new key, or
forgetting the pin ends a change.

**HTTPS certificates** (#535) use the pin the device's read connection keeps
(``DeviceRecord.pinned_fingerprint``, ADR 0019): the same certificate needs no prompt; another
one is recorded as the certificate waiting to be trusted (``pending_fingerprint``, as a read
records it), a run with it is refused before the adapter is called, and only trusting that
certificate by its full fingerprint (``POST /devices/{id}/trust``) ends the change.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from typing import Any

from signalbox.adapters import AdapterError, UntrustedCertificate, UntrustedHostKey
from signalbox.adapters.https import normalise_fingerprint
from signalbox.adapters.provision import key_family, same_fingerprint
from signalbox.adapters.ssh import offered_host_keys
from signalbox.store import DeviceRecord, SshHostKeyPin, SshHostKeys, Store

_HEX = re.compile(r"[0-9a-f]{64}")


def is_ssh(fingerprint: str | None) -> bool:
    """An SSH host key fingerprint (``SHA256:<base64>``), not a certificate's hex SHA-256."""
    return bool(fingerprint) and str(fingerprint).strip().upper().startswith("SHA256:")


def certificate_hex(fingerprint: str | None) -> str | None:
    """A certificate's SHA-256 as Signalbox pins it (64 lower-case hex digits, colons and case
    as copied from a browser accepted), or None when it is not one."""
    if not fingerprint or is_ssh(fingerprint):
        return None
    text = normalise_fingerprint(fingerprint)
    return text if _HEX.fullmatch(text) and len(text) == len(fingerprint.replace(":", "")) else None


def is_certificate(fingerprint: str | None) -> bool:
    return certificate_hex(fingerprint) is not None


def _day(pin: SshHostKeyPin) -> str:
    return pin.confirmed_at.strftime("%Y-%m-%d")


def state(keys: SshHostKeys, presented: str | None) -> dict[str, Any] | None:
    """How a presented SSH host key compares with the pin, for the UI; None: not an SSH key.

    ``new``: nothing confirmed yet (compare and confirm); ``known``: a pinned key (the
    confirmed one or another type confirmed with it), with when and by what it was confirmed;
    ``changed``: another key, with the confirmed one.
    """
    if not is_ssh(presented):
        return None
    pin = keys.pin
    if pin is None:
        return {"kind": "ssh", "state": "new", "fingerprint": presented}
    known = keys.match(presented)
    shown = known or pin
    out = {
        "kind": "ssh",
        "fingerprint": presented,
        "pinned": pin.fingerprint,
        "algorithm": shown.algorithm,
        "confirmed_at": shown.confirmed_at.isoformat(),
        "action": shown.action,
    }
    return {"state": "known" if known else "changed", **out}


def certificate_state(rec: DeviceRecord | None, presented: str | None) -> dict[str, Any] | None:
    """How a presented certificate compares with the device's certificate pin (#535).

    None: not a certificate. ``new``: no stored device or no certificate pinned (compare and
    confirm, as before); ``known``: the pinned certificate; ``changed``: another one.
    ``confirmed_at`` is when the pin was trusted, None when Signalbox did not record it.
    """
    shown = certificate_hex(presented)
    if shown is None:
        return None
    pinned = certificate_hex(rec.pinned_fingerprint) if rec else None
    if pinned is None:
        return {"kind": "certificate", "state": "new", "fingerprint": shown}
    assert rec is not None
    return {
        "kind": "certificate",
        "state": "known" if pinned == shown else "changed",
        "fingerprint": shown,
        "pinned": pinned,
        "confirmed_at": rec.pinned_since.isoformat() if rec.pinned_since else None,
    }


# the other key types offered in a plan the user saw, by the presented key (#535): pinned with
# it after the run; kept in memory for a while (a restart only means they are not pinned)
_OFFERED: dict[str, tuple[float, dict[str, str]]] = {}
_OFFERED_TTL = 3600.0
_OFFERED_MAX = 256


async def with_offered(
    shown: dict[str, Any] | None,
    seen: Mapping[str, str],
    endpoints: Mapping[str, tuple[str, int]],
    timeout: float,
) -> dict[str, Any] | None:
    """A ``new`` SSH host key with the other key types the device offers (``offered``, #535).

    Fetched in key exchanges of their own (no login is sent) from where the presented key came
    from, shown with the key to confirm, and pinned with it by :func:`remember`.
    """
    if shown is None or shown.get("kind") != "ssh" or shown["state"] != "new":
        return shown
    presented = shown["fingerprint"]
    where = next((v for k, v in endpoints.items() if same_fingerprint(k, presented)), None)
    if where is None:
        return shown
    skip = {key_family(algorithm(seen, presented))}
    others = await offered_host_keys(where[0], where[1], min(timeout, 10.0), skip)
    others = {k: v for k, v in others.items() if not same_fingerprint(k, presented)}
    now = time.monotonic()
    for key in [k for k, (at, _) in _OFFERED.items() if now - at > _OFFERED_TTL]:
        del _OFFERED[key]
    while len(_OFFERED) >= _OFFERED_MAX:
        del _OFFERED[next(iter(_OFFERED))]
    _OFFERED[presented] = (now, others)
    shown["offered"] = [
        {"fingerprint": k, "algorithm": v} for k, v in sorted(others.items(), key=lambda kv: kv[1])
    ]
    return shown


def view(keys: SshHostKeys) -> dict[str, Any] | None:
    """The device's SSH host key for the device page; None: none confirmed, changed or old."""
    if keys.pin is None and keys.changed is None and not keys.history:
        return None
    return {
        "pin": keys.pin.model_dump(mode="json") if keys.pin else None,
        "also": [p.model_dump(mode="json") for p in keys.also],
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


def certificate_changed_answer(rec: DeviceRecord, presented: str) -> dict[str, Any]:
    """The body of a ``certificate_changed`` refusal (409, #535): old and new certificate."""
    old = certificate_hex(rec.pinned_fingerprint) or ""
    new = certificate_hex(presented) or presented
    date = rec.pinned_since.strftime("%Y-%m-%d") if rec.pinned_since else ""
    since = f" since {date}" if date else ""
    return {
        "error": "certificate_changed",
        "message": (
            f"The certificate of {rec.name} has changed{since}: old {old}, new {new}. "
            "This happens after a renewal, a reset or a reinstall, or if someone is in between. "
            "No password was sent to the device."
        ),
        "fix": (
            "Compare the new fingerprint with the one the device itself shows. Only if it "
            "matches, trust the new certificate; otherwise check the network path first."
        ),
        "message_id": "certificate.changed" if date else "certificate.changedUndated",
        "fix_id": "certificate.changed.fix",
        "params": {"device": rec.name, "date": date, "old": old, "new": new},
        "host_key": certificate_state(rec, presented),
    }


def notice_certificate(store: Store, device_id: str | None, presented: str | None) -> bool:
    """Record a presented certificate that differs from the device's pin (#535) as the one
    waiting to be trusted, as a read does; returns whether it differs."""
    rec = store.device(device_id) if device_id else None
    shown = certificate_state(rec, presented)
    if rec is None or shown is None or shown["state"] != "changed":
        return False
    if rec.pending_fingerprint != shown["fingerprint"]:
        store.set_pending_fingerprint(rec.id, shown["fingerprint"])
    return True


def refused(
    store: Store, device_id: str | None, name: str, trusts: Iterable[str | None]
) -> dict[str, Any] | None:
    """The refusal for a run whose confirmed identity is not the device's pin, or None.

    Checked before the adapter is called: with a changed SSH host key or certificate no
    password is sent.
    """
    if not device_id:
        return None
    keys = store.ssh_host_keys(device_id)
    rec = store.device(device_id)
    for trust in trusts:
        if is_certificate(trust) and rec is not None:
            shown = certificate_state(rec, trust)
            if shown is None or shown["state"] != "changed":
                continue
            if certificate_hex(rec.pending_fingerprint) == shown["fingerprint"]:
                return certificate_changed_answer(rec, shown["fingerprint"])
            return {
                "error": "untrusted",
                "message": "The certificate in this request is not the one trusted for the "
                "device; nothing was sent. Fetch the device's identity again.",
                "fingerprint": rec.pinned_fingerprint,
            }
        if keys.pin is None or not is_ssh(trust) or keys.match(trust) is not None:
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


def changed(
    store: Store,
    device_id: str | None,
    name: str,
    exc: AdapterError,
    seen: Mapping[str, str],
    action: str,
) -> dict[str, Any] | None:
    """A refused handshake with another SSH host key or certificate than the device's pin:
    the change is recorded and answered with both (409 body), or None for anything else."""
    if not device_id:
        return None
    if isinstance(exc, UntrustedHostKey):
        if not notice(store, device_id, [exc.fingerprint], seen, action):
            return None
        return changed_answer(name, store.ssh_host_keys(device_id), exc.fingerprint)
    if isinstance(exc, UntrustedCertificate):
        if not notice_certificate(store, device_id, exc.fingerprint):
            return None
        rec = store.device(device_id)
        assert rec is not None
        return certificate_changed_answer(rec, exc.fingerprint)
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
    found = False
    for fingerprint in presented:
        if is_ssh(fingerprint):
            assert fingerprint is not None
            found |= store.note_ssh_host_key_change(
                device_id, fingerprint, algorithm(seen, fingerprint), action
            )
    return found


def remember(
    store: Store, device_id: str, trusts: Iterable[str | None], seen: Mapping[str, str], action: str
) -> None:
    """After a run: store the confirmed SSH host keys the device presented in it (first trust),
    with the other key types the plan showed with them (#535).

    Only a key the run actually saw is stored, and only while the device has no pin (a pinned
    key stays; another one was refused before the run)."""
    for trust in trusts:
        if not is_ssh(trust) or not _seen(seen, trust):
            continue
        assert trust is not None
        if store.ssh_host_keys(device_id).pin is not None:
            continue
        store.pin_ssh_host_key(device_id, trust, algorithm(seen, trust), action)
        offered = next((v for k, (_, v) in _OFFERED.items() if same_fingerprint(k, trust)), None)
        if offered:
            store.pin_offered_ssh_host_keys(device_id, offered, action)


def _seen(seen: Mapping[str, str], fingerprint: str | None) -> bool:
    return any(same_fingerprint(k, fingerprint) for k in seen)


def algorithm(seen: Mapping[str, str], fingerprint: str | None) -> str | None:
    """The algorithm of a presented key (``ssh-ed25519``), when the run saw it."""
    return next((v for k, v in seen.items() if same_fingerprint(k, fingerprint)), None)
