"""Login for the web interface: one password (hashed with scrypt), sessions in memory."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from typing import TextIO

from signalbox.store import Store

log = logging.getLogger(__name__)

COOKIE = "signalbox_session"
SETTING = "auth.password"
MAX_FAILURES = 5
LOCK_SECONDS = 60
MAX_TRACKED_CLIENTS = 1000


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()


class Locked(Exception):
    def __init__(self, seconds: int) -> None:
        self.seconds = seconds
        super().__init__(f"locked for {seconds} s")


class Auth:
    def __init__(
        self,
        store: Store,
        password: str | None,
        session_hours: float,
        announce_to: TextIO | None = None,
    ) -> None:
        self.store = store
        self.session_seconds = session_hours * 3600
        self.sessions: dict[str, float] = {}
        self.failures: dict[str, int] = {}
        self.locked: dict[str, float] = {}
        #: True when the password comes from the configuration and cannot be changed in the UI.
        self.fixed = bool(password)
        if password:
            self.salt = os.urandom(16)
            self.hash = _hash(password, self.salt)
        elif (stored := store.get_setting(SETTING)) is not None:
            data = json.loads(stored)
            self.salt, self.hash = bytes.fromhex(data["salt"]), data["hash"]
        else:
            generated = secrets.token_urlsafe(12)
            self.set_password(generated)
            announce(generated, announce_to)
            log.warning("No password configured: generated one and printed it once")

    def set_password(self, password: str) -> None:
        self.salt = os.urandom(16)
        self.hash = _hash(password, self.salt)
        self.store.set_setting(SETTING, json.dumps({"salt": self.salt.hex(), "hash": self.hash}))
        self.sessions.clear()

    def check(self, password: str) -> bool:
        return hmac.compare_digest(_hash(password, self.salt), self.hash)

    def login(self, password: str, client: str) -> str | None:
        """A session token, or None. Raises Locked after too many failures from one client."""
        now = time.time()
        until = self.locked.get(client, 0.0)
        if now < until:
            raise Locked(int(until - now) + 1)
        if not self.check(password):
            if client not in self.failures and len(self.failures) >= MAX_TRACKED_CLIENTS:
                self.failures.pop(next(iter(self.failures)))
            self.failures[client] = self.failures.get(client, 0) + 1
            if self.failures[client] >= MAX_FAILURES:
                del self.failures[client]
                if len(self.locked) >= MAX_TRACKED_CLIENTS:
                    self.locked = {k: v for k, v in self.locked.items() if v > now}
                while len(self.locked) >= MAX_TRACKED_CLIENTS:
                    self.locked.pop(min(self.locked, key=lambda k: self.locked[k]))
                self.locked[client] = now + LOCK_SECONDS
            return None
        self.failures.pop(client, None)
        self.locked.pop(client, None)
        token = secrets.token_urlsafe(32)
        self.sessions[token] = now + self.session_seconds
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        expiry = self.sessions.get(token)
        if expiry is None:
            return False
        if expiry < time.time():
            del self.sessions[token]
            return False
        return True

    def logout(self, token: str | None) -> None:
        self.sessions.pop(token or "", None)


def announce(password: str, stream: TextIO | None = None) -> None:
    """Show a generated password once, on stderr, whatever the log level."""
    stream = stream or sys.stderr
    line = "=" * 64
    stream.write(
        f"\n{line}\n Signalbox: no password was configured, one was generated.\n"
        f" Web interface password: {password}\n"
        f" It is shown only this once and stored hashed in the data folder.\n"
        f" Change it under Settings, set SIGNALBOX_AUTH_PASSWORD, or run\n"
        f" 'signalbox reset-password' to generate a new one.\n{line}\n\n"
    )
    stream.flush()


def reset_password(store: Store) -> str:
    """Generate and store a new password (takes effect at the next start)."""
    password = secrets.token_urlsafe(12)
    salt = os.urandom(16)
    store.set_setting(SETTING, json.dumps({"salt": salt.hex(), "hash": _hash(password, salt)}))
    return password
