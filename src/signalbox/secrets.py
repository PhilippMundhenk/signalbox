"""Encryption of device credentials with a key kept outside the database."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

KEY_FILE = "secret.key"
KEY_ENV = "SIGNALBOX_SECRET_KEY"


class SecretError(Exception):
    pass


class Vault:
    """Encrypts and decrypts short strings (Fernet: AES-128-CBC + HMAC-SHA256)."""

    def __init__(self, key: bytes) -> None:
        try:
            self._fernet = Fernet(key)
        except ValueError as exc:
            raise SecretError(
                "the secret key is not a valid Fernet key (32 url-safe base64 bytes)"
            ) from exc

    def encrypt(self, plain: str) -> str:
        return self._fernet.encrypt(plain.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise SecretError(
                "stored credentials cannot be decrypted: the secret key changed or the data is "
                "damaged. Restore the old key, or enter the device credentials again."
            ) from exc


def load_vault(data_dir: Path, env: Mapping[str, str] | None = None) -> Vault:
    """Key from SIGNALBOX_SECRET_KEY, else ``<data>/secret.key`` (created 0600 on first start)."""
    env = os.environ if env is None else env
    if env.get(KEY_ENV):
        return Vault(env[KEY_ENV].encode())
    path = data_dir / KEY_FILE
    if not path.exists():
        data_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(Fernet.generate_key())
    return Vault(path.read_bytes().strip())
