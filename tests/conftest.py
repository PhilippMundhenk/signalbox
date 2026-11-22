"""Shared test setup."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from signalbox.model import set_passphrase_digest_key


@pytest.fixture(autouse=True)
def _no_passphrase_digest_key() -> Iterator[None]:
    """Every test starts without a passphrase digest key (#167): ``service.build`` installs one
    process-wide, and tests share worker processes. Use ``signalbox.testing.passphrase_digest_key``
    for a key."""
    old = set_passphrase_digest_key(None)
    yield
    set_passphrase_digest_key(old)
