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


@pytest.fixture(autouse=True)
def _no_fake_adapter_failures() -> Iterator[None]:
    """``Fake.fail`` is a class attribute that tests set to make the fake adapter fail; reset it
    after every test too (not only before the next test of one module), or the last test of
    ``test_adapters`` leaks its failure into whichever test a worker runs next (#294)."""
    from test_adapters import Fake

    Fake.fail = {}
    yield
    Fake.fail = {}
