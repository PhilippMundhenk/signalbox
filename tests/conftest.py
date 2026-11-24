"""Shared test setup."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

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


def _english(mid: str, params: dict[str, object]) -> str:
    """The English catalogue entry ``msg.<mid>`` filled with the params (#204)."""
    import json
    import re
    from pathlib import Path

    from signalbox import rules

    path = Path(rules.__file__).parents[1] / "web" / "static" / "i18n" / "en.json"
    catalogue: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
    key = f"msg.{mid}"
    if key not in catalogue:
        count = params.get("count")
        key = f"{key}.{'one' if count == 1 else 'other'}"
    assert key in catalogue, f"{mid}: no entry in en.json"
    missing = set(re.findall(r"\{(\w+)\}", catalogue[key])) - set(params)
    assert not missing, f"{mid}: params lack {sorted(missing)}"
    return re.sub(r"\{(\w+)\}", lambda m: str(params[m.group(1)]), catalogue[key])


@pytest.fixture(autouse=True)
def _findings_match_their_english_catalogue_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Translations (#204): wherever a finding carries a message id, the English catalogue entry
    filled with its params is exactly its English text, so the two cannot drift apart."""
    from signalbox import rules

    original = rules._finding

    def checked(rule: rules.Rule, res: rules.Result, severity: rules.Severity) -> rules.Finding:
        finding = original(rule, res, severity)
        if finding.message_id:
            assert _english(finding.message_id, finding.params) == finding.message
        if finding.fix_id:
            assert finding.fix and _english(finding.fix_id, finding.params) == finding.fix
        return finding

    monkeypatch.setattr(rules, "_finding", checked)


@pytest.fixture(autouse=True)
def _read_errors_match_their_english_catalogue_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same for the read errors and gaps adapters report (#204)."""
    from signalbox import adapters
    from signalbox.model import ReadError

    def checked(**fields: Any) -> ReadError:
        error = ReadError(**fields)
        if error.message_id:
            assert _english(error.message_id, error.params) == error.message
        if error.fix_id:
            assert error.fix and _english(error.fix_id, error.params) == error.fix
        return error

    monkeypatch.setattr(adapters, "ReadError", checked)
