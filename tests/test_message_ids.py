"""Translatable server texts (#204): ids, parameters and the English catalogue agree."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from signalbox.model import ReadError
from signalbox.rules import Finding, Severity, found, incomplete

SRC = Path(__file__).parent.parent / "src" / "signalbox"
EN = json.loads((SRC / "web" / "static" / "i18n" / "en.json").read_text(encoding="utf-8"))
ID_LITERAL = re.compile(r"""\b(?:mid|fix_id|title_id|message_id)\s*=\s*["']([\w.\-]+)["']""")
MSG = re.compile(r"\{(\w+)\}")


def _used_ids() -> set[str]:
    ids = set()
    for path in SRC.rglob("*.py"):
        ids.update(ID_LITERAL.findall(path.read_text(encoding="utf-8")))
    return ids


def test_every_message_id_in_the_code_has_an_english_catalogue_entry() -> None:
    ids = _used_ids()
    assert len(ids) >= 30
    missing = sorted(i for i in ids if f"msg.{i}" not in EN)
    assert not missing, f"message ids without msg.<id> in en.json: {missing}"


def test_found_and_incomplete_carry_ids_and_params() -> None:
    res = found("x", ["a"], mid="m.id", fix_id="m.fix", params={"n": 1})
    assert (res.message_id, res.fix_id, dict(res.params)) == ("m.id", "m.fix", {"n": 1})
    inc = incomplete("y", ["a"], mid="m.inc", params={"s": "t"})
    assert inc.message_id == "m.inc" and inc.incomplete
    plain = found("z", [])
    assert plain.message_id is None and dict(plain.params) == {}


def test_finding_and_read_error_default_to_no_id() -> None:
    f = Finding(id="1", rule_id="r", severity=Severity.INFO, title="t", message="m")
    assert f.message_id is None and f.params == {}
    e = ReadError(device_id="d", capability="c", message="m")
    assert e.message_id is None and e.fix_id is None


@pytest.mark.parametrize("key", [k for k in EN if k.startswith("rule.")])
def test_rule_catalogue_keys_name_existing_rules(key: str) -> None:
    from signalbox.rules import ENGINE_RULES, load_rules

    ids = {r.id for r in [*load_rules(), *ENGINE_RULES]}
    rule_id = key.removeprefix("rule.").rsplit(".", 1)[0]
    assert rule_id in ids
