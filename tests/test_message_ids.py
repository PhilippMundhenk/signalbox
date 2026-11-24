"""Translatable server texts (#204): ids, parameters and the English catalogue agree."""

from __future__ import annotations

import ast
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
    missing = sorted(i for i in ids if not _has(EN, i))
    assert not missing, f"message ids without msg.<id> in en.json: {missing}"


def _has(catalogue: dict[str, str], mid: str) -> bool:
    """The id is in the catalogue, or in its plural forms (``.one`` / ``.other``)."""
    key = f"msg.{mid}"
    return key in catalogue or f"{key}.other" in catalogue


def test_every_message_id_exists_in_german_with_the_same_parameters() -> None:
    de = json.loads((SRC / "web" / "static" / "i18n" / "de.json").read_text(encoding="utf-8"))
    missing = sorted(i for i in _used_ids() if not _has(de, i))
    assert not missing, f"message ids without msg.<id> in de.json: {missing}"
    msg_keys = [k for k in EN if k.startswith("msg.")]
    assert sorted(msg_keys) == sorted(k for k in de if k.startswith("msg."))
    for key in msg_keys:
        assert set(MSG.findall(EN[key])) == set(MSG.findall(de[key])), key


def _calls(path: Path, names: set[str]) -> list[tuple[ast.Call, dict[str, ast.expr]]]:
    out = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name in names:
                out.append((node, {k.arg: k.value for k in node.keywords if k.arg}))
    return out


def test_every_finding_of_the_rule_modules_carries_a_message_id() -> None:
    bad = []
    for path in sorted((SRC / "rules").glob("*.py")):
        if path.name == "__init__.py":
            continue
        for node, kw in _calls(path, {"found", "incomplete"}):
            if "mid" not in kw:
                bad.append(f"{path.name}:{node.lineno}")
    assert not bad, f"found()/incomplete() without mid=: {bad}"


def test_every_gap_and_fix_of_the_adapters_carries_ids() -> None:
    """``Gap(...)`` needs ``message_id=``, and a Gap or error with a literal ``fix=`` needs
    ``fix_id=`` (#204). Not covered: a gap that only passes on a parser's own text
    (``Gap(message=m)``) and a ``fix=`` that passes on another exception's (``fix=exc.fix``)."""
    bad = []
    for path in sorted((SRC / "adapters").rglob("*.py")):
        for node, kw in _calls(path, {"Gap", "AdapterError", "AuthFailed", "Unreachable"}):
            gap = isinstance(node.func, ast.Name) and node.func.id == "Gap"
            own_text = isinstance(kw.get("message"), ast.Name)
            passed_on = isinstance(kw.get("fix"), ast.Attribute | ast.Name)
            if (gap and not own_text and "message_id" not in kw) or (
                "fix" in kw and not passed_on and "fix_id" not in kw
            ):
                bad.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}")
    assert not bad, f"Gap or fix without an id: {bad}"


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
