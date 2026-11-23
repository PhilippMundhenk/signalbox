"""Message catalogues (#204): keys used by the UI exist, catalogues have no stale keys."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

STATIC = Path(__file__).parent.parent / "src" / "signalbox" / "web" / "static"
I18N = STATIC / "i18n"
#: Keys that are not written out in the UI code: the catalogue entries for texts the server
#: sends with an id (``msg.*``), for rules (``rule.<id>.title``) and for dynamic groups.
SERVER_PREFIXES = ("msg.", "rule.", "step.", "vendor.")
PLURAL = re.compile(r"\.(zero|one|two|few|many|other)$")


def _load(code: str) -> dict[str, str]:
    data = json.loads((I18N / f"{code}.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _languages() -> list[str]:
    index = json.loads((I18N / "index.json").read_text(encoding="utf-8"))
    return [entry["code"] for entry in index]


def _base(key: str) -> str:
    return PLURAL.sub("", key)


def _js_files() -> list[Path]:
    return list(STATIC.rglob("*.js"))


def _used_keys(namespaces: set[str]) -> set[str]:
    """Every string literal in the UI code that looks like a key of a known namespace."""
    literal = re.compile(r"""['"`]([a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9_-]+)+)['"`]""")
    used = set()
    for path in _js_files():
        for match in literal.finditer(path.read_text(encoding="utf-8")):
            key = match.group(1)
            if key.split(".")[0] in namespaces:
                used.add(key)
    return used


def test_english_is_complete_for_the_ui() -> None:
    en = _load("en")
    bases = {_base(k) for k in en}
    namespaces = {k.split(".")[0] for k in en} - {"msg", "rule"}
    missing = sorted(k for k in _used_keys(namespaces) if k not in en and k not in bases)
    assert not missing, f"keys used in the UI but not in en.json: {missing}"


def test_english_has_no_unused_keys() -> None:
    en = _load("en")
    namespaces = {k.split(".")[0] for k in en}
    used = _used_keys(namespaces)
    unused = sorted(
        k
        for k in en
        if not k.startswith(SERVER_PREFIXES) and k not in used and _base(k) not in used
    )
    assert not unused, f"keys in en.json that no UI code uses: {unused}"


@pytest.mark.parametrize("code", [c for c in _languages() if c != "en"])
def test_translation_has_no_stale_keys_and_matching_placeholders(code: str) -> None:
    en, other = _load("en"), _load(code)
    stale = sorted(set(other) - set(en))
    assert not stale, f"{code}.json has keys that en.json does not: {stale}"
    holder = re.compile(r"\{(\w+)\}")
    bad = sorted(
        k for k, v in other.items() if set(holder.findall(v)) != set(holder.findall(en[k]))
    )
    assert not bad, f"{code}.json changes the placeholders of: {bad}"


@pytest.mark.parametrize("code", [c for c in _languages() if c != "en"])
def test_translation_is_complete_for_the_ui(code: str) -> None:
    """The first complete language is German; a language added later may start partial."""
    if code != "de":
        pytest.skip("only German is required to be complete")
    missing = sorted(set(_load("en")) - set(_load(code)))
    assert not missing, f"de.json lacks: {missing}"


def test_index_lists_existing_catalogues() -> None:
    index = json.loads((I18N / "index.json").read_text(encoding="utf-8"))
    for entry in index:
        assert (I18N / f"{entry['code']}.json").is_file()
        assert entry["dir"] in ("ltr", "rtl")
    assert "en" in [e["code"] for e in index]
