"""Regenerate the offline MAC vendor database (issue #84).

    python tools/gen_oui.py path/to/oui.csv            # from a downloaded registry file
    python tools/gen_oui.py --download                 # fetch it from the IEEE first

The input is the IEEE "MA-L" registry (https://standards-oui.ieee.org/oui/oui.csv). Only the
prefix and a shortened organisation name are kept (street addresses are dropped), written as
``src/signalbox/data/oui.bin.xz``. The output is deterministic for a given input.
"""

from __future__ import annotations

import csv
import io
import lzma
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from signalbox.oui import DATA_FILE, encode  # noqa: E402

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = ROOT / "src" / "signalbox" / "data" / DATA_FILE

#: Legal forms at the end of a company name; dropped from the short name.
LEGAL = frozenset(
    {
        *("co", "ltd", "limited", "inc", "incorporated", "llc", "gmbh", "corp", "corporation"),
        *("company", "ag", "bv", "sa", "srl", "spa", "oy", "ab", "pte", "pty", "kg", "plc"),
        *("lp", "llp", "sarl", "nv", "sas", "bhd"),
    }
)


def short_name(name: str) -> str:
    """``Hangzhou Hikvision Digital Technology Co.,Ltd.`` -> ``Hangzhou Hikvision Digital
    Technology``: no legal form, no stray punctuation, single spaces."""
    words = name.replace(",", ", ").split()
    while len(words) > 1 and re.sub(r"[^a-z]", "", words[-1].lower()) in LEGAL | {""}:
        words.pop()
    text = " ".join(words).strip(" ,.;&-")
    return text or name.strip()


def parse(text: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        if row.get("Registry") != "MA-L":
            continue
        assignment = row["Assignment"].strip()
        if re.fullmatch(r"[0-9A-Fa-f]{6}", assignment):
            out[int(assignment, 16)] = short_name(row["Organization Name"])
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    if argv[0] == "--download":
        with urllib.request.urlopen(URL, timeout=60) as resp:
            text = resp.read().decode("utf-8")
    else:
        text = Path(argv[0]).read_text(encoding="utf-8")
    entries = parse(text)
    if len(entries) < 10000:
        print(f"only {len(entries)} entries: is this the MA-L registry?", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(lzma.compress(encode(entries), preset=9 | lzma.PRESET_EXTREME))
    print(f"{len(entries)} prefixes, {OUT.stat().st_size} bytes -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
