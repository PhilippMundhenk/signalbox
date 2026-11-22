"""Show the end of a log file as GitHub Actions error annotations (#136).

    python3 tools/integration/annotate.py <file> <title> [lines]

The job logs of a failed integration run are long and not always at hand; annotations are
part of the check run. The last ``lines`` lines (default 60) of the file become ``::error::``
annotations of at most 40 lines each, escaped as GitHub expects.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHUNK = 40


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotations(text: str, title: str, lines: int = 60) -> list[str]:
    tail = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text).splitlines()[-lines:]
    chunks = [tail[i : i + CHUNK] for i in range(0, len(tail), CHUNK)] or [["(empty)"]]
    name = escape(title).replace(",", "%2C").replace("::", "%3A%3A")
    return [
        f"::error title={name} ({n}/{len(chunks)})::" + escape("\n".join(chunk))
        for n, chunk in enumerate(chunks, 1)
    ]


def main() -> None:
    path, title = Path(sys.argv[1]), sys.argv[2]
    lines = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    if not path.is_file():
        print(f"::notice title={escape(title)}::{path} does not exist")
        return
    for line in annotations(path.read_text(errors="replace"), title, lines):
        print(line)


if __name__ == "__main__":
    main()
