"""Print the rpcd ACL with write access from docs/adapters/openwrt.md (for the test image).

The integration test image installs exactly the ACL the documentation tells users to install,
so a wrong ACL in the docs fails the integration tests. Its read part must equal the read-only
ACL of the docs (checked here), so the read-only login tests that one.

    python3 acl_from_docs.py docs/adapters/openwrt.md > signalbox.json
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any


def acl_under(markdown: str, heading: str) -> dict[str, Any]:
    """The first JSON block after ``heading``."""
    block = re.search(r"```json\n(.*?)```", markdown.split(heading, 1)[1], re.S)
    if block is None:
        raise SystemExit(f"no JSON block under {heading!r}")
    acl: dict[str, Any] = json.loads(block.group(1))
    return acl


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as f:
        markdown = f.read()
    read_only = acl_under(markdown, "## Read-only user on the device")
    write = acl_under(markdown, "### Login with write access")
    if write["signalbox"]["read"] != read_only["signalbox"]["read"]:
        raise SystemExit("the read part of the write ACL differs from the read-only ACL")
    json.dump(write, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
