"""The configuration of an EdgeOS or VyOS router as a tree (#403).

``show configuration commands`` prints one ``set a b c value`` line per leaf (values with spaces
in single quotes, a quote inside as ``'\\''``). The lines are put into a trie, so ``interfaces
ethernet eth0 address 192.0.2.1/24`` is the node ``interfaces`` > ``ethernet`` > ``eth0`` >
``address`` whose children are the values. The same shape serves EdgeOS 1.x and 2.0 and VyOS
1.3 and 1.4; the readers ask for the spellings of each.

Lines that name a secret are dropped here once more, although the read script already filters
them on the device: the answer of a device is data, and a password or key must never reach the
model.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator

#: Words of configuration lines that carry a secret (never kept, whatever the device sent).
_SECRET = re.compile(
    r"private-key|preshared-key|pre-shared-key|pre-shared-secret|plaintext-password|"
    r"encrypted-password|passphrase|community|(?:^|\s)'?(?:password|secret|key)'?(?:\s|$)",
    re.I,
)


class Node:
    """One word of the configuration; its children are the words (or values) that follow."""

    __slots__ = ("children", "name")

    def __init__(self, name: str = "") -> None:
        self.name = name
        self.children: dict[str, Node] = {}

    def add(self, words: list[str]) -> None:
        node = self
        for word in words:
            node = node.children.setdefault(word, Node(word))

    def get(self, *path: str) -> Node | None:
        node: Node | None = self
        for word in path:
            node = node.children.get(word) if node is not None else None
        return node

    def has(self, *path: str) -> bool:
        return self.get(*path) is not None

    def keys(self, *path: str) -> list[str]:
        """The children's words (the values of a leaf, the names of a list)."""
        node = self.get(*path)
        return list(node.children) if node is not None else []

    def first(self, *path: str) -> str | None:
        keys = self.keys(*path)
        return keys[0] if keys else None

    def items(self, *path: str) -> Iterator[tuple[str, Node]]:
        node = self.get(*path)
        if node is not None:
            yield from node.children.items()


def split_line(line: str) -> list[str] | None:
    """The words of a ``set`` line, or None for any other line."""
    text = line.strip()
    if not text.startswith("set "):
        return None
    try:
        words = shlex.split(text[4:])
    except ValueError:
        words = text[4:].split()
    return words or None


def parse(text: str) -> Node:
    root = Node()
    for line in text.splitlines():
        if _SECRET.search(line):
            continue
        words = split_line(line)
        if words:
            root.add(words)
    return root
