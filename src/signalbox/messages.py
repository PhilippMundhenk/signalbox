"""Texts that travel with a translation id and values (#204): names Signalbox gives things."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Separates the arguments of a :class:`Label` token.
LABEL_SEP = "\x1f"


class Label(str):
    """A name Signalbox itself gives a thing ("firewall rule x", "SSID y"), #204.

    As a string it is the English text. In a message's ``params`` it travels as a token
    (``@lbl.<key>:<args>``) that the UI translates with the catalogue entry ``lbl.<key>``, whose
    placeholders ``{1}``, ``{2}`` take the arguments; names the device supplied stay as they are.
    """

    token: str

    def __new__(cls, english: str, key: str, *args: object) -> Label:
        text = super().__new__(cls, english)
        text.token = f"@lbl.{key}" + (":" + LABEL_SEP.join(str(a) for a in args) if args else "")
        return text


def plain_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """``params`` with every :class:`Label` replaced by its token (what is sent and stored)."""
    return {k: v.token if isinstance(v, Label) else v for k, v in (params or {}).items()}
