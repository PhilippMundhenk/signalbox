"""rpcd logins of OpenWrt (#175): ``uci get rpcd``, ``config login`` sections.

A login section holds ``username``, ``password`` (``$p$<user>``: the system user's password
from ``/etc/shadow``; otherwise a crypt hash made with ``uhttpd -m``) and the ACL groups it may
``read`` and ``write`` (``*``: all). :func:`scrub` drops every ``password`` option the moment the
answer arrives and keeps only whether one is set; nothing here copies, stores or logs a hash.
"""

from __future__ import annotations

from typing import Any

from signalbox.model import AccountPrivilege, DeviceAccount


def scrub(answer: dict[str, Any]) -> dict[str, Any]:
    """The ``uci get rpcd`` answer without password hashes (in place; also returned):
    ``password`` becomes ``password_kind``: ``system`` (``$p$``), ``hash`` or ``none``."""
    values = answer.get("values")
    for section in values.values() if isinstance(values, dict) else []:
        if not isinstance(section, dict) or "password" not in section:
            continue
        value = str(section.pop("password") or "").strip()
        section["password_kind"] = (
            "system" if value.startswith("$p$") else "hash" if value else "none"
        )
    return answer


def _groups(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return str(value).split() if isinstance(value, str) else []


def privilege(read: list[str], write: list[str]) -> AccountPrivilege:
    """``write *`` is admin, any other write group write, read groups only read."""
    if "*" in write:
        return AccountPrivilege.ADMIN
    if write:
        return AccountPrivilege.WRITE
    if read:
        return AccountPrivilege.READ
    return AccountPrivilege.OTHER


def logins(answer: dict[str, Any], own: str) -> list[DeviceAccount]:
    """The login sections of a scrubbed answer, in file order; ``own``: Signalbox's login."""
    values = answer.get("values")
    found: list[tuple[int, DeviceAccount]] = []
    for s in values.values() if isinstance(values, dict) else []:
        if not isinstance(s, dict) or s.get(".type") != "login":
            continue
        name = str(s.get("username") or "").strip()
        if not name:
            continue
        kind = s.get("password_kind")
        try:
            index = int(str(s.get(".index", 0)))
        except ValueError:
            index = 0
        found.append(
            (
                index,
                DeviceAccount(
                    name=name,
                    privilege=privilege(_groups(s.get("read")), _groups(s.get("write"))),
                    # $p$root: the system password, which is not readable (good): unknown
                    password_set=None if kind == "system" else kind == "hash",
                    is_signalbox=name == own,
                ),
            )
        )
    return [a for _, a in sorted(found, key=lambda item: item[0])]
