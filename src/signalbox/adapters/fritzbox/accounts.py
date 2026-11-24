"""The XML lists in the answers of ``LANConfigSecurity`` (#175).

``X_AVM-DE_GetUserList`` answers ``<List><Username last_user="1">name</Username>...</List>``,
``X_AVM-DE_GetCurrentUser`` the rights of the calling user as
``<rights><path>BoxAdmin</path><access>readwrite</access>...</rights>`` (AVM's TR-064
documentation of LANConfigSecurity; the exact layout is a *guess* until a box confirms it,
#21). Both are parsed with the SOAP parser, which refuses document type declarations.
"""

from __future__ import annotations

from signalbox.adapters import AdapterError
from signalbox.adapters.fritzbox.soap import parse_xml
from signalbox.model import AccountPrivilege


def user_names(text: str) -> list[str]:
    """The user names of a user list, in its order; [] for an empty or unreadable list."""
    if not text.strip():
        return []
    try:
        root = parse_xml(text.encode(), "LANConfigSecurity1 user list")
    except AdapterError:
        return []
    names: list[str] = []
    for e in root.iter():
        if e.tag.rsplit("}", 1)[-1] == "Username" and (e.text or "").strip():
            name = (e.text or "").strip()
            if name not in names:
                names.append(name)
    return names


def box_rights(text: str) -> AccountPrivilege | None:
    """The privilege of the right "FRITZ!Box settings" (``BoxAdmin``): ``readwrite`` is
    admin (it can change every setting, the users too), ``read`` read; without it other.
    ``None`` when the rights cannot be read."""
    if not text.strip():
        return None
    try:
        root = parse_xml(text.encode(), "LANConfigSecurity1 current user rights")
    except AdapterError:
        return None
    rights: dict[str, str] = {}
    path = ""
    for e in root.iter():
        tag = e.tag.rsplit("}", 1)[-1]
        if tag == "path":
            path = (e.text or "").strip()
        elif tag == "access" and path:
            rights[path] = (e.text or "").strip().lower()
            path = ""
    access = rights.get("BoxAdmin")
    if access == "readwrite":
        return AccountPrivilege.ADMIN
    if access == "read":
        return AccountPrivilege.READ
    return AccountPrivilege.OTHER
