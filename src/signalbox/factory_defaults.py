"""Factory-default logins of the supported device kinds (#126, #175, ADR 0020).

The only place with these literals (``.gitleaks.toml`` allows this file, and only this file).
They are the vendors' documented defaults, not secrets of anyone.

An integration calls :func:`is_factory_default` with the login it was configured with; the
comparison runs in memory, in constant time, and only the boolean leaves this module (it becomes
``Device.default_credentials``). Nothing here logs, stores or hashes a secret, and nothing here
sends anything to a device: Signalbox never tries a default login on its own (the only probe,
OpenWrt's empty root password, is the integration's, opt-in per device).
"""

from __future__ import annotations

import hmac

#: Per factory-default list: (user name, password) pairs. A user name of ``None`` matches any
#: user name (devices with a password only).
FACTORY_DEFAULTS: dict[str, tuple[tuple[str | None, str], ...]] = {
    # NETGEAR ProSAFE Plus (NSDP): one management password, "password" from the factory
    "prosafe": ((None, "password"),),
    # TP-Link Easy Smart: admin / admin
    "easysmart": (("admin", "admin"),),
    # MikroTik RouterOS before 6.49 / without a printed password: admin with an empty password
    "mikrotik": (("admin", ""),),
    # OpenWrt: root without a password until one is set
    "openwrt": (("root", ""),),
    # TP-Link Omada devices (standalone, and the site's device account): admin / admin
    "omada-device": (("admin", "admin"),),
}


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def is_factory_default(kind: str, password: str, username: str | None = None) -> bool:
    """Whether ``username`` / ``password`` is a factory default of ``kind`` (a key of
    :data:`FACTORY_DEFAULTS`). User names compare case-insensitively, passwords exactly."""
    user = (username or "").strip().lower()
    found = False
    for default_user, default_password in FACTORY_DEFAULTS.get(kind, ()):
        if default_user is not None and default_user != user:
            continue
        # no early return: the time does not depend on which entry matched
        found = _same(password, default_password) or found
    return found


def has_defaults(kind: str) -> bool:
    """Whether a factory-default list exists for ``kind``."""
    return kind in FACTORY_DEFAULTS
