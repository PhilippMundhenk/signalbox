"""OPNsense release differences (#390): the version, the two API spellings and which API
exists from which release.

The sources are the public ``opnsense/core`` tags 24.7, 25.1, 25.7 and 26.1 (controllers and
models under ``src/opnsense/mvc/app``). What was found there, per release that has it:

* ``/api/<module>/<controller>/<action>``: the router turns ``search_item`` and ``searchItem``
  into the same action since 24.7 (``Mvc/Router.php``); before that only camelCase is certain,
  so a 404 on the snake_case spelling is retried in camelCase (:func:`camel_path`).
* ``auth/user`` (user manager): 25.1; ``dnsmasq/settings``: 25.1; ``ntpd/service``: 25.7.
* ``firewall/d_nat`` (port forwards): 26.1; ``interfaces/assignment`` with addresses: 26.7.6.
* Interface negation (``interfacenot`` of a filter rule): 25.1.
"""

from __future__ import annotations

import re

Version = tuple[int, int, int]

#: Releases that first have an API (see the module docstring).
USER_API = (25, 1, 0)
DNSMASQ_API = (25, 1, 0)
NTPD_API = (25, 7, 0)
DNAT_API = (26, 1, 0)
INTERFACE_NOT = (25, 1, 0)

_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text: str) -> Version | None:
    """``25.1.12_4`` -> ``(25, 1, 12)``; ``25.7`` -> ``(25, 7, 0)``; anything else None."""
    m = _VERSION.match(text.strip())
    if m is None:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def release(version: Version) -> str:
    """``(25, 1, 12)`` -> ``25.1`` (the release line, as OPNsense names it)."""
    return f"{version[0]}.{version[1]}"


def camel_path(path: str) -> str:
    """The camelCase spelling of the action in ``/api/<module>/<controller>/<action>[/...]``.

    ``/api/firewall/filter/search_rule`` -> ``/api/firewall/filter/searchRule``. Parameters
    after the action (uuids, MACs) are left alone, and so are the module and the controller
    (the router accepts ``d_nat`` and ``dNat`` alike).
    """
    parts = path.split("/")
    # ['', 'api', module, controller, action, *parameters]
    if len(parts) < 5 or parts[1] != "api" or "_" not in parts[4]:
        return path
    head, *rest = parts[4].split("_")
    parts[4] = head + "".join(w[:1].upper() + w[1:] for w in rest)
    return "/".join(parts)
