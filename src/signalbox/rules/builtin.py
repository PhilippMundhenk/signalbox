"""The rules that ship with Signalbox (registered as the ``builtin`` entry point).

Every module in :mod:`signalbox.rules` that defines ``RULES`` is picked up here, so a new rule
module registers itself: no shared list to edit (parallel work does not conflict here). Its
documentation goes into ``docs/rules/<module>.md``.
"""

from __future__ import annotations

import importlib
import pkgutil

import signalbox.rules as _package
from signalbox.rules import Rule

#: modules that are not rule groups
_SKIP = {"builtin"}
#: rule groups that live outside the package
_EXTRA = ["signalbox.topology"]


def _discover() -> list[Rule]:
    names = sorted(
        f"{_package.__name__}.{m.name}"
        for m in pkgutil.iter_modules(_package.__path__)
        if not m.name.startswith("_") and m.name not in _SKIP
    )
    found: list[Rule] = []
    for name in [*names, *_EXTRA]:
        rules = getattr(importlib.import_module(name), "RULES", None)
        if rules is not None:
            found.extend(rules)
    return found


RULES: list[Rule] = _discover()
