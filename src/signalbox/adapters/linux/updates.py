"""Update state of a general-purpose Linux system (#181), from files and caches only.

Debian family (Debian 11 to 13, Ubuntu): the effective ``APT::Periodic::Unattended-Upgrade``
(``apt-config shell``), whether ``unattended-upgrade`` is installed and its timer not disabled,
the time of the last successful ``apt update`` (``update-success-stamp``) and the upgradable
packages of ``apt-get -s upgrade`` (the package lists of the last update; nothing is fetched).
Fedora family (Fedora, RHEL 8 to 10): ``dnf-automatic`` timers and ``apply_updates``, and
``dnf -C check-update`` (cache only). ``/var/run/reboot-required`` says a restart is pending.
Nothing needs root. Anything the system does not say stays ``None``; an absent reboot marker
is not "no reboot pending" (not every system writes it).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from signalbox.adapters.linux.collect import Answer

REBOOT_FILE = "/var/run/reboot-required"
_DNF_CONFIGS = ("/etc/dnf/automatic.conf", "/etc/dnf/dnf5-plugins/automatic.conf")
#: Timers that install by themselves, and the one that does it when ``apply_updates = yes``.
_DNF_INSTALL = ("dnf-automatic-install.timer",)
_DNF_CONFIGURED = ("dnf-automatic.timer", "dnf5-automatic.timer")
_DNF_ALL = (*_DNF_INSTALL, *_DNF_CONFIGURED)
_ENABLED = ("enabled", "enabled-runtime", "static", "alias", "indirect", "generated")


def _timers(answer: Answer) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in answer.lines("updates-timers"):
        name, _, state = line.partition(" ")
        out[name] = state.strip()
    return out


def _apt_auto(answer: Answer, timers: dict[str, str]) -> bool | None:
    lines = answer.lines("updates-apt-auto")
    value = next((m.group(1) for ln in lines if (m := re.match(r"U='?(\w*)'?$", ln.strip()))), "")
    if not lines:
        return None  # no apt-config: nothing is known
    enabled = value.isdigit() and int(value) > 0
    installed = "installed" in lines
    timer = timers.get("apt-daily-upgrade.timer", "")
    return enabled and installed and timer not in ("disabled", "masked")


def _dnf_apply(answer: Answer) -> bool:
    files = answer.files("updates-files")
    for path in _DNF_CONFIGS:
        for line in files.get(path, "").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "apply_updates":
                return value.strip().lower() in ("yes", "true", "1", "on")
    return False


def _dnf_auto(answer: Answer, timers: dict[str, str]) -> bool | None:
    if not any(n in timers for n in _DNF_ALL):
        return None
    if any(timers.get(n, "") in _ENABLED for n in _DNF_INSTALL):
        return True
    return any(timers.get(n, "") in _ENABLED for n in _DNF_CONFIGURED) and _dnf_apply(answer)


def _apt_counts(answer: Answer) -> tuple[int, int] | None:
    lines = answer.lines("updates-apt")
    if "# ok" not in lines:
        return None
    inst = [ln for ln in lines if ln.startswith("Inst ")]
    return len(inst), sum(1 for ln in inst if "-security" in ln.lower())


def _dnf_counts(answer: Answer) -> tuple[int, int | None] | None:
    lines = answer.lines("updates-dnf")
    if "# ok" not in lines:
        return None
    pending = 0
    for ln in lines:
        if ln.startswith("Obsoleting"):
            break
        parts = ln.split()
        if len(parts) == 3 and "." in parts[0]:
            pending += 1
    security = sum(1 for ln in answer.lines("updates-dnf-security") if "/Sec." in ln)
    return pending, (security if security or not pending else None)


def read(answer: Answer, manager: str | None) -> dict[str, Any]:
    """``Firmware`` fields for the update state of this system (empty: nothing said)."""
    out: dict[str, Any] = {}
    timers = _timers(answer)
    counts: tuple[int, int | None] | None = None
    if manager == "apt":
        out["auto_update"] = _apt_auto(answer, timers)
        counts = _apt_counts(answer)
        stamp = answer.text("updates-apt-stamp").strip()
        if stamp.isdigit():
            out["last_checked"] = datetime.fromtimestamp(int(stamp), UTC)
    elif manager == "dnf":
        out["auto_update"] = _dnf_auto(answer, timers)
        counts = _dnf_counts(answer)
    if counts is not None:
        out["pending_updates"] = counts[0]
        out["upgradable"] = counts[0] > 0
        if counts[1] is not None:
            out["pending_security_updates"] = counts[1]
            out["security_update"] = counts[1] > 0
    if REBOOT_FILE in answer.files("updates-files"):
        out["reboot_pending"] = True
    return {k: v for k, v in out.items() if v is not None}
