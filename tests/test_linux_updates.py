"""Update state of Linux systems (#181) from the answer sections, for the families the
reader supports: Debian 11 to 13 and Ubuntu (apt), Fedora and RHEL 8 to 10 (dnf)."""

from __future__ import annotations

from datetime import UTC, datetime

from signalbox.adapters.linux import collect, updates
from signalbox.adapters.linux.collect import Answer


def answer(**sections: str) -> Answer:
    return Answer({k.replace("_", "-"): v for k, v in sections.items()})


def test_read_script_only_reads() -> None:
    for word in ("dnf -C -q check-update", "apt-get -s ", "apt-config shell"):
        assert word in collect.READ
    for banned in ("apt-get upgrade", "apt-get install", "dnf upgrade", "dnf install"):
        assert banned not in collect.READ


def test_apt_with_unattended_upgrades_and_a_pending_restart() -> None:
    a = answer(
        updates_files="@@@ /var/run/reboot-required\n*** System restart required ***\n",
        updates_timers="unattended-upgrades.service enabled\napt-daily-upgrade.timer enabled\n",
        updates_apt_auto="U='1'\ninstalled\n",
        updates_apt_stamp="1767225600\n",
        updates_apt="# ok\nInst a [1] (2 Ubuntu:24.04/noble-security [amd64])\nInst b [1] (2 x)\n",
    )
    assert updates.read(a, "apt") == {
        "auto_update": True,
        "last_checked": datetime(2026, 1, 1, tzinfo=UTC),
        "pending_updates": 2,
        "upgradable": True,
        "pending_security_updates": 1,
        "security_update": True,
        "reboot_pending": True,
    }


def test_apt_without_the_package_or_with_the_timer_off_does_not_update_by_itself() -> None:
    off = answer(updates_apt_auto="U='1'\n", updates_apt="# ok\n")
    assert updates.read(off, "apt")["auto_update"] is False
    assert updates.read(off, "apt")["pending_updates"] == 0
    zero = answer(updates_apt_auto="U='0'\ninstalled\n")
    assert updates.read(zero, "apt")["auto_update"] is False
    timer = answer(
        updates_apt_auto="U='1'\ninstalled\n", updates_timers="apt-daily-upgrade.timer masked\n"
    )
    assert updates.read(timer, "apt")["auto_update"] is False


def test_nothing_is_said_where_the_tools_gave_nothing() -> None:
    assert updates.read(answer(), "apt") == {}
    assert updates.read(answer(), "pacman") == {}
    assert updates.read(answer(updates_apt="# ok\n"), "dnf") == {}


def test_dnf_automatic_timers_and_apply_updates() -> None:
    install = answer(updates_timers="dnf-automatic-install.timer enabled\n")
    assert updates.read(install, "dnf")["auto_update"] is True
    conf = "@@@ /etc/dnf/automatic.conf\n[commands]\napply_updates = yes\n"
    yes = answer(updates_timers="dnf-automatic.timer enabled\n", updates_files=conf)
    assert updates.read(yes, "dnf")["auto_update"] is True
    notify = answer(updates_timers="dnf-automatic.timer enabled\n")
    assert updates.read(notify, "dnf")["auto_update"] is False
    disabled = answer(updates_timers="dnf-automatic.timer disabled\n")
    assert updates.read(disabled, "dnf")["auto_update"] is False


def test_dnf_counts_from_the_cache() -> None:
    a = answer(
        updates_dnf="# ok\nbash.x86_64 5.2.2-1 baseos\nkernel.x86_64 6.1 baseos\n\n"
        "Obsoleting Packages\nold.x86_64 1 baseos\n",
        updates_dnf_security="RHSA-2026:1 Important/Sec. kernel-6.1.x86_64\n",
    )
    out = updates.read(a, "dnf")
    assert (out["pending_updates"], out["pending_security_updates"]) == (2, 1)
    unknown = answer(updates_dnf="# ok\nbash.x86_64 5.2.2-1 baseos\n")
    assert "pending_security_updates" not in updates.read(unknown, "dnf")
    none = answer(updates_dnf="# ok\n")
    assert updates.read(none, "dnf")["pending_security_updates"] == 0
