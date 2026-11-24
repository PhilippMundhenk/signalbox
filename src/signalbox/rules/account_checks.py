"""Device account rules (#126, #175, ADR 0020).

They read :attr:`~signalbox.model.Device.default_credentials`, the privilege of Signalbox's own
login and :attr:`~signalbox.model.Device.accounts`. Account names are often personal names:
findings name the device and how many accounts are affected, never an account (the device page
shows which). Nothing here tries a login: the integrations compare the configured secret with
the factory defaults in memory, or the device says itself.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from signalbox.model import PRIVILEGE_RANK, AccountPrivilege, Device, DeviceAccount, Network
from signalbox.rules import Result, Rule, Severity, found, history_rule, rule
from signalbox.rules.vlan import address_segment
from signalbox.sightings import History

#: An administrator account that did not log in for this long is stale.
STALE_DAYS = 90
#: User names anyone tries first.
DEFAULT_NAMES = frozenset({"admin", "administrator"})


def _devices(net: Network) -> Iterator[Device]:
    yield from sorted(net.devices, key=lambda d: d.id)


def _accounts(dev: Device) -> list[DeviceAccount]:
    return [a for a in dev.accounts or [] if a.enabled]


@rule(
    "security.default-password",
    "Device uses its factory password",
    Severity.ERROR,
    "Factory passwords are the first thing anyone in the network tries; on small switches "
    "they give full control (VLANs included). Reported when the login Signalbox was given is "
    "the vendor's documented default (NETGEAR Plus `password`, TP-Link Easy Smart and Omada "
    "`admin`/`admin`, MikroTik `admin` without a password, OpenWrt `root` without a password), "
    "compared in memory without trying anything, or when the device itself says it still has "
    "its default password (FRITZ!Box). OpenWrt can also be probed for an empty root password "
    "(`probe_empty_root_password`, off by default).",
)
def default_password(net: Network) -> Iterator[Result]:
    for dev in _devices(net):
        if dev.default_credentials is not True:
            continue
        yield found(
            f"{dev.name} still has its factory password",
            [dev.id],
            fix=f"Change the password on {dev.name} (its manual describes how), then update it "
            "in Signalbox's device settings.",
            mid="account.defaultPassword",
            fix_id="account.defaultPassword.fix",
            params={"device": dev.name},
        )


@rule(
    "account.signalbox-privileged",
    "Signalbox reads with more privileges than it needs",
    Severity.INFO,
    "Signalbox only needs to read, and each integration's setup guide describes a read-only "
    'login (docs/adapters/, "read-only user"). Reported when the login it was given may do '
    "more than that guide's login, typically the administrator account. A device that may "
    "receive changes from Signalbox needs a login that may write; that is taken into account. "
    "Devices whose integration has no smaller login (FRITZ!Box, small switches) are not "
    "reported.",
)
def signalbox_privileged(net: Network) -> Iterator[Result]:
    for dev in _devices(net):
        have, need = dev.signalbox_account_privilege, dev.signalbox_account_needed
        if have is None or need is None or PRIVILEGE_RANK[have] <= PRIVILEGE_RANK[need]:
            continue
        yield found(
            f"Signalbox reads {dev.name} with a login with {have.value} rights; one with "
            f"{need.value} rights is enough",
            [dev.id],
            fix=f"Set up the read-only login of the setup guide (docs/adapters/{dev.adapter}.md, "
            "read-only user) on the device and give it to Signalbox instead.",
            mid="account.signalboxPrivileged",
            fix_id="account.signalboxPrivileged.fix",
            params={
                "device": dev.name,
                "have": have.value,
                "need": need.value,
                "adapter": dev.adapter,
            },
        )


def _reaches_clients(net: Network, dev: Device) -> bool:
    """Clients or Wi-Fi networks share the network of the device's management address."""
    sid = address_segment(net, dev)
    if sid is None:
        return False
    return any(c.segment_id == sid for c in net.clients) or any(
        w.enabled and w.segment_id == sid for w in net.wlans
    )


@rule(
    "account.admin-default-name",
    "Administrator account with the default name",
    Severity.INFO,
    "An enabled administrator account named `admin` that logs in with a password, on a device "
    "whose management address is in a network with clients or Wi-Fi: anyone there only has to "
    "guess the password. Renaming it (or using another account and disabling it) takes that "
    "half away. Accounts that only log in with a key are left out.",
)
def admin_default_name(net: Network) -> Iterator[Result]:
    for dev in _devices(net):
        hits = [
            a
            for a in _accounts(dev)
            if a.name.strip().lower() in DEFAULT_NAMES
            and a.privilege is AccountPrivilege.ADMIN
            and a.password_set is not False
        ]
        if not hits or not _reaches_clients(net, dev):
            continue
        yield found(
            f"{dev.name} has an enabled administrator account with the default name",
            [dev.id],
            fix="Create an administrator account with a name of your own, then disable or "
            "delete the default one (or rename it, where the device allows).",
            mid="account.adminDefaultName",
            fix_id="account.adminDefaultName.fix",
            params={"device": dev.name},
        )


@rule(
    "account.no-password",
    "Account without a password",
    Severity.WARNING,
    "An enabled account that has no password logs in with the name alone (unless the device "
    "only accepts a key for it). Reported where the device says whether a password is set "
    "(OpenWrt rpcd logins, the Omada device account).",
)
def no_password(net: Network) -> Iterator[Result]:
    for dev in _devices(net):
        hits = [a for a in _accounts(dev) if a.password_set is False and a.key_auth is not True]
        if not hits:
            continue
        yield found(
            f"{dev.name} has {len(hits)} account(s) without a password",
            [dev.id],
            fix="Set a password for the accounts marked on the device page, or delete them.",
            mid="account.noPassword",
            fix_id="account.noPassword.fix",
            params={"device": dev.name, "count": len(hits)},
        )


@history_rule(
    "account.stale",
    "Administrator account not used for a long time",
    Severity.INFO,
    f"An enabled administrator account that did not log in for {STALE_DAYS} days, or never "
    f"while Signalbox has known the device for {STALE_DAYS} days, is a forgotten way in. Only "
    "for devices that report login times (MikroTik); Signalbox's own login is left out. Needs "
    "the observation history clock.",
)
def stale(net: Network, history: History) -> Iterator[Result]:
    now = history.now
    if now is None:
        return
    limit = now - timedelta(days=STALE_DAYS)
    for dev in _devices(net):
        known = history.devices.get(dev.id)
        known_long = known is not None and known.first_seen <= limit
        hits = [
            a
            for a in _accounts(dev)
            if a.logins_tracked
            and not a.is_signalbox
            and a.privilege is AccountPrivilege.ADMIN
            and (a.last_login <= limit if a.last_login is not None else known_long)
        ]
        if not hits:
            continue
        yield found(
            f"{dev.name} has {len(hits)} administrator account(s) without a login for "
            f"{STALE_DAYS} days",
            [dev.id],
            fix="Disable or delete the accounts marked on the device page if nobody needs them.",
            mid="account.stale",
            fix_id="account.stale.fix",
            params={"device": dev.name, "count": len(hits), "days": STALE_DAYS},
        )


RULES: list[Rule] = [
    default_password,
    signalbox_privileged,
    admin_default_name,
    no_password,
    stale,
]
