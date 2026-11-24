"""Device account rules, the account model and what leaves Signalbox (#126, #175, ADR 0020)."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr

from factories import SITE, client, device, iface, snapshot
from signalbox.factory_defaults import FACTORY_DEFAULTS, has_defaults, is_factory_default
from signalbox.model import (
    AccountPrivilege,
    DeviceAccount,
    DeviceStatus,
    Network,
    Segment,
    Subnet,
    segment_id,
)
from signalbox.recording import Neutraliser
from signalbox.rules import Finding, Rule, evaluate
from signalbox.rules.account_checks import (
    RULES,
    admin_default_name,
    default_password,
    no_password,
    signalbox_privileged,
    stale,
)
from signalbox.sightings import DeviceHistory, History
from signalbox.testing import account_problems, credential_problems
from test_adapters import Fake, ctx

LAN = segment_id(SITE.id, None)
NOW = datetime(2026, 11, 24, tzinfo=UTC)


def account(name: str = "admin", **kw: Any) -> DeviceAccount:
    return DeviceAccount(name=name, **({"privilege": AccountPrivilege.ADMIN} | kw))


def make(*accounts: DeviceAccount, clients: bool = True, **dev: Any) -> Network:
    dev.setdefault("management_address", "192.0.2.1")
    subnet = Subnet(
        id="gw/subnet/lan", segment_id=LAN, interface=iface("192.0.2.1/24"), device_id="gw"
    )
    return Network(
        sites=[SITE],
        devices=[device("gw", accounts=list(accounts), **dev)],
        segments=[Segment(id=LAN, site_id=SITE.id)],
        subnets=[subnet],
        clients=[client("02:00:00:00:00:05", "192.0.2.5")] if clients else [],
    )


def run(r: Rule, n: Network, history: History | None = None) -> list[Finding]:
    return [f for f in evaluate(n, [r], None, history) if f.rule_id == r.id]


def test_registered() -> None:
    assert {r.id for r in RULES} == {
        "security.default-password",
        "account.signalbox-privileged",
        "account.admin-default-name",
        "account.no-password",
        "account.stale",
    }


# --- factory defaults --------------------------------------------------------------------------


def test_factory_defaults_compare_exactly() -> None:
    assert is_factory_default("prosafe", "password")
    assert is_factory_default("prosafe", "password", "anyone")
    assert not is_factory_default("prosafe", "Password")
    assert is_factory_default("easysmart", "admin", " Admin ")
    assert not is_factory_default("easysmart", "admin", "root")
    assert is_factory_default("mikrotik", "", "admin")
    assert not is_factory_default("mikrotik", "", None)
    assert is_factory_default("openwrt", "", "root") and is_factory_default(
        "omada-device", "admin", "admin"
    )
    assert not is_factory_default("unknown", "")
    assert has_defaults("openwrt") and not has_defaults("fritzbox")
    assert all(pairs for pairs in FACTORY_DEFAULTS.values())


# --- security.default-password ------------------------------------------------------------------


def test_default_password() -> None:
    (f,) = run(default_password, make(default_credentials=True))
    assert f.severity == "error" and f.objects == ["gw"]
    assert f.message == "gw still has its factory password"
    assert f.message_id == "account.defaultPassword" and f.params == {"device": "gw"}
    assert run(default_password, make(default_credentials=False)) == []
    assert run(default_password, make()) == []


# --- account.signalbox-privileged ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("have", "need", "reported"),
    [
        (AccountPrivilege.ADMIN, AccountPrivilege.READ, True),
        (AccountPrivilege.WRITE, AccountPrivilege.READ, True),
        (AccountPrivilege.READ, AccountPrivilege.READ, False),
        (AccountPrivilege.ADMIN, AccountPrivilege.ADMIN, False),
        (AccountPrivilege.ADMIN, None, False),
        (None, AccountPrivilege.READ, False),
    ],
)
def test_signalbox_privileged(
    have: AccountPrivilege | None, need: AccountPrivilege | None, reported: bool
) -> None:
    n = make(signalbox_account_privilege=have, signalbox_account_needed=need, adapter="openwrt")
    found = run(signalbox_privileged, n)
    assert bool(found) is reported
    if found:
        assert found[0].severity == "info"
        assert "docs/adapters/openwrt.md" in (found[0].fix or "")
        assert found[0].params["have"] == have.value  # type: ignore[union-attr]


# --- account.admin-default-name -----------------------------------------------------------------


def test_admin_default_name_where_clients_are() -> None:
    (f,) = run(admin_default_name, make(account("Admin"), account("other")))
    assert f.severity == "info" and "Admin" not in f.message  # no account names in findings
    assert run(admin_default_name, make(account("admin"), clients=False)) == []
    assert run(admin_default_name, make(account("admin", enabled=False))) == []
    assert run(admin_default_name, make(account("admin", password_set=False))) == []
    assert run(admin_default_name, make(account("admin", privilege=AccountPrivilege.READ))) == []
    assert run(admin_default_name, make(account("admin"), management_address=None)) == []


# --- account.no-password ------------------------------------------------------------------------


def test_no_password() -> None:
    n = make(
        account("nopass-user", password_set=False),
        account("b", password_set=False, key_auth=True),
        account("c", password_set=False, enabled=False),
        account("d", password_set=None),
    )
    (f,) = run(no_password, n)
    assert f.severity == "warning" and f.params == {"device": "gw", "count": 1}
    assert "nopass-user" not in f.message
    assert run(no_password, make(account("d", password_set=True))) == []


# --- account.stale ------------------------------------------------------------------------------


def _history(first_seen: datetime) -> History:
    seen = DeviceHistory(
        first_seen=first_seen, last_seen=NOW, status=DeviceStatus.OK, status_since=first_seen
    )
    return History(now=NOW, since=first_seen, observations=10, devices={"gw": seen})


def test_stale_admin_accounts() -> None:
    old = NOW - timedelta(days=200)
    n = make(
        account("a", logins_tracked=True, last_login=old),
        account("b", logins_tracked=True),  # never
        account("c", logins_tracked=True, last_login=NOW - timedelta(days=3)),
        account("d", logins_tracked=True, last_login=old, is_signalbox=True),
        account("e", logins_tracked=True, last_login=old, privilege=AccountPrivilege.READ),
        account("f", last_login=old),  # login times not reported
    )
    (f,) = run(stale, n, _history(NOW - timedelta(days=100)))
    assert f.params == {"device": "gw", "count": 2, "days": 90} and f.severity == "info"
    (f,) = run(stale, n, _history(NOW - timedelta(days=10)))
    assert f.params["count"] == 1  # "never" only once Signalbox has known the device long enough
    assert run(stale, n, History()) == []


# --- model, observe, contract -------------------------------------------------------------------


def test_network_without_account_names() -> None:
    n = make(account("alice"), default_credentials=True)
    shared = n.without_account_names()
    assert shared.devices[0].accounts is None and shared.devices[0].default_credentials is True
    assert "alice" not in shared.model_dump_json()
    plain = make()
    plain = plain.model_copy(
        update={"devices": [d.model_copy(update={"accounts": None}) for d in plain.devices]}
    )
    assert plain.without_account_names() is plain


class Accounts(Fake):
    managed = False

    async def read_interfaces(self) -> Any:
        base = await super().read_interfaces()
        d = self.context.device_id
        return base.model_copy(
            update={
                "accounts": {d: [account("root", is_signalbox=True)]},
                "default_credentials": {d: False},
                "signalbox_privilege": {d: AccountPrivilege.ADMIN},
            }
        )


async def test_observe_puts_accounts_on_the_device() -> None:
    snap = await Accounts(ctx()).observe()
    dev = snap.device
    assert [a.name for a in dev.accounts or []] == ["root"]
    assert dev.default_credentials is False
    assert dev.signalbox_account_privilege is AccountPrivilege.ADMIN


def test_account_and_credential_problems() -> None:
    assert account_problems("gw", [account("a"), account("a")]) == ["gw: account 'a' listed twice"]
    two = [account("a", is_signalbox=True), account("b", is_signalbox=True)]
    assert account_problems("gw", two) == ["gw: more than one account is Signalbox's login"]
    a = Fake(ctx())
    leaky = snapshot(device("gw", vendor_extra={"x": "$6$salt$hash"}))
    assert credential_problems(a, leaky) == ["a password hash appears in the snapshot"]


def test_credential_problems_find_a_configured_secret() -> None:
    from signalbox.adapters import AdapterContext
    from signalbox.adapters.mikrotik import MikrotikAdapter, MikrotikConfig
    from signalbox.model import DeviceRole

    cfg = MikrotikConfig(url="https://192.0.2.1", password=SecretStr("hunter-22"))
    a = MikrotikAdapter(
        AdapterContext(
            site_id="home", device_id="gw", device_name="gw", role=DeviceRole.GATEWAY, config=cfg
        )
    )
    leaky = snapshot(device("gw", vendor_extra={"note": "pw hunter-22"}))
    assert credential_problems(a, leaky) == ["the secret setting password appears in the snapshot"]
    assert credential_problems(a, snapshot(device("gw"))) == []


# --- recordings ---------------------------------------------------------------------------------


def test_neutraliser_reaches_into_escaped_user_lists() -> None:
    n = Neutraliser()
    n.given("pw-123456", "signalbox")
    body = (
        '<NewX_AVM-DE_UserList>&lt;List&gt;&lt;Username last_user="1"&gt;alice&lt;/Username'
        "&gt;&lt;Username&gt;signalbox&lt;/Username&gt;&lt;/List&gt;</NewX_AVM-DE_UserList>"
        "<NewX_AVM-DE_CurrentUsername>signalbox</NewX_AVM-DE_CurrentUsername>"
        "<NewX_AVM-DE_IsDefaultPasswordActive>0</NewX_AVM-DE_IsDefaultPasswordActive>"
    )
    out = n.document(body)
    assert "alice" not in out and ">signalbox<" not in out and "signalbox&lt;" not in out
    assert "recorded-user" in out and "<NewX_AVM-DE_IsDefaultPasswordActive>0<" in out
