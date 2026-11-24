"""Minimal ubus JSON-RPC client (rpcd behind uhttpd at ``/ubus``).

Every request is ``{"jsonrpc": "2.0", "id": n, "method": "call",
"params": [session, object, method, args]}``. The answer is either
``{"result": [status]}`` / ``{"result": [0, data]}`` with a ubus status code, or a JSON-RPC
``{"error": {"code": ..., "message": ...}}`` (``-32002`` access denied, ``-32000`` object not
found). An expired session also answers "access denied", so a denied call logs in again once
before it is reported as a missing ACL.

Requests are POSTed through :class:`~signalbox.adapters.https.DeviceHttp`, which probes and pins
the device certificate before the first request, so the password is only ever sent to the
pinned certificate.
"""

from __future__ import annotations

import contextlib
from typing import Any

from signalbox.adapters import AdapterError, AuthFailed
from signalbox.adapters.https import DeviceHttp

NO_SESSION = "0" * 32

# ubus status codes (libubus.h)
UBUS_OK = 0
UBUS_INVALID_ARGUMENT = 2
UBUS_METHOD_NOT_FOUND = 3
UBUS_NOT_FOUND = 4
UBUS_NO_DATA = 5
UBUS_PERMISSION_DENIED = 6
UBUS_UNKNOWN_ERROR = 9
UBUS_STATUS = {
    1: "invalid command",
    2: "invalid argument",
    3: "method not found",
    4: "not found",
    5: "no data",
    6: "permission denied",
    7: "timeout",
    8: "not supported",
    9: "unknown error",
    10: "connection failed",
}

# JSON-RPC error codes used by uhttpd-mod-ubus
RPC_OBJECT_NOT_FOUND = -32000
RPC_METHOD_NOT_FOUND = -32601
RPC_ACCESS_DENIED = -32002


class NotFound(AdapterError):
    """The ubus object or method does not exist (package not installed)."""


class AccessDenied(AdapterError):
    """The rpcd ACL of the user does not allow the call."""


class InvalidArgument(AdapterError):
    """ubus status 2: the object refuses the arguments of the call."""


class CallFailed(AdapterError):
    """ubus status 9 (unknown error): the object's script failed (luci.lldpd with lldpd stopped)."""


class NoData(AdapterError):
    """ubus status 5: rpcd's ``uci apply`` with nothing staged, ``uci confirm`` or
    ``uci rollback`` with no change waiting for its confirmation."""


SETUP = "https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/openwrt.md"


def acl_fix_id(username: str) -> str:
    """Catalogue id of :func:`acl_fix` (#204); its values are ``{"setup": SETUP}``."""
    return "openwrt.acl.root.fix" if username == "root" else "openwrt.acl.user.fix"


def acl_fix(username: str) -> str:
    """What to do when rpcd's permissions (ACL) refuse a call."""
    who = (
        "root may call everything a permission file allows"
        if username == "root"
        else f"the login {username!r} also needs the line list read 'signalbox' in its "
        "config login section of /etc/config/rpcd"
    )
    return (
        "Signalbox's permissions are not installed on the router. Log in to the router "
        "(ssh root@<router>), paste the commands under 'Prepare the router' in the device "
        f"settings (they create /usr/share/rpcd/acl.d/signalbox.json; {who}) and test again. "
        f"Details: {SETUP}#read-only-user-on-the-device"
    )


def unexpected(what: str) -> AdapterError:
    return AdapterError(
        f"unexpected answer to {what}", message_id="openwrt.unexpected", params={"what": what}
    )


class _Denied(Exception):
    pass


class Ubus:
    def __init__(self, http: DeviceHttp, path: str, username: str, password: str) -> None:
        self.http = http
        self.path = path
        self.username = username
        self._password = password
        self.session: str | None = None
        self._id = 0

    async def _rpc(self, params: list[Any]) -> Any:
        self._id += 1
        answer = await self.http.post_json(
            self.path, {"jsonrpc": "2.0", "id": self._id, "method": "call", "params": params}
        )
        what = f"{params[1]}.{params[2]}"
        if params[1] == "uci" and isinstance(params[3], dict) and "config" in params[3]:
            what += f" ({params[3]['config']})"
        if not isinstance(answer, dict):
            raise unexpected(what)
        error = answer.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if code == RPC_ACCESS_DENIED:
                raise _Denied
            if code in (RPC_OBJECT_NOT_FOUND, RPC_METHOD_NOT_FOUND):
                raise NotFound(
                    f"ubus {what} not found",
                    message_id="openwrt.ubusNotFound",
                    params={"what": what},
                )
            detail = str(error.get("message", code))
            raise AdapterError(
                f"ubus {what} failed: {detail}",
                message_id="openwrt.ubusFailed",
                params={"what": what, "detail": detail},
            )
        result = answer.get("result")
        if not isinstance(result, list) or not result or not isinstance(result[0], int):
            raise unexpected(what)
        status = result[0]
        if status == UBUS_PERMISSION_DENIED:
            raise _Denied
        if status in (UBUS_NOT_FOUND, UBUS_METHOD_NOT_FOUND):
            raise NotFound(
                f"ubus {what}: {UBUS_STATUS[status]}",
                message_id="openwrt.ubusStatus",
                params={"what": what, "detail": UBUS_STATUS[status]},
            )
        if status == UBUS_INVALID_ARGUMENT:
            raise InvalidArgument(
                f"ubus {what} failed: {UBUS_STATUS[status]}",
                message_id="openwrt.ubusFailed",
                params={"what": what, "detail": UBUS_STATUS[status]},
            )
        if status == UBUS_NO_DATA:
            raise NoData(
                f"ubus {what} failed: {UBUS_STATUS[status]}",
                message_id="openwrt.ubusFailed",
                params={"what": what, "detail": UBUS_STATUS[status]},
            )
        if status == UBUS_UNKNOWN_ERROR:
            raise CallFailed(
                f"ubus {what} failed: {UBUS_STATUS[status]}",
                message_id="openwrt.ubusFailed",
                params={"what": what, "detail": UBUS_STATUS[status]},
            )
        if status != UBUS_OK:
            detail = str(UBUS_STATUS.get(status, status))
            raise AdapterError(
                f"ubus {what} failed: {detail}",
                message_id="openwrt.ubusFailed",
                params={"what": what, "detail": detail},
            )
        data = result[1] if len(result) > 1 else {}
        if not isinstance(data, dict):
            raise unexpected(what)
        return data

    async def login(self) -> None:
        await self.http.connect()  # pin checked before the password leaves this machine
        try:
            data = await self._rpc(
                [
                    NO_SESSION,
                    "session",
                    "login",
                    {"username": self.username, "password": self._password},
                ]
            )
        except _Denied:
            raise AuthFailed(
                f"login as {self.username!r} refused",
                fix="Check the user name and password. A login other than root needs a "
                "config login section in /etc/config/rpcd with a password hashed by uhttpd -m "
                f"(see {SETUP}#read-only-user-on-the-device), then service rpcd restart.",
                message_id="openwrt.loginRefused",
                fix_id="openwrt.loginRefused.fix",
                params={"login": repr(self.username), "setup": SETUP},
            ) from None
        session = data.get("ubus_rpc_session")
        if not isinstance(session, str):
            raise unexpected("session.login")
        self.session = session

    async def try_login(self, username: str, password: str) -> bool:
        """One login attempt with other credentials than the configured ones, for an opt-in
        probe (#175): True when rpcd accepts it. The session is destroyed at once, the
        configured session is not touched, nothing is logged."""
        await self.http.connect()  # pin checked first, as for every login
        try:
            data = await self._rpc(
                [NO_SESSION, "session", "login", {"username": username, "password": password}]
            )
        except (_Denied, AdapterError):
            return False
        session = data.get("ubus_rpc_session")
        if not isinstance(session, str):
            return False
        with contextlib.suppress(_Denied, AdapterError):
            await self._rpc([session, "session", "destroy", {}])
        return True

    async def call(
        self,
        obj: str,
        method: str,
        args: dict[str, Any] | None = None,
        *,
        keep_session: bool = False,
    ) -> Any:
        """Call ``obj.method``; returns the data object of the answer.

        ``keep_session``: never log in again on "access denied". UCI staging belongs to the
        session, so a write transaction must notice a lost session instead of silently going on
        in a new, empty one; the caller starts the transaction over.
        """
        for attempt in (1, 2):
            if self.session is None:
                await self.login()
            try:
                return await self._rpc([self.session, obj, method, args or {}])
            except _Denied:
                if attempt == 2 or keep_session:
                    break
                self.session = None  # may simply have expired: log in again once
        what = f"{obj}.{method}"
        if obj == "uci" and args and "config" in args:
            what += f" ({args['config']})"
        raise AccessDenied(
            f"access denied for {what}: the login {self.username!r} is not allowed to call it",
            fix=acl_fix(self.username),
            remedy="access",
            message_id="openwrt.accessDenied",
            fix_id=acl_fix_id(self.username),
            params={"what": what, "login": repr(self.username), "setup": SETUP},
        )
