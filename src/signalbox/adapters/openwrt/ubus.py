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


class NoData(AdapterError):
    """ubus status 5: rpcd's ``uci apply`` with nothing staged, ``uci confirm`` or
    ``uci rollback`` with no change waiting for its confirmation."""


SETUP = "https://github.com/PhilippMundhenk/signalbox/blob/main/docs/adapters/openwrt.md"


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
            raise AdapterError(f"unexpected answer to {what}")
        error = answer.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if code == RPC_ACCESS_DENIED:
                raise _Denied
            if code in (RPC_OBJECT_NOT_FOUND, RPC_METHOD_NOT_FOUND):
                raise NotFound(f"ubus {what} not found")
            raise AdapterError(f"ubus {what} failed: {error.get('message', code)}")
        result = answer.get("result")
        if not isinstance(result, list) or not result or not isinstance(result[0], int):
            raise AdapterError(f"unexpected answer to {what}")
        status = result[0]
        if status == UBUS_PERMISSION_DENIED:
            raise _Denied
        if status in (UBUS_NOT_FOUND, UBUS_METHOD_NOT_FOUND):
            raise NotFound(f"ubus {what}: {UBUS_STATUS[status]}")
        if status == UBUS_INVALID_ARGUMENT:
            raise InvalidArgument(f"ubus {what} failed: {UBUS_STATUS[status]}")
        if status == UBUS_NO_DATA:
            raise NoData(f"ubus {what} failed: {UBUS_STATUS[status]}")
        if status != UBUS_OK:
            raise AdapterError(f"ubus {what} failed: {UBUS_STATUS.get(status, status)}")
        data = result[1] if len(result) > 1 else {}
        if not isinstance(data, dict):
            raise AdapterError(f"unexpected answer to {what}")
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
            ) from None
        session = data.get("ubus_rpc_session")
        if not isinstance(session, str):
            raise AdapterError("unexpected answer to session.login")
        self.session = session

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
        )
