"""Minimal ubus JSON-RPC client (rpcd behind uhttpd at ``/ubus``).

Every request is ``{"jsonrpc": "2.0", "id": n, "method": "call",
"params": [session, object, method, args]}``. The answer is either
``{"result": [status]}`` / ``{"result": [0, data]}`` with a ubus status code, or a JSON-RPC
``{"error": {"code": ..., "message": ...}}`` (``-32002`` access denied, ``-32000`` object not
found). An expired session also answers "access denied", so a denied call logs in again once
before it is reported as a missing ACL.
"""

from __future__ import annotations

from typing import Any

from signalbox.adapters import AdapterError, AuthFailed
from signalbox.adapters.openwrt.transport import Transport

NO_SESSION = "0" * 32

# ubus status codes (libubus.h)
UBUS_OK = 0
UBUS_METHOD_NOT_FOUND = 3
UBUS_NOT_FOUND = 4
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


class _Denied(Exception):
    pass


class Ubus:
    def __init__(self, transport: Transport, username: str, password: str) -> None:
        self.transport = transport
        self.username = username
        self._password = password
        self.session: str | None = None
        self._id = 0

    async def _rpc(self, params: list[Any]) -> Any:
        self._id += 1
        answer = await self.transport.post(
            {"jsonrpc": "2.0", "id": self._id, "method": "call", "params": params}
        )
        what = f"{params[1]}.{params[2]}"
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
        if status != UBUS_OK:
            raise AdapterError(f"ubus {what} failed: {UBUS_STATUS.get(status, status)}")
        data = result[1] if len(result) > 1 else {}
        if not isinstance(data, dict):
            raise AdapterError(f"unexpected answer to {what}")
        return data

    async def login(self) -> None:
        await self.transport.verify()  # before the password leaves this machine
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
            raise AuthFailed(f"login as {self.username!r} refused") from None
        session = data.get("ubus_rpc_session")
        if not isinstance(session, str):
            raise AdapterError("unexpected answer to session.login")
        self.session = session

    async def call(self, obj: str, method: str, args: dict[str, Any] | None = None) -> Any:
        """Call ``obj.method``; returns the data object of the answer."""
        for attempt in (1, 2):
            if self.session is None:
                await self.login()
            try:
                return await self._rpc([self.session, obj, method, args or {}])
            except _Denied:
                if attempt == 2:
                    break
                self.session = None  # may simply have expired: log in again once
        what = f"{obj}.{method}"
        if obj == "uci" and args and "config" in args:
            what += f" ({args['config']})"
        raise AccessDenied(f"access denied for {what}: add it to the rpcd ACL of {self.username!r}")
