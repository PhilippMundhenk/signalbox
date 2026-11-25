"""FRITZ!Box dynamic DNS (#154): a DDNS provider and MyFRITZ!.

- ``X_AVM-DE_RemoteAccess:1 GetDDNSInfo`` (in the service descriptions of FRITZ!OS 6.83, 7.29,
  7.57 and 8.02): ``NewEnabled``, ``NewProviderName``, ``NewDomain``, ``NewMode`` (``ddns_v4``,
  ``ddns_v6``, ``ddns_both``, *guess*), ``NewStatusIPv4`` and ``NewStatusIPv6`` (the status
  words are free text of the box: an ``error`` or ``fail`` is an error, ``ok`` or ``updated``
  is a success, anything else unknown; *guess*, #21). ``NewUsername`` is never read and of
  ``NewUpdateURL`` (it can carry the account) only the scheme is kept (``tls``);
  ``NewServerIPv4`` is the provider's server, not the address announced, so the announced
  address is not known.
- ``X_AVM-DE_MyFritz:1 GetInfo``: ``NewEnabled``, ``NewDynDNSName`` (the MyFRITZ! name),
  ``NewState``. ``NewEmail`` (the account) is never read.
"""

from __future__ import annotations

from typing import Any, Literal

from signalbox.model import DdnsResult, DynamicDns, object_id

PROVIDERS = (
    ("duckdns", "duckdns"),
    ("cloudflare", "cloudflare"),
    ("no-ip", "noip"),
    ("noip", "noip"),
    ("dyndns", "dyndns2"),
)


def _flag(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def _result(*words: Any) -> DdnsResult:
    text = " ".join(str(w).lower() for w in words if w)
    if "error" in text or "fail" in text:
        return DdnsResult.ERROR
    if text and ("ok" in text.split() or "updated" in text or "success" in text):
        return DdnsResult.OK
    return DdnsResult.UNKNOWN


def _scheme(url: str) -> bool | None:
    low = url.strip().lower()
    return low.startswith("https://") if low.startswith(("http://", "https://")) else None


def provider(name: str) -> str:
    low = name.lower()
    return next((p for key, p in PROVIDERS if key in low), "other")


def clients(
    device_id: str,
    ddns: dict[str, str] | None,
    myfritz: dict[str, str] | None,
    uplink_id: str | None,
) -> list[DynamicDns]:
    out: list[DynamicDns] = []
    domain = (ddns or {}).get("NewDomain", "").strip()
    if ddns is not None and domain:
        mode = ddns.get("NewMode", "").lower()
        families: list[Literal[4, 6]] = (
            [4, 6] if mode.endswith("both") else [6] if mode.endswith("v6") else [4]
        )
        out.append(
            DynamicDns(
                id=object_id(device_id, "ddns", "provider"),
                device_id=device_id,
                provider=provider(ddns.get("NewProviderName", "")),
                hostname=domain,
                uplink_id=uplink_id,
                families=families,
                enabled=_flag(ddns.get("NewEnabled")),
                tls=_scheme(ddns.get("NewUpdateURL", "")),
                last_result=_result(
                    ddns.get("NewStatusIPv4") if 4 in families else None,
                    ddns.get("NewStatusIPv6") if 6 in families else None,
                ),
            )
        )
    name = (myfritz or {}).get("NewDynDNSName", "").strip()
    if myfritz is not None and name:
        out.append(
            DynamicDns(
                id=object_id(device_id, "ddns", "myfritz"),
                device_id=device_id,
                provider="myfritz",
                hostname=name,
                uplink_id=uplink_id,
                enabled=_flag(myfritz.get("NewEnabled")),
                last_result=_result(myfritz.get("NewState")),
            )
        )
    return out
