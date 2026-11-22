"""Write side of the Fritz!Box adapter: changes -> TR-064 ``Set...`` actions.

Pure helpers, no I/O: the adapter reads the current values, these functions turn a change (or
a backup) into the calls that make the device match, and the adapter sends them. Every action
name and argument here comes from AVM's TR-064 documentation and still needs confirmation on a
real device (#21); ``docs/adapters/fritzbox.md`` lists them.

What maps cleanly, and is therefore the only thing ``Manifest.writes`` declares:

- ``dhcp`` on the LAN: ``SetDHCPServerEnable``, ``SetAddressRange``. The DNS servers and the
  lease time the DHCP server hands out are not settable over TR-064: a change to them is refused.
- ``wlan`` for an SSID the box already has: ``SetSSID`` (rename), ``SetBeaconType``,
  ``SetSecurityKeys``, ``SetEnable``, ``X_AVM-DE_SetBeaconAdvertisement`` (hidden). The Wi-Fi
  networks of a Fritz!Box are fixed (one ``WLANConfiguration`` per band plus the guest
  network), so creating or removing one is refused.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Any

from signalbox.adapters import AdapterError, VendorCall
from signalbox.changes import Change, DhcpValue, WlanValue
from signalbox.model import Security

#: ``Backup.format`` of this adapter: the TR-064 values of every setting it may change.
BACKUP_FORMAT = "fritzbox-tr064-values"
LAN_SERVICE = "LANHostConfigManagement1"
SECRET = "***"

#: Security -> ``NewBeaconType`` written. Reading also knows WEP, WPA and OWE; those are not
#: offered for writing (WEP and WPA are broken, OWE is not documented as a beacon type to set).
WRITE_BEACON: dict[Security, str] = {
    Security.OPEN: "None",
    Security.WPA2: "11i",
    Security.WPA3: "WPA3",
    Security.WPA2_WPA3: "11iandWPA3",
}

#: TR-064 value names of the WLAN settings this adapter may change, in the order they are set.
WLAN_FIELDS = ("NewSSID", "NewBeaconType", "NewKeyPassphrase", "NewBeaconAdvertisementEnabled")
#: ... and of the LAN (DHCP) settings.
LAN_FIELDS = ("NewMinAddress", "NewMaxAddress", "NewDHCPServerEnable")


@dataclass(frozen=True)
class Call:
    """One TR-064 action to send; ``secret`` names the arguments shown as ``***``."""

    service: str
    action: str
    args: dict[str, str]
    description: str
    secret: frozenset[str] = field(default_factory=frozenset)

    def vendor(self) -> VendorCall:
        return VendorCall(
            description=self.description,
            method="SOAP",
            target=f"{self.service} {self.action}",
            payload={k: SECRET if k in self.secret else v for k, v in self.args.items()},
        )


# --- DHCP ------------------------------------------------------------------------------------


def dhcp_wanted(c: Change, current: Mapping[str, str]) -> dict[str, str]:
    """The LAN values a DHCP change asks for; refuses what TR-064 cannot set."""
    if c.new is None:
        raise AdapterError(
            f"{c.key}: the DHCP server of a Fritz!Box cannot be removed; set enabled: false"
        )
    if c.old is None:
        raise AdapterError(f"{c.key}: the Fritz!Box reported no DHCP server to change")
    assert isinstance(c.new, DhcpValue)
    new = c.new
    if new.lease_seconds is not None:
        raise AdapterError(f"{c.key}: the DHCP lease time cannot be set over TR-064")
    if new.dns is not None and [str(a) for a in new.dns] != _dns(current):
        raise AdapterError(
            f"{c.key}: the DNS servers the Fritz!Box hands out cannot be set over TR-064 "
            "(it always announces itself)"
        )
    wanted = {"NewDHCPServerEnable": "1" if new.enabled else "0"}
    if new.pool is None:
        if current.get("NewMinAddress") and current.get("NewMaxAddress"):
            raise AdapterError(
                f"{c.key}: the Fritz!Box DHCP server always has an address range; give a pool"
            )
        return wanted
    first, last = new.pool
    if not (isinstance(first, IPv4Address) and isinstance(last, IPv4Address)):
        raise AdapterError(f"{c.key}: the Fritz!Box DHCP server hands out IPv4 addresses only")
    return {"NewMinAddress": str(first), "NewMaxAddress": str(last)} | wanted


def _dns(lan: Mapping[str, str]) -> list[str]:
    return [p.strip() for p in str(lan.get("NewDNSServers", "")).split(",") if p.strip()]


def lan_calls(current: Mapping[str, str], wanted: Mapping[str, str]) -> list[Call]:
    """The calls that turn the current LAN values into the wanted ones (only what differs).

    Switching on: range first, then the server; switching off: the other way round, so the
    server never runs with a range that is about to change.
    """
    calls: list[Call] = []
    rng = (wanted.get("NewMinAddress"), wanted.get("NewMaxAddress"))
    if rng[0] and rng[1] and rng != (current.get("NewMinAddress"), current.get("NewMaxAddress")):
        calls.append(
            Call(
                LAN_SERVICE,
                "SetAddressRange",
                {"NewMinAddress": rng[0], "NewMaxAddress": rng[1]},
                f"DHCP address range {rng[0]}-{rng[1]}",
            )
        )
    on = wanted.get("NewDHCPServerEnable")
    if on is not None and on != _bit(current.get("NewDHCPServerEnable")):
        switch = Call(
            LAN_SERVICE,
            "SetDHCPServerEnable",
            {"NewDHCPServerEnable": on},
            "switch the DHCP server " + ("on" if on == "1" else "off"),
        )
        calls = [*calls, switch] if on == "1" else [switch, *calls]
    return calls


# --- WLAN ------------------------------------------------------------------------------------


def wlan_wanted(
    c: Change, current: Mapping[str, str], have: Security, secrets: Mapping[str, str]
) -> dict[str, str]:
    """The values one ``WLANConfiguration`` should have after a WLAN change.

    ``have`` is the security the current ``NewBeaconType`` reads as.
    """
    new = c.new
    assert isinstance(new, WlanValue)
    beacon = WRITE_BEACON.get(new.security)
    if beacon is None:
        offered = ", ".join(s.value for s in WRITE_BEACON)
        raise AdapterError(
            f"SSID {c.key}: security {new.security.value} cannot be set on a Fritz!Box "
            f"(offered: {offered})"
        )
    if have is new.security:
        beacon = current.get("NewBeaconType", beacon)  # already right: keep the exact type
    possible = [
        p.strip().lower()
        for p in current.get("NewX_AVM-DE_PossibleBeaconTypes", "").split(",")
        if p.strip()
    ]
    if possible and beacon.lower() not in possible:
        raise AdapterError(
            f"SSID {c.key}: this Fritz!Box does not offer {new.security.value} "
            f"(beacon type {beacon}; it offers {current['NewX_AVM-DE_PossibleBeaconTypes']})"
        )
    wanted = {
        "NewSSID": new.ssid,
        "NewBeaconType": beacon,
        "NewBeaconAdvertisementEnabled": "0" if new.hidden else "1",
        "NewEnable": "1" if new.enabled else "0",
    }
    name = new.passphrase_secret
    if name and new.security is not Security.OPEN:
        value = secrets.get(name)
        if value is None:
            raise AdapterError(f"SSID {c.key}: secret {name!r} was not given")
        if not 8 <= len(value) <= 63:
            raise AdapterError(
                f"SSID {c.key}: the passphrase in secret {name!r} must be 8 to 63 characters"
            )
        wanted["NewKeyPassphrase"] = value
    return wanted


def check_wlan(c: Change) -> None:
    """Refuse WLAN changes a Fritz!Box cannot make (before any device call)."""
    if c.old is None:
        assert isinstance(c.new, WlanValue)
        raise AdapterError(
            f"SSID {c.new.ssid}: a Fritz!Box cannot create a Wi-Fi network; its networks are "
            "fixed (one per band and the guest network). Rename or change an existing one."
        )
    if c.new is None:
        raise AdapterError(
            f"SSID {c.key}: a Fritz!Box cannot delete a Wi-Fi network; set enabled: false"
        )
    assert isinstance(c.new, WlanValue)
    new = c.new
    if new.segment != "native":
        raise AdapterError(
            f"SSID {c.key}: the Fritz!Box has no VLANs; its Wi-Fi networks stay in the LAN "
            "or the guest network"
        )
    unsupported = [
        label
        for label, value in (
            ("pmf", new.pmf),
            ("802.11r", new.roaming_80211r),
            ("802.11k", new.roaming_80211k),
            ("802.11v", new.roaming_80211v),
            ("client isolation", new.client_isolation),
        )
        if value is not None
    ]
    if unsupported:
        raise AdapterError(
            f"SSID {c.key}: {', '.join(unsupported)} cannot be set over TR-064; "
            "leave it out of the desired state"
        )


def wlan_calls(
    service: str, current: Mapping[str, str], wanted: Mapping[str, str], passphrase: str | None
) -> list[Call]:
    """The calls that turn one WLAN's current values into the wanted ones.

    ``current`` holds the GetInfo answer plus ``NewBeaconAdvertisementEnabled`` (if the box
    reports it) and ``NewEnable`` as Signalbox reads it; ``passphrase`` the current one, if
    known. Switching on comes last, switching off first.
    """
    calls: list[Call] = []
    ssid = wanted.get("NewSSID")
    if ssid is not None and ssid != current.get("NewSSID"):
        calls.append(Call(service, "SetSSID", {"NewSSID": ssid}, f"{service}: SSID {ssid}"))
    beacon = wanted.get("NewBeaconType")
    if beacon is not None and beacon.lower() != current.get("NewBeaconType", "").lower():
        calls.append(
            Call(
                service,
                "SetBeaconType",
                {"NewBeaconType": beacon},
                f"{service}: security (beacon type {beacon})",
            )
        )
    key = wanted.get("NewKeyPassphrase")
    if key is not None and key != passphrase:
        calls.append(
            Call(
                service,
                "SetSecurityKeys",
                {
                    "NewWEPKey0": "",
                    "NewWEPKey1": "",
                    "NewWEPKey2": "",
                    "NewWEPKey3": "",
                    "NewPreSharedKey": "",
                    "NewKeyPassphrase": key,
                },
                f"{service}: passphrase",
                secret=frozenset({"NewKeyPassphrase"}),
            )
        )
    advertise = wanted.get("NewBeaconAdvertisementEnabled")
    if advertise is not None and advertise != current.get("NewBeaconAdvertisementEnabled", "1"):
        calls.append(
            Call(
                service,
                "X_AVM-DE_SetBeaconAdvertisement",
                {"NewBeaconAdvertisementEnabled": advertise},
                f"{service}: " + ("show the SSID" if advertise == "1" else "hide the SSID"),
            )
        )
    on = wanted.get("NewEnable")
    if on is not None and on != _bit(current.get("NewEnable")):
        switch = Call(
            service,
            "SetEnable",
            {"NewEnable": on},
            f"{service}: switch " + ("on" if on == "1" else "off"),
        )
        calls = [*calls, switch] if on == "1" else [switch, *calls]
    return calls


def _bit(value: str | None) -> str:
    return "1" if (value or "").strip().lower() in ("1", "true", "yes", "up") else "0"


# --- backup ----------------------------------------------------------------------------------


def backup_content(lan: Mapping[str, str], wlans: Mapping[int, Mapping[str, str]]) -> str:
    """The backup document: the values of every setting this adapter may change."""
    return json.dumps(
        {
            "format": BACKUP_FORMAT,
            "lan": {k: lan[k] for k in LAN_FIELDS if k in lan},
            "wlans": {
                str(i): {k: v[k] for k in (*WLAN_FIELDS, "NewEnable") if k in v}
                for i, v in sorted(wlans.items())
            },
        },
        indent=2,
        sort_keys=True,
    )


def parse_backup(content: str) -> tuple[dict[str, str], dict[int, dict[str, str]]]:
    try:
        data: Any = json.loads(content)
        if data.get("format") != BACKUP_FORMAT:
            raise ValueError("wrong format")
        lan = {str(k): str(v) for k, v in data["lan"].items()}
        wlans = {
            int(i): {str(k): str(v) for k, v in values.items()}
            for i, values in data["wlans"].items()
        }
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise AdapterError(f"not a {BACKUP_FORMAT} backup of this adapter") from exc
    return lan, wlans
