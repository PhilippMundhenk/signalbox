"""OpenWrt (write): change sets as UCI operations for rpcd's ``uci`` ubus object.

Pure translation, no I/O: :func:`translate` takes the ``uci get`` answers of ``network``,
``wireless`` and ``dhcp`` (and the running interfaces), applies the changes one by one to an
in-memory copy and records every ``uci set`` / ``add`` / ``delete`` it needs. Later changes see
the result of earlier ones (a PORT change that creates VLAN 30 comes before the WLAN that uses
it). :func:`restore_ops` turns a backup into the operations that put it back. The transaction
(staging, ``uci apply`` with rollback, ``uci confirm``) is in :class:`OpenWrtAdapter`.

What each change does is documented in ``docs/adapters/openwrt.md`` ("Writing").
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_address, ip_interface
from typing import Any

from pydantic import JsonValue

from signalbox.adapters import AdapterError, VendorCall
from signalbox.adapters import openwrt as h  # the read helpers (circular, used at run time)
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    ReservationValue,
    WlanValue,
)
from signalbox.desired import SegmentRef, seg_key
from signalbox.model import Pmf, Security, segment_id

#: The UCI configs Signalbox writes (and backs up); the rpcd ACL grants write access to these only.
CONFIGS = ("network", "wireless", "dhcp")
BACKUP_FORMAT = "openwrt-uci-json"
#: Inverse of the read mapping; enterprise needs RADIUS settings the change model does not carry.
ENCRYPTION_OF = {
    Security.OPEN: "none",
    Security.OWE: "owe",
    Security.WPA2: "psk2",
    Security.WPA3: "sae",
    Security.WPA2_WPA3: "sae-mixed",
}
PMF_OF = {Pmf.DISABLED: "0", Pmf.OPTIONAL: "1", Pmf.REQUIRED: "2"}
#: UCI options whose values never appear in a VendorCall.
SECRET_OPTIONS = frozenset(
    {"key", "key1", "key2", "key3", "key4", "sae_password", "password", "auth_secret"}
)
MASK = "***"


@dataclass(frozen=True)
class UciOp:
    """One ``uci <method>`` call with its arguments."""

    method: str
    config: str
    section: str
    args: dict[str, Any]
    description: str

    def call(self) -> VendorCall:
        payload: dict[str, JsonValue] = copy.deepcopy(self.args)
        values = payload.get("values")
        if isinstance(values, dict):
            for name in values:
                if name in SECRET_OPTIONS:
                    values[name] = MASK
        return VendorCall(
            description=self.description,
            method=f"uci.{self.method}",
            target=f"{self.config}.{self.section}",
            payload=payload,
        )


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:24] or "x"


@dataclass
class Configs:
    """``uci get`` answers of the written configs, changed in memory; ``ops`` reproduce it."""

    data: dict[str, dict[str, Any]]
    ops: list[UciOp] = field(default_factory=list)
    #: VLAN devices (``br-lan.30``) whose bridge-vlan section was deleted in this transaction
    removed_vlans: set[str] = field(default_factory=set)

    def values(self, config: str) -> dict[str, Any]:
        values = self.data[config].get("values")
        if not isinstance(values, dict):
            raise AdapterError(f"unexpected answer to uci.get ({config})")
        return values

    def sections(self, config: str, kind: str) -> list[tuple[str, dict[str, Any]]]:
        return list(h._sections(self.data[config], kind))

    def view(self) -> h.NetworkView:
        return h.NetworkView.build(self.data["network"])

    def set(self, config: str, section: str, values: Mapping[str, Any], description: str) -> None:
        s = self.values(config)[section]
        changed = {k: v for k, v in values.items() if s.get(k) != v}
        if not changed:
            return
        s.update(copy.deepcopy(changed))
        args = {"config": config, "section": section, "values": changed}
        self.ops.append(UciOp("set", config, section, args, description))

    def drop(self, config: str, section: str, options: Iterable[str], description: str) -> None:
        s = self.values(config)[section]
        present = [o for o in options if o in s]
        if not present:
            return
        for o in present:
            del s[o]
        args = {"config": config, "section": section, "options": present}
        self.ops.append(UciOp("delete", config, section, args, description))

    def add(
        self, config: str, kind: str, name: str, values: dict[str, Any], description: str
    ) -> str:
        values_now = self.values(config)
        base, n = name, 2
        while name in values_now:
            name, n = f"{base}_{n}", n + 1
        index = max((_index(s) for s in values_now.values()), default=-1) + 1
        values_now[name] = {
            ".anonymous": False,
            ".type": kind,
            ".name": name,
            ".index": index,
            **copy.deepcopy(values),
        }
        args = {"config": config, "type": kind, "name": name, "values": values}
        self.ops.append(UciOp("add", config, name, args, description))
        return name

    def delete(self, config: str, section: str, description: str) -> None:
        del self.values(config)[section]
        self.ops.append(
            UciOp("delete", config, section, {"config": config, "section": section}, description)
        )


def _index(section: Any) -> int:
    try:
        return int(section.get(".index", 0))
    except (TypeError, ValueError, AttributeError):
        return 0


def _seg(site: str, vid: int) -> str:
    return segment_id(site, None if vid == h._NATIVE else vid)


# --- PORT -----------------------------------------------------------------------------------


def _port(cfg: Configs, c: Change) -> None:
    name = c.key.partition("/port/")[2]
    new = c.new if isinstance(c.new, PortValue) else PortValue()
    vlan_sections = cfg.sections("network", "bridge-vlan")
    bridges = [b for b, ports in cfg.view().bridges.items() if name in ports]
    filtered = [b for b in bridges if any(s.get("device") == b for _, s in vlan_sections)]
    if not filtered:
        if bridges:
            raise AdapterError(
                f"port {name}: bridge {bridges[0]} has no bridge VLANs (VLAN filtering); "
                "set up bridge-vlan sections first"
            )
        raise AdapterError(f"port {name} is not a port of a bridge on this device")
    bridge = filtered[0]
    wanted: dict[int, str] = {}
    if new.untagged is not None:
        wanted[seg_key(new.untagged) or 1] = ":u*"
    for tag in new.tagged:
        wanted.setdefault(seg_key(tag) or 1, ":t")
    what = f"port {name}"
    done: set[int] = set()
    for section, s in vlan_sections:
        vid = h._int(s.get("vlan"))
        if s.get("device") != bridge or vid is None:
            continue
        entries = h._list(s.get("ports"))
        mine = [e for e in entries if e.partition(":")[0] == name]
        target = [name + wanted[vid]] if vid in wanted and vid not in done else []
        if vid in wanted:
            done.add(vid)
        if mine == target:
            continue
        keep = [e for e in entries if e.partition(":")[0] != name] + target
        if keep:
            cfg.set("network", section, {"ports": keep}, f"{what}: VLAN {vid} ports {keep}")
        else:
            cfg.delete("network", section, f"{what}: VLAN {vid} has no ports left, remove it")
            cfg.removed_vlans.add(f"{bridge}.{vid}")
    for vid in sorted(set(wanted) - done):
        cfg.add(
            "network",
            "bridge-vlan",
            f"{_slug(bridge)}_{vid}",
            {"device": bridge, "vlan": str(vid), "ports": [name + wanted[vid]]},
            f"{what}: new VLAN {vid} on {bridge}",
        )
        cfg.removed_vlans.discard(f"{bridge}.{vid}")


# --- WLAN -----------------------------------------------------------------------------------


def _interface_for(cfg: Configs, site: str, ref: SegmentRef, label: str) -> str:
    """The interface on the segment's VLAN; a new ``proto none`` one on a bridge VLAN if needed."""
    target = segment_id(site, seg_key(ref))
    view = cfg.view()
    for name in sorted(view.devices):
        vid = view.vlan_of_interface(name)
        if vid is not None and _seg(site, vid) == target:
            return name
    vid = seg_key(ref)
    bridge = next((b for b, vlans in view.vlans.items() if vid is not None and vid in vlans), None)
    if vid is None or bridge is None:
        where = "the untagged network" if vid is None else f"VLAN {vid}"
        raise AdapterError(
            f"{label}: {where} is not on any port of this device; add it to a port (for "
            "example tag the uplink) in the same plan"
        )
    return cfg.add(
        "network",
        "interface",
        f"vlan{vid}",
        {"device": f"{bridge}.{vid}", "proto": "none"},
        f"{label}: new interface for VLAN {vid} (no address)",
    )


def _wifi_values(
    s: dict[str, Any], w: WlanValue, key: str | None, network: str
) -> tuple[dict[str, Any], list[str]]:
    """Options to set and to delete so that the read side reports ``w``."""
    out: dict[str, Any] = {}
    drop: list[str] = []
    if h.security(s.get("encryption")) is not w.security:
        out["encryption"] = ENCRYPTION_OF[w.security]
    if key is not None and s.get("key") != key:
        out["key"] = key
    if w.security not in h.PERSONAL and "key" in s:
        drop.append("key")
    pmf = h.PMF.get(str(s["ieee80211w"])) if "ieee80211w" in s else h.PMF_DEFAULT.get(w.security)
    if w.pmf is not None and pmf is not w.pmf:
        out["ieee80211w"] = PMF_OF[w.pmf]
    roaming = (
        ("ieee80211r", s.get("ieee80211r"), w.roaming_80211r),
        ("ieee80211k", s.get("ieee80211k"), w.roaming_80211k),
        ("bss_transition", s.get("bss_transition", s.get("ieee80211v")), w.roaming_80211v),
    )
    for option, current, want in roaming:
        if want is not None and h._flag(current) != want:
            out[option] = "1" if want else "0"
    if h._flag(s.get("hidden")) != w.hidden:
        out["hidden"] = "1" if w.hidden else "0"
    if h._flag(s.get("disabled")) == w.enabled:
        out["disabled"] = "0" if w.enabled else "1"
    if h._list(s.get("network"))[:1] != [network]:
        out["network"] = network
    return out, drop


def _wlan(cfg: Configs, c: Change, site: str, secrets: Mapping[str, str]) -> None:
    ssid = c.key
    label = f"SSID {ssid}"
    radios = [n for n, s in cfg.sections("wireless", "wifi-device") if h.band(s) is not None]
    existing = [
        (n, s)
        for n, s in cfg.sections("wireless", "wifi-iface")
        if s.get("device") in radios and s.get("mode", "ap") == "ap" and str(s.get("ssid")) == ssid
    ]
    if not isinstance(c.new, WlanValue):
        for n, _ in existing:
            cfg.delete("wireless", n, f"{label}: remove from {n}")
        return
    w = c.new
    if w.security not in ENCRYPTION_OF:
        raise AdapterError(
            f"{label}: {w.security.value} is not supported by the OpenWrt integration "
            "(enterprise networks need RADIUS settings)"
        )
    key = None
    if w.security in h.PERSONAL:
        if w.passphrase_secret:
            if w.passphrase_secret not in secrets:
                raise AdapterError(f"{label}: secret {w.passphrase_secret!r} was not provided")
            key = secrets[w.passphrase_secret]
        elif not existing:
            raise AdapterError(f"{label}: a new {w.security.value} network needs a passphrase")
    if not radios:
        raise AdapterError(f"{label}: this device has no radios")
    network = _interface_for(cfg, site, w.segment, label)
    if not existing:
        for radio in radios:
            base = {"device": radio, "mode": "ap", "ssid": ssid}
            values, _ = _wifi_values(base, w, key, network)
            cfg.add(
                "wireless",
                "wifi-iface",
                f"{_slug(ssid)}_{radio}",
                base | values,
                f"{label}: new on {radio}",
            )
        return
    view = cfg.view()
    for n, s in existing:
        nets = h._list(s.get("network"))
        vid = view.vlan_of_interface(nets[0]) if nets else None
        here = (
            nets[0]
            if vid is not None and _seg(site, vid) == segment_id(site, seg_key(w.segment))
            else network
        )
        values, drop = _wifi_values(s, w, key, here)
        cfg.set("wireless", n, values, f"{label} on {n}: " + ", ".join(sorted(values)))
        cfg.drop("wireless", n, drop, f"{label} on {n}: remove " + ", ".join(drop))


# --- DHCP and reservations ------------------------------------------------------------------


def _v4(cfg: Configs, dump: Mapping[str, Any], name: str) -> IPv4Interface | None:
    """The interface's IPv4 address: running (dump), else its static configuration."""
    view = h.NetworkView.build(cfg.data["network"], dict(dump))
    running = [a for a in view.addresses(name) if isinstance(a, IPv4Interface)]
    if running:
        return running[0]
    s = cfg.values("network").get(name) or {}
    for text in h._list(s.get("ipaddr")):
        try:
            addr = ip_interface(text if "/" in text else f"{text}/{s.get('netmask', '32')}")
        except ValueError:
            continue
        if isinstance(addr, IPv4Interface):
            return addr
    return None


def _routed(cfg: Configs, dump: Mapping[str, Any], site: str, sid: str) -> tuple[str, IPv4Network]:
    view = cfg.view()
    for name in sorted(view.devices):
        vid = view.vlan_of_interface(name)
        if vid is None or _seg(site, vid) != sid:
            continue
        addr = _v4(cfg, dump, name)
        if addr is not None:
            return name, addr.network
    raise AdapterError(
        f"{sid}: no interface with an IPv4 address on this device (Signalbox does not create "
        "routed interfaces on OpenWrt)"
    )


def lease_text(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return str(seconds)


def _dhcp(cfg: Configs, c: Change, site: str, dump: Mapping[str, Any]) -> None:
    iface, net = _routed(cfg, dump, site, c.key)
    label = f"DHCP on {iface}"
    sections = [
        (n, s) for n, s in cfg.sections("dhcp", "dhcp") if str(s.get("interface", n)) == iface
    ]
    if not isinstance(c.new, DhcpValue):
        for n, _ in sections:
            cfg.delete("dhcp", n, f"{label}: remove")
        return
    d = c.new
    if d.enabled and d.pool is None:
        raise AdapterError(f"{label}: give the pool (first and last address)")
    if sections:
        name = sections[0][0]
    else:
        name = cfg.add("dhcp", "dhcp", iface, {"interface": iface}, f"{label}: new")
    s = cfg.values("dhcp")[name]
    out: dict[str, Any] = {}
    drop: list[str] = []
    if d.enabled and h._flag(s.get("ignore")):
        drop.append("ignore")
    if not d.enabled and not h._flag(s.get("ignore")):
        out["ignore"] = "1"
    if d.pool is not None:
        first, last = d.pool
        if not (
            isinstance(first, IPv4Address)
            and isinstance(last, IPv4Address)
            and first in net
            and last in net
            and first <= last
            and first != net.network_address
            and last != net.broadcast_address
        ):
            raise AdapterError(f"{label}: pool {first}-{last} is not inside {net}")
        start = int(first) - int(net.network_address)
        limit = int(last) - int(first) + 1
        if h._int(s.get("start", 100)) != start:
            out["start"] = str(start)
        if h._int(s.get("limit", 150)) != limit:
            out["limit"] = str(limit)
    if (
        d.lease_seconds is not None
        and h.lease_seconds(s.get("leasetime", "12h")) != d.lease_seconds
    ):
        out["leasetime"] = lease_text(d.lease_seconds)
    options = h._list(s.get("dhcp_option"))
    current = dict(o.split(",", 1) for o in options if "," in o).get("6", "")
    have = [str(ip_address(x)) for x in current.split(",") if x]
    want = [str(x) for x in d.dns or []]
    if have != want:
        rest = [o for o in options if not o.startswith("6,")]
        rest += ["6," + ",".join(want)] if want else []
        if rest:
            out["dhcp_option"] = rest
        else:
            drop.append("dhcp_option")
    cfg.set("dhcp", name, out, f"{label}: " + ", ".join(sorted(out)))
    cfg.drop("dhcp", name, drop, f"{label}: remove " + ", ".join(drop))


def _reservation(cfg: Configs, c: Change) -> None:
    mac = c.key.rsplit("/", 1)[1]
    label = f"reservation {mac}"
    hosts = [
        (n, s)
        for n, s in cfg.sections("dhcp", "host")
        if mac in (h._mac(m) for m in h._list(s.get("mac")))
    ]

    def release(n: str, s: dict[str, Any]) -> bool:
        """Take ``mac`` out of a host section shared with other MACs; False if it is only ours."""
        others = [m for m in h._list(s.get("mac")) if h._mac(m) != mac]
        if others:
            cfg.set("dhcp", n, {"mac": others}, f"{label}: remove from {n}")
        return bool(others)

    if not isinstance(c.new, ReservationValue):
        for n, s in hosts:
            if not release(n, s):
                cfg.delete("dhcp", n, f"{label}: remove")
        return
    r = c.new
    want: dict[str, Any] = {"ip": str(r.address)}
    if r.hostname:
        want["name"] = r.hostname
    own = next(((n, s) for n, s in hosts if len(h._list(s.get("mac"))) == 1), None)
    if own is None:
        for n, s in hosts:
            release(n, s)
        cfg.add(
            "dhcp", "host", f"host_{mac.replace(':', '')}", {"mac": mac, **want}, f"{label}: new"
        )
        return
    n, s = own
    cfg.set("dhcp", n, want, f"{label}: " + ", ".join(f"{k} {v}" for k, v in want.items()))
    if not r.hostname:
        cfg.drop("dhcp", n, ["name"], f"{label}: no host name")


# --- whole change sets ------------------------------------------------------------------------


def _cleanup(cfg: Configs) -> None:
    """Drop ``proto none`` interfaces left on a VLAN this transaction removed, if unused."""
    if not cfg.removed_vlans:
        return
    used = {n for _, s in cfg.sections("wireless", "wifi-iface") for n in h._list(s.get("network"))}
    used |= {str(s.get("interface", n)) for n, s in cfg.sections("dhcp", "dhcp")}
    for name, s in cfg.sections("network", "interface"):
        if (
            s.get("device") in cfg.removed_vlans
            and s.get("proto", "none") == "none"
            and name not in used
        ):
            cfg.delete("network", name, f"interface {name}: its VLAN was removed")


def translate(
    changes: Iterable[Change],
    data: Mapping[str, Any],
    dump: Mapping[str, Any],
    site: str,
    secrets: Mapping[str, str],
) -> Configs:
    """The UCI operations for a device's changes, in order."""
    cfg = Configs({name: copy.deepcopy(data[name]) for name in CONFIGS})
    for name in CONFIGS:
        cfg.values(name)  # shape check
    for c in changes:
        if c.kind is ChangeKind.PORT:
            _port(cfg, c)
        elif c.kind is ChangeKind.WLAN:
            _wlan(cfg, c, site, secrets)
        elif c.kind is ChangeKind.DHCP:
            _dhcp(cfg, c, site, dump)
        elif c.kind is ChangeKind.RESERVATION:
            _reservation(cfg, c)
        else:
            raise AdapterError(f"the OpenWrt integration cannot change {c.kind.value}")
    _cleanup(cfg)
    return cfg


def _options(section: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in section.items() if not k.startswith(".")}


def restore_ops(saved: Mapping[str, Any], current: Mapping[str, Any]) -> list[UciOp]:
    """Operations that turn ``current`` into ``saved`` (both: config -> ``uci get`` values)."""
    ops: list[UciOp] = []
    for config, want in saved.items():
        have = current.get(config) or {}
        cfg = Configs({config: {"values": copy.deepcopy(have)}})
        for name, s in list(have.items()):
            if name not in want or want[name].get(".type") != s.get(".type"):
                cfg.delete(config, name, f"restore {config}: remove {name}")
        for name, s in want.items():
            options = _options(s)
            if name in cfg.values(config):
                old = _options(cfg.values(config)[name])
                cfg.set(config, name, options, f"restore {config}.{name}")
                cfg.drop(
                    config, name, [k for k in old if k not in options], f"restore {config}.{name}"
                )
            else:
                cfg.add(config, str(s.get(".type")), name, options, f"restore {config}: {name}")
        ops += cfg.ops
        order = sorted(want, key=lambda n: _index(want[n]))
        now = sorted(cfg.values(config), key=lambda n: _index(cfg.values(config)[n]))
        if now != order:
            args = {"config": config, "sections": order}
            ops.append(UciOp("order", config, "*", args, f"restore {config}: section order"))
    return ops
