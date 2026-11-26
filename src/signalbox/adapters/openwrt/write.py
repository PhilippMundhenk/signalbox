"""OpenWrt (write): change sets as UCI operations for rpcd's ``uci`` ubus object.

Pure translation, no I/O: :func:`translate` takes the ``uci get`` answers of ``network``,
``wireless``, ``dhcp`` and ``firewall`` (and the running interfaces), applies the changes one by
one to an in-memory copy and records every ``uci set`` / ``add`` / ``delete`` it needs. Later
changes see the result of earlier ones (a PORT change that creates VLAN 30 comes before the WLAN
that uses it). :func:`restore_ops` turns a backup into the operations that put it back. The
transaction (staging, ``uci apply`` with rollback, ``uci confirm``) is in :class:`OpenWrtAdapter`.

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

from signalbox.adapters import (
    AdapterError,
    Described,
    Label,
    VendorCall,
    logging_errors,
    message_fields,
)
from signalbox.adapters import openwrt as h  # the read helpers (circular, used at run time)
from signalbox.adapters.openwrt import wgwrite
from signalbox.adapters.openwrt.firewall import FORWARD_TAG, POLICY_TAG, RULE_TAG
from signalbox.adapters.openwrt.firewall import tag as fw_tag
from signalbox.adapters.openwrt.mwanwrite import gateway_group
from signalbox.adapters.openwrt.wifi_assoc import default_mobility_domain
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    FirewallRuleValue,
    LogTargetValue,
    PortForwardValue,
    PortValue,
    ReservationValue,
    SnmpPolicyValue,
    WlanValue,
    ZonePolicyValue,
    unchanged_left_alone,
)
from signalbox.desired import SegmentRef, seg_key
from signalbox.model import (
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
    LogTransport,
    Pmf,
    PortRange,
    Security,
    segment_id,
)

#: The UCI configs Signalbox writes (and backs up); the rpcd ACL grants write access to these only.
CONFIGS = ("network", "wireless", "dhcp", "firewall", "system", "snmpd", "mwan3")
#: Tag Signalbox puts on the ``system`` section when it set the remote syslog target (#327).
LOG_TAG = "signalbox_syslog"
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
    {
        "key",
        "key1",
        "key2",
        "key3",
        "key4",
        "sae_password",
        "password",
        "auth_secret",
        "private_key",  # WireGuard (#152): never read or written, masked all the same
        "preshared_key",
    }
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
            **message_fields(self.description),
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
    #: WireGuard interfaces created in this transaction: the key helper gives them a key pair
    #: on the router after the apply (#152)
    wg_keys: list[str] = field(default_factory=list)

    def values(self, config: str) -> dict[str, Any]:
        if config not in self.data:
            raise AdapterError(
                f"uci {config} could not be read (the rpcd ACL of the login does not allow it)",
                message_id="openwrt.uciUnreadable",
                params={"config": config},
            )
        values = self.data[config].get("values")
        if not isinstance(values, dict):
            raise AdapterError(
                f"unexpected answer to uci.get ({config})",
                message_id="openwrt.unexpected",
                params={"what": f"uci.get ({config})"},
            )
        return values

    def sections(self, config: str, kind: str) -> list[tuple[str, dict[str, Any]]]:
        self.values(config)  # a config that could not be read: a clear error
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


def _remove(label: str) -> Described:
    return Described(f"{label}: remove", "plan.openwrt.remove", label=label)


def _new(label: str) -> Described:
    return Described(f"{label}: new", "plan.openwrt.new", label=label)


def _options_set(label: str, options: Iterable[str]) -> Described:
    shown = ", ".join(options)
    return Described(f"{label}: {shown}", "plan.openwrt.setOptions", label=label, options=shown)


def _options_removed(label: str, options: Iterable[str]) -> Described:
    shown = ", ".join(options)
    return Described(
        f"{label}: remove {shown}", "plan.openwrt.removeOptions", label=label, options=shown
    )


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
                "set up bridge-vlan sections first",
                message_id="openwrt.noBridgeVlans",
                params={"port": name, "bridge": bridges[0]},
            )
        raise AdapterError(
            f"port {name} is not a port of a bridge on this device",
            message_id="openwrt.notBridgePort",
            params={"port": name},
        )
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
            cfg.set(
                "network",
                section,
                {"ports": keep},
                Described(
                    f"{what}: VLAN {vid} ports {keep}",
                    "plan.openwrt.portVlanPorts",
                    port=name,
                    vlan=str(vid),
                    ports=str(keep),
                ),
            )
        else:
            cfg.delete(
                "network",
                section,
                Described(
                    f"{what}: VLAN {vid} has no ports left, remove it",
                    "plan.openwrt.portVlanRemove",
                    port=name,
                    vlan=str(vid),
                ),
            )
            cfg.removed_vlans.add(f"{bridge}.{vid}")
    for vid in sorted(set(wanted) - done):
        cfg.add(
            "network",
            "bridge-vlan",
            f"{_slug(bridge)}_{vid}",
            {"device": bridge, "vlan": str(vid), "ports": [name + wanted[vid]]},
            Described(
                f"{what}: new VLAN {vid} on {bridge}",
                "plan.openwrt.portVlanNew",
                port=name,
                vlan=str(vid),
                bridge=bridge,
            ),
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
        where = (
            Label("the untagged network", "untaggedNetwork")
            if vid is None
            else Label(f"VLAN {vid}", "vlan", vid)
        )
        raise AdapterError(
            f"{label}: {where} is not on any port of this device; add it to a port (for "
            "example tag the uplink) in the same plan",
            message_id="openwrt.vlanNotOnPort",
            params={"label": label, "where": where},
        )
    return cfg.add(
        "network",
        "interface",
        f"vlan{vid}",
        {"device": f"{bridge}.{vid}", "proto": "none"},
        Described(
            f"{label}: new interface for VLAN {vid} (no address)",
            "plan.openwrt.vlanInterfaceNew",
            label=label,
            vlan=str(vid),
        ),
    )


#: The first release whose netifd hostapd script passes ``rssi_reject_assoc_rssi`` on
#: (hostapd 2.10) *(guess, #21)*; older ones keep the option in UCI without any effect.
RSSI_REJECT_SINCE = (22, 3)


def rssi_reject_supported(release: str | None) -> bool:
    """Whether the OpenWrt ``release`` (``23.05.3``, ``SNAPSHOT``) applies the option."""
    text = (release or "").strip().upper()
    if text.startswith("SNAPSHOT"):
        return True
    match = re.match(r"(\d+)\.(\d+)", text)
    return match is not None and (int(match[1]), int(match[2])) >= RSSI_REJECT_SINCE


def _ft_values(s: dict[str, Any], w: WlanValue, out: dict[str, Any], drop: list[str]) -> None:
    """802.11r details and the minimum signal (#489, ADR 0033); only while 802.11r is on."""
    ft = w.roaming_80211r if w.roaming_80211r is not None else h._flag(s.get("ieee80211r"))
    if ft and w.mobility_domain is not None:
        have = str(s.get("mobility_domain") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{4}", have):
            have = default_mobility_domain(w.ssid)
        if have != w.mobility_domain or "mobility_domain" not in s:
            out["mobility_domain"] = w.mobility_domain
    over_ds = h._flag(s["ft_over_ds"]) if "ft_over_ds" in s else None
    if ft and w.ft_over_ds not in (None, over_ds):
        out["ft_over_ds"] = "1" if w.ft_over_ds else "0"
    if isinstance(w.min_rssi_dbm, int):
        if str(s.get("rssi_reject_assoc_rssi")) != str(w.min_rssi_dbm):
            out["rssi_reject_assoc_rssi"] = str(w.min_rssi_dbm)
    elif w.min_rssi_dbm == "off" and "rssi_reject_assoc_rssi" in s:
        drop.append("rssi_reject_assoc_rssi")


def _wifi_values(
    s: dict[str, Any], w: WlanValue, key: str | None, network: str
) -> tuple[dict[str, Any], list[str]]:
    """Options to set and to delete so that the read side reports ``w``."""
    out: dict[str, Any] = {}
    drop: list[str] = []
    _ft_values(s, w, out, drop)
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
        ("isolate", s.get("isolate"), w.client_isolation),
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


def _wlan(
    cfg: Configs, c: Change, site: str, secrets: Mapping[str, str], release: str | None
) -> None:
    ssid = c.key
    label = Label(f"SSID {ssid}", "ssid", ssid)
    old_rssi = c.old.min_rssi_dbm if isinstance(c.old, WlanValue) else None
    if (
        isinstance(c.new, WlanValue)
        and isinstance(c.new.min_rssi_dbm, int)
        and c.new.min_rssi_dbm != old_rssi
        and not rssi_reject_supported(release)
    ):
        raise AdapterError(
            f"{label}: a minimum signal (rssi_reject_assoc_rssi) needs OpenWrt 22.03 or newer; "
            f"this device runs {release or 'an unknown release'}",
            message_id="openwrt.minRssiRelease",
            params={"label": label, "release": release or "?"},
        )
    radios = [n for n, s in cfg.sections("wireless", "wifi-device") if h.band(s) is not None]
    existing = [
        (n, s)
        for n, s in cfg.sections("wireless", "wifi-iface")
        if s.get("device") in radios and s.get("mode", "ap") == "ap" and str(s.get("ssid")) == ssid
    ]
    if not isinstance(c.new, WlanValue):
        for n, _ in existing:
            cfg.delete(
                "wireless",
                n,
                Described(
                    f"{label}: remove from {n}", "plan.openwrt.removeFrom", label=label, section=n
                ),
            )
        return
    w = c.new
    if w.security not in ENCRYPTION_OF:
        raise AdapterError(
            f"{label}: {w.security.value} is not supported by the OpenWrt integration "
            "(enterprise networks need RADIUS settings)",
            message_id="openwrt.securityUnsupported",
            params={"label": label, "security": w.security.value},
        )
    key = None
    if w.security in h.PERSONAL:
        if w.passphrase_secret:
            if w.passphrase_secret not in secrets:
                raise AdapterError(
                    f"{label}: secret {w.passphrase_secret!r} was not provided",
                    message_id="openwrt.secretMissing",
                    params={"label": label, "name": repr(w.passphrase_secret)},
                )
            key = secrets[w.passphrase_secret]
        elif not existing:
            raise AdapterError(
                f"{label}: a new {w.security.value} network needs a passphrase",
                message_id="openwrt.passphraseNeeded",
                params={"label": label, "security": w.security.value},
            )
    if not radios:
        raise AdapterError(
            f"{label}: this device has no radios",
            message_id="openwrt.noRadios",
            params={"label": label},
        )
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
                Described(
                    f"{label}: new on {radio}", "plan.openwrt.wlanNew", label=label, radio=radio
                ),
            )
        return
    w = unchanged_left_alone(w, c.old)
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
        shown = ", ".join(sorted(values))
        cfg.set(
            "wireless",
            n,
            values,
            Described(
                f"{label} on {n}: {shown}",
                "plan.openwrt.wlanSet",
                label=label,
                section=n,
                options=shown,
            ),
        )
        gone = ", ".join(drop)
        cfg.drop(
            "wireless",
            n,
            drop,
            Described(
                f"{label} on {n}: remove {gone}",
                "plan.openwrt.wlanDrop",
                label=label,
                section=n,
                options=gone,
            ),
        )


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
        "routed interfaces on OpenWrt)",
        message_id="openwrt.noRoutedInterface",
        params={"segment": sid},
    )


def lease_text(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return str(seconds)


def _dhcp(cfg: Configs, c: Change, site: str, dump: Mapping[str, Any]) -> None:
    iface, net = _routed(cfg, dump, site, c.key)
    label = Label(f"DHCP on {iface}", "dhcpOn", iface)
    sections = [
        (n, s) for n, s in cfg.sections("dhcp", "dhcp") if str(s.get("interface", n)) == iface
    ]
    if not isinstance(c.new, DhcpValue):
        for n, _ in sections:
            cfg.delete("dhcp", n, _remove(label))
        return
    d = c.new
    if d.enabled and d.pool is None:
        raise AdapterError(
            f"{label}: give the pool (first and last address)",
            message_id="openwrt.poolNeeded",
            params={"label": label},
        )
    if sections:
        name = sections[0][0]
    else:
        name = cfg.add("dhcp", "dhcp", iface, {"interface": iface}, _new(label))
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
            raise AdapterError(
                f"{label}: pool {first}-{last} is not inside {net}",
                message_id="openwrt.poolOutside",
                params={"label": label, "first": str(first), "last": str(last), "net": str(net)},
            )
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
    cfg.set("dhcp", name, out, _options_set(label, sorted(out)))
    cfg.drop("dhcp", name, drop, _options_removed(label, drop))


def _reservation(cfg: Configs, c: Change) -> None:
    mac = c.key.rsplit("/", 1)[1]
    label = Label(f"reservation {mac}", "reservation", mac)
    hosts = [
        (n, s)
        for n, s in cfg.sections("dhcp", "host")
        if mac in (h._mac(m) for m in h._list(s.get("mac")))
    ]

    def release(n: str, s: dict[str, Any]) -> bool:
        """Take ``mac`` out of a host section shared with other MACs; False if it is only ours."""
        others = [m for m in h._list(s.get("mac")) if h._mac(m) != mac]
        if others:
            cfg.set(
                "dhcp",
                n,
                {"mac": others},
                Described(
                    f"{label}: remove from {n}", "plan.openwrt.removeFrom", label=label, section=n
                ),
            )
        return bool(others)

    if not isinstance(c.new, ReservationValue):
        for n, s in hosts:
            if not release(n, s):
                cfg.delete("dhcp", n, _remove(label))
        return
    r = c.new
    want: dict[str, Any] = {"ip": str(r.address)}
    if r.hostname:
        want["name"] = r.hostname
    own = next(((n, s) for n, s in hosts if len(h._list(s.get("mac"))) == 1), None)
    if own is None:
        for n, s in hosts:
            release(n, s)
        cfg.add("dhcp", "host", f"host_{mac.replace(':', '')}", {"mac": mac, **want}, _new(label))
        return
    n, s = own
    cfg.set("dhcp", n, want, _options_set(label, [f"{k} {v}" for k, v in want.items()]))
    if not r.hostname:
        cfg.drop(
            "dhcp",
            n,
            ["name"],
            Described(f"{label}: no host name", "plan.openwrt.noHostName", label=label),
        )


# --- firewall (#295) ------------------------------------------------------------------------
#
# Signalbox only creates named sections with its prefix (``sb_rule_<key>``, ``sb_fwd_<key>``,
# ``sb_pol_<src>_<dest>``) and only changes or deletes those. The device's own sections are
# left alone, except: a zone's ``input`` / ``forward`` option for a declared policy, and the
# device's own rule, redirect or forwarding a change adopts (``Change.adopt``), which is deleted
# and replaced by Signalbox's section.

#: Options of a rule and a redirect that Signalbox writes (others it removes from its sections).
RULE_OPTIONS = (
    "name",
    "enabled",
    "src",
    "src_ip",
    "src_port",
    "dest",
    "dest_ip",
    "dest_port",
    "proto",
    "family",
    "target",
)
FORWARD_OPTIONS = (
    "name",
    "enabled",
    "target",
    "src",
    "src_ip",
    "src_dip",
    "src_dport",
    "dest",
    "dest_ip",
    "dest_port",
    "proto",
)


#: Options the writer sets from the declaration (an adopted section's others are carried over).
RULE_MODELLED = tuple(o for o in RULE_OPTIONS if o != "src_port")
FORWARD_MODELLED = (
    "name",
    "enabled",
    "target",
    "src",
    "src_dport",
    "dest",
    "dest_ip",
    "dest_port",
    "proto",
)


def _ports_text(ports: list[PortRange]) -> str:
    return " ".join(str(r) for r in ports)


def _proto(protocols: list[FirewallProtocol]) -> str | list[str]:
    if not protocols:
        return "all"
    return [p.value for p in protocols]


def _zone_section(cfg: Configs, name: str, label: str) -> str:
    for section, z in cfg.sections("firewall", "zone"):
        if str(z.get("name")) == name:
            return section
    raise AdapterError(
        f"{label}: the firewall has no zone {name!r}",
        message_id="openwrt.noZone",
        params={"label": label, "zone": repr(name)},
    )


def _show(value: Any) -> str:
    return " ".join(str(v) for v in value) if isinstance(value, list) else str(value)


def _kept(
    section: dict[str, Any], values: dict[str, Any] | None, modelled: tuple[str, ...]
) -> dict[str, Any]:
    """The options of an adopted section that the declaration does not model (``log``, ``limit``,
    ``extra`` ...): they are carried over to Signalbox's section."""
    return {
        k: v
        for k, v in section.items()
        if not k.startswith(".") and k not in modelled and k not in (values or {})
    }


def _refuse_kept(kept: dict[str, Any], values: dict[str, Any], label: str) -> None:
    """A kept option the declared ones cannot live with: refuse and list every kept option."""
    proto = values.get("proto")
    protos = proto if isinstance(proto, list) else [proto]
    clash = []
    if "icmp_type" in kept and not any(str(p).startswith("icmp") for p in protos):
        clash.append("icmp_type (needs the protocol icmp)")
    if clash:
        everything = ", ".join(f"{k}={_show(v)}" for k, v in kept.items())
        raise AdapterError(
            f"{label}: the device's section has options the declaration does not model and that "
            f"do not fit it: {'; '.join(clash)}. Adopting would keep: {everything}. "
            "Change the declaration or the section on the device",
            message_id="openwrt.keptClash",
            params={"label": label, "clash": "; ".join(clash), "kept": everything},
        )


def _replace(
    cfg: Configs,
    kind: str,
    section: str,
    adopt: str | None,
    values: dict[str, Any] | None,
    managed: tuple[str, ...],
    label: str,
    modelled: tuple[str, ...] = (),
) -> bool:
    """Signalbox's section ``section`` gets ``values`` (``None``: deleted); an adopted section
    of the device's own is deleted first. True when the section was created."""
    have = cfg.values("firewall")
    adopted_note = ""
    if section not in have and adopt:
        own = [
            n
            for n, x in cfg.sections("firewall", kind)
            if str(x.get("name")) == adopt
            and not fw_tag(x, RULE_TAG if kind == "rule" else FORWARD_TAG)
        ]
        if len(own) != 1:
            raise AdapterError(
                f"{label}: the device has {'no' if not own else 'several'} {kind} named {adopt!r} "
                "to adopt",
                message_id="openwrt.adoptNone" if not own else "openwrt.adoptSeveral",
                params={"label": label, "kind": kind, "name": repr(adopt)},
            )
        kept = _kept(have[own[0]], values, modelled)
        if values is not None:
            _refuse_kept(kept, values, label)
        shown = ", ".join(f"{k}={_show(v)}" for k, v in kept.items())
        cfg.delete(
            "firewall",
            own[0],
            Described(
                f"{label}: adopt the device's {kind} {adopt!r}",
                "plan.adoptSection",
                label=label,
                kind=kind,
                name=repr(adopt),
            ),
        )
        if values is not None:
            # the section is created again with the options the declaration does not model
            values = {**kept, **values}
            adopted_note = f" (keeps {shown})" if shown else ""
    if values is None:
        if section in have:
            cfg.delete("firewall", section, _remove(label))
        return False
    if section in have:
        cfg.set("firewall", section, values, _options_set(label, sorted(values)))
        cfg.drop(
            "firewall",
            section,
            [o for o in managed if o not in values],
            Described(f"{label}: remove options", "plan.openwrt.removeUnmodelled", label=label),
        )
        return False
    note = (
        Described(f"{label}: new{adopted_note}", "plan.newKeeps", label=label, kept=shown)
        if adopted_note
        else _new(label)
    )
    cfg.add("firewall", kind, section, values, note)
    return True


def _policy(cfg: Configs, c: Change) -> None:
    _, source, dest_text = c.key.split("/", 2)
    dest = None if dest_text == "device" else dest_text
    label = Label(f"policy {source} → {dest or 'device'}", "policy", source, dest or "device")
    if not isinstance(c.new, ZonePolicyValue):  # pragma: no cover - policies are never removed
        return
    action = c.new.action.value.upper()
    zone = _zone_section(cfg, source, label)
    if dest is None or dest == source:
        option = "input" if dest is None else "forward"
        cfg.set(
            "firewall",
            zone,
            {option: action},
            Described(
                f"{label}: zone {source} {option} {action}",
                "plan.openwrt.zoneOption",
                label=label,
                zone=source,
                option=option,
                action=action,
            ),
        )
        return
    _zone_section(cfg, dest, label)
    pair = [
        (n, x)
        for n, x in cfg.sections("firewall", "forwarding")
        if str(x.get("src")) == source
        and str(x.get("dest")) == dest
        and h._flag(x.get("enabled"), default=True)
    ]
    if c.new.action is FirewallAction.ACCEPT:
        if not pair:
            cfg.add(
                "firewall",
                "forwarding",
                f"{POLICY_TAG}{source}_{dest}",
                {"src": source, "dest": dest},
                Described(f"{label}: new forwarding", "plan.openwrt.newForwarding", label=label),
            )
        return
    if c.new.action is FirewallAction.DROP:
        raise AdapterError(
            f"{label}: OpenWrt rejects traffic between two zones without a forwarding; declare "
            "reject, or a rule that drops",
            message_id="openwrt.dropNeedsForwarding",
            params={"label": label},
        )
    for n, x in pair:
        if fw_tag(x, POLICY_TAG) is None and not c.adopt:
            raise AdapterError(
                f"{label}: the forwarding {n} is the device's own, not created by Signalbox; "
                "remove it on the device, or declare the policy with `adopt: true`",
                message_id="openwrt.foreignForwarding",
                params={"label": label, "section": n},
            )
        cfg.delete(
            "firewall",
            n,
            Described(
                f"{label}: remove forwarding {n}",
                "plan.openwrt.removeForwarding",
                label=label,
                section=n,
            ),
        )


def _rule_values(v: FirewallRuleValue) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": v.name,
        "src": v.source_zone or "*",
        "proto": _proto(v.protocols),
        "target": v.action.value.upper(),
    }
    if v.chain is FirewallChain.FORWARD:
        out["dest"] = v.destination_zone or "*"
    if v.source_networks:
        out["src_ip"] = [str(n) for n in v.source_networks]
    if v.destination_networks:
        out["dest_ip"] = [str(n) for n in v.destination_networks]
    if v.destination_ports:
        out["dest_port"] = _ports_text(v.destination_ports)
    if v.family is not None:
        out["family"] = f"ipv{v.family}"
    if not v.enabled:
        out["enabled"] = "0"
    return out


def _rule_change(cfg: Configs, c: Change) -> str | None:
    key = c.key.partition("/")[2]
    section = RULE_TAG + key
    v = c.new if isinstance(c.new, FirewallRuleValue) else None
    created = _replace(
        cfg,
        "rule",
        section,
        c.adopt,
        _rule_values(v) if v else None,
        RULE_OPTIONS,
        Label(f"firewall rule {key}", "fwRule", key),
        RULE_MODELLED,
    )
    return section if created else None


def _zone_of_address(cfg: Configs, dump: Mapping[str, Any], address: Any, label: str) -> str:
    """The firewall zone of the interface whose IPv4 subnet holds ``address``."""
    for name, _ in cfg.sections("network", "interface"):
        addr = _v4(cfg, dump, name)
        if addr is None or address not in addr.network:
            continue
        for _, z in cfg.sections("firewall", "zone"):
            nets = h._list(z.get("network")) or [str(z.get("name"))]
            if name in nets:
                return str(z.get("name"))
    raise AdapterError(
        f"{label}: {address} is in no network of a firewall zone on this router",
        message_id="openwrt.noZoneForAddress",
        params={"label": label, "address": str(address)},
    )


def _forward_change(cfg: Configs, c: Change, dump: Mapping[str, Any]) -> None:
    key = c.key.partition("/")[2]
    label = Label(f"port forward {key}", "portForward", key)
    v = c.new if isinstance(c.new, PortForwardValue) else None
    values: dict[str, Any] | None = None
    if v is not None:
        _zone_section(cfg, v.zone, label)
        values = {
            "name": v.name,
            "target": "DNAT",
            "src": v.zone,
            "src_dport": _ports_text(v.external_ports),
            "dest": _zone_of_address(cfg, dump, v.target_address, label),
            "dest_ip": str(v.target_address),
            "proto": _proto(v.protocols),
        }
        if v.target_port is not None:
            first = v.external_ports[0]
            span = first.last - first.start
            values["dest_port"] = (
                str(v.target_port) if not span else f"{v.target_port}-{v.target_port + span}"
            )
        if not v.enabled:
            values["enabled"] = "0"
    _replace(
        cfg,
        "redirect",
        FORWARD_TAG + key,
        c.adopt,
        values,
        FORWARD_OPTIONS,
        label,
        FORWARD_MODELLED,
    )


def _order_rules(cfg: Configs, created: list[str]) -> None:
    """Signalbox's rules first (before the device's own), the new ones after the older ones."""
    if not created:
        return
    values = cfg.values("firewall")
    ours = [
        n for n, x in cfg.sections("firewall", "rule") if fw_tag(x, RULE_TAG) and n not in created
    ]
    order = [*ours, *created]
    for i, name in enumerate(sorted(values, key=lambda n: _index(values[n]))):
        values[name][".index"] = i + len(order)
    for i, name in enumerate(order):
        values[name][".index"] = i
    args = {"config": "firewall", "sections": order}
    note = Described("Signalbox's rules before the others", "plan.openwrt.rulesFirst")
    cfg.ops.append(UciOp("order", "firewall", "*", args, note))


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
            cfg.delete(
                "network",
                name,
                Described(
                    f"interface {name}: its VLAN was removed",
                    "plan.openwrt.vlanInterfaceRemoved",
                    name=name,
                ),
            )


def _first(value: Any) -> str:
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).strip() if value is not None else ""


def _log_target(cfg: Configs, c: Change, adopted: set[str], created: list[str]) -> None:
    """The remote syslog target of logd: ``log_ip``, ``log_port`` and ``log_proto`` of the first
    ``system`` section, tagged with ``signalbox_syslog`` (#327). The device has one slot."""
    found = cfg.sections("system", "system")
    if not found:
        raise AdapterError(
            "the router has no system section to set the syslog target in",
            message_id="openwrt.noSystemSection",
        )
    name, section = found[0]
    address = c.key.partition("/")[2]
    now = _first(section.get("log_ip"))
    owned = _first(section.get(LOG_TAG)) == "1"
    label = Label(f"syslog target {address}", "syslogTarget", address)
    if isinstance(c.new, LogTargetValue):
        v = c.new
        if v.transport not in (LogTransport.UDP, LogTransport.TCP):
            raise logging_errors.transport(v.transport.value)
        if created:
            raise logging_errors.one_target(len(created) + 1)
        if now and now != address and not owned and now not in adopted:
            raise logging_errors.foreign_target(now)
        created.append(address)
        # putting back the device's own target (the undo of an adoption) leaves it untagged
        theirs = c.adopt == address and c.old is None
        values = {"log_ip": v.address, "log_port": str(v.port), "log_proto": v.transport.value}
        cfg.set(
            "system",
            name,
            values if theirs else {**values, LOG_TAG: "1"},
            Described(f"{label}: set", "plan.openwrt.targetSet", label=label),
        )
        if theirs:
            cfg.drop(
                "system",
                name,
                [LOG_TAG],
                Described(f"{label}: not Signalbox's", "plan.openwrt.targetNotOurs", label=label),
            )
        cfg.drop(
            "system",
            name,
            ["log_remote"],
            Described(f"{label}: send it", "plan.openwrt.targetSend", label=label),
        )
        return
    # removal: only when the slot still holds this target (an update at another address came first)
    if now != address:
        return
    if not owned and c.adopt != address:
        raise logging_errors.foreign_target(address)
    cfg.drop("system", name, ["log_ip", "log_port", "log_proto", LOG_TAG], _remove(label))


def _snmp_policy(cfg: Configs, c: Change) -> None:
    """Switch the net-snmp agent (package ``snmpd``) on or off through ``snmpd.general``."""
    if "snmpd" not in cfg.data:
        raise logging_errors.no_agent("snmpd")
    mode = c.new.mode if isinstance(c.new, SnmpPolicyValue) else "off"
    if mode == "v3-only":
        raise logging_errors.v3_only()
    value = "0" if mode == "off" else "1"
    found = cfg.sections("snmpd", "snmpd")
    note = Described(f"SNMP agent: {mode}", "plan.openwrt.snmpAgent", mode=mode)
    if found:
        cfg.set("snmpd", found[0][0], {"enabled": value}, note)
    else:
        cfg.add("snmpd", "snmpd", "general", {"enabled": value}, note)


def translate(
    changes: Iterable[Change],
    data: Mapping[str, Any],
    dump: Mapping[str, Any],
    site: str,
    secrets: Mapping[str, str],
    release: str | None = None,
) -> Configs:
    """The UCI operations for a device's changes, in order; ``release`` is the OpenWrt
    version (``system board``), needed for a minimum signal only."""
    # ``firewall`` is missing where an older ACL does not let the login read it
    cfg = Configs({name: copy.deepcopy(data[name]) for name in CONFIGS if name in data})
    for name in cfg.data:
        cfg.values(name)  # shape check
    created: list[str] = []
    changes = list(changes)
    adopted = {
        c.adopt for c in changes if c.kind is ChangeKind.LOG_TARGET and c.new is None and c.adopt
    }
    syslog: list[str] = []
    for c in changes:
        if c.kind is ChangeKind.LOG_TARGET:
            _log_target(cfg, c, {a for a in adopted if a}, syslog)
        elif c.kind is ChangeKind.SNMP_POLICY:
            _snmp_policy(cfg, c)
        elif c.kind is ChangeKind.GATEWAY_GROUP:
            gateway_group(cfg, c)
        elif c.kind is ChangeKind.TUNNEL:
            if (iface := wgwrite.tunnel(cfg, c)) is not None:
                cfg.wg_keys.append(iface)
        elif c.kind is ChangeKind.TUNNEL_PEER:
            wgwrite.peer(cfg, c)
        elif c.kind is ChangeKind.ZONE_POLICY:
            _policy(cfg, c)
        elif c.kind is ChangeKind.FIREWALL_RULE:
            if (new := _rule_change(cfg, c)) is not None:
                created.append(new)
        elif c.kind is ChangeKind.PORT_FORWARD:
            _forward_change(cfg, c, dump)
        elif c.kind is ChangeKind.PORT:
            _port(cfg, c)
        elif c.kind is ChangeKind.WLAN:
            _wlan(cfg, c, site, secrets, release)
        elif c.kind is ChangeKind.DHCP:
            _dhcp(cfg, c, site, dump)
        elif c.kind is ChangeKind.RESERVATION:
            _reservation(cfg, c)
        else:
            raise AdapterError(
                f"the OpenWrt integration cannot change {c.kind.value}",
                message_id="openwrt.unsupportedKind",
                params={"kind": c.kind.value},
            )
    _order_rules(cfg, created)
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
                cfg.delete(
                    config,
                    name,
                    Described(
                        f"restore {config}: remove {name}",
                        "plan.openwrt.restoreRemove",
                        config=config,
                        name=name,
                    ),
                )
        for name, s in want.items():
            options = _options(s)
            if name in cfg.values(config):
                old = _options(cfg.values(config)[name])
                note = Described(
                    f"restore {config}.{name}", "plan.openwrt.restoreSet", config=config, name=name
                )
                cfg.set(config, name, options, note)
                cfg.drop(config, name, [k for k in old if k not in options], note)
            else:
                cfg.add(
                    config,
                    str(s.get(".type")),
                    name,
                    options,
                    Described(
                        f"restore {config}: {name}",
                        "plan.openwrt.restoreAdd",
                        config=config,
                        name=name,
                    ),
                )
        ops += cfg.ops
        order = sorted(want, key=lambda n: _index(want[n]))
        now = sorted(cfg.values(config), key=lambda n: _index(cfg.values(config)[n]))
        if now != order:
            args = {"config": config, "sections": order}
            note = Described(
                f"restore {config}: section order", "plan.openwrt.restoreOrder", config=config
            )
            ops.append(UciOp("order", config, "*", args, note))
    return ops
