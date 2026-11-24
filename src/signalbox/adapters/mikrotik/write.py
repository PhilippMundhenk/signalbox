"""MikroTik RouterOS 7 (write): router interfaces, DHCP, static leases, bridge VLANs, Wi-Fi.

The RouterOS REST API changes one menu entry per request: ``PUT /rest/<menu>`` creates,
``PATCH /rest/<menu>/<.id>`` updates, ``DELETE /rest/<menu>/<.id>`` removes, and
``POST /rest/<menu>/unset`` clears a property (it then falls back to its profile or default).
Every value is sent as a string, as RouterOS answers them.

How a change is translated (details and open questions in ``docs/adapters/mikrotik.md``):

- the integration reads every menu it may touch, works out the calls on a local copy (so a
  later change of the same deployment sees the interfaces an earlier one creates), and sends
  them in order; ``plan_changes`` returns the same calls without sending them
- RouterOS has no confirm timer for API sessions (``safe-mode`` exists for interactive
  terminals only), so ``apply`` returns no deadline and ``confirm`` does nothing
- the backup is a JSON snapshot of every menu the integration writes to, plus the text of
  ``/export`` for people. An export cannot be imported through the REST API, so ``restore``
  compares the device with the snapshot and undoes the difference: entries that were added are
  removed, removed ones are added again, changed ones are set back
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Interface, ip_address, ip_interface
from typing import TYPE_CHECKING, Any

from signalbox.adapters import (
    AdapterError,
    ApplyResult,
    AuthFailed,
    Backup,
    Unreachable,
    VendorCall,
    message_fields,
)
from signalbox.adapters.https import NotFound
from signalbox.adapters.mikrotik import fwwrite
from signalbox.changes import (
    Change,
    ChangeKind,
    DhcpValue,
    PortValue,
    ReservationValue,
    RouterValue,
    WlanValue,
)
from signalbox.desired import seg_key
from signalbox.model import Pmf, Security, normalise_mac

if TYPE_CHECKING:  # pragma: no cover
    from signalbox.adapters import AdapterContext, Observation
    from signalbox.adapters.https import DeviceHttp
    from signalbox.adapters.mikrotik import _Layout

#: How long a DHCP server may stay ``invalid`` after a change ("No IP address on interface":
#: RouterOS 7.25.1 shows that for about a second after the address of a new VLAN interface).
SETTLE_SECONDS = 15.0

#: Kinds of change the integration applies (all of them; Wi-Fi on the RouterOS 7 ``wifi``
#: package; firewall kinds (#295, docs/adr/0017) with a revert timer, see ``fwwrite``).
WRITES = frozenset(ChangeKind)

#: ``/system/scheduler``: the revert timer of firewall changes.
SCHEDULER = "/rest/system/scheduler"

BACKUP_FORMAT = "routeros-export"
#: ``POST /rest/export`` answers ``[]`` (the text goes to a terminal that REST does not have);
#: ``/execute`` with ``as-string`` returns the output of the script as ``{"ret": ...}``.
EXECUTE = "/rest/execute"
EXPORT_SCRIPT = {"script": "/export", "as-string": ""}

_TRUE, _FALSE = "true", "false"
_SECURITY_TYPES = {
    Security.OPEN: "",
    Security.WPA2: "wpa2-psk",
    Security.WPA3: "wpa3-psk",
    Security.WPA2_WPA3: "wpa2-psk,wpa3-psk",
    Security.OWE: "owe",
}
_PERSONAL = {Security.WPA2, Security.WPA3, Security.WPA2_WPA3}
_PMF_VALUES = {Pmf.DISABLED: "disabled", Pmf.OPTIONAL: "allowed", Pmf.REQUIRED: "required"}
_SECRET_PROPS = {"security.passphrase", "passphrase", "wpa2-pre-shared-key", "wpa-pre-shared-key"}
#: Properties the device computes; never compared or sent when restoring.
_READ_ONLY = {
    ".id",
    ".about",
    ".nextid",
    "dynamic",
    "running",
    "invalid",
    "inactive",
    "disabled-by",
    "actual-interface",
    "actual-mtu",
    "current-tagged",
    "current-untagged",
    "status",
    "active-address",
    "active-mac-address",
    "active-client-id",
    "active-server",
    "active-hostname",
    "expires-after",
    "last-seen",
    "host-name",
    "age",
    "radius",
    "blocked",
    "default-name",
    "slave",
    "network",
    "hw-offload",
    "debug-info",
    "port-number",
    "role",
    "edge-port",
    "point-to-point-port",
    "forwarding",
    "learning",
    "sending-rstp",
    "external-fdb-status",
    "class-id",
    "bytes",
    "packets",
    # read-only state RouterOS 7.25.1 CHR lists in these menus (seen in CI, #139)
    "actual-path-cost",
    "designated-bridge-id",
    "designated-cost",
    "designated-port-id",
    "discard-transitions",
    "edge-port-discovery",
    "forward-transitions",
    "mvrp-applicant-state",
    "mvrp-registrar-state",
    "root-path-cost",
    "rx-bpdu",
    "rx-tc",
    "topology-changes",
    "tx-bpdu",
    "tx-tc",
    "port-id",
    "l2mtu",
    "loop-protect-status",
    "hw-offloaded",
    "managed",
    "available",
    "total",
    "used",
    "active-agent-circuit-id",
    "active-agent-remote-id",
    "agent-circuit-id",
    "agent-remote-id",
}


def _menus() -> tuple[str, ...]:
    from signalbox.adapters import mikrotik as m

    return (
        m.VLAN,
        m.BRIDGE,
        m.BRIDGE_VLAN,
        m.BRIDGE_PORT,
        m.IP_ADDRESS,
        m.POOL,
        m.DHCP_NETWORK,
        m.DHCP_SERVER,
        m.DHCP_LEASE,
        m.WIFI,
        m.FW_FILTER,
        m.FW_FILTER6,
        m.FW_NAT,
    )


def _fw_menus() -> tuple[str, ...]:
    from signalbox.adapters import mikrotik as m

    return (m.FW_FILTER, m.FW_FILTER6, m.FW_NAT)


def ros_duration(seconds: int) -> str:
    """Seconds as RouterOS writes a time: ``1d``, ``30m``, ``1h30m``, ``0s``."""
    out, rest = "", seconds
    for unit, size in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if rest >= size:
            out += f"{rest // size}{unit}"
            rest %= size
    return out or "0s"


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-")[:24] or "ssid"


# --- calls on a local copy of the configuration ----------------------------------------------


@dataclass
class _Op:
    method: str
    menu: str
    ref: str | None
    body: dict[str, str]
    description: str

    @property
    def target(self) -> str:
        if self.method == "PUT":
            return self.menu
        if self.method == "POST":
            return f"{self.menu}/unset"
        return f"{self.menu}/{self.ref}"

    def call(self) -> VendorCall:
        payload: dict[str, Any] = {
            k: ("***" if k in _SECRET_PROPS else v) for k, v in self.body.items()
        }
        return VendorCall(
            description=self.description,
            **message_fields(self.description),
            method=self.method,
            target=self.target,
            payload=payload,
        )


@dataclass
class _Config:
    """Rows of the menus read from the device; changes are recorded as calls."""

    menus: dict[str, list[dict[str, Any]]]
    ops: list[_Op] = field(default_factory=list)
    _counter: int = 0
    #: Menus the router does not have (a package that is not installed).
    absent: set[str] = field(default_factory=set)
    #: What undoes the firewall changes of the plan (the script of the revert timer).
    revert: fwwrite.Revert = field(default_factory=fwwrite.Revert)

    def rows(self, menu: str) -> list[dict[str, Any]]:
        return self.menus.setdefault(menu, [])

    def static(self, menu: str) -> list[dict[str, Any]]:
        return [r for r in self.rows(menu) if not _flag(r.get("dynamic"))]

    def put(self, menu: str, body: dict[str, str], description: str) -> dict[str, Any]:
        self._counter += 1
        row: dict[str, Any] = {".id": f"new-{self._counter}", **body}
        self.rows(menu).append(row)
        self.ops.append(_Op("PUT", menu, row[".id"], dict(body), description))
        return row

    def patch(self, menu: str, row: dict[str, Any], body: dict[str, str], description: str) -> None:
        body = {k: v for k, v in body.items() if row.get(k) != v}
        if not body:
            return
        row.update(body)
        self.ops.append(_Op("PATCH", menu, row[".id"], body, description))

    def unset(self, menu: str, row: dict[str, Any], prop: str, description: str) -> None:
        if row.get(prop) in (None, ""):
            return
        row.pop(prop)
        body = {"numbers": str(row[".id"]), "value-name": prop}
        self.ops.append(_Op("POST", menu, row[".id"], body, description))

    def delete(self, menu: str, row: dict[str, Any], description: str) -> None:
        self.rows(menu).remove(row)
        self.ops.append(_Op("DELETE", menu, row[".id"], {}, description))


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> bool:
    return value is True or _text(value).lower() in ("true", "yes", "on")


def _names(value: Any) -> list[str]:
    parts = value if isinstance(value, list) else _text(value).split(",")
    return [p.strip() for p in parts if isinstance(p, str) and p.strip()]


def _join(names: list[str]) -> str:
    return ",".join(names)


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _v4(row: dict[str, Any]) -> IPv4Interface | None:
    try:
        a = ip_interface(_text(row.get("address")))
    except ValueError:
        return None
    return a if isinstance(a, IPv4Interface) else None


def _refused(description: str, response: Any, scrub: Callable[[str], str]) -> AdapterError:
    """RouterOS answers a refused change with ``{"error": 400, "message", "detail"}``, and a
    user without the ``write`` policy with HTTP 500 ``not enough permissions (9)``."""
    try:
        data = response.json()
    except ValueError:
        data = {}
    detail = ""
    if isinstance(data, dict):
        detail = _text(data.get("detail")) or _text(data.get("message"))
    detail = detail or f"HTTP {response.status_code}"
    if "not enough permissions" in detail:
        return AuthFailed(
            scrub(f"{description}: access denied ({detail}); the user's group needs write")
        )
    return AdapterError(scrub(f"{description}: the router refused the change: {detail}"))


# --- the write side of the adapter -----------------------------------------------------------


class MikrotikWrites:
    """``WritesConfig`` for :class:`signalbox.adapters.mikrotik.MikrotikAdapter`."""

    if TYPE_CHECKING:  # provided by the adapter
        context: AdapterContext
        http: DeviceHttp
        _cache: dict[str, Any]
        _layout_cache: _Layout | None

        async def _build_layout(self) -> _Layout: ...

        async def _wifi(self, layout: _Layout, rows: list[dict[str, Any]]) -> Observation: ...

    async def _snapshot(self) -> tuple[_Config, bool]:
        """Fresh copies of every menu the planner needs; ``(config, wifi package present)``."""
        from signalbox.adapters import mikrotik as m

        self._cache.clear()
        self._layout_cache = None
        menus: dict[str, list[dict[str, Any]]] = {}
        absent: set[str] = set()
        wifi = True
        for menu in dict.fromkeys(
            (
                m.INTERFACE,
                m.INTERFACE_LIST,
                m.ETHERNET,
                m.LIST_MEMBER,
                m.IPV6_ADDRESS,
                *_menus(),
                m.WIFI_CONFIGURATION,
                m.WIFI_SECURITY,
                m.WIFI_CHANNEL,
                m.WIFI_DATAPATH,
                m.WIFI_STEERING,
            )
        ):
            try:
                menus[menu] = m._rows(await m.get_menu(self.http, menu), menu)
            except NotFound:
                menus[menu] = []
                absent.add(menu)
                wifi = wifi and menu != m.WIFI
        self._cache.clear()
        return _Config(menus, absent=absent), wifi

    async def _layout_of(self, cfg: _Config) -> _Layout:
        self._cache.clear()
        self._cache.update(cfg.menus)
        self._layout_cache = None
        try:
            return await self._build_layout()
        finally:
            self._cache.clear()
            self._layout_cache = None

    async def _plan(
        self, changes: list[Change], secrets: Mapping[str, str], strict: bool
    ) -> _Config:
        cfg, wifi = await self._snapshot()
        for c in changes:
            if c.device_id != self.context.device_id:
                raise AdapterError(f"{c.id}: not a change of {self.context.device_id}")
            layout = await self._layout_of(cfg)
            if c.kind is ChangeKind.ROUTER:
                await self._router(cfg, layout, c)
            elif c.kind is ChangeKind.DHCP:
                self._dhcp(cfg, layout, c)
            elif c.kind is ChangeKind.RESERVATION:
                self._reservation(cfg, layout, c)
            elif c.kind is ChangeKind.PORT:
                self._port(cfg, layout, c)
            elif c.kind is ChangeKind.FIREWALL_RULE:
                fwwrite.firewall_rule(cfg, c, cfg.revert)
            elif c.kind is ChangeKind.ZONE_POLICY:
                fwwrite.zone_policy(cfg, c, cfg.revert)
            elif c.kind is ChangeKind.PORT_FORWARD:
                fwwrite.port_forward(cfg, c, cfg.revert)
            else:
                if not wifi:
                    raise AdapterError(
                        f"SSID {c.key}: only the RouterOS 7 wifi package (/interface/wifi) "
                        "can be changed; the legacy wireless package is read only"
                    )
                await self._wlan(cfg, layout, c, secrets, strict)
        return cfg

    # WritesConfig -----------------------------------------------------------------------------

    async def plan_changes(
        self, changes: list[Change], secrets: Mapping[str, str]
    ) -> list[VendorCall]:
        cfg = await self._plan(changes, secrets, strict=False)
        calls = [op.call() for op in cfg.ops]
        if cfg.revert:
            calls.insert(0, _revert_op(cfg.revert, "<device time + the confirm time>").call())
        return calls

    async def apply(
        self,
        changes: list[Change],
        secrets: Mapping[str, str],
        rollback_seconds: int,
    ) -> ApplyResult:
        """Send the calls. Firewall changes are protected by the revert timer: a scheduler entry
        that undoes them at ``rollback_seconds`` unless ``confirm`` removes it; the other kinds
        have no confirm timer on RouterOS (``safe-mode`` is for interactive terminals only)."""
        cfg = await self._plan(changes, secrets, strict=True)
        ops = list(cfg.ops)
        deadline = None
        if cfg.revert:
            await self._disarm_revert()  # a leftover of an earlier deployment
            when = await self._device_time(rollback_seconds)
            arm = _revert_op(cfg.revert, when)
            deadline = datetime.now(UTC) + timedelta(seconds=rollback_seconds)
            await self._send([arm], secrets)
            ops = [arm, *ops]
        try:
            await self._send(ops[1:] if cfg.revert else ops, secrets)
        except AdapterError:
            if cfg.revert:  # the deployment restores the backup; the timer must not run later
                await self._disarm_revert()
            raise
        return ApplyResult(confirm_deadline=deadline, calls=[op.call() for op in ops])

    async def confirm(self) -> None:
        """Remove the revert timer. Gone already: it ran, and undid the change."""
        if not await self._disarm_revert():
            raise AdapterError(
                "the revert timer of the firewall change is gone: it ran before the change was "
                "confirmed, so the router has the old rules again"
            )

    async def _scheduled(self) -> list[dict[str, Any]]:
        from signalbox.adapters import mikrotik as m

        try:
            rows = m._rows(await m.get_menu(self.http, SCHEDULER), SCHEDULER)
        except NotFound:
            return []
        return [r for r in rows if _text(r.get("name")) == fwwrite.REVERT_NAME]

    async def _disarm_revert(self) -> bool:
        """Delete the revert timer; ``False``: there was none."""
        rows = await self._scheduled()
        for row in rows:
            ref = _text(row.get(".id"))
            response = await self.http.request(
                "DELETE", f"{SCHEDULER}/{ref}", accept=(400, 404, 500)
            )
            if response.status_code >= 400 and response.status_code != 404:
                raise _refused("remove the revert timer", response, lambda t: t)
        return bool(rows)

    async def _device_time(self, seconds: int) -> str:
        """``seconds`` from now by the router's clock, as ``start-date`` and ``start-time``
        of a scheduler entry (``date`` ``time`` in the format the clock uses)."""
        from signalbox.adapters import mikrotik as m

        clock = m._object(await m.get_menu(self.http, m.CLOCK), m.CLOCK)
        day = m.clock_date(clock.get("date"))
        match = re.fullmatch(r"(\d\d?):(\d\d):(\d\d)", _text(clock.get("time")))
        if day is None or match is None:
            raise AdapterError(
                "cannot arm the revert timer: the router's clock is unreadable "
                f"({clock.get('date')!r} {clock.get('time')!r}); firewall changes need it"
            )
        hh, mm, ss = (int(g) for g in match.groups())
        at = datetime(day.year, day.month, day.day, hh, mm, ss) + timedelta(seconds=seconds)
        slashed = "/" in _text(clock.get("date"))
        date = (
            f"{m._MONTHS[at.month - 1]}/{at.day:02d}/{at.year}"
            if slashed
            else at.date().isoformat()
        )
        return f"{date} {at:%H:%M:%S}"

    async def backup(self) -> Backup:
        from signalbox.adapters import mikrotik as m

        menus: dict[str, Any] = {}
        for menu in _menus():
            try:
                menus[menu] = await m.get_menu(self.http, menu)
            except NotFound:
                menus[menu] = None  # package not installed: nothing to restore
        export: str | None
        try:
            response = await self.http.request("POST", EXECUTE, json=EXPORT_SCRIPT)
            export = _export_text(response)
        except Unreachable:
            raise
        except AdapterError:  # only for people; the snapshot is what restore uses
            export = None
        content = json.dumps({"version": 1, "export": export, "menus": menus}, sort_keys=True)
        return Backup(
            device_id=self.context.device_id,
            taken_at=datetime.now(UTC),
            format=BACKUP_FORMAT,
            content=content,
        )

    async def restore(self, backup: Backup) -> None:
        if backup.format != BACKUP_FORMAT:
            raise AdapterError(f"cannot restore a {backup.format!r} backup on RouterOS")
        try:
            saved = json.loads(backup.content)["menus"]
            assert isinstance(saved, dict)
        except (ValueError, KeyError, TypeError, AssertionError):
            raise AdapterError("the backup holds no menu snapshot; it cannot be restored") from None
        await self._disarm_revert()  # the timer must not undo a change that is restored now
        cfg, _ = await self._snapshot()
        order = [m for m in _menus() if isinstance(saved.get(m), list)]
        pairs = {m: _pair(m, saved[m], cfg.static(m)) for m in order}
        for menu in reversed(order):  # removals first, dependants before what they use
            kept = {id(row) for _, row in pairs[menu] if row is not None}
            for row in list(cfg.static(menu)):
                if id(row) not in kept:
                    cfg.delete(menu, row, f"restore: remove {menu} {_label(row)}")
        for menu in order:
            # firewall rows are ordered: add them last to first, each before the one after it
            ordered = list(reversed(pairs[menu])) if menu in _fw_menus() else pairs[menu]
            anchor: str | None = None
            for old, have in ordered:
                want = _writable(menu, old)
                if have is None:
                    if anchor is not None:
                        want = {**want, "place-before": anchor}
                    anchor = str(cfg.put(menu, want, f"restore: add {menu} {_label(old)}")[".id"])
                    continue
                anchor = str(have.get(".id"))
                cfg.patch(menu, have, want, f"restore: set {menu} {_label(old)} back")
                for prop in list(_writable(menu, have)):
                    if prop not in want and prop == "disabled":
                        # RouterOS cannot unset it (the snapshot of a row never had it: false)
                        cfg.patch(menu, have, {prop: "false"}, f"restore: enable {_label(old)}")
                    elif prop not in want:
                        cfg.unset(menu, have, prop, f"restore: unset {prop} of {_label(old)}")
        await self._send(cfg.ops, {})
        self._cache.clear()
        self._layout_cache = None

    # sending ------------------------------------------------------------------------------------

    async def _send(self, ops: list[_Op], secrets: Mapping[str, str]) -> None:
        values = [v for v in secrets.values() if v]

        def scrub(text: str) -> str:
            for v in values:
                text = text.replace(v, "***")
            return text

        ids: dict[str, str] = {}
        for op in ops:
            ref = ids.get(op.ref or "", op.ref)
            body: dict[str, Any] = dict(op.body)
            if "place-before" in body:
                body["place-before"] = ids.get(body["place-before"], body["place-before"])
            if op.method == "POST":
                body["numbers"] = ref
                path = f"{op.menu}/unset"
            elif op.method == "PUT":
                path = op.menu
            else:
                path = f"{op.menu}/{ref}"
            kw: dict[str, Any] = {} if op.method == "DELETE" else {"json": body}
            try:
                response = await self.http.request(op.method, path, accept=(400, 500), **kw)
            except AdapterError as exc:
                raise AdapterError(scrub(f"{op.description}: {exc}")) from None
            if response.status_code >= 400:
                raise _refused(op.description, response, scrub)
            if op.method == "PUT":
                try:
                    created = response.json()
                except ValueError:
                    created = None
                if isinstance(created, list) and len(created) == 1:
                    created = created[0]
                if not isinstance(created, dict) or not _text(created.get(".id")):
                    raise AdapterError(f"{op.description}: the router did not return the new .id")
                ids[str(op.ref)] = _text(created[".id"])
        self._cache.clear()
        self._layout_cache = None
        from signalbox.adapters import mikrotik as m

        touched = {
            ids.get(op.ref or "", op.ref or "")
            for op in ops
            if op.menu == m.DHCP_SERVER and op.method in ("PUT", "PATCH")
        }
        if touched:
            await self._settle_dhcp(touched)

    async def _settle_dhcp(self, ids: set[str]) -> None:
        """Wait until the DHCP servers just written are valid again (RouterOS checks the
        interface's address a moment after the change); the verification judges the rest."""
        from signalbox.adapters import mikrotik as m

        deadline = time.monotonic() + SETTLE_SECONDS
        while True:
            rows = m._rows(await m.get_menu(self.http, m.DHCP_SERVER), m.DHCP_SERVER)
            waiting = [r for r in rows if r.get(".id") in ids and _flag(r.get("invalid"))]
            if not waiting or time.monotonic() > deadline:
                return
            await asyncio.sleep(0.5)

    # ROUTER -------------------------------------------------------------------------------------

    async def _router(self, cfg: _Config, layout: _Layout, c: Change) -> None:
        from signalbox.adapters import mikrotik as m

        new = c.new if isinstance(c.new, RouterValue) else None
        names = [n for n, seg in layout.l3.items() if seg == c.key]
        v4 = [
            r
            for r in cfg.rows(m.IP_ADDRESS)
            if _iface(r) in names and _v4(r) is not None and not _flag(r.get("disabled"))
        ]
        if new is None:
            for r in v4:
                if _flag(r.get("dynamic")):
                    raise AdapterError(
                        f"{c.key}: {r.get('address')} is a dynamic address (DHCP client, ...); "
                        "it cannot be removed"
                    )
                cfg.delete(m.IP_ADDRESS, r, f"remove {r.get('address')} from {_iface(r)}")
            for name in names:
                vlan = next((r for r in cfg.static(m.VLAN) if _text(r.get("name")) == name), None)
                if vlan is None or any(_iface(r) == name for r in cfg.rows(m.IP_ADDRESS)):
                    continue
                old_vid = m._int(vlan.get("vlan-id")) or 0
                parent = _text(vlan.get("interface"))
                cfg.delete(m.VLAN, vlan, f"remove VLAN interface {name}")
                if parent in layout.filtering:
                    self._untag(cfg, parent, parent, old_vid, c.key)
            return
        vid = seg_key(new.vlan)
        if not names:
            if vid is None:
                raise AdapterError(
                    f"{c.key}: the device has no interface for this network; "
                    "only VLAN interfaces are created"
                )
            bridge = self._bridge(cfg, layout, c.key)
            name = f"vlan{vid}"
            if any(_text(r.get("name")) == name for r in cfg.rows(m.INTERFACE) + cfg.rows(m.VLAN)):
                raise AdapterError(f"{c.key}: an interface named {name} exists already")
            body = {"name": name, "vlan-id": str(vid), "interface": bridge}
            if new.name:
                body["comment"] = new.name
            cfg.put(m.VLAN, body, f"create VLAN interface {name} (VLAN {vid}) on {bridge}")
            if bridge in layout.filtering:
                entry = self._entry(cfg, bridge, vid, c.key)
                if entry is None:
                    body = {"bridge": bridge, "vlan-ids": str(vid), "tagged": bridge}
                    if new.name:
                        body["comment"] = new.name
                    cfg.put(m.BRIDGE_VLAN, body, f"VLAN {vid}: tag it on {bridge} itself")
                elif bridge not in _names(entry.get("tagged")):
                    tagged = _join([*_names(entry.get("tagged")), bridge])
                    cfg.patch(
                        m.BRIDGE_VLAN, entry, {"tagged": tagged}, f"VLAN {vid}: tag it on {bridge}"
                    )
            names = [name]
        address = str(new.address)
        static_v4 = [r for r in v4 if not _flag(r.get("dynamic"))]
        if static_v4:
            row = static_v4[0]
            if _v4(row) != new.address:
                cfg.patch(
                    m.IP_ADDRESS, row, {"address": address}, f"set {_iface(row)} to {address}"
                )
        elif v4:
            raise AdapterError(f"{c.key}: the address is dynamic (DHCP client); it cannot be set")
        else:
            cfg.put(
                m.IP_ADDRESS,
                {"address": address, "interface": names[0]},
                f"add {address} to {names[0]}",
            )
        await self._name(cfg, c.key, new.name)

    def _bridge(self, cfg: _Config, layout: _Layout, key: str) -> str:
        from signalbox.adapters import mikrotik as m

        if len(layout.filtering) == 1:
            return next(iter(layout.filtering))
        bridges = [_text(r.get("name")) for r in cfg.rows(m.BRIDGE) if _text(r.get("name"))]
        if not layout.filtering and len(bridges) == 1:
            return bridges[0]
        raise AdapterError(f"{key}: no single bridge to put the VLAN interface on")

    def _entry(self, cfg: _Config, bridge: str, vid: int, key: str) -> dict[str, Any] | None:
        """The static bridge VLAN entry of one VLAN id (refused when it shares an entry)."""
        from signalbox.adapters import mikrotik as m

        for row in cfg.static(m.BRIDGE_VLAN):
            if _text(row.get("bridge")) != bridge:
                continue
            vids = m.vlan_ids(row.get("vlan-ids"))
            if vid in vids:
                if len(vids) > 1:
                    raise AdapterError(
                        f"{key}: VLAN {vid} shares the bridge VLAN entry "
                        f"{row.get('vlan-ids')!r} with other VLANs; split it on the device first"
                    )
                return row
        return None

    def _untag(self, cfg: _Config, bridge: str, port: str, vid: int, key: str) -> None:
        from signalbox.adapters import mikrotik as m

        entry = self._entry(cfg, bridge, vid, key)
        if entry is None or port not in _names(entry.get("tagged")):
            return
        tagged = [p for p in _names(entry.get("tagged")) if p != port]
        if not tagged and not _names(entry.get("untagged")):
            cfg.delete(m.BRIDGE_VLAN, entry, f"VLAN {vid}: remove the bridge VLAN entry")
        else:
            cfg.patch(m.BRIDGE_VLAN, entry, {"tagged": _join(tagged)}, f"VLAN {vid}: untag {port}")

    async def _name(self, cfg: _Config, key: str, name: str | None) -> None:
        """Set the comment the read side takes the segment's name from."""
        from signalbox.adapters import mikrotik as m

        layout = await self._layout_of(cfg)
        seg = layout.segments.get(key)
        if seg is None or seg.name == name:
            return
        vid = seg.vlan or 1
        what = f"name of {key}"
        sources: list[tuple[str, dict[str, Any]]] = []
        for row in cfg.static(m.BRIDGE):
            b = _text(row.get("name"))
            if layout.l3.get(b) == key:
                sources.append((m.BRIDGE, row))
        for row in cfg.static(m.BRIDGE_VLAN):
            single = m.vlan_ids(row.get("vlan-ids")) == [vid]
            if single and _text(row.get("bridge")) in layout.filtering:
                sources.append((m.BRIDGE_VLAN, row))
        for row in cfg.static(m.VLAN):
            if layout.l3.get(_text(row.get("name"))) == key:
                sources.append((m.VLAN, row))
        # The read side takes the first comment in this order: a name goes to the first source
        # only (the others stay as they are, so undoing it leaves the device as it was); no
        # name clears them all.
        for menu, row in sources[:1] if name else sources:
            if name:
                cfg.patch(menu, row, {"comment": name}, f"{what}: {name}")
            else:
                cfg.unset(menu, row, "comment", f"{what}: none")
        after = (await self._layout_of(cfg)).segments.get(key)
        if after is not None and after.name != name:
            raise AdapterError(
                f"{key}: the name cannot be set to {name!r} (RouterOS shows {after.name!r}, "
                "from an entry Signalbox does not change)"
            )

    # DHCP ---------------------------------------------------------------------------------------

    def _servers(self, cfg: _Config, layout: _Layout, key: str) -> list[Any]:
        from signalbox.adapters import mikrotik as m

        return [
            r
            for r in cfg.static(m.DHCP_SERVER)
            if _text(r.get("name")) and layout.l3.get(_text(r.get("interface"))) == key
        ]

    def _own(self, cfg: _Config, layout: _Layout, key: str) -> tuple[str, Any]:
        """The interface of a network and its IPv4 address (for a new DHCP server)."""
        from signalbox.adapters import mikrotik as m

        for row in cfg.rows(m.IP_ADDRESS):
            a = _v4(row)
            if a is not None and layout.l3.get(_iface(row)) == key:
                return _iface(row), a
        raise AdapterError(f"{key}: the device has no IPv4 address in this network for DHCP")

    def _network_row(self, cfg: _Config, a: IPv4Interface) -> Any:
        """The most specific DHCP network holding an address (as the read side picks it)."""
        from signalbox.adapters import mikrotik as m

        best: tuple[int, Any] | None = None
        for row in cfg.rows(m.DHCP_NETWORK):
            try:
                net = ip_interface(_text(row.get("address"))).network
            except ValueError:
                continue
            if a.ip in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, row)
        return best[1] if best else None

    def _dhcp(self, cfg: _Config, layout: _Layout, c: Change) -> None:
        from signalbox.adapters import mikrotik as m

        new = c.new if isinstance(c.new, DhcpValue) else None
        servers = self._servers(cfg, layout, c.key)
        if new is None:
            for srv in servers:
                sname = _text(srv.get("name"))
                cfg.delete(m.DHCP_SERVER, srv, f"remove DHCP server {sname}")
                pname = _text(srv.get("address-pool"))
                used = any(_text(r.get("address-pool")) == pname for r in cfg.rows(m.DHCP_SERVER))
                prow = next((r for r in cfg.static(m.POOL) if _text(r.get("name")) == pname), None)
                if prow is not None and not used:
                    cfg.delete(m.POOL, prow, f"remove address pool {pname}")
                own = [
                    a
                    for r in cfg.rows(m.IP_ADDRESS)
                    if _iface(r) == _text(srv.get("interface")) and (a := _v4(r)) is not None
                ]
                net = self._network_row(cfg, own[0]) if own else None
                exact = net is not None and _text(net.get("address")) == str(own[0].network)
                if (
                    net is not None
                    and exact
                    and not any(
                        _text(r.get("interface")) == _text(srv.get("interface"))
                        for r in cfg.rows(m.DHCP_SERVER)
                    )
                ):
                    cfg.delete(m.DHCP_NETWORK, net, f"remove DHCP network {net.get('address')}")
            return
        iface, own = self._own(cfg, layout, c.key)
        fresh = not servers
        if servers:
            srv = servers[0]
            sname = _text(srv.get("name"))
        else:
            sname = self._free(cfg, m.DHCP_SERVER, f"dhcp-{iface}")
            srv = cfg.put(
                m.DHCP_SERVER,
                {
                    "name": sname,
                    "interface": iface,
                    "address-pool": "static-only",
                    "disabled": _FALSE if new.enabled else _TRUE,
                    **(
                        {"lease-time": ros_duration(new.lease_seconds)}
                        if new.lease_seconds is not None
                        else {}
                    ),
                },
                f"create DHCP server {sname} on {iface}",
            )
        body: dict[str, str] = {"disabled": _FALSE if new.enabled else _TRUE}
        if new.lease_seconds is not None and m.duration(srv.get("lease-time")) != new.lease_seconds:
            body["lease-time"] = ros_duration(new.lease_seconds)
        cfg.patch(m.DHCP_SERVER, srv, body, f"DHCP server {sname}")
        # pool: the first range of the server's pool
        pools = {_text(r.get("name")): r for r in cfg.rows(m.POOL)}
        pool = pools.get(_text(srv.get("address-pool")))
        if new.pool is None:
            if pool is not None:
                cfg.patch(m.DHCP_SERVER, srv, {"address-pool": "static-only"}, f"{sname}: no pool")
        else:
            text = f"{new.pool[0]}-{new.pool[1]}"
            if pool is None:
                same = [
                    r for r in cfg.rows(m.POOL) if _names(r.get("ranges"))[:1] == [text]
                ]  # a pool of exactly this range (one a revert left), else a new one
                pname = (
                    _text(same[0].get("name")) if same else self._free(cfg, m.POOL, f"dhcp-{iface}")
                )
                if not same:
                    cfg.put(m.POOL, {"name": pname, "ranges": text}, f"create address pool {pname}")
                cfg.patch(m.DHCP_SERVER, srv, {"address-pool": pname}, f"{sname}: use {pname}")
            else:
                ranges = _names(pool.get("ranges"))
                current = m._pool(ranges[0]) if ranges else None
                if current is None or (current.start, current.end) != new.pool:
                    cfg.patch(
                        m.POOL,
                        pool,
                        {"ranges": _join([text, *ranges[1:]])},
                        f"address pool {pool.get('name')}: {text}",
                    )
        # network: gateway and DNS servers
        dns = _join([str(a) for a in new.dns or []])
        net = self._network_row(cfg, own)
        if net is None or (fresh and _text(net.get("address")) != str(own.network)):
            body = {"address": str(own.network), "gateway": str(own.ip)}
            if dns:
                body["dns-server"] = dns
            cfg.put(m.DHCP_NETWORK, body, f"create DHCP network {own.network}")
        elif [ip_address(a) for a in _names(net.get("dns-server")) if _is_ip(a)] != list(
            new.dns or []
        ):
            if dns:
                cfg.patch(
                    m.DHCP_NETWORK, net, {"dns-server": dns}, f"DHCP network {own.network}: DNS"
                )
            else:
                cfg.unset(m.DHCP_NETWORK, net, "dns-server", f"DHCP network {own.network}: DNS")

    def _free(self, cfg: _Config, menu: str, base: str) -> str:
        taken = {_text(r.get("name")) for r in cfg.rows(menu)}
        name, n = base, 1
        while name in taken:
            n += 1
            name = f"{base}-{n}"
        return name

    # RESERVATION --------------------------------------------------------------------------------

    def _reservation(self, cfg: _Config, layout: _Layout, c: Change) -> None:
        from signalbox.adapters import mikrotik as m

        sid, mac = c.key.rsplit("/", 1)
        servers = self._servers(cfg, layout, sid)
        if not servers:
            raise AdapterError(f"{c.key}: no DHCP server for {sid} on the device")
        sname = _text(servers[0].get("name"))
        _, own = self._own(cfg, layout, sid)
        rows = []
        for row in cfg.static(m.DHCP_LEASE):
            if _flag(row.get("disabled")) or m._mac(row.get("mac-address")) != mac:
                continue
            server = _text(row.get("server"))
            address = m._addr(row.get("address"))
            if server == sname or (
                server in ("", "all") and address is not None and address in own.network
            ):
                rows.append(row)
        new = c.new if isinstance(c.new, ReservationValue) else None
        if new is None:
            for row in rows:
                cfg.delete(m.DHCP_LEASE, row, f"remove the static lease of {mac}")
            return
        body = {"address": str(new.address), "mac-address": normalise_mac(new.mac).upper()}
        if rows:
            cfg.patch(m.DHCP_LEASE, rows[0], body, f"static lease of {mac}: {new.address}")
            if new.hostname:
                cfg.patch(m.DHCP_LEASE, rows[0], {"comment": new.hostname}, f"{mac}: comment")
            else:
                cfg.unset(m.DHCP_LEASE, rows[0], "comment", f"{mac}: no comment")
            return
        body["server"] = sname
        if new.hostname:
            body["comment"] = new.hostname
        cfg.put(m.DHCP_LEASE, body, f"static lease {new.address} for {mac} on {sname}")

    # PORT ---------------------------------------------------------------------------------------

    def _port(self, cfg: _Config, layout: _Layout, c: Change) -> None:
        from signalbox.adapters import mikrotik as m

        prefix = f"{self.context.device_id}/port/"
        name = c.key[len(prefix) :] if c.key.startswith(prefix) else ""
        if name not in layout.ports:
            raise AdapterError(f"{c.key}: no such port on the device")
        row = next(
            (r for r in cfg.static(m.BRIDGE_PORT) if _text(r.get("interface")) == name), None
        )
        bridge = _text(row.get("bridge")) if row else ""
        if row is None or bridge not in layout.filtering:
            raise AdapterError(
                f"{c.key}: only ports of a bridge with vlan-filtering can be changed "
                f"({name} is {'in ' + bridge if bridge else 'not a bridge port'})"
            )
        new = c.new if isinstance(c.new, PortValue) else PortValue()
        untagged = None if new.untagged is None else (seg_key(new.untagged) or 1)
        tagged = set(new.tagged) - {1}
        if untagged in tagged:
            raise AdapterError(f"{c.key}: VLAN {untagged} cannot be untagged and tagged")
        covered: set[int] = set()
        for entry in list(cfg.static(m.BRIDGE_VLAN)):
            if _text(entry.get("bridge")) != bridge:
                continue
            vids = set(m.vlan_ids(entry.get("vlan-ids")))
            covered |= vids
            t, u = _names(entry.get("tagged")), _names(entry.get("untagged"))
            want_t = bool(vids & tagged)
            if want_t and not vids <= tagged:
                raise AdapterError(
                    f"{c.key}: the bridge VLAN entry {entry.get('vlan-ids')!r} holds several "
                    "VLANs and the port needs only some of them; split it on the device first"
                )
            t2 = [p for p in t if p != name] + ([name] if want_t else [])
            u2 = [p for p in u if p != name or vids == {untagged}]
            if t2 == t and u2 == u:
                continue
            label = f"VLAN {entry.get('vlan-ids')}"
            if not t2 and not u2:
                cfg.delete(m.BRIDGE_VLAN, entry, f"{label}: remove the bridge VLAN entry")
                continue
            body = {}
            if t2 != t:
                body["tagged"] = _join(t2)
            if u2 != u:
                body["untagged"] = _join(u2)
            cfg.patch(
                m.BRIDGE_VLAN,
                entry,
                body,
                f"{label}: {name} " + ("tagged" if want_t else "not tagged"),
            )
        for vid in sorted(tagged - covered):
            cfg.put(
                m.BRIDGE_VLAN,
                {"bridge": bridge, "vlan-ids": str(vid), "tagged": name},
                f"VLAN {vid}: tag {name}",
            )
        frames = _text(row.get("frame-types")) or "admit-all"
        if untagged is None:
            body = {"frame-types": m._TAGGED_ONLY}
        else:
            body = {"pvid": str(untagged)}
            if frames == m._TAGGED_ONLY or (tagged and frames != "admit-all"):
                body["frame-types"] = "admit-all"
        cfg.patch(
            m.BRIDGE_PORT,
            row,
            body,
            f"bridge port {name}: "
            + ("tagged only" if untagged is None else f"untagged VLAN {untagged}"),
        )

    # WLAN ---------------------------------------------------------------------------------------

    async def _wlan(
        self,
        cfg: _Config,
        layout: _Layout,
        c: Change,
        secrets: Mapping[str, str],
        strict: bool,
    ) -> None:
        from signalbox.adapters import mikrotik as m

        profiles = {
            section: {_text(r.get("name")): r for r in cfg.rows(menu)}
            for section, menu in m._WIFI_PROFILES.items()
        }

        def prop(row: dict[str, Any], section: str, key: str) -> Any:
            inline = row.get(f"{section}.{key}")
            if inline not in (None, ""):
                return inline
            return profiles[section].get(_text(row.get(section)), {}).get(key)

        rows = [
            r
            for r in cfg.rows(m.WIFI)
            if _text(prop(r, "configuration", "ssid")) == c.key
            and (_text(prop(r, "configuration", "mode")) or "ap") in m._AP_MODES
        ]
        new = c.new if isinstance(c.new, WlanValue) else None
        if new is None:
            for row in rows:
                if not _text(row.get("master-interface")):
                    raise AdapterError(
                        f"SSID {c.key} is the main SSID of the radio {row.get('name')}; "
                        "it cannot be removed, only disabled"
                    )
                cfg.delete(m.WIFI, row, f"remove the Wi-Fi interface {row.get('name')}")
            return
        if new.client_isolation is not None:
            raise AdapterError(
                f"SSID {c.key}: client isolation is not read or changed on RouterOS yet; "
                "leave client_isolation out of the desired state"
            )
        if new.security not in _SECURITY_TYPES:
            raise AdapterError(
                f"SSID {c.key}: {new.security.value} cannot be set through Signalbox on RouterOS "
                "(only open, OWE and WPA2/WPA3 personal)"
            )
        passphrase: str | None = None
        if new.passphrase_secret:
            passphrase = secrets.get(new.passphrase_secret)
            if passphrase is None:
                if strict:
                    raise AdapterError(
                        f"SSID {c.key}: the secret {new.passphrase_secret!r} was not given"
                    )
                passphrase = "***"
        vid = seg_key(new.segment) or 1
        self._cache.update(cfg.menus)
        try:
            observed = await self._wifi(layout, cfg.rows(m.WIFI))
        finally:
            self._cache.clear()
        radios = [r.name for r in observed.radios]
        if not rows:
            if not radios:
                raise AdapterError(f"SSID {c.key}: the device has no radio")
            if new.security in _PERSONAL and passphrase is None:
                raise AdapterError(f"SSID {c.key}: a new SSID needs a passphrase secret")
            bridge = next(iter(sorted(layout.filtering)), "")
            for radio in radios:
                iname = self._free(cfg, m.WIFI, f"{radio}-{_slug(c.key)}")
                body = {
                    "name": iname,
                    "master-interface": radio,
                    "configuration.mode": "ap",
                    "configuration.ssid": c.key,
                    "disabled": _FALSE if new.enabled else _TRUE,
                }
                if new.hidden:
                    body["configuration.hide-ssid"] = "yes"
                if _SECURITY_TYPES[new.security]:
                    body["security.authentication-types"] = _SECURITY_TYPES[new.security]
                if passphrase is not None and new.security in _PERSONAL:
                    body["security.passphrase"] = passphrase
                if new.pmf is not None:
                    body["security.management-protection"] = _PMF_VALUES[new.pmf]
                for key, value in (
                    ("security.ft", new.roaming_80211r),
                    ("steering.rrm", new.roaming_80211k),
                    ("steering.wnm", new.roaming_80211v),
                ):
                    if value is not None:
                        body[key] = _yes(value)
                if bridge:
                    body["datapath.bridge"] = bridge
                    if vid != 1:
                        body["datapath.vlan-id"] = str(vid)
                elif vid != 1:
                    raise AdapterError(
                        f"SSID {c.key}: VLAN {vid} needs a bridge with vlan-filtering"
                    )
                cfg.put(m.WIFI, body, f"create the Wi-Fi interface {iname} for SSID {c.key}")
            return
        for row in rows:
            iname = _text(row.get("name"))
            what = f"{iname} (SSID {c.key})"
            body = {}
            unset: list[str] = []
            if _flag(row.get("disabled")) == new.enabled:
                body["disabled"] = _FALSE if new.enabled else _TRUE
            if _flag(prop(row, "configuration", "hide-ssid")) != new.hidden:
                body["configuration.hide-ssid"] = _yes(new.hidden)
            types = _SECURITY_TYPES[new.security]
            cur = row  # the entry as it will be (an open SSID loses its security profile)
            if m.security_of(prop(row, "security", "authentication-types")) != new.security:
                if types:
                    body["security.authentication-types"] = types
                else:  # open: no types inline, and no profile to fall back on
                    unset += ["security.authentication-types", "security"]
                    cur = {k: v for k, v in row.items() if k not in unset}
            if new.security in _PERSONAL:
                if passphrase is not None:
                    body["security.passphrase"] = passphrase
                elif (
                    not _text(prop(cur, "security", "passphrase"))
                    and m.security_of(prop(cur, "security", "authentication-types"))
                    not in _PERSONAL
                ):
                    raise AdapterError(f"SSID {c.key}: {new.security.value} needs a passphrase")
            # None: not set (the inverse of setting it); the inline value is cleared
            pmf = m._PMF.get(_text(prop(cur, "security", "management-protection")))
            if new.pmf is None and pmf is not None:
                unset.append("security.management-protection")
            elif new.pmf is not None and pmf != new.pmf:
                body["security.management-protection"] = _PMF_VALUES[new.pmf]
            for section, key, value in (
                ("security", "ft", new.roaming_80211r),
                ("steering", "rrm", new.roaming_80211k),
                ("steering", "wnm", new.roaming_80211v),
            ):
                have = m._maybe(prop(cur, section, key))
                if value is None and have is not None:
                    unset.append(f"{section}.{key}")
                elif value is not None and have != value:
                    body[f"{section}.{key}"] = _yes(value)
            # segment: the pvid of a static bridge port wins; else the datapath VLAN
            port = next(
                (r for r in cfg.static(m.BRIDGE_PORT) if _text(r.get("interface")) == iname), None
            )
            current_vid = m._int(prop(row, "datapath", "vlan-id"))
            if port is not None and _text(port.get("bridge")) in layout.filtering:
                cfg.patch(m.BRIDGE_PORT, port, {"pvid": str(vid)}, f"{what}: VLAN {vid}")
            if (current_vid or 1) != vid:
                if vid == 1:
                    unset.append("datapath.vlan-id")
                else:
                    body["datapath.vlan-id"] = str(vid)
            cfg.patch(m.WIFI, row, body, f"Wi-Fi interface {what}")
            for key in unset:
                cfg.unset(m.WIFI, row, key, f"{what}: unset {key}")


def _revert_op(revert: fwwrite.Revert, when: str) -> _Op:
    """The scheduler entry that runs the revert script at ``when`` (``date time``)."""
    date, _, clock = when.partition(" ")
    body = {
        "name": fwwrite.REVERT_NAME,
        "start-date": date,
        "start-time": clock,
        "interval": "0s",
        "policy": fwwrite.REVERT_POLICY,
        "on-event": revert.script(),
        "comment": "signalbox: undoes the firewall change unless it is confirmed",
    }
    return _Op(
        "PUT", SCHEDULER, "revert-timer", body, "arm the revert timer of the firewall change"
    )


def _iface(row: dict[str, Any]) -> str:
    return _text(row.get("actual-interface")) or _text(row.get("interface"))


def _is_ip(text: str) -> bool:
    try:
        ip_address(text)
    except ValueError:
        return False
    return True


def _label(row: dict[str, Any]) -> str:
    for key in ("name", "address", "vlan-ids", "interface", "mac-address", "comment"):
        if _text(row.get(key)):
            return _text(row.get(key))
    return _text(row.get(".id"))


def _pair(
    menu: str, saved: list[Any], current: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    """Saved entries with the current entry they are now (same ``.id``, else same content).

    An entry that a restore removed and added again has a new ``.id``; matching it by content
    keeps a second restore from doing it all again.
    """
    rows = [r for r in saved if isinstance(r, dict) and not _flag(r.get("dynamic"))]
    by_id = {r.get(".id"): r for r in current}
    out: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    used: set[int] = set()
    for old in rows:
        have = by_id.get(old.get(".id"))
        if have is not None:
            used.add(id(have))
        out.append((old, have))
    for i, (old, have) in enumerate(out):
        if have is None:
            same = next(
                (
                    r
                    for r in current
                    if id(r) not in used and _writable(menu, r) == _writable(menu, old)
                ),
                None,
            )
            if same is not None:
                used.add(id(same))
                out[i] = (old, same)
    return out


def _writable(menu: str, row: dict[str, Any]) -> dict[str, str]:
    from signalbox.adapters import mikrotik as m

    skip = set(_READ_ONLY)
    if menu != m.DHCP_LEASE:
        skip.add("mac-address")  # derived for VLAN, bridge and Wi-Fi interfaces
    return {
        k: v if isinstance(v, str) else json.dumps(v)
        for k, v in row.items()
        if k not in skip and v is not None
    }


def _export_text(response: Any) -> str:
    """The export: ``{"ret": ...}`` (a JSON string or plain text are accepted too)."""
    try:
        data = response.json()
    except ValueError:
        return str(response.text)
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if isinstance(data, dict) and isinstance(data.get("ret"), str):
        return str(data["ret"])
    return data if isinstance(data, str) else json.dumps(data)
