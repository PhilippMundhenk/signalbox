"""A simulated Linux gateway (a Raspberry Pi with Raspberry Pi OS) behind an SSH server (#240).

The device answers the read scripts of :mod:`signalbox.adapters.linux.collect` section by
section from :class:`LinuxSim` (what ``ip -j``, ``ss``, ``df`` ... print, and the files), and
the setup scripts of :mod:`signalbox.adapters.linux.provision` against a small model of the
users, their ``authorized_keys`` and ``/etc/sudoers.d``. Anything else fails with status 127.
Every script received is kept in ``scripts`` (the tests check that nothing that prints a
private key is ever sent). The WireGuard sections are answered only for root or a user with
exactly the sudoers rule of the setup guide.

Sample data uses documentation addresses and locally administered MACs only.

    async with serve_ssh(LinuxSim()) as (port, fingerprint):
        ...
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import json
import re
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from signalbox.adapters.linux.setup import sudoers, sudoers_path
from signalbox.adapters.ssh import host_key_fingerprint

ROOT_PASSWORD = "example-root-password"
ADMIN_USER = "pi"
ADMIN_PASSWORD = "example-admin-password"
NOW = 1795400000  # the simulated clock (2026-11-22)


def wg_key(seed: int) -> str:
    """A well-formed WireGuard public key (32 bytes, base64)."""
    raw = bytes((seed * 7 + i * 13) % 256 for i in range(31)) + b"\x00"
    return base64.b64encode(raw).decode()


GW_KEY = wg_key(1)
PEER_KEY = wg_key(2)  # the other site (OPNsense)
PHONE_KEY = wg_key(3)


def _link(
    index: int, name: str, mac: str | None = None, *, up: bool = True, **extra: Any
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "ifindex": index,
        "ifname": name,
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"] if up else ["BROADCAST", "MULTICAST"],
        "mtu": 1500,
        "operstate": "UP" if up else "DOWN",
        "link_type": "ether",
        "address": mac,
    }
    row.update(extra)
    return row


def default_links() -> list[dict[str, Any]]:
    return [
        {
            "ifindex": 1,
            "ifname": "lo",
            "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "mtu": 65536,
            "operstate": "UNKNOWN",
            "link_type": "loopback",
            "address": "00:00:00:00:00:00",
        },
        _link(2, "eth0", "02:5b:00:00:00:01", parentbus="platform", parentdev="fd580000.ethernet"),
        _link(3, "eth1", "02:5b:00:00:00:02", master="br0", parentbus="usb"),
        _link(
            4,
            "wlan0",
            "02:5b:00:00:00:03",
            master="br0",
            parentbus="mmc",
        ),
        _link(
            5,
            "br0",
            "02:5b:00:00:00:02",
            linkinfo={"info_kind": "bridge", "info_data": {"vlan_filtering": 0, "stp_state": 0}},
        ),
        _link(
            6,
            "eth1.30",
            "02:5b:00:00:00:02",
            link="eth1",
            linkinfo={"info_kind": "vlan", "info_data": {"protocol": "802.1Q", "id": 30}},
        ),
        {
            "ifindex": 7,
            "ifname": "wg0",
            "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"],
            "mtu": 1420,
            "operstate": "UNKNOWN",
            "link_type": "none",
            "linkinfo": {"info_kind": "wireguard"},
        },
    ]


def _addr(name: str, *entries: tuple[str, str, int, bool]) -> dict[str, Any]:
    return {
        "ifname": name,
        "addr_info": [
            {
                "family": fam,
                "local": local,
                "prefixlen": plen,
                "scope": "global" if not local.startswith("fe80") else "link",
                **({"dynamic": True} if dyn else {}),
            }
            for fam, local, plen, dyn in entries
        ],
    }


def default_addresses() -> list[dict[str, Any]]:
    return [
        _addr("lo", ("inet", "127.0.0.1", 8, False)),
        _addr(
            "eth0", ("inet", "198.51.100.2", 24, True), ("inet6", "fe80::5b:ff:fe00:1", 64, False)
        ),
        _addr("br0", ("inet", "192.0.2.1", 25, False), ("inet6", "2001:db8:1::1", 64, False)),
        _addr("eth1.30", ("inet", "192.0.2.129", 26, False)),
        _addr("wg0", ("inet", "203.0.113.250", 30, False)),
    ]


DNSMASQ_CONF = """# Signalbox simulator: LAN and IoT VLAN
interface=br0
interface=eth1.30
listen-address=192.0.2.1
no-resolv
server=203.0.113.53
server=/corp.example/192.0.2.250
domain=home.example
dhcp-authoritative
dhcp-range=set:lan,192.0.2.50,192.0.2.100,255.255.255.128,12h
dhcp-range=set:iot,192.0.2.140,192.0.2.180,255.255.255.192,1h
dhcp-option=tag:lan,option:ntp-server,192.0.2.1
dhcp-option=tag:iot,option:router,192.0.2.129
dhcp-option=tag:lan,option:domain-search,home.example,lab.example
dhcp-option=tag:lan,252,"http://192.0.2.1/wpad.dat"
dhcp-host=02:00:00:00:00:10,192.0.2.10,printer
host-record=nas.home.example,192.0.2.20
address=/router.home.example/192.0.2.1
"""

DNSMASQ_LEASES = f"""{NOW + 3600} 02:00:00:00:00:10 192.0.2.10 printer 01:02:00:00:00:00:10
{NOW + 7200} 02:00:00:00:00:21 192.0.2.61 laptop *
{NOW + 600} 02:00:00:00:00:31 192.0.2.141 sensor *
"""

SSHD_CONFIG = """Include /etc/ssh/sshd_config.d/*.conf
#Port 22
KbdInteractiveAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
"""


def _files(files: dict[str, str], unreadable: tuple[str, ...] = ()) -> str:
    out = [f"@@@ {p}\n{t.rstrip(chr(10))}" for p, t in files.items()]
    out += [f"@@! {p}" for p in unreadable]
    return "\n".join(out) + ("\n" if out else "")


def default_sections() -> dict[str, str]:
    return {
        "os": _files(
            {
                "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian '
                'GNU/Linux"\nVERSION_ID="12"\nID=debian\n',
                "/etc/debian_version": "12.12\n",
            }
        ),
        "hostname": "gateway2\n",
        "kernel": "Linux 6.12.47+rpt-rpi-2712 aarch64\n",
        "model": _files({"/proc/device-tree/model": "Raspberry Pi 5 Model B Rev 1.0\x00"}),
        "link": json.dumps(default_links()) + "\n",
        "addr": json.dumps(default_addresses()) + "\n",
        "route": json.dumps(
            [
                {
                    "dst": "default",
                    "gateway": "198.51.100.1",
                    "dev": "eth0",
                    "protocol": "dhcp",
                    "metric": 100,
                    "flags": [],
                },
                {"dst": "192.0.2.0/25", "dev": "br0", "protocol": "kernel", "scope": "link"},
                {"dst": "198.51.100.128/25", "dev": "wg0", "protocol": "static", "scope": "link"},
            ]
        )
        + "\n",
        "route6": json.dumps(
            [
                {
                    "dst": "default",
                    "gateway": "fe80::1",
                    "dev": "eth0",
                    "protocol": "ra",
                    "metric": 1024,
                }
            ]
        )
        + "\n",
        "sysnet": "eth0 1 0 1000 full\neth1 1 0 1000 full\nwlan0 1 1 - -\nbr0 0 0 - -\n"
        "eth1.30 0 0 1000 full\nwg0 0 0 - -\nlo 0 0 - -\n",
        "bridge-vlan": "",
        "forward": "1\n1\n",
        "uptime": "273906.51 1043262.11\n",
        "loadavg": "0.08 0.12 0.10 1/312 4321\n",
        "meminfo": "MemTotal:        8245136 kB\nMemFree:         6123456 kB\n"
        "MemAvailable:    7012345 kB\n",
        "cpus": "4\n",
        "df": "Filesystem     Type     1-blocks        Used   Available Capacity Mounted on\n"
        "/dev/mmcblk0p2 ext4  62763040768  5242880000 54830080000      9% /\n"
        "tmpfs          tmpfs  4221509632     1052672  4220456960      1% /dev/shm\n"
        "tmpfs          tmpfs   844304384     6291456   838012928      1% /run\n"
        "/dev/mmcblk0p1 vfat    535805952    66060288   469745664     13% /boot/firmware\n",
        "thermal": "cpu-thermal 48250\n",
        "units": "ssh active enabled\nsshd  \ndnsmasq active enabled\nkea-dhcp4-server inactive "
        "not-found\nisc-dhcp-server inactive not-found\nsystemd-networkd inactive disabled\n"
        "AdGuardHome inactive not-found\npihole-FTL inactive not-found\nunbound inactive "
        "not-found\nchrony active enabled\nchronyd active alias\nsystemd-timesyncd inactive "
        "not-found\n",
        "procs": "chronyd\ndnsmasq\nsshd\nsystemd\n",
        "present": "",
        "listen": "udp   UNCONN 0      0        192.0.2.1:53         0.0.0.0:*\n"
        "udp   UNCONN 0      0          0.0.0.0:67         0.0.0.0:*\n"
        "udp   UNCONN 0      0          0.0.0.0:51820      0.0.0.0:*\n"
        "tcp   LISTEN 0      128        0.0.0.0:22         0.0.0.0:*\n"
        "tcp   LISTEN 0      128           [::]:22            [::]:*\n",
        "sshd": _files(
            {
                "/etc/ssh/sshd_config": SSHD_CONFIG,
                "/etc/ssh/sshd_config.d/10-signalbox-sim.conf": "PasswordAuthentication no\n",
            }
        ),
        "resolv": _files({"/etc/resolv.conf": "nameserver 127.0.0.1\nsearch home.example\n"}),
        "dnsmasq": _files({"/etc/dnsmasq.conf": DNSMASQ_CONF}),
        "dnsmasq-leases": _files({"/var/lib/misc/dnsmasq.leases": DNSMASQ_LEASES}),
        "kea": "",
        "kea-leases": "",
        "isc": "",
        "isc-leases": "",
        "networkd": "",
    }


def default_wireguard() -> dict[str, str]:
    return {
        "public-key": f"wg0\t{GW_KEY}\n",
        "listen-port": "wg0\t51820\n",
        "peers": f"wg0\t{PEER_KEY}\nwg0\t{PHONE_KEY}\n",
        "endpoints": f"wg0\t{PEER_KEY}\t203.0.113.1:51820\nwg0\t{PHONE_KEY}\t(none)\n",
        "allowed-ips": f"wg0\t{PEER_KEY}\t203.0.113.249/32 198.51.100.128/25\n"
        f"wg0\t{PHONE_KEY}\t203.0.113.251/32\n",
        "latest-handshakes": f"wg0\t{PEER_KEY}\t{NOW - 42}\nwg0\t{PHONE_KEY}\t0\n",
        "transfer": f"wg0\t{PEER_KEY}\t123456\t654321\nwg0\t{PHONE_KEY}\t0\t0\n",
    }


def default_time() -> dict[str, str]:
    return {
        "clock": f"{NOW}.250000000\n",
        "timedatectl": "Timezone=Europe/Berlin\nLocalRTC=no\nCanNTP=yes\nNTP=yes\n"
        "NTPSynchronized=yes\n",
        "timesync": "",
        "tracking": "CB007101,203.0.113.123,2,1795399990.123,0.000012,-0.000004,0.000020,"
        "-1.234,0.001,0.010,0.012,0.001,64.2,Normal\n",
        "sources": "^,*,203.0.113.123,1,6,377,12,-0.000012,-0.000013,0.000011\n"
        "^,+,203.0.113.124,2,6,377,13,0.000101,0.000099,0.000210\n",
        "timezone": _files({"/etc/timezone": "Europe/Berlin\n"})
        + "/usr/share/zoneinfo/Europe/Berlin\n",
        "chrony": _files(
            {
                "/etc/chrony/chrony.conf": "pool 2.debian.pool.ntp.org iburst\n"
                "server 203.0.113.123 iburst\nallow 192.0.2.0/24\n"
            }
        ),
        "timesyncd": "",
    }


@dataclass
class User:
    password: str | None = None
    keys: list[str] = field(default_factory=list)  # authorized_keys lines
    groups: set[str] = field(default_factory=set)
    #: may use sudo: "nopasswd", "password" or None
    sudo: str | None = None
    system: bool = False


def default_users() -> dict[str, User]:
    return {
        "root": User(password=ROOT_PASSWORD),
        ADMIN_USER: User(password=ADMIN_PASSWORD, groups={"sudo"}, sudo="password"),
    }


@dataclass
class LinuxSim:
    """The device; change its fields between connections."""

    sections: dict[str, str] = field(default_factory=default_sections)
    wireguard: dict[str, str] = field(default_factory=default_wireguard)
    time: dict[str, str] = field(default_factory=default_time)
    users: dict[str, User] = field(default_factory=default_users)
    sudoers_files: dict[str, str] = field(default_factory=dict)
    wg_installed: bool = True
    visudo: bool = True
    scripts: list[str] = field(default_factory=list)
    commands: list[tuple[str, str]] = field(default_factory=list)

    # reading -------------------------------------------------------------------------------

    def wg_allowed(self, user: str) -> bool:
        if user == "root":
            return True
        return self.sudoers_files.get(sudoers_path(user)) == sudoers(user)

    def read(self, user: str, script: str) -> str:
        source = self.sections if script.startswith("# signalbox-read") else self.time
        out: list[str] = []
        for name in re.findall(r"echo @@([a-z0-9-]+)", script):
            if name == "wg-denied":
                continue
            if name == "wg-tool":
                if self.wg_installed and not self.wg_allowed(user):
                    out.append("@@wg-denied")
                out.append(f"@@wg-tool\n{'/usr/bin/wg' if self.wg_installed else 'none'}")
                continue
            if name.startswith("wg-"):
                text = ""
                if self.wg_installed and self.wg_allowed(user):
                    text = self.wireguard.get(name[3:], "")
                out.append(f"@@{name}\n{text.rstrip(chr(10))}" if text else f"@@{name}")
                continue
            text = source.get(name, "")
            out.append(f"@@{name}\n{text.rstrip(chr(10))}" if text else f"@@{name}")
        return "\n".join(out) + "\n"

    # setup -----------------------------------------------------------------------------------

    def run(self, user: str, command: str, stdin: bytes) -> tuple[int, bytes, str]:
        self.commands.append((user, command))
        if command == "sudo -n true":
            return (
                (0, b"", "")
                if self.users[user].sudo == "nopasswd"
                else (
                    1,
                    b"",
                    "sudo: a password is required",
                )
            )
        as_root = user == "root"
        data = stdin
        if command in ("sudo -n sh -s", "sudo -S -p '' sh -s"):
            account = self.users.get(user)
            if account is None or account.sudo is None:
                return 1, b"", f"{user} is not in the sudoers file."
            if command.startswith("sudo -S"):
                line, _, data = stdin.partition(b"\n")
                if account.sudo == "password" and line.decode() != account.password:
                    return 1, b"", "sudo: 1 incorrect password attempt"
            elif account.sudo != "nopasswd":
                return 1, b"", "sudo: a password is required"
            as_root = True
        elif command != "sh -s":
            return 127, b"", f"sh: {command}: not found"
        script = data.decode()
        self.scripts.append(script)
        if script.startswith(("# signalbox-read", "# signalbox-time")):
            return 0, self.read(user, script).encode(), ""
        if not script.startswith("# signalbox-setup:"):
            return 127, b"", "sh: unknown script"
        if not as_root:
            return 1, b"", "Permission denied"
        return self.setup(script)

    def setup(self, script: str) -> tuple[int, bytes, str]:
        step = script.split("\n", 1)[0].split(":", 1)[1].strip()
        values = dict(re.findall(r"^(\w+)='([^']*)'$", script, re.M))
        name = values.get("U", "")
        if step == "inspect":
            account = self.users.get(name)
            out = ["@@user"]
            if account is not None:
                out.append(f"{name}:x:999:999::/home/{name}:/bin/sh")
            out.append("@@groups")
            if account is not None:
                out.append(" ".join(sorted({name, *account.groups})))
            out.append("@@keys")
            if account is not None:
                out += account.keys
            out.append("@@sudoers")
            if sudoers_path(name) in self.sudoers_files:
                out.append(self.sudoers_files[sudoers_path(name)].rstrip("\n"))
            out.append("@@wg")
            if self.wg_installed:
                out.append("/usr/bin/wg")
            out.append("@@end")
            return 0, ("\n".join(out) + "\n").encode(), ""
        if step == "user":
            if name in self.users:
                return 9, b"", f"useradd: user '{name}' already exists"
            self.users[name] = User(system=True)
            return 0, b"", ""
        if step == "key":
            if name not in self.users:
                return 1, b"", f"getent: no user {name}"
            self.users[name].keys = [values["K"]]
            return 0, b"", ""
        if step == "sudoers":
            if not self.visudo:
                return 1, b"", "sh: visudo: not found"
            body = re.search(r"<<'SIGNALBOX'\n(.*?)\nSIGNALBOX\n", script, re.S)
            if body is None:
                return 1, b"", "no rule"
            target = re.search(r"^mv \"\$T\" '([^']+)'$", script, re.M)
            if target is None:
                return 1, b"", "no target"
            self.sudoers_files[target.group(1)] = body.group(1) + "\n"
            return 0, b"", ""
        if step == "remove-sudoers":
            self.sudoers_files.pop(values.get("P", ""), None)
            return 0, b"", ""
        if step == "remove-user":
            self.users.pop(name, None)
            return 0, b"", ""
        return 127, b"", f"unknown step {step}"


class _Server(asyncssh.SSHServer):
    def __init__(self, device: LinuxSim) -> None:
        self.device = device

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        account = self.device.users.get(username)
        return account is not None and account.password is not None and account.password == password

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        account = self.device.users.get(username)
        if account is None:
            return False
        mine = key.export_public_key("openssh").decode().split()[:2]
        return any(line.split()[:2] == mine for line in account.keys)


@asynccontextmanager
async def serve_ssh(device: LinuxSim) -> AsyncIterator[tuple[int, str]]:
    """Serve ``device`` on 127.0.0.1; yields the port and the host key fingerprint."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        user = process.get_extra_info("username")
        command = process.command or ""
        data = await process.stdin.read() if command.endswith("sh -s") else b""
        code, out, err = device.run(user, command, data)
        process.stdout.write(out)
        if err:
            process.stderr.write(err.encode() + b"\n")
        process.exit(code)

    server = await asyncssh.create_server(
        lambda: _Server(device),
        "127.0.0.1",
        0,
        server_host_keys=[key],
        process_factory=handle,
        encoding=None,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port, host_key_fingerprint(key)
    finally:
        server.close()
        await server.wait_closed()


@contextmanager
def serve_ssh_in_thread(device: LinuxSim) -> Iterator[tuple[int, str]]:
    """:func:`serve_ssh` on an event loop of its own (for synchronous tests and the demo)."""
    loop = asyncio.new_event_loop()
    ready: concurrent.futures.Future[tuple[int, str]] = concurrent.futures.Future()
    stop = asyncio.Event()

    async def main() -> None:
        async with serve_ssh(device) as served:
            ready.set_result(served)
            await stop.wait()

    thread = threading.Thread(target=loop.run_until_complete, args=(main(),), daemon=True)
    thread.start()
    try:
        yield ready.result(timeout=10)
    finally:
        loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=10)
        loop.close()
