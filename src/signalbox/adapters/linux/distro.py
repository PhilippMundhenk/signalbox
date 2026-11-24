"""Which Linux distribution a device runs, and what installs a tool on it (#302).

Detected from ``/etc/os-release`` (``ID`` and ``ID_LIKE``), never assumed to be Debian. The
package manager and the package names of what the reader needs are a fixed table, so the
commands of the automatic setup, of *Fix it* and of the guide (docs/adapters/linux.md) are the
same text. Only what is installed here is read-side: the tools Signalbox reads through.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The things the reader can use and the setup may offer: id -> (what, the tool it provides).
TOOLS = {
    "nftables": ("nftables (nft, the firewall rules)", "nft"),
    "iproute2": ("iproute2 with JSON output (ip -j, bridge)", "ip"),
    "wireguard": ("wireguard-tools (wg, the VPN status)", "wg"),
    "tracepath": ("tracepath (path traces)", "tracepath"),
}

_PACKAGES = {
    "apt": {
        "nftables": "nftables",
        "iproute2": "iproute2",
        "wireguard": "wireguard-tools",
        "tracepath": "iputils-tracepath",
    },
    "pacman": {
        "nftables": "nftables",
        "iproute2": "iproute2",
        "wireguard": "wireguard-tools",
        "tracepath": "iputils",
    },
    "dnf": {
        "nftables": "nftables",
        "iproute2": "iproute",
        "wireguard": "wireguard-tools",
        "tracepath": "iputils",
    },
    "apk": {
        "nftables": "nftables",
        "iproute2": "iproute2",
        "wireguard": "wireguard-tools",
        "tracepath": "iputils-tracepath",
    },
}

_INSTALL = {
    "apt": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}",
    "pacman": "pacman -S --needed --noconfirm {pkgs}",
    "dnf": "dnf install -y {pkgs}",
    "apk": "apk update && apk add {pkgs}",
}

#: ID (or an ID_LIKE word) -> (family name, package manager).
_FAMILIES = (
    ("arch", "Arch Linux", "pacman"),
    ("archarm", "Arch Linux", "pacman"),
    ("manjaro", "Arch Linux", "pacman"),
    ("debian", "Debian", "apt"),
    ("raspbian", "Debian", "apt"),
    ("ubuntu", "Debian", "apt"),
    ("fedora", "Fedora", "dnf"),
    ("rhel", "Fedora", "dnf"),
    ("centos", "Fedora", "dnf"),
    ("alpine", "Alpine", "apk"),
)


@dataclass(frozen=True)
class Distro:
    id: str = ""
    family: str = ""
    #: ``apt``, ``pacman``, ``dnf``, ``apk``; ``None``: unknown distribution
    manager: str | None = None
    pretty: str = ""

    def package(self, tool: str) -> str | None:
        return _PACKAGES.get(self.manager or "", {}).get(tool)

    def install(self, *tools: str) -> str | None:
        """The shell command that installs the packages of these tools (``None``: unknown)."""
        names = [p for t in tools if (p := self.package(t))]
        template = _INSTALL.get(self.manager or "")
        if not names or template is None:
            return None
        return template.format(pkgs=" ".join(dict.fromkeys(names)))

    def hint(self, tool: str) -> str:
        """For a message: the command to install a tool, or a general sentence."""
        command = self.install(tool)
        return f"as root: {command}" if command else f"install {TOOLS[tool][0]}"


def detect(release: dict[str, str]) -> Distro:
    """From the parsed ``/etc/os-release``: its ``ID`` first, then the words of ``ID_LIKE``."""
    ident = release.get("ID", "").strip().lower()
    words = [ident, *re.split(r"[\s,]+", release.get("ID_LIKE", "").lower())]
    for word in words:
        for key, family, manager in _FAMILIES:
            if word and word == key:
                pretty = release.get("PRETTY_NAME") or release.get("NAME") or family
                return Distro(ident or word, family, manager, pretty)
    return Distro(ident, "", None, release.get("PRETTY_NAME") or release.get("NAME") or "")
