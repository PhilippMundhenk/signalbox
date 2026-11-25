"""Parsing helpers shared by the IPsec and OpenVPN readers (#153): proposal strings, networks,
gateways. Only algorithm names and addresses; nothing here touches a key.
"""

from __future__ import annotations

import contextlib
import re
from ipaddress import ip_network

from signalbox.model import CryptoProposal, IPNetwork

#: Diffie-Hellman group names of strongSwan, RouterOS and legacy IKE to the IANA group number.
DH_GROUPS = {
    "modp768": 1,
    "modp1024": 2,
    "modp1536": 5,
    "modp2048": 14,
    "modp3072": 15,
    "modp4096": 16,
    "modp6144": 17,
    "modp8192": 18,
    "ecp256": 19,
    "ecp384": 20,
    "ecp521": 21,
    "modp1024s160": 22,
    "modp2048s224": 23,
    "modp2048s256": 24,
    "ecp192": 25,
    "ecp224": 26,
    "curve25519": 31,
    "x25519": 31,
    "curve448": 32,
    "x448": 32,
    "ec2n155": 3,
    "ec2n185": 4,
}
_INTEGRITY = re.compile(r"^(md5|sha1|sha2?(?:256|384|512)?|aesxcbc|aescmac)(?:_\d+)?$")
_ENCRYPTION = re.compile(r"^(aes|3des|des|blowfish|cast|camellia|chacha20|null|serpent|twofish)")


def dh_group(text: str) -> int | None:
    """``modp2048``, ``ecp256``, ``14``, ``group2`` or ``DH2`` to the group number."""
    low = text.strip().lower().replace("_", "")
    if low in DH_GROUPS:
        return DH_GROUPS[low]
    m = re.fullmatch(r"(?:dh|group|modp)?(\d{1,2})", low)
    return int(m.group(1)) if m else None


def proposal(text: str) -> CryptoProposal | None:
    """One strongSwan proposal such as ``aes256-sha256-modp2048`` or ``aes128gcm16-ecp256``
    (``-`` separated, in any order, ``prf`` and ``esn`` parts ignored)."""
    enc = integrity = None
    group: int | None = None
    for part in re.split(r"-", text.strip().lower()):
        if not part or part.startswith(("prf", "esn", "noesn")):
            continue
        if (g := DH_GROUPS.get(part)) is not None:
            group = g
        elif _INTEGRITY.match(part) and "gcm" not in part:
            integrity = part
        elif _ENCRYPTION.match(part) and enc is None:
            enc = part
        elif part.isdigit() and enc is not None and enc.startswith(("aes", "camellia")):
            enc += part  # ``aes-256`` split by the dash
        elif part.isdigit() and 0 < int(part) < 40:
            group = int(part)
    if enc is None and integrity is None and group is None:
        return None
    return CryptoProposal(encryption=enc, integrity=integrity, dh_group=group)


def proposals(text: str) -> list[CryptoProposal]:
    """A comma separated list of proposals."""
    out: list[CryptoProposal] = []
    for part in text.split(","):
        p = proposal(part)
        if p is not None and p not in out:
            out.append(p)
    return out


def parts(encryption: list[str], integrity: list[str], groups: list[str]) -> list[CryptoProposal]:
    """RouterOS lists algorithms per kind, not as combinations: one entry per algorithm, so a
    weak one shows up whatever it is combined with."""
    out = [CryptoProposal(encryption=e.strip().lower()) for e in encryption if e.strip()]
    out += [CryptoProposal(integrity=i.strip().lower()) for i in integrity if i.strip()]
    for g in groups:
        number = dh_group(g)
        if number is not None:
            out.append(CryptoProposal(dh_group=number))
    return out


def networks(text: str) -> list[IPNetwork]:
    """``192.0.2.0/24,198.51.100.0/24`` or space separated; anything else (``dynamic``) is left."""
    out: list[IPNetwork] = []
    for part in re.split(r"[,\s;]+", text.strip()):
        with contextlib.suppress(ValueError):
            n = ip_network(part, strict=False)
            if n not in out:
                out.append(n)
    return out


def gateway(text: str) -> str | None:
    """The remote gateway of a connection: the first address or name; a wildcard is None."""
    first = re.split(r"[,\s]+", text.strip())[0] if text.strip() else ""
    if first.lower() in ("", "any", "%any", "0.0.0.0", "::", "0.0.0.0/0", "::/0"):
        return None
    return first
