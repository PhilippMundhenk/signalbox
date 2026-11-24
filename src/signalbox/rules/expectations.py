"""Checks of what the user said a client should be (#84, #85; expectations of #186).

A client's annotation can name the network it belongs in (``expected.segment``) and what kind of
thing it is (``expected.category``). The vendor database that would guess a category from the
MAC address does not exist yet, so only declared categories are used.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from signalbox.model import (
    Client,
    ClientCategory,
    Network,
    PurposeSource,
    SegmentPurpose,
    client_target,
)
from signalbox.rules import Result, Rule, Severity, found, rule
from signalbox.rules._names import segment_name

#: Categories that belong in an IoT network, and those that do not.
IOT_CATEGORIES = frozenset({ClientCategory.IOT, ClientCategory.CAMERA})
USER_CATEGORIES = frozenset(
    {ClientCategory.COMPUTER, ClientCategory.PHONE, ClientCategory.TABLET, ClientCategory.SERVER}
)


def _name(client: Client) -> str:
    return f"{client.hostname} ({client.mac})" if client.hostname else client.mac


@rule(
    "clients.unexpected-network",
    "Client is not in the network it belongs in",
    Severity.INFO,
    "You said which network a device belongs in (its annotation), and it is seen in another "
    "one: it joined the wrong SSID or sits on a port with the wrong VLAN. Only clients with a "
    "known network are checked.",
)
def unexpected_network(net: Network) -> Iterator[Result]:
    for client in net.clients:
        want = net.expected(client_target(client.mac)).segment
        if want is None or client.segment_id is None or client.segment_id == want:
            continue
        yield found(
            f"{_name(client)} is on {segment_name(net, client.segment_id)} but belongs in "
            f"{segment_name(net, want)}",
            [client.id, client.segment_id, want],
            fix="Check the SSID it joined, or the switch port it is plugged into and that "
            "port's VLAN. If it belongs where it is now, change the expected network of the "
            "device.",
            mid="clients.wrongNetwork",
            fix_id="clients.wrongNetwork.fix",
            params={
                "client": _name(client),
                "segment": segment_name(net, client.segment_id),
                "expected": segment_name(net, want),
            },
        )


def _iot_networks(net: Network) -> dict[str, set[str]]:
    """Per site, the networks that are known (not merely guessed) to be IoT networks."""
    out: dict[str, set[str]] = defaultdict(set)
    for seg in net.segments:
        if seg.purpose is SegmentPurpose.IOT and seg.purpose_source is not PurposeSource.HEURISTIC:
            out[seg.site_id].add(seg.id)
    return out


@rule(
    "clients.category-network",
    "IoT device on the main network, or a computer in the IoT network",
    Severity.INFO,
    "The point of an IoT network is that cheap, rarely updated devices cannot reach the "
    "computers and the NAS. One camera left on the main network defeats it, and nobody "
    "notices because it works. The kind of each device comes from its annotation "
    "(category); a device with an expected network is checked by clients.unexpected-network "
    "instead. Needs an IoT network whose purpose is declared or reported, not guessed.",
)
def category_network(net: Network) -> Iterator[Result]:
    iot = _iot_networks(net)
    stray: dict[tuple[str, str], list[Client]] = defaultdict(list)
    misplaced: dict[str, list[Client]] = defaultdict(list)
    for client in net.clients:
        exp = net.expected(client_target(client.mac))
        seg = net.segment(client.segment_id) if client.segment_id else None
        if exp.category is None or exp.segment is not None or seg is None:
            continue
        networks = iot.get(seg.site_id)
        if not networks:
            continue
        if seg.id in networks:
            if exp.category in USER_CATEGORIES:
                misplaced[seg.id].append(client)
        elif exp.category in IOT_CATEGORIES and seg.purpose not in (
            SegmentPurpose.GUEST,
            SegmentPurpose.CAMERAS,
        ):
            stray[(seg.id, seg.site_id)].append(client)
    for (seg_id, site), clients in sorted(stray.items()):
        target = segment_name(net, sorted(iot[site])[0])
        yield found(
            f"{len(clients)} IoT device{'s' if len(clients) > 1 else ''} "
            f"({', '.join(_name(c) for c in clients)}) "
            f"{'are' if len(clients) > 1 else 'is'} on {segment_name(net, seg_id)} although "
            f"{target} exists",
            [c.id for c in clients],
            fix=f"Move them to the IoT Wi-Fi or port ({target}), or change their category.",
            key=f"iot-outside:{seg_id}",
            mid="clients.iotOutside",
            fix_id="clients.iotOutside.fix",
            params={
                "count": len(clients),
                "clients": ", ".join(_name(c) for c in clients),
                "segment": segment_name(net, seg_id),
                "target": target,
            },
        )
    for seg_id, clients in sorted(misplaced.items()):
        yield found(
            f"{len(clients)} computer{'s' if len(clients) > 1 else ''}, phone"
            f"{'s' if len(clients) > 1 else ''} or server{'s' if len(clients) > 1 else ''} "
            f"({', '.join(_name(c) for c in clients)}) "
            f"{'are' if len(clients) > 1 else 'is'} in the IoT network "
            f"{segment_name(net, seg_id)}",
            [c.id for c in clients],
            fix="Move them to the main network: the IoT network is for devices you do not "
            "trust, and they should not share it with your own.",
            key=f"user-in-iot:{seg_id}",
            mid="clients.userInIot",
            fix_id="clients.userInIot.fix",
            params={
                "count": len(clients),
                "clients": ", ".join(_name(c) for c in clients),
                "segment": segment_name(net, seg_id),
            },
        )


RULES: list[Rule] = [unexpected_network, category_network]
