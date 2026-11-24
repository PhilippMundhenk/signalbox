"""A service on the address of another device (#387): derived in the merge, declared in the
device settings, drawn inside the host's box by the topology view."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from factories import SITE, device, port, snapshot
from signalbox.adapters import AdapterConfig
from signalbox.merge import merge
from signalbox.model import DeviceRole, DeviceStatus, Network, Snapshot
from signalbox.secrets import load_vault
from signalbox.store import DeviceRecord, Store
from signalbox.topology import view


def host(dev: str = "gw", address: str = "192.0.2.1") -> Snapshot:
    return snapshot(device(dev, management_address=address), ports=[port(dev, "lan1")])


def service(dev: str, address: str, port_number: int | None = 3000, **kw: object) -> Snapshot:
    d = device(
        dev,
        DeviceRole.OTHER,
        management_address=address,
        management_port=port_number,
        **kw,
    )
    return snapshot(d)


def hosted(net: Network) -> dict[str, str | None]:
    return {d.id: d.hosted_on for d in net.devices}


def test_a_service_at_the_address_of_a_device_with_ports_runs_on_it() -> None:
    net = merge([SITE], [host(), service("dns", "192.0.2.1")])
    assert hosted(net) == {"gw": None, "dns": "gw"}
    assert [d.id for d in net.hosted_here("gw")] == ["dns"]


def test_the_address_is_compared_as_an_address() -> None:
    net = merge([SITE], [host(address="2001:db8::1"), service("dns", "[2001:0db8:0::1]")])
    assert hosted(net)["dns"] == "gw"


def test_the_same_port_is_the_same_device() -> None:
    gw = host()
    gw = gw.model_copy(update={"device": gw.device.model_copy(update={"management_port": 3000})})
    net = merge([SITE], [gw, service("dns", "192.0.2.1", 3000)])
    assert hosted(net)["dns"] is None


def test_two_devices_with_ports_are_not_hosted_on_each_other() -> None:
    net = merge([SITE], [host("a"), host("b")])
    assert hosted(net) == {"a": None, "b": None}


def test_a_service_between_two_possible_hosts_is_left_alone() -> None:
    net = merge([SITE], [host("a"), host("b"), service("dns", "192.0.2.1")])
    assert hosted(net)["dns"] is None


def test_other_addresses_and_unknown_addresses_are_not_hosted() -> None:
    other = service("dns", "192.0.2.9")
    unknown = snapshot(device("odd", DeviceRole.OTHER))
    net = merge([SITE], [host(), other, unknown])
    assert hosted(net) == {"gw": None, "dns": None, "odd": None}


def test_a_declared_host_wins_and_a_wrong_one_is_ignored() -> None:
    snaps = [host(), service("dns", "192.0.2.77"), service("other", "192.0.2.78")]
    net = merge([SITE], snaps, hosted_on={"dns": "gw", "other": "missing"})
    assert hosted(net) == {"gw": None, "dns": "gw", "other": None}
    # a device is never its own host, and a host is not hosted itself
    net = merge([SITE], snaps, hosted_on={"gw": "dns", "dns": "gw"})
    assert hosted(net) == {"gw": None, "dns": "gw", "other": None}
    net = merge([SITE], snaps, hosted_on={"dns": "dns"})
    assert hosted(net)["dns"] is None


def test_the_view_has_the_service_in_the_box_of_its_host_and_not_as_a_node() -> None:
    dns = service("dns", "192.0.2.1", name="DNS filter", model="AdGuard Home")
    dns = dns.model_copy(update={"status": DeviceStatus.PARTIAL})
    net = merge([SITE], [host(), dns])
    shown = view(net)
    assert [n["id"] for n in shown["nodes"]] == ["gw"]
    assert shown["nodes"][0]["hosted"] == [
        {
            "id": "dns",
            "name": "DNS filter",
            "role": "other",
            "kind": "AdGuard Home",
            "port": 3000,
            "status": "partial",
        }
    ]


def test_a_hosted_device_with_ports_of_its_own_stays_a_box() -> None:
    both = snapshot(device("srv", DeviceRole.OTHER), ports=[port("srv", "eth0")])
    net = merge([SITE], [host(), both], hosted_on={"srv": "gw"})
    shown = view(net)
    assert [n["id"] for n in shown["nodes"]] == ["gw", "srv"]
    assert shown["nodes"][0]["hosted"] == []


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    yield s
    s.close()


def test_the_store_keeps_the_declared_host(store: Store) -> None:
    rec = DeviceRecord(
        id="dns", site_id=SITE.id, name="DNS", role=DeviceRole.OTHER, adapter="x", hosted_on="gw"
    )
    assert store.put_device(rec, {}, AdapterConfig).hosted_on == "gw"
    again = store.put_device(rec.model_copy(update={"hosted_on": None}), {}, AdapterConfig)
    assert again.hosted_on is None
    assert store.device("dns") == again
