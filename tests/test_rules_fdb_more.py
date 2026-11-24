"""FDB data in the history store, #85 and #112 (#298)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from factories import SITE, T0, client, iface
from signalbox.model import Segment, Subnet, port_id, segment_id
from signalbox.rules.ports import client_port_mismatch
from signalbox.secrets import load_vault
from signalbox.sightings import client_segment
from signalbox.store import Store
from test_rules_fdb_checks import M1, M2, P, base, entry


def test_store_roundtrip_of_fdb_history(tmp_path: Path) -> None:
    s = Store(tmp_path / "db.sqlite", load_vault(tmp_path, env={}))
    s.put_site(SITE)
    s.record_history(base(entry("sw1", "1", M1)), T0)
    s.record_history(base(entry("sw1", "2", M1)), T0 + timedelta(minutes=5))
    h = s.history(T0 + timedelta(minutes=6), 30)
    assert h.fdb[M1].value == port_id("sw1", "2") and len(h.fdb[M1].changes) == 1
    s.close()


def test_client_segment_from_table() -> None:
    n = base(
        entry("sw1", "1", M1, segment_id="home/vlan/20"), clients=[client(M1, segment_id=None)]
    )
    assert client_segment(n, n.clients[0]) == "home/vlan/20"
    assert client_segment(base(entry("sw1", "1", M1)), client(M1, segment_id=None)) is None


def test_mismatch_uses_learned_vlan_and_hidden_switch() -> None:
    lan, iot = segment_id(SITE.id, None), segment_id(SITE.id, 20)
    n = base(
        entry("sw1", "1", M1, segment_id=lan),
        clients=[client(M1, "198.51.100.40", seen_on=P[0])],
    ).model_copy(
        update={
            "segments": [
                Segment(id=lan, site_id=SITE.id, vlan=None),
                Segment(id=iot, site_id=SITE.id, vlan=20),
            ],
            "subnets": [
                Subnet(id="s1", device_id="sw1", segment_id=lan, interface=iface("192.0.2.1/24")),
                Subnet(
                    id="s2", device_id="sw1", segment_id=iot, interface=iface("198.51.100.1/24")
                ),
            ],
        }
    )
    assert len(list(client_port_mismatch.check(n))) == 1
    hidden = n.model_copy(update={"fdb": [*n.fdb, entry("sw1", "1", M2)]})
    assert list(client_port_mismatch.check(hidden)) == []
