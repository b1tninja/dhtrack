from __future__ import annotations

import time

import pytest

from dhtrack.swarm import SwarmManager


def test_upsert_creates_and_selects_first_swarm() -> None:
    mgr = SwarmManager()
    ih = b"\x01" * 20
    sw = mgr.upsert(ih, display_name="test")
    assert sw.info_hash == ih
    assert sw.display_name == "test"
    assert mgr.selected() is sw


def test_upsert_updates_display_name() -> None:
    mgr = SwarmManager()
    ih = b"\x02" * 20
    sw1 = mgr.upsert(ih, display_name="a")
    sw2 = mgr.upsert(ih, display_name="b")
    assert sw1 is sw2
    assert sw2.display_name == "b"


def test_remove_updates_selection() -> None:
    mgr = SwarmManager()
    ih1 = b"\x10" * 20
    ih2 = b"\x11" * 20
    sw1 = mgr.upsert(ih1)
    sw2 = mgr.upsert(ih2)
    mgr.select(ih1)
    assert mgr.selected() is sw1
    mgr.remove(ih1)
    assert mgr.selected() is sw2


def test_update_snapshots_updates_counters_and_last_updated() -> None:
    mgr = SwarmManager()
    ih = b"\x03" * 20
    sw = mgr.upsert(ih)
    assert sw.peers_found == 0
    assert sw.last_updated == 0.0

    mgr.update_swarm_peers(ih, [{"ip": "1.2.3.4", "port": 1}])
    assert sw.peers_found == 1
    assert sw.last_updated > 0.0

    lu = sw.last_updated
    time.sleep(0.01)
    mgr.update_dht_nodes(ih, [{"ip": "5.6.7.8", "port": 2, "node_id": b"x" * 20}])
    assert sw.last_updated >= lu


def test_invalid_infohash_length_rejected() -> None:
    mgr = SwarmManager()
    with pytest.raises(ValueError):
        mgr.upsert(b"\x00" * 10)
