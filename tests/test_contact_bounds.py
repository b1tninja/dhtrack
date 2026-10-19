"""Contact-table cap and closest-k candidate selection.

The live table is capped by ``MAX_PEER_TABLE`` (8192), the limit added with
KRPC-validated admission. Closest-k does not walk every contact.
"""

from __future__ import annotations

import os

import pytest

from dhtrack.dht import MAX_PEER_TABLE, DHTNode


def _node(tmp_path) -> DHTNode:
    return DHTNode(
        node_id=os.urandom(20),
        bind_addr=("127.0.0.1", 0),
        peers_file=str(tmp_path / "peers.dat"),
        persist_node_identity=False,
    )


def test_peer_table_cap_constant_is_the_admission_cap() -> None:
    assert MAX_PEER_TABLE == 8192


def test_evicts_oldest_unbucketed_contact(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import dhtrack.dht as dht_module

    monkeypatch.setattr(dht_module, "MAX_PEER_TABLE", 2)
    node = _node(tmp_path)
    try:
        node.add_peer(None, "192.0.2.1", 1, last_contacted=1.0)
        node.add_peer(None, "192.0.2.2", 2, last_contacted=5.0)
        node.add_peer(None, "192.0.2.3", 3, last_contacted=9.0)
        assert len(node.peers) == 2
        assert ("192.0.2.1", 1) not in node.peers
        assert ("192.0.2.3", 3) in node.peers
    finally:
        node.close()


def test_evicts_empty_queue_before_a_busy_contact(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import dhtrack.dht as dht_module

    monkeypatch.setattr(dht_module, "MAX_PEER_TABLE", 2)
    node = _node(tmp_path)
    try:
        busy = node.add_peer(None, "192.0.2.1", 1, last_contacted=1.0)
        assert busy is not None
        busy.queue[b"aa"] = object()
        node.add_peer(None, "192.0.2.2", 2, last_contacted=50.0)
        node.add_peer(None, "192.0.2.3", 3, last_contacted=60.0)
        assert ("192.0.2.1", 1) in node.peers
        assert ("192.0.2.2", 2) not in node.peers
        assert len(node.peers) == 2
    finally:
        node.close()


def test_routing_table_contact_survives_a_stray_insert(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import dhtrack.dht as dht_module

    monkeypatch.setattr(dht_module, "MAX_PEER_TABLE", 2)
    node = _node(tmp_path)
    try:
        routed = node.add_peer(b"\x11" * 20, "192.0.2.10", 10, last_contacted=1.0)
        assert routed is not None and routed.in_routing_table
        node.add_peer(None, "192.0.2.11", 11, last_contacted=100.0)
        node.add_peer(b"\x13" * 20, "192.0.2.12", 12, last_contacted=200.0)
        assert len(node.peers) == 2
        assert ("192.0.2.11", 11) not in node.peers
        assert ("192.0.2.10", 10) in node.peers
    finally:
        node.close()


def test_closest_k_uses_buckets_not_every_contact(tmp_path) -> None:
    node = _node(tmp_path)
    try:
        far = b"\xff" * 20
        close = b"\x00" * 19 + b"\x01"
        assert node.add_peer(far, "192.0.2.2", 2) is not None
        stuffed = node.add_peer(close, "192.0.2.1", 1)
        assert stuffed is not None
        node.routing_table.remove_node(node_id=close, endpoint=stuffed.endpoint)
        node._lookup_overflow.pop(close, None)
        stuffed.in_routing_table = False

        ids = [c.node_id for c in node.iter_query_candidates(b"\x00" * 20, 8)]
        assert close not in ids
        assert far in ids
    finally:
        node.close()
