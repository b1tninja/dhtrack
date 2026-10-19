"""BEP 51 samples and passive infohashes feed the index, swarms, and watchlist."""

from __future__ import annotations

import os

from dhtrack.dht import DHTNode
from dhtrack.infohash_index import (
    EVIDENCE_BEP51_SAMPLE,
    EVIDENCE_INBOUND_GET_PEERS,
    InfohashIndex,
)


def _node(tmp_path) -> DHTNode:
    return DHTNode(
        node_id=os.urandom(20),
        bind_addr=("127.0.0.1", 0),
        peers_file=str(tmp_path / "peers.dat"),
        persist_node_identity=False,
    )


def test_sample_response_is_stored_and_mirrored(tmp_path) -> None:
    node = _node(tmp_path)
    try:
        peer = node.add_peer(os.urandom(20), "192.0.2.8", 6881)
        assert peer is not None
        first = b"\x11" * 20
        second = b"\x22" * 20
        peer._process_sample_infohashes_response({b"r": {b"samples": first + second, b"num": 2, b"interval": 100}})
        row = node.infohash_index.get(first)
        assert row is not None
        assert row.source == EVIDENCE_BEP51_SAMPLE
        hints = node.endpoint_swarms.snapshot(ip="192.0.2.8", port=6881, is_ipv6=False)
        assert any(h.info_hash_hex == first.hex() for h in hints)
        assert node._sample_next_at[("192.0.2.8", 6881)] > 0
    finally:
        node.close()


def test_poll_respects_interval(tmp_path) -> None:
    node = _node(tmp_path)
    try:
        peer = node.add_peer(os.urandom(20), "192.0.2.9", 6881)
        assert peer is not None
        calls: list[int] = []
        peer.sample_infohashes = lambda: calls.append(1)  # type: ignore[method-assign]
        assert node.poll_sample_infohashes(max_queries=1) == 1
        assert node.poll_sample_infohashes(max_queries=1) == 0
        assert calls == [1]
    finally:
        node.close()


def test_passive_get_peers_is_indexed(tmp_path) -> None:
    node = _node(tmp_path)
    try:
        peer = node.add_peer(os.urandom(20), "192.0.2.4", 6881)
        assert peer is not None
        peer.write = lambda _data: None  # type: ignore[method-assign]
        peer._handle_get_peers = lambda _txid, _args: None  # type: ignore[method-assign]
        info_hash = os.urandom(20)
        peer._handle_query(
            {
                b"y": b"q",
                b"q": b"get_peers",
                b"t": b"ab",
                b"a": {b"id": os.urandom(20), b"info_hash": info_hash},
            }
        )
        row = node.infohash_index.get(info_hash)
        assert row is not None
        assert row.source == EVIDENCE_INBOUND_GET_PEERS
    finally:
        node.close()


def test_watchlist_resolve_calls_retrieve_metadata(tmp_path) -> None:
    node = _node(tmp_path)
    try:
        info_hash = os.urandom(20)
        node.watchlist.watch(info_hash, "keep")
        seen: dict[str, bytes] = {}

        class Manager:
            def retrieve_metadata(self, ih: bytes, **_kwargs: object) -> str:
                seen["ih"] = ih
                return "meta"

        assert node.watchlist.resolve(Manager(), info_hash, timeout=1.0) == "meta"
        assert seen["ih"] == info_hash
    finally:
        node.close()


def test_infohash_index_lru_cap() -> None:
    index = InfohashIndex(max_entries=2)
    index.observe(b"\x01" * 20, source="a")
    index.observe(b"\x02" * 20, source="a")
    index.observe(b"\x03" * 20, source="a")
    assert len(index) == 2
    assert index.get(b"\x01" * 20) is None
    assert index.get(b"\x03" * 20) is not None
