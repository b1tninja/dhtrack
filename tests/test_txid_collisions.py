from __future__ import annotations

import os


def test_krpc_txid_allocation_avoids_pending_collision(monkeypatch) -> None:
    # Import inside test so monkeypatch applies cleanly.
    from dhtrack.dht import DHTPeer

    # Create a minimal DHTPeer without running networking.
    peer: DHTPeer = DHTPeer.__new__(DHTPeer)  # type: ignore[assignment]
    peer.queue = {}

    class _DummyNode:
        node_id = b"\x00" * 20

        def _record_query_sent(self) -> None:
            return None

    class _DummyEndpoint:
        ip = "127.0.0.1"
        port = 1
        is_ipv6 = False

    peer.dht_node = _DummyNode()  # type: ignore[assignment]
    peer.endpoint = _DummyEndpoint()  # type: ignore[assignment]

    # Stub write so query() doesn't try to send anything.
    peer.write = lambda _data: None  # type: ignore[method-assign]

    # Force os.urandom(2) to always return the same value so we'd collide unless we probe.
    monkeypatch.setattr(os, "urandom", lambda n: b"\x12\x34" if n == 2 else b"\x00" * n)

    # Pre-seed the pending queue with the "random" txid.
    peer.queue[b"\x12\x34"] = object()  # type: ignore[assignment]

    txid = peer.query("ping")
    assert txid != b"\x12\x34"
    assert txid in peer.queue
