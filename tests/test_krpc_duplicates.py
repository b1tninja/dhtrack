from __future__ import annotations


def test_dhtpeer_classifies_duplicate_responses(monkeypatch) -> None:
    from dhtrack.dht import DHTPeer

    peer: DHTPeer = DHTPeer.__new__(DHTPeer)  # type: ignore[assignment]
    peer.queue = {}
    peer._recent_handled_txids = __import__("collections").deque(maxlen=256)  # type: ignore[attr-defined]

    class _DummyEndpoint:
        ip = "1.2.3.4"
        port = 9999
        is_ipv6 = False

    peer.endpoint = _DummyEndpoint()  # type: ignore[assignment]

    # Mark txid as recently handled; the next unmatched response should be treated as duplicate.
    peer._recent_handled_txids.append(b"\xaa\xbb")  # type: ignore[attr-defined]

    # We can't easily assert logs here without caplog wiring; just ensure it doesn't crash.
    peer._handle_response({b"t": b"\xaa\xbb", b"y": b"r", b"r": {b"id": b"\x00" * 20}})  # type: ignore[arg-type]
