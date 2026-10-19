"""Each inbound datagram is bdecoded once, and wire dumps stay off unless DEBUG."""

from __future__ import annotations

import logging
import os

from dhtrack import bencode
from dhtrack.dht import DHTNode


def _node(tmp_path) -> DHTNode:
    return DHTNode(
        node_id=b"\x01" * 20,
        bind_addr=("127.0.0.1", 0),
        peers_file=str(tmp_path / "peers.dat"),
        persist_node_identity=False,
    )


def _ping(tid: bytes = b"\x0a\x0b") -> bytes:
    return bencode.encode(
        {
            b"t": tid,
            b"y": b"q",
            b"q": b"ping",
            b"a": {b"id": b"\x09" * 20},
        }
    )


def test_known_peer_datagram_is_decoded_once(tmp_path, monkeypatch) -> None:
    node = _node(tmp_path)
    calls = {"n": 0}
    real = bencode.decode

    def counting(data):
        calls["n"] += 1
        return real(data)

    monkeypatch.setattr("dhtrack.dht.bencode_module.decode", counting)
    logging.getLogger("dhtrack.wire").setLevel(logging.WARNING)
    try:
        peer = node.add_peer(os.urandom(20), "192.0.2.5", 5)
        assert peer is not None
        peer._process_parsed_message = lambda parsed: None  # type: ignore[method-assign]
        before = calls["n"]
        node._handle_datagram(_ping(), ("192.0.2.5", 5))
        assert calls["n"] - before == 1
    finally:
        node.close()


def test_unknown_krpc_is_admitted_with_one_decode(tmp_path, monkeypatch) -> None:
    node = _node(tmp_path)
    calls = {"n": 0}
    real = bencode.decode

    def counting(data):
        calls["n"] += 1
        return real(data)

    monkeypatch.setattr("dhtrack.dht.bencode_module.decode", counting)
    logging.getLogger("dhtrack.wire").setLevel(logging.WARNING)
    sent: list[bytes] = []

    def _capture_write(self, data: bytes) -> None:
        sent.append(data)

    monkeypatch.setattr("dhtrack.dht.DHTPeer.write", _capture_write)
    try:
        before = calls["n"]
        node._handle_datagram(_ping(), ("192.0.2.50", 6881))
        assert calls["n"] - before == 1
        assert ("192.0.2.50", 6881) in node.peers
        assert sent
    finally:
        node.close()


def test_wire_log_skips_decode_unless_debug(tmp_path, monkeypatch) -> None:
    node = _node(tmp_path)
    calls = {"n": 0}

    def counting(data):
        calls["n"] += 1
        return {b"y": b"q"}

    monkeypatch.setattr("dhtrack.dht.bencode_module.decode", counting)
    wire = logging.getLogger("dhtrack.wire")
    previous = wire.level
    try:
        wire.setLevel(logging.WARNING)
        node._log_datagram("IN", b"de", ("192.0.2.1", 1), False)
        assert calls["n"] == 0
        wire.setLevel(logging.DEBUG)
        node._log_datagram("IN", b"de", ("192.0.2.1", 1), False)
        assert calls["n"] == 1
        node._log_datagram("IN", b"de", ("192.0.2.1", 1), False, parsed={b"y": b"q"})
        assert calls["n"] == 1
    finally:
        wire.setLevel(previous)
        node.close()
