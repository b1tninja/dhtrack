"""GUI-oriented DHT datagram field extraction."""

import os

import pytest

from dhtrack import bencode
from dhtrack.dht import extract_gui_message_info_from_datagram


def _nid() -> bytes:
    return os.urandom(20)


@pytest.fixture
def ih() -> bytes:
    return _nid()


@pytest.fixture
def oid() -> bytes:
    return _nid()


def test_get_peers_query_exposes_info_hash_hex(ih: bytes, oid: bytes) -> None:
    pkt = {
        b"t": b"a1",
        b"y": b"q",
        b"q": b"get_peers",
        b"a": {b"id": oid, b"info_hash": ih},
    }
    info = extract_gui_message_info_from_datagram(bencode.encode(pkt))
    assert info["status"] == "query"
    assert info["q"] == "get_peers"
    assert info["info_hash_hex"] == ih.hex()
    assert info["find_node_target_hex"] == ""


def test_announce_peer_query_exposes_info_hash_hex(ih: bytes, oid: bytes) -> None:
    pkt = {
        b"t": b"z9",
        b"y": b"q",
        b"q": b"announce_peer",
        b"a": {b"id": oid, b"info_hash": ih, b"port": 6882, b"token": b"tok"},
    }
    info = extract_gui_message_info_from_datagram(bencode.encode(pkt))
    assert info["q"] == "announce_peer"
    assert info["info_hash_hex"] == ih.hex()


def test_find_node_query_exposes_target_not_as_swarm(ih: bytes, oid: bytes) -> None:
    target = ih
    pkt = {
        b"t": b"bb",
        b"y": b"q",
        b"q": b"find_node",
        b"a": {b"id": oid, b"target": target},
    }
    info = extract_gui_message_info_from_datagram(bencode.encode(pkt))
    assert info["find_node_target_hex"] == target.hex()
    assert info["info_hash_hex"] == ""


def test_ping_query_no_hashes(oid: bytes) -> None:
    pkt = {b"t": b"c3", b"y": b"q", b"q": b"ping", b"a": {b"id": oid}}
    info = extract_gui_message_info_from_datagram(bencode.encode(pkt))
    assert info["info_hash_hex"] == ""
    assert info["find_node_target_hex"] == ""


def test_response_has_empty_hint_fields(ih: bytes, oid: bytes) -> None:
    pkt = {
        b"t": b"d4",
        b"y": b"r",
        b"r": {b"id": oid},
    }
    info = extract_gui_message_info_from_datagram(bencode.encode(pkt))
    assert info["info_hash_hex"] == ""
    assert info["find_node_target_hex"] == ""
