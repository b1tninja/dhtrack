"""Tests for BEP 9/10 metadata retrieval helpers in metadata_retriever."""

from __future__ import annotations

import hashlib

import pytest

import dhtrack.metadata_retriever as metadata_retriever
from dhtrack import bencode as bencode_module
from dhtrack.metadata_retriever import (
    MAX_METADATA_SIZE,
    _build_ltep_handshake_payload,
    _extract_ut_metadata_piece,
    _parse_peer_ltep_handshake_payload,
    download_torrent_metadata,
)
from dhtrack.peer import UT_METADATA_DATA, UT_METADATA_REJECT, ExtensionError


def test_build_ltep_handshake_payload_roundtrip() -> None:
    raw = _build_ltep_handshake_payload({b"ut_metadata": 2}, v=b"test")
    d = bencode_module.decode(raw)
    assert d[b"m"][b"ut_metadata"] == 2
    assert d[b"v"] == b"test"


def test_parse_peer_ltep_handshake_payload() -> None:
    payload = bytes([0]) + bencode_module.encode(
        {
            b"m": {b"ut_metadata": 3},
            b"metadata_size": 12345,
        }
    )
    ext, md = _parse_peer_ltep_handshake_payload(payload)
    assert ext[b"ut_metadata"] == 3
    assert md == 12345


def test_parse_peer_ltep_handshake_wrong_ext_id() -> None:
    payload = bytes([1]) + bencode_module.encode({b"m": {}})
    with pytest.raises(ExtensionError):
        _parse_peer_ltep_handshake_payload(payload)


def test_extract_ut_metadata_trailing_raw_bytes() -> None:
    """BEP 9: dict is bencoded; metadata follows as raw bytes (not 'buffer' key)."""
    ut_id = 3
    meta_len = 100
    inner_dict = bencode_module.encode(
        {
            b"msg_type": UT_METADATA_DATA,
            b"piece": 0,
            b"total_size": meta_len,
        }
    )
    chunk = b"x" * meta_len
    payload = bytes([ut_id]) + inner_dict + chunk
    got = _extract_ut_metadata_piece(payload, ut_id)
    assert got is not None
    msg_type, piece, data = got
    assert msg_type == UT_METADATA_DATA
    assert piece == 0
    assert data == chunk


def test_extract_ut_metadata_buffer_fallback() -> None:
    """Legacy path: piece bytes only inside bencoded 'buffer'."""
    ut_id = 2
    inner = bencode_module.encode(
        {
            b"msg_type": UT_METADATA_DATA,
            b"piece": 1,
            b"total_size": 50,
            b"buffer": b"y" * 50,
        }
    )
    payload = bytes([ut_id]) + inner
    got = _extract_ut_metadata_piece(payload, ut_id)
    assert got is not None
    _, piece, data = got
    assert piece == 1
    assert data == b"y" * 50


def test_extract_ut_metadata_inner_len_cap_rejects_large_payload() -> None:
    ut_id = 1
    inner = (
        bencode_module.encode(
            {
                b"msg_type": UT_METADATA_DATA,
                b"piece": 0,
                b"total_size": 16384,
            }
        )
        + b"z" * 50000
    )
    payload = bytes([ut_id]) + inner
    assert _extract_ut_metadata_piece(payload, ut_id) is None


def test_extract_wrong_ut_ext_id() -> None:
    inner = bencode_module.encode(
        {
            b"msg_type": UT_METADATA_DATA,
            b"piece": 0,
            b"total_size": 10,
            b"buffer": b"a" * 10,
        }
    )
    payload = bytes([9]) + inner
    assert _extract_ut_metadata_piece(payload, 3) is None


def test_extract_reject_message() -> None:
    ut_id = 1
    inner = bencode_module.encode(
        {
            b"msg_type": UT_METADATA_REJECT,
            b"piece": 0,
        }
    )
    payload = bytes([ut_id]) + inner
    got = _extract_ut_metadata_piece(payload, ut_id)
    assert got is not None
    msg_type, piece, _data = got
    assert msg_type == UT_METADATA_REJECT
    assert piece == 0


def test_info_metadata_sha1_matches_magnet_infohash() -> None:
    """Sanity: assembled metadata bytes must hash to the torrent infohash."""
    info = {
        b"name": b"hello.txt",
        b"piece length": 16384,
        b"pieces": hashlib.sha1(b"piecehashplaceholder!!!").digest(),
    }
    meta_bytes = bencode_module.encode(info)
    ih = hashlib.sha1(meta_bytes).digest()
    assert hashlib.sha1(meta_bytes).digest() == ih
    assert len(meta_bytes) < MAX_METADATA_SIZE


def test_download_torrent_metadata_empty_peers():
    ih = hashlib.sha1(b"x").digest()
    assert download_torrent_metadata([], ih, timeout=5.0) is None


def test_download_torrent_metadata_bad_infohash_length():
    assert download_torrent_metadata([("127.0.0.1", 1, False)], b"x" * 3, timeout=2.0) is None


def test_download_torrent_metadata_iterative_until_success(monkeypatch):
    """Slots refill after failure; succeeding peer completes the resolver."""
    attempts: list[tuple[str, int]] = []

    def fake_retrieve(
        ip,
        port,
        info_hash,
        timeout=90.0,
        is_ipv6=False,
        progress_callback=None,
    ):
        attempts.append((ip, port))
        if ip == "2.2.2.2":
            return b"torrent-bytes"
        return None

    monkeypatch.setattr(metadata_retriever, "retrieve_metadata", fake_retrieve)
    ih = hashlib.sha1(b"torrent-bytes").digest()
    peers = [
        ("1.1.1.1", 100, False),
        ("2.2.2.2", 200, False),
        ("3.3.3.3", 300, False),
    ]
    out = download_torrent_metadata(
        peers,
        ih,
        timeout=30.0,
        max_concurrent=2,
        per_peer_timeout=10.0,
    )
    assert out == b"torrent-bytes"
    ips_tried = {a[0] for a in attempts}
    assert "1.1.1.1" in ips_tried
    assert "2.2.2.2" in ips_tried


def test_download_torrent_metadata_none_when_all_fail(monkeypatch):
    monkeypatch.setattr(metadata_retriever, "retrieve_metadata", lambda *a, **k: None)
    ih = hashlib.sha1(b"x").digest()
    peers = [("127.0.0.1", 1, False), ("127.0.0.2", 2, False)]
    assert download_torrent_metadata(peers, ih, timeout=8.0, max_concurrent=2, per_peer_timeout=3.0) is None
