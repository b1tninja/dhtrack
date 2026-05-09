from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from dhtrack import bencode
from dhtrack.downloader import BLOCK_LEN
from dhtrack.peer import MSG_PIECE, MSG_REQUEST, serialize_peer_message
from dhtrack.storage import TorrentStorage, piece_hashes, total_length
from dhtrack.torrent import Torrent


def _make_single_file_torrent(piece_len: int, payload: bytes) -> Torrent:
    pieces = []
    for i in range(0, len(payload), piece_len):
        pieces.append(hashlib.sha1(payload[i : i + piece_len]).digest())
    meta = {
        b"info": {
            b"name": b"file.bin",
            b"piece length": piece_len,
            b"length": len(payload),
            b"pieces": b"".join(pieces),
        }
    }
    return Torrent(bencode.decode(bencode.encode(meta)))


def test_serialize_request_message() -> None:
    payload = struct.pack("!III", 7, 16384, 4096)
    msg = serialize_peer_message(MSG_REQUEST, payload)
    # length prefix includes id byte
    assert msg[:4] == struct.pack("!I", 1 + len(payload))
    assert msg[4] == MSG_REQUEST
    assert msg[5:] == payload


def test_serialize_piece_message() -> None:
    block = b"x" * min(BLOCK_LEN, 1024)
    payload = struct.pack("!II", 3, 0) + block
    msg = serialize_peer_message(MSG_PIECE, payload)
    assert msg[:4] == struct.pack("!I", 1 + len(payload))
    assert msg[4] == MSG_PIECE
    assert msg[5:] == payload


def test_storage_single_file_write_read(tmp_path: Path) -> None:
    data = b"hello world" * 1000
    t = _make_single_file_torrent(piece_len=1024, payload=data)
    assert total_length(t) == len(data)
    hs = piece_hashes(t)
    assert len(hs) == (len(data) + 1023) // 1024

    st = TorrentStorage(t, tmp_path)
    st.ensure_files()
    st.write_at(10, b"ABCDEF")
    got = st.read_at(8, 10)
    assert got[2:8] == b"ABCDEF"
    st.close()
