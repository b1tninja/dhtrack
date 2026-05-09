"""TorrentStorage mmap paths, multi-file layouts, BEP-47 padding skips."""

from __future__ import annotations

import hashlib
from pathlib import Path

from dhtrack import bencode
from dhtrack.storage import TorrentStorage, total_length
from dhtrack.torrent import Torrent


def _torrent_from_info(info: dict) -> Torrent:
    meta = {b"info": info}
    raw = bencode.encode(meta)
    return Torrent(bencode.decode(raw))


def test_two_material_files_cross_write_read(tmp_path: Path) -> None:
    piece_len = 512
    a = b"a" * 300
    b = b"b" * 700
    buf = bytearray(len(a) + len(b))
    buf[: len(a)] = a
    buf[len(a) :] = b
    pieces = []
    for i in range(0, len(buf), piece_len):
        slice_ = buf[i : i + piece_len].ljust(piece_len, b"\x00")
        pieces.append(hashlib.sha1(bytes(slice_)).digest())
    info = {
        b"piece length": piece_len,
        b"pieces": b"".join(pieces),
        b"files": [
            {b"path": [b"small.bin"], b"length": len(a)},
            {b"path": [b"large.bin"], b"length": len(b)},
        ],
    }
    t = _torrent_from_info(info)
    assert total_length(t) == len(buf)

    st = TorrentStorage(t, tmp_path)
    st.ensure_files()
    offset = 200
    st.write_at(offset, b"XY")
    blob = st.read_at(offset - 2, 6)
    assert blob[2:4] == b"XY"

    st.close()


def test_bep47_padding_no_disk_file_zeros_in_layout(tmp_path: Path) -> None:
    piece_len = 256
    head = b"c" * 80
    pad_len = piece_len - (len(head) % piece_len)  # pad to boundary
    assert len(head) + pad_len == piece_len
    tail = b"d" * 400
    full = head + bytes(pad_len) + tail

    pieces = []
    for i in range(0, len(full), piece_len):
        chunk = full[i : i + piece_len]
        chunk = chunk.ljust(piece_len, b"\x00")
        pieces.append(hashlib.sha1(chunk).digest())

    info = {
        b"piece length": piece_len,
        b"pieces": b"".join(pieces),
        b"name": b"collection",
        b"files": [
            {
                b"path": [b"head.bin"],
                b"length": len(head),
            },
            {
                b"path": [b".pad", str(pad_len).encode("ascii")],
                b"length": pad_len,
                b"attr": b"p",
            },
            {
                b"path": [b"tail.bin"],
                b"length": len(tail),
            },
        ],
    }
    t = _torrent_from_info(info)
    st = TorrentStorage(t, tmp_path)
    st.ensure_files()

    pad_disk = tmp_path / ".pad" / str(pad_len)
    assert not pad_disk.exists(), "padding must not allocate on disk"

    st.write_at(0, head)
    st.write_at(piece_len, tail)

    rd_all = st.read_at(0, len(full))
    assert rd_all == full

    st.close()


def test_storage_close_prevents_writes(tmp_path: Path) -> None:
    payload = b"q" * 2000
    piece_len = 1024
    pieces = []
    for i in range(0, len(payload), piece_len):
        pieces.append(hashlib.sha1(payload[i : i + piece_len].ljust(piece_len, b"\x00")).digest())
    meta = {
        b"info": {
            b"name": b"z.bin",
            b"piece length": piece_len,
            b"length": len(payload),
            b"pieces": b"".join(pieces),
        }
    }
    t = Torrent(bencode.decode(bencode.encode(meta)))

    st = TorrentStorage(t, tmp_path)
    st.ensure_files()
    st.close()
    try:
        st.write_at(0, b"xx")
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "closed" in str(e).lower()
