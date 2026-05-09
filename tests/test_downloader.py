"""Tests for dhtrack.downloader (DownloadCoordinator)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from dhtrack import bencode
from dhtrack.downloader import DownloadCoordinator, bitfield_has
from dhtrack.storage import TorrentStorage
from dhtrack.torrent import Torrent


def _torrent_from_info(info: dict) -> Torrent:
    meta = {b"info": info}
    raw = bencode.encode(meta)
    return Torrent(bencode.decode(raw))


def test_reconcile_marks_prefilled_pieces_on_disk(tmp_path: Path) -> None:
    piece_len = 64
    total = piece_len * 2
    buf = bytes(range(total))
    digests: list[bytes] = []
    for i in range(0, total, piece_len):
        digests.append(hashlib.sha1(buf[i : i + piece_len]).digest())

    info = {
        b"piece length": piece_len,
        b"pieces": b"".join(digests),
        b"name": b"f.bin",
        b"length": total,
    }
    torrent = _torrent_from_info(info)
    dl = tmp_path / "dl"
    resume_dir = tmp_path / "resume"
    dl.mkdir()
    resume_dir.mkdir()

    st = TorrentStorage(torrent, dl)
    st.ensure_files()
    st.write_at(0, buf[:piece_len])
    st.close()

    coord = DownloadCoordinator(torrent, dl, resume_dir)
    try:
        assert bitfield_has(bytes(coord._completed), 0)
        assert not bitfield_has(bytes(coord._completed), 1)
    finally:
        coord.storage.close()
