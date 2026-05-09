"""TorrentManager metainfo persistence and startup scan."""

from __future__ import annotations

import hashlib
from pathlib import Path

from dhtrack import bencode
from dhtrack.swarm import SwarmManager
from dhtrack.torrent import Torrent
from dhtrack.torrent_track import TorrentManager


def _minimal_info_torrent(payload: bytes, piece_len: int = 32) -> tuple[bytes, bytes]:
    n_pieces = (len(payload) + piece_len - 1) // piece_len
    pcs = []
    for i in range(n_pieces):
        chunk = payload[i * piece_len : (i + 1) * piece_len].ljust(piece_len, b"\x00")
        pcs.append(hashlib.sha1(chunk).digest())
    meta = {
        b"info": {
            b"name": b"z.bin",
            b"piece length": piece_len,
            b"length": len(payload),
            b"pieces": b"".join(pcs),
        }
    }
    raw_meta = bencode.encode(meta)
    tor = Torrent(bencode.decode(raw_meta))
    return raw_meta, tor.infohash


def test_save_metadata_full_metainfo_writes_and_roundtrips(tmp_path: Path) -> None:
    payload = b"hello" * 20
    raw_meta, ih = _minimal_info_torrent(payload, piece_len=32)
    sm = SwarmManager()
    tm = TorrentManager(sm, torrent_library_directory=tmp_path / "lib")
    p = tm.save_metadata_blob(ih, raw_meta)
    assert p.is_file()

    sw2 = SwarmManager()
    tm2 = TorrentManager(sw2, torrent_library_directory=tmp_path / "lib")
    assert tm2.load_saved_metainfo_from_disk() >= 1
    sw_row = sw2.get(ih)
    assert sw_row is not None
    assert sw_row.cached_metadata_bytes == p.read_bytes()
    tt = tm2.get(ih)
    assert tt is not None
    assert tt.metadata_path == p.resolve()


def test_save_metadata_ut_metadata_wraps(tmp_path: Path) -> None:
    payload = b"a" * 64
    piece_len = 32
    info = {
        b"name": b"wrap.bin",
        b"piece length": piece_len,
        b"length": len(payload),
        b"pieces": b"".join(
            hashlib.sha1(payload[i : i + piece_len]).digest() for i in range(0, len(payload), piece_len)
        ),
    }
    raw_info = bencode.encode(info)
    ih = hashlib.sha1(raw_info).digest()

    tm = TorrentManager(SwarmManager(), torrent_library_directory=tmp_path / "l")
    p = tm.save_metadata_blob(ih, raw_info)

    decoded = bencode.decode(Path(p).read_bytes())
    assert isinstance(decoded, dict) and (b"info" in decoded or "info" in decoded)


def test_mismatched_filename_skipped_when_embedded_other_hash(tmp_path: Path) -> None:
    """Corrupt stray file stem must not hydrate if bytes yield different info-hash."""

    payload = b"q" * 32
    info = {
        b"name": b"bad.bin",
        b"piece length": 16,
        b"length": len(payload),
        b"pieces": b"".join(
            hashlib.sha1(payload[i : i + 16].ljust(16, b"\x00")).digest() for i in range(0, len(payload), 16)
        ),
    }
    raw_info = bencode.encode(info)
    real_ih = hashlib.sha1(raw_info).digest()
    meta = {b"info": info}
    full = bencode.encode(meta)

    lib = tmp_path / "libcorrupt"
    lib.mkdir(parents=True)
    fake_stem = "a" * 40
    (lib / f"{fake_stem}.torrent").write_bytes(full)

    sw = SwarmManager()
    tm = TorrentManager(sw, torrent_library_directory=lib)
    n = tm.load_saved_metainfo_from_disk()
    assert n == 0
    assert sw.get(real_ih) is None
