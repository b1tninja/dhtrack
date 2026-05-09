from __future__ import annotations

import mmap
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dhtrack import bep47
from dhtrack.torrent import Torrent


def _normalize_file_entry_for_bep47(entry: dict) -> dict[bytes, Any]:
    """Bytes-key view of a file entry for :func:`bep47.is_padding_file`."""
    out: dict[bytes, Any] = {}
    for k, v in entry.items():
        bk = k if isinstance(k, bytes) else str(k).encode("utf-8", "replace")
        if bk == b"path":
            if not isinstance(v, list):
                continue
            comp: list[bytes] = []
            for p in v:
                if isinstance(p, bytes):
                    comp.append(p)
                else:
                    comp.append(str(p).encode("utf-8", "replace"))
            out[b"path"] = comp
            continue
        if bk == b"length":
            if isinstance(v, int):
                out[b"length"] = v
            continue
        if bk == b"attr":
            if isinstance(v, bytes):
                out[b"attr"] = v
            elif isinstance(v, str):
                out[b"attr"] = v.encode("ascii", "replace")
            continue
    return out


def _torrent_files(t: Torrent) -> list[tuple[Path, int]]:
    """Return list of (relative_path, length) for single or multi-file torrents."""
    info = t.info
    if not isinstance(info, dict):
        raise ValueError("torrent has no info dict")

    files = info.get("files", info.get(b"files"))
    if isinstance(files, list) and files:
        out: list[tuple[Path, int]] = []
        for entry in files:
            if not isinstance(entry, dict):
                continue
            length = entry.get("length", entry.get(b"length", 0))
            path_list = entry.get("path", entry.get(b"path"))
            if not isinstance(length, int) or length < 0 or not isinstance(path_list, list) or not path_list:
                continue
            parts = []
            for p in path_list:
                if isinstance(p, bytes):
                    parts.append(p.decode("utf-8", "replace"))
                else:
                    parts.append(str(p))
            out.append((Path(*parts), int(length)))
        return out

    # single-file
    name = info.get("name", info.get(b"name"))
    if isinstance(name, bytes):
        name_s = name.decode("utf-8", "replace")
    else:
        name_s = str(name or "download.bin")
    length = info.get("length", info.get(b"length", 0))
    if not isinstance(length, int) or length < 0:
        raise ValueError("invalid torrent length")
    return [(Path(name_s), int(length))]


def total_length(t: Torrent) -> int:
    return sum(length for _p, length in _torrent_files(t))


def torrent_files(t: Torrent) -> list[tuple[Path, int]]:
    """Relative paths and byte lengths for all payload files."""
    return list(_torrent_files(t))


def piece_hashes(t: Torrent) -> list[bytes]:
    info = t.info
    if not isinstance(info, dict):
        return []
    pieces = info.get("pieces", info.get(b"pieces"))
    if not isinstance(pieces, (bytes, bytearray)):
        return []
    pieces_b = bytes(pieces)
    if len(pieces_b) % 20 != 0:
        return []
    return [pieces_b[i : i + 20] for i in range(0, len(pieces_b), 20)]


@dataclass(frozen=True)
class StorageSpan:
    """One contiguous torrent byte range. ``path`` is None for BEP-47 padding (virtual zeros)."""

    path: Path | None
    offset: int
    length: int


class TorrentStorage:
    """Piece-addressable storage backed by files on disk (mmap); padding spans omit files."""

    def __init__(self, torrent: Torrent, base_dir: Path) -> None:
        self.torrent = torrent
        self.base_dir = Path(base_dir)
        self._files = _torrent_files(torrent)
        self._spans: list[StorageSpan] = self._build_spans()
        self._file_handles: list[Any] = []
        self._mmaps: dict[Path, mmap.mmap] = {}
        self._closed = False

    def _build_spans(self) -> list[StorageSpan]:
        spans: list[StorageSpan] = []
        torrent_offset = 0
        info = self.torrent.info
        if not isinstance(info, dict):
            raise ValueError("torrent has no info dict")

        files = info.get("files", info.get(b"files"))
        if isinstance(files, list) and files:
            for entry in files:
                if not isinstance(entry, dict):
                    continue
                length = entry.get("length", entry.get(b"length", 0))
                path_list = entry.get("path", entry.get(b"path"))
                if not isinstance(length, int) or length < 0 or not isinstance(path_list, list) or not path_list:
                    continue
                parts = []
                for p in path_list:
                    if isinstance(p, bytes):
                        parts.append(p.decode("utf-8", "replace"))
                    else:
                        parts.append(str(p))
                rel = Path(*parts)
                ne = _normalize_file_entry_for_bep47(entry)
                if bep47.is_padding_file(ne):
                    disk_path: Path | None = None
                else:
                    disk_path = self.base_dir / rel
                spans.append(StorageSpan(path=disk_path, offset=torrent_offset, length=int(length)))
                torrent_offset += int(length)
            return spans

        # single-file — never synthetic padding-only in standard metainfo layout
        name = info.get("name", info.get(b"name"))
        if isinstance(name, bytes):
            name_s = name.decode("utf-8", "replace")
        else:
            name_s = str(name or "download.bin")
        length = info.get("length", info.get(b"length", 0))
        if not isinstance(length, int) or length < 0:
            raise ValueError("invalid torrent length")
        spans.append(
            StorageSpan(path=self.base_dir / Path(name_s), offset=0, length=int(length)),
        )
        return spans

    def close(self) -> None:
        """Unmap files and release handles."""
        self._closed = True
        for mm in list(self._mmaps.values()):
            try:
                mm.close()
            except Exception:
                pass
        self._mmaps.clear()
        for fh in self._file_handles:
            try:
                fh.close()
            except Exception:
                pass
        self._file_handles.clear()

    def __enter__(self) -> TorrentStorage:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _extend_file_to_length(self, path: Path, length: int) -> None:
        with open(path, "r+b") as fh:
            fh.seek(0, os.SEEK_END)
            cur = fh.tell()
            if cur < length:
                fh.truncate(length)

    def ensure_files(self) -> None:
        """Create parent dirs and sparse material files; skip BEP-47 padding on disk."""
        for span in self._spans:
            if span.path is None:
                continue
            span.path.parent.mkdir(parents=True, exist_ok=True)
            if not span.path.exists():
                with open(span.path, "wb") as fh:
                    fh.truncate(span.length)
            else:
                self._extend_file_to_length(span.path, span.length)
        self._map_material_files()

    def _map_material_files(self) -> None:
        if self._closed:
            return
        by_path: dict[Path, int] = {}
        for span in self._spans:
            if span.path is not None:
                by_path[span.path] = span.length
        for p, ln in by_path.items():
            if p in self._mmaps:
                continue
            self._extend_file_to_length(p, ln)
            fh = open(p, "r+b")
            self._file_handles.append(fh)
            self._mmaps[p] = mmap.mmap(fh.fileno(), ln, access=mmap.ACCESS_WRITE)

    def write_at(self, offset: int, data: bytes) -> None:
        """Write bytes at absolute torrent offset."""
        if self._closed:
            raise RuntimeError("TorrentStorage is closed")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        remaining = memoryview(data)
        pos = offset
        for span in self._spans:
            if pos >= span.offset + span.length:
                continue
            if pos < span.offset:
                continue
            within = pos - span.offset
            avail = span.length - within
            take = min(len(remaining), avail)
            if take <= 0:
                continue
            if span.path is None:
                # BEP-47 padding: logical zeros only
                pass
            else:
                mm = self._mmaps.get(span.path)
                if mm is None:
                    self._map_material_files()
                    mm = self._mmaps.get(span.path)
                if mm is None:
                    raise OSError(f"mmap missing for {span.path}")
                dest = memoryview(mm)[within : within + take]
                dest[:] = remaining[:take].cast("B")
                try:
                    mm.flush(within, take)
                except OSError:
                    mm.flush()
            remaining = remaining[take:]
            pos += take
            if not remaining:
                return
        if remaining:
            raise OSError("write beyond end of torrent")

    def read_at(self, offset: int, length: int) -> bytes:
        if self._closed:
            raise RuntimeError("TorrentStorage is closed")
        if offset < 0 or length < 0:
            raise ValueError("offset/length must be >= 0")
        out = bytearray()
        pos = offset
        remain = length
        for span in self._spans:
            if pos >= span.offset + span.length:
                continue
            if pos < span.offset:
                continue
            within = pos - span.offset
            avail = span.length - within
            take = min(remain, avail)
            if take <= 0:
                continue
            if span.path is None:
                out.extend(b"\x00" * take)
            else:
                mm = self._mmaps.get(span.path)
                if mm is None:
                    self._map_material_files()
                    mm = self._mmaps.get(span.path)
                if mm is None:
                    raise OSError(f"mmap missing for {span.path}")
                out.extend(mm[within : within + take])
            pos += take
            remain -= take
            if remain <= 0:
                break
        return bytes(out)
