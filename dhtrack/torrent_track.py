"""In-memory registry of torrents linked to tracked swarms (GUI/session scope)."""

from __future__ import annotations

import builtins
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dhtrack import bencode
from dhtrack.swarm import SwarmManager
from dhtrack.torrent import Torrent

logger = logging.getLogger(__name__)
# Stored on TrackedTorrent.status and used by GUI / scheduler (no Qt).
TORRENT_STATUS_IDLE = "idle"
TORRENT_STATUS_PENDING_METADATA = "pending_metadata"
TORRENT_STATUS_QUEUED = "queued"
TORRENT_STATUS_DOWNLOADING = "downloading"
TORRENT_STATUS_COMPLETE = "complete"
TORRENT_STATUS_ERROR = "error"

DEFAULT_MAX_CONCURRENT_PAYLOAD_DOWNLOADS = 2


def _canonical_metainfo_bytes(raw_bencoded: bytes, expected_infohash: bytes) -> tuple[bytes, Torrent]:
    """Same wrapping rules as :meth:`dhtrack.dht_manager.DHTManager.create_torrent`."""
    decoded = bencode.decode(raw_bencoded)
    if not isinstance(decoded, dict):
        raise ValueError("invalid torrent metainfo")

    top: Any
    if b"info" in decoded or "info" in decoded:
        torrent = Torrent(decoded)
        top = decoded
    else:
        top = {b"info": decoded}
        torrent = Torrent(top)
    ih = bytes(expected_infohash)
    if len(ih) != 20:
        raise ValueError("expected_infohash must be 20 bytes")
    if torrent.infohash != ih:
        raise ValueError("metainfo info-hash mismatch")
    encoded = bencode.encode(top)
    return encoded, torrent


@dataclass
class TrackedTorrent:
    """A torrent entry registered separately from swarm tracking."""

    info_hash: bytes
    display_name: str | None = None
    download_directory: Path | None = None
    metadata_path: Path | None = None
    registered_at: float = field(default_factory=time.time)
    status: str = TORRENT_STATUS_IDLE
    last_error: str | None = None

    def __post_init__(self) -> None:
        if len(self.info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")

    @property
    def short_id(self) -> str:
        h = self.info_hash.hex()
        return f"{h[:8]}…{h[-8:]}"


class TorrentManager:
    """Registry of torrents; swarm-scoped state lives in ``SwarmManager``.

    Bounded-concurrency FIFO queue for payload downloads via
    `_waiting_payload`: ``enqueue_payload_download`` enqueues jobs;
    callers spawn ``DownloadWorker`` for each ih returned by
    ``try_acquire_payload_slots`` / ``release_payload_slot``.
    """

    def __init__(
        self,
        swarm_manager: SwarmManager,
        *,
        max_concurrent_payload_downloads: int = DEFAULT_MAX_CONCURRENT_PAYLOAD_DOWNLOADS,
        torrent_library_directory: Path | None = None,
    ) -> None:
        self._swarm_mgr = swarm_manager
        self._library_dir = Path(torrent_library_directory) if torrent_library_directory is not None else None
        self._torrents: dict[bytes, TrackedTorrent] = {}
        self._max_payload = max(1, int(max_concurrent_payload_downloads))
        self._waiting_payload: deque[bytes] = deque()
        self._waiting_payload_set: set[bytes] = set()
        self._active_payload: set[bytes] = set()

    @property
    def max_concurrent_payload_downloads(self) -> int:
        return self._max_payload

    @property
    def torrent_library_directory(self) -> Path | None:
        return self._library_dir

    def set_torrent_library_directory(self, path: Path | None) -> None:
        """Point metainfo persistence and default resume subdirectory at ``path``."""
        self._library_dir = None if path is None else Path(path)

    def ensure_library_dir(self) -> Path:
        if self._library_dir is None:
            raise RuntimeError("TorrentManager has no torrent_library_directory")
        self._library_dir.mkdir(parents=True, exist_ok=True)
        return self._library_dir

    def resume_subdirectory(self) -> Path:
        return self.ensure_library_dir() / "resume"

    @property
    def active_payload_infohashes(self) -> frozenset[bytes]:
        return frozenset(self._active_payload)

    def waiting_payload_infohashes(self) -> builtins.list[bytes]:
        """FIFO queue of infohashes waiting for a payload slot (copy, stable order)."""
        return list(self._waiting_payload)

    def _remove_from_waiting(self, ih: bytes) -> None:
        if ih not in self._waiting_payload_set:
            return
        self._waiting_payload_set.discard(ih)
        rebuilt: deque[bytes] = deque()
        for x in self._waiting_payload:
            if x != ih:
                rebuilt.append(x)
        self._waiting_payload = rebuilt

    def dequeue_payload_waiting(self, info_hash: bytes) -> None:
        """Leave queue without starting download (cancel queued job)."""
        ih = bytes(info_hash)
        self._remove_from_waiting(ih)
        tt = self._torrents.get(ih)
        if tt is not None and tt.status == TORRENT_STATUS_QUEUED:
            tt.status = TORRENT_STATUS_IDLE

    def register(
        self,
        info_hash: bytes,
        *,
        display_name: str | None = None,
        download_directory: Path | None = None,
    ) -> TrackedTorrent:
        """Ensure swarm exists and add or update torrent registration."""
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")
        ih = bytes(info_hash)
        self._swarm_mgr.upsert(ih, display_name=display_name)
        existing = self._torrents.get(ih)
        if existing is None:
            tt = TrackedTorrent(
                info_hash=ih,
                display_name=display_name,
                download_directory=download_directory,
            )
            self._torrents[ih] = tt
            return tt
        if display_name:
            existing.display_name = display_name
        if download_directory is not None:
            existing.download_directory = Path(download_directory)
        return existing

    def save_metadata_blob(self, info_hash: bytes, raw_bencoded: bytes) -> Path:
        """Write ``{{ih}}.torrent`` atomically; update :attr:`TrackedTorrent.metadata_path`."""
        ih = bytes(info_hash)
        if len(ih) != 20:
            raise ValueError("info_hash must be 20 bytes")
        canon, torrent = _canonical_metainfo_bytes(raw_bencoded, ih)
        root = self.ensure_library_dir()
        out = root / f"{ih.hex()}.torrent"
        tmp = out.with_suffix(".torrent.tmp")
        tmp.write_bytes(canon)
        tmp.replace(out)
        tt = self.get(ih)
        if tt is None:
            tt = self.register(ih)
        tt.metadata_path = out.resolve()
        name = getattr(torrent, "name", None)
        display = str(name).strip() if name else ""
        if display:
            tt.display_name = tt.display_name or display
            self._swarm_mgr.upsert(ih, display_name=display)
        logger.info("Wrote torrent metainfo library file %s", out)
        return out

    def load_saved_metainfo_from_disk(self) -> int:
        """Load ``*.torrent`` from the library into swarms / library rows."""
        if self._library_dir is None:
            return 0
        if not self._library_dir.is_dir():
            return 0
        n = 0
        for p in sorted(self._library_dir.glob("*.torrent")):
            ih_hex = p.stem.lower()
            if len(ih_hex) != 40:
                continue
            try:
                ih = bytes.fromhex(ih_hex)
            except ValueError:
                continue
            try:
                raw = p.read_bytes()
            except OSError:
                logger.debug("Unreadable torrent library file %s", p)
                continue
            try:
                _, tor = _canonical_metainfo_bytes(raw, ih)
            except Exception as exc:
                logger.debug("Skipping %s: %s", p, exc)
                continue
            display = str(getattr(tor, "name", "") or "").strip() or None
            self._swarm_mgr.upsert(ih, display_name=display)
            self._swarm_mgr.update_cached_metadata(ih, raw)
            tt = self.register_library_metadata_only(ih, display_name=display)
            tt.metadata_path = p.resolve()
            n += 1
        return n

    def remove(self, info_hash: bytes) -> builtins.list[bytes]:
        """Remove torrent registration only (swarm may still be tracked).

        Drops any queued/active payload bookkeeping and may yield new starters
        to fill freed slots once the caller tears down workers for ``info_hash``.
        """
        ih = bytes(info_hash)
        self.dequeue_payload_waiting(ih)
        self._active_payload.discard(ih)
        self._torrents.pop(ih, None)
        return self.try_acquire_payload_slots()

    def get(self, info_hash: bytes) -> TrackedTorrent | None:
        return self._torrents.get(bytes(info_hash))

    def list(self) -> builtins.list[TrackedTorrent]:
        return sorted(
            self._torrents.values(),
            key=lambda t: t.registered_at,
            reverse=True,
        )

    def set_download_directory(self, info_hash: bytes, path: Path | None) -> None:
        """Set payload directory; registers a minimal torrent row if needed."""
        ih = bytes(info_hash)
        tt = self._torrents.get(ih)
        if tt is None:
            self.register(ih, download_directory=path)
            return
        tt.download_directory = None if path is None else Path(path)

    def register_library_metadata_only(
        self,
        info_hash: bytes,
        *,
        display_name: str | None = None,
    ) -> TrackedTorrent:
        """Register in the library without queueing payload download."""
        ih = bytes(info_hash)
        tt = self.register(ih, display_name=display_name)
        busy = ih in self._active_payload or ih in self._waiting_payload_set
        if not busy and tt.status not in (
            TORRENT_STATUS_DOWNLOADING,
            TORRENT_STATUS_COMPLETE,
            TORRENT_STATUS_ERROR,
            TORRENT_STATUS_QUEUED,
        ):
            sw = self._swarm_mgr.get(ih)
            if sw and sw.cached_metadata_bytes:
                tt.status = TORRENT_STATUS_IDLE
            else:
                tt.status = TORRENT_STATUS_PENDING_METADATA
        return tt

    def enqueue_payload_download(
        self,
        info_hash: bytes,
        download_directory: Path,
        *,
        display_name: str | None = None,
    ) -> builtins.list[bytes]:
        """Register path, mark queued, return infohashes that should start workers now.

        Does not add duplicate queue entries for the same ``info_hash`` while it is
        already waiting or actively downloading.
        """
        ih = bytes(info_hash)
        self.register(ih, display_name=display_name, download_directory=download_directory)
        tt = self._torrents[ih]
        tt.last_error = None
        if ih in self._active_payload:
            return []
        if ih not in self._waiting_payload_set:
            tt.status = TORRENT_STATUS_QUEUED
            self._waiting_payload.append(ih)
            self._waiting_payload_set.add(ih)
        return self.try_acquire_payload_slots()

    def try_acquire_payload_slots(self) -> builtins.list[bytes]:
        """Fill free payload slots from the FIFO queue; mark those rows downloading."""
        starters: builtins.list[bytes] = []
        while len(self._active_payload) < self._max_payload and self._waiting_payload:
            cand = self._waiting_payload.popleft()
            self._waiting_payload_set.discard(cand)
            if cand in self._active_payload:
                continue
            tt = self._torrents.get(cand)
            if tt is None:
                continue
            self._active_payload.add(cand)
            tt.status = TORRENT_STATUS_DOWNLOADING
            starters.append(cand)
        return starters

    def release_payload_slot(
        self,
        info_hash: bytes,
        *,
        complete: bool = False,
        error_message: str | None = None,
        cancelled: bool = False,
    ) -> builtins.list[bytes]:
        """Worker finished/cancelled: free slot and start waiting jobs."""
        ih = bytes(info_hash)
        self._active_payload.discard(ih)
        tt = self._torrents.get(ih)
        if tt is not None:
            if cancelled:
                if tt.status != TORRENT_STATUS_ERROR:
                    tt.status = TORRENT_STATUS_IDLE
            elif error_message:
                tt.status = TORRENT_STATUS_ERROR
                tt.last_error = error_message
            elif complete:
                tt.status = TORRENT_STATUS_COMPLETE
            elif tt.status == TORRENT_STATUS_DOWNLOADING:
                tt.status = TORRENT_STATUS_IDLE
        return self.try_acquire_payload_slots()
