"""Tests for dhtrack.torrent_track (TorrentManager / TrackedTorrent)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dhtrack.swarm import SwarmManager
from dhtrack.torrent_track import (
    TORRENT_STATUS_COMPLETE,
    TORRENT_STATUS_DOWNLOADING,
    TORRENT_STATUS_QUEUED,
    TorrentManager,
    TrackedTorrent,
)


def _ih(b: int) -> bytes:
    return bytes([b % 256]) * 20


def test_tracked_torrent_rejects_bad_length() -> None:
    with pytest.raises(ValueError, match="info_hash"):
        TrackedTorrent(info_hash=b"tooshort")


def test_register_upserts_swarm_and_merges_display_name() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm)
    ih = _ih(1)
    tm.register(ih, display_name="Hello")
    sw = sm.get(ih)
    assert sw is not None
    assert sw.display_name == "Hello"
    ent = tm.get(ih)
    assert ent is not None
    assert ent.display_name == "Hello"


def test_register_updates_existing_torrent_display_name() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm)
    ih = _ih(2)
    tm.register(ih, display_name="A")
    tm.register(ih, display_name="B")
    assert tm.get(ih).display_name == "B"
    assert sm.get(ih).display_name == "B"


def test_remove_drops_torrent_only_keeps_swarm() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm)
    ih = _ih(3)
    tm.register(ih)
    starters = tm.remove(ih)
    assert starters == []
    assert tm.get(ih) is None
    assert sm.get(ih) is not None


def test_list_sorted_by_registered_at() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm)
    tm.register(_ih(4))
    tm.register(_ih(5))
    rows = tm.list()
    assert len(rows) == 2


def test_set_download_directory_creates_minimal_entry() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm)
    ih = _ih(6)
    tm.set_download_directory(ih, Path("/tmp/out"))
    tt = tm.get(ih)
    assert tt is not None
    assert tt.download_directory == Path("/tmp/out")
    assert sm.get(ih) is not None


def test_set_download_directory_on_existing() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm)
    ih = _ih(7)
    tm.register(ih, display_name="X")
    tm.set_download_directory(ih, Path("/data"))
    assert tm.get(ih).download_directory == Path("/data")


def test_enqueue_respects_concurrency_fifo() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm, max_concurrent_payload_downloads=1)
    h1, h2 = _ih(10), _ih(11)
    s1 = tm.enqueue_payload_download(h1, Path("/a"))
    assert s1 == [h1]
    assert tm.get(h1).status == TORRENT_STATUS_DOWNLOADING
    s2 = tm.enqueue_payload_download(h2, Path("/b"))
    assert s2 == []
    assert tm.get(h2).status == TORRENT_STATUS_QUEUED
    nxt = tm.release_payload_slot(h1, complete=True)
    assert nxt == [h2]
    assert tm.get(h1).status == TORRENT_STATUS_COMPLETE
    assert tm.get(h2).status == TORRENT_STATUS_DOWNLOADING


def test_waiting_payload_infohashes_fifo_order() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm, max_concurrent_payload_downloads=1)
    h1, h2, h3 = _ih(30), _ih(31), _ih(32)
    tm.enqueue_payload_download(h1, Path("/x"))
    tm.enqueue_payload_download(h2, Path("/y"))
    tm.enqueue_payload_download(h3, Path("/z"))
    assert tm.active_payload_infohashes == frozenset({h1})
    assert tm.waiting_payload_infohashes() == [h2, h3]
    tm.release_payload_slot(h1, complete=True)
    assert tm.waiting_payload_infohashes() == [h3]


def test_remove_frees_slot_for_waiting() -> None:
    sm = SwarmManager()
    tm = TorrentManager(sm, max_concurrent_payload_downloads=1)
    h1, h2 = _ih(20), _ih(21)
    tm.enqueue_payload_download(h1, Path("/x"))
    tm.enqueue_payload_download(h2, Path("/y"))
    assert tm.get(h2).status == TORRENT_STATUS_QUEUED
    starters = tm.remove(h1)
    assert starters == [h2]
    assert tm.get(h1) is None
