"""Tests for Swarm Inspector peer row helpers (Qt-free)."""

from __future__ import annotations

from dhtrack.swarm_peer_display import (
    is_active_swarm_peer_row,
    merge_peer_detail_fields,
    peer_row_detail_lines,
)


class TestMergePeerDetailFields:
    def test_merge_updates(self) -> None:
        p: dict = {"ip": "10.0.0.1", "port": 6881}
        merge_peer_detail_fields(p, {"peer_chokes_us": False, "we_interested": True})
        assert p["peer_chokes_us"] is False
        assert p["we_interested"] is True


class TestPeerRowDetailLines:
    def test_sorted_keys(self) -> None:
        p = {"z": 1, "a": 2}
        lines = peer_row_detail_lines(p)
        assert lines[0].startswith("a:")


class TestIsActiveSwarmPeerRow:
    def test_rejects_last_error(self) -> None:
        assert is_active_swarm_peer_row({"last_error": "x"}) is False

    def test_rejects_connect_failed(self) -> None:
        assert is_active_swarm_peer_row({"status": "connect_failed"}) is False

    def test_accepts_connected(self) -> None:
        assert is_active_swarm_peer_row({"status": "connected"}) is True

    def test_accepts_good_dht_row(self) -> None:
        assert is_active_swarm_peer_row({"status": "good", "source": "swarm"}) is True

    def test_swarm_no_timestamp_still_active(self) -> None:
        assert is_active_swarm_peer_row({"source": "swarm", "status": "unknown"}) is True

    def test_stale_inactive(self) -> None:
        assert is_active_swarm_peer_row({"status": "stale"}) is False
