"""Shared torrent / swarm display helpers for GUI tables and panels."""

from __future__ import annotations

from dhtrack.swarm import Swarm
from dhtrack.torrent_track import (
    TORRENT_STATUS_COMPLETE,
    TORRENT_STATUS_DOWNLOADING,
    TORRENT_STATUS_ERROR,
    TORRENT_STATUS_IDLE,
    TORRENT_STATUS_PENDING_METADATA,
    TORRENT_STATUS_QUEUED,
    TrackedTorrent,
)


def tcp_active_peer_count(sw: Swarm | None) -> int:
    if sw is None:
        return 0
    n = 0
    for p in sw.swarm_peers or []:
        st = str(p.get("status", "") or "").lower()
        phase = str(p.get("phase", "") or "").lower()
        if phase == "payload_transfer":
            n += 1
        elif st in ("connected", "good", "active"):
            n += 1
        elif st == "" and p.get("ip"):
            n += 1
    return n


def format_throughput_human(bps: float) -> str:
    if bps <= 0:
        return "—"
    if bps >= 1048576:
        return f"{bps / 1048576:.2f} MiB/s"
    if bps >= 1024:
        return f"{bps / 1024:.1f} KiB/s"
    return f"{bps:.0f} B/s"


def torrent_status_display(tt: TrackedTorrent) -> str:
    mapping = {
        TORRENT_STATUS_IDLE: "Idle",
        TORRENT_STATUS_PENDING_METADATA: "Pending (metadata)",
        TORRENT_STATUS_QUEUED: "Queued",
        TORRENT_STATUS_DOWNLOADING: "Downloading",
        TORRENT_STATUS_COMPLETE: "Seeding",
        TORRENT_STATUS_ERROR: "Error",
    }
    return mapping.get(tt.status, tt.status)
