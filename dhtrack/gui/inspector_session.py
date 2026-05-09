"""Grouped GUI session registries shared across Swarm Tracker, Torrent Manager, and Inspector."""

from __future__ import annotations

from dataclasses import dataclass

from dhtrack.swarm import SwarmManager
from dhtrack.torrent_track import TorrentManager


@dataclass
class InspectorSession:
    """Holds swarm + torrent registries with one ``TorrentManager.library_directory`` subtree."""

    swarm_manager: SwarmManager
    torrent_manager: TorrentManager
