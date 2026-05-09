from __future__ import annotations

import binascii
import builtins
import time
from dataclasses import dataclass, field


@dataclass
class Swarm:
    """In-memory representation of a swarm (peers for a single infohash)."""

    info_hash: bytes
    display_name: str | None = None
    # pending | resolving_metadata | downloading | seeding_disabled_complete | error | inactive
    state: str = "pending"

    created_at: float = field(default_factory=time.time)
    last_updated: float = 0.0

    # Snapshots (for GUI / callers)
    swarm_peers: list[dict] = field(default_factory=list)
    dht_nodes: list[dict] = field(default_factory=list)

    # BEP 53 magnet ``pe`` hints: (host, port, is_ipv6), prepended for metadata retrieval
    magnet_peer_triplets: list[tuple[str, int, bool]] = field(default_factory=list)

    # Lightweight counters
    peers_found: int = 0
    completed_pieces: int = 0
    total_pieces: int = 0
    downloaded_bytes: int = 0
    total_bytes: int = 0
    last_error: str | None = None

    # Last retrieved bencoded *info* blob (ut_metadata) / local piece completion (BEP 3)
    cached_metadata_bytes: bytes | None = None
    local_piece_bitfield: bytes | None = None

    def __post_init__(self) -> None:
        if len(self.info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")

    @property
    def info_hash_hex(self) -> str:
        return binascii.b2a_hex(self.info_hash).decode("ascii")

    @property
    def short_id(self) -> str:
        h = self.info_hash_hex
        return f"{h[:8]}…{h[-8:]}"

    def update_swarm_peers(self, peers: list[dict]) -> None:
        preserved = {(str(p.get("ip")), int(p.get("port", 0))): p for p in self.swarm_peers}
        merged: list[dict] = []
        for raw in peers or []:
            d = dict(raw)
            k = (str(d.get("ip")), int(d.get("port", 0)))
            old = preserved.get(k)
            if old is not None:
                for fld in ("peer_chokes_us", "we_interested", "phase"):
                    if fld in old:
                        d[fld] = old[fld]
            merged.append(d)
        self.swarm_peers = merged
        self.peers_found = len(self.swarm_peers)
        self.last_updated = time.time()

    def update_dht_nodes(self, nodes: list[dict]) -> None:
        self.dht_nodes = list(nodes or [])
        self.last_updated = time.time()

    def update_download_progress(
        self,
        *,
        completed_pieces: int,
        total_pieces: int,
        downloaded_bytes: int,
        total_bytes: int,
    ) -> None:
        self.completed_pieces = int(completed_pieces)
        self.total_pieces = int(total_pieces)
        self.downloaded_bytes = int(downloaded_bytes)
        self.total_bytes = int(total_bytes)
        self.last_updated = time.time()

    def update_cached_metadata(self, metadata_bytes: bytes) -> None:
        """Store last successfully retrieved metadata (raw *info* bencode bytes)."""
        self.cached_metadata_bytes = bytes(metadata_bytes)
        self.last_updated = time.time()

    def update_local_piece_bitfield(self, bf: bytes | None) -> None:
        """Snapshot of local HAVE bitfield (from download / resume); None clears."""
        self.local_piece_bitfield = None if bf is None else bytes(bf)
        self.last_updated = time.time()


class SwarmManager:
    """Registry of active swarms for the current run (in-memory only)."""

    def __init__(self) -> None:
        self._swarms: dict[bytes, Swarm] = {}
        self._selected: bytes | None = None

    def upsert(
        self,
        info_hash: bytes,
        *,
        display_name: str | None = None,
        magnet_peer_triplets: builtins.list[tuple[str, int, bool]] | None = None,
    ) -> Swarm:
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")
        sw = self._swarms.get(info_hash)
        if sw is None:
            sw = Swarm(
                info_hash=bytes(info_hash),
                display_name=display_name,
                magnet_peer_triplets=list(magnet_peer_triplets or []),
            )
            self._swarms[bytes(info_hash)] = sw
        else:
            if display_name:
                sw.display_name = display_name
            if magnet_peer_triplets is not None:
                sw.magnet_peer_triplets = list(magnet_peer_triplets)
        if self._selected is None:
            self._selected = bytes(info_hash)
        return sw

    def remove(self, info_hash: bytes) -> None:
        self._swarms.pop(info_hash, None)
        if self._selected == info_hash:
            self._selected = next(iter(self._swarms.keys()), None)

    def list(self) -> builtins.list[Swarm]:
        # Most recently updated first; stable fallback on creation time.
        return sorted(
            self._swarms.values(),
            key=lambda s: (s.last_updated or 0.0, s.created_at),
            reverse=True,
        )

    def get(self, info_hash: bytes) -> Swarm | None:
        return self._swarms.get(info_hash)

    def select(self, info_hash: bytes) -> Swarm | None:
        if info_hash in self._swarms:
            self._selected = info_hash
        return self.selected()

    def deselect(self) -> None:
        """Clear the current selection (no swarm active)."""
        self._selected = None

    def selected(self) -> Swarm | None:
        if self._selected is None:
            return None
        return self._swarms.get(self._selected)

    def update_swarm_peers(self, info_hash: bytes, peers: builtins.list[dict]) -> Swarm | None:
        sw = self._swarms.get(info_hash)
        if sw is None:
            return None
        sw.update_swarm_peers(peers)
        return sw

    def update_dht_nodes(self, info_hash: bytes, nodes: builtins.list[dict]) -> Swarm | None:
        sw = self._swarms.get(info_hash)
        if sw is None:
            return None
        sw.update_dht_nodes(nodes)
        return sw

    def update_cached_metadata(self, info_hash: bytes, metadata_bytes: bytes) -> Swarm | None:
        sw = self._swarms.get(info_hash)
        if sw is None:
            return None
        sw.update_cached_metadata(metadata_bytes)
        return sw

    def update_local_piece_bitfield(self, info_hash: bytes, bf: bytes | None) -> Swarm | None:
        sw = self._swarms.get(info_hash)
        if sw is None:
            return None
        sw.update_local_piece_bitfield(bf)
        return sw

    def update_download_progress(
        self,
        info_hash: bytes,
        *,
        completed_pieces: int,
        total_pieces: int,
        downloaded_bytes: int,
        total_bytes: int,
    ) -> Swarm | None:
        sw = self._swarms.get(info_hash)
        if sw is None:
            return None
        sw.update_download_progress(
            completed_pieces=completed_pieces,
            total_pieces=total_pieces,
            downloaded_bytes=downloaded_bytes,
            total_bytes=total_bytes,
        )
        return sw
