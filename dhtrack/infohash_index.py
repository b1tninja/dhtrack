"""Bounded indexes for infohashes observed on the DHT.

BEP 51 ``sample_infohashes`` responses and passive ``get_peers`` /
``announce_peer`` queries land here. A :class:`InfohashWatchlist` is the
explicit set an operator wants resolved; :meth:`InfohashWatchlist.resolve`
calls :meth:`DHTManager.retrieve_metadata` and does not open sockets itself.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from dhtrack.endpoint_swarm_index import (
    EVIDENCE_INBOUND_ANNOUNCE_PEER,
    EVIDENCE_INBOUND_GET_PEERS,
    EndpointSwarmIndex,
)

EVIDENCE_BEP51_SAMPLE = "bep51_sample"


@dataclass
class ObservedInfohash:
    """One infohash seen on the wire or in a BEP 51 sample."""

    info_hash: bytes
    source: str
    first_seen: float
    last_seen: float
    hits: int = 1
    endpoint: tuple[str, int] | None = None

    @property
    def info_hash_hex(self) -> str:
        return self.info_hash.hex()


@dataclass
class InfohashIndex:
    """LRU map of observed infohashes, capped so a long crawl cannot grow forever."""

    max_entries: int = 10000
    _rows: OrderedDict[bytes, ObservedInfohash] = field(default_factory=OrderedDict)

    def __post_init__(self) -> None:
        self.max_entries = max(1, int(self.max_entries))

    def observe(
        self,
        info_hash: bytes,
        *,
        source: str,
        endpoint: tuple[str, int] | None = None,
        now: float | None = None,
        swarm_index: EndpointSwarmIndex | None = None,
        is_ipv6: bool = False,
    ) -> ObservedInfohash | None:
        """Record ``info_hash`` and optionally mirror it into an endpoint index."""
        if not isinstance(info_hash, (bytes, bytearray)) or len(info_hash) != 20:
            return None
        ih = bytes(info_hash)
        ts = time.time() if now is None else float(now)
        row = self._rows.get(ih)
        if row is None:
            row = ObservedInfohash(
                info_hash=ih,
                source=source,
                first_seen=ts,
                last_seen=ts,
                hits=1,
                endpoint=endpoint,
            )
            self._rows[ih] = row
            while len(self._rows) > self.max_entries:
                self._rows.popitem(last=False)
        else:
            row.hits += 1
            row.last_seen = ts
            row.source = source
            if endpoint is not None:
                row.endpoint = endpoint
            self._rows.move_to_end(ih)
        if swarm_index is not None and endpoint is not None:
            swarm_index.record_hint(
                ip=endpoint[0],
                port=int(endpoint[1]),
                is_ipv6=is_ipv6,
                info_hash_hex=ih.hex(),
                evidence=source,
                now=ts,
            )
        return row

    def get(self, info_hash: bytes) -> ObservedInfohash | None:
        return self._rows.get(bytes(info_hash))

    def __len__(self) -> int:
        return len(self._rows)

    def recent(self, limit: int = 50) -> list[ObservedInfohash]:
        """Newest observations first."""
        if limit <= 0:
            return []
        rows = list(self._rows.values())
        rows.reverse()
        return rows[:limit]


class InfohashWatchlist:
    """Operator-selected infohashes that can be handed to metadata retrieval."""

    def __init__(self) -> None:
        self._notes: dict[bytes, str] = {}
        self._order: list[bytes] = []

    def watch(self, info_hash: bytes, note: str = "") -> None:
        if not isinstance(info_hash, (bytes, bytearray)) or len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")
        ih = bytes(info_hash)
        if ih not in self._notes:
            self._order.append(ih)
        self._notes[ih] = note

    def unwatch(self, info_hash: bytes) -> None:
        ih = bytes(info_hash)
        self._notes.pop(ih, None)
        self._order = [x for x in self._order if x != ih]

    def __contains__(self, info_hash: object) -> bool:
        if not isinstance(info_hash, (bytes, bytearray)):
            return False
        return bytes(info_hash) in self._notes

    def __len__(self) -> int:
        return len(self._order)

    def infohashes(self) -> list[bytes]:
        return list(self._order)

    def resolve(
        self,
        manager: object,
        info_hash: bytes,
        *,
        retrieve: Callable[..., object] | None = None,
        **kwargs: object,
    ) -> object:
        """Resolve metadata for a watched (or any) infohash.

        ``retrieve`` defaults to ``manager.retrieve_metadata``. Tests pass a
        fake callable; the GUI and CLI pass a :class:`DHTManager`.
        """
        ih = bytes(info_hash)
        if len(ih) != 20:
            raise ValueError("info_hash must be 20 bytes")
        fn = retrieve if retrieve is not None else getattr(manager, "retrieve_metadata", None)
        if fn is None:
            raise TypeError("manager has no retrieve_metadata")
        return fn(ih, **kwargs)


__all__ = [
    "EVIDENCE_BEP51_SAMPLE",
    "EVIDENCE_INBOUND_ANNOUNCE_PEER",
    "EVIDENCE_INBOUND_GET_PEERS",
    "InfohashIndex",
    "InfohashWatchlist",
    "ObservedInfohash",
]
