"""In-memory index of info-hashes casually associated with UDP endpoints."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

EVIDENCE_INBOUND_GET_PEERS = "inbound_get_peers"
EVIDENCE_INBOUND_ANNOUNCE_PEER = "inbound_announce_peer"


@dataclass
class EndpointSwarmRow:
    info_hash_hex: str
    evidence: set[str] = field(default_factory=set)
    last_seen: float = 0.0
    hit_count: int = 0


@dataclass(frozen=True)
class EndpointKey:
    ip: str
    port: int
    is_ipv6: bool


class EndpointSwarmIndex:
    """Merge passive DHT hints: which info-hashes appear in queries per endpoint."""

    def __init__(self, *, max_hashes_per_endpoint: int = 512) -> None:
        self._max_per_ep = max(8, int(max_hashes_per_endpoint))
        self._by_ep: dict[EndpointKey, dict[str, EndpointSwarmRow]] = {}

    @staticmethod
    def normalize_ip(ip: str) -> str:
        return ip.strip()

    def record_hint(
        self,
        *,
        ip: str,
        port: int,
        is_ipv6: bool,
        info_hash_hex: str,
        evidence: str,
        now: float | None = None,
    ) -> None:
        if not info_hash_hex or len(info_hash_hex) != 40:
            return
        ih = info_hash_hex.lower()
        ts = now if now is not None else time.time()
        key = EndpointKey(self.normalize_ip(ip), int(port), bool(is_ipv6))
        bucket = self._by_ep.setdefault(key, {})
        row = bucket.get(ih)
        if row is None:
            if len(bucket) >= self._max_per_ep:
                oldest_hex = min(bucket.items(), key=lambda kv: kv[1].last_seen)[0]
                bucket.pop(oldest_hex, None)
            bucket[ih] = EndpointSwarmRow(
                info_hash_hex=ih,
                evidence={evidence},
                last_seen=ts,
                hit_count=1,
            )
            return
        row.evidence.add(evidence)
        row.hit_count += 1
        row.last_seen = ts

    def snapshot(self, *, ip: str, port: int, is_ipv6: bool) -> list[EndpointSwarmRow]:
        key = EndpointKey(self.normalize_ip(ip), int(port), bool(is_ipv6))
        bucket = self._by_ep.get(key)
        if not bucket:
            return []
        rows = sorted(
            bucket.values(),
            key=lambda r: (-r.last_seen, r.info_hash_hex),
        )
        return list(rows)


__all__ = [
    "EndpointKey",
    "EndpointSwarmIndex",
    "EndpointSwarmRow",
    "EVIDENCE_INBOUND_ANNOUNCE_PEER",
    "EVIDENCE_INBOUND_GET_PEERS",
]
