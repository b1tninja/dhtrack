"""
KRPC encode/decode helpers for dhtrack (BEP 5).

Phase 3 module split: this module is the stable import surface for KRPC helpers.
Implementation currently lives in `dhtrack.dht` and is re-exported here.
"""

from __future__ import annotations

from dhtrack.dht import (
    _compact_node_decode,
    _compact_node_encode,
    _compact_peer_decode,
    _compact_peer_encode,
    _encode_dht_error,
    _encode_dht_query,
    _encode_dht_response,
)

__all__ = [
    "_compact_node_decode",
    "_compact_node_encode",
    "_compact_peer_decode",
    "_compact_peer_encode",
    "_encode_dht_error",
    "_encode_dht_query",
    "_encode_dht_response",
]
