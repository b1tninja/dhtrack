"""
Routing table and bucket structures for dhtrack.

Phase 3 module split: this module is the stable import surface for routing types.
Implementation currently lives in `dhtrack.dht` and is re-exported here to avoid
breaking callers while the monolith is decomposed.
"""

from __future__ import annotations

from dhtrack.dht import DualStackRoutingTable, KBucket, RoutingTable

__all__ = ["DualStackRoutingTable", "KBucket", "RoutingTable"]
