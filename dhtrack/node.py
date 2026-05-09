"""
DHT node orchestration for dhtrack.

Phase 3 module split: this module is the stable import surface for DHTNode.
Implementation currently lives in `dhtrack.dht` and is re-exported here.
"""

from __future__ import annotations

from dhtrack.dht import DHTNode, DHTPeer, Endpoint

__all__ = ["DHTNode", "DHTPeer", "Endpoint"]
