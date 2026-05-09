"""
Async UDP I/O utilities for dhtrack.

Phase 3 module split: this module is the stable import surface for socket I/O.
Implementation currently lives in `dhtrack.dht` and is re-exported here.
"""

from __future__ import annotations

from dhtrack.dht import SocketManager

__all__ = ["SocketManager"]
