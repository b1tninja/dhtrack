"""
dhtrack - A modern DHT swarm inspector for BitTorrent.

Provides tools for inspecting the Distributed Hash Table (DHT) network
used by the BitTorrent protocol.
"""

from __future__ import annotations

__version__ = "2.0.0"

# BEP 10 Extension Protocol support
from dhtrack.peer import (
    ExtensionNegotiator,
    MetadataExchange,
    PEXManager,
    HolePunchHandler,
    PeerConnection,
    ExtensionError,
    ExtensionHandshakeError,
    MetadataExchangeError,
    PEXError,
    UT_METADATA,
    UT_PEX,
    UT_HOLEPUNCH,
)

from dhtrack.extension import (
    ExtensionManager,
    ExtensionRegistry,
    Extension,
    ExtensionType,
    MetadataExtension,
    PEXExtension,
    HolePunchExtension,
)

__all__ = [
    # Peer connection
    "ExtensionNegotiator",
    "MetadataExchange",
    "PEXManager",
    "HolePunchHandler",
    "PeerConnection",
    # Errors
    "ExtensionError",
    "ExtensionHandshakeError",
    "MetadataExchangeError",
    "PEXError",
    # Extensions
    "ExtensionManager",
    "ExtensionRegistry",
    "Extension",
    "ExtensionType",
    "MetadataExtension",
    "PEXExtension",
    "HolePunchExtension",
    # Extension names
    "UT_METADATA",
    "UT_PEX",
    "UT_HOLEPUNCH",
]
