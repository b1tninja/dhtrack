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

# BEP 19 WebSeed support
from dhtrack.webseed import (
    WebSeedManager,
    DownloadState,
    HTTPDownloadThread,
    FTPDownloadThread,
    WebSeedError,
    WebSeedTimeout,
    WebSeedConnectionError,
    WebSeedChecksumError,
    WebSeedEmptyError,
    WebSeedHTTPError,
    WebSeedFTPError,
)

# BEP 19 Piece Selection algorithms
from dhtrack.piece_selector import (
    PieceSelector,
    Gap,
    bitfield_to_string,
    string_to_bitfield,
)

# BEP 15: UDP Tracker Protocol
from dhtrack.udp_tracker import (
    UDPTrackerClient,
    TrackerError,
    TrackerConnectionError,
    TrackerProtocolError,
    TrackerResponseError,
    TrackerClientError,
    IPPeer,
    AnnounceEvent,
    AnnounceRequest,
    AnnounceResponse,
    ScrapeInfo,
    ScrapeResponse,
)

# BEP 48: Tracker Scrape Extension
from dhtrack.tracker import (
    TrackerClient,
    ScrapeError,
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
    # BEP 19 WebSeed
    "WebSeedManager",
    "DownloadState",
    "HTTPDownloadThread",
    "FTPDownloadThread",
    "WebSeedError",
    "WebSeedTimeout",
    "WebSeedConnectionError",
    "WebSeedChecksumError",
    "WebSeedEmptyError",
    "WebSeedHTTPError",
    "WebSeedFTPError",
    # BEP 19 Piece Selection
    "PieceSelector",
    "Gap",
    "bitfield_to_string",
    "string_to_bitfield",
    # BEP 15 UDP Tracker
    "UDPTrackerClient",
    "TrackerError",
    "TrackerConnectionError",
    "TrackerProtocolError",
    "TrackerResponseError",
    "TrackerClientError",
    "IPPeer",
    "AnnounceEvent",
    "AnnounceRequest",
    "AnnounceResponse",
    "ScrapeInfo",
    "ScrapeResponse",
    # BEP 48 Tracker Scrape
    "TrackerClient",
    "ScrapeError",
]