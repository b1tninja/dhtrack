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

# BEP 14: Local Service Discovery
from dhtrack.lsd import (
    LSDManager,
    LSDConfig,
    LSDAnnouncement,
    build_lsd_announce,
    LSD_MULTICAST_V4,
    LSD_MULTICAST_V6,
    LSD_PORT,
)

# BEP 29: uTorrent Transport Protocol (uTP)
from dhtrack.utp import (
    # Packet types
    ST_DATA,
    ST_FIN,
    ST_STATE,
    ST_RESET,
    ST_SYN,
    PACKET_TYPE_NAMES,
    # Connection states
    ConnectionState,
    # Selective ACK
    SELECTIVE_ACK_EXTENSION,
    EXT_TYPE_NONE,
    EXT_TYPE_SELECTIVE_ACK,
    # Parameters
    DEFAULT_PACKET_SIZE,
    MIN_PACKET_SIZE,
    MAX_PACKET_SIZE,
    INITIAL_CONGESTION_WINDOW,
    CCONTROL_TARGET,
    MAX_CWND_INCREASE_PACKETS_PER_RTT,
    WINDOW_FACTOR_MIN,
    INITIAL_PACKET_SIZE,
    INITIAL_TIMEOUT_MS,
    TIMEOUT_MULTIPLIER,
    RTT_ALPHA,
    RTT_BETA,
    MAX_RTT,
    MIN_RTT,
    RTT_VAR_MIN,
    BASE_DELAY_WINDOW,
    SELECTIVE_ACK_MIN_BITS,
    SELECTIVE_ACK_MAX_BITS,
    SELECTIVE_ACK_MAX_BYTES,
    # Errors
    UTPError,
    UTPPacketError,
    UTPConnectionError,
    UTPCongestionError,
    UTPTimestampError,
    # Core classes
    PacketHeader,
    SelectiveAck,
    CongestionControl,
    PendingPacket,
    UTPConnection,
    UTPSocket,
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
    # BEP 14 LSD
    "LSDManager",
    "LSDConfig",
    "LSDAnnouncement",
    "build_lsd_announce",
    "LSD_MULTICAST_V4",
    "LSD_MULTICAST_V6",
    "LSD_PORT",
    # BEP 29 uTP
    "ST_DATA",
    "ST_FIN",
    "ST_STATE",
    "ST_RESET",
    "ST_SYN",
    "PACKET_TYPE_NAMES",
    "ConnectionState",
    "SELECTIVE_ACK_EXTENSION",
    "EXT_TYPE_NONE",
    "EXT_TYPE_SELECTIVE_ACK",
    "DEFAULT_PACKET_SIZE",
    "MIN_PACKET_SIZE",
    "MAX_PACKET_SIZE",
    "INITIAL_CONGESTION_WINDOW",
    "CCONTROL_TARGET",
    "MAX_CWND_INCREASE_PACKETS_PER_RTT",
    "WINDOW_FACTOR_MIN",
    "INITIAL_PACKET_SIZE",
    "INITIAL_TIMEOUT_MS",
    "TIMEOUT_MULTIPLIER",
    "RTT_ALPHA",
    "RTT_BETA",
    "MAX_RTT",
    "MIN_RTT",
    "RTT_VAR_MIN",
    "BASE_DELAY_WINDOW",
    "SELECTIVE_ACK_MIN_BITS",
    "SELECTIVE_ACK_MAX_BITS",
    "SELECTIVE_ACK_MAX_BYTES",
    "UTPError",
    "UTPPacketError",
    "UTPConnectionError",
    "UTPCongestionError",
    "UTPTimestampError",
    "PacketHeader",
    "SelectiveAck",
    "CongestionControl",
    "PendingPacket",
    "UTPConnection",
    "UTPSocket",
]
