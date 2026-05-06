"""
dhtrack - A modern DHT swarm inspector for BitTorrent.

Provides tools for inspecting the Distributed Hash Table (DHT) network
used by the BitTorrent protocol.
"""

from __future__ import annotations

__version__ = "2.0.0"

# BEP 4: Assigned Numbers
from dhtrack.bep4 import (
    # Reserved byte constants
    RESERVED_AZUREUS_MSG,
    RESERVED_LOCATION_AWARE,
    RESERVED_LTEP,
    RESERVED_DHT,
    RESERVED_PEER_EXCHANGE,
    RESERVED_FAST_EXTENSIONS,
    RESERVED_NAT_TRAVERSAL,
    RESERVED_HYBRID_TORRENT_LEGACY,
    RESERVED_BITCOMET_MSG,
    RESERVED_BITCOMET_EXT,
    RESERVED_XBT_METADATA_EXCHANGE,
    RESERVED_BEP10,
    # Core protocol message types
    MSG_CHOKE,
    MSG_UNCHOKE,
    MSG_INTERESTED,
    MSG_NOT_INTERESTED,
    MSG_HAVE,
    MSG_BITFIELD,
    MSG_REQUEST,
    MSG_PIECE,
    MSG_CANCEL,
    # BEP 6 / BEP 16 message types
    MSG_PORT,
    MSG_SUGGEST,
    MSG_HAVE_ALL,
    MSG_HAVE_NONE,
    MSG_REJECT_REQUEST,
    MSG_ALLOWED_FAST,
    # BEP 10
    MSG_LTEP_HANDSHAKE,
    # Hash Transfer Protocol
    MSG_HASH_REQUEST,
    MSG_HASH_REQUESTS,
    MSG_HASH_REJECT,
    # Sets and mappings
    CORE_MESSAGE_IDS,
    FAST_EXTENSION_MESSAGE_IDS,
    DHT_EXTENSION_MESSAGE_IDS,
    DEPLOYED_EXTENSION_MESSAGE_IDS,
    ALL_KNOWN_MESSAGE_IDS,
    MESSAGE_NAMES,
    # Utility functions
    is_reserved_bit_set,
    set_reserved_bit,
    clear_reserved_bit,
    message_name,
    is_valid_message_type,
    is_core_message,
    is_fast_extension_message,
    is_dht_extension_message,
    decode_reserved_bytes,
    make_handshake_reserved,
    # Exceptions
    BEP4Error,
    InvalidReservedByteError,
    InvalidMessageTypeError,
)

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

# BEP 31: Failure Retry Extension
from dhtrack.bep31 import (
    FailureRetryInfo,
    TrackerRetryScheduler,
    parse_failure_response,
    should_retry_tracker,
)

# BEP 53: Magnet URI File Selection
from dhtrack.bep53 import (
    MagnetInfo,
    parse_magnet_uri,
    filter_files_by_select_only,
    create_magnet_from_torrent,
)

# BEP 54: lt_donthave Extension
from dhtrack.bep54 import (
    LT_DONTHAVE_NAME,
    LT_DONTHAVE_SUBOP,
    encode_donthave,
    decode_donthave,
    create_donthave_message,
    parse_donthave_from_extended,
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
    # BEP 4: Assigned Numbers
    "RESERVED_AZUREUS_MSG",
    "RESERVED_LOCATION_AWARE",
    "RESERVED_LTEP",
    "RESERVED_DHT",
    "RESERVED_PEER_EXCHANGE",
    "RESERVED_FAST_EXTENSIONS",
    "RESERVED_NAT_TRAVERSAL",
    "RESERVED_HYBRID_TORRENT_LEGACY",
    "RESERVED_BITCOMET_MSG",
    "RESERVED_BITCOMET_EXT",
    "RESERVED_XBT_METADATA_EXCHANGE",
    "RESERVED_BEP10",
    "MSG_CHOKE",
    "MSG_UNCHOKE",
    "MSG_INTERESTED",
    "MSG_NOT_INTERESTED",
    "MSG_HAVE",
    "MSG_BITFIELD",
    "MSG_REQUEST",
    "MSG_PIECE",
    "MSG_CANCEL",
    "MSG_PORT",
    "MSG_SUGGEST",
    "MSG_HAVE_ALL",
    "MSG_HAVE_NONE",
    "MSG_REJECT_REQUEST",
    "MSG_ALLOWED_FAST",
    "MSG_LTEP_HANDSHAKE",
    "MSG_HASH_REQUEST",
    "MSG_HASH_REQUESTS",
    "MSG_HASH_REJECT",
    "CORE_MESSAGE_IDS",
    "FAST_EXTENSION_MESSAGE_IDS",
    "DHT_EXTENSION_MESSAGE_IDS",
    "DEPLOYED_EXTENSION_MESSAGE_IDS",
    "ALL_KNOWN_MESSAGE_IDS",
    "MESSAGE_NAMES",
    "is_reserved_bit_set",
    "set_reserved_bit",
    "clear_reserved_bit",
    "message_name",
    "is_valid_message_type",
    "is_core_message",
    "is_fast_extension_message",
    "is_dht_extension_message",
    "decode_reserved_bytes",
    "make_handshake_reserved",
    "BEP4Error",
    "InvalidReservedByteError",
    "InvalidMessageTypeError",
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
    # BEP 31 Failure Retry
    "FailureRetryInfo",
    "TrackerRetryScheduler",
    "parse_failure_response",
    "should_retry_tracker",
    # BEP 53 Magnet URI
    "MagnetInfo",
    "parse_magnet_uri",
    "filter_files_by_select_only",
    "create_magnet_from_torrent",
    # BEP 54 lt_donthave
    "LT_DONTHAVE_NAME",
    "LT_DONTHAVE_SUBOP",
    "encode_donthave",
    "decode_donthave",
    "create_donthave_message",
    "parse_donthave_from_extended",
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
