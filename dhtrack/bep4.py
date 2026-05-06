"""BEP-4: Assigned Numbers - BitTorrent Protocol Constants.

This module centralizes all bit allocations and message IDs defined in
BEP-4 (https://www.bittorrent.org/beps/bep_0004.html) for the BitTorrent
protocol.

Reserved Bit Allocations
========================

These constants represent flags in the 8 reserved bytes (reserved[0]-reserved[7])
of the BitTorrent peer wire handshake.

Core Protocol Message IDs
=========================

Standard peer wire protocol message types (BEP 3).

Fast Extension Message IDs
==========================

Additional message types for the fast extensions extension (BEP 6, BEP 16).

DHT Extension Message IDs
=========================

Message types used with BEP 6 (DHT support).

References
----------
- BEP-4: https://www.bittorrent.org/beps/bep_0004.html
- BEP-3: https://www.bittorrent.org/beps/bep_0003.html
- BEP-6: https://www.bittorrent.org/beps/bep_0006.html
- BEP-10: https://www.bittorrent.org/beps/bep_0010.html
"""

from __future__ import annotations

import struct
from typing import Optional


# ============================================================================
# Reserved Byte Constants (BEP-4)
# ============================================================================

# reserved[0] - Azureus Messaging Protocol
RESERVED_AZUREUS_MSG = 0x80  # Bit 7 (0x80) in reserved[0]

# reserved[2] - BitTorrent Location-aware Protocol (no known implementations)
RESERVED_LOCATION_AWARE = 0x08  # Bit 3 (0x08) in reserved[2]

# reserved[5] - Extension Protocol Bits
RESERVED_LTEP = 0x10  # Bit 4 (0x10) in reserved[5] - Libtorrent Extension Protocol
RESERVED_EXT_NEGOTIATION_HIGH = 0x02  # Bit 1 (0x02) in reserved[5] - Extension Negotiation
RESERVED_EXT_NEGOTIATION_LOW = 0x01  # Bit 0 (0x01) in reserved[5] - Extension Negotiation

# reserved[7] - DHT and Other Extensions
RESERVED_DHT = 0x01  # Bit 0 (0x01) in reserved[7] - BitTorrent DHT
RESERVED_PEER_EXCHANGE = 0x02  # Bit 1 (0x02) in reserved[7] - XBT Peer Exchange
RESERVED_FAST_EXTENSIONS = 0x04  # Bit 2 (0x04) in reserved[7] - Fast extensions
RESERVED_NAT_TRAVERSAL = 0x08  # Bit 3 (0x08) in reserved[7] - NAT Traversal
RESERVED_HYBRID_TORRENT_LEGACY = 0x10  # Bit 4 (0x10) in reserved[7] - Hybrid torrent legacy to v2 upgrade

# Known collision flags
RESERVED_BITCOMET_MSG = 0xFF  # reserved[0] - BitComet Extension Protocol
RESERVED_BITCOMET_EXT = 0xFF  # reserved[1] - BitComet Extension Protocol
RESERVED_XBT_METADATA_EXCHANGE = 0x01  # reserved[7] - XBT Metadata Exchange (known collision)

# BEP 10 support flag (Bit 2 in reserved[7])
RESERVED_BEP10 = 0x04

# ============================================================================
# BEP 3 - Core Protocol Message IDs
# ============================================================================

MSG_CHOKE = 0x00
MSG_UNCHOKE = 0x01
MSG_INTERESTED = 0x02
MSG_NOT_INTERESTED = 0x03
MSG_HAVE = 0x04
MSG_BITFIELD = 0x05
MSG_REQUEST = 0x06
MSG_PIECE = 0x07
MSG_CANCEL = 0x08

# ============================================================================
# BEP 6 - Fast Extensions Message IDs
# ============================================================================

MSG_PORT = 0x09  # BEP 6: DHT port (overrides BEP 3 default)

# These were part of BEP 6 (Extended) but BEP 16 (Fast Extension) defines:
MSG_SUGGEST = 0x0D  # BEP 16: Suggest
MSG_HAVE_ALL = 0x0E  # BEP 16: Have All
MSG_HAVE_NONE = 0x0F  # BEP 16: Have None
MSG_REJECT_REQUEST = 0x10  # BEP 16: Reject Request
MSG_ALLOWED_FAST = 0x11  # BEP 16: Allowed Fast

# ============================================================================
# BEP 10 - Extension Protocol (Deployed Extension Message IDs)
# ============================================================================

MSG_LTEP_HANDSHAKE = 0x14  # LTEP Handshake (deployed in libtorrent, uTorrent, etc.)

# ============================================================================
# Hash Transfer Protocol Message IDs
# ============================================================================

MSG_HASH_REQUEST = 0x15
MSG_HASH_REQUESTS = 0x16  # Note: BEP-4 uses "hashes" in the value
MSG_HASH_REJECT = 0x17

# ============================================================================
# Message Type Constants - Known Message IDs
# ============================================================================

# Set of all core protocol message IDs
CORE_MESSAGE_IDS = frozenset({
    MSG_CHOKE,
    MSG_UNCHOKE,
    MSG_INTERESTED,
    MSG_NOT_INTERESTED,
    MSG_HAVE,
    MSG_BITFIELD,
    MSG_REQUEST,
    MSG_PIECE,
    MSG_CANCEL,
})

# Set of all fast extension message IDs
FAST_EXTENSION_MESSAGE_IDS = frozenset({
    MSG_SUGGEST,
    MSG_HAVE_ALL,
    MSG_HAVE_NONE,
    MSG_REJECT_REQUEST,
    MSG_ALLOWED_FAST,
})

# Set of all DHT extension message IDs
DHT_EXTENSION_MESSAGE_IDS = frozenset({
    MSG_PORT,
})

# Set of all deployed extension message IDs
DEPLOYED_EXTENSION_MESSAGE_IDS = frozenset({
    MSG_LTEP_HANDSHAKE,
})

# Complete set of all known BitTorrent message IDs
ALL_KNOWN_MESSAGE_IDS = frozenset({
    *CORE_MESSAGE_IDS,
    *FAST_EXTENSION_MESSAGE_IDS,
    *DHT_EXTENSION_MESSAGE_IDS,
    *DEPLOYED_EXTENSION_MESSAGE_IDS,
})

# Message type names for display/debugging
MESSAGE_NAMES: dict[int, str] = {
    MSG_CHOKE: "choke",
    MSG_UNCHOKE: "unchoke",
    MSG_INTERESTED: "interested",
    MSG_NOT_INTERESTED: "not interested",
    MSG_HAVE: "have",
    MSG_BITFIELD: "bitfield",
    MSG_REQUEST: "request",
    MSG_PIECE: "piece",
    MSG_CANCEL: "cancel",
    MSG_PORT: "port",
    MSG_SUGGEST: "suggest",
    MSG_HAVE_ALL: "have all",
    MSG_HAVE_NONE: "have none",
    MSG_REJECT_REQUEST: "reject request",
    MSG_ALLOWED_FAST: "allowed fast",
    MSG_LTEP_HANDSHAKE: "ltep_handshake",
    MSG_HASH_REQUEST: "hash_request",
    MSG_HASH_REQUESTS: "hashes",
    MSG_HASH_REJECT: "hash_reject",
}


class BEP4Error(Exception):
    """Base exception for BEP-4 related errors."""


class InvalidReservedByteError(BEP4Error):
    """Raised when a reserved byte value is invalid."""


class InvalidMessageTypeError(BEP4Error):
    """Raised when a message type is invalid."""


def is_reserved_bit_set(reserved_byte: int, flag: int) -> bool:
    """Check if a specific flag is set in a reserved byte.

    Parameters
    ----------
    reserved_byte : int
        The byte value (0-255).
    flag : int
        The flag bit to check (must be a power of 2).

    Returns
    -------
    bool
        True if the flag is set.

    Raises
    ------
    InvalidReservedByteError
        If the parameters are out of valid range.
    """
    if not (0 <= reserved_byte <= 255):
        raise InvalidReservedByteError(
            f"reserved_byte must be 0-255, got {reserved_byte}"
        )
    if not (flag & (flag - 1) == 0) or flag == 0:
        raise InvalidReservedByteError(
            f"flag must be a power of 2, got {flag}"
        )
    return bool(reserved_byte & flag)


def set_reserved_bit(reserved_byte: int, flag: int) -> int:
    """Set a specific flag in a reserved byte.

    Parameters
    ----------
    reserved_byte : int
        The byte value (0-255).
    flag : int
        The flag bit to set (must be a power of 2).

    Returns
    -------
    int
        The new byte value with the flag set.

    Raises
    ------
    InvalidReservedByteError
        If the parameters are out of valid range.
    """
    if not (0 <= reserved_byte <= 255):
        raise InvalidReservedByteError(
            f"reserved_byte must be 0-255, got {reserved_byte}"
        )
    if not (flag & (flag - 1) == 0) or flag == 0:
        raise InvalidReservedByteError(
            f"flag must be a power of 2, got {flag}"
        )
    return reserved_byte | flag


def clear_reserved_bit(reserved_byte: int, flag: int) -> int:
    """Clear a specific flag in a reserved byte.

    Parameters
    ----------
    reserved_byte : int
        The byte value (0-255).
    flag : int
        The flag bit to clear (must be a power of 2).

    Returns
    -------
    int
        The new byte value with the flag cleared.

    Raises
    ------
    InvalidReservedByteError
        If the parameters are out of valid range.
    """
    if not (0 <= reserved_byte <= 255):
        raise InvalidReservedByteError(
            f"reserved_byte must be 0-255, got {reserved_byte}"
        )
    if not (flag & (flag - 1) == 0) or flag == 0:
        raise InvalidReservedByteError(
            f"flag must be a power of 2, got {flag}"
        )
    return reserved_byte & ~flag


def message_name(msg_type: int) -> str:
    """Get the human-readable name for a message type.

    Parameters
    ----------
    msg_type : int
        The message type code.

    Returns
    -------
    str
        The human-readable name, or "unknown (0x{msg_type:02x})" if not
        recognized.
    """
    return MESSAGE_NAMES.get(msg_type, f"unknown (0x{msg_type:02x})")


def is_valid_message_type(msg_type: int) -> bool:
    """Check if a message type is a known BitTorrent protocol message.

    Parameters
    ----------
    msg_type : int
        The message type code.

    Returns
    -------
    bool
        True if the message type is in the known set.
    """
    return msg_type in ALL_KNOWN_MESSAGE_IDS


def is_core_message(msg_type: int) -> bool:
    """Check if a message type is a core protocol message (BEP 3).

    Parameters
    ----------
    msg_type : int
        The message type code.

    Returns
    -------
    bool
        True if it is a core protocol message.
    """
    return msg_type in CORE_MESSAGE_IDS


def is_fast_extension_message(msg_type: int) -> bool:
    """Check if a message type is a fast extension message (BEP 6/16).

    Parameters
    ----------
    msg_type : int
        The message type code.

    Returns
    -------
    bool
        True if it is a fast extension message.
    """
    return msg_type in FAST_EXTENSION_MESSAGE_IDS


def is_dht_extension_message(msg_type: int) -> bool:
    """Check if a message type is a DHT extension message (BEP 6).

    Parameters
    ----------
    msg_type : int
        The message type code.

    Returns
    -------
    bool
        True if it is a DHT extension message.
    """
    return msg_type in DHT_EXTENSION_MESSAGE_IDS


def decode_reserved_bytes(reserved: bytes) -> dict[str, bool]:
    """Decode all 8 reserved bytes into named flags.

    Parameters
    ----------
    reserved : bytes
        8 bytes of reserved flags from the handshake.

    Returns
    -------
    dict[str, bool]
        Dictionary of flag names to boolean values.

    Raises
    ------
    InvalidReservedByteError
        If the reserved bytes are not exactly 8 bytes.
    """
    if len(reserved) != 8:
        raise InvalidReservedByteError(
            f"reserved bytes must be 8 bytes, got {len(reserved)}"
        )

    result: dict[str, bool] = {}

    # reserved[0]
    result["azureus_msg_protocol"] = is_reserved_bit_set(reserved[0], 0x80)

    # reserved[2]
    result["location_aware_protocol"] = is_reserved_bit_set(reserved[2], 0x08)

    # reserved[5]
    result["ltep"] = is_reserved_bit_set(reserved[5], 0x10)
    result["ext_negotiation"] = is_reserved_bit_set(reserved[5], 0x02) or \
        is_reserved_bit_set(reserved[5], 0x01)

    # reserved[7]
    result["dht"] = is_reserved_bit_set(reserved[7], 0x01)
    result["peer_exchange"] = is_reserved_bit_set(reserved[7], 0x02)
    result["fast_extensions"] = is_reserved_bit_set(reserved[7], 0x04)
    result["nat_traversal"] = is_reserved_bit_set(reserved[7], 0x08)
    result["hybrid_torrent_legacy"] = is_reserved_bit_set(reserved[7], 0x10)
    result["bep10"] = is_reserved_bit_set(reserved[7], 0x04)

    return result


def make_handshake_reserved(
    support_dht: bool = False,
    support_fast_extensions: bool = False,
    support_bep10: bool = False,
) -> bytes:
    """Create a standard reserved bytes array for the handshake.

    Parameters
    ----------
    support_dht : bool
        Set the DHT flag (reserved[7] bit 0).
    support_fast_extensions : bool
        Set the fast extensions flag (reserved[7] bit 2).
    support_bep10 : bool
        Set the BEP 10 flag (reserved[7] bit 2).

    Returns
    -------
    bytes
        8 bytes of reserved flags.
    """
    reserved = bytearray(8)

    if support_dht:
        reserved[7] = set_reserved_bit(reserved[7], RESERVED_DHT)

    if support_fast_extensions:
        reserved[7] = set_reserved_bit(reserved[7], RESERVED_FAST_EXTENSIONS)

    if support_bep10:
        reserved[7] = set_reserved_bit(reserved[7], RESERVED_BEP10)

    return bytes(reserved)