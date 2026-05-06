"""Peer connection management with extension protocol support (BEP 10, 9, 11, 55).

This module provides:
- ExtensionNegotiator: BEP 10 extension handshake and message negotiation
- MetadataExchange: BEP 9 metadata exchange for transferring torrent info
- PEXManager: BEP 11 peer exchange for discovering peers from peers
- HolePunchHandler: BEP 55 NAT holepunching for connecting to NATted peers
- PeerConnection: Full peer-to-peer connection with extension protocol
"""

from __future__ import annotations

import hashlib
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from dhtrack import bencode as bencode_module
from dhtrack.bencode import BEncodeValue
from dhtrack.peerid import Endpoint
from dhtrack.torrent import Torrent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BEP 3: Peer Wire Protocol constants
# ---------------------------------------------------------------------------

# Peer wire protocol message types (BEP 3)
MSG_CHOKE = 0
MSG_UNCHOKE = 1
MSG_INTERESTED = 2
MSG_NOT_INTERESTED = 3
MSG_HAVE = 4
MSG_BITFIELD = 5
MSG_REQUEST = 6
MSG_PIECE = 7
MSG_CANCEL = 8

# BEP 6 additional message types
MSG_PORT = 7  # BEP 6 (overrides BEP 3 default, use BEP 6 constants)
MSG_HAVE_ALL = 8
MSG_HAVE_NONE = 9
MSG_ALLOWED_FAST = 10
MSG_NOT_ALLOWED_FAST = 11
MSG_SATISFIED = 12

# BEP 6 alias
MSG_SATISFIED_ALT = 13

# Extended protocol message type (BEP 10)
EXTENSION_MSG_TYPE_HANDSHAKE = 0
EXTENSION_MSG_TYPE_MESSAGE = 1

# The protocol name used in extension handshakes
EXTENSION_NAME = b"BitTorrent protocol"

# Pre-handshake message identifier (used before extension protocol is established)
PRE_HANDSHAKE = b""

# Timeout for extension handshake in seconds
EXTENSION_HANDSHAKE_TIMEOUT = 30

# Maximum extended message payload size (64 KB)
MAX_EXTENDED_MESSAGE_SIZE = 65536

# BEP 3 defaults
# Maximum request size: 16 KB (de-facto standard, per BEP 3)
MAX_REQUEST_SIZE = 16384

# Default keepalive interval (seconds)
KEEPALIVE_INTERVAL = 120

# Maximum pending requests per peer
MAX_PENDING_REQUESTS = 100

# ---------------------------------------------------------------------------
# BEP 3 Peer Message Dataclass
# ---------------------------------------------------------------------------


@dataclass
class PeerMessage:
    """Represents a decoded peer wire protocol message (BEP 3).

    Attributes
    ----------
    msg_type : int
        The message type code (0-15).
    payload : bytes
        The raw payload bytes (may contain bencoded data).
    piece_index : int | None
        Piece index (for REQUEST, PIECE messages).
    begin : int
        Byte offset within the piece (for REQUEST, PIECE messages).
    length : int
        Request length (for REQUEST messages) or actual length of piece data.
    piece_data : bytes | None
        The actual piece data for MSG_PIECE messages.
    piece_bitmask : bytes | None
        The bitfield data for MSG_BITFIELD messages.
    """

    msg_type: int
    payload: bytes = b""
    piece_index: Optional[int] = None
    begin: int = 0
    length: int = 0
    piece_data: Optional[bytes] = None
    piece_bitmask: Optional[bytes] = None


def serialize_peer_message(msg_type: int, payload: bytes = b"") -> bytes:
    """Serialize a peer wire protocol message to wire format.

    Format: [4-byte length prefix][1-byte msg type][payload]
    For zero-length messages (keepalives), only the 4-byte prefix is sent.

    Parameters
    ----------
    msg_type : int
        The message type code (0-15).
    payload : bytes
        Optional payload data.

    Returns
    -------
    bytes
        The serialized message for TCP transmission.
    """
    if msg_type < 0 or msg_type > 255:
        raise ExtensionError(f"Invalid message type: {msg_type}")

    if len(payload) == 0:
        # Keepalive: just the length prefix (0)
        return struct.pack("!I", 0)

    # Length prefix = 1 (msg type) + len(payload)
    msg_len = 1 + len(payload)
    result = struct.pack("!I", msg_len)
    result += struct.pack("!B", msg_type)
    result += payload
    return result


def parse_peer_message(data: bytes) -> PeerMessage:
    """Parse an incoming peer wire protocol message (BEP 3).

    Parameters
    ----------
    data : bytes
        The raw bytes received from the peer (must contain a complete
        length-prefixed message).

    Returns
    -------
    PeerMessage
        The parsed message with type and payload.

    Raises
    ------
    ExtensionError
        If the message is malformed.
    """
    if len(data) < 4:
        raise ExtensionError(f"Message too short: {len(data)} bytes (need at least 4)")

    # Read length prefix
    msg_len = struct.unpack("!I", data[:4])[0]

    if msg_len == 0:
        # Keepalive
        return PeerMessage(msg_type=-1)  # -1 = keepalive

    if msg_len < 1 or msg_len > 0xFFFF:
        raise ExtensionError(f"Invalid message length: {msg_len}")

    if len(data) < 4 + msg_len:
        raise ExtensionError(
            f"Truncated message: expected {4 + msg_len} bytes, got {len(data)}"
        )

    payload = data[5:4 + msg_len]
    msg_type = data[4]

    msg = PeerMessage(msg_type=msg_type, payload=payload)

    # Decode type-specific fields
    if msg_type == MSG_REQUEST or msg_type == MSG_PIECE or msg_type == MSG_CANCEL:
        if len(payload) >= 12:
            idx, begin, length = struct.unpack("!III", payload[:12])
            msg.piece_index = idx
            msg.begin = begin
            msg.length = length
        if msg_type == MSG_PIECE and len(payload) > 12:
            msg.piece_data = payload[12:]

    elif msg_type == MSG_HAVE:
        if len(payload) >= 4:
            msg.piece_index = struct.unpack("!I", payload[:4])[0]

    elif msg_type == MSG_BITFIELD:
        msg.piece_bitmask = payload

    return msg


def create_handshake(
    info_hash: bytes,
    peer_id: bytes,
    reserved_bytes: bytes = b"\x00" * 8,
) -> bytes:
    """Create a BEP 3 peer handshake.

    Format: [1 byte length=19][8 byte protocol identifier][8 reserved bytes]
            [20 byte info hash][20 byte peer ID]

    Parameters
    ----------
    info_hash : bytes
        The 20-byte infohash of the torrent.
    peer_id : bytes
        The 20-byte peer ID.
    reserved_bytes : bytes
        8 reserved bytes for extension flags (default: all zeros).

    Returns
    -------
    bytes
        The full 68-byte handshake.

    Raises
    ------
    ExtensionError
        If info_hash or peer_id is not exactly 20 bytes.
    """
    if len(info_hash) != 20:
        raise ExtensionError(f"info_hash must be 20 bytes, got {len(info_hash)}")
    if len(peer_id) != 20:
        raise ExtensionError(f"peer_id must be 20 bytes, got {len(peer_id)}")

    protocol_str = b"\x10BitTorrent protocol"  # 19 bytes
    handshake = struct.pack("B", len(protocol_str)) + protocol_str
    handshake += reserved_bytes
    handshake += info_hash
    handshake += peer_id
    return handshake


def parse_handshake(data: bytes) -> tuple[bool, bytes, bytes, bytes]:
    """Parse an incoming BEP 3 peer handshake.

    Parameters
    ----------
    data : bytes
        The raw handshake bytes received from the peer.

    Returns
    -------
    tuple[bool, bytes, bytes, bytes]
        A tuple of (extensions_enabled, reserved_bytes, info_hash, peer_id).
        extensions_enabled is True if reserved_bytes[7] & 0x04 is set (BEP 10).

    Raises
    ------
    ExtensionError
        If the handshake is malformed.
    """
    expected_len = 1 + 19 + 8 + 20 + 20  # 68 bytes
    if len(data) < expected_len:
        raise ExtensionError(
            f"Handshake too short: expected {expected_len} bytes, got {len(data)}"
        )

    # Byte 0: length of protocol string (should be 19)
    pstrlen = data[0]
    if pstrlen != 19:
        raise ExtensionError(f"Invalid protocol string length: {pstrlen}")

    # Bytes 1-19: protocol identifier
    pstr = data[1:20]
    if pstr != EXTENSION_NAME:
        raise ExtensionError(f"Invalid protocol identifier: {pstr!r}")

    # Bytes 20-27: reserved bytes
    reserved_bytes = data[20:28]

    # Byte 7, bit 2 (0x04) indicates BEP 10 support
    extensions_enabled = bool(reserved_bytes[7] & 0x04)

    # Bytes 28-47: info hash
    info_hash = data[28:48]
    if len(info_hash) != 20:
        raise ExtensionError(f"Invalid info_hash: {len(info_hash)} bytes")

    # Bytes 48-67: peer ID
    peer_id = data[48:68]
    if len(peer_id) != 20:
        raise ExtensionError(f"Invalid peer_id: {len(peer_id)} bytes")

    return extensions_enabled, reserved_bytes, info_hash, peer_id

# ---------------------------------------------------------------------------
# BEP 9: Metadata Extension constants
# ---------------------------------------------------------------------------

UT_METADATA = b"ut_metadata"
UT_METADATA_HANDSHAKE = 0
UT_METADATA_DATA = 1
UT_METADATA_REJECT = 2
UT_METADATA_REQUEST = 3

# Maximum metadata size: 10 MB (DoS protection)
MAX_METADATA_SIZE = 10 * 1024 * 1024

# ---------------------------------------------------------------------------
# BEP 11: Peer Exchange constants
# ---------------------------------------------------------------------------

UT_PEX = b"ut_pex"

PEX_EVENT_NEW = 0x01
PEX_EVENT_REMOVE = 0x02

# Maximum peers in a single PEX message
MAX_PEX_PEERS = 50

# ---------------------------------------------------------------------------
# BEP 55: Hole Punching Extension constants
# ---------------------------------------------------------------------------

UT_HOLEPUNCH = b"ut_holepunch"

# Message types (BEP 55)
HOLEPUNCH_RENDEZVOUS = 0x00
HOLEPUNCH_CONNECT = 0x01
HOLEPUNCH_ERROR = 0x02

# Error codes (BEP 55)
HOLEPUNCH_ERR_NO_PEER = 0x01
HOLEPUNCH_ERR_NOT_CONNECTED = 0x02
HOLEPUNCH_ERR_NO_SUPPORT = 0x03
HOLEPUNCH_ERR_NO_SELF = 0x04

# Address types (BEP 55)
HOLEPUNCH_ADDR_IPV4 = 0x00
HOLEPUNCH_ADDR_IPV6 = 0x01

# Minimum and maximum message sizes
HOLEPUNCH_MSG_MIN_SIZE = 9   # 1 + 1 + 4 + 2 + 1 (min for ipv4, no err_code)
HOLEPUNCH_MSG_MIN_SIZE_V6 = 13  # 1 + 1 + 16 + 2 (ipv6, no err_code)
HOLEPUNCH_MSG_WITH_ERROR = 13  # 9 + 4 bytes err_code for ipv4
HOLEPUNCH_MSG_WITH_ERROR_V6 = 17  # 13 + 4 bytes err_code for ipv6


# ---------------------------------------------------------------------------
# BEP 55: Hole Punch binary payload encoding/decoding
# ---------------------------------------------------------------------------


def encode_holepunch_message(
    msg_type: int,
    target_ip: str,
    target_port: int,
    err_code: int = 0,
) -> bytes:
    """Encode a BEP 55 holepunch message payload.

    Binary format:
        msg_type (1 byte)
        addr_type (1 byte): 0x00 for IPv4, 0x01 for IPv6
        addr (4 bytes for IPv4, 16 bytes for IPv6)
        port (2 bytes, big-endian)
        err_code (4 bytes, big-endian, only in error messages)

    Parameters
    ----------
    msg_type : int
        Message type: HOLEPUNCH_RENDEZVOUS (0x00), HOLEPUNCH_CONNECT (0x01),
        or HOLEPUNCH_ERROR (0x02).
    target_ip : str
        Target IP address (IPv4 or IPv6).
    target_port : int
        Target port number (0-65535).
    err_code : int
        Error code (only used when msg_type is HOLEPUNCH_ERROR).

    Returns
    -------
    bytes
        Encoded binary payload.

    Raises
    ------
    ExtensionError
        If the message is malformed.
    """
    if msg_type not in (HOLEPUNCH_RENDEZVOUS, HOLEPUNCH_CONNECT, HOLEPUNCH_ERROR):
        raise ExtensionError(f"Invalid holepunch message type: {msg_type}")

    if target_port < 0 or target_port > 65535:
        raise ExtensionError(f"Invalid port number: {target_port}")

    # Determine address type from IP string
    try:
        # Try IPv4 first
        addr_bytes = socket.inet_aton(target_ip)
        addr_type = HOLEPUNCH_ADDR_IPV4
    except OSError:
        try:
            addr_bytes = socket.inet_pton(socket.AF_INET6, target_ip)
            addr_type = HOLEPUNCH_ADDR_IPV6
        except OSError:
            raise ExtensionError(f"Invalid IP address: {target_ip}")

    payload = bytearray()
    payload.append(msg_type)
    payload.append(addr_type)
    payload.extend(addr_bytes)
    payload.extend(struct.pack("!H", target_port))

    if msg_type == HOLEPUNCH_ERROR:
        payload.extend(struct.pack("!I", err_code))

    return bytes(payload)


def decode_holepunch_message(data: bytes) -> dict[str, Any]:
    """Decode a BEP 55 holepunch message payload.

    Parameters
    ----------
    data : bytes
        The binary payload bytes.

    Returns
    -------
    dict[str, Any]
        Dictionary with keys: msg_type, addr_type, ip, port, err_code.

    Raises
    ------
    ExtensionError
        If the message is malformed.
    """
    if len(data) < 7:
        raise ExtensionError(f"Holepunch message too short: {len(data)} bytes (minimum 7)")

    msg_type = data[0]
    if msg_type not in (HOLEPUNCH_RENDEZVOUS, HOLEPUNCH_CONNECT, HOLEPUNCH_ERROR):
        raise ExtensionError(f"Invalid holepunch message type: {msg_type}")

    addr_type = data[1]
    if addr_type not in (HOLEPUNCH_ADDR_IPV4, HOLEPUNCH_ADDR_IPV6):
        raise ExtensionError(f"Invalid holepunch address type: {addr_type}")

    if addr_type == HOLEPUNCH_ADDR_IPV4:
        # IPv4: msg_type(1) + addr_type(1) + ip(4) + port(2) = 8 bytes
        if len(data) < 8:
            raise ExtensionError(
                f"IPv4 holepunch message too short: {len(data)} bytes (minimum 8)"
            )
        ip = socket.inet_ntop(socket.AF_INET, data[2:6])
        port = struct.unpack("!H", data[6:8])[0]
        err_code = 0
        if msg_type == HOLEPUNCH_ERROR and len(data) >= 12:
            err_code = struct.unpack("!I", data[8:12])[0]
    else:  # IPv6
        # IPv6: msg_type(1) + addr_type(1) + ip(16) + port(2) = 20 bytes
        if len(data) < 20:
            raise ExtensionError(
                f"IPv6 holepunch message too short: {len(data)} bytes (minimum 20)"
            )
        ip = socket.inet_ntop(socket.AF_INET6, data[2:18])
        port = struct.unpack("!H", data[18:20])[0]
        err_code = 0
        if msg_type == HOLEPUNCH_ERROR and len(data) >= 24:
            err_code = struct.unpack("!I", data[20:24])[0]

    result: dict[str, Any] = {
        "msg_type": msg_type,
        "addr_type": addr_type,
        "ip": ip,
        "port": port,
    }

    if msg_type == HOLEPUNCH_ERROR:
        result["err_code"] = err_code

    return result


# ---------------------------------------------------------------------------
# Extension Protocol Errors
# ---------------------------------------------------------------------------


class ExtensionError(Exception):
    """Base exception for extension protocol errors."""


class ExtensionHandshakeError(ExtensionError):
    """Raised when extension handshake fails."""


class MetadataExchangeError(ExtensionError):
    """Raised when metadata exchange fails."""


class PEXError(ExtensionError):
    """Raised when PEX processing fails."""


# ---------------------------------------------------------------------------
# ExtensionNegotiator (BEP 10)
# ---------------------------------------------------------------------------


@dataclass
class ExtensionNegotiator:
    """Negotiates extensions with a remote peer (BEP 10).

    Attributes
    ----------
    client_version : str
        This client's version string (e.g., "dh01").
    negotiated_extensions : set[bytes]
        Extensions successfully negotiated with the peer.
    peer_version : str
        The peer's version string.
    peer_extensions : set[bytes]
        Extensions reported by the peer.
    handshake_sent_time : float
        Timestamp when handshake was sent (for timeout).
    """

    client_version: str = "dh01"
    negotiated_extensions: set[bytes] = field(default_factory=set)
    peer_version: str = ""
    peer_extensions: set[bytes] = field(default_factory=set)
    handshake_sent_time: float = field(default_factory=time.time)
    handshake_complete: bool = False

    # Supported extensions (ordered by preference)
    SUPPORTED_EXTENSIONS: list[bytes] = field(
        default_factory=lambda: [UT_METADATA, UT_PEX, UT_HOLEPUNCH]
    )

    def create_handshake(self) -> bytes:
        """Create the extension handshake message payload.

        Returns
        -------
        bytes
            Bencoded handshake dictionary with supported extensions
            and client version.

        Examples
        --------
        >>> negotiator = ExtensionNegotiator()
        >>> handshake = negotiator.create_handshake()
        >>> bencode_module.decode(handshake)
        {'m': [b'ut_metadata', b'ut_pex', b'ut_holepunch'], 'v': b'dh01'}
        """
        return bencode_module.encode({
            "m": [ext.decode("utf-8", errors="replace") for ext in self.SUPPORTED_EXTENSIONS],
            "v": self.client_version,
        })

    def parse_handshake(self, data: bytes) -> bool:
        """Parse an extension handshake response from a peer.

        Determines which extensions both this client and the peer support
        by comparing the extension lists.

        Parameters
        ----------
        data : bytes
            Bencoded handshake response from the peer.

        Returns
        -------
        bool
            True if at least one common extension is found, False otherwise.

        Raises
        ------
        ExtensionHandshakeError
            If the handshake data is malformed.
        """
        try:
            parsed = bencode_module.decode(data)
        except Exception as exc:
            raise ExtensionHandshakeError(f"Failed to decode handshake: {exc}") from exc

        if not isinstance(parsed, dict):
            raise ExtensionHandshakeError("Handshake is not a dictionary")

        # Extract peer version
        v = parsed.get(b"v" if isinstance(parsed.get(b"v"), bytes) else "v", b"")
        if isinstance(v, bytes):
            self.peer_version = v.decode("utf-8", errors="replace")
        else:
            self.peer_version = str(v) if v else ""

        # Extract peer extensions
        m = parsed.get(b"m" if isinstance(parsed.get(b"m"), bytes) else "m", [])
        if isinstance(m, list):
            self.peer_extensions = {
                ext.encode("utf-8") if isinstance(ext, str) else ext
                for ext in m
            }

        # Determine common extensions
        for ext in self.SUPPORTED_EXTENSIONS:
            if ext in self.peer_extensions:
                self.negotiated_extensions.add(ext)
                logger.debug("Negotiated extension: %s", ext)

        self.handshake_complete = True
        return bool(self.negotiated_extensions)

    def send_extended_message(self, msg_type: int, payload: dict[str, Any]) -> bytes:
        """Create an extended message payload (BEP 10).

        Constructs the byte-level message format:
            Byte 0: 0 (extended message type)
            Byte 1-2: payload_length (big-endian uint16)
            Byte 3: msg_type
            Byte 4+: bencoded payload

        Parameters
        ----------
        msg_type : int
            Message type: 0 = handshake, 1 = message.
        payload : dict[str, Any]
            The message payload dictionary.

        Returns
        -------
        bytes
            Complete extended message ready for transmission.

        Raises
        ------
        ExtensionError
            If the payload exceeds the maximum extended message size.
        """
        if msg_type not in (EXTENSION_MSG_TYPE_HANDSHAKE, EXTENSION_MSG_TYPE_MESSAGE):
            raise ExtensionError(f"Invalid message type: {msg_type}")

        # Encode the payload
        m_val = payload.get("m", b"")
        if isinstance(m_val, bytes):
            m_val = m_val.decode("utf-8", errors="replace")
        encoded_payload = bencode_module.encode({
            "m": m_val,
            **{k: v for k, v in payload.items() if k != "m"},
        })

        # Check payload size
        if len(encoded_payload) > MAX_EXTENDED_MESSAGE_SIZE:
            raise ExtensionError(
                f"Payload exceeds maximum size: {len(encoded_payload)} > {MAX_EXTENDED_MESSAGE_SIZE}"
            )

        # Build the extended message
        message = bytearray()
        message.append(0)  # message_type = 0 (extended message)
        message.extend(struct.pack("!H", len(encoded_payload)))  # payload length
        message.append(msg_type)  # msg_type
        message.extend(encoded_payload)

        return bytes(message)

    def parse_extended_message(self, data: bytes) -> tuple[int, dict[str, Any]]:
        """Parse an incoming extended message (BEP 10).

        Parameters
        ----------
        data : bytes
            The raw extended message bytes.

        Returns
        -------
        tuple[int, dict[str, Any]]
            A tuple of (msg_type, payload_dict).

        Raises
        ------
        ExtensionError
            If the message is malformed or exceeds maximum size.
        """
        if len(data) < 4:
            raise ExtensionError(f"Extended message too short: {len(data)} bytes")

        # Byte 0 should be 0 (extended message)
        msg_type_byte = data[0]
        if msg_type_byte != 0:
            raise ExtensionError(f"Not an extended message: type={msg_type_byte}")

        # Bytes 1-2: payload length
        payload_length = struct.unpack("!H", data[1:3])[0]

        if payload_length > MAX_EXTENDED_MESSAGE_SIZE:
            raise ExtensionError(
                f"Payload too large: {payload_length} > {MAX_EXTENDED_MESSAGE_SIZE}"
            )

        if len(data) < 4 + payload_length:
            raise ExtensionError(
                f"Message truncated: expected {4 + payload_length} bytes, got {len(data)}"
            )

        # Byte 3: msg_type
        msg_type = data[3]

        # Payload
        payload_bytes = data[4:4 + payload_length]
        try:
            payload = bencode_module.decode(payload_bytes)
        except Exception as exc:
            raise ExtensionError(f"Failed to decode payload: {exc}") from exc

        if not isinstance(payload, dict):
            raise ExtensionError("Payload is not a dictionary")

        return msg_type, payload

    def is_timed_out(self) -> bool:
        """Check if the handshake has timed out.

        Returns
        -------
        bool
            True if more than EXTENSION_HANDSHAKE_TIMEOUT seconds have
            elapsed since the handshake was sent.
        """
        return time.time() - self.handshake_sent_time > EXTENSION_HANDSHAKE_TIMEOUT

    def reset_handshake_timer(self) -> None:
        """Reset the handshake timeout timer."""
        self.handshake_sent_time = time.time()

    def supports_extension(self, extension: bytes) -> bool:
        """Check if an extension has been negotiated with the peer.

        Parameters
        ----------
        extension : bytes
            The extension name to check.

        Returns
        -------
        bool
            True if the extension is in the negotiated set.
        """
        return extension in self.negotiated_extensions


# ---------------------------------------------------------------------------
# MetadataExchange (BEP 9)
# ---------------------------------------------------------------------------


@dataclass
class MetadataExchange:
    """Handles BEP 9 metadata exchange between peers.

    Attributes
    ----------
    torrent : Torrent
        The torrent being exchanged.
    block_size : int
        Size of each metadata block (16 KB default).
    pending_requests : dict[bytes, list]
        Pending piece requests keyed by request ID.
    complete_parts : dict[bytes, list]
        Received piece data keyed by request ID.
    total_pieces : int
        Total number of pieces in the metadata.
    piece_length : int
        Size of each piece in the metadata.
    """

    torrent: Torrent
    block_size: int = 16384  # 16 KB per piece (BEP 9 default)
    pending_requests: dict[bytes, list] = field(default_factory=dict)
    complete_parts: dict[bytes, list] = field(default_factory=dict)
    total_pieces: int = 0
    piece_length: int = 0
    _info_hash: bytes = field(default_factory=lambda: b"")

    def __post_init__(self) -> None:
        """Initialize from torrent metadata."""
        self._info_hash = self.torrent.infohash
        info = self.torrent.info
        if isinstance(info, dict):
            # Try various key formats for piece data
            piece_data = None
            for key in [b"piece", "piece"]:
                val = info.get(key)
                if val:
                    piece_data = val
                    break
            if piece_data:
                self.total_pieces = len(piece_data)
            # Try various key formats for piece length
            for key in [b"piece length", "piece length"]:
                pl = info.get(key)
                if isinstance(pl, int):
                    self.piece_length = pl
                    break
        elif isinstance(info, bytes):
            # Raw bytes - try to decode
            try:
                decoded = bencode_module.decode(info)
                if isinstance(decoded, dict):
                    for key in [b"piece", "piece"]:
                        val = decoded.get(key)
                        if val:
                            self.total_pieces = len(val)
                            break
                    for key in [b"piece length", "piece length"]:
                        pl = decoded.get(key)
                        if isinstance(pl, int):
                            self.piece_length = pl
                            break
            except Exception:
                pass

        if self.total_pieces > 0:
            # Initialize complete_parts for each peer_id seen
            pass

    def get_handshake(self) -> bytes:
        """Create a metadata exchange handshake (BEP 9, msg_type=0).

        Returns
        -------
        bytes
            Bencoded handshake with total_size and piece_length.
        """
        return bencode_module.encode({
            "msg_type": UT_METADATA_HANDSHAKE,
            "total_size": self._get_total_size(),
            "piece_length": self.piece_length,
        })

    def handle_handshake(self, data: bytes, negotiator: ExtensionNegotiator) -> bool:
        """Handle an incoming metadata handshake.

        Parameters
        ----------
        data : bytes
            Bencoded handshake data from the peer.
        negotiator : ExtensionNegotiator
            The extension negotiator to check for ut_metadata support.

        Returns
        -------
        bool
            True if the peer supports metadata exchange.
        """
        try:
            parsed = bencode_module.decode(data)
        except Exception:
            return False

        if not isinstance(parsed, dict):
            return False

        msg_type = parsed.get("msg_type")
        if msg_type == UT_METADATA_HANDSHAKE:
            return negotiator.supports_extension(UT_METADATA)

        return False

    def create_request(self, piece_index: int, request_id: bytes) -> bytes:
        """Create a metadata request message (BEP 9, msg_type=3).

        Parameters
        ----------
        piece_index : int
            The piece index to request.
        request_id : bytes
            A unique request identifier.

        Returns
        -------
        bytes
            Bencoded request message.
        """
        if piece_index < 0 or piece_index >= self.total_pieces:
            raise MetadataExchangeError(
                f"Invalid piece index: {piece_index} (total: {self.total_pieces})"
            )

        self.pending_requests[request_id] = [piece_index, 0]  # [piece_index, offset]

        return bencode_module.encode({
            "msg_type": UT_METADATA_REQUEST,
            "piece": piece_index,
            "reqid": request_id,
        })

    def handle_data(self, data: bytes, peer_id: bytes = b"") -> bool:
        """Handle an incoming metadata data piece (BEP 9, msg_type=1).

        Accumulates piece data and verifies when the complete metadata
        is received.

        Parameters
        ----------
        data : bytes
            Bencoded data piece from the peer.
        peer_id : bytes
            Peer identifier for tracking piece data per peer.

        Returns
        -------
        bool
            True if the complete metadata has been received and verified,
            False otherwise.

        Raises
        ------
        MetadataExchangeError
            If the data message is malformed.
        """
        try:
            parsed = bencode_module.decode(data)
        except Exception as exc:
            raise MetadataExchangeError(f"Failed to decode metadata data: {exc}") from exc

        if not isinstance(parsed, dict):
            raise MetadataExchangeError("Metadata data is not a dictionary")

        msg_type = parsed.get("msg_type")
        if msg_type != UT_METADATA_DATA:
            raise MetadataExchangeError(
                f"Expected msg_type {UT_METADATA_DATA}, got {msg_type}"
            )

        piece = parsed.get("piece", 0)
        begin = parsed.get("begin", 0)
        buffer = parsed.get("buffer", b"")

        if not isinstance(piece, int) or piece < 0:
            raise MetadataExchangeError(f"Invalid piece index: {piece}")

        if not isinstance(begin, int) or begin < 0:
            raise MetadataExchangeError(f"Invalid begin offset: {begin}")

        if not isinstance(buffer, bytes):
            raise MetadataExchangeError("Buffer is not bytes")

        # Initialize piece list for this peer if needed
        if not peer_id:
            peer_id = hash(data)  # Use data hash as peer identifier
        if isinstance(peer_id, int):
            peer_id = str(peer_id).encode()

        if peer_id not in self.complete_parts:
            self.complete_parts[peer_id] = [None] * self.total_pieces

        # Store the piece data
        self.complete_parts[peer_id][piece] = buffer

        # Check if we have all pieces
        if all(p is not None for p in self.complete_parts[peer_id]):
            full_metadata = b"".join(
                p for p in self.complete_parts[peer_id] if p is not None
            )
            return self.verify_metadata(full_metadata)

        return False

    def handle_reject(self, data: bytes) -> None:
        """Handle an incoming metadata reject message (BEP 9, msg_type=2).

        Parameters
        ----------
        data : bytes
            Bencoded reject message.
        """
        try:
            parsed = bencode_module.decode(data)
        except Exception:
            logger.debug("Failed to decode metadata reject message")
            return

        piece = parsed.get("piece", -1)
        logger.debug("Metadata piece %d rejected", piece)

    def verify_metadata(self, full_metadata: bytes) -> bool:
        """Verify collected metadata matches torrent info hash.

        BEncodes the info dictionary from the metadata and computes
        SHA-1. The result should match the torrent's infohash.

        Parameters
        ----------
        full_metadata : bytes
            The complete metadata as raw bytes.

        Returns
        -------
        bool
            True if the infohash matches, False otherwise.
        """
        try:
            metadata_dict = bencode_module.decode(full_metadata)
            if not isinstance(metadata_dict, dict):
                return False

            info = None
            for k in metadata_dict:
                if isinstance(k, bytes) and k.lower() == b"info" or (isinstance(k, str) and k.lower() == "info"):
                    info = metadata_dict[k]
                    break

            if info is None:
                return False

            info_hash = hashlib.sha1(bencode_module.encode(info)).digest()
            return info_hash == self._info_hash
        except Exception as exc:
            logger.debug("Failed to verify metadata: %s", exc)
            return False

    def _get_total_size(self) -> int:
        """Get the total metadata size in bytes."""
        if self.piece_length > 0 and self.total_pieces > 0:
            return self.piece_length * self.total_pieces
        return 0


# ---------------------------------------------------------------------------
# PEXManager (BEP 11)
# ---------------------------------------------------------------------------


@dataclass
class PEXManager:
    """Handles BEP 11 peer exchange.

    Attributes
    ----------
    info_hash : bytes
        The torrent infohash.
    my_node_id : bytes
        This node's 20-byte node ID.
    known_peers : set[Endpoint]
        All known peers.
    recent_peers : set[Endpoint]
        Peers received recently (not yet sent in PEX).
    pex_sent : set[bytes]
        Peer IDs we've already sent PEX to.
    """

    info_hash: bytes
    my_node_id: bytes
    known_peers: set[Endpoint] = field(default_factory=set)
    recent_peers: set[Endpoint] = field(default_factory=set)
    pex_sent: set[bytes] = field(default_factory=set)

    def create_pex_message(
        self,
        new_peers: Optional[list[Endpoint]] = None,
        removed_peers: Optional[list[Endpoint]] = None,
        direction: int = PEX_EVENT_NEW,
    ) -> bytes:
        """Create a PEX message (BEP 11).

        Parameters
        ----------
        new_peers : list of Endpoint, optional
            New peers to include in the message.
        removed_peers : list of Endpoint, optional
            Peers to remove from the message.
        direction : int
            PEX_EVENT_NEW (0x01) for new peers, PEX_EVENT_REMOVE (0x02) for removals.

        Returns
        -------
        bytes
            Bencoded PEX message with "m" extension name and peer lists.
        """
        new_peers = new_peers or []
        removed_peers = removed_peers or []

        # Format peer data
        formatted_new = self._format_peers(new_peers)
        formatted_removed = self._format_peers(removed_peers)

        return bencode_module.encode({
            "m": [UT_PEX.decode("utf-8")],
            "peers": formatted_new,
            "peers.s": formatted_removed,
            "events": direction,
        })

    def parse_pex_message(self, data: bytes) -> tuple[list[Endpoint], list[Endpoint], int]:
        """Parse an incoming PEX message (BEP 11).

        Parameters
        ----------
        data : bytes
            Bencoded PEX message.

        Returns
        -------
        tuple[list[Endpoint], list[Endpoint], int]
            A tuple of (new_peers, removed_peers, events_bitfield).

        Raises
        ------
        PEXError
            If the message is malformed.
        """
        try:
            parsed = bencode_module.decode(data)
        except Exception as exc:
            raise PEXError(f"Failed to decode PEX message: {exc}") from exc

        if not isinstance(parsed, dict):
            raise PEXError("PEX message is not a dictionary")

        # Extract events bitfield
        events = parsed.get("events", 0)
        if isinstance(events, bytes):
            events = struct.unpack("!B", events)[0]

        # Extract new peers
        new_peers = []
        peers_data = parsed.get("peers", parsed.get(b"peers", []))
        if isinstance(peers_data, list):
            for peer_data in peers_data:
                peer = self._parse_peer(peer_data)
                if peer:
                    new_peers.append(peer)

        # Extract removed peers
        removed_peers = []
        removed_data = parsed.get("peers.s", parsed.get(b"peers.s", []))
        if isinstance(removed_data, list):
            for peer_data in removed_data:
                peer = self._parse_peer(peer_data)
                if peer:
                    removed_peers.append(peer)

        return new_peers, removed_peers, events

    def add_peer(self, peer: Endpoint) -> None:
        """Add a peer to the known peers set.

        Parameters
        ----------
        peer : Endpoint
            The peer to add.
        """
        self.known_peers.add(peer)
        self.recent_peers.add(peer)

    def clear_recent_peers(self) -> None:
        """Clear the recent peers set after PEX has been sent."""
        self.recent_peers.clear()

    def _format_peers(self, peers: list[Endpoint]) -> list[dict[str, Any]]:
        """Format peers for PEX message.

        Parameters
        ----------
        peers : list of Endpoint
            The peers to format.

        Returns
        -------
        list of dict
            Formatted peer data for bencoding.
        """
        formatted = []
        for peer in peers:
            if peer.is_ipv6:
                ip_bytes = socket.inet_pton(socket.AF_INET6, peer.ip)
            else:
                ip_bytes = socket.inet_aton(peer.ip)

            formatted.append({
                "ip": ip_bytes,
                "port": peer.port.to_bytes(2, "big"),
                "id": peer.node_id or b"",
            })
        return formatted

    def _parse_peer(self, peer_data: Any) -> Optional[Endpoint]:
        """Parse a peer from PEX data.

        Parameters
        ----------
        peer_data : Any
            The peer data from the PEX message.

        Returns
        -------
        Endpoint or None
            The parsed endpoint, or None if parsing fails.
        """
        if not isinstance(peer_data, dict):
            return None

        try:
            ip_data = None
            for key in [b"ip", "ip"]:
                val = peer_data.get(key)
                if val is not None:
                    ip_data = val
                    break

            if ip_data is None or not isinstance(ip_data, bytes):
                return None

            # Try IPv4 first
            if len(ip_data) == 4:
                ip = socket.inet_ntop(socket.AF_INET, ip_data)
                is_ipv6 = False
            elif len(ip_data) == 16:
                ip = socket.inet_ntop(socket.AF_INET6, ip_data)
                is_ipv6 = True
            else:
                return None

            port_data = None
            for key in [b"port", "port"]:
                val = peer_data.get(key)
                if val is not None:
                    port_data = val
                    break

            if isinstance(port_data, bytes):
                port = struct.unpack("!H", port_data)[0]
            elif isinstance(port_data, int):
                port = port_data
            else:
                return None

            node_id_data = None
            for key in [b"id", "id"]:
                val = peer_data.get(key)
                if val is not None:
                    node_id_data = val
                    break

            if isinstance(node_id_data, str):
                node_id_data = node_id_data.encode("latin-1")
            node_id = node_id_data if isinstance(node_id_data, bytes) else b""

            return Endpoint(ip=ip, port=port, is_ipv6=is_ipv6, node_id=node_id)
        except (socket.error, struct.error, ValueError) as exc:
            logger.debug("Failed to parse PEX peer: %s", exc)
            return None


# ---------------------------------------------------------------------------
# HolePunchHandler (BEP 55)
# ---------------------------------------------------------------------------


@dataclass
class HolePunchHandler:
    """Handles BEP 55 NAT holepunching.

    The holepunch protocol enables peers behind NAT/firewall to connect
    via a relaying peer. The flow is:

    1. Initiating peer sends rendezvous to relay (with target's endpoint)
    2. Relay sends connect to both peers
    3. Both peers initiate uTP connection to each other

    Attributes
    ----------
    peer_id : bytes
        This peer's 20-byte peer ID.
    endpoint : Endpoint
        This peer's network endpoint.
    pending_requests : dict[bytes, dict]
        Pending holepunch requests keyed by request ID.
    on_holepunch_connect : callable or None
        Callback invoked when a CONNECT message is received.
        Signature: ``callback(target_ip, target_port, is_ipv6)``
    """

    peer_id: bytes = field(default_factory=lambda: b"")
    endpoint: Optional[Endpoint] = None
    pending_requests: dict[bytes, dict] = field(default_factory=dict)
    on_holepunch_connect: Optional[Any] = None

    def create_rendezvous_message(
        self,
        target_ip: str,
        target_port: int,
    ) -> bytes:
        """Create a BEP 55 rendezvous message payload.

        Sent by the initiating peer to the relaying peer, requesting
        a connection to the target peer.

        Parameters
        ----------
        target_ip : str
            Target peer's IP address (IPv4 or IPv6).
        target_port : int
            Target peer's port number.

        Returns
        -------
        bytes
            Binary rendezvous message payload.

        Raises
        ------
        ExtensionError
            If parameters are invalid.
        """
        return encode_holepunch_message(
            HOLEPUNCH_RENDEZVOUS, target_ip, target_port
        )

    def create_connect_message(
        self,
        peer_ip: str,
        peer_port: int,
    ) -> bytes:
        """Create a BEP 55 connect message payload.

        Sent to both peers to instruct them to connect to each other.

        Parameters
        ----------
        peer_ip : str
            The peer IP to connect to.
        peer_port : int
            The peer port to connect to.

        Returns
        -------
        bytes
            Binary connect message payload.

        Raises
        ------
        ExtensionError
            If parameters are invalid.
        """
        return encode_holepunch_message(
            HOLEPUNCH_CONNECT, peer_ip, peer_port
        )

    def create_error_message(
        self,
        target_ip: str,
        target_port: int,
        err_code: int,
    ) -> bytes:
        """Create a BEP 55 error message payload.

        Sent when a rendezvous or connect request cannot be fulfilled.

        Parameters
        ----------
        target_ip : str
            The endpoint that caused the error (echoed back).
        target_port : int
            The port that caused the error (echoed back).
        err_code : int
            Error code: HOLEPUNCH_ERR_NO_PEER, HOLEPUNCH_ERR_NOT_CONNECTED,
            HOLEPUNCH_ERR_NO_SUPPORT, or HOLEPUNCH_ERR_NO_SELF.

        Returns
        -------
        bytes
            Binary error message payload.

        Raises
        ------
        ExtensionError
            If parameters are invalid.
        """
        return encode_holepunch_message(
            HOLEPUNCH_ERROR, target_ip, target_port, err_code
        )

    def handle_rendezvous(self, data: bytes) -> tuple[dict[str, Any], Optional[bytes]]:
        """Handle an incoming rendezvous message.

        Parses the rendezvous message and returns the decoded data.
        The caller should check if connected to the target peer and
        send a connect message back, or an error if not possible.

        Parameters
        ----------
        data : bytes
            The raw binary rendezvous message.

        Returns
        -------
        tuple[dict[str, Any], Optional[bytes]]
            A tuple of (decoded_data, response_message).
            response_message is None if no response needed (caller handles).
            decoded_data contains ip, port of the target peer.

        Raises
        ------
        ExtensionError
            If the message is malformed.
        """
        decoded = decode_holepunch_message(data)

        if decoded["msg_type"] != HOLEPUNCH_RENDEZVOUS:
            raise ExtensionError(
                f"Expected rendezvous message, got type {decoded['msg_type']}"
            )

        return decoded, None

    def handle_connect(self, data: bytes) -> dict[str, Any]:
        """Handle an incoming connect message.

        Parses the connect message and invokes the on_holepunch_connect
        callback if set.

        Parameters
        ----------
        data : bytes
            The raw binary connect message.

        Returns
        -------
        dict[str, Any]
            Decoded message data with ip, port keys.

        Raises
        ------
        ExtensionError
            If the message is malformed.
        """
        decoded = decode_holepunch_message(data)

        if decoded["msg_type"] != HOLEPUNCH_CONNECT:
            raise ExtensionError(
                f"Expected connect message, got type {decoded['msg_type']}"
            )

        # Invoke callback if set
        if self.on_holepunch_connect:
            is_ipv6 = decoded["addr_type"] == HOLEPUNCH_ADDR_IPV6
            try:
                self.on_holepunch_connect(decoded["ip"], decoded["port"], is_ipv6)
            except Exception as exc:
                logger.debug("Error in on_holepunch_connect callback: %s", exc)

        return decoded

    def handle_error(self, data: bytes) -> dict[str, Any]:
        """Handle an incoming error message.

        Parses the error message and stores the result in pending_requests.

        Parameters
        ----------
        data : bytes
            The raw binary error message.

        Returns
        -------
        dict[str, Any]
            Decoded message data with ip, port, err_code keys.

        Raises
        ------
        ExtensionError
            If the message is malformed.
        """
        decoded = decode_holepunch_message(data)

        if decoded["msg_type"] != HOLEPUNCH_ERROR:
            raise ExtensionError(
                f"Expected error message, got type {decoded['msg_type']}"
            )

        return decoded

    def is_self_address(self, ip: str, port: int) -> bool:
        """Check if the given address belongs to this peer.

        Parameters
        ----------
        ip : str
            IP address to check.
        port : int
            Port to check.

        Returns
        -------
        bool
            True if the address matches this peer's endpoint.
        """
        if self.endpoint is None:
            return False
        return self.endpoint.ip == ip and self.endpoint.port == port


# ---------------------------------------------------------------------------
# PeerConnection
# ---------------------------------------------------------------------------


@dataclass
class PeerConnection:
    """Manages a peer-to-peer connection with extension protocol support.

    Attributes
    ----------
    peer_id : bytes
        The remote peer's 20-byte peer ID.
    endpoint : Endpoint
        The network endpoint of the peer.
    info_hash : bytes
        The torrent infohash for this connection.
    negotiator : ExtensionNegotiator
        Extension negotiation state.
    metadata_exchange : MetadataExchange
        Metadata exchange state (if torrent is provided).
    pex_manager : PEXManager
        PEX state for the connection.
    holepunch_handler : HolePunchHandler
        Holepunch state for the connection.
    is_initiator : bool
        Whether this side initiated the connection.
    connected : bool
        Whether the connection is fully established.
    extended_enabled : bool
        Whether the extended protocol has been negotiated.
    handshake_done : bool
        Whether the extension handshake has been completed.
    choked : bool
        Whether this side is choked (cannot send data).
    peer_choked : bool
        Whether the remote peer is choked.
    interested : bool
        Whether this side is interested.
    peer_interested : bool
        Whether the remote peer is interested.
    has_all : bool
        Whether this side has all pieces.
    pending_requests : list[dict]
        Pending piece requests.
    send_buffer : bytearray
        Buffer for outgoing data.
    """

    peer_id: bytes
    endpoint: Endpoint
    info_hash: bytes = field(default_factory=lambda: b"")
    negotiator: ExtensionNegotiator = field(default_factory=ExtensionNegotiator)
    metadata_exchange: Optional[MetadataExchange] = None
    pex_manager: Optional[PEXManager] = None
    holepunch_handler: Optional[HolePunchHandler] = None
    is_initiator: bool = True
    connected: bool = False
    extended_enabled: bool = False
    handshake_done: bool = False
    choked: bool = True
    peer_choked: bool = True
    interested: bool = False
    peer_interested: bool = False
    has_all: bool = False
    pending_requests: list[dict] = field(default_factory=list)
    send_buffer: bytearray = field(default_factory=bytearray)
    last_activity: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        """Initialize optional components."""
        if self.metadata_exchange is not None:
            self.pex_manager = PEXManager(
                info_hash=self.metadata_exchange._info_hash,
                my_node_id=self.peer_id,
            )
            self.holepunch_handler = HolePunchHandler()

    def create_handshake(self) -> bytes:
        """Create the initial BitTorrent handshake (BEP 3/23).

        Returns
        -------
        bytes
            The full handshake: pref + length + identifier + info.

        Raises
        ------
        ExtensionError
            If info_hash is not 20 bytes.
        """
        return create_handshake(self.info_hash, self.peer_id)

    def parse_incoming_handshake(self, data: bytes) -> tuple[bytes, bytes]:
        """Parse an incoming BEP 3 handshake from a peer.

        Parameters
        ----------
        data : bytes
            The raw handshake bytes.

        Returns
        -------
        tuple[bytes, bytes]
            A tuple of (info_hash, peer_id) from the handshake.

        Raises
        ------
        ExtensionError
            If the handshake is invalid or info_hash doesn't match.
        """
        extensions_enabled, reserved_bytes, info_hash, peer_id = parse_handshake(data)

        # Verify info_hash matches this torrent
        if self.info_hash and info_hash != self.info_hash:
            raise ExtensionError(
                f"Info hash mismatch: expected {self.info_hash.hex()}, got {info_hash.hex()}"
            )

        # Store extension support
        if extensions_enabled:
            self.extended_enabled = True

        return info_hash, peer_id

    def create_extended_handshake(self) -> bytes:
        """Create an extended protocol handshake.

        Creates the extended message format with msg_type=0 for
        extension negotiation.

        Returns
        -------
        bytes
            Complete extended handshake message.
        """
        return self.negotiator.send_extended_message(
            EXTENSION_MSG_TYPE_HANDSHAKE,
            {"m": ""},
        )

    def parse_extended_handshake(self, data: bytes) -> bool:
        """Parse an incoming extended handshake.

        Parameters
        ----------
        data : bytes
            The raw extended message.

        Returns
        -------
        bool
            True if handshake was successful, False otherwise.
        """
        try:
            msg_type, payload = self.negotiator.parse_extended_message(data)
            if msg_type == EXTENSION_MSG_TYPE_HANDSHAKE:
                # Extract the extension names from the payload
                handshake_data = payload.get("m", "")
                if isinstance(handshake_data, str):
                    handshake_data = handshake_data.encode("utf-8", errors="replace")

                # Re-encode as bencoded for parse_handshake
                handshake_bytes = bencode_module.encode({"m": handshake_data})
                return self.negotiator.parse_handshake(handshake_bytes)
        except ExtensionError as exc:
            logger.debug("Failed to parse extended handshake: %s", exc)

        return False

    def send_message(self, msg_type: int, payload: dict[str, Any]) -> bytes:
        """Send an extended message to the peer (BEP 10).

        Parameters
        ----------
        msg_type : int
            Message type: 0 = handshake, 1 = message.
        payload : dict[str, Any]
            Message payload.

        Returns
        -------
        bytes
            Encoded message bytes.
        """
        if not self.handshake_done:
            raise ExtensionError("Cannot send message: handshake not complete")

        return self.negotiator.send_extended_message(msg_type, payload)

    def handle_extended_message(self, data: bytes) -> tuple[int, dict[str, Any]]:
        """Handle an incoming extended message.

        Parameters
        ----------
        data : bytes
            Raw extended message bytes.

        Returns
        -------
        tuple[int, dict[str, Any]]
            (msg_type, payload)

        Raises
        ------
        ExtensionError
            If the message cannot be parsed.
        """
        return self.negotiator.parse_extended_message(data)

    def update_activity(self) -> None:
        """Update the last activity timestamp."""
        self.last_activity = time.time()

    def is_idle(self, timeout: float = 120.0) -> bool:
        """Check if the connection has been idle too long.

        Parameters
        ----------
        timeout : float
            Idle timeout in seconds.

        Returns
        -------
        bool
            True if the connection has been idle longer than timeout.
        """
        return time.time() - self.last_activity > timeout

    def create_choke(self) -> bytes:
        """Create a choke message (BEP 3).

        Returns
        -------
        bytes
            Serialized choke message.
        """
        self.choked = True
        return serialize_peer_message(MSG_CHOKE)

    def create_unchoke(self) -> bytes:
        """Create an unchoke message (BEP 3).

        Returns
        -------
        bytes
            Serialized unchoke message.
        """
        self.choked = False
        return serialize_peer_message(MSG_UNCHOKE)

    def create_interested(self) -> bytes:
        """Create an interested message (BEP 3).

        Returns
        -------
        bytes
            Serialized interested message.
        """
        self.interested = True
        return serialize_peer_message(MSG_INTERESTED)

    def create_not_interested(self) -> bytes:
        """Create a not interested message (BEP 3).

        Returns
        -------
        bytes
            Serialized not interested message.
        """
        self.interested = False
        return serialize_peer_message(MSG_NOT_INTERESTED)

    def create_have(self, piece_index: int) -> bytes:
        """Create a have message (BEP 3).

        Parameters
        ----------
        piece_index : int
            The index of the newly available piece.

        Returns
        -------
        bytes
            Serialized have message.
        """
        payload = struct.pack("!I", piece_index)
        return serialize_peer_message(MSG_HAVE, payload)

    def create_bitfield(self, bitfield: bytes) -> bytes:
        """Create a bitfield message (BEP 3).

        Parameters
        ----------
        bitfield : bytes
            The bitfield bytes representing owned pieces.

        Returns
        -------
        bytes
            Serialized bitfield message.
        """
        return serialize_peer_message(MSG_BITFIELD, bitfield)

    def create_request(self, piece_index: int, begin: int, length: int = 16384) -> bytes:
        """Create a request message (BEP 3).

        Parameters
        ----------
        piece_index : int
            The index of the piece to request.
        begin : int
            The byte offset within the piece.
        length : int
            The number of bytes to request. Default: 16384.

        Returns
        -------
        bytes
            Serialized request message.

        Raises
        ------
        ExtensionError
            If the request exceeds maximum size or pending queue is full.
        """
        if length > MAX_REQUEST_SIZE:
            raise ExtensionError(
                f"Request size {length} exceeds maximum {MAX_REQUEST_SIZE}"
            )
        if len(self.pending_requests) >= MAX_PENDING_REQUESTS:
            raise ExtensionError(
                f"Pending requests {len(self.pending_requests)} exceeds maximum {MAX_PENDING_REQUESTS}"
            )

        payload = struct.pack("!III", piece_index, begin, length)
        msg = serialize_peer_message(MSG_REQUEST, payload)

        # Track the pending request
        self.pending_requests.append({
            "piece_index": piece_index,
            "begin": begin,
            "length": length,
            "timestamp": time.time(),
        })

        return msg

    def create_cancel(self, piece_index: int, begin: int, length: int = 16384) -> bytes:
        """Create a cancel message (BEP 3).

        Parameters
        ----------
        piece_index : int
            The index of the piece to cancel.
        begin : int
            The byte offset within the piece.
        length : int
            The number of bytes to cancel. Default: 16384.

        Returns
        -------
        bytes
            Serialized cancel message.
        """
        payload = struct.pack("!III", piece_index, begin, length)
        msg = serialize_peer_message(MSG_CANCEL, payload)

        # Remove from pending requests
        self.pending_requests = [
            r for r in self.pending_requests
            if not (
                r["piece_index"] == piece_index
                and r["begin"] == begin
                and r["length"] == length
            )
        ]

        return msg

    def handle_choke(self) -> None:
        """Handle an incoming choke message from the peer."""
        self.peer_choked = True
        logger.debug("Peer choked")

    def handle_unchoke(self) -> None:
        """Handle an incoming unchoke message from the peer."""
        self.peer_choked = False
        logger.debug("Peer unchoked")

    def handle_interested(self) -> None:
        """Handle an incoming interested message from the peer."""
        self.peer_interested = True

    def handle_not_interested(self) -> None:
        """Handle an incoming not interested message from the peer."""
        self.peer_interested = False

    def handle_have(self, piece_index: int) -> None:
        """Handle an incoming have message from the peer.

        Parameters
        ----------
        piece_index : int
            The index of the piece the peer has.
        """
        logger.debug("Peer has piece %d", piece_index)

    def handle_bitfield(self, bitfield: bytes, total_pieces: int) -> None:
        """Handle an incoming bitfield message from the peer.

        Parameters
        ----------
        bitfield : bytes
            The bitfield data.
        total_pieces : int
            Total number of pieces in the torrent.
        """
        num_bits = len(bitfield) * 8
        if num_bits > total_pieces:
            logger.warning("Bitfield has %d bits, but torrent has %d pieces", num_bits, total_pieces)

    def handle_piece(self, piece_index: int, begin: int, piece_data: bytes) -> None:
        """Handle an incoming piece message from the peer.

        Parameters
        ----------
        piece_index : int
            The index of the piece.
        begin : int
            The byte offset within the piece.
        piece_data : bytes
            The actual piece data.
        """
        logger.debug("Received piece %d offset %d length %d", piece_index, begin, len(piece_data))
        self.update_activity()

        # Remove completed request from pending
        self.pending_requests = [
            r for r in self.pending_requests
            if not (r["piece_index"] == piece_index and r["begin"] == begin)
        ]

    def handle_request(self, piece_index: int, begin: int, length: int) -> None:
        """Handle an incoming request from the peer.

        Parameters
        ----------
        piece_index : int
            The requested piece index.
        begin : int
            Byte offset within the piece.
        length : int
            Number of bytes requested.

        Returns
        -------
        bool
            True if the request is accepted, False otherwise.
        """
        if self.peer_choked:
            logger.debug("Rejected request from choked peer")
            return False

        if length > MAX_REQUEST_SIZE:
            logger.debug("Request size %d exceeds maximum %d", length, MAX_REQUEST_SIZE)
            return False

        logger.debug("Peer requested piece %d offset %d length %d", piece_index, begin, length)
        return True

    def handle_cancel(self, piece_index: int, begin: int, length: int) -> None:
        """Handle an incoming cancel message from the peer.

        Parameters
        ----------
        piece_index : int
            The cancelled piece index.
        begin : int
            Byte offset.
        length : int
            Request length.
        """
        logger.debug("Peer cancelled piece %d offset %d length %d", piece_index, begin, length)

    def handle_peer_message(self, msg: PeerMessage) -> None:
        """Handle a parsed peer wire message and update connection state.

        Parameters
        ----------
        msg : PeerMessage
            The parsed peer message.
        """
        msg_type = msg.msg_type

        if msg_type == MSG_CHOKE:
            self.handle_choke()
        elif msg_type == MSG_UNCHOKE:
            self.handle_unchoke()
        elif msg_type == MSG_INTERESTED:
            self.handle_interested()
        elif msg_type == MSG_NOT_INTERESTED:
            self.handle_not_interested()
        elif msg_type == MSG_HAVE:
            if msg.piece_index is not None:
                self.handle_have(msg.piece_index)
        elif msg_type == MSG_BITFIELD:
            if msg.piece_bitmask is not None:
                # We need total_pieces from somewhere
                self.handle_bitfield(msg.piece_bitmask, 0)
        elif msg_type == MSG_REQUEST:
            if msg.piece_index is not None:
                self.handle_request(msg.piece_index, msg.begin, msg.length)
        elif msg_type == MSG_PIECE:
            if msg.piece_index is not None and msg.piece_data is not None:
                self.handle_piece(msg.piece_index, msg.begin, msg.piece_data)
        elif msg_type == MSG_CANCEL:
            if msg.piece_index is not None:
                self.handle_cancel(msg.piece_index, msg.begin, msg.length)

    def build_keepalive(self) -> bytes:
        """Build a keepalive message (zero-length message).

        Returns
        -------
        bytes
            Zero-length message for keepalive.
        """
        return serialize_peer_message(MSG_CHOKE)  # Will be zero-length via empty payload

    def clear_pending_requests(self) -> None:
        """Clear all pending requests (e.g., on choke or disconnect)."""
        self.pending_requests.clear()

    def get_pending_count(self) -> int:
        """Get the number of pending requests.

        Returns
        -------
        int
            Number of pending requests.
        """
        return len(self.pending_requests)

    def is_pipelining_allowed(self) -> bool:
        """Check if request pipelining is allowed.

        Returns
        -------
        bool
            True if we can queue more requests.
        """
        return len(self.pending_requests) < MAX_PENDING_REQUESTS and (
            not self.peer_choked or self.choked
        )

    def __repr__(self) -> str:
        status = "connected" if self.connected else "disconnected"
        ext = "extended" if self.extended_enabled else "plain"
        choke_state = "choked" if self.choked else "unchoked"
        interest_state = "interested" if self.interested else "not interested"
        return (
            f"PeerConnection({self.endpoint}, {status}, {ext}, "
            f"{choke_state}, {interest_state}, "
            f"pending={len(self.pending_requests)})"
        )
