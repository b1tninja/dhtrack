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
# BEP 10: Extension Protocol constants
# ---------------------------------------------------------------------------

# Extended message type values
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

HOLEPUNCH_CONNECT = 1
HOLEPUNCH_CONNECTRESP = 2
HOLEPUNCH_FAIL = 3

HOLEPUNCH_ECN_ENABLE = 0
HOLEPUNCH_ECN_DISABLE = 1

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

    Attributes
    ----------
    pending_requests : dict[bytes, dict]
        Pending holepunch requests keyed by request ID.
    """

    pending_requests: dict[bytes, dict] = field(default_factory=dict)

    def create_holepunch_message(
        self,
        target_peer_id: bytes,
        request_id: bytes,
        message_type: int = HOLEPUNCH_CONNECT,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
    ) -> bytes:
        """Create a holepunch message (BEP 55).

        Parameters
        ----------
        target_peer_id : bytes
            The target peer's 20-byte peer ID.
        request_id : bytes
            A unique request identifier.
        message_type : int
            Message type: HOLEPUNCH_CONNECT (1), HOLEPUNCH_CONNECTRESP (2),
            or HOLEPUNCH_FAIL (3).
        target_ip : str, optional
            Target IP address (for CONNECT messages).
        target_port : int, optional
            Target port (for CONNECT messages).

        Returns
        -------
        bytes
            Bencoded holepunch message.
        """
        msg = {
            "msg_type": message_type,
            "reqid": request_id,
            "target_peer": target_peer_id,
        }

        if message_type == HOLEPUNCH_CONNECT and target_ip and target_port:
            if ":" in target_ip:
                msg["target_ip"] = socket.inet_pton(socket.AF_INET6, target_ip)
            else:
                msg["target_ip"] = socket.inet_aton(target_ip)
            msg["target_port"] = struct.pack("!H", target_port)

        return bencode_module.encode(msg)

    def handle_holepunch(self, data: bytes) -> dict[str, Any]:
        """Process an incoming holepunch message.

        Parameters
        ----------
        data : bytes
            Bencoded holepunch message.

        Returns
        -------
        dict[str, Any]
            Parsed holepunch message data.

        Raises
        ------
        ExtensionError
            If the message is malformed.
        """
        try:
            parsed = bencode_module.decode(data)
        except Exception as exc:
            raise ExtensionError(f"Failed to decode holepunch message: {exc}") from exc

        if not isinstance(parsed, dict):
            raise ExtensionError("Holepunch message is not a dictionary")

        msg_type = parsed.get("msg_type")
        if msg_type == HOLEPUNCH_CONNECT:
            self.pending_requests[parsed.get("reqid", b"")] = {
                "type": "connect",
                "target_peer": parsed.get("target_peer"),
                "target_ip": parsed.get("target_ip"),
                "target_port": struct.unpack("!H", parsed.get("target_port", b"\x00\x00"))[0],
            }
        elif msg_type == HOLEPUNCH_CONNECTRESP:
            self.pending_requests[parsed.get("reqid", b"")] = {
                "type": "connect_response",
                "peer_ip": parsed.get("peer_ip"),
                "peer_port": struct.unpack("!H", parsed.get("peer_port", b"\x00\x00"))[0],
            }
        elif msg_type == HOLEPUNCH_FAIL:
            self.pending_requests[parsed.get("reqid", b"")] = {
                "type": "fail",
                "reason": parsed.get("reason", "unknown"),
            }

        return parsed

    def cancel_request(self, request_id: bytes) -> bytes:
        """Create a CANCEL message for a pending request.

        Parameters
        ----------
        request_id : bytes
            The request ID to cancel.

        Returns
        -------
        bytes
            Bencoded cancel message.
        """
        return bencode_module.encode({
            "msg_type": HOLEPUNCH_FAIL,
            "reqid": request_id,
            "reason": "cancelled",
        })


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
    send_buffer : bytearray
        Buffer for outgoing data.
    """

    peer_id: bytes
    endpoint: Endpoint
    negotiator: ExtensionNegotiator = field(default_factory=ExtensionNegotiator)
    metadata_exchange: Optional[MetadataExchange] = None
    pex_manager: Optional[PEXManager] = None
    holepunch_handler: Optional[HolePunchHandler] = None
    is_initiator: bool = True
    connected: bool = False
    extended_enabled: bool = False
    handshake_done: bool = False
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
        """
        pref = b"\x10BitTorrent protocol"
        reserved_bytes = b"\x00" * 8
        info_hash = b"\x00" * 20  # Placeholder
        peer_id_bytes = b"\x00" * 20  # Placeholder

        length = len(pref)  # 19
        handshake = struct.pack("B", length) + pref + reserved_bytes + info_hash + peer_id_bytes
        return handshake

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

    def __repr__(self) -> str:
        status = "connected" if self.connected else "disconnected"
        ext = "extended" if self.extended_enabled else "plain"
        return f"PeerConnection({self.endpoint}, {status}, {ext})"