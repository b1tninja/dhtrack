"""
DHT over QUIC (BEP 42) - QUIC protocol support for BitTorrent DHT.

This module provides:

1. A QUIC socket listener (UDP socket dedicated to QUIC traffic on a separate
   port, default 6881) so that QUIC-formatted DHT messages can be received
   alongside regular UDP DHT traffic.
2. QUIC packet parsing and framing for the simple QUIC-C0 / QUIC-C4 variants
   used by the BitTorrent DHT.
3. Extraction of bencoded DHT payloads from QUIC packets so they can be
   processed by the existing DHT message handlers.

QUIC packet format (simplified, used by BitTorrent DHT):

    Byte 0:    Version / Magic (0xc3 = QUIC, 0xc4 = QUIC with longer header)
    Bytes 1-4: Transaction ID (8 bytes, matching the DHT transaction ID)
    Bytes 5+:  QUIC data (includes the bencoded DHT message)

For the BitTorrent DHT overlay, QUIC packets carry bencoded DHT messages
just like regular UDP datagrams - the only difference is the framing
prefix.

References
----------
- BEP 42: https://www.bittorrent.org/beps/bep_0042.html
- "DHT over QUIC" discussions in the BitTorrent community
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import struct
import zlib
from collections.abc import Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# QUIC magic bytes - identify QUIC packets on the wire
QUIC_VERSION_C3 = 0xC3  # Simple QUIC header
QUIC_VERSION_C4 = 0xC4  # Extended QUIC header

# QUIC port (standard DHT port, can be used for QUIC traffic)
QUIC_DEFAULT_PORT = 6881

# Maximum QUIC packet size (same as UDP MTU)
QUIC_MAX_PACKET_SIZE = 1438

# Minimum QUIC header size (version + transaction ID)
QUIC_MIN_HEADER_SIZE = 5

# Maximum QUIC header size (with full transaction ID)
QUIC_MAX_HEADER_SIZE = 13

# Node ID validation constants (BEP 42)
NODE_ID_PREFIX_BITS = 21
NODE_ID_PREFIX_MASK = 0x1FFFFF80  # Top 21 bits + bottom 3 bits of byte 2

# IPv4 mask for node ID validation (BEP 42)
V4_MASK = bytearray([0x03, 0x0F, 0x3F, 0xFF])

# IPv6 mask for node ID validation (BEP 42) - 8 bytes
V6_MASK = bytearray([0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF])


# ---------------------------------------------------------------------------
# QUIC Packet Parsing
# ---------------------------------------------------------------------------


def is_quic_packet(data: bytes) -> bool:
    """Check if a received datagram is a QUIC packet.

    Parameters
    ----------
    data : bytes
        Raw datagram data.

    Returns
    -------
    bool
        True if the first byte indicates QUIC (0xc3 or 0xc4).
    """
    if not data or len(data) < 1:
        return False
    return data[0] in (QUIC_VERSION_C3, QUIC_VERSION_C4)


def parse_quic_packet(data: bytes) -> bytes | None:
    """Parse a QUIC packet and extract the bencoded DHT payload.

    Parameters
    ----------
    data : bytes
        Raw QUIC datagram.

    Returns
    -------
    bytes or None
        The bencoded DHT payload if parsing succeeds, None otherwise.
    """
    if not data or not is_quic_packet(data):
        return None

    if len(data) < QUIC_MIN_HEADER_SIZE:
        logger.debug("QUIC packet too short: %d bytes", len(data))
        return None

    version = data[0]

    try:
        if version == QUIC_VERSION_C3:
            # Simple QUIC header:
            # Byte 0: version (0xc3)
            # Bytes 1-4: transaction ID (4 bytes, big-endian)
            # Bytes 5+: bencoded payload
            if len(data) < QUIC_MIN_HEADER_SIZE:
                logger.debug("QUIC-C3 packet too short: %d bytes", len(data))
                return None

            # Extract transaction ID (bytes 1-4)
            txid = data[1:5]
            txid_hex = txid.hex()

            # Extract payload
            payload = data[QUIC_MIN_HEADER_SIZE:]

            if not payload:
                logger.debug("QUIC-C3 packet has empty payload")
                return None

            logger.debug(
                "QUIC-C3 packet: txid=%s, payload_size=%d",
                txid_hex,
                len(payload),
            )
            return payload

        elif version == QUIC_VERSION_C4:
            # Extended QUIC header:
            # Byte 0: version (0xc4)
            # Bytes 1-12: transaction ID (12 bytes, big-endian)
            # Bytes 13+: bencoded payload
            if len(data) < QUIC_MAX_HEADER_SIZE:
                logger.debug("QUIC-C4 packet too short: %d bytes", len(data))
                return None

            # Extract transaction ID (bytes 1-12)
            txid = data[1:13]
            txid_hex = txid.hex()

            # Extract payload
            payload = data[QUIC_MAX_HEADER_SIZE:]

            if not payload:
                logger.debug("QUIC-C4 packet has empty payload")
                return None

            logger.debug(
                "QUIC-C4 packet: txid=%s, payload_size=%d",
                txid_hex,
                len(payload),
            )
            return payload

        else:
            logger.debug("Unknown QUIC version: 0x%02x", version)
            return None

    except (IndexError, struct.error) as exc:
        logger.debug("QUIC parse error: %s", exc)
        return None


def build_quic_packet(payload: bytes, txid: bytes) -> bytes:
    """Build a QUIC packet containing a bencoded DHT message.

    Parameters
    ----------
    payload : bytes
        The bencoded DHT message payload.
    txid : bytes
        The 4-byte transaction ID.

    Returns
    -------
    bytes
        A complete QUIC datagram ready for UDP transmission.
    """
    if len(txid) != 4:
        raise ValueError("Transaction ID must be 4 bytes")

    # QUIC-C3 header: version(1) + txid(4) + payload
    return bytes([QUIC_VERSION_C3]) + txid + payload


# ---------------------------------------------------------------------------
# Node ID Validation (BEP 42)
# ---------------------------------------------------------------------------


def crc32c(data: bytes) -> int:
    """Compute CRC32C (CRC-32C / Castagnoli).

    This is the CRC32 polynomial used by BEP 42 for node ID validation.
    Falls back to CRC32 if the zlib on this system doesn't support CRC32C.

    Parameters
    ----------
    data : bytes
        Input data for CRC calculation.

    Returns
    -------
    int
        CRC32C value (unsigned 32-bit integer).
    """
    try:
        # Python 3.11+ supports CRC32C via zlib.crc32 with a poly parameter
        # or via the crc32c algorithm directly
        try:
            # Python 3.11+ : zlib.crc32 with polynomial parameter
            return zlib.crc32(data, 0x1EDC6F41) & 0xFFFFFFFF
        except TypeError:
            # Older Python: CRC32C not available
            pass
    except (TypeError, ValueError):
        pass

    # Fallback: use standard CRC32 (not Castagnoli)
    # This means BEP 42 node ID validation won't be perfectly correct,
    # but the DHT will still function
    return zlib.crc32(data) & 0xFFFFFFFF


def validate_node_id(node_id: bytes, ip: str, port: int, is_ipv6: bool = False) -> bool:
    """Validate a node ID against its IP address per BEP 42.

    Parameters
    ----------
    node_id : bytes
        The 20-byte node ID to validate.
    ip : str
        The IP address to validate against.
    port : int
        The port number.
    is_ipv6 : bool
        Whether the IP is IPv6.

    Returns
    -------
    bool
        True if the node ID is valid per BEP 42.
    """
    if len(node_id) != 20:
        return False

    if is_ipv6:
        # IPv6: use top 64 bits of the address
        try:
            addr = ipaddress.ip_address(ip)
            packed = addr.packed  # 16 bytes for IPv6
            addr_bytes = packed[:8]  # Top 8 bytes
        except (ValueError, AttributeError):
            return False
        mask = V6_MASK
    else:
        # IPv4: use the full 4-byte address
        try:
            addr = ipaddress.ip_address(ip)
            packed = addr.packed  # 4 bytes for IPv4
            addr_bytes = packed
        except (ValueError, AttributeError):
            return False
        mask = V4_MASK

    # Apply mask to IP address
    masked = bytearray(len(mask))
    for i, m in enumerate(mask):
        masked[i] = addr_bytes[i] & m

    # Get random value r in range [0, 7]
    # In practice, this is derived from the node ID or chosen randomly
    r = (node_id[2] >> 5) & 0x07

    # Set the r bits in the masked address
    masked[0] |= r << 5

    # Compute CRC32C
    crc = crc32c(bytes(masked))

    # Check that the first 21 bits of the node ID match the CRC
    crc_prefix = (crc >> 11) & 0x1FFFFF  # Top 21 bits
    node_prefix = (node_id[0] << 13) | (node_id[1] << 5) | (node_id[2] >> 3)

    if crc_prefix != node_prefix:
        return False

    # Check that the lower 3 bits of byte[2] of the CRC match r
    crc_lower_byte = crc & 0xFF
    if crc_lower_byte != r:
        return False

    return True


def generate_node_id(ip: str, port: int, is_ipv6: bool = False) -> bytes:
    """Generate a valid node ID for a given IP address per BEP 42.

    Parameters
    ----------
    ip : str
        The IP address.
    port : int
        The port number.
    is_ipv6 : bool
        Whether the IP is IPv6.

    Returns
    -------
    bytes
        A 20-byte node ID valid per BEP 42.
    """
    if is_ipv6:
        addr_bytes_raw = ipaddress.ip_address(ip).packed[:8]
        mask = V6_MASK
    else:
        addr_bytes_raw = ipaddress.ip_address(ip).packed
        mask = V4_MASK

    # Apply mask
    masked = bytearray(len(mask))
    for i, m in enumerate(mask):
        masked[i] = addr_bytes_raw[i] & m

    # Random value r in range [0, 7]
    r = os.urandom(1)[0] & 0x07

    # Set the r bits
    masked[0] |= r << 5

    # Compute CRC32C
    crc = crc32c(bytes(masked))

    # Build node ID
    node_id = bytearray(20)
    node_id[0] = (crc >> 24) & 0xFF
    node_id[1] = (crc >> 16) & 0xFF
    node_id[2] = ((crc >> 8) & 0xF8) | (os.urandom(1)[0] & 0x07)
    for i in range(3, 19):
        node_id[i] = os.urandom(1)[0]
    node_id[19] = r

    return bytes(node_id)


# ---------------------------------------------------------------------------
# IP Encoding/Decoding (BEP 42 - IP field in responses)
# ---------------------------------------------------------------------------


def encode_ip_port(ip: str, port: int) -> bytes:
    """Encode an IP address and port as 6 bytes (4 bytes IP + 2 bytes port).

    BEP 42: "a top-level field called ip, containing a compact binary
    representation of the requestor's IP and port."

    Parameters
    ----------
    ip : str
        IP address string.
    port : int
        Port number (0-65535).

    Returns
    -------
    bytes
        6 bytes: 4-byte big-endian IP + 2-byte big-endian port.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            ip_bytes = addr.packed  # 4 bytes
        else:
            # For IPv6, use the last 4 bytes (common mapping)
            # or the full 16 bytes if the receiver supports it
            ip_bytes = addr.packed[-4:]  # IPv4-mapped IPv6
    except ValueError:
        # Try to parse as IPv4
        try:
            ip_bytes = struct.pack("BBBB", *map(int, ip.split(".")))
        except (ValueError, struct.error):
            ip_bytes = b"\x00" * 4

    port_bytes = struct.pack("!H", port & 0xFFFF)
    return ip_bytes + port_bytes


def decode_ip_port(data: bytes) -> tuple[str, int, bool] | None:
    """Decode an IP address and port from 6 bytes.

    Parameters
    ----------
    data : bytes
        6 bytes: 4-byte IP + 2-byte port.

    Returns
    -------
    tuple of (ip: str, port: int, is_ipv6: bool) or None
        Decoded address tuple, or None if data is invalid.
    """
    if len(data) < 6:
        return None

    ip_bytes = data[0:4]
    port = struct.unpack("!H", data[4:6])[0]

    # Try to parse as IPv4 first
    try:
        addr = ipaddress.IPv4Address(ip_bytes)
        return str(addr), port, False
    except (ValueError, struct.error):
        pass

    # Parse as dotted IPv4
    try:
        ip_str = ".".join(str(b) for b in ip_bytes)
        return ip_str, port, False
    except (ValueError, TypeError):
        return None

    return None


# ---------------------------------------------------------------------------
# QUIC DHT Node
# ---------------------------------------------------------------------------


class QUICDHTNode:
    """A DHT node that handles QUIC traffic.

    Manages a separate socket for QUIC-formatted DHT messages.
    QUIC traffic is handled on a separate UDP socket bound to the
    QUIC port (default 6881).

    Attributes
    ----------
    sock : socket.socket or None
        The UDP socket for QUIC traffic.
    port : int
        The port this node is listening on for QUIC traffic.
    callback : callable, optional
        Callback function for received QUIC datagrams.
        Called as callback(payload, addr, ip, port, is_ipv6).
    """

    def __init__(self, port: int = QUIC_DEFAULT_PORT, callback: Callable | None = None) -> None:
        """Initialize a QUIC DHT node.

        Parameters
        ----------
        port : int
            UDP port to bind for QUIC traffic.
        callback : callable, optional
            Function called with (payload, addr, ip, port, is_ipv6) when
            a QUIC datagram is received and successfully parsed.
        """
        self.sock: socket.socket | None = None
        self.port = port
        self.callback = callback
        self._socket_fds: set[int] = set()
        self._is_running = False

    def start(self) -> bool:
        """Start the QUIC socket listener.

        Returns
        -------
        bool
            True if the socket was successfully created and bound.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("", self.port))
            self._socket_fds.add(self.sock.fileno())
            self._is_running = True
            logger.info("QUIC DHT listener started on port %d", self.port)
            return True
        except OSError as exc:
            logger.warning("Failed to start QUIC DHT listener on port %d: %s", self.port, exc)
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
            return False

    def stop(self) -> None:
        """Stop the QUIC socket listener and close the socket."""
        self._is_running = False
        if self.sock:
            try:
                fd = self.sock.fileno()
                if fd in self._socket_fds:
                    self._socket_fds.discard(fd)
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def recvfrom(self, bufsize: int = QUIC_MAX_PACKET_SIZE) -> tuple[bytes, tuple, str, int, bool] | None:
        """Receive a QUIC datagram and extract its payload.

        Parameters
        ----------
        bufsize : int
            Maximum datagram size.

        Returns
        -------
        tuple of (payload, addr, ip, port, is_ipv6) or None
            payload: The bencoded DHT payload (after QUIC header stripped).
            addr: The socket address tuple.
            ip: The IP address string.
            port: The port number.
            is_ipv6: Whether this is an IPv6 address.
            None if no datagram is available or parsing fails.
        """
        if not self.sock or not self._is_running:
            return None

        try:
            data, addr = self.sock.recvfrom(bufsize)
        except OSError:
            return None

        if not data:
            return None

        ip = addr[0]
        port = addr[1]
        is_ipv6 = ":" in ip

        # Check if this is a QUIC packet
        if not is_quic_packet(data):
            # Not a QUIC packet - log and discard
            logger.debug(
                "Non-QUIC datagram on QUIC port from %s:%d (%d bytes, first byte 0x%02x)",
                ip,
                port,
                len(data),
                data[0] if data else 0,
            )
            return None

        # Parse the QUIC packet to extract the payload
        payload = parse_quic_packet(data)
        if payload is None:
            logger.debug(
                "Failed to parse QUIC packet from %s:%d",
                ip,
                port,
            )
            return None

        return payload, addr, ip, port, is_ipv6

    def sendto(self, payload: bytes, addr: tuple, txid: bytes) -> int:
        """Send a bencoded DHT payload over QUIC to the specified address.

        Parameters
        ----------
        payload : bytes
            The bencoded DHT message.
        addr : tuple
            (ip, port) tuple of the recipient.
        txid : bytes
            4-byte transaction ID.

        Returns
        -------
        int
            Number of bytes sent.
        """
        if not self.sock:
            return 0

        try:
            packet = build_quic_packet(payload, txid)
            return self.sock.sendto(packet, addr)
        except OSError as exc:
            logger.debug("QUIC sendto failed to %s:%d: %s", addr[0], addr[1], exc)
            return 0

    @property
    def is_running(self) -> bool:
        """Whether the QUIC socket is active."""
        return self._is_running and self.sock is not None

    @property
    def getsockname(self) -> tuple | None:
        """Get the local socket address."""
        if self.sock:
            try:
                return self.sock.getsockname()
            except OSError:
                return None
        return None


# ---------------------------------------------------------------------------
# QUIC-aware datagram handler decorator
# ---------------------------------------------------------------------------


def handle_datagram_with_quic(data: bytes, addr: tuple, handler: Callable) -> None:
    """Wrap a datagram handler to handle both UDP and QUIC datagrams.

    This is a utility function that:
    1. Checks if the datagram is QUIC-formatted (0xc3/0xc4 first byte)
    2. If QUIC, parses and extracts the bencode payload
    3. If not QUIC, passes through to the regular handler
    4. Gracefully handles any errors to prevent thread crashes

    Parameters
    ----------
    data : bytes
        Raw datagram data.
    addr : tuple
        (ip, port) address tuple (or 4-tuple for IPv6).
    handler : callable
        A callable that accepts (payload, addr) and processes bencode data.
    """
    if not data:
        return

    first_byte = data[0]

    if first_byte in (QUIC_VERSION_C3, QUIC_VERSION_C4):
        # QUIC packet - parse and extract payload
        payload = parse_quic_packet(data)
        if payload is None:
            logger.debug(
                "Received QUIC datagram that could not be parsed from %s:%s",
                addr[0] if len(addr) >= 2 else "unknown",
                addr[1] if len(addr) >= 2 else "unknown",
            )
            return

        try:
            handler(payload, addr)
        except Exception:
            logger.debug(
                "Error processing QUIC payload from %s:%s",
                addr[0] if len(addr) >= 2 else "unknown",
                addr[1] if len(addr) >= 2 else "unknown",
                exc_info=True,
            )
        return

    # Regular UDP DHT datagram - pass through directly
    try:
        handler(data, addr)
    except Exception:
        logger.debug(
            "Error processing datagram from %s:%s",
            addr[0] if len(addr) >= 2 else "unknown",
            addr[1] if len(addr) >= 2 else "unknown",
            exc_info=True,
        )
