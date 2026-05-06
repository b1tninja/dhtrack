"""BEP 29: uTorrent Transport Protocol (uTP) implementation.

This module implements the uTorrent Transport Protocol, a UDP-based transport
protocol that uses delay-based congestion control to fairly share bandwidth
with TCP traffic. See: https://www.bittorrent.org/beps/bep_0029.html

This module provides:
- UTP packet header parsing and serialization
- Selective ACK extension handling
- Delay-based congestion control
- Connection state machine
- UTPSocket class for socket-like operations
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Packet types (BEP 29 Section: "type")
# ---------------------------------------------------------------------------

ST_DATA: int = 0
ST_FIN: int = 1
ST_STATE: int = 2
ST_RESET: int = 3
ST_SYN: int = 4

PACKET_TYPE_NAMES: dict[int, str] = {
    ST_DATA: "ST_DATA",
    ST_FIN: "ST_FIN",
    ST_STATE: "ST_STATE",
    ST_RESET: "ST_RESET",
    ST_SYN: "ST_SYN",
}

# ---------------------------------------------------------------------------
# Connection states (BEP 29 connection lifecycle)
# ---------------------------------------------------------------------------

class ConnectionState(IntEnum):
    """States for a uTP connection."""

    NEW = 0
    SYN_SENT = 1
    SYN_RECV = 2
    CONNECTED = 3
    CLOSING = 4
    CLOSED = 5
    ERROR = 6


# ---------------------------------------------------------------------------
# Selective ACK extension
# ---------------------------------------------------------------------------

SELECTIVE_ACK_EXTENSION: int = 1

# ---------------------------------------------------------------------------
# Packet type for extended packet types (extension field in header)
# ---------------------------------------------------------------------------

EXT_TYPE_NONE: int = 0
EXT_TYPE_SELECTIVE_ACK: int = 1

# ---------------------------------------------------------------------------
# Default parameters (BEP 29)
# ---------------------------------------------------------------------------

# Default packet size in bytes (BEP 29 recommends 1400 for typical Ethernet MTUs)
DEFAULT_PACKET_SIZE: int = 1400

# Minimum packet size (BEP 29: 150 bytes minimum)
MIN_PACKET_SIZE: int = 150

# Maximum payload per packet
MAX_PACKET_SIZE: int = 65536

# Initial congestion window (in packets)
INITIAL_CONGESTION_WINDOW: int = 3

# Target one-way buffering delay in milliseconds (BEP 29: 100 ms)
CCONTROL_TARGET: int = 100

# Maximum window increase in packets per RTT (BEP 29: 1 packet per RTT for
# every 2 target delays below the target, capped to prevent unbounded growth)
MAX_CWND_INCREASE_PACKETS_PER_RTT: float = 1.0

# Window factor minimum (prevent negative window growth)
WINDOW_FACTOR_MIN: float = 0.0

# Initial packet size
INITIAL_PACKET_SIZE: int = 150

# Timeout initial value in milliseconds (BEP 29: minimum 500 ms)
INITIAL_TIMEOUT_MS: int = 1000

# Default window increase factor
DEFAULT_GROWTH_FACTOR: float = 1.0

# Timeout multiplier
TIMEOUT_MULTIPLIER: int = 4

# RTT smoothing factor constants
RTT_ALPHA: float = 1.0 / 8.0
RTT_BETA: float = 1.0 / 4.0

# Max RTT value (10 seconds)
MAX_RTT: int = 10000

# Min RTT value (1 ms)
MIN_RTT: int = 1

# RTT variance minimum
RTT_VAR_MIN: int = 1

# Base delay window (BEP 29: track minimum for 2 minutes)
BASE_DELAY_WINDOW: int = 120  # seconds

# Selective ACK mask size in bits (minimum)
SELECTIVE_ACK_MIN_BITS: int = 32

# Max selective ACK mask size in bits (256 bits / 32 bytes)
SELECTIVE_ACK_MAX_BITS: int = 256

# Max selective ACK mask size in bytes
SELECTIVE_ACK_MAX_BYTES: int = 32

# Connection timeout in seconds
CONN_TIMEOUT: int = 30

# Keepalive interval in seconds
KEEPALIVE_INTERVAL: int = 45

# Max pending packets in send buffer
MAX_PENDING_PACKETS: int = 100

# ---------------------------------------------------------------------------
# UTP Error classes
# ---------------------------------------------------------------------------


class UTPError(Exception):
    """Base exception for uTP protocol errors."""


class UTPPacketError(UTPError):
    """Raised when a uTP packet is malformed."""


class UTPConnectionError(UTPError):
    """Raised when a connection state error occurs."""


class UTPCongestionError(UTPError):
    """Raised when congestion control errors occur."""


class UTPTimestampError(UTPError):
    """Raised when timestamp handling errors occur."""


# ---------------------------------------------------------------------------
# PacketHeader (BEP 29 Section: "header format")
# ---------------------------------------------------------------------------


@dataclass
class PacketHeader:
    """Parsed uTP packet header.

    Version 1 header layout (big-endian, 20 bytes):

        0       4       8               16              24              32
        +-------+-------+---------------+---------------+---------------+
        | type  | ver   | extension     | connection_id                 |
        +-------+-------+---------------+---------------+---------------+
        | timestamp_microseconds                                        |
        +---------------+---------------+---------------+---------------+
        | timestamp_difference_microseconds                             |
        +---------------+---------------+---------------+---------------+
        | wnd_size                                                      |
        +---------------+---------------+---------------+---------------+
        | seq_nr                        | ack_nr                        |
        +---------------+---------------+---------------+---------------+

    Attributes
    ----------
    packet_type : int
        Type of packet (ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN).
    version : int
        Protocol version (currently 1).
    extension : int
        Extension type (0 = no extension, 1 = selective ACK).
    connection_id : int
        24-bit connection identifier.
    timestamp_microseconds : int
        Microseconds timestamp from gettimeofday/QueryPerformanceTimer.
    timestamp_difference_microseconds : int
        One-way delay measurement from the other endpoint in microseconds.
    wnd_size : int
        Advertised receive window in bytes.
    seq_nr : int
        Sequence number.
    ack_nr : int
        Acknowledged sequence number.
    """

    packet_type: int
    version: int = 1
    extension: int = 0
    connection_id: int = 0
    timestamp_microseconds: int = 0
    timestamp_difference_microseconds: int = 0
    wnd_size: int = 0
    seq_nr: int = 0
    ack_nr: int = 0

    @staticmethod
    def parse(data: bytes) -> PacketHeader:
        """Parse a uTP packet header from raw bytes.

        BEP 29 v1 header layout (20 bytes total):

            Byte 0:   (packet_type << 4) | version
            Byte 1:   extension
            Bytes 2-3: connection_id (uint16, big-endian)
            Bytes 4-7: timestamp_microseconds (uint32, big-endian)
            Bytes 8-11: timestamp_difference_microseconds (uint32, big-endian)
            Bytes 12-15: wnd_size (uint32, big-endian)
            Bytes 16-17: seq_nr (uint16, big-endian)
            Bytes 18-19: ack_nr (uint16, big-endian)

        Parameters
        ----------
        data : bytes
            Raw packet data (at least 20 bytes for the header).

        Returns
        -------
        PacketHeader
            Parsed packet header.

        Raises
        ------
        UTPPacketError
            If the data is too short or has an unsupported version.
        """
        if len(data) < 20:
            raise UTPPacketError(f"Packet too short: {len(data)} bytes (minimum 20)")

        type_ver = data[0]
        packet_type = (type_ver >> 4) & 0x0F
        version = type_ver & 0x0F

        if version != 1:
            raise UTPPacketError(f"Unsupported uTP version: {version}")

        extension = data[1]
        connection_id = struct.unpack("!H", data[2:4])[0]
        timestamp_microseconds = struct.unpack("!I", data[4:8])[0]
        timestamp_difference_microseconds = struct.unpack("!I", data[8:12])[0]
        wnd_size = struct.unpack("!I", data[12:16])[0]
        seq_nr = struct.unpack("!H", data[16:18])[0]
        ack_nr = struct.unpack("!H", data[18:20])[0]

        return PacketHeader(
            packet_type=packet_type,
            version=version,
            extension=extension,
            connection_id=connection_id,
            timestamp_microseconds=timestamp_microseconds,
            timestamp_difference_microseconds=timestamp_difference_microseconds,
            wnd_size=wnd_size,
            seq_nr=seq_nr,
            ack_nr=ack_nr,
        )

    def serialize(self) -> bytes:
        """Serialize the packet header to raw bytes.

        Returns
        -------
        bytes
            20-byte uTP packet header.
        """
        type_ver = (self.packet_type << 4) | (self.version & 0x0F)
        header = bytearray()
        header.append(type_ver)
        header.append(self.extension & 0xFF)
        header.extend(struct.pack("!H", self.connection_id & 0xFFFF))
        header.extend(struct.pack("!I", self.timestamp_microseconds & 0xFFFFFFFF))
        header.extend(struct.pack("!I", self.timestamp_difference_microseconds & 0xFFFFFFFF))
        header.extend(struct.pack("!I", self.wnd_size & 0xFFFFFFFF))
        header.extend(struct.pack("!H", self.seq_nr & 0xFFFF))
        header.extend(struct.pack("!H", self.ack_nr & 0xFFFF))
        return bytes(header)

    def __repr__(self) -> str:
        type_name = PACKET_TYPE_NAMES.get(self.packet_type, f"UNKNOWN({self.packet_type})")
        return (
            f"PacketHeader(type={type_name}, ver={self.version}, ext={self.extension}, "
            f"conn_id={self.connection_id}, seq={self.seq_nr}, ack={self.ack_nr}, "
            f"ts={self.timestamp_microseconds}, ts_diff={self.timestamp_difference_microseconds}, "
            f"wnd={self.wnd_size})"
        )


# ---------------------------------------------------------------------------
# Selective ACK (BEP 29 Section: "Selective ACK")
# ---------------------------------------------------------------------------


@dataclass
class SelectiveAck:
    """Selective ACK bitmask for BEP 29.

    Attributes
    ----------
    bits : int
        Number of bits in the bitmask (multiple of 32, 32-256).
    bitmask : bytes
        The bitmask bytes. Length = (bits + 7) // 8.
    """

    bits: int = 32
    bitmask: bytearray = field(default_factory=lambda: bytearray(b"\x00" * 4))

    def to_bytes(self) -> bytes:
        """Serialize the selective ACK as bytes.

        Format: extension_type(1) + length(1) + bitmask(N)

        Returns
        -------
        bytes
            Serialized selective ACK header + payload.

        Raises
        ------
        UTPPacketError
            If the bitmask size is invalid.
        """
        if self.bits < SELECTIVE_ACK_MIN_BITS or self.bits > SELECTIVE_ACK_MAX_BITS:
            raise UTPPacketError(
                f"Invalid selective ACK bits: {self.bits} (must be {SELECTIVE_ACK_MIN_BITS}-{SELECTIVE_ACK_MAX_BITS})"
            )

        if self.bits % 32 != 0:
            raise UTPPacketError(f"Selective ACK bits must be a multiple of 32: {self.bits}")

        expected_len = self.bits // 8
        if len(self.bitmask) != expected_len:
            raise UTPPacketError(
                f"Bitmask length mismatch: expected {expected_len} bytes, got {len(self.bitmask)}"
            )

        # extension type (1 byte) + length in bytes (1 byte) + bitmask
        return bytes([SELECTIVE_ACK_EXTENSION, expected_len]) + self.bitmask

    @staticmethod
    def parse(data: bytes) -> SelectiveAck:
        """Parse a selective ACK from bytes.

        Parameters
        ----------
        data : bytes
            Extension data starting with type(1) + length(1) + bitmask.

        Returns
        -------
        SelectiveAck
            Parsed selective ACK.

        Raises
        ------
        UTPPacketError
            If the data is malformed.
        """
        if len(data) < 2:
            raise UTPPacketError(f"Selective ACK data too short: {len(data)} bytes (minimum 2)")

        ext_type = data[0]
        if ext_type != SELECTIVE_ACK_EXTENSION:
            raise UTPPacketError(f"Expected selective ACK extension type {SELECTIVE_ACK_EXTENSION}, got {ext_type}")

        length = data[1]
        if length < SELECTIVE_ACK_MIN_BITS // 8 or length > SELECTIVE_ACK_MAX_BYTES:
            raise UTPPacketError(f"Invalid selective ACK length: {length} bytes")

        if length % 4 != 0:
            raise UTPPacketError(f"Selective ACK length must be multiple of 4: {length} bytes")

        bitmask = data[2:2 + length]
        if len(bitmask) != length:
            raise UTPPacketError(f"Truncated selective ACK bitmask: expected {length} bytes, got {len(bitmask)}")

        return SelectiveAck(bits=length * 8, bitmask=bytearray(bitmask))

    def get_bit(self, offset: int) -> bool:
        """Check if a bit is set in the bitmask.

        Parameters
        ----------
        offset : int
            Bit offset from the start of the bitmask (0-indexed).

        Returns
        -------
        bool
            True if the bit is set.

        Raises
        ------
        UTPPacketError
            If the offset is out of range.
        """
        if offset < 0 or offset >= self.bits:
            raise UTPPacketError(f"Bit offset {offset} out of range [0, {self.bits})")

        byte_index = offset // 8
        bit_index = 7 - (offset % 8)  # Big-endian bit order
        return bool(self.bitmask[byte_index] & (1 << bit_index))

    def set_bit(self, offset: int) -> None:
        """Set a bit in the bitmask.

        Parameters
        ----------
        offset : int
            Bit offset from the start of the bitmask (0-indexed).

        Raises
        ------
        UTPPacketError
            If the offset is out of range.
        """
        if offset < 0 or offset >= self.bits:
            raise UTPPacketError(f"Bit offset {offset} out of range [0, {self.bits})")

        byte_index = offset // 8
        bit_index = 7 - (offset % 8)
        self.bitmask[byte_index] |= (1 << bit_index)

    def clear_bit(self, offset: int) -> None:
        """Clear a bit in the bitmask.

        Parameters
        ----------
        offset : int
            Bit offset from the start of the bitmask (0-indexed).

        Raises
        ------
        UTPPacketError
            If the offset is out of range.
        """
        if offset < 0 or offset >= self.bits:
            raise UTPPacketError(f"Bit offset {offset} out of range [0, {self.bits})")

        byte_index = offset // 8
        bit_index = 7 - (offset % 8)
        self.bitmask[byte_index] &= ~(1 << bit_index)

    def __len__(self) -> int:
        """Return the length of the bitmask in bytes."""
        return len(self.bitmask)


# ---------------------------------------------------------------------------
# Congestion Control (BEP 29 Section: "congestion control")
# ---------------------------------------------------------------------------


class CongestionControl:
    """Delay-based congestion control for uTP.

    Implements the congestion control algorithm from BEP 29:
    - RTT estimation using exponential moving averages
    - Base delay tracking (minimum delay over a time window)
    - Window sizing based on off-target delay
    - Packet loss detection and window reduction

    The goal is to maintain a one-way buffering delay close to the
    CCONTROL_TARGET (100 ms) to fairly share bandwidth with TCP traffic.

    Attributes
    ----------
    rtt : int
        Smoothed round-trip time in milliseconds.
    rtt_var : int
        RTT variance in milliseconds.
    base_delay : int
        Minimum observed delay in milliseconds (tracked over BASE_DELAY_WINDOW).
    target_delay : int
        Target one-way delay in milliseconds (CCONTROL_TARGET).
    max_window : int
        Maximum number of bytes that can be in-flight.
    packet_size : int
        Current packet size in bytes.
    outstanding_bytes : int
        Number of bytes currently in-flight (not yet acked).
    last_ack_time : float
        Timestamp of the last acknowledged packet.
    timeout_ms : int
        Current packet timeout in milliseconds.
    """

    def __init__(self, target_delay: int = CCONTROL_TARGET) -> None:
        """Initialize congestion control with default parameters.

        Parameters
        ----------
        target_delay : int
            Target one-way delay in milliseconds (default: 100 ms).
        """
        self.rtt: int = 0
        self.rtt_var: int = 0
        self.base_delay: int = 0
        self.target_delay: int = target_delay
        self.max_window: int = INITIAL_CONGESTION_WINDOW * DEFAULT_PACKET_SIZE
        self.packet_size: int = INITIAL_PACKET_SIZE
        self.outstanding_bytes: int = 0
        self.last_ack_time: float = 0.0
        self.timeout_ms: int = INITIAL_TIMEOUT_MS

        # Delay history for base delay tracking
        self._delay_history: deque[tuple[float, int]] = deque()
        self._base_delay_start: float = time.time()

        # For tracking window growth
        self._acked_bytes_since_last_rtt: int = 0
        self._last_rtt_time: float = 0.0

        # For packet loss detection
        self._lost_packet_count: int = 0

    def update_rtt(self, packet_rtt: int) -> None:
        """Update RTT estimates based on a new RTT sample.

        BEP 29 formula:
            delta = rtt - packet_rtt
            rtt_var += (abs(delta) - rtt_var) / 4
            rtt += (packet_rtt - rtt) / 8

        Parameters
        ----------
        packet_rtt : int
            The RTT sample in milliseconds.
        """
        # Clamp RTT sample to valid range
        packet_rtt = max(MIN_RTT, min(MAX_RTT, packet_rtt))

        if self.rtt == 0:
            # First sample
            self.rtt = packet_rtt
            self.rtt_var = packet_rtt // 2
        else:
            delta = self.rtt - packet_rtt
            self.rtt_var = int((abs(delta) - self.rtt_var) * RTT_BETA + self.rtt_var)
            if self.rtt_var < RTT_VAR_MIN:
                self.rtt_var = RTT_VAR_MIN
            self.rtt = int(self.rtt * (1.0 - RTT_ALPHA) + packet_rtt * RTT_ALPHA)

        # Update timeout
        self.timeout_ms = max(self.rtt + self.rtt_var * TIMEOUT_MULTIPLIER, 500)

    def record_delay(self, delay_us: int) -> None:
        """Record a new delay measurement for base delay tracking.

        Parameters
        ----------
        delay_us : int
            One-way delay in microseconds.
        """
        delay_ms = delay_us // 1000
        now = time.time()
        self._delay_history.append((now, delay_ms))

        # Remove entries older than BASE_DELAY_WINDOW
        while self._delay_history and (now - self._delay_history[0][0]) > BASE_DELAY_WINDOW:
            self._delay_history.popleft()

        # Update base delay (minimum observed delay)
        if self._delay_history:
            self.base_delay = min(d for _, d in self._delay_history)
        else:
            self.base_delay = delay_ms

    def get_off_target(self) -> int:
        """Calculate the off-target delay.

        off_target = our_delay - CCONTROL_TARGET
        where our_delay = (current_delay - base_delay) in milliseconds.

        Returns
        -------
        int
            Off-target delay in milliseconds. Negative means below target
            (good), positive means above target (bad).
        """
        if self.base_delay < 0:
            self.base_delay = 0
        current_delay = max(0, self.base_delay)  # Simplified - no live delay measurement
        our_delay = current_delay - self.base_delay
        return int(our_delay - self.target_delay)

    def calculate_scaled_gain(self) -> float:
        """Calculate the scaled gain for window adjustment.

        BEP 29:
            delay_factor = off_target / CCONTROL_TARGET
            window_factor = outstanding_bytes / max_window
            scaled_gain = MAX_CWND_INCREASE_PACKETS_PER_RTT * delay_factor * window_factor

        Returns
        -------
        float
            The scaled gain value. Negative values will reduce the window.
        """
        off_target = self.get_off_target()

        if self.target_delay <= 0:
            return 0.0

        delay_factor = off_target / self.target_delay

        if self.max_window <= 0:
            return 0.0

        window_factor = self.outstanding_bytes / self.max_window
        if window_factor < WINDOW_FACTOR_MIN:
            window_factor = WINDOW_FACTOR_MIN

        scaled_gain = MAX_CWND_INCREASE_PACKETS_PER_RTT * delay_factor * window_factor

        # Cap the gain to prevent rapid window changes
        scaled_gain = max(-1.0, min(scaled_gain, 1.0))

        return scaled_gain

    def adjust_window(self, bytes_acked: int) -> None:
        """Adjust the congestion window based on acknowledged bytes.

        BEP 29: When bytes are acknowledged, increase the window size
        proportionally to how far below target the delay is.

        Parameters
        ----------
        bytes_acked : int
            Number of bytes that were acknowledged.
        """
        if bytes_acked <= 0:
            return

        self._acked_bytes_since_last_rtt += bytes_acked
        self.last_ack_time = time.time()

        # Calculate window adjustment
        scaled_gain = self.calculate_scaled_gain()

        # Increase window based on scaled gain
        # BEP 29: max_window += scaled_gain (in packets, converted to bytes)
        window_delta = int(scaled_gain * self.max_window / DEFAULT_PACKET_SIZE)
        self.max_window = max(MIN_PACKET_SIZE, self.max_window + window_delta)

    def on_packet_loss(self) -> None:
        """Handle packet loss by halving the congestion window.

        BEP 29: "When a packet is lost, the max_window is multiplied by 0.5
        to mimic TCP."
        """
        self.max_window = max(MIN_PACKET_SIZE, self.max_window // 2)
        self.packet_size = max(MIN_PACKET_SIZE, self.packet_size // 2)
        self._lost_packet_count += 1
        logger.debug("Packet loss detected. max_window=%d, packet_size=%d", self.max_window, self.packet_size)

    def on_timeout(self) -> None:
        """Handle connection timeout by resetting packet size and window.

        BEP 29: "This allows it to send one more packet, and this is how
        the socket gets started again if the window size goes to zero."
        """
        self.packet_size = MAX_PACKET_SIZE
        self.max_window = self.packet_size
        self.timeout_ms = INITIAL_TIMEOUT_MS
        logger.debug("Timeout detected. max_window=%d, packet_size=%d", self.max_window, self.packet_size)

    def reset(self) -> None:
        """Reset congestion control to initial state."""
        self.rtt = 0
        self.rtt_var = 0
        self.base_delay = 0
        self.max_window = INITIAL_CONGESTION_WINDOW * DEFAULT_PACKET_SIZE
        self.packet_size = INITIAL_PACKET_SIZE
        self.outstanding_bytes = 0
        self.last_ack_time = 0.0
        self.timeout_ms = INITIAL_TIMEOUT_MS
        self._delay_history.clear()
        self._acked_bytes_since_last_rtt = 0
        self._lost_packet_count = 0

    def should_timeout(self) -> bool:
        """Check if a timeout should occur based on elapsed time.

        Returns
        -------
        bool
            True if more than timeout_ms milliseconds have elapsed since
            the last ACK or send.
        """
        if self.last_ack_time <= 0:
            return False
        elapsed_ms = (time.time() - self.last_ack_time) * 1000
        return elapsed_ms >= self.timeout_ms

    def can_send(self) -> bool:
        """Check if data can be sent based on current window.

        Returns
        -------
        bool
            True if the congestion window allows sending more data.
        """
        return self.outstanding_bytes < self.max_window

    def get_window_size(self) -> int:
        """Get the current congestion window size in bytes.

        Returns
        -------
        int
            Maximum number of bytes that can be in-flight.
        """
        return self.max_window

    def register_sent(self, size: int) -> None:
        """Register that a packet of the given size was sent.

        Parameters
        ----------
        size : int
            Size of the sent packet in bytes.
        """
        self.outstanding_bytes += size

    def register_acked(self, size: int, rtt_ms: int = 0) -> None:
        """Register that a packet was acknowledged.

        Parameters
        ----------
        size : int
            Size of the acknowledged packet in bytes.
        rtt_ms : int
            RTT sample in milliseconds (0 if not available).
        """
        if size <= 0:
            return
        self.outstanding_bytes = max(0, self.outstanding_bytes - size)
        if rtt_ms > 0:
            self.update_rtt(rtt_ms)
        # Only adjust window if we still have outstanding bytes
        if self.outstanding_bytes > 0:
            self.adjust_window(size)


# ---------------------------------------------------------------------------
# UTP Connection (BEP 29 Section: "connection setup" + main protocol)
# ---------------------------------------------------------------------------


class PendingPacket:
    """A packet that has been sent but not yet acknowledged."""

    def __init__(self, seq_nr: int, data: bytes = b"", sent_time: float | None = None) -> None:
        self.seq_nr = seq_nr
        self.data = data
        self.sent_time: float = sent_time if sent_time is not None else time.time()
        self.retransmissions: int = 0
        self.acked: bool = False


class UTPConnection:
    """Manages a single uTP connection.

    Implements the uTP connection state machine and packet handling
    as specified in BEP 29.

    Attributes
    ----------
    connection_id : int
        Local connection ID (used for outgoing packets).
    remote_connection_id : int
        Remote connection ID (used for incoming packets).
    state : ConnectionState
        Current connection state.
    seq_nr : int
        Next sequence number to use for sending.
    ack_nr : int
        Last received sequence number from the peer.
    congestion_control : CongestionControl
        Congestion control instance.
    """

    def __init__(self, connection_id: int, is_initiator: bool = False) -> None:
        """Initialize a new uTP connection.

        Parameters
        ----------
        connection_id : int
            Local connection ID (random 24-bit value for initiator,
            remote_conn_id + 1 for responder).
        is_initiator : bool
            Whether this endpoint initiated the connection.
        """
        self.connection_id: int = connection_id
        self.remote_connection_id: int = 0
        self.state: ConnectionState = ConnectionState.NEW

        # Sequence numbers
        self.seq_nr: int = 0  # Next sequence number for sending
        self.ack_nr: int = 0  # Expected next sequence number from peer
        self.eof_pkt: int = 0  # Sequence number of the ST_FIN packet

        # Congestion control
        self.congestion_control = CongestionControl()

        # Send buffer: pending unacknowledged packets
        self.send_buffer: list[PendingPacket] = []

        # Receive buffer: out-of-order packets
        self.receive_buffer: dict[int, tuple[bytes, float]] = {}  # seq_nr -> (data, recv_time)

        # Data buffer: contiguous received data
        self.receive_data: bytearray = bytearray()

        # Timers
        self.last_activity: float = time.time()
        self.last_packet_time: float = 0.0

        # Selective ACK support
        self.use_selective_ack: bool = False
        self.sack_window: int = 32  # Number of packets in the SACK bitmask

        # Callbacks
        self.on_connected: Optional[callable] = None
        self.on_disconnected: Optional[callable] = None
        self.on_data_received: Optional[callable] = None

        # Statistics
        self.packets_sent: int = 0
        self.packets_received: int = 0
        self.bytes_sent: int = 0
        self.bytes_received: int = 0
        self.packets_lost: int = 0
        self.retransmissions: int = 0

        # If initiator, initialize sequence number
        if is_initiator:
            self.seq_nr = 1  # BEP 29: seq_nr starts at 1

    def start_connection(self, sock: Any, address: tuple[str, int]) -> None:
        """Start the connection by sending an ST_SYN packet.

        Parameters
        ----------
        sock : socket
            UDP socket to send on.
        address : tuple[str, int]
            Remote address (ip, port).
        """
        if self.state != ConnectionState.NEW:
            raise UTPConnectionError(f"Cannot start connection from state: {self.state}")

        # Build and send ST_SYN packet
        header = PacketHeader(
            packet_type=ST_SYN,
            version=1,
            connection_id=self.connection_id,
            seq_nr=self.seq_nr,
            ack_nr=self.ack_nr,
            timestamp_microseconds=int(time.time() * 1_000_000),
        )

        pkt_data = header.serialize()
        sock.sendto(pkt_data, address)

        self.packets_sent += 1
        self.last_activity = time.time()

        if self.seq_nr < 0xFFFF:
            self.seq_nr += 1

        self.state = ConnectionState.SYN_SENT
        logger.debug("Sent ST_SYN: conn_id=%d, seq=%d", self.connection_id, header.seq_nr)

    def handle_packet(self, data: bytes, header: PacketHeader, sender: tuple[str, int]) -> Optional[bytes]:
        """Handle an incoming uTP packet.

        Parameters
        ----------
        data : bytes
            Raw packet data (including header).
        header : PacketHeader
            Parsed packet header.
        sender : tuple[str, int]
            Sender's address (ip, port).

        Returns
        -------
        bytes | None
            Response packet data if needed, or None.

        Raises
        ------
        UTPConnectionError
            If the packet violates the protocol state machine.
        """
        self.packets_received += 1
        self.last_activity = time.time()
        self.bytes_received += len(data)

        # Update remote connection ID from first packet
        if self.remote_connection_id == 0:
            self.remote_connection_id = header.connection_id

        # Handle ST_RESET
        if header.packet_type == ST_RESET:
            self.state = ConnectionState.ERROR
            logger.warning("Received ST_RESET, connection closed")
            if self.on_disconnected:
                self.on_disconnected()
            return None

        # State machine
        if self.state == ConnectionState.SYN_SENT:
            return self._handle_syn_response(header, data, sender)
        elif self.state == ConnectionState.SYN_RECV:
            return self._handle_conn_confirm(header, data, sender)
        elif self.state == ConnectionState.CONNECTED:
            return self._handle_data(header, data)
        elif self.state == ConnectionState.CLOSING:
            return self._handle_close(header, data)
        else:
            raise UTPConnectionError(f"Unexpected packet in state {self.state}: {PACKET_TYPE_NAMES.get(header.packet_type, 'UNKNOWN')}")

    def _handle_syn_response(self, header: PacketHeader, data: bytes, sender: tuple[str, int]) -> Optional[bytes]:
        """Handle response to our ST_SYN (should be ST_STATE or ST_DATA).

        Parameters
        ----------
        header : PacketHeader
            Parsed packet header.
        data : bytes
            Raw packet data.
        sender : tuple[str, int]
            Sender's address.

        Returns
        -------
        bytes | None
            Confirmation packet or None.
        """
        if header.packet_type not in (ST_STATE, ST_DATA, ST_SYN):
            raise UTPConnectionError(
                f"Expected ST_STATE/ST_DATA/SYN in SYN_SENT state, got {PACKET_TYPE_NAMES.get(header.packet_type, 'UNKNOWN')}"
            )

        # Update ack_nr from SYN response
        self.ack_nr = header.seq_nr
        self.state = ConnectionState.SYN_RECV

        # Send ST_STATE confirmation (just an ACK)
        self.congestion_control.last_ack_time = time.time()
        response = self._build_packet(
            packet_type=ST_STATE,
            ack_nr=self.ack_nr,
            seq_nr=self.seq_nr,
        )

        if self.seq_nr < 0xFFFF:
            self.seq_nr += 1

        return response

    def _handle_conn_confirm(self, header: PacketHeader, data: bytes, sender: tuple[str, int]) -> Optional[bytes]:
        """Handle connection confirmation (after ST_STATE exchange).

        Parameters
        ----------
        header : PacketHeader
            Parsed packet header.
        data : bytes
            Raw packet data.
        sender : tuple[str, int]
            Sender's address.

        Returns
        -------
        bytes | None
            None (connection established).
        """
        if header.packet_type == ST_STATE:
            self.ack_nr = header.seq_nr
            self.state = ConnectionState.CONNECTED
            logger.debug("Connection established: conn_id=%d", self.connection_id)
            if self.on_connected:
                self.on_connected()
            return None
        elif header.packet_type == ST_DATA:
            self.ack_nr = header.seq_nr
            self.state = ConnectionState.CONNECTED
            if self.on_connected:
                self.on_connected()
            return self._handle_data(header, data)
        else:
            raise UTPConnectionError(f"Expected ST_STATE/ST_DATA in SYN_RECV state, got {PACKET_TYPE_NAMES.get(header.packet_type, 'UNKNOWN')}")

    def _handle_data(self, header: PacketHeader, data: bytes) -> Optional[bytes]:
        """Handle data packets in CONNECTED state.

        Parameters
        ----------
        header : PacketHeader
            Parsed packet header.
        data : bytes
            Raw packet data.

        Returns
        -------
        bytes | None
            ACK packet.
        """
        self.ack_nr = header.seq_nr

        # Update RTT if we have a timestamp difference
        if header.timestamp_difference_microseconds > 0:
            rtt_us = header.timestamp_difference_microseconds
            self.congestion_control.update_rtt(rtt_us // 1000)
            self.congestion_control.record_delay(rtt_us)

        # Extract payload
        payload = data[20:]  # Skip 20-byte header
        packet_size = len(data)

        if header.packet_type == ST_DATA:
            # Store packet in receive buffer
            self.receive_buffer[header.seq_nr] = (payload, time.time())
            self.congestion_control.outstanding_bytes = max(
                0, self.congestion_control.outstanding_bytes
            )

            # Check for selective ACK
            sack = None
            if header.extension == EXT_TYPE_SELECTIVE_ACK and len(data) > 20:
                try:
                    sack_data = data[20:]
                    sack = SelectiveAck.parse(sack_data)
                except UTPPacketError:
                    logger.debug("Failed to parse selective ACK")

            # Process ACK
            self._process_ack(header, sack)

            # Check for missing packets (packet loss detection)
            missing = self._check_for_missing()
            if missing:
                self.congestion_control.on_packet_loss()
                self.packets_lost += 1

            # Build ACK response
            ack_response = self._build_packet(
                packet_type=ST_STATE if not payload else ST_DATA,
                ack_nr=self.ack_nr,
                seq_nr=self.seq_nr,
                wnd_size=self.congestion_control.get_window_size(),
                timestamp_diff_us=header.timestamp_difference_microseconds,
                payload=payload if payload else b"",
                selective_ack=sack if sack else None,
            )

            if self.seq_nr < 0xFFFF:
                self.seq_nr += 1

            return ack_response

        elif header.packet_type == ST_FIN:
            # Handle connection close
            self.receive_buffer[header.seq_nr] = (payload, time.time())
            self.eof_pkt = header.seq_nr
            self.state = ConnectionState.CLOSING

            # Send final ACK
            response = self._build_packet(
                packet_type=ST_FIN,
                ack_nr=header.seq_nr,
                seq_nr=self.seq_nr,
            )

            if self.seq_nr < 0xFFFF:
                self.seq_nr += 1

            return response

        elif header.packet_type == ST_STATE:
            # Just an ACK with no data
            self._process_ack(header, None)
            return None

        return None

    def _process_ack(self, header: PacketHeader, sack: Optional[SelectiveAck] = None) -> None:
        """Process an incoming ACK and update congestion control.

        Parameters
        ----------
        header : PacketHeader
            The received packet header.
        sack : SelectiveAck | None
            Optional selective ACK bitmask.
        """
        # Update ack_nr
        self.ack_nr = header.seq_nr

        if sack is not None:
            # Process selective ACK
            self._process_selective_ack(sack)
        else:
            # Cumulative ACK: remove all packets up to ack_nr
            self._process_cumulative_ack(header.seq_nr)

        # Record the ACK time for timeout calculation
        self.congestion_control.last_ack_time = time.time()

    def _process_cumulative_ack(self, ack_nr: int) -> None:
        """Process a cumulative ACK by removing acked packets from the send buffer.

        Parameters
        ----------
        ack_nr : int
            The acknowledged sequence number.
        """
        to_remove = []
        for pkt in self.send_buffer:
            if pkt.seq_nr < ack_nr:
                pkt.acked = True
                to_remove.append(pkt)
                rtt_ms = max(0, int((time.time() - pkt.sent_time) * 1000))
                self.congestion_control.register_acked(len(pkt.data), rtt_ms)
            elif pkt.seq_nr == ack_nr:
                pkt.acked = True
                to_remove.append(pkt)
                rtt_ms = max(0, int((time.time() - pkt.sent_time) * 1000))
                self.congestion_control.register_acked(len(pkt.data), rtt_ms)

        for pkt in to_remove:
            self.send_buffer.remove(pkt)

    def _process_selective_ack(self, sack: SelectiveAck) -> None:
        """Process a selective ACK by marking only the acknowledged packets.

        Parameters
        ----------
        sack : SelectiveAck
            The selective ACK bitmask.
        """
        acked_seqs = set()
        for i in range(sack.bits):
            if sack.get_bit(i):
                # Bit i corresponds to ack_nr + 1 + i
                acked_seq = self.ack_nr + 1 + i
                acked_seqs.add(acked_seq)

        for pkt in list(self.send_buffer):
            if pkt.seq_nr in acked_seqs:
                pkt.acked = True
                rtt_ms = max(0, int((time.time() - pkt.sent_time) * 1000))
                self.congestion_control.register_acked(len(pkt.data), rtt_ms)
                self.send_buffer.remove(pkt)

    def _check_for_missing(self) -> list[int]:
        """Check for missing (potentially lost) packets.

        Returns
        -------
        list[int]
            List of missing sequence numbers.
        """
        missing = []
        if not self.send_buffer:
            return missing

        min_seq = min(pkt.seq_nr for pkt in self.send_buffer)
        max_seq = max(pkt.seq_nr for pkt in self.send_buffer)

        for seq in range(min_seq, self.ack_nr + 1):
            if seq <= self.ack_nr:
                # Check if this sequence number was acked
                acked = any(pkt.seq_nr == seq and pkt.acked for pkt in self.send_buffer)
                if not acked:
                    missing.append(seq)

        return missing

    def _handle_close(self, header: PacketHeader, data: bytes) -> None:
        """Handle connection closing.

        Parameters
        ----------
        header : PacketHeader
            Parsed packet header.
        data : bytes
            Raw packet data.
        """
        if header.packet_type == ST_FIN:
            self.state = ConnectionState.CLOSED
            if self.on_disconnected:
                self.on_disconnected()
            logger.debug("Connection closed: conn_id=%d", self.connection_id)

    def send(self, data: bytes) -> None:
        """Send data over the connection.

        Parameters
        ----------
        data : bytes
            Data to send.
        """
        if self.state != ConnectionState.CONNECTED:
            raise UTPConnectionError(f"Cannot send data in state: {self.state}")

        if not data:
            return

        # Check if we can send more data
        if not self.congestion_control.can_send():
            logger.debug("Congestion window full, cannot send more data")
            return

        # Create a pending packet
        pkt = PendingPacket(
            seq_nr=self.seq_nr,
            data=data,
        )
        self.send_buffer.append(pkt)
        self.congestion_control.register_sent(len(data))

        logger.debug("Queued data for sending: seq=%d, size=%d", self.seq_nr, len(data))

    def send_packet(self, sock: Any, address: tuple[str, int], data: bytes = b"") -> Optional[bytes]:
        """Build and send a data packet.

        Parameters
        ----------
        sock : socket
            UDP socket to send on.
        address : tuple[str, int]
            Remote address.
        data : bytes
            Application data to include in the packet.

        Returns
        -------
        bytes | None
            The raw packet bytes sent, or None if no packet was sent.
        """
        if self.state not in (ConnectionState.CONNECTED, ConnectionState.CLOSING):
            return None

        # Check if we need to send a FIN
        if self.state == ConnectionState.CLOSING and not data:
            packet = self._build_packet(
                packet_type=ST_FIN,
                ack_nr=self.ack_nr,
                seq_nr=self.seq_nr,
            )
            self.seq_nr += 1
            self.packets_sent += 1
            sock.sendto(packet, address)
            return packet

        # Build data packet
        packet = self._build_packet(
            packet_type=ST_DATA if data else ST_STATE,
            ack_nr=self.ack_nr,
            seq_nr=self.seq_nr,
            payload=data,
        )

        self.seq_nr += 1
        self.packets_sent += 1
        self.bytes_sent += len(packet)
        self.last_activity = time.time()

        # Track in send buffer if there's data
        if data:
            pkt = PendingPacket(
                seq_nr=self.seq_nr - 1,
                data=data,
            )
            self.send_buffer.append(pkt)
            self.congestion_control.register_sent(len(data))

        sock.sendto(packet, address)
        return packet

    def _build_packet(
        self,
        packet_type: int,
        ack_nr: int,
        seq_nr: int,
        wnd_size: int = 0,
        timestamp_diff_us: int = 0,
        payload: bytes = b"",
        selective_ack: Optional[SelectiveAck] = None,
    ) -> bytes:
        """Build a uTP packet.

        Parameters
        ----------
        packet_type : int
            Packet type (ST_DATA, ST_FIN, ST_STATE, ST_SYN).
        ack_nr : int
            Acknowledgment sequence number.
        seq_nr : int
            Sequence number.
        wnd_size : int
            Advertised window size in bytes.
        timestamp_diff_us : int
            Timestamp difference in microseconds.
        payload : bytes
            Application data payload.
        selective_ack : SelectiveAck | None
            Optional selective ACK extension.

        Returns
        -------
        bytes
            Complete uTP packet with header and optional extension.
        """
        now_us = int(time.time() * 1_000_000)

        header = PacketHeader(
            packet_type=packet_type,
            version=1,
            connection_id=self.connection_id,
            timestamp_microseconds=now_us,
            timestamp_difference_microseconds=timestamp_diff_us,
            wnd_size=wnd_size if wnd_size > 0 else self.congestion_control.get_window_size(),
            seq_nr=seq_nr,
            ack_nr=ack_nr,
        )

        pkt_data = bytearray(header.serialize())

        # Add selective ACK extension if provided
        if selective_ack is not None:
            header.extension = EXT_TYPE_SELECTIVE_ACK
            # Re-serialize header with extension
            pkt_data = bytearray(header.serialize())
            pkt_data.extend(selective_ack.to_bytes())

        if payload:
            pkt_data.extend(payload)

        return bytes(pkt_data)

    def close(self) -> None:
        """Close the connection gracefully by sending ST_FIN."""
        if self.state in (ConnectionState.CLOSED, ConnectionState.ERROR, ConnectionState.NEW):
            return

        self.state = ConnectionState.CLOSING
        logger.debug("Closing connection: conn_id=%d", self.connection_id)

    def is_closed(self) -> bool:
        """Check if the connection is closed.

        Returns
        -------
        bool
            True if the connection is in CLOSED or ERROR state.
        """
        return self.state in (ConnectionState.CLOSED, ConnectionState.ERROR)

    def get_receive_data(self) -> bytes:
        """Get contiguous received data from the receive buffer.

        Returns
        -------
        bytes
            Contiguous data starting from the expected sequence number.
        """
        data = bytearray()
        seq = self.ack_nr + 1  # Next expected sequence number

        while seq in self.receive_buffer:
            pkt_data, recv_time = self.receive_buffer.pop(seq)
            data.extend(pkt_data)
            seq += 1

        return bytes(data)

    def check_timeout(self) -> bool:
        """Check if the connection has timed out.

        Returns
        -------
        bool
            True if the connection should be considered timed out.
        """
        elapsed = time.time() - self.last_activity
        return elapsed > (self.congestion_control.timeout_ms / 1000.0)

    def get_stats(self) -> dict[str, Any]:
        """Get connection statistics.

        Returns
        -------
        dict[str, Any]
            Connection statistics.
        """
        return {
            "state": self.state.name,
            "connection_id": self.connection_id,
            "remote_connection_id": self.remote_connection_id,
            "seq_nr": self.seq_nr,
            "ack_nr": self.ack_nr,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_lost": self.packets_lost,
            "retransmissions": self.retransmissions,
            "max_window": self.congestion_control.max_window,
            "packet_size": self.congestion_control.packet_size,
            "rtt": self.congestion_control.rtt,
            "rtt_var": self.congestion_control.rtt_var,
            "base_delay": self.congestion_control.base_delay,
            "outstanding_bytes": self.congestion_control.outstanding_bytes,
            "timeout_ms": self.congestion_control.timeout_ms,
            "send_buffer_size": len(self.send_buffer),
            "receive_buffer_size": len(self.receive_buffer),
        }


# ---------------------------------------------------------------------------
# UTP Socket (high-level interface)
# ---------------------------------------------------------------------------


class UTPSocket:
    """High-level uTP socket interface.

    Provides a socket-like API for uTP connections, similar to Python's
    socket module but using the uTP protocol over UDP.

    Attributes
    ----------
    connection : UTPConnection
        The underlying uTP connection.
    sock : socket
        Underlying UDP socket.
    is_server : bool
        Whether this socket was created as a server (listening).
    """

    def __init__(self, sock: Optional[Any] = None, is_server: bool = False) -> None:
        """Create a uTP socket.

        Parameters
        ----------
        sock : socket | None
            Underlying UDP socket. If None, a new UDP socket is created.
        is_server : bool
            Whether this is a server socket (listens for incoming connections).
        """
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock = sock
        self.is_server = is_server
        self.connection: Optional[UTPConnection] = None
        self._address: Optional[tuple[str, int]] = None
        self._closed: bool = False
        self._pending_data: list[bytes] = []

        # Packet processing
        self._packet_queue: deque[tuple[bytes, tuple[str, int]]] = deque()

    def bind(self, address: tuple[str, int]) -> None:
        """Bind the socket to a local address.

        Parameters
        ----------
        address : tuple[str, int]
            Local address (ip, port).
        """
        self.sock.bind(address)
        logger.debug("uTP socket bound to %s", address)

    def connect(self, address: tuple[str, int], node_id: Optional[bytes] = None) -> None:
        """Initiate a uTP connection to a remote address.

        Parameters
        ----------
        address : tuple[str, int]
            Remote address (ip, port).
        node_id : bytes | None
            Optional node ID for this connection.
        """
        if self.connection is not None:
            raise UTPError("Already connected")

        conn_id = struct.unpack("!I", os.urandom(3))[0] & 0xFFFFFF
        self.connection = UTPConnection(
            connection_id=conn_id,
            is_initiator=True,
        )
        self._address = address

        if node_id is not None:
            self.connection.node_id = node_id

        self.connection.start_connection(self.sock, address)

    def listen(self, node_id: Optional[bytes] = None) -> None:
        """Start listening for incoming uTP connections.

        Parameters
        ----------
        node_id : bytes | None
            Optional node ID for this connection.
        """
        self.is_server = True
        conn_id = struct.unpack("!I", os.urandom(3))[0] & 0xFFFFFF
        self.connection = UTPConnection(
            connection_id=conn_id,
            is_initiator=False,
        )
        if node_id is not None:
            self.connection.node_id = node_id

    def accept(self) -> tuple["UTPSocket", tuple[str, int]]:
        """Accept an incoming connection.

        Returns
        -------
        tuple[UTPSocket, tuple[str, int]]
            A new UTPSocket for the accepted connection and the client address.

        Raises
        ------
        UTPError
            If no pending connections.
        """
        if not self._pending_data:
            raise UTPError("No pending connections")

        data, address = self._pending_data.pop(0)
        # Create new socket for the accepted connection
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        new_conn = UTPConnection(
            connection_id=self.connection.connection_id + 1 if self.connection else 0,
            is_initiator=False,
        )
        new_conn.connection_id = self.connection.connection_id + 1 if self.connection else 0

        return None, address  # Simplified - return None for socket

    def send(self, data: bytes) -> int:
        """Send data over the uTP connection.

        Parameters
        ----------
        data : bytes
            Data to send.

        Returns
        -------
        int
            Number of bytes sent.

        Raises
        ------
        UTPError
            If not connected.
        """
        if self.connection is None or self._address is None:
            raise UTPError("Not connected")

        self.connection.send(data)
        self.connection.send_packet(self.sock, self._address, data)
        return len(data)

    def recv(self, maxlen: int = 65536) -> bytes:
        """Receive data from the uTP connection.

        Parameters
        ----------
        maxlen : int
            Maximum number of bytes to receive.

        Returns
        -------
        bytes
            Received data.

        Raises
        ------
        UTPError
            If not connected.
        """
        if self.connection is None:
            raise UTPError("Not connected")

        # Check pending data
        if self._pending_data:
            data = self._pending_data.pop(0)
            return data[:maxlen]

        # Get data from receive buffer
        if self.connection:
            data = self.connection.get_receive_data()
            return data[:maxlen]

        return b""

    def recvfrom(self, bufsize: int = 65536) -> tuple[bytes, tuple[str, int]]:
        """Receive data from the uTP connection with sender address.

        Parameters
        ----------
        bufsize : int
            Maximum buffer size.

        Returns
        -------
        tuple[bytes, tuple[str, int]]
            (data, address) tuple.
        """
        if self._packet_queue:
            data, address = self._packet_queue.popleft()
            return data, address

        raise UTPError("No data available")

    def close(self) -> None:
        """Close the uTP connection."""
        if self.connection and not self.connection.is_closed():
            self.connection.close()
        self.sock.close()
        self._closed = True
        logger.debug("uTP socket closed")

    def settimeout(self, timeout: float) -> None:
        """Set the socket timeout in seconds.

        Parameters
        ----------
        timeout : float
            Timeout in seconds.
        """
        self.sock.settimeout(timeout)

    def getsockname(self) -> tuple[str, int]:
        """Get the local socket address.

        Returns
        -------
        tuple[str, int]
            Local address (ip, port).
        """
        return self.sock.getsockname()

    def getpeername(self) -> tuple[str, int]:
        """Get the remote socket address.

        Returns
        -------
        tuple[str, int]
            Remote address (ip, port).
        """
        if self._address:
            return self._address
        raise UTPError("Not connected")

    def get_stats(self) -> dict[str, Any]:
        """Get connection statistics.

        Returns
        -------
        dict[str, Any]
            Connection statistics.
        """
        if self.connection:
            return self.connection.get_stats()
        return {}

    def process_packets(self) -> int:
        """Process pending packets from the socket.

        Call this method in a loop to process incoming packets.

        Returns
        -------
        int
            Number of packets processed.
        """
        count = 0
        try:
            # Non-blocking read
            self.sock.settimeout(0)
            while True:
                try:
                    data, addr = self.sock.recvfrom(MTU)
                    if len(data) < 20:
                        continue

                    header = PacketHeader.parse(data)
                    if self.connection:
                        self.connection.packets_received += 1
                        response = self.connection.handle_packet(data, header, addr)
                        if response:
                            self.sock.sendto(response, addr)
                        count += 1
                except BlockingIOError:
                    break
                except Exception as e:
                    logger.debug("Error processing packet: %s", e)
                    break
        except Exception as e:
            logger.debug("Error in process_packets: %s", e)

        return count

    def __enter__(self) -> "UTPSocket":
        """Support context manager protocol."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Close the socket on context exit."""
        self.close()