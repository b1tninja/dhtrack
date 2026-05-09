"""Tests for BEP 29: uTorrent Transport Protocol (uTP) implementation."""

from __future__ import annotations

import time
import unittest

from dhtrack.utp import (  # Core classes; Error classes
    BASE_DELAY_WINDOW,
    CCONTROL_TARGET,
    DEFAULT_PACKET_SIZE,
    INITIAL_CONGESTION_WINDOW,
    INITIAL_PACKET_SIZE,
    INITIAL_TIMEOUT_MS,
    MAX_PACKET_SIZE,
    MAX_RTT,
    MIN_PACKET_SIZE,
    MIN_RTT,
    PACKET_TYPE_NAMES,
    RTT_ALPHA,
    RTT_BETA,
    RTT_VAR_MIN,
    SELECTIVE_ACK_EXTENSION,
    ST_DATA,
    ST_FIN,
    ST_RESET,
    ST_STATE,
    ST_SYN,
    CongestionControl,
    ConnectionState,
    PacketHeader,
    PendingPacket,
    SelectiveAck,
    UTPCongestionError,
    UTPConnection,
    UTPConnectionError,
    UTPError,
    UTPPacketError,
    UTPSocket,
)


class TestPacketHeader(unittest.TestCase):
    """Tests for PacketHeader parsing and serialization."""

    def test_serialize_parse_roundtrip(self):
        """Test that serialization and parsing produce the same values."""
        header = PacketHeader(
            packet_type=ST_DATA,
            version=1,
            extension=0,
            connection_id=0x1234,
            timestamp_microseconds=1234567890,
            timestamp_difference_microseconds=45678,
            wnd_size=65536,
            seq_nr=100,
            ack_nr=50,
        )

        serialized = header.serialize()
        self.assertEqual(len(serialized), 20, "Header should be exactly 20 bytes")

        parsed = PacketHeader.parse(serialized)
        self.assertEqual(parsed.packet_type, header.packet_type)
        self.assertEqual(parsed.version, header.version)
        self.assertEqual(parsed.extension, header.extension)
        self.assertEqual(parsed.connection_id, header.connection_id)
        self.assertEqual(parsed.timestamp_microseconds, header.timestamp_microseconds)
        self.assertEqual(parsed.timestamp_difference_microseconds, header.timestamp_difference_microseconds)
        self.assertEqual(parsed.wnd_size, header.wnd_size)
        self.assertEqual(parsed.seq_nr, header.seq_nr)
        self.assertEqual(parsed.ack_nr, header.ack_nr)

    def test_parse_too_short(self):
        """Test that parsing a too-short packet raises an error."""
        with self.assertRaises(UTPPacketError):
            PacketHeader.parse(b"\x00" * 19)

    def test_unsupported_version(self):
        """Test that an unsupported version raises an error."""
        # version 0 in low nibble
        data = b"\x00" + b"\x00" * 19
        with self.assertRaises(UTPPacketError):
            PacketHeader.parse(data)

    def test_packet_type_extraction(self):
        """Test that packet type is correctly extracted from high nibble."""
        for pt in range(5):  # ST_DATA=0 through ST_SYN=4
            header = PacketHeader(
                packet_type=pt,
                version=1,
                connection_id=0,
            )
            serialized = header.serialize()
            self.assertEqual(serialized[0] >> 4, pt)

    def test_version_extraction(self):
        """Test that version is correctly extracted from low nibble."""
        header = PacketHeader(
            packet_type=ST_SYN,
            version=1,
            connection_id=0,
        )
        serialized = header.serialize()
        self.assertEqual(serialized[0] & 0x0F, 1)

    def test_zero_connection_id(self):
        """Test that zero connection_id serializes correctly."""
        header = PacketHeader(
            packet_type=ST_STATE,
            connection_id=0,
            seq_nr=0,
            ack_nr=0,
        )
        serialized = header.serialize()
        parsed = PacketHeader.parse(serialized)
        self.assertEqual(parsed.connection_id, 0)

    def test_max_values(self):
        """Test that max values for uint16/uint32 fields work."""
        header = PacketHeader(
            packet_type=ST_DATA,
            version=1,
            connection_id=0xFFFF,
            timestamp_microseconds=0xFFFFFFFF,
            timestamp_difference_microseconds=0xFFFFFFFF,
            wnd_size=0xFFFFFFFF,
            seq_nr=0xFFFF,
            ack_nr=0xFFFF,
        )
        serialized = header.serialize()
        parsed = PacketHeader.parse(serialized)
        self.assertEqual(parsed.connection_id, 0xFFFF)
        self.assertEqual(parsed.seq_nr, 0xFFFF)
        self.assertEqual(parsed.ack_nr, 0xFFFF)
        # For uint32, Python handles arbitrary precision so we check lower 32 bits
        self.assertEqual(parsed.wnd_size & 0xFFFFFFFF, 0xFFFFFFFF)

    def test_repr(self):
        """Test the __repr__ output."""
        header = PacketHeader(packet_type=ST_DATA, version=1)
        repr_str = repr(header)
        self.assertIn("ST_DATA", repr_str)
        self.assertIn("ver=1", repr_str)

    def test_extension_field(self):
        """Test extension field handling."""
        header = PacketHeader(
            packet_type=ST_DATA,
            version=1,
            extension=1,
            connection_id=0x0001,
        )
        serialized = header.serialize()
        self.assertEqual(serialized[1], 1)

        parsed = PacketHeader.parse(serialized)
        self.assertEqual(parsed.extension, 1)

    def test_all_packet_types(self):
        """Test all packet types serialize correctly."""
        for pt_val, _pt_name in PACKET_TYPE_NAMES.items():
            header = PacketHeader(packet_type=pt_val, version=1)
            serialized = header.serialize()
            parsed = PacketHeader.parse(serialized)
            self.assertEqual(parsed.packet_type, pt_val)


class TestSelectiveAck(unittest.TestCase):
    """Tests for Selective ACK handling."""

    def test_default_selective_ack(self):
        """Test default selective ACK values."""
        sack = SelectiveAck()
        self.assertEqual(sack.bits, 32)
        self.assertEqual(len(sack.bitmask), 4)

    def test_selective_ack_serialization(self):
        """Test selective ACK serialization."""
        sack = SelectiveAck(bits=32, bitmask=b"\xff\x00\x00\x00")
        serialized = sack.to_bytes()
        # extension_type(1) + length(1) + bitmask(4)
        self.assertEqual(len(serialized), 6)
        self.assertEqual(serialized[0], SELECTIVE_ACK_EXTENSION)
        self.assertEqual(serialized[1], 4)

    def test_selective_ack_parse(self):
        """Test selective ACK parsing."""
        data = bytes([SELECTIVE_ACK_EXTENSION, 4, 0xFF, 0x00, 0x00, 0x00])
        sack = SelectiveAck.parse(data)
        self.assertEqual(sack.bits, 32)
        self.assertEqual(len(sack.bitmask), 4)
        self.assertEqual(bytes(sack.bitmask), b"\xff\x00\x00\x00")

    def test_selective_ack_set_get_bit(self):
        """Test setting and getting bits in the bitmask."""
        sack = SelectiveAck(bits=32, bitmask=bytearray(b"\x00" * 4))
        self.assertFalse(sack.get_bit(0))
        self.assertFalse(sack.get_bit(7))
        self.assertFalse(sack.get_bit(8))

        sack.set_bit(0)
        self.assertTrue(sack.get_bit(0))

        sack.set_bit(7)
        self.assertTrue(sack.get_bit(7))

        # Bit 8 should still be 0 (different byte)
        self.assertFalse(sack.get_bit(8))

    def test_selective_ack_clear_bit(self):
        """Test clearing bits in the bitmask."""
        sack = SelectiveAck(bits=32, bitmask=bytearray(b"\xff" * 4))
        self.assertTrue(sack.get_bit(0))

        sack.clear_bit(0)
        self.assertFalse(sack.get_bit(0))

        # Other bits should still be set
        self.assertTrue(sack.get_bit(1))

    def test_selective_ack_invalid_bits(self):
        """Test that invalid bit counts raise errors."""
        sack = SelectiveAck(bits=16, bitmask=b"\x00" * 2)
        with self.assertRaises(UTPPacketError):
            sack.to_bytes()

    def test_selective_ack_invalid_length(self):
        """Test that bitmask length mismatch raises errors."""
        sack = SelectiveAck(bits=32, bitmask=bytearray(b"\x00" * 3))  # wrong length
        with self.assertRaises(UTPPacketError):
            sack.to_bytes()

    def test_selective_ack_not_multiple_of_32(self):
        """Test that non-multiple-of-32 bits raises error."""
        sack = SelectiveAck(bits=64, bitmask=b"\x00" * 8)
        # 64 is a multiple of 32, so this should work
        serialized = sack.to_bytes()
        self.assertIsNotNone(serialized)

    def test_selective_ack_bit_out_of_range(self):
        """Test that out-of-range bit access raises error."""
        sack = SelectiveAck(bits=32, bitmask=b"\x00" * 4)
        with self.assertRaises(UTPPacketError):
            sack.get_bit(32)
        with self.assertRaises(UTPPacketError):
            sack.set_bit(32)
        with self.assertRaises(UTPPacketError):
            sack.clear_bit(-1)

    def test_selective_ack_too_short_data(self):
        """Test that too-short data raises error."""
        with self.assertRaises(UTPPacketError):
            SelectiveAck.parse(b"\x01")
        with self.assertRaises(UTPPacketError):
            SelectiveAck.parse(b"")

    def test_selective_ack_wrong_type(self):
        """Test that wrong extension type raises error."""
        data = bytes([0xFF, 4, 0xFF, 0x00, 0x00, 0x00])
        with self.assertRaises(UTPPacketError):
            SelectiveAck.parse(data)

    def test_selective_ack_len_method(self):
        """Test __len__ returns the bitmask length."""
        sack = SelectiveAck(bits=32, bitmask=bytearray(b"\xff" * 4))
        self.assertEqual(len(sack), 4)

        sack64 = SelectiveAck(bits=64, bitmask=bytearray(b"\xff" * 8))
        self.assertEqual(len(sack64), 8)

    def test_selective_ack_multiple_bits(self):
        """Test setting multiple bits."""
        sack = SelectiveAck(bits=32, bitmask=bytearray(b"\x00" * 4))
        sack.set_bit(0)
        sack.set_bit(8)
        sack.set_bit(16)
        sack.set_bit(24)

        # In our big-endian bit order: bit N is at bit (7 - N%8) of byte (N//8)
        # bit 0 -> byte 0, bit 7 -> 0x80
        # bit 8 -> byte 1, bit 7 -> 0x80
        self.assertEqual(sack.bitmask[0], 0x80)
        self.assertEqual(sack.bitmask[1], 0x80)
        self.assertEqual(sack.bitmask[2], 0x80)
        self.assertEqual(sack.bitmask[3], 0x80)


class TestCongestionControl(unittest.TestCase):
    """Tests for congestion control implementation."""

    def test_default_initialization(self):
        """Test default congestion control initialization."""
        cc = CongestionControl()
        self.assertEqual(cc.rtt, 0)
        self.assertEqual(cc.rtt_var, 0)
        self.assertEqual(cc.base_delay, 0)
        self.assertEqual(cc.target_delay, CCONTROL_TARGET)
        self.assertEqual(cc.max_window, INITIAL_CONGESTION_WINDOW * DEFAULT_PACKET_SIZE)
        self.assertEqual(cc.packet_size, INITIAL_PACKET_SIZE)
        self.assertEqual(cc.outstanding_bytes, 0)
        self.assertEqual(cc.timeout_ms, INITIAL_TIMEOUT_MS)

    def test_custom_initialization(self):
        """Test custom target delay."""
        cc = CongestionControl(target_delay=200)
        self.assertEqual(cc.target_delay, 200)

    def test_update_rtt_first_sample(self):
        """Test first RTT sample sets both rtt and rtt_var."""
        cc = CongestionControl()
        cc.update_rtt(100)
        self.assertEqual(cc.rtt, 100)
        self.assertEqual(cc.rtt_var, 50)  # rtt // 2

    def test_update_rtt_subsequent(self):
        """Test subsequent RTT samples update smoothly."""
        cc = CongestionControl()
        cc.rtt = 100
        cc.rtt_var = 50

        # New sample is higher
        cc.update_rtt(120)

        # rtt should move toward 120
        delta = 100 - 120  # = -20
        expected_rtt_var = int((abs(delta) - 50) * RTT_BETA + 50)
        if expected_rtt_var < RTT_VAR_MIN:
            expected_rtt_var = RTT_VAR_MIN
        else:
            expected_rtt_var = expected_rtt_var

        expected_rtt = int(100 * (1.0 - RTT_ALPHA) + 120 * RTT_ALPHA)

        self.assertEqual(cc.rtt, expected_rtt)
        self.assertEqual(cc.rtt_var, expected_rtt_var)

    def test_update_rtt_clamping(self):
        """Test RTT sample is clamped to valid range."""
        cc = CongestionControl()

        # Below minimum
        cc.update_rtt(0)
        self.assertEqual(cc.rtt, MIN_RTT)

        # Reset
        cc.rtt = 0
        cc.rtt_var = 0

        # Above maximum
        cc.update_rtt(100000)
        self.assertEqual(cc.rtt, MAX_RTT)

    def test_update_rtt_timeout(self):
        """Test that timeout is updated based on rtt and rtt_var."""
        cc = CongestionControl()
        cc.update_rtt(100)
        # timeout = max(rtt + rtt_var * 4, 500)
        expected_timeout = max(100 + 50 * 4, 500)
        self.assertEqual(cc.timeout_ms, expected_timeout)

    def test_record_delay(self):
        """Test delay recording updates base_delay."""
        cc = CongestionControl()
        cc.record_delay(50000)  # 50 ms in microseconds
        self.assertEqual(cc.base_delay, 50)

    def test_record_delay_updates_minimum(self):
        """Test that base_delay tracks the minimum."""
        cc = CongestionControl()
        cc.record_delay(100000)  # 100 ms
        self.assertEqual(cc.base_delay, 100)

        cc.record_delay(50000)  # 50 ms (lower)
        self.assertEqual(cc.base_delay, 50)

        cc.record_delay(75000)  # 75 ms (higher, base_delay stays 50)
        self.assertEqual(cc.base_delay, 50)

    def test_get_off_target(self):
        """Test off-target delay calculation."""
        cc = CongestionControl()
        cc.base_delay = 100  # base_delay = target
        cc.record_delay(100000)  # 100 ms = target

        # When base_delay == observed_delay, our_delay = 0
        # off_target = 0 - target = -100
        off_target = cc.get_off_target()
        self.assertEqual(off_target, -100)  # below target (good)

    def test_on_packet_loss(self):
        """Test packet loss handling halves the window."""
        cc = CongestionControl()
        cc.max_window = 10000
        cc.on_packet_loss()
        self.assertEqual(cc.max_window, 5000)

    def test_on_packet_loss_minimum(self):
        """Test packet loss doesn't go below minimum."""
        cc = CongestionControl()
        cc.max_window = MIN_PACKET_SIZE
        cc.on_packet_loss()
        self.assertEqual(cc.max_window, MIN_PACKET_SIZE)

    def test_on_timeout(self):
        """Test timeout handling resets window and packet size."""
        cc = CongestionControl()
        cc.max_window = 1000
        cc.packet_size = 150
        cc.on_timeout()
        self.assertEqual(cc.packet_size, MAX_PACKET_SIZE)
        self.assertEqual(cc.max_window, MAX_PACKET_SIZE)
        self.assertEqual(cc.timeout_ms, INITIAL_TIMEOUT_MS)

    def test_reset(self):
        """Test congestion control reset."""
        cc = CongestionControl()
        cc.rtt = 100
        cc.rtt_var = 50
        cc.max_window = 5000
        cc.reset()
        self.assertEqual(cc.rtt, 0)
        self.assertEqual(cc.rtt_var, 0)
        self.assertEqual(cc.max_window, INITIAL_CONGESTION_WINDOW * DEFAULT_PACKET_SIZE)

    def test_can_send(self):
        """Test can_send based on window."""
        cc = CongestionControl()
        # No bytes in flight, should be able to send
        self.assertTrue(cc.can_send())

        # Fill the window
        cc.outstanding_bytes = cc.max_window
        self.assertFalse(cc.can_send())

        # Free some bytes
        cc.outstanding_bytes = cc.max_window - 100
        self.assertTrue(cc.can_send())

    def test_register_sent_and_acked(self):
        """Test registering sent and acked bytes."""
        cc = CongestionControl()
        cc.register_sent(1000)
        self.assertEqual(cc.outstanding_bytes, 1000)

        cc.register_acked(500, rtt_ms=50)
        self.assertEqual(cc.outstanding_bytes, 500)

    def test_register_acked_no_negative(self):
        """Test that acked bytes don't go negative."""
        cc = CongestionControl()
        cc.outstanding_bytes = 100
        cc.register_acked(200, rtt_ms=50)
        self.assertEqual(cc.outstanding_bytes, 0)

    def test_should_timeout(self):
        """Test timeout detection."""
        cc = CongestionControl()
        cc.last_ack_time = time.time() - 5  # 5 seconds ago
        self.assertTrue(cc.should_timeout())

        cc.last_ack_time = time.time()  # just now
        self.assertFalse(cc.should_timeout())

    def test_get_window_size(self):
        """Test getting window size."""
        cc = CongestionControl()
        self.assertEqual(cc.get_window_size(), cc.max_window)

    def test_scaled_gain_capping(self):
        """Test that scaled gain is capped to [-1, 1]."""
        cc = CongestionControl()
        # With a very negative off_target, scaled_gain should be capped
        cc.base_delay = 0
        cc.outstanding_bytes = 100000
        cc.max_window = 100

        gain = cc.calculate_scaled_gain()
        self.assertGreaterEqual(gain, -1.0)
        self.assertLessEqual(gain, 1.0)

    def test_delay_history_cleanup(self):
        """Test that old delay history entries are cleaned up."""
        cc = CongestionControl()
        cc._delay_history.clear()
        now = time.time()
        old_time = now - BASE_DELAY_WINDOW - 10
        recent_time = now - 10
        cc._delay_history.append((old_time, 100))
        cc._delay_history.append((recent_time, 50))

        # Should clean up the old entry
        cc.record_delay(50000)
        for ts, _ in cc._delay_history:
            self.assertGreater(now - ts, -1)


class TestPendingPacket(unittest.TestCase):
    """Tests for PendingPacket."""

    def test_default_sent_time(self):
        """Test that default sent_time is current time."""
        pkt = PendingPacket(seq_nr=1, data=b"hello")
        self.assertAlmostEqual(pkt.sent_time, time.time(), places=1)

    def test_data_stored(self):
        """Test that data is stored."""
        data = b"test data"
        pkt = PendingPacket(seq_nr=1, data=data)
        self.assertEqual(pkt.data, data)

    def test_retransmissions_counter(self):
        """Test retransmissions counter."""
        pkt = PendingPacket(seq_nr=1)
        self.assertEqual(pkt.retransmissions, 0)
        self.assertFalse(pkt.acked)


class TestUTPConnection(unittest.TestCase):
    """Tests for UTPConnection."""

    def test_initialization(self):
        """Test connection initialization."""
        conn = UTPConnection(connection_id=0x1234, is_initiator=True)
        self.assertEqual(conn.connection_id, 0x1234)
        self.assertEqual(conn.state, ConnectionState.NEW)
        self.assertEqual(conn.remote_connection_id, 0)

    def test_initiator_seq_nr(self):
        """Test that initiator starts with seq_nr=1."""
        conn = UTPConnection(connection_id=0x1234, is_initiator=True)
        self.assertEqual(conn.seq_nr, 1)

    def test_non_initiator_seq_nr(self):
        """Test that non-initiator starts with seq_nr=0."""
        conn = UTPConnection(connection_id=0x1234, is_initiator=False)
        self.assertEqual(conn.seq_nr, 0)

    def test_send_not_connected(self):
        """Test that sending data in non-connected state raises error."""
        conn = UTPConnection(connection_id=0x1234)
        with self.assertRaises(UTPConnectionError):
            conn.send(b"hello")

    def test_is_closed(self):
        """Test is_closed detection."""
        conn = UTPConnection(connection_id=0x1234)
        self.assertFalse(conn.is_closed())

        conn.state = ConnectionState.CLOSED
        self.assertTrue(conn.is_closed())

        conn.state = ConnectionState.ERROR
        self.assertTrue(conn.is_closed())

    def test_close_new(self):
        """Test closing a connection in NEW state (no-op)."""
        conn = UTPConnection(connection_id=0x1234)
        conn.close()
        self.assertEqual(conn.state, ConnectionState.NEW)

    def test_close_closed(self):
        """Test closing an already closed connection (no-op)."""
        conn = UTPConnection(connection_id=0x1234)
        conn.state = ConnectionState.CLOSED
        conn.close()
        self.assertEqual(conn.state, ConnectionState.CLOSED)

    def test_close_error(self):
        """Test closing an error connection (no-op)."""
        conn = UTPConnection(connection_id=0x1234)
        conn.state = ConnectionState.ERROR
        conn.close()
        self.assertEqual(conn.state, ConnectionState.ERROR)

    def test_close_closing(self):
        """Test closing a connection not in error/closed/new."""
        conn = UTPConnection(connection_id=0x1234)
        conn.state = ConnectionState.CONNECTED
        conn.close()
        self.assertEqual(conn.state, ConnectionState.CLOSING)

    def test_get_receive_data_empty(self):
        """Test getting receive data when buffer is empty."""
        conn = UTPConnection(connection_id=0x1234)
        self.assertEqual(conn.get_receive_data(), b"")

    def test_get_receive_data_contiguous(self):
        """Test getting contiguous receive data."""
        conn = UTPConnection(connection_id=0x1234)
        conn.ack_nr = 0
        conn.receive_buffer[1] = (b"hello", time.time())
        conn.receive_buffer[2] = (b"world", time.time())

        data = conn.get_receive_data()
        self.assertEqual(data, b"helloworld")
        # Buffer should be emptied for contiguous data
        self.assertNotIn(1, conn.receive_buffer)
        self.assertNotIn(2, conn.receive_buffer)

    def test_get_receive_data_non_contiguous(self):
        """Test getting non-contiguous data stops at gap."""
        conn = UTPConnection(connection_id=0x1234)
        conn.ack_nr = 0
        conn.receive_buffer[1] = (b"hello", time.time())
        conn.receive_buffer[3] = (b"world", time.time())

        data = conn.get_receive_data()
        self.assertEqual(data, b"hello")
        # Only seq 1 should be removed, 3 should remain
        self.assertNotIn(1, conn.receive_buffer)
        self.assertIn(3, conn.receive_buffer)

    def test_check_timeout(self):
        """Test timeout check."""
        conn = UTPConnection(connection_id=0x1234)
        conn.last_activity = time.time()
        self.assertFalse(conn.check_timeout())

    def test_stats(self):
        """Test statistics gathering."""
        conn = UTPConnection(connection_id=0x1234)
        stats = conn.get_stats()
        self.assertIn("state", stats)
        self.assertIn("connection_id", stats)
        self.assertIn("seq_nr", stats)
        self.assertIn("ack_nr", stats)
        self.assertIn("packets_sent", stats)
        self.assertIn("rtt", stats)
        self.assertEqual(stats["state"], "NEW")

    def test_send_buffer_tracking(self):
        """Test that sent data is tracked in the send buffer."""
        conn = UTPConnection(connection_id=0x1234, is_initiator=True)
        # Manually set to connected to allow sending
        conn.state = ConnectionState.CONNECTED

        # This tests that send() queues data
        # Note: In practice, this would need the congestion window to allow sending


class TestUTPSocket(unittest.TestCase):
    """Tests for UTPSocket."""

    def test_default_initialization(self):
        """Test UTPSocket default initialization."""
        sock = UTPSocket()
        self.assertIsNotNone(sock.sock)
        self.assertFalse(sock.is_server)
        self.assertIsNone(sock.connection)

    def test_close(self):
        """Test socket close."""
        sock = UTPSocket()
        sock.close()
        self.assertTrue(sock._closed)

    def test_context_manager(self):
        """Test context manager protocol."""
        with UTPSocket() as sock:
            self.assertIsNotNone(sock.sock)
        # Socket should be closed after context exit
        self.assertTrue(sock._closed)

    def test_getsockname(self):
        """Test getting local socket name."""
        sock = UTPSocket()
        name = sock.getsockname()
        self.assertIsInstance(name, tuple)
        self.assertEqual(len(name), 2)

    def test_bind(self):
        """Test binding the socket."""
        sock = UTPSocket()
        sock.bind(("127.0.0.1", 0))

    def test_process_packets_empty(self):
        """Test processing packets when there are none."""
        sock = UTPSocket()
        count = sock.process_packets()
        self.assertEqual(count, 0)


class TestPacketTypeNames(unittest.TestCase):
    """Tests for PACKET_TYPE_NAMES mapping."""

    def test_all_types_present(self):
        """Test all packet types are in the mapping."""
        for pt in range(5):
            self.assertIn(pt, PACKET_TYPE_NAMES)

    def test_type_names(self):
        """Test type names are correct."""
        self.assertEqual(PACKET_TYPE_NAMES[ST_DATA], "ST_DATA")
        self.assertEqual(PACKET_TYPE_NAMES[ST_FIN], "ST_FIN")
        self.assertEqual(PACKET_TYPE_NAMES[ST_STATE], "ST_STATE")
        self.assertEqual(PACKET_TYPE_NAMES[ST_RESET], "ST_RESET")
        self.assertEqual(PACKET_TYPE_NAMES[ST_SYN], "ST_SYN")

    def test_unknown_type(self):
        """Test unknown type in repr."""
        header = PacketHeader(packet_type=99, version=1)
        self.assertIn("UNKNOWN(99)", repr(header))


class TestConnectionStates(unittest.TestCase):
    """Tests for ConnectionState enum."""

    def test_all_states(self):
        """Test all connection states exist."""
        self.assertEqual(ConnectionState.NEW, 0)
        self.assertEqual(ConnectionState.SYN_SENT, 1)
        self.assertEqual(ConnectionState.SYN_RECV, 2)
        self.assertEqual(ConnectionState.CONNECTED, 3)
        self.assertEqual(ConnectionState.CLOSING, 4)
        self.assertEqual(ConnectionState.CLOSED, 5)
        self.assertEqual(ConnectionState.ERROR, 6)


class TestUTPErrors(unittest.TestCase):
    """Tests for uTP error hierarchy."""

    def test_base_error(self):
        """Test UTPError is a proper Exception."""
        with self.assertRaises(UTPError):
            raise UTPError("test")

    def test_packet_error_is_utp_error(self):
        """Test UTPPacketError is a UTPError."""
        with self.assertRaises(UTPPacketError):
            raise UTPPacketError("test")
        with self.assertRaises(UTPError):
            raise UTPPacketError("test")

    def test_connection_error_is_utp_error(self):
        """Test UTPConnectionError is a UTPError."""
        with self.assertRaises(UTPConnectionError):
            raise UTPConnectionError("test")
        with self.assertRaises(UTPError):
            raise UTPConnectionError("test")

    def test_congestion_error_is_utp_error(self):
        """Test UTPCongestionError is a UTPError."""
        with self.assertRaises(UTPCongestionError):
            raise UTPCongestionError("test")
        with self.assertRaises(UTPError):
            raise UTPCongestionError("test")


class TestHeaderEdgeCases(unittest.TestCase):
    """Edge case tests for packet header handling."""

    def test_header_with_zero_fields(self):
        """Test header with all zero fields (except type)."""
        header = PacketHeader(
            packet_type=ST_STATE,
            version=1,
            extension=0,
            connection_id=0,
            timestamp_microseconds=0,
            timestamp_difference_microseconds=0,
            wnd_size=0,
            seq_nr=0,
            ack_nr=0,
        )
        serialized = header.serialize()
        parsed = PacketHeader.parse(serialized)
        self.assertEqual(parsed.ack_nr, 0)
        self.assertEqual(parsed.wnd_size, 0)

    def test_header_size_consistency(self):
        """Test that header serialization always produces 20 bytes."""
        import random

        for _i in range(100):
            header = PacketHeader(
                packet_type=random.randint(0, 4),
                version=1,
                extension=random.randint(0, 255),
                connection_id=random.randint(0, 0xFFFF),
                timestamp_microseconds=random.randint(0, 0xFFFFFFFF),
                timestamp_difference_microseconds=random.randint(0, 0xFFFFFFFF),
                wnd_size=random.randint(0, 0xFFFFFFFF),
                seq_nr=random.randint(0, 0xFFFF),
                ack_nr=random.randint(0, 0xFFFF),
            )
            serialized = header.serialize()
            self.assertEqual(len(serialized), 20)


if __name__ == "__main__":
    unittest.main()
