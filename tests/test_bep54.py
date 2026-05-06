"""Tests for BEP 54 — The lt_donthave extension."""

from __future__ import annotations

import struct
import pytest

from dhtrack.bep54 import (
    LT_DONTHAVE_NAME,
    LT_DONTHAVE_SUBOP,
    encode_donthave,
    decode_donthave,
    create_donthave_message,
    parse_donthave_from_extended,
    create_donthave_extended,
    EXTENDED_MSG_TYPE,
    EXTENDED_MSG_OP,
    PAYLOAD_LENGTH,
)


class TestConstants:
    """Tests for module constants."""

    def test_extension_name(self):
        assert LT_DONTHAVE_NAME == b"lt_donthave"

    def test_default_subop(self):
        assert LT_DONTHAVE_SUBOP == 1

    def test_payload_length(self):
        assert PAYLOAD_LENGTH == 5  # 1 byte subop + 4 bytes index


class TestEncodeDonthave:
    """Tests for encode_donthave function."""

    def test_basic(self):
        """Encode basic subop and index."""
        result = encode_donthave(0x00, 42)
        assert result == struct.pack("!BI", 0x00, 42)
        assert len(result) == 5

    def test_subop_255(self):
        """Encode max subop value."""
        result = encode_donthave(0xFF, 0)
        assert result == struct.pack("!BI", 0xFF, 0)

    def test_large_index(self):
        """Encode large piece index."""
        result = encode_donthave(0x01, 65535)
        assert result == struct.pack("!BI", 0x01, 65535)

    def test_invalid_subop_negative(self):
        """Reject negative subop."""
        with pytest.raises(ValueError, match="subop must be 0-255"):
            encode_donthave(-1, 0)

    def test_invalid_subop_too_large(self):
        """Reject subop > 255."""
        with pytest.raises(ValueError, match="subop must be 0-255"):
            encode_donthave(256, 0)

    def test_negative_index(self):
        """Reject negative index."""
        with pytest.raises(ValueError, match="piece_index must be >= 0"):
            encode_donthave(0x00, -1)


class TestDecodeDonthave:
    """Tests for decode_donthave function."""

    def test_basic(self):
        """Decode basic payload."""
        data = struct.pack("!BI", 0x00, 42)
        subop, index = decode_donthave(data)
        assert subop == 0x00
        assert index == 42

    def test_subop_255(self):
        """Decode max subop."""
        data = struct.pack("!BI", 0xFF, 100)
        subop, index = decode_donthave(data)
        assert subop == 0xFF
        assert index == 100

    def test_too_short(self):
        """Reject too-short data."""
        with pytest.raises(ValueError, match="too short"):
            decode_donthave(b"\x00\x00\x00")

    def test_empty(self):
        """Reject empty data."""
        with pytest.raises(ValueError, match="too short"):
            decode_donthave(b"")


class TestCreateDonthaveMessage:
    """Tests for create_donthave_message function."""

    def test_wire_format(self):
        """Verify complete wire format."""
        result = create_donthave_message(0x01, 100)

        # msg_type (1 byte) = 0 (extended message)
        assert result[0] == 0

        # payload_length (2 bytes) = 5
        payload_len = struct.unpack("!H", result[1:3])[0]
        assert payload_len == 5

        # op = 20
        assert result[3] == EXTENDED_MSG_OP

        # subop = 1
        assert result[4] == 0x01

        # index = 100
        index = struct.unpack("!I", result[5:9])[0]
        assert index == 100

    def test_message_length(self):
        """Total message is 9 bytes."""
        result = create_donthave_message(0x00, 0)
        assert len(result) == 9

    def test_subop_0(self):
        """Encode with subop 0."""
        result = create_donthave_message(0x00, 0)
        assert result[4] == 0x00


class TestParseDonthaveFromExtended:
    """Tests for parse_donthave_from_extended function."""

    def test_valid_data(self):
        """Parse valid extended message data."""
        # [op=20][subop=1][index=42] (5 bytes after extended message header)
        data = struct.pack("!BI", 1, 42)  # op=20 would be at index 0, but we pass subop+index directly
        data = struct.pack("!B", 20) + struct.pack("!BI", 1, 42)

        result = parse_donthave_from_extended(data)
        assert result is not None
        subop, index = result
        assert subop == 1
        assert index == 42

    def test_wrong_op(self):
        """Reject non-lt_donthave op."""
        data = struct.pack("!B", 0xFF) + struct.pack("!BI", 1, 42)
        result = parse_donthave_from_extended(data)
        assert result is None

    def test_too_short(self):
        """Reject too-short data."""
        result = parse_donthave_from_extended(b"\x14\x01")
        assert result is None

    def test_valid_zero_index(self):
        """Parse with index 0."""
        data = struct.pack("!B", 20) + struct.pack("!BI", 0x00, 0)
        result = parse_donthave_from_extended(data)
        assert result is not None
        subop, index = result
        assert subop == 0x00
        assert index == 0


class TestCreateDonthaveExtended:
    """Tests for create_donthave_extended function."""

    def test_wraps_payload(self):
        """Create extended message from 5-byte payload."""
        payload = struct.pack("!BI", 0x01, 42)
        result = create_donthave_extended(payload)

        assert result[0] == EXTENDED_MSG_TYPE  # msg_type = 0
        payload_len = struct.unpack("!H", result[1:3])[0]
        assert payload_len == 5
        assert result[3:] == payload


class TestRoundTrip:
    """Test encode → decode round trips."""

    def test_round_trip(self):
        """Encode then decode should return original values."""
        original_subop = 0x0F
        original_index = 12345

        encoded = encode_donthave(original_subop, original_index)
        decoded_subop, decoded_index = decode_donthave(encoded)

        assert decoded_subop == original_subop
        assert decoded_index == original_index

    def test_message_round_trip(self):
        """Create message then parse should return original values."""
        original_subop = 0x02
        original_index = 99999

        msg = create_donthave_message(original_subop, original_index)

        # Parse the payload portion (after msg_type and length)
        parsed = parse_donthave_from_extended(msg[3:])
        assert parsed is not None
        subop, index = parsed
        assert subop == original_subop
        assert index == original_index