"""Tests for BEP-4 constants and utilities (BEP-4: Assigned Numbers)."""

from __future__ import annotations

import unittest

from dhtrack import bep4
from dhtrack.bep4 import (
    BEP4Error,
    InvalidReservedByteError,
    InvalidMessageTypeError,
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
    # Sets
    CORE_MESSAGE_IDS,
    FAST_EXTENSION_MESSAGE_IDS,
    DHT_EXTENSION_MESSAGE_IDS,
    DEPLOYED_EXTENSION_MESSAGE_IDS,
    ALL_KNOWN_MESSAGE_IDS,
    MESSAGE_NAMES,
)


class TestReservedByteConstants(unittest.TestCase):
    """Test reserved byte flag constants are correct per BEP-4."""

    def test_azureus_msg(self):
        self.assertEqual(RESERVED_AZUREUS_MSG, 0x80)

    def test_location_aware(self):
        self.assertEqual(RESERVED_LOCATION_AWARE, 0x08)

    def test_ltep(self):
        self.assertEqual(RESERVED_LTEP, 0x10)

    def test_reserved_dht(self):
        self.assertEqual(RESERVED_DHT, 0x01)

    def test_reserved_peer_exchange(self):
        self.assertEqual(RESERVED_PEER_EXCHANGE, 0x02)

    def test_reserved_fast_extensions(self):
        self.assertEqual(RESERVED_FAST_EXTENSIONS, 0x04)

    def test_reserved_nat_traversal(self):
        self.assertEqual(RESERVED_NAT_TRAVERSAL, 0x08)

    def test_reserved_hybrid_torrent(self):
        self.assertEqual(RESERVED_HYBRID_TORRENT_LEGACY, 0x10)

    def test_bitcomet_collision(self):
        self.assertEqual(RESERVED_BITCOMET_MSG, 0xFF)
        self.assertEqual(RESERVED_BITCOMET_EXT, 0xFF)

    def test_xbt_metadata_exchange(self):
        self.assertEqual(RESERVED_XBT_METADATA_EXCHANGE, 0x01)


class TestCoreMessageTypes(unittest.TestCase):
    """Test core protocol message types (BEP 3)."""

    def test_choke(self):
        self.assertEqual(MSG_CHOKE, 0x00)

    def test_unchoke(self):
        self.assertEqual(MSG_UNCHOKE, 0x01)

    def test_interested(self):
        self.assertEqual(MSG_INTERESTED, 0x02)

    def test_not_interested(self):
        self.assertEqual(MSG_NOT_INTERESTED, 0x03)

    def test_have(self):
        self.assertEqual(MSG_HAVE, 0x04)

    def test_bitfield(self):
        self.assertEqual(MSG_BITFIELD, 0x05)

    def test_request(self):
        self.assertEqual(MSG_REQUEST, 0x06)

    def test_piece(self):
        self.assertEqual(MSG_PIECE, 0x07)

    def test_cancel(self):
        self.assertEqual(MSG_CANCEL, 0x08)


class TestFastExtensionMessageTypes(unittest.TestCase):
    """Test fast extension message types (BEP 6/16)."""

    def test_port(self):
        self.assertEqual(MSG_PORT, 0x09)

    def test_suggest(self):
        self.assertEqual(MSG_SUGGEST, 0x0D)

    def test_have_all(self):
        self.assertEqual(MSG_HAVE_ALL, 0x0E)

    def test_have_none(self):
        self.assertEqual(MSG_HAVE_NONE, 0x0F)

    def test_reject_request(self):
        self.assertEqual(MSG_REJECT_REQUEST, 0x10)

    def test_allowed_fast(self):
        self.assertEqual(MSG_ALLOWED_FAST, 0x11)


class TestLTEPHandshake(unittest.TestCase):
    """Test BEP 10 LTEP handshake message type."""

    def test_ltep_handshake(self):
        self.assertEqual(MSG_LTEP_HANDSHAKE, 0x14)


class TestHashTransferProtocol(unittest.TestCase):
    """Test Hash Transfer Protocol message types."""

    def test_hash_request(self):
        self.assertEqual(MSG_HASH_REQUEST, 0x15)

    def test_hashes(self):
        self.assertEqual(MSG_HASH_REQUESTS, 0x16)

    def test_hash_reject(self):
        self.assertEqual(MSG_HASH_REJECT, 0x17)


class TestMessageIDSets(unittest.TestCase):
    """Test message ID sets."""

    def test_core_message_ids(self):
        expected = {
            MSG_CHOKE, MSG_UNCHOKE, MSG_INTERESTED, MSG_NOT_INTERESTED,
            MSG_HAVE, MSG_BITFIELD, MSG_REQUEST, MSG_PIECE, MSG_CANCEL,
        }
        self.assertEqual(CORE_MESSAGE_IDS, frozenset(expected))

    def test_fast_extension_message_ids(self):
        expected = {
            MSG_SUGGEST, MSG_HAVE_ALL, MSG_HAVE_NONE,
            MSG_REJECT_REQUEST, MSG_ALLOWED_FAST,
        }
        self.assertEqual(FAST_EXTENSION_MESSAGE_IDS, frozenset(expected))

    def test_dht_extension_message_ids(self):
        self.assertEqual(DHT_EXTENSION_MESSAGE_IDS, frozenset({MSG_PORT}))

    def test_deployed_extension_message_ids(self):
        self.assertEqual(DEPLOYED_EXTENSION_MESSAGE_IDS, frozenset({MSG_LTEP_HANDSHAKE}))

    def test_all_known_message_ids(self):
        combined = CORE_MESSAGE_IDS | FAST_EXTENSION_MESSAGE_IDS | \
                   DHT_EXTENSION_MESSAGE_IDS | DEPLOYED_EXTENSION_MESSAGE_IDS
        self.assertEqual(ALL_KNOWN_MESSAGE_IDS, frozenset(combined))


class TestMessageNames(unittest.TestCase):
    """Test message type name mapping."""

    def test_core_message_names(self):
        self.assertEqual(MESSAGE_NAMES[MSG_CHOKE], "choke")
        self.assertEqual(MESSAGE_NAMES[MSG_UNCHOKE], "unchoke")
        self.assertEqual(MESSAGE_NAMES[MSG_INTERESTED], "interested")
        self.assertEqual(MESSAGE_NAMES[MSG_NOT_INTERESTED], "not interested")
        self.assertEqual(MESSAGE_NAMES[MSG_HAVE], "have")
        self.assertEqual(MESSAGE_NAMES[MSG_BITFIELD], "bitfield")
        self.assertEqual(MESSAGE_NAMES[MSG_REQUEST], "request")
        self.assertEqual(MESSAGE_NAMES[MSG_PIECE], "piece")
        self.assertEqual(MESSAGE_NAMES[MSG_CANCEL], "cancel")

    def test_fast_extension_names(self):
        self.assertEqual(MESSAGE_NAMES[MSG_SUGGEST], "suggest")
        self.assertEqual(MESSAGE_NAMES[MSG_HAVE_ALL], "have all")
        self.assertEqual(MESSAGE_NAMES[MSG_HAVE_NONE], "have none")
        self.assertEqual(MESSAGE_NAMES[MSG_REJECT_REQUEST], "reject request")
        self.assertEqual(MESSAGE_NAMES[MSG_ALLOWED_FAST], "allowed fast")

    def test_unknown_message_name(self):
        # MESSAGE_NAMES is a plain dict without default, so .get() returns None
        # Use message_name() helper instead which handles unknown types
        self.assertEqual(bep4.message_name(0xFF), "unknown (0xff)")

    def test_message_name_helper(self):
        self.assertEqual(bep4.message_name(MSG_CHOKE), "choke")
        self.assertEqual(bep4.message_name(0x99), "unknown (0x99)")


class TestIsReservedBitSet(unittest.TestCase):
    """Test the is_reserved_bit_set function."""

    def test_bit_set(self):
        self.assertTrue(bep4.is_reserved_bit_set(0x80, 0x80))
        self.assertTrue(bep4.is_reserved_bit_set(0x01, 0x01))
        self.assertTrue(bep4.is_reserved_bit_set(0xFF, 0x04))

    def test_bit_not_set(self):
        self.assertFalse(bep4.is_reserved_bit_set(0x00, 0x80))
        self.assertFalse(bep4.is_reserved_bit_set(0x7F, 0x80))
        self.assertFalse(bep4.is_reserved_bit_set(0x00, 0x01))

    def test_invalid_reserved_byte_low(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.is_reserved_bit_set(-1, 0x01)

    def test_invalid_reserved_byte_high(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.is_reserved_bit_set(256, 0x01)

    def test_invalid_flag_zero(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.is_reserved_bit_set(0x01, 0)

    def test_invalid_flag_not_power_of_2(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.is_reserved_bit_set(0x01, 3)


class TestSetReservedBit(unittest.TestCase):
    """Test the set_reserved_bit function."""

    def test_set_bit(self):
        self.assertEqual(bep4.set_reserved_bit(0x00, 0x01), 0x01)
        self.assertEqual(bep4.set_reserved_bit(0x00, 0x80), 0x80)
        self.assertEqual(bep4.set_reserved_bit(0x00, 0x04), 0x04)

    def test_already_set(self):
        self.assertEqual(bep4.set_reserved_bit(0x81, 0x01), 0x81)

    def test_set_multiple(self):
        result = bep4.set_reserved_bit(0x00, 0x01)
        result = bep4.set_reserved_bit(result, 0x04)
        self.assertEqual(result, 0x05)

    def test_invalid_byte(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.set_reserved_bit(300, 0x01)


class TestClearReservedBit(unittest.TestCase):
    """Test the clear_reserved_bit function."""

    def test_clear_bit(self):
        self.assertEqual(bep4.clear_reserved_bit(0x01, 0x01), 0x00)
        self.assertEqual(bep4.clear_reserved_bit(0x81, 0x01), 0x80)
        self.assertEqual(bep4.clear_reserved_bit(0xFF, 0x80), 0x7F)

    def test_already_cleared(self):
        self.assertEqual(bep4.clear_reserved_bit(0x00, 0x01), 0x00)

    def test_invalid_byte(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.clear_reserved_bit(-1, 0x01)


class TestMessageNameHelper(unittest.TestCase):
    """Test message_name function."""

    def test_known_core_messages(self):
        self.assertEqual(bep4.message_name(MSG_CHOKE), "choke")
        self.assertEqual(bep4.message_name(MSG_UNCHOKE), "unchoke")
        self.assertEqual(bep4.message_name(MSG_BITFIELD), "bitfield")

    def test_known_fast_extensions(self):
        self.assertEqual(bep4.message_name(MSG_HAVE_ALL), "have all")
        self.assertEqual(bep4.message_name(MSG_ALLOWED_FAST), "allowed fast")

    def test_unknown(self):
        self.assertEqual(bep4.message_name(0x99), "unknown (0x99)")


class TestIsFunctions(unittest.TestCase):
    """Test message type classification functions."""

    def test_is_core_message(self):
        self.assertTrue(bep4.is_core_message(MSG_CHOKE))
        self.assertTrue(bep4.is_core_message(MSG_REQUEST))
        self.assertFalse(bep4.is_core_message(MSG_SUGGEST))
        self.assertFalse(bep4.is_core_message(MSG_PORT))

    def test_is_fast_extension_message(self):
        self.assertTrue(bep4.is_fast_extension_message(MSG_SUGGEST))
        self.assertTrue(bep4.is_fast_extension_message(MSG_ALLOWED_FAST))
        self.assertFalse(bep4.is_fast_extension_message(MSG_CHOKE))

    def test_is_dht_extension_message(self):
        self.assertTrue(bep4.is_dht_extension_message(MSG_PORT))
        self.assertFalse(bep4.is_dht_extension_message(MSG_CHOKE))

    def test_is_valid_message_type(self):
        self.assertTrue(bep4.is_valid_message_type(MSG_CHOKE))
        self.assertTrue(bep4.is_valid_message_type(MSG_SUGGEST))
        self.assertTrue(bep4.is_valid_message_type(MSG_LTEP_HANDSHAKE))
        self.assertFalse(bep4.is_valid_message_type(0x99))
        self.assertFalse(bep4.is_valid_message_type(0x12))


class TestDecodeReservedBytes(unittest.TestCase):
    """Test decode_reserved_bytes function."""

    def test_all_zeros(self):
        reserved = b"\x00" * 8
        result = bep4.decode_reserved_bytes(reserved)
        self.assertFalse(result["dht"])
        self.assertFalse(result["fast_extensions"])
        self.assertFalse(result["bep10"])
        self.assertFalse(result["azureus_msg_protocol"])
        self.assertFalse(result["ltep"])

    def test_dht_flag(self):
        reserved = b"\x00" * 7 + b"\x01"
        result = bep4.decode_reserved_bytes(reserved)
        self.assertTrue(result["dht"])

    def test_fast_extensions_flag(self):
        # fast_extensions flag is at reserved[7] bit 0x04
        reserved = b"\x00" * 7 + b"\x04"
        result = bep4.decode_reserved_bytes(reserved)
        self.assertTrue(result["fast_extensions"])

    def test_bep10_flag(self):
        reserved = b"\x00" * 7 + b"\x04"
        result = bep4.decode_reserved_bytes(reserved)
        self.assertTrue(result["bep10"])

    def test_ltep_flag(self):
        # ltep flag is at reserved[5] = 0x10
        reserved = b"\x00\x00\x00\x00\x00\x10\x00\x00"
        result = bep4.decode_reserved_bytes(reserved)
        self.assertTrue(result["ltep"])

    def test_short_reserved_bytes(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.decode_reserved_bytes(b"\x00" * 4)

    def test_long_reserved_bytes(self):
        with self.assertRaises(bep4.InvalidReservedByteError):
            bep4.decode_reserved_bytes(b"\x00" * 10)


class TestMakeHandshakeReserved(unittest.TestCase):
    """Test make_handshake_reserved function."""

    def test_default(self):
        result = bep4.make_handshake_reserved()
        self.assertEqual(result, b"\x00" * 8)

    def test_dht_enabled(self):
        result = bep4.make_handshake_reserved(support_dht=True)
        self.assertEqual(result[7] & 0x01, 0x01)

    def test_fast_extensions_enabled(self):
        result = bep4.make_handshake_reserved(support_fast_extensions=True)
        self.assertEqual(result[7] & 0x04, 0x04)

    def test_bep10_enabled(self):
        result = bep4.make_handshake_reserved(support_bep10=True)
        self.assertEqual(result[7] & 0x04, 0x04)

    def test_all_enabled(self):
        result = bep4.make_handshake_reserved(
            support_dht=True,
            support_fast_extensions=True,
            support_bep10=True,
        )
        # DHT sets 0x01, fast_extensions sets 0x04, bep10 sets 0x04
        # Combined: 0x01 | 0x04 | 0x04 = 0x05
        self.assertEqual(result[7], 0x05)


class TestExceptionClasses(unittest.TestCase):
    """Test exception class hierarchy."""

    def test_bep4_error_base(self):
        self.assertTrue(issubclass(BEP4Error, Exception))

    def test_invalid_reserved_byte_error(self):
        self.assertTrue(issubclass(InvalidReservedByteError, BEP4Error))

    def test_invalid_message_type_error(self):
        self.assertTrue(issubclass(InvalidMessageTypeError, BEP4Error))


if __name__ == "__main__":
    unittest.main()