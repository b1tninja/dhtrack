"""Tests for BEP 9 - Metadata Exchange Extension.

Tests the MetadataExchange class which implements the metadata transfer
protocol for BitTorrent's extension protocol.
"""

from __future__ import annotations

import hashlib
import pytest

from dhtrack.peer import (
    MetadataExchange,
    MetadataExchangeError,
    UT_METADATA,
    UT_METADATA_REQUEST,
    UT_METADATA_DATA,
    UT_METADATA_REJECT,
    METADATA_BLOCK_SIZE,
    MAX_METADATA_SIZE,
)
from dhtrack import bencode as bencode_module
from dhtrack.torrent import Torrent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_torrent() -> Torrent:
    """Create a minimal valid torrent for testing.

    Returns
    -------
    Torrent
        A valid Torrent instance.
    """
    info = {
        "name": "test file",
        "piece length": 16384,
        "piece": b"\x00" * 20,
    }
    metainfo = {
        "info": info,
        "announce": "http://example.com/announce",
    }
    return Torrent(metainfo)


# ---------------------------------------------------------------------------
# Tests: Constants
# ---------------------------------------------------------------------------


class TestBEP9Constants:
    """Test BEP 9 constant values."""

    def test_message_types(self):
        """Message types should match BEP 9 specification."""
        assert UT_METADATA_REQUEST == 0
        assert UT_METADATA_DATA == 1
        assert UT_METADATA_REJECT == 2

    def test_block_size(self):
        """Default block size should be 16 KiB."""
        assert METADATA_BLOCK_SIZE == 16384

    def test_max_metadata_size(self):
        """Max metadata size should be 10 MiB."""
        assert MAX_METADATA_SIZE == 10 * 1024 * 1024


# ---------------------------------------------------------------------------
# Tests: MetadataExchange - Initialization
# ---------------------------------------------------------------------------


class TestMetadataExchangeInit:
    """Test MetadataExchange initialization."""

    def test_empty_metadata_exchange(self):
        """Empty MetadataExchange should have zero pieces and size."""
        mex = MetadataExchange()
        assert mex.num_pieces == 0
        assert mex.metadata_size == 0
        assert mex.metadata is None
        assert mex.torrent is None

    def test_metadata_exchange_from_torrent(self):
        """MetadataExchange from a torrent should calculate size and pieces."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        assert mex.torrent is torrent
        assert mex.num_pieces > 0
        assert mex.metadata_size > 0
        # Metadata should be extracted automatically
        assert mex.metadata is not None

    def test_metadata_exchange_block_size(self):
        """MetadataExchange should use default block size."""
        mex = MetadataExchange()
        assert mex.block_size == METADATA_BLOCK_SIZE

    def test_num_pieces_calculation(self):
        """Number of pieces should be ceiling of metadata_size / block_size."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        expected_pieces = (mex.metadata_size + METADATA_BLOCK_SIZE - 1) // METADATA_BLOCK_SIZE
        assert mex.num_pieces == expected_pieces


# ---------------------------------------------------------------------------
# Tests: MetadataExchange - Handshake
# ---------------------------------------------------------------------------


class TestMetadataExchangeHandshake:
    """Test BEP 9 handshake messages."""

    def test_create_handshake(self):
        """Should create a handshake with metadata size."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        handshake_bytes = mex.create_handshake()
        handshake = bencode_module.decode(handshake_bytes)

        assert "msg_type" in handshake
        assert handshake["msg_type"] == UT_METADATA_DATA  # 1
        assert "total_size" in handshake
        assert handshake["total_size"] == mex.metadata_size

    def test_parse_handshake(self):
        """Should parse a valid handshake."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        handshake_bytes = mex.create_handshake()
        parsed = mex.parse_handshake(handshake_bytes)

        assert parsed is not None
        assert parsed["msg_type"] == UT_METADATA_DATA
        assert parsed["total_size"] == mex.metadata_size

    def test_parse_invalid_handshake(self):
        """Should return None for invalid handshake."""
        mex = MetadataExchange()
        assert mex.parse_handshake(b"not bencoded data") is None
        assert mex.parse_handshake(bencode_module.encode({"msg_type": 99})) is None


# ---------------------------------------------------------------------------
# Tests: MetadataExchange - Request
# ---------------------------------------------------------------------------


class TestMetadataExchangeRequest:
    """Test BEP 9 request messages."""

    def test_create_request(self):
        """Should create a valid request message."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        request_bytes = mex.create_request(0, b"peer_id_test")
        request = bencode_module.decode(request_bytes)

        assert request["msg_type"] == UT_METADATA_REQUEST  # 0
        assert request["piece"] == 0
        assert "reqid" in request
        assert len(request["reqid"]) == 4

    def test_create_request_invalid_piece(self):
        """Should raise error for invalid piece index."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        with pytest.raises(MetadataExchangeError):
            mex.create_request(-1, b"peer_id_test")

        with pytest.raises(MetadataExchangeError):
            mex.create_request(mex.num_pieces, b"peer_id_test")

    def test_create_request_for_each_piece(self):
        """Should create requests for all pieces."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        for i in range(mex.num_pieces):
            req_bytes = mex.create_request(i, b"peer_id_test")
            req = bencode_module.decode(req_bytes)
            assert req["piece"] == i


# ---------------------------------------------------------------------------
# Tests: MetadataExchange - Data
# ---------------------------------------------------------------------------


class TestMetadataExchangeData:
    """Test BEP 9 data messages."""

    def test_create_data_message(self):
        """Should create a valid data message."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        data_bytes = mex.create_data_message(0)
        data = bencode_module.decode(data_bytes)

        assert data["msg_type"] == UT_METADATA_DATA  # 1
        assert data["piece"] == 0
        assert data["total_size"] == mex.metadata_size
        assert "buffer" in data
        assert isinstance(data["buffer"], bytes)

    def test_create_data_message_invalid_piece(self):
        """Should raise error for invalid piece index."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        with pytest.raises(MetadataExchangeError):
            mex.create_data_message(-1)

        with pytest.raises(MetadataExchangeError):
            mex.create_data_message(mex.num_pieces)

    def test_handle_data_message(self):
        """Should handle a valid data message."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        # Create and send data message
        data_bytes = mex.create_data_message(0)
        result = mex.handle_data(data_bytes, peer_id=b"test_peer")

        # For a single-piece metadata, should return True
        # since the metadata is complete and verified
        assert result is not None

    def test_handle_data_with_peer_tracking(self):
        """Should track received data per peer."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        data_bytes = mex.create_data_message(0)
        result1 = mex.handle_data(data_bytes, peer_id=b"peer1")
        result2 = mex.handle_data(data_bytes, peer_id=b"peer2")

        # Both peers should receive the data
        assert result1 is not None
        assert result2 is not None


# ---------------------------------------------------------------------------
# Tests: MetadataExchange - Reject
# ---------------------------------------------------------------------------


class TestMetadataExchangeReject:
    """Test BEP 9 reject messages."""

    def test_create_reject_message(self):
        """Should create a valid reject message."""
        mex = MetadataExchange()
        reject_bytes = mex.create_reject_message(0)
        reject = bencode_module.decode(reject_bytes)

        assert reject["msg_type"] == UT_METADATA_REJECT  # 2
        assert reject["piece"] == 0
        assert "reqid" in reject

    def test_handle_reject_message(self):
        """Should handle a reject message without errors."""
        mex = MetadataExchange()
        reject_bytes = mex.create_reject_message(0)

        # Should not raise any exceptions
        mex.handle_reject(reject_bytes)


# ---------------------------------------------------------------------------
# Tests: MetadataExchange - Full Transfer
# ---------------------------------------------------------------------------


class TestMetadataExchangeFullTransfer:
    """Test full metadata transfer scenarios."""

    def test_sender_receives_metadata(self):
        """A sender should be able to receive its own metadata."""
        torrent = _make_torrent()
        sender_mex = MetadataExchange(torrent=torrent)
        receiver_mex = MetadataExchange()

        # Sender creates data messages for each piece
        for i in range(sender_mex.num_pieces):
            data_bytes = sender_mex.create_data_message(i)
            result = receiver_mex.handle_data(data_bytes, peer_id=b"sender")
            if result is True:
                break

        # Receiver should have the complete metadata
        assert receiver_mex.metadata is not None
        assert receiver_mex.is_complete()

    def test_metadata_verification(self):
        """Metadata should be verified against info hash."""
        torrent = _make_torrent()
        sender_mex = MetadataExchange(torrent=torrent)
        receiver_mex = MetadataExchange()

        # Send all pieces
        for i in range(sender_mex.num_pieces):
            data_bytes = sender_mex.create_data_message(i)
            result = receiver_mex.handle_data(data_bytes, peer_id=b"sender")
            if result is True:
                break

        # Verify the metadata matches the torrent's infohash
        assert receiver_mex.metadata is not None
        # Per BEP 9, the metadata is the info dict itself (not wrapped in 'info' key)
        metadata_dict = bencode_module.decode(receiver_mex.metadata)
        import hashlib
        info_hash = hashlib.sha1(bencode_module.encode(metadata_dict)).digest()
        assert info_hash == torrent.infohash

    def test_request_response_cycle(self):
        """Should handle request -> response cycle."""
        torrent = _make_torrent()
        sender_mex = MetadataExchange(torrent=torrent)
        receiver_mex = MetadataExchange()

        # Receiver requests a piece
        request_bytes = receiver_mex.create_request(0, torrent.infohash)

        # Sender handles the request and responds with data
        response_bytes = sender_mex.handle_request(request_bytes, peer_id=b"receiver")

        assert response_bytes is not None
        response = bencode_module.decode(response_bytes)
        assert response["msg_type"] == UT_METADATA_DATA

    def test_incomplete_metadata_not_returned(self):
        """Incomplete metadata should not be returned."""
        mex = MetadataExchange()

        assert mex.get_metadata() is None
        assert mex.is_complete() is False


# ---------------------------------------------------------------------------
# Tests: MetadataExchange - Edge Cases
# ---------------------------------------------------------------------------


class TestMetadataExchangeEdgeCases:
    """Test edge cases and error handling."""

    def test_request_without_metadata(self):
        """Request handling without metadata should return reject."""
        mex = MetadataExchange()

        request_bytes = bencode_module.encode({
            "msg_type": UT_METADATA_REQUEST,
            "piece": 0,
            "reqid": b"\x00\x00\x00\x00",
        })

        result = mex.handle_request(request_bytes)
        assert result is not None
        result_decoded = bencode_module.decode(result)
        assert result_decoded["msg_type"] == UT_METADATA_REJECT

    def test_empty_peer_id(self):
        """Should handle empty peer ID."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        data_bytes = mex.create_data_message(0)
        result = mex.handle_data(data_bytes, peer_id=b"")
        assert result is not None

    def test_handle_invalid_data_message(self):
        """Should handle malformed data messages gracefully."""
        mex = MetadataExchange()

        result = mex.handle_data(b"not bencoded")
        assert result is None

        result = mex.handle_data(bencode_module.encode({"msg_type": 99}))
        assert result is None

    def test_handle_exceedingly_large_metadata(self):
        """Should reject metadata larger than MAX_METADATA_SIZE."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        large_size = MAX_METADATA_SIZE + 1
        large_data = bencode_module.encode({
            "msg_type": UT_METADATA_DATA,
            "piece": 0,
            "total_size": large_size,
            "buffer": b"x" * 100,
        })

        result = mex.handle_data(large_data, peer_id=b"test")
        assert result is None

    def test_get_piece_count(self):
        """Should return correct piece count."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        assert mex.get_piece_count() == mex.num_pieces
        assert mex.get_piece_count() > 0

    def test_msg_counter_increments(self):
        """Message counter should increment with each request."""
        torrent = _make_torrent()
        mex = MetadataExchange(torrent=torrent)

        counter_before = mex.msg_counter
        mex.create_request(0, b"peer1")
        assert mex.msg_counter == counter_before + 1
        mex.create_request(1, b"peer2")
        assert mex.msg_counter == counter_before + 2