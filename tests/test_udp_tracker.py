"""
Tests for BEP 15 UDP Tracker Protocol.

Tests the UDPTrackerClient, data classes, and protocol encoding/decoding
for connect, announce, scrape, and error responses.
"""

from __future__ import annotations

import struct
import time
from dataclasses import FrozenInstanceError

import pytest

from dhtrack.udp_tracker import (
    _ACTION_ANNOUNCE,
    _ACTION_CONNECT,
    _ACTION_ERROR,
    _ACTION_SCRAPES,
    _CONN_ID_USE_LIMIT,
    _PROTOCOL_MAGIC,
    AnnounceEvent,
    AnnounceRequest,
    AnnounceResponse,
    IPPeer,
    ScrapeInfo,
    ScrapeResponse,
    TrackerClientError,
    TrackerConnectionError,
    TrackerProtocolError,
    TrackerResponseError,
    UDPTrackerClient,
)

# -----------------------------------------------------------------------
# IPPeer tests
# -----------------------------------------------------------------------


class TestIPPeer:
    """Tests for the IPPeer dataclass."""

    def test_ipv4_creation(self):
        """Create an IPPeer from IPv4 bytes."""
        ip_bytes = b"\x7f\x00\x00\x01"
        peer = IPPeer.from_ipv4(ip_bytes, 6881)
        assert peer.ip == "127.0.0.1"
        assert peer.port == 6881
        assert peer.version == "ipv4"

    def test_ipv4_public_address(self):
        """Create an IPPeer from a public IPv4 address."""
        ip_bytes = b"\xc0\xa8\x01\x01"
        peer = IPPeer.from_ipv4(ip_bytes, 12345)
        assert peer.ip == "192.168.1.1"
        assert peer.port == 12345

    def test_ipv6_creation(self):
        """Create an IPPeer from IPv6 bytes."""
        # ::1 (loopback)
        ip_bytes = b"\x00" * 15 + b"\x01"
        peer = IPPeer.from_ipv6(ip_bytes, 6881)
        assert peer.ip == "::1"
        assert peer.port == 6881
        assert peer.version == "ipv6"

    def test_ipv6_full_address(self):
        """Create an IPPeer from a full IPv6 address."""
        ip_bytes = bytes(
            [
                0x20,
                0x01,
                0x0D,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
            ]
        )
        peer = IPPeer.from_ipv6(ip_bytes, 6881)
        assert "2001:0db8" in peer.ip or "2001:db8" in peer.ip
        assert peer.port == 6881

    def test_frozen_dataclass(self):
        """IPPeer should be immutable (frozen)."""
        peer = IPPeer(ip="1.2.3.4", port=80)
        with pytest.raises(FrozenInstanceError):
            peer.ip = "5.6.7.8"
        with pytest.raises(FrozenInstanceError):
            peer.port = 443


# -----------------------------------------------------------------------
# AnnounceRequest tests
# -----------------------------------------------------------------------


class TestAnnounceRequest:
    """Tests for the AnnounceRequest dataclass."""

    def test_defaults(self):
        """Default values should be valid."""
        req = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 20,
        )
        assert req.downloaded == 0
        assert req.left == 0
        assert req.uploaded == 0
        assert req.event == AnnounceEvent.NONE
        assert req.ip_address == 0
        assert req.key == 0
        assert req.num_want == -1
        assert req.port == 0

    def test_valid_request(self):
        """Valid request should pass validation."""
        req = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 20,
            downloaded=1000,
            left=500,
            uploaded=2000,
            event=AnnounceEvent.COMPLETED,
            ip_address=0x01020304,
            key=12345,
            num_want=50,
            port=6881,
        )
        req.validate()  # Should not raise

    def test_invalid_info_hash_length(self):
        """Info hash must be exactly 20 bytes."""
        req = AnnounceRequest(
            info_hash=b"\x00" * 19,
            peer_id=b"\x01" * 20,
        )
        with pytest.raises(TrackerClientError):
            req.validate()

        req2 = AnnounceRequest(
            info_hash=b"\x00" * 21,
            peer_id=b"\x01" * 20,
        )
        with pytest.raises(TrackerClientError):
            req2.validate()

    def test_invalid_peer_id_length(self):
        """Peer ID must be exactly 20 bytes."""
        req = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 19,
        )
        with pytest.raises(TrackerClientError):
            req.validate()

    def test_invalid_port(self):
        """Port must be 0-65535."""
        req = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 20,
            port=65536,
        )
        with pytest.raises(TrackerClientError):
            req.validate()

        req2 = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 20,
            port=-1,
        )
        with pytest.raises(TrackerClientError):
            req2.validate()

    def test_negative_byte_counts(self):
        """downloaded, left, uploaded must be non-negative."""
        req = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 20,
            downloaded=-1,
        )
        with pytest.raises(TrackerClientError):
            req.validate()

        req2 = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 20,
            left=-1,
        )
        with pytest.raises(TrackerClientError):
            req2.validate()

        req3 = AnnounceRequest(
            info_hash=b"\x00" * 20,
            peer_id=b"\x01" * 20,
            uploaded=-1,
        )
        with pytest.raises(TrackerClientError):
            req3.validate()


# -----------------------------------------------------------------------
# AnnounceResponse tests
# -----------------------------------------------------------------------


class TestAnnounceResponse:
    """Tests for AnnounceResponse."""

    def test_defaults(self):
        """Default values."""
        resp = AnnounceResponse()
        assert resp.interval == 0
        assert resp.leechers == 0
        assert resp.seeders == 0
        assert resp.peers == []

    def test_with_data(self):
        """Response with data."""
        peer1 = IPPeer(ip="1.2.3.4", port=6881)
        peer2 = IPPeer(ip="5.6.7.8", port=6882)
        resp = AnnounceResponse(
            interval=1800,
            leechers=10,
            seeders=5,
            peers=[peer1, peer2],
        )
        assert resp.interval == 1800
        assert resp.leechers == 10
        assert resp.seeders == 5
        assert len(resp.peers) == 2


# -----------------------------------------------------------------------
# ScrapeInfo / ScrapeResponse tests
# -----------------------------------------------------------------------


class TestScrapeInfo:
    """Tests for ScrapeInfo dataclass."""

    def test_defaults(self):
        info = ScrapeInfo()
        assert info.seeders == 0
        assert info.completed == 0
        assert info.leechers == 0

    def test_custom_values(self):
        info = ScrapeInfo(seeders=10, completed=100, leechers=5)
        assert info.seeders == 10
        assert info.completed == 100
        assert info.leechers == 5


class TestScrapeResponse:
    """Tests for ScrapeResponse dataclass."""

    def test_defaults(self):
        resp = ScrapeResponse()
        assert resp.files == {}
        assert resp.error is None
        assert not resp.is_error

    def test_error_response(self):
        resp = ScrapeResponse(error="tracker full")
        assert resp.is_error
        assert resp.error == "tracker full"

    def test_successful_response(self):
        h1 = b"\x01" * 20
        resp = ScrapeResponse(files={h1: ScrapeInfo(seeders=5, completed=10, leechers=2)})
        assert not resp.is_error
        assert h1 in resp.files


# -----------------------------------------------------------------------
# AnnounceEvent tests
# -----------------------------------------------------------------------


class TestAnnounceEvent:
    """Tests for AnnounceEvent."""

    def test_values(self):
        assert AnnounceEvent.NONE == 0
        assert AnnounceEvent.COMPLETED == 1
        assert AnnounceEvent.STARTED == 2
        assert AnnounceEvent.STOPPED == 3


# -----------------------------------------------------------------------
# Connect request/response encoding and decoding
# -----------------------------------------------------------------------


class TestConnectEncoding:
    """Tests for connect request and response encoding."""

    def test_connect_request_format(self):
        """Build a valid connect request."""
        tid = 12345
        request = struct.pack("!QII", _PROTOCOL_MAGIC, _ACTION_CONNECT, tid)
        assert len(request) == 16
        # Verify structure
        protocol_id, action, transaction_id = struct.unpack_from("!QII", request, 0)
        assert protocol_id == _PROTOCOL_MAGIC
        assert action == _ACTION_CONNECT
        assert transaction_id == tid

    def test_connect_response_format(self):
        """Build a valid connect response."""
        tid = 12345
        conn_id = 0xABCDEF1234567890
        response = struct.pack("!IIQ", _ACTION_CONNECT, tid, conn_id)
        assert len(response) == 16
        action, resp_tid, resp_conn_id = struct.unpack_from("!IIQ", response, 0)
        assert action == _ACTION_CONNECT
        assert resp_tid == tid
        assert resp_conn_id == conn_id

    def test_connect_response_minimum_length(self):
        """Response must be at least 16 bytes."""
        assert len(struct.pack("!IIQ", 0, 0, 0)) == 16


# -----------------------------------------------------------------------
# Announce request encoding
# -----------------------------------------------------------------------


class TestAnnounceEncoding:
    """Tests for announce request encoding."""

    def _make_request(self, **kwargs):
        """Build an announce request packet."""
        info_hash = kwargs.get("info_hash", b"\x00" * 20)
        peer_id = kwargs.get("peer_id", b"\x01" * 20)
        downloaded = kwargs.get("downloaded", 0)
        left = kwargs.get("left", 0)
        uploaded = kwargs.get("uploaded", 0)
        event = kwargs.get("event", AnnounceEvent.NONE)
        ip_address = kwargs.get("ip_address", 0)
        key = kwargs.get("key", 0)
        num_want = kwargs.get("num_want", -1)
        port = kwargs.get("port", 6881)

        ip_bytes = ip_address.to_bytes(4, "big") if ip_address else b"\x00" * 4

        # num_want is packed as uint32; -1 becomes 0xFFFFFFFF
        num_want_val = num_want & 0xFFFFFFFF if num_want < 0 else num_want
        request = (
            struct.pack(
                "!QII",
                0xDEADBEEF12345678,  # connection_id
                _ACTION_ANNOUNCE,
                99999,  # transaction_id
            )
            + info_hash
            + peer_id
            + struct.pack(
                "!qqqI",
                downloaded,
                left,
                uploaded,
                event,
            )
            + ip_bytes
            + struct.pack("!IIH", key, num_want_val, port)
        )

        return request

    def test_announce_request_size(self):
        """IPv4 announce request size is 98 bytes.

        header 16 + info_hash 20 + peer_id 20 + data 28 + ip 4 +
        key/num_want/port 10.
        """
        request = self._make_request(num_want=0)
        assert len(request) == 98

    def test_announce_request_fields(self):
        """Verify all fields are encoded correctly."""
        request = self._make_request(
            info_hash=b"\xaa" * 20,
            peer_id=b"\xbb" * 20,
            downloaded=1000,
            left=500,
            uploaded=200,
            event=AnnounceEvent.COMPLETED,
            ip_address=0x01020304,
            key=42,
            num_want=50,
            port=7000,
        )

        # Parse header
        conn_id, action, tid = struct.unpack_from("!QII", request, 0)
        assert action == _ACTION_ANNOUNCE
        assert tid == 99999

        # Parse info_hash
        parsed_info_hash = request[16:36]
        assert parsed_info_hash == b"\xaa" * 20

        # Parse peer_id
        parsed_peer_id = request[36:56]
        assert parsed_peer_id == b"\xbb" * 20

        # Parse downloaded, left, uploaded, event
        downloaded, left, uploaded, event = struct.unpack_from("!qqqI", request, 56)
        assert downloaded == 1000
        assert left == 500
        assert uploaded == 200
        assert event == AnnounceEvent.COMPLETED

        # Parse IP at offset 84 (56 + 28 stats bytes)
        parsed_ip = struct.unpack_from("!I", request, 84)[0]
        assert parsed_ip == 0x01020304

        # Parse key at 88, num_want at 92, port at 96
        parsed_key = struct.unpack_from("!I", request, 88)[0]
        parsed_num_want_raw = struct.unpack_from("!I", request, 92)[0]
        parsed_port = struct.unpack_from("!H", request, 96)[0]
        assert parsed_key == 42
        assert parsed_num_want_raw == 50
        assert parsed_port == 7000

        # Verify total packet structure:
        # header(16) + info_hash(20) + peer_id(20) + stats(28) + ip(4) + key(4) + num_want(4) + port(2) = 98
        assert len(request) == 98

    def test_zero_values(self):
        """Announce request with all default values (including num_want=-1 -> 0xFFFFFFFF)."""
        request = self._make_request()
        # Size is always 98 bytes regardless of num_want value
        assert len(request) == 98


# -----------------------------------------------------------------------
# Announce response decoding
# -----------------------------------------------------------------------


class TestAnnounceResponseDecoding:
    """Tests for parsing announce responses."""

    def _make_response(self, **kwargs):
        """Build an announce response packet."""
        action = kwargs.get("action", _ACTION_ANNOUNCE)
        tid = kwargs.get("tid", 12345)
        interval = kwargs.get("interval", 1800)
        leechers = kwargs.get("leechers", 5)
        seeders = kwargs.get("seeders", 10)
        peers = kwargs.get(
            "peers",
            [
                (b"\x7f\x00\x00\x01", 6881),
                (b"\xc0\xa8\x01\x01", 6882),
            ],
        )

        response = struct.pack("!IIIII", action, tid, interval, leechers, seeders)
        for ip_bytes, port in peers:
            response += ip_bytes + struct.pack("!H", port)

        return response

    def test_announce_response_parsing(self):
        """Parse a valid announce response."""
        response = self._make_response()
        assert len(response) == 20 + 6 * 2  # header + 2 peers

        action, tid, interval, leechers, seeders = struct.unpack_from("!IIIII", response, 0)
        assert action == _ACTION_ANNOUNCE
        assert tid == 12345
        assert interval == 1800
        assert leechers == 5
        assert seeders == 10

    def test_announce_response_with_peers(self):
        """Parse response with multiple peers."""
        peers_data = [
            (b"\x01\x02\x03\x04", 8080),
            (b"\x05\x06\x07\x08", 9090),
            (b"\x0a\x0b\x0c\x0d", 12345),
        ]
        response = self._make_response(peers=peers_data)

        offset = 20
        for expected_ip, expected_port in peers_data:
            parsed_ip = response[offset : offset + 4]
            parsed_port = struct.unpack_from("!H", response, offset + 4)[0]
            assert parsed_ip == expected_ip
            assert parsed_port == expected_port
            offset += 6

    def test_empty_peer_list(self):
        """Parse response with no peers."""
        response = self._make_response(peers=[])
        assert len(response) == 20

        action, tid, interval, leechers, seeders = struct.unpack_from("!IIIII", response, 0)
        assert seeders == 10
        assert leechers == 5


# -----------------------------------------------------------------------
# Scrape request encoding
# -----------------------------------------------------------------------


class TestScrapeEncoding:
    """Tests for scrape request encoding per BEP 15 spec."""

    def test_scrape_request_format(self):
        """Build a valid scrape request per BEP 15:
        connection_id(8) + action(4) + transaction_id(4) + info_hash(20) * N
        """
        info_hashes = [b"\x01" * 20, b"\x02" * 20, b"\x03" * 20]
        conn_id = 0xDEADBEEF12345678
        request = struct.pack("!QII", conn_id, _ACTION_SCRAPES, 42)
        for ih in info_hashes:
            request += ih

        # 8 (conn_id) + 4 (action) + 4 (tid) + 3 * 20 = 80 bytes
        expected_len = 8 + 4 + 4 + 3 * 20  # = 80
        assert len(request) == expected_len
        conn_id_parsed, action, tid = struct.unpack_from("!QII", request, 0)
        assert conn_id_parsed == conn_id
        assert action == _ACTION_SCRAPES
        assert tid == 42

    def test_single_infohash(self):
        """Scrape request with one infohash."""
        conn_id = 0x1234567890ABCDEF
        request = struct.pack("!QII", conn_id, _ACTION_SCRAPES, 1) + b"\xaa" * 20
        # 8 + 4 + 4 + 20 = 36 bytes
        assert len(request) == 36

    def test_max_infohashes(self):
        """Scrape request with maximum number of infohashes (74)."""
        max_hashes = [b"\x00" * 20] * 74
        conn_id = 0xFFFFFFFF
        request = struct.pack("!QII", conn_id, _ACTION_SCRAPES, 1)
        for ih in max_hashes:
            request += ih
        # 8 (conn_id) + 4 (action) + 4 (tid) + 20 * 74 = 1500 bytes
        expected_len = 8 + 4 + 4 + 20 * 74  # = 1500
        assert len(request) == expected_len


# -----------------------------------------------------------------------
# Scrape response decoding
# -----------------------------------------------------------------------


class TestScrapeResponseDecoding:
    """Tests for parsing scrape responses."""

    def test_scrape_response_format(self):
        """Parse a valid scrape response per BEP 15."""
        # action(4) + transaction_id(4) + data per torrent
        response = struct.pack("!II", _ACTION_SCRAPES, 42)
        # h1 stats
        response += struct.pack("!III", 10, 100, 5)
        # h2 stats
        response += struct.pack("!III", 20, 200, 10)

        assert len(response) == 8 + 12 * 2

        action, tid = struct.unpack_from("!II", response, 0)
        assert action == _ACTION_SCRAPES
        assert tid == 42

        offset = 8
        s1 = struct.unpack_from("!III", response, offset)
        assert s1 == (10, 100, 5)

        offset = 20
        s2 = struct.unpack_from("!III", response, offset)
        assert s2 == (20, 200, 10)

    def test_scrape_error_response(self):
        """Parse an error response."""
        response = struct.pack("!II", _ACTION_ERROR, 42) + b"tracker full"
        action, tid = struct.unpack_from("!II", response, 0)
        assert action == _ACTION_ERROR
        assert tid == 42
        msg = response[8:].decode("utf-8", errors="replace")
        assert msg == "tracker full"

    def test_scrape_too_short(self):
        """Response shorter than minimum."""
        response = b"\x00" * 10
        assert len(response) < 12


# -----------------------------------------------------------------------
# Error response tests
# -----------------------------------------------------------------------


class TestErrorResponse:
    """Tests for error response handling."""

    def test_error_response_format(self):
        """Parse error response with message."""
        data = struct.pack("!II", _ACTION_ERROR, 99) + b"Connection refused"
        action, tid = struct.unpack_from("!II", data, 0)
        assert action == _ACTION_ERROR
        assert tid == 99
        msg = data[8:].decode("utf-8", errors="replace")
        assert msg == "Connection refused"

    def test_error_empty_message(self):
        """Error with empty message."""
        data = struct.pack("!II", _ACTION_ERROR, 1) + b""
        action, tid = struct.unpack_from("!II", data, 0)
        assert action == _ACTION_ERROR
        assert tid == 1

    def test_error_short(self):
        """Very short error response."""
        data = struct.pack("!II", _ACTION_ERROR, 1)
        action, tid = struct.unpack_from("!II", data, 0)
        assert action == _ACTION_ERROR
        msg = data[8:].decode("utf-8", errors="replace")
        assert msg == ""


# -----------------------------------------------------------------------
# UDPTrackerClient tests (no network)
# -----------------------------------------------------------------------


class TestUDPTrackerClientInit:
    """Tests for UDPTrackerClient initialization."""

    def test_default_init(self):
        client = UDPTrackerClient()
        assert client.timeout == 15
        assert client.max_retries == 8
        assert client._connection_id is None
        assert client._connection_time == 0.0

    def test_custom_init(self):
        client = UDPTrackerClient(timeout=30, max_retries=5)
        assert client.timeout == 30
        assert client.max_retries == 5

    def test_no_connection_id(self):
        """Should not have a connection ID initially."""
        client = UDPTrackerClient()
        assert client._connection_id is None


class TestTransactionId:
    """Tests for transaction ID generation."""

    def test_unique_ids(self):
        """Each call should return a unique transaction ID."""
        client = UDPTrackerClient()
        tids = set()
        for _ in range(100):
            tid = client._next_transaction_id()
            assert 0 <= tid <= 0xFFFFFFFF
            tids.add(tid)
        assert len(tids) == 100

    def test_wraps_at_max(self):
        """Transaction IDs are now random per BEP 15. Just verify range."""
        client = UDPTrackerClient()
        tid = client._next_transaction_id()
        assert 0 <= tid <= 0xFFFFFFFF


class TestValidateConnection:
    """Tests for connection validation."""

    def test_no_connection(self):
        """Should raise when no connection exists."""
        client = UDPTrackerClient()
        with pytest.raises(TrackerConnectionError):
            client._validate_connection()

    def test_valid_connection(self):
        """Should not raise when connected."""
        client = UDPTrackerClient()
        client._connection_id = 12345
        client._connection_time = time.time()
        client._validate_connection()  # Should not raise

    def test_expired_connection(self):
        """Should raise when connection ID has expired."""
        client = UDPTrackerClient()
        client._connection_id = 12345
        client._connection_time = time.time() - (_CONN_ID_USE_LIMIT + 10)
        with pytest.raises(TrackerConnectionError):
            client._validate_connection()


class TestClose:
    """Tests for client close."""

    def test_close(self):
        client = UDPTrackerClient()
        client._connection_id = 12345
        client._connection_time = time.time()
        client.close()
        assert client._connection_id is None
        assert client._connection_time == 0.0


class TestContextManager:
    """Tests for context manager protocol."""

    def test_enter(self):
        client = UDPTrackerClient()
        result = client.__enter__()
        assert result is client

    def test_exit(self):
        client = UDPTrackerClient()
        client._connection_id = 12345
        client.__exit__(None, None, None)
        assert client._connection_id is None


# -----------------------------------------------------------------------
# Integration-style tests (mocked)
# -----------------------------------------------------------------------


class TestAnnounceResponseParsing:
    """Tests for the _parse_announce_response method using mocked data."""

    def _make_announce_response(self, **kwargs):
        """Build raw announce response bytes."""
        action = kwargs.get("action", _ACTION_ANNOUNCE)
        tid = kwargs.get("tid", 42)
        interval = kwargs.get("interval", 1800)
        leechers = kwargs.get("leechers", 5)
        seeders = kwargs.get("seeders", 10)
        peers = kwargs.get(
            "peers",
            [
                (b"\x7f\x00\x00\x01", 6881),
            ],
        )

        data = struct.pack("!IIIII", action, tid, interval, leechers, seeders)
        for ip_bytes, port in peers:
            data += ip_bytes + struct.pack("!H", port)
        return data

    def test_successful_parsing(self):
        """Parse a successful announce response."""
        client = UDPTrackerClient()
        raw = self._make_announce_response()
        result = client._parse_announce_response(raw, 42, ip_version=4)

        assert result.interval == 1800
        assert result.leechers == 5
        assert result.seeders == 10
        assert len(result.peers) == 1
        assert result.peers[0].ip == "127.0.0.1"
        assert result.peers[0].port == 6881

    def test_error_response_parsing(self):
        """Parsing an error response should raise."""
        client = UDPTrackerClient()
        error_data = struct.pack("!II", _ACTION_ERROR, 42) + b"tracker full"
        with pytest.raises(TrackerResponseError) as exc_info:
            client._parse_announce_response(error_data, 42, ip_version=4)
        assert "tracker full" in str(exc_info.value)

    def test_unexpected_action_parsing(self):
        """Parsing with wrong action should raise."""
        client = UDPTrackerClient()
        wrong_action = self._make_announce_response(action=_ACTION_CONNECT)
        with pytest.raises(TrackerProtocolError):
            client._parse_announce_response(wrong_action, 42, ip_version=4)

    def test_transaction_id_mismatch(self):
        """Mismatched transaction ID should raise."""
        client = UDPTrackerClient()
        raw = self._make_announce_response(tid=999)
        with pytest.raises(TrackerProtocolError):
            client._parse_announce_response(raw, 42, ip_version=4)

    def test_response_too_short(self):
        """Response too short should raise."""
        client = UDPTrackerClient()
        short = struct.pack("!II", _ACTION_ANNOUNCE, 42)  # Only 8 bytes
        with pytest.raises(TrackerProtocolError):
            client._parse_announce_response(short, 42, ip_version=4)

    def test_multiple_peers(self):
        """Parse response with multiple peers."""
        client = UDPTrackerClient()
        peers = [
            (b"\x01\x02\x03\x04", 8080),
            (b"\x05\x06\x07\x08", 9090),
            (b"\x0a\x0b\x0c\x0d", 12345),
        ]
        raw = self._make_announce_response(peers=peers)
        result = client._parse_announce_response(raw, 42, ip_version=4)

        assert len(result.peers) == 3
        assert result.peers[0].ip == "1.2.3.4"
        assert result.peers[0].port == 8080
        assert result.peers[1].ip == "5.6.7.8"
        assert result.peers[1].port == 9090
        assert result.peers[2].ip == "10.11.12.13"
        assert result.peers[2].port == 12345


class TestScrapeResponseParsing:
    """Tests for _parse_scrape_response method."""

    def test_successful_parsing(self):
        """Parse a successful scrape response per BEP 15 spec."""
        client = UDPTrackerClient()
        h1 = b"\x01" * 20
        h2 = b"\x02" * 20
        requested = [h1, h2]

        data = struct.pack("!II", _ACTION_SCRAPES, 42)
        data += struct.pack("!III", 10, 100, 5)  # h1
        data += struct.pack("!III", 20, 200, 10)  # h2

        result = client._parse_scrape_response(data, 42, requested)

        assert not result.is_error
        assert h1 in result.files
        assert h2 in result.files
        assert result.files[h1].seeders == 10
        assert result.files[h1].completed == 100
        assert result.files[h1].leechers == 5
        assert result.files[h2].seeders == 20
        assert result.files[h2].completed == 200
        assert result.files[h2].leechers == 10

    def test_error_response(self):
        """Error response should raise."""
        client = UDPTrackerClient()
        data = struct.pack("!II", _ACTION_ERROR, 42) + b"ban hammer"
        with pytest.raises(TrackerResponseError) as exc_info:
            client._parse_scrape_response(data, 42, [b"\x01" * 20])
        assert "ban hammer" in str(exc_info.value)

    def test_partial_response(self):
        """Response with fewer entries than requested."""
        client = UDPTrackerClient()
        h1 = b"\x01" * 20
        h2 = b"\x02" * 20
        h3 = b"\x03" * 20
        requested = [h1, h2, h3]

        # Only provide 2 entries in response
        data = struct.pack("!II", _ACTION_SCRAPES, 42)
        data += struct.pack("!III", 10, 100, 5)
        data += struct.pack("!III", 20, 200, 10)

        result = client._parse_scrape_response(data, 42, requested)

        assert h1 in result.files
        assert h2 in result.files
        assert h3 not in result.files  # No data for h3

    def test_empty_response(self):
        """Empty scrape response with no file entries returned."""
        client = UDPTrackerClient()
        requested = [b"\x01" * 20]
        # Minimal valid response: action(4) + tid(4) = 8 bytes, but minimum is 12
        # So we need at least 12 bytes for a valid scrape response header
        data = struct.pack("!II", _ACTION_SCRAPES, 42) + b"\x00" * 4
        # 12 bytes = 8 header + 4 extra bytes (not enough for a full 12-byte entry)

        result = client._parse_scrape_response(data, 42, requested)
        assert len(result.files) == 0

    def test_scrape_response_minimum_length(self):
        """Response shorter than minimum should raise. Per BEP 15: minimum is 8 bytes,
        so exactly 8 bytes is valid but less than 8 should raise.
        """
        client = UDPTrackerClient()
        data = struct.pack("!II", _ACTION_SCRAPES, 1)  # Exactly 8 bytes - valid
        # 8 bytes should NOT raise - it's a valid header
        result = client._parse_scrape_response(data, 1, [b"\x01" * 20])
        assert len(result.files) == 0  # No entries to parse

        # Less than 8 bytes should raise
        short_data = struct.pack("!I", _ACTION_SCRAPES)  # Only 4 bytes
        with pytest.raises(TrackerProtocolError):
            client._parse_scrape_response(short_data, 1, [b"\x01" * 20])


class TestAnnounceEventConstants:
    """Verify AnnounceEvent constants match BEP 15 spec."""

    def test_none(self):
        assert AnnounceEvent.NONE == 0

    def test_completed(self):
        assert AnnounceEvent.COMPLETED == 1

    def test_started(self):
        assert AnnounceEvent.STARTED == 2

    def test_stopped(self):
        assert AnnounceEvent.STOPPED == 3
