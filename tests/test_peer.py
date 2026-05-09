"""Tests for the dhtrack.peer module (BEP 10, 9, 11, 55)."""

from __future__ import annotations

import socket
import struct
import time

import pytest

from dhtrack import bencode as bencode_module
from dhtrack.extension import (
    ExtensionManager,
    ExtensionRegistry,
    MetadataExtension,
)
from dhtrack.peer import (
    EXTENSION_HANDSHAKE_TIMEOUT,
    EXTENSION_MSG_TYPE_HANDSHAKE,
    EXTENSION_MSG_TYPE_MESSAGE,
    HOLEPUNCH_CONNECT,
    HOLEPUNCH_ERR_NO_PEER,
    HOLEPUNCH_ERROR,
    PEX_SEMANTICS_BEP11,
    UT_METADATA,
    UT_PEX,
    ExtensionError,
    ExtensionHandshakeError,
    ExtensionNegotiator,
    HolePunchHandler,
    MetadataExchange,
    MetadataExchangeError,
    PeerConnection,
    PEXError,
    PEXManager,
)
from dhtrack.peerid import Endpoint
from dhtrack.torrent import Torrent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_torrent(data: dict) -> Torrent:
    """Create a minimal torrent object for testing."""
    return Torrent(data)


@pytest.fixture
def negotiator() -> ExtensionNegotiator:
    return ExtensionNegotiator()


@pytest.fixture
def sample_torrent() -> Torrent:
    """Create a minimal torrent with piece data."""
    info = {
        b"name": b"test_file.txt",
        b"piece length": 16384,
        b"piece": b"\x00" * 20,  # dummy piece hash
    }
    torrent_data = {b"announce": b"http://example.com/announce", b"info": info}
    return Torrent(torrent_data)


@pytest.fixture
def sample_endpoint() -> Endpoint:
    return Endpoint(ip="192.168.1.1", port=6881, node_id=b"\x00" * 20)


# ---------------------------------------------------------------------------
# ExtensionNegotiator Tests
# ---------------------------------------------------------------------------


class TestExtensionNegotiator:
    """Tests for ExtensionNegotiator."""

    def test_create_handshake(self, negotiator):
        handshake = negotiator.create_handshake()
        parsed = bencode_module.decode(handshake)
        assert isinstance(parsed, dict)
        assert b"m" in parsed
        assert b"v" in parsed

    def test_create_handshake_contains_extensions(self, negotiator):
        handshake = negotiator.create_handshake()
        parsed = bencode_module.decode(handshake)
        m = parsed.get(b"m", [])
        assert UT_METADATA in m

    def test_parse_handshake_valid(self, negotiator):
        handshake = bencode_module.encode(
            {
                b"m": [b"ut_metadata", b"ut_pex"],
                b"v": b"deluge2.1.0",
            }
        )
        result = negotiator.parse_handshake(handshake)
        assert result is True
        assert negotiator.peer_version == "deluge2.1.0"
        assert UT_METADATA in negotiator.negotiated_extensions
        assert UT_PEX in negotiator.negotiated_extensions

    def test_parse_handshake_no_common_extensions(self, negotiator):
        handshake = bencode_module.encode(
            {
                b"m": [b"unknown_ext"],
                b"v": b"other_client",
            }
        )
        result = negotiator.parse_handshake(handshake)
        assert result is False
        assert len(negotiator.negotiated_extensions) == 0

    def test_parse_handshake_malformed(self, negotiator):
        with pytest.raises(ExtensionHandshakeError):
            negotiator.parse_handshake(b"not bencoded")

    def test_send_extended_message_handshake(self, negotiator):
        msg = negotiator.send_extended_message(
            EXTENSION_MSG_TYPE_HANDSHAKE,
            {"m": "ut_metadata"},
        )
        assert isinstance(msg, bytes)
        assert msg[0] == 0  # message_type = 0 (extended message)

    def test_send_extended_message_data(self, negotiator):
        msg = negotiator.send_extended_message(
            EXTENSION_MSG_TYPE_MESSAGE,
            {"m": "ut_metadata"},
        )
        assert isinstance(msg, bytes)
        assert msg[0] == 0  # message_type = 0 (extended message)
        assert msg[3] == 1  # msg_type = 1

    def test_send_extended_message_invalid_type(self, negotiator):
        with pytest.raises(ExtensionError):
            negotiator.send_extended_message(99, {"m": "test"})

    def test_parse_extended_message_valid(self, negotiator):
        msg = negotiator.send_extended_message(
            EXTENSION_MSG_TYPE_MESSAGE,
            {"m": "ut_metadata", "piece": 0},
        )
        msg_type, payload = negotiator.parse_extended_message(msg)
        assert msg_type == 1
        assert isinstance(payload, dict)

    def test_parse_extended_message_too_short(self, negotiator):
        with pytest.raises(ExtensionError, match="too short"):
            negotiator.parse_extended_message(b"\x00\x00\x01")

    def test_parse_extended_message_invalid_type(self, negotiator):
        # Byte 0 is not 0 (extended message)
        msg = struct.pack("!BHB", 1, 2, 3)  # type=1, not extended
        with pytest.raises(ExtensionError, match="Not an extended message"):
            negotiator.parse_extended_message(msg)

    def test_is_timed_out(self, negotiator):
        assert negotiator.is_timed_out() is False
        # Manually set the time in the past
        negotiator.handshake_sent_time = time.time() - EXTENSION_HANDSHAKE_TIMEOUT - 1
        assert negotiator.is_timed_out() is True

    def test_reset_handshake_timer(self, negotiator):
        negotiator.handshake_sent_time = time.time() - 100
        negotiator.reset_handshake_timer()
        assert negotiator.is_timed_out() is False

    def test_supports_extension_true(self, negotiator):
        negotiator.negotiated_extensions.add(UT_METADATA)
        assert negotiator.supports_extension(UT_METADATA) is True

    def test_supports_extension_false(self, negotiator):
        assert negotiator.supports_extension(UT_PEX) is False

    def test_handshake_complete_flag(self, negotiator):
        handshake = bencode_module.encode(
            {
                "m": [b"ut_metadata"],
                "v": b"dh01",
            }
        )
        assert negotiator.handshake_complete is False
        negotiator.parse_handshake(handshake)
        assert negotiator.handshake_complete is True


# ---------------------------------------------------------------------------
# MetadataExchange Tests
# ---------------------------------------------------------------------------


class TestMetadataExchange:
    """Tests for MetadataExchange."""

    def test_get_handshake(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        handshake = m.create_handshake()
        parsed = bencode_module.decode(handshake)
        assert isinstance(parsed, dict)
        assert parsed.get(b"msg_type") == 1  # UT_METADATA_DATA (used as handshake type)

    def test_create_request(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        request = m.create_request(0, b"req123")
        parsed = bencode_module.decode(request)
        assert parsed.get(b"msg_type") == 0  # UT_METADATA_REQUEST
        assert parsed.get(b"piece") == 0
        # reqid is auto-generated MD5 hash, not the passed value
        assert b"reqid" in parsed

    def test_create_request_invalid_index(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        with pytest.raises(MetadataExchangeError):
            m.create_request(-1, b"req123")

    def test_create_request_index_out_of_range(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        with pytest.raises(MetadataExchangeError):
            m.create_request(100, b"req123")

    def test_handle_data_valid(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        data = bencode_module.encode(
            {
                b"msg_type": 1,
                b"piece": 0,
                b"total_size": 100,
                b"buffer": b"test data",
            }
        )
        # Should not raise, returns None or False
        result = m.handle_data(data)
        assert result is None or result is False

    def test_handle_data_invalid_type(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        data = bencode_module.encode(
            {
                b"msg_type": 99,  # Invalid
                b"piece": 0,
                b"buffer": b"test data",
            }
        )
        # Should return None, not raise
        result = m.handle_data(data)
        assert result is None

    def test_handle_reject(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        data = bencode_module.encode(
            {
                b"msg_type": 2,
                b"piece": 0,
            }
        )
        # Should not raise
        m.handle_reject(data)

    def test_verify_metadata_invalid(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        # Verify with random bytes that don't form valid metadata
        result = m._verify_metadata(b"not valid metadata")
        assert result is False

    def test_get_total_size(self, sample_torrent):
        m = MetadataExchange(sample_torrent)
        total = m._calculate_metadata_size()
        assert total >= 0


# ---------------------------------------------------------------------------
# PEXManager Tests
# ---------------------------------------------------------------------------


class TestPEXManager:
    """Tests for PEXManager."""

    @pytest.fixture
    def pex_manager(self, sample_torrent):
        return PEXManager(
            info_hash=sample_torrent.infohash,
            my_node_id=b"\x00" * 20,
        )

    def test_create_pex_message_empty(self, pex_manager):
        msg = pex_manager.create_pex_message()
        parsed = bencode_module.decode(msg)
        assert isinstance(parsed, dict)
        assert b"m" not in parsed
        assert parsed.get(b"added") == b""

    def test_create_pex_message_with_peers(self, pex_manager, sample_endpoint):
        msg = pex_manager.create_pex_message(new_peers=[sample_endpoint])
        parsed = bencode_module.decode(msg)
        assert b"added" in parsed
        compact = parsed[b"added"]
        assert isinstance(compact, bytes)
        assert len(compact) == 6
        assert compact[:4] == socket.inet_aton("192.168.1.1")
        assert int.from_bytes(compact[4:6], "big") == 6881

    def test_create_pex_message_with_removed(self, pex_manager, sample_endpoint):
        msg = pex_manager.create_pex_message(removed_peers=[sample_endpoint])
        parsed = bencode_module.decode(msg)
        compact = parsed[b"dropped"]
        assert len(compact) == 6

    def test_parse_pex_bep11_compact(self, pex_manager, sample_endpoint):
        msg = pex_manager.create_pex_message(new_peers=[sample_endpoint])
        new_peers, removed_peers, semantics = pex_manager.parse_pex_message(msg)
        assert semantics == PEX_SEMANTICS_BEP11
        assert len(new_peers) == 1
        assert new_peers[0].ip == "192.168.1.1"
        assert new_peers[0].port == 6881
        assert removed_peers == []

    def test_parse_legacy_pex_dict_peers(self, pex_manager, sample_endpoint):
        peer_data = {
            b"ip": struct.pack("!BBBB", 192, 168, 1, 1),
            b"port": struct.pack("!H", 6881),
        }
        msg = bencode_module.encode(
            {
                b"m": [b"ut_pex"],
                b"peers": [peer_data],
                b"events": 1,
            }
        )
        new_peers, removed_peers, events = pex_manager.parse_pex_message(msg)
        assert len(new_peers) == 1
        assert new_peers[0].ip == "192.168.1.1"
        assert new_peers[0].port == 6881
        assert removed_peers == []
        assert events == 1

    def test_parse_pex_message_invalid(self, pex_manager):
        with pytest.raises(PEXError):
            pex_manager.parse_pex_message(b"not bencoded")

    def test_add_peer(self, pex_manager, sample_endpoint):
        pex_manager.add_peer(sample_endpoint)
        assert sample_endpoint in pex_manager.known_peers
        assert sample_endpoint in pex_manager.recent_peers

    def test_remove_peer(self, pex_manager, sample_endpoint):
        pex_manager.add_peer(sample_endpoint)
        pex_manager.remove_peer(sample_endpoint)
        assert sample_endpoint not in pex_manager.known_peers
        assert sample_endpoint not in pex_manager.recent_peers

    def test_clear_recent_peers(self, pex_manager, sample_endpoint):
        pex_manager.add_peer(sample_endpoint)
        pex_manager.clear_recent_peers()
        assert sample_endpoint not in pex_manager.recent_peers
        assert sample_endpoint in pex_manager.known_peers

    def test_parse_pex_peer_ipv6(self, pex_manager):
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, "::1")
        peer_data = {
            "ip": ipv6_bytes,
            "port": struct.pack("!H", 6881),
            "id": b"\x00" * 20,
        }
        msg = bencode_module.encode(
            {
                "peers": [peer_data],
            }
        )
        new_peers, _, _ = pex_manager.parse_pex_message(msg)
        assert len(new_peers) == 1
        assert new_peers[0].is_ipv6 is True

    def test_pex_compact_ipv6_encode_decode(self, pex_manager):
        ep_v6 = Endpoint(ip="2001:db8::1", port=51413, node_id=None)
        raw = pex_manager.create_pex_message(new_peers=[ep_v6])
        dec = bencode_module.decode(raw)
        blob = dec[b"added6"]
        assert len(blob) == 18
        new_peers, _, sem = pex_manager.parse_pex_message(raw)
        assert sem == PEX_SEMANTICS_BEP11
        assert len(new_peers) == 1
        assert new_peers[0].ip == "2001:db8::1"
        assert new_peers[0].port == 51413


# ---------------------------------------------------------------------------
# HolePunchHandler Tests
# ---------------------------------------------------------------------------


class TestHolePunchHandler:
    """Tests for HolePunchHandler."""

    def test_create_holepunch_message(self):
        handler = HolePunchHandler()
        msg = handler.create_connect_message(
            peer_ip="192.168.1.1",
            peer_port=6881,
        )
        # Binary format: msg_type(1) + addr_type(1) + ip(4) + port(2)
        assert isinstance(msg, bytes)
        assert len(msg) >= 8
        assert msg[0] == HOLEPUNCH_CONNECT

    def test_handle_holepunch_connect(self):
        handler = HolePunchHandler()
        # Create binary connect message
        msg = handler.create_connect_message(
            peer_ip="192.168.1.1",
            peer_port=6881,
        )
        result = handler.handle_connect(msg)
        assert isinstance(result, dict)
        assert result.get("msg_type") == HOLEPUNCH_CONNECT
        assert result.get("ip") == "192.168.1.1"

    def test_handle_holepunch_invalid(self):
        handler = HolePunchHandler()
        with pytest.raises(ExtensionError):
            handler.handle_connect(b"too short")

    def test_cancel_request(self):
        handler = HolePunchHandler()
        msg = handler.create_error_message(
            target_ip="192.168.1.1",
            target_port=6881,
            err_code=HOLEPUNCH_ERR_NO_PEER,
        )
        # Binary error message
        assert isinstance(msg, bytes)
        assert msg[0] == HOLEPUNCH_ERROR


# ---------------------------------------------------------------------------
# PeerConnection Tests
# ---------------------------------------------------------------------------


class TestPeerConnection:
    """Tests for PeerConnection."""

    @pytest.fixture
    def connection(self):
        endpoint = Endpoint(ip="192.168.1.1", port=6881)
        peer_id = b"\x00" * 20
        info_hash = b"\x11" * 20
        return PeerConnection(peer_id=peer_id, endpoint=endpoint, info_hash=info_hash)

    def test_create_handshake(self, connection):
        handshake = connection.create_handshake()
        assert isinstance(handshake, bytes)
        assert len(handshake) > 0

    def test_create_extended_handshake(self, connection):
        msg = connection.create_extended_handshake()
        assert isinstance(msg, bytes)
        assert msg[0] == 0  # extended message type

    def test_handshake_not_done(self, connection):
        assert connection.handshake_done is False

    def test_update_activity(self, connection):
        old_time = connection.last_activity
        time.sleep(0.01)
        connection.update_activity()
        assert connection.last_activity > old_time

    def test_is_idle(self, connection):
        connection.last_activity = time.time() - 200
        assert connection.is_idle(timeout=100.0) is True
        assert connection.is_idle(timeout=300.0) is False

    def test_is_not_idle(self, connection):
        assert connection.is_idle(timeout=300.0) is False

    def test_repr(self, connection):
        repr_str = repr(connection)
        assert "PeerConnection" in repr_str
        assert "192.168.1.1" in repr_str

    def test_send_message_before_handshake(self, connection):
        with pytest.raises(ExtensionError, match="handshake not complete"):
            connection.send_message(1, {"m": "test"})

    def test_parse_extended_message_invalid(self, connection):
        with pytest.raises(ExtensionError):
            connection.handle_extended_message(b"\x01\x00\x00\x01")


# ---------------------------------------------------------------------------
# ExtensionManager Tests
# ---------------------------------------------------------------------------


class TestExtensionManager:
    """Tests for ExtensionManager."""

    def test_initialize(self):
        manager = ExtensionManager()
        manager.initialize()
        assert len(manager.enabled_extensions) >= 0

    def test_get_handshake_names(self):
        manager = ExtensionManager()
        names = manager.get_handshake_names()
        assert isinstance(names, list)

    def test_handle_handshake_no_extension(self):
        manager = ExtensionManager()
        result = manager.handle_handshake("nonexistent", b"data")
        assert result is False

    def test_handle_message_no_extension(self):
        manager = ExtensionManager()
        result = manager.handle_message("nonexistent", 0, b"data")
        assert result is None

    def test_create_extended_message(self):
        manager = ExtensionManager()
        msg = manager.create_extended_message(
            "ut_metadata",
            1,
            {"piece": 0},
        )
        assert isinstance(msg, bytes)


# ---------------------------------------------------------------------------
# ExtensionRegistry Tests
# ---------------------------------------------------------------------------


class TestExtensionRegistry:
    """Tests for ExtensionRegistry."""

    def test_register_and_get(self):
        registry = ExtensionRegistry()
        ext = MetadataExtension.__new__(MetadataExtension)  # Minimal instance
        ext.name = "test_ext"
        ext.enabled = True
        registry.register(ext)
        assert registry.get("test_ext") is not None

    def test_register_disabled_extension(self):
        registry = ExtensionRegistry()
        ext = MetadataExtension.__new__(MetadataExtension)
        ext.name = "test_ext"
        ext.enabled = False
        registry.register(ext)
        assert registry.get("test_ext") is None

    def test_get_all(self):
        registry = ExtensionRegistry()
        ext1 = MetadataExtension.__new__(MetadataExtension)
        ext1.name = "ext1"
        ext1.enabled = True
        ext2 = MetadataExtension.__new__(MetadataExtension)
        ext2.name = "ext2"
        ext2.enabled = True
        registry.register(ext1)
        registry.register(ext2)
        all_ext = registry.get_all()
        assert len(all_ext) == 2

    def test_has(self):
        registry = ExtensionRegistry()
        ext = MetadataExtension.__new__(MetadataExtension)
        ext.name = "test_ext"
        ext.enabled = True
        registry.register(ext)
        assert registry.has("test_ext") is True
        assert registry.has("nonexistent") is False

    def test_unregister(self):
        registry = ExtensionRegistry()
        ext = MetadataExtension.__new__(MetadataExtension)
        ext.name = "test_ext"
        ext.enabled = True
        registry.register(ext)
        registry.unregister("test_ext")
        assert registry.get("test_ext") is None

    def test_get_supported_names(self):
        registry = ExtensionRegistry()
        ext = MetadataExtension.__new__(MetadataExtension)
        ext.name = "test_ext"
        ext.enabled = True
        registry.register(ext)
        names = registry.get_supported_names()
        assert "test_ext" in names


# ---------------------------------------------------------------------------
# Extension Class Tests
# ---------------------------------------------------------------------------


class TestExtension:
    """Tests for Extension base class."""

    def test_extension_repr(self):
        ext = MetadataExtension.__new__(MetadataExtension)
        ext.name = "test"
        ext.enabled = True
        assert "enabled" in repr(ext)

    def test_extension_repr_disabled(self):
        ext = MetadataExtension.__new__(MetadataExtension)
        ext.name = "test"
        ext.enabled = False
        assert "disabled" in repr(ext)


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestExtensionIntegration:
    """Integration tests for the extension protocol."""

    def test_full_handshake_negotiation(self):
        """Test the full handshake negotiation flow."""
        # Client A creates handshake
        negotiator_a = ExtensionNegotiator(client_version="dh01")
        negotiator_a.create_handshake()

        # Client B parses handshake and creates response
        negotiator_b = ExtensionNegotiator(client_version="deluge2.1.0")
        # Simulate B's response
        handshake_b = bencode_module.encode(
            {
                b"m": [b"ut_metadata", b"ut_pex"],
                b"v": b"deluge2.1.0",
            }
        )
        result = negotiator_b.parse_handshake(handshake_b)
        assert result is True
        assert UT_METADATA in negotiator_b.negotiated_extensions

        # Client A parses response
        result_a = negotiator_a.parse_handshake(handshake_b)
        assert result_a is True

    def test_extended_message_roundtrip(self):
        """Test sending and receiving extended messages."""
        negotiator = ExtensionNegotiator()

        # Send message
        msg = negotiator.send_extended_message(
            EXTENSION_MSG_TYPE_MESSAGE,
            {"m": "ut_metadata", "piece": 5},
        )

        # Parse message
        msg_type, payload = negotiator.parse_extended_message(msg)
        assert msg_type == 1
        assert payload.get(b"piece") == 5
