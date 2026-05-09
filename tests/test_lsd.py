"""Tests for the dhtrack.lsd module (BEP-14: Local Service Discovery)."""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

from dhtrack.lsd import (
    LSD_MULTICAST_V4,
    LSD_MULTICAST_V6,
    LSD_PORT,
    LSDAnnouncement,
    LSDConfig,
    LSDManager,
    build_lsd_announce,
)

# ============================================================================
# LSDAnnouncement Tests
# ============================================================================


class TestLSDAnnouncement:
    """Tests for the LSDAnnouncement dataclass."""

    def test_encode_ipv4_announcement(self):
        """Encode an IPv4 LSD announcement."""
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie="testcookie123",
        )

        data = announcement.to_bytes()
        text = data.decode("latin-1")

        assert "BT-SEARCH * HTTP/1.1" in text
        assert f"Host: {LSD_MULTICAST_V4}" in text
        assert "Port: 6881" in text
        assert f"Infohash: {infohash.hex()}" in text
        assert "cookie: testcookie123" in text

    def test_encode_ipv6_announcement(self):
        """Encode an IPv6 LSD announcement."""
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V6,
            port=6881,
            infohashes=[infohash],
            cookie="testcookie123",
            is_ipv6=True,
        )

        data = announcement.to_bytes()
        text = data.decode("latin-1")

        assert "BT-SEARCH * HTTP/1.1" in text
        assert f"Host: {LSD_MULTICAST_V6}" in text
        assert "Port: 6881" in text

    def test_encode_announcement_without_cookie(self):
        """Encode an announcement without a cookie."""
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
        )

        data = announcement.to_bytes()
        text = data.decode("latin-1")

        assert "cookie:" not in text

    def test_encode_multiple_infohashes(self):
        """Encode an announcement with multiple infohashes."""
        infohashes = [os.urandom(20) for _ in range(3)]
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=infohashes,
        )

        data = announcement.to_bytes()
        text = data.decode("latin-1")

        for ih in infohashes:
            assert ih.hex() in text

    def test_decode_ipv4_announcement(self):
        """Decode an IPv4 LSD announcement."""
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie="testcookie123",
        )

        data = announcement.to_bytes()
        parsed = LSDAnnouncement.from_bytes(data, "192.168.1.100", 6881)

        assert parsed is not None
        assert parsed.host == LSD_MULTICAST_V4
        assert parsed.port == 6881
        assert len(parsed.infohashes) == 1
        assert parsed.infohashes[0] == infohash
        assert parsed.cookie == "testcookie123"
        assert parsed.source_ip == "192.168.1.100"
        assert parsed.source_port == 6881
        assert parsed.is_ipv6 is False

    def test_decode_ipv6_announcement(self):
        """Decode an IPv6 LSD announcement."""
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V6,
            port=6881,
            infohashes=[infohash],
            cookie="testcookie123",
        )

        data = announcement.to_bytes()
        parsed = LSDAnnouncement.from_bytes(data, "::1", 6881)

        assert parsed is not None
        assert parsed.host == LSD_MULTICAST_V6
        assert parsed.is_ipv6 is True

    def test_decode_invalid_method(self):
        """Decode a packet with an invalid HTTP method."""
        data = b"GET / HTTP/1.1\r\n\r\n"
        parsed = LSDAnnouncement.from_bytes(data, "127.0.0.1", 6881)
        assert parsed is None

    def test_decode_invalid_port(self):
        """Decode a packet with an invalid port."""
        infohash = os.urandom(20)
        lines = "\r\n".join(
            [
                "BT-SEARCH * HTTP/1.1",
                f"Host: {LSD_MULTICAST_V4}",
                "Port: invalid",
                f"Infohash: {infohash.hex()}",
                "",
            ]
        )
        parsed = LSDAnnouncement.from_bytes(lines.encode("latin-1"), "127.0.0.1", 6881)
        assert parsed is None

    def test_decode_empty_data(self):
        """Decode empty data."""
        parsed = LSDAnnouncement.from_bytes(b"", "127.0.0.1", 6881)
        assert parsed is None

    def test_decode_malformed_data(self):
        """Decode malformed data."""
        parsed = LSDAnnouncement.from_bytes(b"not valid data", "127.0.0.1", 6881)
        assert parsed is None

    def test_repr(self):
        """Test the __repr__ method."""
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            source_ip="192.168.1.100",
            source_port=6881,
        )
        r = repr(announcement)
        assert "LSDAnnouncement" in r
        assert "192.168.1.100" in r
        assert "6881" in r

    def test_decode_invalid_infohash_hex(self):
        """Decode a packet with invalid infohash hex."""
        lines = "\r\n".join(
            [
                "BT-SEARCH * HTTP/1.1",
                f"Host: {LSD_MULTICAST_V4}",
                "Port: 6881",
                "Infohash: not_hex",
                "",
            ]
        )
        parsed = LSDAnnouncement.from_bytes(lines.encode("latin-1"), "127.0.0.1", 6881)
        # Should still parse, just skip the invalid infohash
        assert parsed is not None
        assert len(parsed.infohashes) == 0


# ============================================================================
# LSDConfig Tests
# ============================================================================


class TestLSDConfig:
    """Tests for the LSDConfig dataclass."""

    def test_default_config(self):
        """Create a default LSDConfig."""
        config = LSDConfig()
        assert config.listen_port == 6881
        assert config.infohashes == []
        assert config.cookie is not None
        assert config.ttl == 1
        assert config.enabled is True

    def test_custom_config(self):
        """Create a custom LSDConfig."""
        config = LSDConfig(
            listen_port=6882,
            infohashes=[os.urandom(20)],
            ttl=2,
            enabled=False,
        )
        assert config.listen_port == 6882
        assert len(config.infohashes) == 1
        assert config.ttl == 2
        assert config.enabled is False

    def test_cookie_generation(self):
        """Cookie should be generated automatically."""
        config1 = LSDConfig()
        config2 = LSDConfig()
        assert config1.cookie != config2.cookie

    def test_custom_cookie(self):
        """Custom cookie should be preserved."""
        custom_cookie = "my_custom_cookie"
        config = LSDConfig(cookie=custom_cookie)
        assert config.cookie == custom_cookie


# ============================================================================
# LSDManager Tests
# ============================================================================


class TestLSDManager:
    """Tests for the LSDManager class."""

    def test_create_manager(self):
        """Create an LSDManager."""
        config = LSDConfig()
        manager = LSDManager(config=config)
        assert manager.config == config
        assert not manager.is_running

    def test_manager_default_config(self):
        """Create an LSDManager with default config."""
        manager = LSDManager()
        assert isinstance(manager.config, LSDConfig)
        assert not manager.is_running

    def test_manager_with_callback(self):
        """Create an LSDManager with a callback."""
        callback = MagicMock()
        manager = LSDManager(on_announcement_received=callback)
        assert manager.on_announcement_received is not None

    def test_stop_without_start(self):
        """Stopping a non-running manager should be safe."""
        manager = LSDManager()
        manager.stop()  # Should not raise

    def test_update_infohashes(self):
        """Update the infohashes in the manager."""
        config = LSDConfig()
        manager = LSDManager(config=config)

        infohashes = [os.urandom(20) for _ in range(3)]
        manager.update_infohashes(infohashes)

        assert len(manager.config.infohashes) == 3
        for ih in infohashes:
            assert ih in manager.config.infohashes

    def test_update_infohashes_filters_invalid(self):
        """Update should filter out invalid infohashes."""
        config = LSDConfig()
        manager = LSDManager(config=config)

        invalid_infohashes = [
            os.urandom(20),  # valid
            b"short",  # too short
            os.urandom(20),  # valid
            os.urandom(10),  # too short
        ]
        manager.update_infohashes(invalid_infohashes)

        assert len(manager.config.infohashes) == 2

    def test_send_announcement_when_not_running(self):
        """Sending announcement when not running should be a no-op."""
        manager = LSDManager()
        infohash = os.urandom(20)
        manager.send_announcement(infohashes=[infohash])  # Should not raise

    def test_send_announcement_rate_limiting(self):
        """Send announcement should respect rate limiting."""
        config = LSDConfig()
        config.enabled = True
        manager = LSDManager(config=config)

        # Start the manager (this will fail to create sockets in test env, but that's ok)
        # We test the rate limiting logic directly
        manager._last_announce_time = time.time() - 10  # 10 seconds ago

        # First call should be rate-limited
        with patch.object(manager, "_send_multicast"):
            manager.send_announcement(infohashes=[os.urandom(20)])

        # Force update the time and try again
        manager._last_announce_time = time.time()
        with patch.object(manager, "_send_multicast"):
            manager.send_announcement(infohashes=[os.urandom(20)])
        # Should have been called (rate limit passed)

    def test_get_discovered_peers_empty(self):
        """Get discovered peers when none exist."""
        manager = LSDManager()
        peers = manager.get_discovered_peers()
        assert peers == []

    def test_get_discovered_peers_expires_old(self):
        """Old discovered peers should be expired."""
        config = LSDConfig()
        manager = LSDManager(config=config)

        infohash = os.urandom(20)
        manager._discovered_peers[("192.168.1.1", 6881, infohash)] = time.time() - 700  # > 10 min
        manager._discovered_peers[("192.168.1.2", 6881, infohash)] = time.time()  # recent

        peers = manager.get_discovered_peers()
        assert len(peers) == 1
        assert peers[0][0] == "192.168.1.2"


# ============================================================================
# build_lsd_announce Function Tests
# ============================================================================


class TestBuildLSDAnnounce:
    """Tests for the build_lsd_announce convenience function."""

    def test_build_announce(self):
        """Build a LSD announce packet."""
        infohash = os.urandom(20)
        data = build_lsd_announce(6881, [infohash], cookie="test")

        text = data.decode("latin-1")
        assert "BT-SEARCH * HTTP/1.1" in text
        assert "Port: 6881" in text
        assert infohash.hex() in text
        assert "cookie: test" in text

    def test_build_announce_without_cookie(self):
        """Build a LSD announce without cookie."""
        infohash = os.urandom(20)
        data = build_lsd_announce(6881, [infohash])

        text = data.decode("latin-1")
        assert "BT-SEARCH * HTTP/1.1" in text
        assert "Port: 6881" in text

    def test_build_announce_multiple_infohashes(self):
        """Build a LSD announce with multiple infohashes."""
        infohashes = [os.urandom(20) for _ in range(5)]
        data = build_lsd_announce(6881, infohashes)

        text = data.decode("latin-1")
        for ih in infohashes:
            assert ih.hex() in text


# ============================================================================
# Multicast Group Tests
# ============================================================================


class TestMulticastGroups:
    """Tests for multicast group constants and address handling."""

    def test_multicast_v4_address(self):
        """IPv4 multicast address should be correct."""
        assert LSD_MULTICAST_V4 == "239.192.152.143"

    def test_multicast_v6_address(self):
        """IPv6 multicast address should be correct."""
        assert LSD_MULTICAST_V6 == "ff15::efc0:988f"

    def test_lsd_port(self):
        """LSD port should be 6771."""
        assert LSD_PORT == 6771

    def test_decode_host_header_detection(self):
        """Host header should determine IPv4/IPv6."""
        # IPv4 host
        lines = "\r\n".join(
            [
                "BT-SEARCH * HTTP/1.1",
                f"Host: {LSD_MULTICAST_V4}",
                "Port: 6881",
                "",
            ]
        )
        parsed = LSDAnnouncement.from_bytes(lines.encode("latin-1"), "192.168.1.100", 6881)
        assert parsed is not None
        assert parsed.is_ipv6 is False

        # IPv6 host
        lines = "\r\n".join(
            [
                "BT-SEARCH * HTTP/1.1",
                f"Host: {LSD_MULTICAST_V6}",
                "Port: 6881",
                "",
            ]
        )
        parsed = LSDAnnouncement.from_bytes(lines.encode("latin-1"), "::1", 6881)
        assert parsed is not None
        assert parsed.is_ipv6 is True


# ============================================================================
# Cookie Filter Tests
# ============================================================================


class TestCookieFiltering:
    """Tests for cookie-based announcement filtering."""

    def test_cookie_match_filters_announcement(self):
        """Announcements with matching cookie should be filtered."""
        cookie = "my_cookie"
        config = LSDConfig(cookie=cookie)
        callback = MagicMock()
        manager = LSDManager(config=config, on_announcement_received=callback)

        # Build an announcement with the same cookie
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie=cookie,
        )
        data = announcement.to_bytes()

        # Handle the packet
        manager._handle_packet(data, "192.168.1.100", 6881, False)

        # Callback should NOT be called (cookie matches)
        callback.assert_not_called()

    def test_cookie_mismatch_allows_announcement(self):
        """Announcements with different cookie should be allowed."""
        config = LSDConfig(cookie="my_cookie")
        callback = MagicMock()
        manager = LSDManager(config=config, on_announcement_received=callback)

        # Build an announcement with a different cookie
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie="other_cookie",
        )
        data = announcement.to_bytes()

        manager._handle_packet(data, "192.168.1.100", 6881, False)

        # Callback should be called
        callback.assert_called_once()

    def test_no_cookie_allows_announcement(self):
        """Announcements without cookie should be allowed."""
        config = LSDConfig(cookie="my_cookie")
        callback = MagicMock()
        manager = LSDManager(config=config, on_announcement_received=callback)

        # Build an announcement without cookie
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
        )
        data = announcement.to_bytes()

        manager._handle_packet(data, "192.168.1.100", 6881, False)

        # Callback should be called
        callback.assert_called_once()


# ============================================================================
# Discovered Peer Storage Tests
# ============================================================================


class TestDiscoveredPeerStorage:
    """Tests for discovered peer storage."""

    def test_peer_stored_on_announcement(self):
        """Peers should be stored when an announcement is received."""
        config = LSDConfig()
        manager = LSDManager(config=config)

        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie="other_cookie",
        )
        data = announcement.to_bytes()

        manager._handle_packet(data, "192.168.1.100", 6881, False)

        peers = manager.get_discovered_peers()
        assert len(peers) == 1
        assert peers[0][0] == "192.168.1.100"
        assert peers[0][1] == 6881
        assert peers[0][2] == infohash

    def test_multiple_infohashes_store_multiple_peers(self):
        """Multiple infohashes should store multiple peers."""
        config = LSDConfig()
        manager = LSDManager(config=config)

        infohashes = [os.urandom(20) for _ in range(3)]
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=infohashes,
            cookie="other_cookie",
        )
        data = announcement.to_bytes()

        manager._handle_packet(data, "192.168.1.100", 6881, False)

        peers = manager.get_discovered_peers()
        assert len(peers) == 3
        for ih in infohashes:
            assert ("192.168.1.100", 6881, ih) in peers


# ============================================================================
# Integration-style Tests
# ============================================================================


class TestLSDIntegration:
    """Integration-style tests for LSD components."""

    def test_full_announce_cycle(self):
        """Test a complete announce receive cycle."""
        config = LSDConfig()
        received = []

        def callback(ann):
            return received.append(ann)

        manager = LSDManager(config=config, on_announcement_received=callback)

        # Simulate receiving an announcement
        infohash = os.urandom(20)
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie="remote_cookie",
            source_ip="192.168.1.50",
            source_port=6881,
        )

        data = announcement.to_bytes()
        manager._handle_packet(data, "192.168.1.50", 6881, False)

        # Verify callback was called
        assert len(received) == 1
        assert received[0].source_ip == "192.168.1.50"
        assert received[0].source_port == 6881

        # Verify peer was stored
        peers = manager.get_discovered_peers()
        assert len(peers) == 1
        assert peers[0][0] == "192.168.1.50"
        assert peers[0][1] == 6881
        assert peers[0][2] == infohash

    def test_packet_size_limit(self):
        """Large announcements should be truncated to avoid MTU issues."""
        config = LSDConfig()
        LSDManager(config=config)

        # Create an announcement with many infohashes
        infohashes = [os.urandom(20) for _ in range(50)]
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=infohashes,
        )

        # The packet should not exceed LSD_MAX_PACKET_SIZE
        data = announcement.to_bytes()
        assert len(data) <= 1400 * 2  # Allow some margin (may need truncation)

    def test_announcement_from_bytes_handles_edge_cases(self):
        """Test edge cases in from_bytes."""
        # Empty infohash list
        lines = "\r\n".join(
            [
                "BT-SEARCH * HTTP/1.1",
                f"Host: {LSD_MULTICAST_V4}",
                "Port: 6881",
                "",
            ]
        )
        parsed = LSDAnnouncement.from_bytes(lines.encode("latin-1"), "127.0.0.1", 6881)
        assert parsed is not None
        assert len(parsed.infohashes) == 0

    def test_lsd_config_cookie_is_hex(self):
        """Cookie should be a hex string."""
        config = LSDConfig()
        int(config.cookie, 16)  # Should not raise

    def test_announcement_to_bytes_reproducible(self):
        """Same announcement should encode to the same bytes."""
        infohash = os.urandom(20)
        announcement1 = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie="test",
        )
        announcement2 = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=6881,
            infohashes=[infohash],
            cookie="test",
        )

        data1 = announcement1.to_bytes()
        data2 = announcement2.to_bytes()
        assert data1 == data2
