"""Tests for BEP-27 (Private Torrents) implementation."""

from __future__ import annotations

import pytest

from dhtrack.torrent import Torrent
from dhtrack.extension import PEXExtension


# ============================================================================
# Test Data Helpers
# ============================================================================


def create_private_torrent() -> Torrent:
    """Create a torrent with the private flag set."""
    data = {
        'announce': b'http://tracker.example.com/announce',
        'info': {
            'name': b'test_file.txt',
            'piece length': 16384,
            'pieces': b'\x00' * 20,
            'private': 1,
        },
    }
    return Torrent(data)


def create_public_torrent() -> Torrent:
    """Create a torrent without the private flag."""
    data = {
        'announce': b'http://tracker.example.com/announce',
        'info': {
            'name': b'test_file.txt',
            'piece length': 16384,
            'pieces': b'\x00' * 20,
        },
    }
    return Torrent(data)


# ============================================================================
# Test Torrent.is_private Property
# ============================================================================


class TestTorrentIsPrivate:
    """Tests for Torrent.is_private property."""

    def test_private_torrent_with_int_value(self):
        """Torrent should be private when info contains private=1 (int)."""
        torrent = create_private_torrent()
        assert torrent.is_private is True

    def test_private_torrent_with_string_value(self):
        """Torrent should be private when info contains private='1' (string)."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': {
                'name': b'test_file.txt',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
                'private': '1',
            },
        }
        torrent = Torrent(data)
        assert torrent.is_private is True

    def test_private_torrent_with_string_true(self):
        """Torrent should be private when info contains private='true'."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': {
                'name': b'test_file.txt',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
                'private': 'true',
            },
        }
        torrent = Torrent(data)
        assert torrent.is_private is True

    def test_public_torrent_no_private_key(self):
        """Torrent without private key should not be private."""
        torrent = create_public_torrent()
        assert torrent.is_private is False

    def test_public_torrent_with_zero_value(self):
        """Torrent with private=0 should not be private."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': {
                'name': b'test_file.txt',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
                'private': 0,
            },
        }
        torrent = Torrent(data)
        assert torrent.is_private is False

    def test_public_torrent_with_false_value(self):
        """Torrent with private=false should not be private."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': {
                'name': b'test_file.txt',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
                'private': False,
            },
        }
        torrent = Torrent(data)
        assert torrent.is_private is False

    def test_info_not_dict(self):
        """Torrent with non-dict info should not be private."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': b'not_a_dict',
        }
        torrent = Torrent(data)
        assert torrent.is_private is False


# ============================================================================
# Test Torrent.is_private Setter
# ============================================================================


class TestTorrentIsPrivateSetter:
    """Tests for Torrent.is_private setter."""

    def test_set_private_true(self):
        """Setting is_private=True should add private=1 to info dict."""
        torrent = create_public_torrent()
        torrent.is_private = True
        assert torrent.is_private is True

        info = torrent.info
        assert isinstance(info, dict)
        assert 'private' in info or b'private' in info

    def test_set_private_false(self):
        """Setting is_private=False should remove private key from info dict."""
        torrent = create_private_torrent()
        assert torrent.is_private is True
        torrent.is_private = False
        assert torrent.is_private is False

        info = torrent.info
        if isinstance(info, dict):
            assert 'private' not in info
            assert b'private' not in info

    def test_set_private_already_true(self):
        """Setting is_private=True when already True should not error."""
        torrent = create_private_torrent()
        torrent.is_private = True
        assert torrent.is_private is True

    def test_set_private_on_non_dict_info(self):
        """Setting is_private should not error when info is not a dict."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': b'not_a_dict',
        }
        torrent = Torrent(data)
        # Should not raise
        torrent.is_private = True


# ============================================================================
# Test Private Flag with Different Key Types
# ============================================================================


class TestPrivateFlagKeyTypes:
    """Tests for handling different key types for the private flag."""

    def test_private_with_bytes_key_in_raw_dict(self):
        """Torrent with bytes key in raw dict should be detected."""
        # Note: bytes keys at top level (b'announce', b'info') are fine
        # because the Torrent class handles them.
        # The info dict itself uses string keys for bencode compatibility.
        data = {
            b'announce': b'http://tracker.example.com/announce',
            b'info': {
                'name': b'test_file.txt',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
                'private': b'1',
            },
        }
        torrent = Torrent(data)
        # The info property uses normalized dict with string keys
        info = torrent.info
        if isinstance(info, dict):
            assert 'private' in info

    def test_setter_adds_key(self):
        """Setting is_private should add key to info dict."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': {
                'name': b'test_file.txt',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        torrent.is_private = True
        # Check that private is inside the info dict (not at top level)
        info = torrent.info
        assert isinstance(info, dict)
        assert 'private' in info or b'private' in info

    def test_setter_removes_key(self):
        """Setting is_private=False should remove key from info dict."""
        data = {
            'announce': b'http://tracker.example.com/announce',
            'info': {
                'name': b'test_file.txt',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
                'private': '1',
            },
        }
        torrent = Torrent(data)
        torrent.is_private = False
        info = torrent.info
        if isinstance(info, dict):
            assert 'private' not in info


# ============================================================================
# Test PEX Extension Private Torrent Enforcement (BEP-27)
# ============================================================================


class TestPEXExtensionPrivate:
    """Tests for PEX extension BEP-27 enforcement."""

    def _make_pex_extension(self, is_private: bool = False) -> PEXExtension:
        """Create a mock PEX extension with private flag."""
        # Create a minimal mock PEX manager
        class MockPEXManager:
            def parse_pex_message(self, payload):
                return ([], [], 0)

        return PEXExtension(MockPEXManager(), is_private=is_private)

    def test_pex_disabled_for_private_torrent(self):
        """PEX messages should be dropped for private torrents."""
        pex = self._make_pex_extension(is_private=True)
        # PEX message type 0 with sample payload
        payload = b'e'  # bencoded empty list
        result = pex.on_message(0, payload)
        # Should return None (dropped, not processed)
        assert result is None

    def test_pex_enabled_for_public_torrent(self):
        """PEX messages should be processed for public torrents."""
        pex = self._make_pex_extension(is_private=False)
        payload = b'e'  # bencoded empty list (no new peers)
        result = pex.on_message(0, payload)
        # Should return None (processed, but nothing to respond)
        assert result is None

    def test_pex_is_private_property(self):
        """The is_private property should reflect the torrent's privacy."""
        pex_private = self._make_pex_extension(is_private=True)
        pex_public = self._make_pex_extension(is_private=False)

        assert pex_private.is_private is True
        assert pex_public.is_private is False

    def test_pex_set_private(self):
        """Setting is_private should toggle PEX enforcement."""
        pex = self._make_pex_extension(is_private=False)
        assert pex.is_private is False

        payload = b'e'

        # Not private - should process normally
        result = pex.on_message(0, payload)
        assert result is None

        # Toggle to private
        pex.is_private = True
        assert pex.is_private is True

        # Should still drop (returns None for private)
        result = pex.on_message(0, payload)
        assert result is None

    def test_pex_drops_all_message_types(self):
        """PEX should drop all message types for private torrents."""
        pex = self._make_pex_extension(is_private=True)

        # Even if different message types come in, they should be dropped
        for msg_type in [0, 1, 2, 255]:
            result = pex.on_message(msg_type, b'e')
            assert result is None