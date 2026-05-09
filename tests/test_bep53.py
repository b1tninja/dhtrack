"""Tests for BEP 53 — Magnet URI File Selection."""

from __future__ import annotations

import pytest

from dhtrack.bep53 import (
    MagnetInfo,
    _format_select_only,
    _parse_so_parameter,
    create_magnet_from_torrent,
    magnet_peer_strings_to_triplets,
    merge_peer_triplets_preferred,
    parse_magnet_uri,
)


class TestParseSoParameter:
    """Tests for _parse_so_parameter."""

    def test_single_indices(self):
        """Parse single file indices."""
        result = _parse_so_parameter("0,2,4")
        assert result == {0, 2, 4}

    def test_range(self):
        """Parse inclusive range."""
        result = _parse_so_parameter("4-8")
        assert result == {4, 5, 6, 7, 8}

    def test_mixed(self):
        """Parse mixed indices and ranges."""
        result = _parse_so_parameter("0,2,4-6,8")
        assert result == {0, 2, 4, 5, 6, 8}

    def test_empty(self):
        """Empty string returns None."""
        assert _parse_so_parameter("") is None

    def test_whitespace_only(self):
        """Whitespace-only returns None."""
        assert _parse_so_parameter("   ") is None

    def test_invalid_index(self):
        """Invalid index is logged and skipped."""
        result = _parse_so_parameter("0,abc,2")
        assert result == {0, 2}

    def test_negative(self):
        """Negative indices are rejected."""
        result = _parse_so_parameter("0,-1,2")
        assert result == {0, 2}

    def test_invalid_range(self):
        """Invalid range (start > end) is rejected."""
        result = _parse_so_parameter("5-2")
        assert result is None

    def test_reverse_range(self):
        """Reverse range is rejected."""
        result = _parse_so_parameter("3-1")
        assert result is None


class TestMagnetInfo:
    """Tests for MagnetInfo dataclass."""

    def test_info_hash_hex(self):
        """Hex encoding of info hash."""
        info = MagnetInfo(info_hash=b"\x01\x02\x03")
        assert info.info_hash_hex == "010203"

    def test_info_hash_hex_none(self):
        """None info hash returns None."""
        info = MagnetInfo()
        assert info.info_hash_hex is None

    def test_info_hash_base16(self):
        """Upper-case hex info hash."""
        info = MagnetInfo(info_hash=b"\x01\x02\x03")
        assert info.info_hash_base16 == "010203"


class TestMagnetPeerHints:
    """Magnet ``pe`` → triplets and merge ordering (GUI / CLI hints)."""

    def test_ipv4_triplet(self) -> None:
        assert magnet_peer_strings_to_triplets(["192.0.2.10:6881"]) == [
            ("192.0.2.10", 6881, False),
        ]

    def test_ipv6_bracketed(self) -> None:
        assert magnet_peer_strings_to_triplets(["[2001:db8::1]:51413"]) == [
            ("2001:db8::1", 51413, True),
        ]

    def test_hostname_passthrough(self) -> None:
        assert magnet_peer_strings_to_triplets(["example.invalid:6881"]) == [
            ("example.invalid", 6881, False),
        ]

    def test_invalid_entries_skipped(self) -> None:
        assert (
            magnet_peer_strings_to_triplets(
                ["", "nocolon", "::1:not-bracket", "bad:xyz", "[no-bracket-close:89"],
            )
            == []
        )

    def test_merge_prepends_magnet_hints_dedupe(self) -> None:
        first = [("10.0.0.1", 6881, False), ("10.0.0.2", 6882, False)]
        second = [("10.0.0.2", 6882, True), ("10.0.0.3", 6883, False)]
        assert merge_peer_triplets_preferred(first, second) == [
            ("10.0.0.1", 6881, False),
            ("10.0.0.2", 6882, False),
            ("10.0.0.3", 6883, False),
        ]

    def test_parse_magnet_uri_collects_pe(self) -> None:
        xt = "abcdef1234567890abcdef1234567890abcdef12"
        uri = f"magnet:?xt=urn:btih:{xt}&pe=192.0.2.6:6881&pe=[2001:db8::5]:6882"
        info = parse_magnet_uri(uri)
        assert info.peers == ["192.0.2.6:6881", "[2001:db8::5]:6882"]
        trip = magnet_peer_strings_to_triplets(info.peers)
        assert trip == [
            ("192.0.2.6", 6881, False),
            ("2001:db8::5", 6882, True),
        ]


class TestCliResolveMagnetParsing:
    """Light tests for CLI resolve target parsing."""

    def test_hex_and_magnet_equivalent_btih(self) -> None:
        from dhtrack.cli import _parse_resolve_target

        h = "abcdef1234567890abcdef1234567890abcdef12"
        a, dn_a, init_a = _parse_resolve_target(h)
        uri = f"magnet:?xt=urn:btih:{h}&dn=My+Name&pe=192.0.2.1:7000"
        b, dn_b, init_b = _parse_resolve_target(uri)
        assert a == b
        assert dn_a is None
        assert dn_b == "My Name"
        assert init_a == []
        assert init_b == [("192.0.2.1", 7000)]


class TestParseMagnetUri:
    """Tests for parse_magnet_uri."""

    def test_hex_info_hash(self):
        """Parse hex-encoded info hash."""
        uri = "magnet:?xt=urn:btih:abcdef1234567890abcdef1234567890abcdef12"
        result = parse_magnet_uri(uri)

        assert result.info_hash is not None
        assert len(result.info_hash) == 20
        assert result.info_hash_hex == "abcdef1234567890abcdef1234567890abcdef12"

    def test_name(self):
        """Parse display name."""
        uri = "magnet:?xt=urn:btih:abcdef1234567890abcdef1234567890abcdef12&dn=Test%20Torrent"
        result = parse_magnet_uri(uri)
        assert result.name == "Test Torrent"

    def test_trackers(self):
        """Parse tracker URLs."""
        uri = "magnet:?xt=urn:btih:abcdef1234567890abcdef1234567890abcdef12&tr=http://tracker.example.com/announce"
        result = parse_magnet_uri(uri)
        assert len(result.trackers) == 1
        assert result.trackers[0] == "http://tracker.example.com/announce"

    def test_multiple_trackers(self):
        """Parse multiple tracker URLs."""
        uri = (
            "magnet:?xt=urn:btih:abcdef1234567890abcdef1234567890abcdef12"
            "&tr=http://tracker1.example.com/announce"
            "&tr=http://tracker2.example.com/announce"
        )
        result = parse_magnet_uri(uri)
        assert len(result.trackers) == 2

    def test_select_only(self):
        """Parse select-only parameter."""
        uri = "magnet:?xt=urn:btih:abcdef1234567890abcdef1234567890abcdef12&so=0,2,4-6"
        result = parse_magnet_uri(uri)
        assert result.select_only == {0, 2, 4, 5, 6}

    def test_invalid_scheme(self):
        """Non-magnet URI raises ValueError."""
        with pytest.raises(ValueError, match="Not a magnet URI"):
            parse_magnet_uri("http://example.com/file.torrent")

    def test_base32_info_hash(self):
        """Parse base32-encoded info hash."""
        # This is a valid base32-encoded hash (20 bytes = 32 base32 chars + padding)
        uri = "magnet:?xt=urn:btih:YCSSNFBUGVNCSSFBUGVNCSSFBU"
        result = parse_magnet_uri(uri)
        assert result.info_hash is not None


class TestFormatSelectOnly:
    """Tests for _format_select_only."""

    def test_single_index(self):
        """Single index formatted correctly."""
        assert _format_select_only([0]) == "0"

    def test_consecutive_indices(self):
        """Consecutive indices formatted as range."""
        assert _format_select_only([1, 2, 3, 4]) == "1-4"

    def test_mixed_format(self):
        """Mixed single indices and ranges."""
        assert _format_select_only([0, 2, 5, 6, 7]) == "0,2,5-7"

    def test_empty(self):
        """Empty list returns empty string."""
        assert _format_select_only([]) == ""

    def test_sorted_output(self):
        """Output is always sorted regardless of input order."""
        assert _format_select_only([5, 0, 2]) == "0,2,5"


class TestCreateMagnetFromTorrent:
    """Tests for create_magnet_from_torrent."""

    def test_basic_magnet(self):
        """Create basic magnet URI from a torrent-like object."""
        mock_torrent = type(
            "MockTorrent",
            (),
            {
                "infohash": b"\x01" * 20,
                "name": "Test Torrent",
                "file_count": 5,
            },
        )()

        uri = create_magnet_from_torrent(mock_torrent)
        assert uri.startswith("magnet:?")
        assert "xt=urn:btih:" in uri
        assert "dn=Test+Torrent" in uri

    def test_magnet_with_select_only(self):
        """Create magnet with select-only parameter."""
        mock_torrent = type(
            "MockTorrent",
            (),
            {
                "infohash": b"\x01" * 20,
                "name": "Test Torrent",
                "file_count": 5,
            },
        )()

        uri = create_magnet_from_torrent(mock_torrent, select_only={0, 2, 3})
        assert "so=0,2-3" in uri

    def test_magnet_with_trackers(self):
        """Create magnet with tracker URLs."""
        mock_torrent = type(
            "MockTorrent",
            (),
            {
                "infohash": b"\x01" * 20,
                "name": "Test Torrent",
            },
        )()

        trackers = ["http://tracker1.example.com/announce", "http://tracker2.example.com/announce"]
        uri = create_magnet_from_torrent(mock_torrent, trackers=trackers)
        assert "tr=" in uri
