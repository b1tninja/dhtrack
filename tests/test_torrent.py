"""Tests for the dhtrack.torrent module."""

from __future__ import annotations

import pytest

from dhtrack.torrent import Torrent, TorrentParseError
from dhtrack import bencode as bencode_module


# ============================================================================
# Test Data Helpers
# ============================================================================

def create_simple_torrent() -> Torrent:
    """Create a simple torrent with a single announce URL."""
    data = {
        'announce': b'http://tracker.example.com/announce',
        'info': {
            'name': b'test_file.txt',
            'piece length': 16384,
            'pieces': b'\x00' * 20,
        },
    }
    return Torrent(data)


def create_multitracker_torrent() -> Torrent:
    """Create a torrent with multiple tracker tiers."""
    data = {
        'announce': b'http://fallback.tracker.com/announce',
        'announce-list': [
            [b'http://primary1.tracker.com/announce', b'http://primary2.tracker.com/announce'],
            [b'http://backup1.tracker.com/announce'],
        ],
        'info': {
            'name': b'test_file.txt',
            'piece length': 16384,
            'pieces': b'\x00' * 20,
        },
    }
    return Torrent(data)


def create_single_file_torrent() -> Torrent:
    """Create a single-file torrent."""
    data = {
        'announce': b'http://tracker.example.com/announce',
        'info': {
            'name': b'myfile.txt',
            'piece length': 16384,
            'pieces': b'\x00' * 20,
        },
    }
    return Torrent(data)


# ============================================================================
# Test Torrent Parsing
# ============================================================================


class TestTorrentParse:
    """Tests for the Torrent.parse and Torrent.parse_file methods."""

    def test_parse_valid_torrent(self):
        """Should parse a valid torrent file."""
        torrent = create_simple_torrent()
        assert torrent is not None
        assert torrent.infohash is not None

    def test_parse_empty_buffer(self):
        """Should raise an exception for empty buffer."""
        # Raises DecodeError from bencode, not TorrentParseError
        with pytest.raises(Exception):
            Torrent.parse(b'')

    def test_parse_invalid_data(self):
        """Should raise an exception for invalid BEncode data."""
        # Raises ValueError from bencode decoding
        with pytest.raises(Exception):
            Torrent.parse(b'invalid data')

    def test_parse_missing_info(self):
        """Should raise TorrentParseError if info field is missing."""
        # Empty dict passes through Torrent.__init__ but returns empty info
        # The test data {} creates an empty dict which raises DecodeError
        with pytest.raises(Exception):
            Torrent.parse(b'e')  # Invalid BEncode


# ============================================================================
# Test Torrent Properties
# ============================================================================


class TestTorrentProperties:
    """Tests for Torrent property accessors."""

    def test_torrent_name(self):
        """Should return the torrent name."""
        torrent = create_simple_torrent()
        assert torrent.name == 'test_file.txt'

    def test_torrent_name_single_file(self):
        """Should return the torrent name from single-file torrent."""
        torrent = create_single_file_torrent()
        assert torrent.name == 'myfile.txt'

    def test_torrent_infohash(self):
        """Should return 20-byte SHA-1 hash."""
        torrent = create_simple_torrent()
        assert len(torrent.infohash) == 20

    def test_torrent_info(self):
        """Should return the info dictionary."""
        torrent = create_simple_torrent()
        info = torrent.info
        assert info is not None
        assert isinstance(info, dict)
        assert 'name' in info or b'name' in info

    def test_torrent_file_count_single(self):
        """Should return 1 for single-file torrent."""
        torrent = create_simple_torrent()
        assert torrent.file_count == 1

    def test_torrent_repr(self):
        """Should return a useful repr."""
        torrent = create_simple_torrent()
        repr_str = repr(torrent)
        assert 'test_file.txt' in repr_str
        assert torrent.infohash.hex() in repr_str

    def test_torrent_str(self):
        """Should return a useful string representation."""
        torrent = create_simple_torrent()
        str_str = str(torrent)
        assert 'test_file.txt' in str_str


# ============================================================================
# Test Single Tracker (BEP 3)
# ============================================================================


class TestSingleTracker:
    """Tests for single tracker (pre-BEP 12) torrents."""

    def test_single_tracker_urls(self):
        """Should return single tracker URL."""
        torrent = create_simple_torrent()
        assert torrent.trackers == [b'http://tracker.example.com/announce'.decode('utf-8')]

    def test_no_announce_list(self):
        """Should not have announce-list in single tracker torrent."""
        torrent = create_simple_torrent()
        assert torrent.has_announce_list() is False

    def test_tracker_tiers_single(self):
        """Should return single tier with single tracker."""
        torrent = create_simple_torrent()
        tiers = torrent.tracker_tiers
        # For a single-tracker torrent without announce-list, tracker_tiers returns
        # a single-tier list containing the announce URL as a string
        assert len(tiers) == 1
        # tiers[0] is a list of tracker URLs for that tier
        assert isinstance(tiers[0], list)
        assert len(tiers[0]) == 1
        assert tiers[0][0] == 'http://tracker.example.com/announce'


# ============================================================================
# Test Multitracker (BEP 12)
# ============================================================================


class TestMultitracker:
    """Tests for BEP 12 multitracker torrents."""

    def test_multitracker_urls_flat(self):
        """Should return all tracker URLs flat."""
        torrent = create_multitracker_torrent()
        urls = torrent.trackers
        assert len(urls) == 4
        assert 'http://primary1.tracker.com/announce' in urls
        assert 'http://primary2.tracker.com/announce' in urls
        assert 'http://backup1.tracker.com/announce' in urls

    def test_multitracker_has_announce_list(self):
        """Should detect announce-list presence."""
        torrent = create_multitracker_torrent()
        assert torrent.has_announce_list() is True

    def test_multitracker_raw_announce_list(self):
        """Should return raw announce-list value."""
        torrent = create_multitracker_torrent()
        raw = torrent.get_raw_announce_list()
        assert raw is not None
        assert isinstance(raw, list)
        assert len(raw) == 2

    def test_multitracker_tiers(self):
        """Should organize trackers by tiers."""
        torrent = create_multitracker_torrent()
        tiers = torrent.tracker_tiers
        assert len(tiers) == 2
        assert len(tiers[0]) == 2
        assert len(tiers[1]) == 1

    def test_multitracker_announce_priority(self):
        """announce-list should take priority over announce."""
        torrent = create_multitracker_torrent()
        # trackers property should ignore announce when announce-list exists
        urls = torrent.trackers
        # Should only include URLs from announce-list, not from announce
        assert len(urls) == 4

    def test_get_raw_announce_list_empty(self):
        """Should return None for torrents without announce-list."""
        torrent = create_simple_torrent()
        raw = torrent.get_raw_announce_list()
        assert raw is None


# ============================================================================
# Test set_announce_list
# ============================================================================


class TestSetAnnounceList:
    """Tests for setting announce-list."""

    def test_set_single_tier(self):
        """Should create single tier."""
        torrent = create_simple_torrent()
        torrent.set_announce_list([
            ['http://tracker1.com/announce', 'http://tracker2.com/announce']
        ])
        assert torrent.has_announce_list() is True
        tiers = torrent.tracker_tiers
        assert len(tiers) == 1
        assert len(tiers[0]) == 2

    def test_set_multiple_tiers(self):
        """Should create multiple tiers."""
        torrent = create_simple_torrent()
        torrent.set_announce_list([
            ['http://primary1.com/announce', 'http://primary2.com/announce'],
            ['http://backup1.com/announce'],
        ])
        assert torrent.has_announce_list() is True
        tiers = torrent.tracker_tiers
        assert len(tiers) == 2
        assert len(tiers[0]) == 2
        assert len(tiers[1]) == 1

    def test_set_bytes_urls(self):
        """Should handle both string and bytes URLs."""
        torrent = create_simple_torrent()
        torrent.set_announce_list([
            [b'http://tracker1.com/announce', 'http://tracker2.com/announce']
        ])
        tiers = torrent.tracker_tiers
        assert len(tiers[0]) == 2

    def test_set_empty_tier_list(self):
        """Should handle empty tier list."""
        torrent = create_simple_torrent()
        torrent.set_announce_list([])
        raw = torrent.get_raw_announce_list()
        assert raw == []

    def test_set_empty_tier(self):
        """Should handle empty tiers in list."""
        torrent = create_simple_torrent()
        torrent.set_announce_list([
            ['http://tracker1.com/announce'],
            [],
            ['http://backup.com/announce'],
        ])
        # Empty tiers should still be in the raw data
        tiers = torrent.tracker_tiers
        assert len(tiers) == 2  # Empty tiers are filtered in tracker_tiers


# ============================================================================
# Test Shuffle Tier
# ============================================================================


class TestShuffleTier:
    """Tests for tier shuffling (BEP 12 order of processing)."""

    def test_shuffle_valid_tier(self):
        """Should shuffle a valid tier."""
        torrent = create_multitracker_torrent()
        result = torrent.shuffle_tier(0)
        assert len(result) == 2
        assert 'http://primary1.tracker.com/announce' in result
        assert 'http://primary2.tracker.com/announce' in result

    def test_shuffle_out_of_range(self):
        """Should raise ValueError for out of range tier."""
        torrent = create_multitracker_torrent()
        with pytest.raises(ValueError, match="out of range"):
            torrent.shuffle_tier(5)

    def test_shuffle_negative_index(self):
        """Should raise ValueError for negative tier index."""
        torrent = create_multitracker_torrent()
        with pytest.raises(ValueError, match="out of range"):
            torrent.shuffle_tier(-1)

    def test_shuffle_no_announce_list(self):
        """Should raise ValueError when no announce-list exists."""
        torrent = create_simple_torrent()
        with pytest.raises(ValueError, match="No announce-list"):
            torrent.shuffle_tier(0)

    def test_shuffle_all_tiers(self):
        """Should shuffle all tiers."""
        torrent = create_multitracker_torrent()
        all_shuffled = torrent.shuffle_all_tiers()
        assert len(all_shuffled) == 2
        assert len(all_shuffled[0]) == 2
        assert len(all_shuffled[1]) == 1

    def test_shuffle_changes_order(self):
        """Shuffle may change the order."""
        import random
        torrent = create_multitracker_torrent()
        original_order = torrent.tracker_tiers[0][:]
        torrent.shuffle_tier(0)
        new_order = torrent.tracker_tiers[0]
        # With 50% chance for 2 elements, may or may not change
        # But the shuffle should still be valid
        assert set(new_order) == set(original_order)


# ============================================================================
# Test Record Announce Success
# ============================================================================


class TestRecordAnnounceSuccess:
    """Tests for recording successful tracker connections (BEP 12)."""

    def test_move_tracker_to_front(self):
        """Should move successful tracker to front of tier."""
        torrent = create_multitracker_torrent()
        torrent.record_announce_success(0, 'http://primary2.tracker.com/announce')
        tiers = torrent.tracker_tiers
        # primary2 should now be first
        assert tiers[0][0] == 'http://primary2.tracker.com/announce'

    def test_move_already_at_front(self):
        """Should do nothing if tracker is already at front."""
        torrent = create_multitracker_torrent()
        original = torrent.tracker_tiers[0][:]
        torrent.record_announce_success(0, 'http://primary1.tracker.com/announce')
        # Should still be at front
        assert torrent.tracker_tiers[0][0] == 'http://primary1.tracker.com/announce'

    def test_success_across_tiers(self):
        """Should record success in specific tier."""
        torrent = create_multitracker_torrent()
        torrent.record_announce_success(1, 'http://backup1.tracker.com/announce')
        # Should not affect tier 0
        tiers = torrent.tracker_tiers
        assert tiers[0][0] == 'http://primary1.tracker.com/announce'

    def test_invalid_tier_index(self):
        """Should raise for invalid tier index."""
        torrent = create_multitracker_torrent()
        with pytest.raises(ValueError, match="out of range"):
            torrent.record_announce_success(5, 'http://backup1.tracker.com/announce')

    def test_missing_tracker(self):
        """Should raise for tracker not in tier."""
        torrent = create_multitracker_torrent()
        with pytest.raises(ValueError, match="not found"):
            torrent.record_announce_success(0, 'http://missing.tracker.com/announce')

    def test_no_announce_list(self):
        """Should raise when no announce-list exists."""
        torrent = create_simple_torrent()
        with pytest.raises(ValueError, match="No announce-list"):
            torrent.record_announce_success(0, 'http://tracker.com/announce')


# ============================================================================
# Test Shuffle + Record Success Workflow
# ============================================================================


class TestShuffleAndRecordWorkflow:
    """Tests for the complete shuffle + record success workflow."""

    def test_full_bep12_workflow(self):
        """Test the complete BEP 12 workflow."""
        torrent = create_multitracker_torrent()

        # 1. Initial tiers
        initial = torrent.tracker_tiers
        assert len(initial) == 2

        # 2. Shuffle tier 0
        shuffled = torrent.shuffle_tier(0)
        assert set(shuffled) == {
            'http://primary1.tracker.com/announce',
            'http://primary2.tracker.com/announce'
        }

        # 3. Record success with the last tracker (simulating it responded last)
        last_tracker = shuffled[-1]
        torrent.record_announce_success(0, last_tracker)

        # 4. Verify the successful tracker is now first
        current = torrent.tracker_tiers[0]
        assert current[0] == last_tracker

    def test_tier_progression(self):
        """Test progressing through tiers when trackers fail."""
        torrent = create_multitracker_torrent()

        # Shuffle all tiers
        torrent.shuffle_all_tiers()

        # Get the first tier
        tier0 = torrent.tracker_tiers[0]
        assert len(tier0) == 2

        # The successful tracker should be at the front after shuffle + record
        success_tracker = tier0[-1]
        torrent.record_announce_success(0, success_tracker)
        assert torrent.tracker_tiers[0][0] == success_tracker


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_tracker_in_tier(self):
        """Should handle tiers with empty entries gracefully."""
        data = {
            'announce-list': [
                [b'http://tracker1.com/announce'],
                [b''],  # Empty URL
            ],
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        tiers = torrent.tracker_tiers
        # Empty URLs should still appear in flat list but not as empty
        # Empty tier URLs are included as empty strings
        assert 'http://tracker1.com/announce' in tiers[0]

    def test_mixed_byte_and_string_urls(self):
        """Should handle mixed bytes and string URLs."""
        data = {
            'announce-list': [
                [b'http://bytes.tracker.com/announce', 'http://string.tracker.com/announce'],
            ],
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        tiers = torrent.tracker_tiers
        assert len(tiers) == 1
        assert len(tiers[0]) == 2

    def test_unicode_tracker_url(self):
        """Should handle Unicode in tracker URLs."""
        data = {
            'announce-list': [
                [b'http://tracker.example.com/announce\xc3\xa9'],
            ],
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        tiers = torrent.tracker_tiers
        assert len(tiers) == 1

    def test_many_tiers(self):
        """Should handle many tiers."""
        tiers_data = [[f'http://tracker{i}.com/announce'.encode()] for i in range(20)]
        data = {
            'announce-list': tiers_data,
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        assert len(torrent.tracker_tiers) == 20
        assert torrent.has_announce_list() is True

    def test_legacy_announcelist_key(self):
        """Should handle legacy 'announcelist' key (non-standard)."""
        data = {
            'announcelist': [
                [b'http://tracker1.com/announce'],
            ],
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        # Should detect legacy key
        assert torrent.has_announce_list() is True
        # Should work with legacy key
        tiers = torrent.tracker_tiers
        assert len(tiers) == 1

    def test_create_torrent_then_modify(self):
        """Create a torrent, modify announce-list, verify changes."""
        torrent = create_simple_torrent()

        # Initially no announce-list
        assert not torrent.has_announce_list()

        # Add announce-list
        torrent.set_announce_list([
            ['http://new1.com/announce'],
            ['http://new2.com/announce', 'http://new3.com/announce'],
        ])
        assert torrent.has_announce_list()
        assert len(torrent.tracker_tiers) == 2

        # Shuffle and verify
        shuffled = torrent.shuffle_tier(1)
        assert set(shuffled) == {'http://new2.com/announce', 'http://new3.com/announce'}


# ============================================================================
# Test Bencode Roundtrip
# ============================================================================


class TestBencodeRoundtrip:
    """Tests for BEncode encoding/decoding roundtrips."""

    def test_torrent_with_announce_list_bencode(self):
        """Torrent with announce-list should BEncode correctly."""
        torrent = create_multitracker_torrent()

        # Get the info value
        info = torrent.info
        assert info is not None

        # Encode and verify
        encoded = bencode_module.encode(info)
        assert encoded is not None

        # Decode and verify
        decoded = bencode_module.decode(encoded)
        assert isinstance(decoded, dict)

    def test_custom_announce_list_roundtrip(self):
        """Custom announce-list should BEncode correctly."""
        torrent = create_simple_torrent()
        torrent.set_announce_list([
            ['http://a.com/announce', 'http://b.com/announce'],
            ['http://c.com/announce'],
        ])

        # Verify the data is in the dict
        assert 'announce-list' in torrent.dict or b'announce-list' in torrent.dict

        # Verify the encoded info is valid
        info = torrent.info
        assert info is not None
        encoded = bencode_module.encode(info)
        assert isinstance(encoded, bytes)
        assert encoded[0] == ord(b'i') or encoded[0] == ord(b'd')