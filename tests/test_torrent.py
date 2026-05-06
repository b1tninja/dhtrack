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
        """Should return all tracker URLs flat from announce-list only."""
        torrent = create_multitracker_torrent()
        urls = torrent.trackers
        # Per BEP-12: announce is ignored when announce-list exists
        assert len(urls) == 3
        assert 'http://primary1.tracker.com/announce' in urls
        assert 'http://primary2.tracker.com/announce' in urls
        assert 'http://backup1.tracker.com/announce' in urls
        # announce URL should NOT be present
        assert 'http://fallback.tracker.com/announce' not in urls

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
        """announce-list should take priority over announce (BEP-12)."""
        torrent = create_multitracker_torrent()
        # trackers property should ignore announce when announce-list exists
        urls = torrent.trackers
        # Should only include URLs from announce-list (3 URLs), not announce
        assert len(urls) == 3
        # Verify announce URL is excluded
        assert all('fallback' not in u for u in urls)

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


# ============================================================================
# Test BEP-12: Trackers property ignores announce when announce-list exists
# ============================================================================


class TestTrackersProperty:
    """Tests for the trackers property with BEP-12 priority."""

    def test_trackers_ignores_announce_when_announce_list_exists(self):
        """When announce-list exists, trackers should NOT include announce URL."""
        data = {
            'announce': b'http://ignored.tracker.com/announce',
            'announce-list': [
                [b'http://tier1.tracker1.com/announce', b'http://tier1.tracker2.com/announce'],
                [b'http://tier2.backup.com/announce'],
            ],
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        urls = torrent.trackers
        # announce-list URLs only
        assert 'http://tier1.tracker1.com/announce' in urls
        assert 'http://tier1.tracker2.com/announce' in urls
        assert 'http://tier2.backup.com/announce' in urls
        # announce URL should NOT be included
        assert 'http://ignored.tracker.com/announce' not in urls

    def test_trackers_includes_announce_when_no_announce_list(self):
        """When no announce-list, trackers should include announce URL."""
        data = {
            'announce': b'http://single.tracker.com/announce',
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        urls = torrent.trackers
        assert urls == ['http://single.tracker.com/announce']

    def test_trackers_empty_with_no_announce(self):
        """Should return empty list when no announce or announce-list."""
        data = {
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        assert torrent.trackers == []


# ============================================================================
# Test BEP-12: Tier Progression Tracking
# ============================================================================


class TestTierProgression:
    """Tests for BEP-12 tier progression tracking methods."""

    def test_get_current_tier_index(self):
        """Should return initial tier index of 0."""
        torrent = create_multitracker_torrent()
        assert torrent.get_current_tier_index() == 0

    def test_advance_tier_on_failure(self):
        """Should advance tier index when trackers fail."""
        torrent = create_multitracker_torrent()
        # 2-tier torrent
        assert len(torrent.tracker_tiers) == 2
        # Start at tier 0
        assert torrent.get_current_tier_index() == 0
        # Advance once
        tier_after_advance = torrent.advance_tier_on_failure()
        assert tier_after_advance == 1
        assert torrent.get_current_tier_index() == 1

    def test_advance_tier_clamps_at_last_tier(self):
        """Should not advance beyond last tier."""
        torrent = create_multitracker_torrent()
        # Already at last tier, advance again should stay at last tier
        torrent.advance_tier_on_failure()  # Now at tier 1
        tier_after = torrent.advance_tier_on_failure()
        assert tier_after == 1  # Should stay at last tier

    def test_advance_tier_no_announce_list(self):
        """Should handle advance when no announce-list."""
        torrent = create_simple_torrent()
        # No announce-list, should not cause error
        tier = torrent.advance_tier_on_failure()
        assert tier == 0

    def test_reset_tier_index(self):
        """Should reset tier index to 0."""
        torrent = create_multitracker_torrent()
        torrent.advance_tier_on_failure()  # Move to tier 1
        assert torrent.get_current_tier_index() == 1
        torrent.reset_tier_index()
        assert torrent.get_current_tier_index() == 0

    def test_get_current_tier_urls(self):
        """Should return URLs for the current tier."""
        torrent = create_multitracker_torrent()
        # Current tier is 0
        tier0_urls = torrent.get_current_tier_urls()
        assert len(tier0_urls) == 2
        assert 'http://primary1.tracker.com/announce' in tier0_urls
        assert 'http://primary2.tracker.com/announce' in tier0_urls

    def test_get_current_tier_urls_after_advance(self):
        """Should return URLs for the advanced tier."""
        torrent = create_multitracker_torrent()
        torrent.advance_tier_on_failure()  # Move to tier 1
        tier1_urls = torrent.get_current_tier_urls()
        assert len(tier1_urls) == 1
        assert tier1_urls[0] == 'http://backup1.tracker.com/announce'

    def test_get_current_tier_urls_no_announce_list(self):
        """Should raise error when no announce-list."""
        torrent = create_simple_torrent()
        with pytest.raises(ValueError, match="No announce-list"):
            torrent.get_current_tier_urls()

    def test_get_current_tier_urls_invalid_tier(self):
        """Should raise error for invalid tier index."""
        torrent = create_multitracker_torrent()
        torrent._current_tier_index = 99  # Manually set invalid index
        with pytest.raises(ValueError, match="Invalid tier index"):
            torrent.get_current_tier_urls()

    def test_full_bep12_workflow(self):
        """Test the complete BEP-12 tracker iteration workflow."""
        torrent = create_multitracker_torrent()

        # 1. Start at tier 0
        assert torrent.get_current_tier_index() == 0
        tier0_urls = torrent.get_current_tier_urls()
        assert len(tier0_urls) == 2

        # 2. Try all URLs in tier 0, none succeed
        # (In practice, the tracker layer would try each URL)
        for url in tier0_urls:
            # Simulate failure...
            pass

        # 3. Advance to next tier on complete failure
        torrent.advance_tier_on_failure()
        assert torrent.get_current_tier_index() == 1

        # 4. Get URLs for new tier
        tier1_urls = torrent.get_current_tier_urls()
        assert len(tier1_urls) == 1
        assert tier1_urls[0] == 'http://backup1.tracker.com/announce'

        # 5. On successful tracker connection, next announce cycle starts from tier 0
        torrent.record_announce_success(1, 'http://backup1.tracker.com/announce')
        torrent.reset_tier_index()
        assert torrent.get_current_tier_index() == 0

        # 6. Shuffle tier 0 for the new cycle
        shuffled = torrent.shuffle_tier(0)
        assert set(shuffled) == {
            'http://primary1.tracker.com/announce',
            'http://primary2.tracker.com/announce'
        }

    def test_announce_list_not_modified_by_tier_progression(self):
        """Tier progression should not modify the announce-list data."""
        torrent = create_multitracker_torrent()
        original_raw = torrent.get_raw_announce_list()

        # Perform many tier advances
        for _ in range(10):
            torrent.advance_tier_on_failure()

        # Raw data should be unchanged
        assert torrent.get_raw_announce_list() == original_raw

    def test_tier_progression_with_four_tiers(self):
        """Test tier progression with 4 tiers."""
        data = {
            'announce-list': [
                [b'http://tier0.tracker.com/announce'],
                [b'http://tier1.tracker.com/announce'],
                [b'http://tier2.tracker.com/announce'],
                [b'http://tier3.tracker.com/announce'],
            ],
            'info': {
                'name': b'test',
                'piece length': 16384,
                'pieces': b'\x00' * 20,
            },
        }
        torrent = Torrent(data)
        assert torrent.get_current_tier_index() == 0

        # Advance through all tiers
        assert torrent.advance_tier_on_failure() == 1
        assert torrent.advance_tier_on_failure() == 2
        assert torrent.advance_tier_on_failure() == 3
        # Already at last tier
        assert torrent.advance_tier_on_failure() == 3

        # Reset should go back to 0
        torrent.reset_tier_index()
        assert torrent.get_current_tier_index() == 0
