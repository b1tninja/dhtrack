"""
Tests for BEP 48 Tracker Scrape Extension.

Tests the TrackerClient, ScrapeResponse, and ScrapeInfo classes,
as well as the URL construction and bencode encoding/decoding utilities.
"""

from __future__ import annotations

import pytest
from dhtrack.tracker import (
    ScrapeInfo,
    ScrapeResponse,
    TrackerClient,
    TrackerError,
    ScrapeError,
    TrackerClientError,
    _build_scrape_url,
    _encode_scrape_request,
    _decode_scrape_response,
    _parse_swarm_info,
    _get_int_field,
)


# --- _build_scrape_url tests ---


class TestBuildScrapeUrl:
    """Tests for URL derivation (BEP 48)."""

    def test_basic_announce_url(self):
        """Replace 'announce' in a simple path."""
        result = _build_scrape_url("http://tracker.example.com/announce")
        assert result == "http://tracker.example.com/scrape"

    def test_announce_with_trailing_path(self):
        """Replace 'announce' when followed by additional path segments."""
        result = _build_scrape_url("http://tracker.example.com/announce/path")
        assert result == "http://tracker.example.com/scrape/path"

    def test_announce_in_query_params(self):
        """Should still replace 'announce' in the path."""
        result = _build_scrape_url("http://tracker.example.com/path/announce?key=value")
        assert "scrape" in result
        assert "?key=value" in result

    def test_no_announce_in_path(self):
        """Raise error when 'announce' is not in path."""
        with pytest.raises(TrackerClientError):
            _build_scrape_url("http://tracker.example.com/tracker")

    def test_announce_in_hostname(self):
        """Should not replace 'announce' in hostname, only path."""
        # hostname contains 'announce' but path doesn't - should raise error
        with pytest.raises(TrackerClientError):
            _build_scrape_url("http://announce.example.com/path")

    def test_double_announce(self):
        """Only first 'announce' occurrence should be replaced."""
        result = _build_scrape_url("http://tracker.example.com/announce/announce-test")
        assert result == "http://tracker.example.com/scrape/announce-test"

    def test_port_preserved(self):
        """Port number should be preserved."""
        result = _build_scrape_url("http://tracker.example.com:6969/announce")
        assert result == "http://tracker.example.com:6969/scrape"

    def test_https_preserved(self):
        """Protocol should be preserved."""
        result = _build_scrape_url("https://tracker.example.com/announce")
        assert result.startswith("https://")


# --- _encode_scrape_request tests ---


class TestEncodeScrapeRequest:
    """Tests for request URL encoding."""

    def test_single_infohash(self):
        """Encode a single infohash."""
        info_hash = b"\x00" * 20
        result = _encode_scrape_request([info_hash])
        assert "info_hash" in result

    def test_multiple_infohashes(self):
        """Encode multiple infohashes."""
        hashes = [b"\x01" * 20, b"\x02" * 20, b"\x03" * 20]
        result = _encode_scrape_request(hashes)
        # Should contain multiple info_hash parameters
        assert result.count("info_hash") == 3

    def test_invalid_hash_length(self):
        """Raise error for non-20-byte infohash."""
        with pytest.raises(TrackerClientError):
            _encode_scrape_request([b"short"])

    def test_empty_infohashes(self):
        """Empty list should produce empty query."""
        result = _encode_scrape_request([])
        assert result == ""

    def test_infohash_bytes_encoded(self):
        """Infohash bytes should be properly URL-encoded."""
        # Infohash with non-ASCII bytes
        info_hash = bytes([0xAA, 0xBB, 0xCC] + [0] * 17)
        result = _encode_scrape_request([info_hash])
        assert "info_hash" in result


# --- _decode_scrape_response tests ---


class TestDecodeScrapeResponse:
    """Tests for response decoding."""

    def test_successful_response_single(self):
        """Decode a response with one torrent."""
        # Proper bencoding: d...e for outer dict
        response_bytes = (
            b"d"                              # outer dict start
            b"5:files"                        # key "files"
            b"d"                              # files dict start
            b"20:" + b"\x00" * 20 +           # 20-byte hash key
            b"d"                              # swarm info dict start
            b"8:completei" + b"42" + b"e"     # "complete": 42
            b"10:downloadedi" + b"1234" + b"e"  # "downloaded": 1234
            b"10:incompletei" + b"56" + b"e"   # "incomplete": 56
            b"e"                              # end swarm info
            b"e"                              # end files dict
            b"e"                              # end outer dict
        )
        result = _decode_scrape_response(response_bytes)
        assert not result.is_error
        assert len(result.files) == 1
        info = result.files[b"\x00" * 20]
        assert info.complete == 42
        assert info.downloaded == 1234
        assert info.incomplete == 56

    def test_successful_response_multiple(self):
        """Decode a response with multiple torrents."""
        hash1 = b"\x01" * 20
        hash2 = b"\x02" * 20
        response_bytes = (
            b"d"                               # outer dict start
            b"5:files"                         # key "files"
            b"d"                               # files dict start
            # First torrent
            b"20:" + hash1 +
            b"d"
            b"8:completei" + b"10" + b"e"
            b"10:downloadedi" + b"100" + b"e"
            b"10:incompletei" + b"5" + b"e"
            b"e"
            # Second torrent
            b"20:" + hash2 +
            b"d"
            b"8:completei" + b"20" + b"e"
            b"10:downloadedi" + b"200" + b"e"
            b"10:incompletei" + b"10" + b"e"
            b"e"
            b"e"  # end files dict
            b"e"  # end outer dict
        )
        result = _decode_scrape_response(response_bytes)
        assert not result.is_error
        assert len(result.files) == 2

        info1 = result.files[hash1]
        assert info1.complete == 10
        assert info1.downloaded == 100
        assert info1.incomplete == 5

        info2 = result.files[hash2]
        assert info2.complete == 20
        assert info2.downloaded == 200
        assert info2.incomplete == 10

    def test_error_response(self):
        """Decode an error response."""
        # "failure reason" is 14 chars, "tracker full" is 12 chars
        response_bytes = b"d14:failure reason12:tracker fulle"
        result = _decode_scrape_response(response_bytes)
        assert result.is_error
        assert result.failure_reason == "tracker full"

    def test_error_response_various_messages(self):
        """Decode error responses with various messages."""
        # "not found" is 9 chars
        response_bytes = b"d14:failure reason9:not founde"
        result = _decode_scrape_response(response_bytes)
        assert result.is_error
        assert "not found" in result.failure_reason

    def test_missing_files_key(self):
        """Raise error when 'files' key is missing."""
        response_bytes = b"e"  # empty dict
        with pytest.raises(ScrapeError):
            _decode_scrape_response(response_bytes)

    def test_invalid_bencoding(self):
        """Raise error for malformed bencoding."""
        with pytest.raises(ScrapeError):
            _decode_scrape_response(b"not bencoded data")

    def test_zero_values(self):
        """Decode response with zero values."""
        response_bytes = (
            b"d"                              # outer dict start
            b"5:files"                        # key "files"
            b"d"                              # files dict start
            b"20:" + b"\xff" * 20 +           # 20-byte hash key
            b"d"                              # swarm info dict start
            b"8:completei" + b"0" + b"e"      # "complete": 0
            b"10:downloadedi" + b"0" + b"e"   # "downloaded": 0
            b"10:incompletei" + b"0" + b"e"   # "incomplete": 0
            b"e"                              # end swarm info
            b"e"                              # end files dict
            b"e"                              # end outer dict
        )
        result = _decode_scrape_response(response_bytes)
        assert not result.is_error
        info = result.files[b"\xff" * 20]
        assert info.complete == 0
        assert info.incomplete == 0
        assert info.downloaded == 0

    def test_missing_fields_defaults(self):
        """Missing fields should default to 0."""
        response_bytes = (
            b"d"                              # outer dict start
            b"5:files"                        # key "files"
            b"d"                              # files dict start
            b"20:" + b"\x00" * 20 +           # 20-byte hash key
            b"d"                              # swarm info dict start
            b"8:completei" + b"10" + b"e"     # "complete": 10
            b"e"                              # end swarm info
            b"e"                              # end files dict
            b"e"                              # end outer dict
        )
        result = _decode_scrape_response(response_bytes)
        info = result.files[b"\x00" * 20]
        assert info.complete == 10
        assert info.incomplete == 0
        assert info.downloaded == 0


# --- _parse_swarm_info tests ---


class TestParseSwarmInfo:
    """Tests for swarm info parsing."""

    def test_valid_swarm_info(self):
        """Parse valid swarm info."""
        swarm_info = {
            "complete": 100,
            "incomplete": 50,
            "downloaded": 1000,
        }
        result = _parse_swarm_info(swarm_info)
        assert result is not None
        assert result.complete == 100
        assert result.incomplete == 50
        assert result.downloaded == 1000

    def test_missing_fields(self):
        """Missing fields should default to 0."""
        swarm_info = {"complete": 10}
        result = _parse_swarm_info(swarm_info)
        assert result is not None
        assert result.complete == 10
        assert result.incomplete == 0
        assert result.downloaded == 0

    def test_invalid_type(self):
        """Invalid type should return None."""
        assert _parse_swarm_info("not a dict") is None
        assert _parse_swarm_info([1, 2, 3]) is None

    def test_negative_values(self):
        """Negative values should raise ValueError."""
        swarm_info = {"complete": -1, "incomplete": 0, "downloaded": 0}
        result = _parse_swarm_info(swarm_info)
        assert result is None


# --- _get_int_field tests ---


class TestGetIntField:
    """Tests for integer field extraction."""

    def test_existing_int(self):
        """Get existing integer value."""
        data = {"key": 42}
        assert _get_int_field(data, "key") == 42

    def test_missing_key(self):
        """Missing key should return 0."""
        data = {"other": 42}
        assert _get_int_field(data, "key") == 0

    def test_negative_value(self):
        """Negative value should raise ValueError."""
        data = {"key": -5}
        with pytest.raises(ValueError):
            _get_int_field(data, "key")

    def test_non_int_value(self):
        """Non-integer value should raise ValueError."""
        data = {"key": "not an int"}
        with pytest.raises(ValueError):
            _get_int_field(data, "key")

    def test_zero_value(self):
        """Zero should be valid."""
        data = {"key": 0}
        assert _get_int_field(data, "key") == 0


# --- ScrapeInfo tests ---


class TestScrapeInfo:
    """Tests for the ScrapeInfo dataclass."""

    def test_defaults(self):
        """Default values should be 0."""
        info = ScrapeInfo()
        assert info.complete == 0
        assert info.incomplete == 0
        assert info.downloaded == 0

    def test_custom_values(self):
        """Custom values should be set correctly."""
        info = ScrapeInfo(complete=10, incomplete=20, downloaded=30)
        assert info.complete == 10
        assert info.incomplete == 20
        assert info.downloaded == 30


# --- ScrapeResponse tests ---


class TestScrapeResponse:
    """Tests for the ScrapeResponse dataclass."""

    def test_defaults(self):
        """Default values should be empty/error."""
        response = ScrapeResponse()
        assert response.files == {}
        assert response.failure_reason is None
        assert not response.is_error

    def test_error_response(self):
        """Setting failure_reason should indicate error."""
        response = ScrapeResponse(failure_reason="tracker full")
        assert response.is_error
        assert response.failure_reason == "tracker full"

    def test_success_after_error(self):
        """Clearing failure_reason should indicate success."""
        response = ScrapeResponse(failure_reason="error")
        response.failure_reason = None
        assert not response.is_error


# --- TrackerClient tests ---


class TestTrackerClientScrapeUrl:
    """Tests for the static scrape_url method."""

    def test_basic_url_construction(self):
        """Build a valid scrape URL."""
        info_hash = b"\x01" * 20
        url = TrackerClient.scrape_url("http://tracker.example.com/announce", [info_hash])
        assert "scrape" in url
        assert "info_hash" in url

    def test_multiple_infohashes(self):
        """Build URL with multiple infohashes."""
        hashes = [b"\x01" * 20, b"\x02" * 20]
        url = TrackerClient.scrape_url("http://tracker.example.com/announce", hashes)
        # URL should contain both infohashes
        assert "info_hash=" in url


class TestTrackerClientInit:
    """Tests for TrackerClient initialization."""

    def test_default_init(self):
        """Default initialization."""
        client = TrackerClient()
        assert client.timeout == 10
        assert client.user_agent == "dhtrack"
        assert client.max_retries == 2
        assert client.retry_delay == 1.0

    def test_custom_timeout(self):
        """Custom timeout value."""
        client = TrackerClient(timeout=30)
        assert client.timeout == 30

    def test_custom_user_agent(self):
        """Custom user agent."""
        client = TrackerClient(user_agent="MyClient/1.0")
        assert client.user_agent == "MyClient/1.0"

    def test_custom_retries(self):
        """Custom retry count."""
        client = TrackerClient(max_retries=5)
        assert client.max_retries == 5


class TestTrackerClientScrape:
    """Tests for the scrape method."""

    def test_empty_infohashes(self):
        """Empty list should raise error."""
        client = TrackerClient()
        with pytest.raises(TrackerClientError):
            client.scrape([], "http://tracker.example.com/announce")

    def test_invalid_announce_url(self):
        """URL without 'announce' should raise error."""
        client = TrackerClient()
        with pytest.raises(TrackerClientError):
            client.scrape([b"\x01" * 20], "http://tracker.example.com/tracker")

    def test_invalid_infohash_length(self):
        """Wrong length infohash should raise error."""
        client = TrackerClient()
        with pytest.raises(TrackerClientError):
            client.scrape([b"short"], "http://tracker.example.com/announce")


class TestTrackerClientScrapeSingle:
    """Tests for the scrape_single method."""

    def test_signature(self):
        """Method should accept single infohash and URL."""
        client = TrackerClient()
        # Just verify the signature - won't actually connect
        assert hasattr(client, "scrape_single")
        import inspect
        sig = inspect.signature(client.scrape_single)
        params = list(sig.parameters.keys())
        assert "info_hash" in params
        assert "announce_url" in params