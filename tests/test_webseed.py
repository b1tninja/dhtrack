"""Tests for BEP 19 WebSeed module."""

import hashlib
import unittest

from dhtrack.torrent import Torrent
from dhtrack.webseed import (
    DownloadState,
    HTTPDownloadThread,
    WebSeedError,
    WebSeedManager,
)


class TestDownloadState(unittest.TestCase):
    """Tests for the DownloadState class."""

    def test_initial_state(self):
        """Test initial DownloadState."""
        state = DownloadState(piece_index=0, start_offset=0, length=16384)
        self.assertEqual(state.piece_index, 0)
        self.assertEqual(state.start_offset, 0)
        self.assertEqual(state.length, 16384)
        self.assertIsNone(state.data)
        self.assertIsNone(state.sha1_hash)
        self.assertEqual(state.status, "pending")
        self.assertIsNone(state.error)

    def test_is_complete(self):
        """Test is_complete property."""
        state = DownloadState(piece_index=0, start_offset=0, length=16384)
        state.status = "pending"
        self.assertFalse(state.is_complete)
        state.status = "completed"
        self.assertTrue(state.is_complete)

    def test_is_failed(self):
        """Test is_failed property."""
        state = DownloadState(piece_index=0, start_offset=0, length=16384)
        state.status = "failed"
        self.assertTrue(state.is_failed)
        state.status = "completed"
        self.assertFalse(state.is_failed)

    def test_compute_sha1(self):
        """Test SHA-1 computation."""
        data = b"hello world"
        state = DownloadState(piece_index=0, start_offset=0, length=len(data))
        state.data = data
        computed = state.compute_sha1()
        expected = hashlib.sha1(data).digest()
        self.assertEqual(computed, expected)
        self.assertEqual(state.sha1_hash, expected)

    def test_compute_sha1_no_data(self):
        """Test SHA-1 computation with no data raises error."""
        state = DownloadState(piece_index=0, start_offset=0, length=100)
        with self.assertRaises(WebSeedError):
            state.compute_sha1()

    def test_repr(self):
        """Test string representation."""
        state = DownloadState(piece_index=5, start_offset=100, length=200)
        state.status = "completed"
        s = repr(state)
        self.assertIn("piece=5", s)
        self.assertIn("status=completed", s)


class TestHTTPDownloadThread(unittest.TestCase):
    """Tests for the HTTPDownloadThread class."""

    def test_initialization(self):
        """Test thread initialization."""
        thread = HTTPDownloadThread(
            url="http://example.com/file",
            start_offset=0,
            end_offset=1000,
            timeout=30,
        )
        self.assertEqual(thread.url, "http://example.com/file")
        self.assertEqual(thread.start_offset, 0)
        self.assertEqual(thread.end_offset, 1000)
        self.assertIsNone(thread.data)
        self.assertIsNone(thread.error)

    def test_daemon_thread(self):
        """Test that the thread is a daemon thread."""
        thread = HTTPDownloadThread(
            url="http://example.com/file",
            start_offset=0,
            end_offset=100,
        )
        self.assertTrue(thread.daemon)


class TestWebSeedManager(unittest.TestCase):
    """Tests for the WebSeedManager class."""

    def _create_torrent(self, webseed_urls=None):
        """Create a test torrent with optional webseed URLs."""
        # Use string keys for info dict (bencode requirement)
        info = {
            "name": b"test file",
            "piece length": 16384,
            "piece": b"\x00" * 20,
        }
        data = {
            "announce": b"http://tracker.example.com/announce",
            "info": info,
        }

        if webseed_urls:
            data["url-list"] = webseed_urls if isinstance(webseed_urls, list) else [webseed_urls]

        torrent = Torrent(data)
        return torrent

    def test_init(self):
        """Test WebSeedManager initialization."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        self.assertEqual(manager.torrent, torrent)
        self.assertEqual(manager.piece_length, 16384)
        self.assertEqual(manager.max_threads, 8)

    def test_no_webseed_urls_returns_none(self):
        """Test download with no webseed URLs."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        result = manager.download_piece(0, 0, 16384)
        # Should return None when no URLs available
        self.assertIsNone(result)

    def test_download_piece_invalid_url(self):
        """Test that invalid URLs are handled."""
        torrent = self._create_torrent(webseed_urls="http://invalid.example.com/file")
        manager = WebSeedManager(torrent)

        # Try to download from an invalid URL
        # Should fail but not crash
        manager.download_piece(0, 0, 100)

    def test_download_range_no_urls(self):
        """Test downloading a range with no URLs."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        results = manager.download_range(0, 5)
        self.assertEqual(len(results), 6)

    def test_valid_urls_tracking(self):
        """Test that valid URLs are tracked."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        self.assertEqual(len(manager.valid_urls), 0)
        self.assertEqual(len(manager.invalid_urls), 0)

    def test_clear_invalid_urls(self):
        """Test clearing invalid URLs."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        manager.invalid_urls.add("http://bad.url")
        self.assertEqual(len(manager.invalid_urls), 1)
        manager.clear_invalid_urls()
        self.assertEqual(len(manager.invalid_urls), 0)

    def test_get_success_rate_empty(self):
        """Test success rate with no data."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        rate = manager.get_success_rate()
        self.assertEqual(rate, 0.0)

    def test_get_success_rate(self):
        """Test success rate calculation."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        manager.valid_urls.add("http://good.url")
        manager.invalid_urls.add("http://bad.url")
        rate = manager.get_success_rate()
        self.assertEqual(rate, 50.0)

    def test_downloaded_piece_count(self):
        """Test downloaded piece count."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        self.assertEqual(manager.downloaded_piece_count, 0)

    def test_failed_piece_count(self):
        """Test failed piece count."""
        torrent = self._create_torrent()
        manager = WebSeedManager(torrent)
        self.assertEqual(manager.failed_piece_count, 0)


class TestTorrentWebseedUrls(unittest.TestCase):
    """Tests for Torrent webseed URL properties."""

    def test_no_webseed_urls(self):
        """Test torrent without webseed URLs."""
        info = {"name": b"test", "piece length": 16384, "piece": b"\x00" * 20}
        data = {"info": info}
        torrent = Torrent(data)
        urls = torrent.webseeding_urls
        self.assertEqual(urls, [])

    def test_single_webseed_url(self):
        """Test torrent with single webseed URL."""
        info = {"name": b"test", "piece length": 16384, "piece": b"\x00" * 20}
        data = {"info": info, "url-list": b"http://mirror.com/file"}
        torrent = Torrent(data)
        urls = torrent.webseeding_urls
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0], "http://mirror.com/file")

    def test_multiple_webseed_urls(self):
        """Test torrent with multiple webseed URLs."""
        info = {"name": b"test", "piece length": 16384, "piece": b"\x00" * 20}
        urls_bytes = [b"http://mirror1.com/file", b"http://mirror2.com/file"]
        data = {"info": info, "url-list": urls_bytes}
        torrent = Torrent(data)
        urls = torrent.webseeding_urls
        self.assertEqual(len(urls), 2)
        self.assertIn("http://mirror1.com/file", urls)
        self.assertIn("http://mirror2.com/file", urls)

    def test_get_webseeding_url_single_file(self):
        """Test URL construction for single-file torrent."""
        info = {"name": b"file.dat", "piece length": 16384, "piece": b"\x00" * 20}
        data = {"info": info, "url-list": b"http://mirror.com/files/"}
        torrent = Torrent(data)
        url = torrent.get_webseeding_url_for_file(0)
        self.assertIsNotNone(url)
        self.assertIn("file.dat", url)

    def test_get_webseeding_url_no_trailing_slash(self):
        """Test URL without trailing slash."""
        info = {"name": b"file.dat", "piece length": 16384, "piece": b"\x00" * 20}
        data = {"info": info, "url-list": b"http://mirror.com/file"}
        torrent = Torrent(data)
        url = torrent.get_webseeding_url_for_file(0)
        self.assertIsNotNone(url)
        self.assertEqual(url, "http://mirror.com/file")

    def test_set_webseeding_urls(self):
        """Test setting webseed URLs."""
        info = {"name": b"test", "piece length": 16384, "piece": b"\x00" * 20}
        data = {"info": info}
        torrent = Torrent(data)
        torrent.webseeding_urls = ["http://mirror1.com", "http://mirror2.com"]
        urls = torrent.webseeding_urls
        self.assertEqual(len(urls), 2)

    def test_get_webseeding_url_no_urls(self):
        """Test URL with no webseed URLs."""
        info = {"name": b"test", "piece length": 16384, "piece": b"\x00" * 20}
        data = {"info": info}
        torrent = Torrent(data)
        url = torrent.get_webseeding_url_for_file(0)
        self.assertIsNone(url)


class TestWebSeedManagerMultiURLFallback(unittest.TestCase):
    """Multi-URL fallback and discard behaviour (BEP 19)."""

    def _create_torrent(self, urls: list[str]) -> Torrent:
        piece_hash = hashlib.sha1(b"testdata" * 1024).digest()
        info = {
            "name": b"test.dat",
            "piece length": 16384,
            "piece": piece_hash,
            "length": 16384,
        }
        data = {
            "info": info,
            "url-list": [u.encode() for u in urls],
        }
        return Torrent(data)

    def test_falls_back_to_second_url_when_first_fails(self):
        """WebSeedManager.download_piece tries all URLs and succeeds on second."""
        from unittest.mock import patch

        from dhtrack.webseed import DownloadState, HTTPDownloadThread

        torrent = self._create_torrent(
            [
                "http://bad.example.com/file",
                "http://good.example.com/file",
            ]
        )
        manager = WebSeedManager(torrent)

        def fake_download(thread_self):
            if "bad" in thread_self.url:
                thread_self.data = None
                thread_self.error = "connection refused"
            else:
                thread_self.data = b"x" * 16384
                thread_self.error = None

        def fake_join(thread_self, timeout=None):
            pass

        # Bypass SHA-1 check so we can test the URL fallback logic in isolation
        with (
            patch.object(HTTPDownloadThread, "start", fake_download),
            patch.object(HTTPDownloadThread, "join", fake_join),
            patch.object(DownloadState, "compute_sha1", return_value=torrent.infohash),
        ):
            state = manager.download_piece(0, 0, 16384)

        self.assertIsNotNone(state)
        self.assertIsNotNone(state.data)
        self.assertEqual(len(state.data), 16384)

    def test_bad_url_added_to_invalid_set_on_all_failures(self):
        """All tried URLs are discarded when every download attempt fails."""
        from unittest.mock import patch

        from dhtrack.webseed import HTTPDownloadThread

        torrent = self._create_torrent(["http://down1.example.com/file"])
        manager = WebSeedManager(torrent)

        def fake_download(thread_self):
            thread_self.data = None
            thread_self.error = "timeout"

        def fake_join(thread_self, timeout=None):
            pass

        with (
            patch.object(HTTPDownloadThread, "start", fake_download),
            patch.object(HTTPDownloadThread, "join", fake_join),
        ):
            result = manager.download_piece(0, 0, 16384)

        # Should return a failed DownloadState (not None) and mark URL invalid
        self.assertIsNotNone(result)
        self.assertTrue(result.is_failed)
        self.assertTrue(len(manager.invalid_urls) > 0)

    def test_invalid_url_skipped_on_subsequent_call(self):
        """A discarded URL is not retried in subsequent download_piece calls."""
        torrent = self._create_torrent(["http://bad.example.com/file"])
        manager = WebSeedManager(torrent)
        manager.invalid_urls.add("http://bad.example.com/file")

        state = manager.download_piece(0, 0, 16384)
        self.assertIsNone(state)


if __name__ == "__main__":
    unittest.main()
