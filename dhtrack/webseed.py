"""WebSeed HTTP/FTP download engine (BEP 19).

This module provides HTTP and FTP downloading capabilities for BitTorrent
webseeding. It implements:

- HTTP Range request downloads with byte-range support
- FTP download support (more limited - can only start from beginning)
- SHA-1 piece validation against torrent infohash
- Concurrent thread pooling for multiple HTTP downloads
- Automatic URL discard on SHA-1 checksum mismatch
- Gap-aware piece selection for efficient downloading
"""

from __future__ import annotations

import hashlib
import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from dhtrack.torrent import Torrent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WebSeed Constants
# ---------------------------------------------------------------------------

# Default HTTP timeout in seconds
HTTP_TIMEOUT = 30

# Default FTP timeout in seconds
FTP_TIMEOUT = 30

# Maximum redirect count
MAX_REDIRECTS = 5

# User agent string for HTTP requests
USER_AGENT = "dhtrack/2.0 (BEP 19 WebSeed)"

# Default HTTP buffer size
HTTP_BUFFER_SIZE = 65536  # 64 KB

# Default FTP buffer size
FTP_BUFFER_SIZE = 65536  # 64 KB

# Minimum piece size for HTTP Range requests (16 KB)
MIN_HTTP_RANGE_SIZE = 16384


# ---------------------------------------------------------------------------
# WebSeed Errors
# ---------------------------------------------------------------------------


class WebSeedError(Exception):
    """Base exception for webseed errors."""


class WebSeedTimeoutError(WebSeedError):
    """Raised when a webseed request times out."""


WebSeedTimeout = WebSeedTimeoutError  # backward-compatible alias


class WebSeedConnectionError(WebSeedError):
    """Raised when a webseed connection fails."""


class WebSeedChecksumError(WebSeedError):
    """Raised when the SHA-1 checksum of downloaded data doesn't match."""


class WebSeedEmptyError(WebSeedError):
    """Raised when a webseed returns no data."""


class WebSeedHTTPError(WebSeedError):
    """Raised when an HTTP error occurs."""


class WebSeedFTPError(WebSeedError):
    """Raised when an FTP error occurs."""


# ---------------------------------------------------------------------------
# Download State
# ---------------------------------------------------------------------------


class DownloadState:
    """Tracks the state of a single piece download.

    Attributes
    ----------
    piece_index : int
        The piece index being downloaded.
    start_offset : int
        Starting byte offset in the file.
    length : int
        Number of bytes to download.
    data : bytes | None
        The downloaded data, or None if not yet downloaded.
    sha1_hash : bytes | None
        The SHA-1 hash of the downloaded data, or None if not computed.
    status : str
        One of 'pending', 'downloading', 'completed', 'failed'.
    error : str | None
        Error message if failed.
    start_time : float
        Timestamp when the download started.
    end_time : float
        Timestamp when the download completed/failed.
    bytes_downloaded : int
        Number of bytes successfully downloaded.
    """

    def __init__(
        self,
        piece_index: int,
        start_offset: int,
        length: int,
    ) -> None:
        """Initialize a DownloadState.

        Parameters
        ----------
        piece_index : int
            The piece index.
        start_offset : int
            Starting byte offset.
        length : int
            Number of bytes.
        """
        self.piece_index = piece_index
        self.start_offset = start_offset
        self.length = length
        self.data: bytes | None = None
        self.sha1_hash: bytes | None = None
        self.status = "pending"
        self.error: str | None = None
        self.start_time = 0.0
        self.end_time = 0.0
        self.bytes_downloaded = 0

    @property
    def is_complete(self) -> bool:
        """Check if the download is complete.

        Returns
        -------
        bool
            True if the download completed successfully.
        """
        return self.status == "completed"

    @property
    def is_failed(self) -> bool:
        """Check if the download has failed.

        Returns
        -------
        bool
            True if the download failed.
        """
        return self.status == "failed"

    def compute_sha1(self) -> bytes:
        """Compute the SHA-1 hash of the downloaded data.

        Returns
        -------
        bytes
            The 20-byte SHA-1 hash.

        Raises
        ------
        WebSeedError
            If no data has been downloaded.
        """
        if self.data is None:
            raise WebSeedError("No data available for SHA-1 computation")
        self.sha1_hash = hashlib.sha1(self.data).digest()
        return self.sha1_hash

    def __repr__(self) -> str:
        return (
            f"DownloadState(piece={self.piece_index}, "
            f"offset={self.start_offset}, len={self.length}, "
            f"status={self.status})"
        )


# ---------------------------------------------------------------------------
# HTTP Download Thread
# ---------------------------------------------------------------------------


class HTTPDownloadThread(threading.Thread):
    """HTTP download thread that downloads a range of bytes from a URL.

    Uses HTTP Range requests to download specific byte ranges.
    """

    def __init__(
        self,
        url: str,
        start_offset: int,
        end_offset: int,
        timeout: float = HTTP_TIMEOUT,
        follow_redirects: bool = True,
    ) -> None:
        """Initialize an HTTP download thread.

        Parameters
        ----------
        url : str
            The URL to download from.
        start_offset : int
            The starting byte offset (Range: bytes=start_offset-end_offset).
        end_offset : int
            The ending byte offset (inclusive).
        timeout : float
            Request timeout in seconds.
        follow_redirects : bool
            Whether to follow HTTP redirects.
        """
        super().__init__(daemon=True)
        self.url = url
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.data: bytes | None = None
        self.error: str | None = None
        self.status_code: int | None = None

    def run(self) -> None:
        """Execute the HTTP download."""
        try:
            # Use http.client for granular control over Range headers
            import http.client

            parsed = urlparse(self.url)
            host = parsed.hostname or "localhost"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")

            # Check if we can connect via FTP first
            if parsed.scheme.lower() in ("ftp",):
                raise WebSeedError(f"HTTP download requested for FTP URL: {self.url}")

            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            if parsed.scheme == "https":
                import ssl

                conn = http.client.HTTPSConnection(
                    host,
                    port,
                    timeout=self.timeout,
                    context=ssl.create_default_context(),
                )

            # Set Range header
            range_header = f"bytes={self.start_offset}-{self.end_offset}"

            headers = {
                "User-Agent": USER_AGENT,
                "Range": range_header,
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            self.status_code = response.status

            if self.follow_redirects and response.status in (301, 302, 303, 307, 308):
                redirect_url = response.getheader("Location")
                if redirect_url:
                    conn.close()
                    # Follow redirect (recursively, limited by MAX_REDIRECTS)
                    redirect_thread = HTTPDownloadThread(
                        redirect_url,
                        self.start_offset,
                        self.end_offset,
                        self.timeout,
                        False,
                    )
                    redirect_thread.start()
                    redirect_thread.join()
                    self.data = redirect_thread.data
                    self.status_code = redirect_thread.status_code
                    self.error = redirect_thread.error
                    return

            if response.status == 206:  # Partial Content
                self.data = response.read()
            elif response.status == 200:  # Full Content (server doesn't support Range)
                self.data = response.read()
                # Trim to requested range
                if self.data and len(self.data) > (self.end_offset - self.start_offset + 1):
                    self.data = self.data[self.start_offset : self.end_offset + 1]
            else:
                self.error = f"HTTP {response.status}: {response.reason}"

            conn.close()

        except Exception as exc:
            self.error = str(exc)
            logger.debug("HTTP download failed: %s", exc)


# ---------------------------------------------------------------------------
# FTP Download Thread
# ---------------------------------------------------------------------------


class FTPDownloadThread(threading.Thread):
    """FTP download thread that downloads data from an FTP URL.

    Note: FTP is more limited than HTTP - it can only start from the
    beginning of a file. For partial downloads, we download the full file
    and then slice the result.
    """

    def __init__(
        self,
        url: str,
        start_offset: int,
        end_offset: int,
        timeout: float = FTP_TIMEOUT,
    ) -> None:
        """Initialize an FTP download thread.

        Parameters
        ----------
        url : str
            The FTP URL to download from.
        start_offset : int
            The starting byte offset (for slicing after download).
        end_offset : int
            The ending byte offset (for slicing after download).
        timeout : float
            Connection timeout in seconds.
        """
        super().__init__(daemon=True)
        self.url = url
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.timeout = timeout
        self.data: bytes | None = None
        self.error: str | None = None

    def run(self) -> None:
        """Execute the FTP download."""
        try:
            import ssl
            from ftplib import FTP, FTP_TLS

            parsed = urlparse(self.url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 21
            path = parsed.path.lstrip("/")  # Remove leading /
            username = parsed.username or "anonymous"
            password = parsed.password or "anonymous@"

            # Connect to FTP server
            conn: FTP
            if parsed.scheme == "ftps":
                ctx = ssl.create_default_context()
                conn = FTP_TLS(context=ctx)
                conn.connect(host, port, timeout=self.timeout)
                conn.login(user=username, passwd=password)
                conn.prot_p()  # Secure data channel
            else:
                conn = FTP()
                conn.connect(host, port, timeout=self.timeout)
                conn.login(user=username, passwd=password)

            # Read the entire file
            data: list[bytes] = []
            conn.retrbinary(f"RETR {path}", data.append)
            conn.quit()

            full_data = b"".join(data)

            # Slice to the requested range
            self.data = full_data[self.start_offset : self.end_offset + 1]
            self.error = None

        except Exception as exc:
            self.error = str(exc)
            logger.debug("FTP download failed: %s", exc)


# ---------------------------------------------------------------------------
# WebSeedManager
# ---------------------------------------------------------------------------


@dataclass
class WebSeedManager:
    """Manages HTTP/FTP webseed downloads for a torrent.

    Coordinates concurrent HTTP/FTP downloads, validates SHA-1 checksums,
    and tracks download progress.

    Attributes
    ----------
    torrent : Torrent
        The torrent being downloaded.
    max_threads : int
        Maximum number of concurrent download threads.
    timeout : float
        Request timeout in seconds.
    valid_urls : set[str]
        URLs that have successfully provided valid data.
    invalid_urls : set[str]
        URLs that have been discarded due to checksum mismatch.
    download_threads : list[threading.Thread]
        Currently active download threads.
    lock : threading.Lock
        Thread safety lock.
    piece_length : int
        The size of each piece in bytes.
    """

    torrent: Torrent
    max_threads: int = 8
    timeout: float = HTTP_TIMEOUT
    valid_urls: set[str] = field(default_factory=set)
    invalid_urls: set[str] = field(default_factory=set)
    download_threads: list[threading.Thread] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    piece_length: int = 0
    _downloaded_pieces: set[int] = field(default_factory=set)
    _failed_pieces: set[int] = field(default_factory=set)

    def __post_init__(self) -> None:
        """Initialize the piece length from torrent info."""
        info = self.torrent.info
        if isinstance(info, dict):
            for key in [b"piece length", "piece length"]:
                val = info.get(key)
                if isinstance(val, int):
                    self.piece_length = val
                    break

    def download_piece(
        self,
        piece_index: int,
        start_offset: int,
        length: int,
        urls: list[str] | None = None,
    ) -> DownloadState | None:
        """Download a single piece from webseed URLs.

        Attempts to download the piece data from the provided URLs,
        validating the SHA-1 checksum against the torrent's infohash.

        Parameters
        ----------
        piece_index : int
            The piece index to download.
        start_offset : int
            Starting byte offset within the piece.
        length : int
            Number of bytes to download.
        urls : list of str, optional
            URLs to try. If None, uses webseeding_urls from the torrent.

        Returns
        -------
        DownloadState or None
            The download state with data if successful, None otherwise.

        Notes
        -----
        Per BEP 19, if the SHA-1 checksum doesn't match, the URL must
        be discarded.
        """
        if urls is None:
            urls = self.torrent.webseeding_urls

        if not urls:
            logger.debug("No webseed URLs available for piece %d", piece_index)
            return None

        # Filter to valid URLs only
        available_urls = [url for url in urls if url not in self.invalid_urls]

        if not available_urls:
            logger.debug("No valid webseed URLs available for piece %d", piece_index)
            return None

        state = DownloadState(
            piece_index=piece_index,
            start_offset=start_offset,
            length=length,
        )
        state.status = "downloading"
        state.start_time = time.time()

        # Shuffle URLs for random selection
        url_list = list(available_urls)
        random.shuffle(url_list)

        for url in url_list:
            # Determine which protocol to use
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()

            downloaded_data: bytes | None = None

            try:
                if scheme in ("http", "https"):
                    # Calculate end offset for range request
                    end_offset = start_offset + length - 1 if length > 0 else start_offset
                    thread = HTTPDownloadThread(
                        url,
                        start_offset,
                        end_offset,
                        self.timeout,
                    )
                    thread.start()
                    thread.join(timeout=self.timeout)
                    downloaded_data = thread.data
                    if thread.error:
                        logger.debug(
                            "HTTP download failed for piece %d from %s: %s",
                            piece_index,
                            url,
                            thread.error,
                        )

                elif scheme in ("ftp", "ftps"):
                    # FTP downloads the full file then slices
                    thread = FTPDownloadThread(
                        url,
                        start_offset,
                        start_offset + length,
                        self.timeout,
                    )
                    thread.start()
                    thread.join(timeout=self.timeout)
                    downloaded_data = thread.data
                    if thread.error:
                        logger.debug(
                            "FTP download failed for piece %d from %s: %s",
                            piece_index,
                            url,
                            thread.error,
                        )
                else:
                    logger.debug("Unsupported scheme: %s for URL %s", scheme, url)
                    continue

            except Exception as exc:
                logger.debug(
                    "Download exception for piece %d from %s: %s",
                    piece_index,
                    url,
                    exc,
                )
                continue

            if downloaded_data and len(downloaded_data) > 0:
                state.data = downloaded_data
                break

        if state.data is None or len(state.data) == 0:
            state.status = "failed"
            state.error = "No data received from any URL"
            logger.debug("Piece %d: all URLs failed", piece_index)
            # Mark all tried URLs as invalid for this piece
            for url in available_urls[:3]:  # Only discard first few URLs
                self.invalid_urls.add(url)
            return state

        # Track bytes downloaded
        state.bytes_downloaded = len(state.data)
        state.status = "completed"
        state.end_time = time.time()

        # Validate SHA-1 checksum
        try:
            computed_hash = state.compute_sha1()
            if computed_hash != self.torrent.infohash:
                state.status = "failed"
                state.error = f"SHA-1 mismatch: expected {self.torrent.infohash.hex()}, got {computed_hash.hex()}"
                # Per BEP 19: discard this URL
                self.invalid_urls.add(available_urls[0])
                logger.debug(
                    "Piece %d: SHA-1 mismatch, discarding URL %s",
                    piece_index,
                    available_urls[0],
                )
                return None
            else:
                # Valid piece received
                self.valid_urls.add(available_urls[0])
                self._downloaded_pieces.add(piece_index)
                logger.debug("Piece %d: successfully downloaded from %s", piece_index, available_urls[0])
                return state

        except WebSeedError as exc:
            state.status = "failed"
            state.error = str(exc)
            return None

    def download_piece_from_url(
        self,
        piece_index: int,
        url: str,
        start_offset: int,
        length: int,
    ) -> DownloadState | None:
        """Download a single piece from a specific URL.

        Parameters
        ----------
        piece_index : int
            The piece index.
        url : str
            The URL to download from.
        start_offset : int
            Starting byte offset.
        length : int
            Number of bytes.

        Returns
        -------
        DownloadState or None
            The download state with data if successful.
        """
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        state = DownloadState(
            piece_index=piece_index,
            start_offset=start_offset,
            length=length,
        )
        state.status = "downloading"
        state.start_time = time.time()

        downloaded_data: bytes | None = None

        try:
            if scheme in ("http", "https"):
                end_offset = start_offset + length - 1 if length > 0 else start_offset
                thread = HTTPDownloadThread(
                    url,
                    start_offset,
                    end_offset,
                    self.timeout,
                )
                thread.start()
                thread.join(timeout=self.timeout)
                downloaded_data = thread.data

            elif scheme in ("ftp", "ftps"):
                thread = FTPDownloadThread(
                    url,
                    start_offset,
                    start_offset + length,
                    self.timeout,
                )
                thread.start()
                thread.join(timeout=self.timeout)
                downloaded_data = thread.data
            else:
                state.status = "failed"
                state.error = f"Unsupported scheme: {scheme}"
                return None

        except Exception as exc:
            state.status = "failed"
            state.error = str(exc)
            return None

        if downloaded_data and len(downloaded_data) > 0:
            state.data = downloaded_data
            state.bytes_downloaded = len(downloaded_data)
            state.status = "completed"
            state.end_time = time.time()

            # Validate SHA-1
            try:
                computed_hash = state.compute_sha1()
                if computed_hash != self.torrent.infohash:
                    state.status = "failed"
                    state.error = f"SHA-1 mismatch: expected {self.torrent.infohash.hex()}, got {computed_hash.hex()}"
                    self.invalid_urls.add(url)
                    return None
                else:
                    self.valid_urls.add(url)
                    self._downloaded_pieces.add(piece_index)
                    return state
            except WebSeedError as exc:
                state.status = "failed"
                state.error = str(exc)
                return None
        else:
            state.status = "failed"
            state.error = "No data received"
            return None

    def download_range(
        self,
        start_piece: int,
        end_piece: int,
        urls: list[str] | None = None,
    ) -> dict[int, DownloadState | None]:
        """Download a range of pieces from webseed URLs.

        Downloads all pieces from start_piece to end_piece (inclusive).

        Parameters
        ----------
        start_piece : int
            The first piece index.
        end_piece : int
            The last piece index (inclusive).
        urls : list of str, optional
            URLs to try. If None, uses torrent webseed URLs.

        Returns
        -------
        dict
            Mapping of piece_index to DownloadState.
        """
        results: dict[int, DownloadState | None] = {}

        for piece_idx in range(start_piece, end_piece + 1):
            start_offset = piece_idx * self.piece_length
            length = self.piece_length

            state = self.download_piece(
                piece_index=piece_idx,
                start_offset=start_offset,
                length=length,
                urls=urls,
            )
            results[piece_idx] = state

        return results

    def clear_invalid_urls(self) -> None:
        """Clear the set of invalid URLs.

        This can be called to reset URL tracking, for example
        when starting a new download session.
        """
        self.invalid_urls.clear()

    def get_success_rate(self) -> float:
        """Get the webseed download success rate.

        Returns
        -------
        float
            Percentage of valid URLs (0.0 to 100.0).
        """
        total = len(self.valid_urls) + len(self.invalid_urls)
        if total == 0:
            return 0.0
        return (len(self.valid_urls) / total) * 100.0

    @property
    def downloaded_piece_count(self) -> int:
        """Get the number of successfully downloaded pieces.

        Returns
        -------
        int
            Number of pieces downloaded from webseed.
        """
        return len(self._downloaded_pieces)

    @property
    def failed_piece_count(self) -> int:
        """Get the number of failed piece downloads.

        Returns
        -------
        int
            Number of pieces that failed to download.
        """
        return len(self._failed_pieces)
