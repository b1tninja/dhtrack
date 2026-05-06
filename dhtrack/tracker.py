"""
Tracker Protocol Extension: Scrape (BEP 48).

Provides HTTP tracker scrape functionality for querying swarm metadata
in bulk. A scrape request returns complete, incomplete, and downloaded
counts for one or more torrents identified by infohash.

Examples
--------
>>> from dhtrack.tracker import TrackerClient
>>> client = TrackerClient()
>>> response = client.scrape([infohash1, infohash2], "http://tracker.example.com/announce")
>>> for infohash, info in response.files.items():
...     print(f"Complete: {info.complete}, Incomplete: {info.incomplete}")
"""

from __future__ import annotations

import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from dhtrack import bencode as bencode_module
from dhtrack.bencode import BEncodeValue
from dhtrack.bep31 import FailureRetryInfo, parse_failure_response, TrackerRetryScheduler

logger = logging.getLogger(__name__)


class TrackerError(Exception):
    """Base exception for tracker errors."""


class ScrapeError(TrackerError):
    """Raised when a scrape request fails."""


class TrackerClientError(TrackerError):
    """Raised when the tracker client encounters a client-side error."""


@dataclass
class ScrapeInfo:
    """Scrape information for a single torrent swarm.

    Attributes
    ----------
    complete : int
        The number of active peers that have completed downloading.
    incomplete : int
        The number of active peers that have not completed downloading.
    downloaded : int
        The number of peers that have ever completed downloading.
    """

    complete: int = 0
    incomplete: int = 0
    downloaded: int = 0


@dataclass
class ScrapeResponse:
    """Response from a tracker scrape request.

    Attributes
    ----------
    files : dict[bytes, ScrapeInfo]
        A mapping from 20-byte infohash to scrape information.
    failure_reason : str | None
        If present, the request failed with this reason.
    """

    files: dict[bytes, ScrapeInfo] = field(default_factory=dict)
    failure_reason: Optional[str] = None

    @property
    def is_error(self) -> bool:
        """True if the response indicates an error."""
        return self.failure_reason is not None


def _build_scrape_url(announce_url: str) -> str:
    """Derive the scrape URL from an announce URL.

    Per BEP 48: replace the string ``announce`` in the path section
    of the URL with the string ``scrape``.

    Parameters
    ----------
    announce_url : str
        The tracker announce URL.

    Returns
    -------
    str
        The corresponding scrape URL.

    Raises
    ------
    TrackerClientError
        If the announce URL does not contain the path segment 'announce'.
    """
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(announce_url)

    # Replace 'announce' with 'scrape' in the path
    path = parsed.path
    # Find 'announce' in the path and replace it
    if "announce" not in path:
        raise TrackerClientError(
            f"Announce URL path does not contain 'announce': {announce_url}"
        )

    # Replace only the first occurrence of 'announce' in the path
    new_path = path.replace("announce", "scrape", 1)

    new_parsed = parsed._replace(path=new_path)
    return urlunparse(new_parsed)


def _encode_scrape_request(info_hashes: list[bytes]) -> str:
    """Build the scrape request URL with info_hash query parameters.

    Per BEP 48: the ``info_hash`` key is appended multiple times,
    once for each infohash to query.

    Parameters
    ----------
    info_hashes : list[bytes]
        List of 20-byte infohashes.

    Returns
    -------
    str
        The full scrape request URL with query parameters.

    Raises
    ------
    TrackerClientError
        If any infohash is not exactly 20 bytes.
    """
    for ih in info_hashes:
        if len(ih) != 20:
            raise TrackerClientError(
                f"Infohash must be 20 bytes, got {len(ih)} bytes"
            )

    # Build query string with multiple info_hash parameters
    query_pairs = [(b"info_hash", ih) for ih in info_hashes]
    query_string = urllib.parse.urlencode(query_pairs, doseq=False)

    return query_string


def _decode_scrape_response(data: bytes) -> ScrapeResponse:
    """Decode a bencoded scrape response.

    Expected format on success::

        d5:filesd20:<infohash>d8:completei<complete>e10:downloadedi<downloaded>e10:incompletei<incomplete>eee
                                  ...
                                   e

    Expected format on error::

        d12:failure reason<string>e

    Parameters
    ----------
    data : bytes
        The raw bencoded response from the tracker.

    Returns
    -------
    ScrapeResponse
        The parsed scrape response.

    Raises
    ------
    ScrapeError
        If the response cannot be decoded.
    """
    try:
        decoded = bencode_module.decode(data)
    except bencode_module.DecodeError as exc:
        raise ScrapeError(f"Failed to decode bencoded response: {exc}") from exc

    if not isinstance(decoded, dict):
        raise ScrapeError(f"Expected dictionary response, got {type(decoded).__name__}")

    response = ScrapeResponse()

    # Check for error response first
    failure_reason = decoded.get("failure reason")
    if failure_reason is not None:
        if isinstance(failure_reason, bytes):
            response.failure_reason = failure_reason.decode("utf-8", errors="replace")
        elif isinstance(failure_reason, str):
            response.failure_reason = failure_reason
        else:
            response.failure_reason = str(failure_reason)
        return response

    # Parse success response
    files_dict = decoded.get("files")
    if files_dict is None:
        raise ScrapeError("Response missing 'files' key")

    if not isinstance(files_dict, dict):
        raise ScrapeError(f"'files' value must be a dictionary, got {type(files_dict).__name__}")

    for infohash_bytes, swarm_info in files_dict.items():
        # Handle both bytes and string keys
        if isinstance(infohash_bytes, str):
            infohash = infohash_bytes.encode("latin-1")
        elif isinstance(infohash_bytes, bytes):
            infohash = infohash_bytes
        else:
            logger.warning("Skipping non-bytes/str infohash key: %s", type(infohash_bytes))
            continue

        if len(infohash) != 20:
            logger.warning(
                "Skipping infohash with wrong length (%d bytes): %s",
                len(infohash),
                infohash,
            )
            continue

        scrape_info = _parse_swarm_info(swarm_info)
        if scrape_info is not None:
            response.files[infohash] = scrape_info

    return response


def _parse_swarm_info(swarm_info: BEncodeValue) -> Optional[ScrapeInfo]:
    """Parse a single swarm's metadata dictionary.

    Parameters
    ----------
    swarm_info : BEncodeValue
        The bencoded dictionary containing complete, incomplete, downloaded.

    Returns
    -------
    ScrapeInfo or None
        The parsed scrape info, or None on failure.
    """
    if not isinstance(swarm_info, dict):
        logger.warning("Swarm info is not a dict: %s", type(swarm_info))
        return None

    try:
        complete = _get_int_field(swarm_info, "complete")
        incomplete = _get_int_field(swarm_info, "incomplete")
        downloaded = _get_int_field(swarm_info, "downloaded")
    except (ValueError, TypeError) as exc:
        logger.warning("Failed to parse swarm info: %s", exc)
        return None

    return ScrapeInfo(
        complete=complete,
        incomplete=incomplete,
        downloaded=downloaded,
    )


def _get_int_field(data: dict[str, Any], key: str) -> int:
    """Extract an integer field from a dictionary.

    Parameters
    ----------
    data : dict[str, Any]
        The source dictionary.
    key : str
        The key to look up.

    Returns
    -------
    int
        The integer value.

    Raises
    ------
    ValueError
        If the value is not an integer or is negative.
    """
    value = data.get(key)
    if value is None:
        return 0

    if not isinstance(value, int):
        raise ValueError(f"Expected int for '{key}', got {type(value).__name__}: {value}")

    if value < 0:
        raise ValueError(f"Negative value for '{key}': {value}")

    return value


class TrackerClient:
    """HTTP tracker client with scrape support (BEP 48).

    Parameters
    ----------
    timeout : int, optional
        Connection timeout in seconds. Defaults to 10.
    user_agent : str, optional
        User-Agent header value. Defaults to ``dhtrack/<version>``.
    max_retries : int, optional
        Number of retry attempts on connection failure. Defaults to 2.
    retry_delay : float, optional
        Delay between retries in seconds. Defaults to 1.0.

    Attributes
    ----------
    timeout : int
        Connection timeout in seconds.
    user_agent : str
        User-Agent header string.
    max_retries : int
        Maximum number of retry attempts.
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        max_retries: int = 2,
        retry_delay: float = 1.0,
    ) -> None:
        self.timeout: int = timeout
        self.user_agent: str = user_agent or f"dhtrack"
        self.max_retries: int = max_retries
        self.retry_delay: float = retry_delay

    def scrape(
        self,
        info_hashes: list[bytes],
        announce_url: str,
    ) -> ScrapeResponse:
        """Send a scrape request to a tracker for multiple infohashes.

        Per BEP 48, the scrape URL is derived from the announce URL by
        replacing "announce" with "scrape" in the path. The request includes
        all infohashes as ``info_hash`` query parameters.

        Parameters
        ----------
        info_hashes : list[bytes]
            List of 20-byte infohashes to query.
        announce_url : str
            The tracker announce URL (e.g., ``http://tracker.example.com/announce``).

        Returns
        -------
        ScrapeResponse
            The parsed scrape response containing swarm metadata.

        Raises
        ------
        TrackerClientError
            If the URLs or infohashes are invalid.
        ScrapeError
            If the scrape request fails or returns an error.
        """
        if not info_hashes:
            raise TrackerClientError("No infohashes provided for scrape")

        # Build the scrape URL
        try:
            scrape_base = _build_scrape_url(announce_url)
        except TrackerClientError:
            raise

        # Encode the request
        try:
            query_string = _encode_scrape_request(info_hashes)
        except TrackerClientError:
            raise

        # Build full URL
        if "?" in scrape_base:
            url = f"{scrape_base}&{query_string}"
        else:
            url = f"{scrape_base}?{query_string}"

        # Send the request with retries
        last_exception: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._do_scrape_request(url)
            except (urllib.error.URLError, OSError) as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    logger.debug(
                        "Scrape request failed (attempt %d/%d): %s",
                        attempt + 1,
                        self.max_retries,
                        exc,
                    )
                    import time
                    time.sleep(self.retry_delay)
                else:
                    logger.error(
                        "Scrape request failed after %d attempts: %s",
                        self.max_retries + 1,
                        exc,
                    )

        raise ScrapeError(
            f"Failed to scrape after {self.max_retries + 1} attempts: {last_exception}"
        ) from last_exception

    def _parse_failure_response(self, data: bytes) -> FailureRetryInfo:
        """Parse a bencoded failure response from the tracker.

        Parameters
        ----------
        data : bytes
            The raw response from the tracker.

        Returns
        -------
        FailureRetryInfo
            Parsed BEP 31 failure information.
        """
        try:
            decoded = bencode_module.decode(data)
        except Exception:
            return FailureRetryInfo(
                failure_reason="Failed to decode tracker response",
                permanent=True,
            )

        if not isinstance(decoded, dict):
            return FailureRetryInfo(
                failure_reason="Invalid response format",
                permanent=True,
            )

        return parse_failure_response(decoded)

    def _do_scrape_request(self, url: str) -> ScrapeResponse:
        """Execute a single scrape request.

        Parameters
        ----------
        url : str
            The full scrape request URL.

        Returns
        -------
        ScrapeResponse
            The parsed scrape response.

        Raises
        ------
        ScrapeError
            If the HTTP request fails.
        """
        request = urllib.request.Request(url, method="GET")
        request.add_header("User-Agent", self.user_agent)
        request.add_header("Accept", "*/*")

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = response.read()
                result = _decode_scrape_response(data)
                # Check for BEP 31 retry information in error responses
                if result.is_error:
                    failure_info = self._parse_failure_response(data)
                    logger.warning(
                        "Scrape failed: %s (retry in %s minutes, permanent=%s)",
                        result.failure_reason,
                        failure_info.retry_minutes,
                        failure_info.permanent,
                    )
                return result
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise ScrapeError(f"Tracker not found: {exc}") from exc
            elif exc.code >= 500:
                raise ScrapeError(f"Tracker server error: {exc}") from exc
            else:
                raise ScrapeError(f"Tracker HTTP error: {exc}") from exc

    def scrape_single(
        self,
        info_hash: bytes,
        announce_url: str,
    ) -> ScrapeResponse:
        """Convenience method to scrape a single infohash.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash to query.
        announce_url : str
            The tracker announce URL.

        Returns
        -------
        ScrapeResponse
            The parsed scrape response.
        """
        return self.scrape([info_hash], announce_url)

    @staticmethod
    def scrape_url(announce_url: str, info_hashes: list[bytes]) -> str:
        """Build the full scrape request URL without making a request.

        This is a convenience method that combines ``_build_scrape_url``
        and ``_encode_scrape_request`` to produce the complete URL.

        Parameters
        ----------
        announce_url : str
            The tracker announce URL.
        info_hashes : list[bytes]
            List of 20-byte infohashes.

        Returns
        -------
        str
            The complete scrape request URL.

        Raises
        ------
        TrackerClientError
            If the URLs or infohashes are invalid.
        """
        base = _build_scrape_url(announce_url)
        query = _encode_scrape_request(info_hashes)
        if "?" in base:
            return f"{base}&{query}"
        return f"{base}?{query}"