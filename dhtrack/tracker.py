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
from typing import Any

from dhtrack import bencode as bencode_module
from dhtrack.bencode import BEncodeValue
from dhtrack.bep31 import FailureRetryInfo, parse_failure_response

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
class AnnounceResponse:
    """Response from a tracker HTTP announce request (BEP 3 / BEP 23).

    Attributes
    ----------
    peers : list[tuple[str, int]]
        Decoded compact peer list — each entry is ``(ip_str, port)``.
    peers6 : list[tuple[str, int]]
        Optional decoded compact IPv6 peer list (``peers6``). Each entry is
        ``(ip_str, port)``.
    interval : int
        Seconds until the next mandatory re-announce (``interval`` field).
    min_interval : int | None
        Optional minimum re-announce interval (``min interval`` field).
    complete : int
        Number of seeders reported by the tracker (``complete`` field).
    incomplete : int
        Number of leechers reported by the tracker (``incomplete`` field).
    failure_reason : str | None
        Non-empty when the tracker returned a ``failure reason``.
    warning_message : str | None
        Optional ``warning message`` from the tracker.
    tracker_id : bytes | None
        Optional opaque ``tracker id`` to re-send on subsequent announces.
    """

    peers: list[tuple[str, int]] = field(default_factory=list)
    peers6: list[tuple[str, int]] = field(default_factory=list)
    interval: int = 1800
    min_interval: int | None = None
    complete: int = 0
    incomplete: int = 0
    failure_reason: str | None = None
    warning_message: str | None = None
    tracker_id: bytes | None = None

    @property
    def is_error(self) -> bool:
        """True if the response indicates an error."""
        return self.failure_reason is not None


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
    failure_reason: str | None = None

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
        raise TrackerClientError(f"Announce URL path does not contain 'announce': {announce_url}")

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
            raise TrackerClientError(f"Infohash must be 20 bytes, got {len(ih)} bytes")

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

    decoded_b: dict[bytes, Any] = decoded

    # Error response first (bytes keys from bencode)
    failure_reason = decoded_b.get(b"failure reason")
    if failure_reason is not None:
        if isinstance(failure_reason, bytes):
            response.failure_reason = failure_reason.decode("utf-8", errors="replace")
        else:
            response.failure_reason = str(failure_reason)
        return response

    # Success response
    files_dict = decoded_b.get(b"files")
    if files_dict is None:
        raise ScrapeError("Response missing 'files' key")

    if not isinstance(files_dict, dict):
        raise ScrapeError(f"'files' value must be a dictionary, got {type(files_dict).__name__}")

    files_b: dict[bytes, Any] = files_dict
    for infohash, swarm_info in files_b.items():
        if not isinstance(infohash, (bytes, bytearray)):
            continue
        infohash = bytes(infohash)

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


def _parse_swarm_info(swarm_info: BEncodeValue) -> ScrapeInfo | None:
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
        complete = _get_int_field(swarm_info, b"complete")
        incomplete = _get_int_field(swarm_info, b"incomplete")
        downloaded = _get_int_field(swarm_info, b"downloaded")
    except (ValueError, TypeError) as exc:
        logger.warning("Failed to parse swarm info: %s", exc)
        return None

    return ScrapeInfo(
        complete=complete,
        incomplete=incomplete,
        downloaded=downloaded,
    )


def _decode_compact_peers(data: bytes) -> list[tuple[str, int]]:
    """Decode a compact IPv4 peer list (BEP 23).

    Each peer is encoded as 6 bytes: 4-byte IP followed by 2-byte big-endian port.

    Parameters
    ----------
    data : bytes
        Raw compact peer blob from the tracker.

    Returns
    -------
    list[tuple[str, int]]
        Decoded list of ``(ip_str, port)`` tuples.
    """
    import socket as _socket
    import struct as _struct

    peers = []
    for offset in range(0, len(data) - 5, 6):
        ip = _socket.inet_ntoa(data[offset : offset + 4])
        port = _struct.unpack_from("!H", data, offset + 4)[0]
        peers.append((ip, port))
    return peers


def _decode_compact_peers6(data: bytes) -> list[tuple[str, int]]:
    """Decode a compact IPv6 peer list (18-byte tuples).

    Each peer is encoded as 18 bytes: 16-byte IPv6 address followed by 2-byte
    big-endian port.
    """
    import socket as _socket
    import struct as _struct

    peers: list[tuple[str, int]] = []
    for offset in range(0, len(data) - 17, 18):
        ip = _socket.inet_ntop(_socket.AF_INET6, data[offset : offset + 16])
        port = _struct.unpack_from("!H", data, offset + 16)[0]
        peers.append((ip, port))
    return peers


def _decode_announce_response(data: bytes) -> AnnounceResponse:
    """Decode a bencoded HTTP tracker announce response (BEP 3 / BEP 23).

    Handles both the compact peer format (BEP 23 — ``peers`` is a bytes blob)
    and the older dictionary-list format (``peers`` is a list of dicts).

    Parameters
    ----------
    data : bytes
        Raw bencoded response from the tracker.

    Returns
    -------
    AnnounceResponse
        Parsed announce response.

    Raises
    ------
    ScrapeError
        If the response cannot be decoded.
    """
    try:
        decoded = bencode_module.decode(data)
    except bencode_module.DecodeError as exc:
        raise ScrapeError(f"Failed to decode announce response: {exc}") from exc

    if not isinstance(decoded, dict):
        raise ScrapeError(f"Expected dictionary response, got {type(decoded).__name__}")

    decoded_b: dict[bytes, Any] = decoded
    response = AnnounceResponse()

    # Failure reason (BEP 3 / BEP 31)
    failure = decoded_b.get(b"failure reason")
    if failure is not None:
        response.failure_reason = (
            failure.decode("utf-8", errors="replace") if isinstance(failure, bytes) else str(failure)
        )
        return response

    # Warning message
    warning = decoded_b.get(b"warning message")
    if warning is not None:
        response.warning_message = (
            warning.decode("utf-8", errors="replace") if isinstance(warning, bytes) else str(warning)
        )

    # Interval
    interval = decoded_b.get(b"interval") or 1800
    response.interval = int(interval) if isinstance(interval, int) else 1800

    min_interval = decoded_b.get(b"min interval")
    if isinstance(min_interval, int):
        response.min_interval = min_interval

    # Seeder / leecher counts
    complete = decoded_b.get(b"complete") or 0
    response.complete = int(complete) if isinstance(complete, int) else 0
    incomplete = decoded_b.get(b"incomplete") or 0
    response.incomplete = int(incomplete) if isinstance(incomplete, int) else 0

    # Tracker ID
    tracker_id = decoded_b.get(b"tracker id")
    if isinstance(tracker_id, bytes):
        response.tracker_id = tracker_id

    # Peer list: compact bytes blob (BEP 23) or legacy list of dicts (BEP 3)
    peers_raw = decoded_b.get(b"peers")
    if isinstance(peers_raw, bytes):
        response.peers = _decode_compact_peers(peers_raw)
    elif isinstance(peers_raw, list):
        for entry in peers_raw:
            if not isinstance(entry, dict):
                continue
            ip = entry.get(b"ip")
            port = entry.get(b"port")
            if ip and port:
                ip_str = ip.decode("utf-8", errors="replace") if isinstance(ip, bytes) else str(ip)
                response.peers.append((ip_str, int(port)))

    # Optional IPv6 compact peer list
    peers6_raw = decoded_b.get(b"peers6")
    if isinstance(peers6_raw, bytes):
        response.peers6 = _decode_compact_peers6(peers6_raw)

    return response


def _get_int_field(data: dict[bytes, Any], key: bytes) -> int:
    """Extract an integer field from a dictionary.

    Parameters
    ----------
    data : dict[bytes, Any]
        The source dictionary (decoded bencode; keys are bytes).
    key : bytes
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
        user_agent: str | None = None,
        max_retries: int = 2,
        retry_delay: float = 1.0,
    ) -> None:
        self.timeout: int = timeout
        self.user_agent: str = user_agent or "dhtrack"
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

    def announce(
        self,
        announce_url: str,
        info_hash: bytes,
        peer_id: bytes,
        port: int,
        uploaded: int = 0,
        downloaded: int = 0,
        left: int = 0,
        event: str = "",
        numwant: int = 50,
        tracker_id: bytes | None = None,
        compact: int = 1,
    ) -> AnnounceResponse:
        """Send an HTTP GET announce request to a tracker (BEP 3 / BEP 23).

        Builds a ``GET /announce?...`` request with ``compact=1`` by default
        so the tracker returns a compact peer list (BEP 23).  Falls back to
        parsing the legacy dictionary-list format if the tracker ignores
        ``compact=1``.

        Parameters
        ----------
        announce_url : str
            Full announce URL, e.g. ``http://tracker.example.com/announce``.
        info_hash : bytes
            20-byte SHA-1 infohash of the torrent.
        peer_id : bytes
            20-byte peer ID identifying this client.
        port : int
            Local TCP port the client is listening on.
        uploaded : int
            Total bytes uploaded so far.
        downloaded : int
            Total bytes downloaded so far.
        left : int
            Bytes remaining to download.
        event : str
            One of ``"started"``, ``"stopped"``, ``"completed"``, or ``""``
            (empty string omits the event parameter).
        numwant : int
            Number of peers requested from the tracker.
        tracker_id : bytes or None
            Opaque tracker ID from a previous response; re-sent when present.
        compact : int
            Pass 1 to request compact peer lists (BEP 23); 0 for legacy format.

        Returns
        -------
        AnnounceResponse
            Parsed announce response with a peer list, interval, and counts.

        Raises
        ------
        TrackerClientError
            If the infohash or peer_id are invalid.
        ScrapeError
            If the announce request fails or returns an error response.
        """
        if len(info_hash) != 20:
            raise TrackerClientError(f"info_hash must be 20 bytes, got {len(info_hash)}")
        if len(peer_id) != 20:
            raise TrackerClientError(f"peer_id must be 20 bytes, got {len(peer_id)}")

        params: list[tuple[str, str]] = [
            ("info_hash", info_hash.decode("latin-1")),
            ("peer_id", peer_id.decode("latin-1")),
            ("port", str(port)),
            ("uploaded", str(uploaded)),
            ("downloaded", str(downloaded)),
            ("left", str(left)),
            ("compact", str(compact)),
            ("numwant", str(numwant)),
        ]
        if event:
            params.append(("event", event))
        if tracker_id is not None:
            params.append(("trackerid", tracker_id.decode("latin-1")))

        query = urllib.parse.urlencode(params)
        sep = "&" if "?" in announce_url else "?"
        url = f"{announce_url}{sep}{query}"

        last_exception: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._do_announce_request(url)
            except (urllib.error.URLError, OSError) as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    logger.debug(
                        "Announce request failed (attempt %d/%d): %s",
                        attempt + 1,
                        self.max_retries,
                        exc,
                    )
                    import time as _time

                    _time.sleep(self.retry_delay)
                else:
                    logger.error(
                        "Announce request failed after %d attempts: %s",
                        self.max_retries + 1,
                        exc,
                    )

        raise ScrapeError(
            f"Failed to announce after {self.max_retries + 1} attempts: {last_exception}"
        ) from last_exception

    def _do_announce_request(self, url: str) -> AnnounceResponse:
        """Execute a single HTTP announce request.

        Parameters
        ----------
        url : str
            Full announce URL including query parameters.

        Returns
        -------
        AnnounceResponse
            Parsed announce response.

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
                result = _decode_announce_response(data)
                if result.is_error:
                    failure_info = self._parse_failure_response(data)
                    logger.warning(
                        "Announce failed: %s (retry_in=%s min, permanent=%s)",
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
