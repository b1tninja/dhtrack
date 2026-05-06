"""
UDP Tracker Protocol for BitTorrent (BEP 15).

Provides a UDP-based alternative to HTTP trackers for peer discovery.
The protocol uses a 4-packet handshake:
  1. Connect  - Client obtains a connection ID from the tracker
  2. Announce - Client announces to the tracker and discovers peers
  3. Scrape   - Client queries torrent statistics (up to ~74 torrents)
  4. Error    - Tracker reports errors

Examples
--------
>>> from dhtrack.udp_tracker import UDPTrackerClient
>>> client = UDPTrackerClient()
>>> client.connect("tracker.example.com", 6969)
>>> response = client.announce(
...     info_hash=b"\\x00" * 20,
...     peer_id=b"AAAAAAAAAAAAAAAAAA",
...     port=6881,
... )
>>> print(f"Seeders: {response.seeders}, Leechers: {response.leechers}")
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

#: Magic constant for the BEP 15 protocol (64-bit).
_PROTOCOL_MAGIC = 0x000041727101980

#: Action codes.
_ACTION_CONNECT = 0
_ACTION_ANNOUNCE = 1
_ACTION_SCRAPES = 2
_ACTION_ERROR = 3

#: Exponential-backoff base interval in seconds.
_RETRY_BASE_INTERVAL = 15

#: Maximum retries when a request fails.
_MAX_RETRIES = 8

#: Seconds after which a connection ID is considered expired for reuse.
_CONN_ID_USE_LIMIT = 60

#: Maximum number of torrents per scrape request.
_MAX_SCRAPES = 74


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TrackerError(Exception):
    """Base exception for UDP tracker errors."""


class TrackerConnectionError(TrackerError):
    """Raised when connection to the tracker fails."""


class TrackerProtocolError(TrackerError):
    """Raised on tracker protocol violations (bad response, etc.)."""


class TrackerResponseError(TrackerError):
    """Raised when the tracker returns an error message."""


class TrackerClientError(TrackerError):
    """Raised for client-side errors (bad arguments, etc.)."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IPPeer:
    """An IPv4 (or IPv6) address and port pair representing a peer.

    Attributes
    ----------
    ip : str
        The IP address as a dotted-decimal string.
    port : int
        The TCP port number.
    """

    ip: str
    port: int

    @classmethod
    def from_ipv4(cls, ip_bytes: bytes, port: int) -> IPPeer:
        """Create an IPPeer from a 4-byte IPv4 address.

        Parameters
        ----------
        ip_bytes : bytes
            4 bytes of IPv4 address in network byte order.
        port : int
            TCP port number.

        Returns
        -------
        IPPeer
        """
        ip_str = ".".join(str(b) for b in ip_bytes)
        return cls(ip=ip_str, port=port)

    @classmethod
    def from_ipv6(cls, ip_bytes: bytes, port: int) -> IPPeer:
        """Create an IPPeer from a 16-byte IPv6 address.

        Parameters
        ----------
        ip_bytes : bytes
            16 bytes of IPv6 address in network byte order.
        port : int
            TCP port number.

        Returns
        -------
        IPPeer
        """
        ip_addr = IPv6Address(ip_bytes)
        return cls(ip=str(ip_addr), port=port)


class AnnounceEvent:
    """Enumerate possible events in an announce request.

    Per BEP 15:
        0 = none
        1 = completed
        2 = started
        3 = stopped
    """

    NONE = 0
    COMPLETED = 1
    STARTED = 2
    STOPPED = 3


@dataclass
class AnnounceRequest:
    """Parameters for an announce request.

    Attributes
    ----------
    info_hash : bytes
        20-byte info hash of the torrent.
    peer_id : bytes
        20-byte peer ID.
    downloaded : int
        Total bytes downloaded (since this session / ever).
    left : int
        Bytes still needed to complete the torrent.
    uploaded : int
        Total bytes uploaded.
    event : AnnounceEvent
        Event type.  Default is ``NONE``.
    ip_address : int
        Client IP address as a 32-bit integer (0 = let tracker decide).
    key : int
        Unique client key.
    num_want : int
        Maximum number of peers to return (-1 = default).
    port : int
        TCP port number for listening peers.
    """

    info_hash: bytes
    peer_id: bytes
    downloaded: int = 0
    left: int = 0
    uploaded: int = 0
    event: int = AnnounceEvent.NONE
    ip_address: int = 0
    key: int = 0
    num_want: int = -1
    port: int = 0

    def validate(self) -> None:
        """Validate the request fields.

        Raises
        ------
        TrackerClientError
            If any field is invalid.
        """
        if len(self.info_hash) != 20:
            raise TrackerClientError(
                f"info_hash must be 20 bytes, got {len(self.info_hash)}"
            )
        if len(self.peer_id) != 20:
            raise TrackerClientError(
                f"peer_id must be 20 bytes, got {len(self.peer_id)}"
            )
        if not (0 <= self.port <= 65535):
            raise TrackerClientError(f"port must be 0-65535, got {self.port}")
        if (
            self.downloaded < 0
            or self.left < 0
            or self.uploaded < 0
        ):
            raise TrackerClientError(
                "downloaded, left, and uploaded must be non-negative"
            )


@dataclass
class AnnounceResponse:
    """Response from an announce request.

    Attributes
    ----------
    interval : int
        Seconds between announces.
    leechers : int
        Number of peers who still have data to download.
    seeders : int
        Number of peers who have completed downloading.
    peers : list[IPPeer]
        List of peer entries discovered.
    """

    interval: int = 0
    leechers: int = 0
    seeders: int = 0
    peers: list[IPPeer] = field(default_factory=list)


@dataclass
class ScrapeInfo:
    """Scrape information for a single torrent.

    Attributes
    ----------
    seeders : int
        Number of active peers that have completed downloading.
    completed : int
        Number of peers that have completed downloading.
    leechers : int
        Number of active peers that have not completed downloading.
    """

    seeders: int = 0
    completed: int = 0
    leechers: int = 0


@dataclass
class ScrapeResponse:
    """Response from a scrape request.

    Attributes
    ----------
    files : dict[bytes, ScrapeInfo]
        Mapping from 20-byte infohash to scrape information.
    error : str or None
        Error message if the request failed.
    """

    files: dict[bytes, ScrapeInfo] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def is_error(self) -> bool:
        """Return ``True`` if the response indicates an error."""
        return self.error is not None


# ---------------------------------------------------------------------------
# UDPTrackerClient
# ---------------------------------------------------------------------------


class UDPTrackerClient:
    """UDP tracker client implementing BEP 15.

    Parameters
    ----------
    timeout : int, optional
        Socket timeout in seconds.  Defaults to 15.
    max_retries : int, optional
        Maximum number of retry attempts for a request. Defaults to 8.
    """

    def __init__(
        self,
        timeout: int = 15,
        max_retries: int = 8,
    ) -> None:
        self.timeout: int = timeout
        self.max_retries: int = max_retries

        # Per-instance mutable state
        self._connection_id: Optional[int] = None
        self._connection_time: float = 0.0
        self._tracker_host: Optional[str] = None
        self._tracker_port: Optional[int] = None
        self._tracker_af: Optional[int] = None  # AF_INET or AF_INET6
        self._transaction_id: int = int(time.time() * 1000) & 0xFFFFFFFF

    # ------------------------------------------------------------------
    # Transaction ID generator
    # ------------------------------------------------------------------

    def _next_transaction_id(self) -> int:
        """Return the next 32-bit transaction ID."""
        tid = self._transaction_id
        self._transaction_id = (self._transaction_id + 1) & 0xFFFFFFFF
        return tid

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _validate_connection(self) -> None:
        """Ensure we have a valid connection ID.

        Raises
        ------
        TrackerConnectionError
            If not connected or the connection ID has expired.
        """
        if self._connection_id is None:
            raise TrackerConnectionError(
                "No connection ID obtained. Call connect() first."
            )
        elapsed = time.time() - self._connection_time
        if elapsed > _CONN_ID_USE_LIMIT:
            raise TrackerConnectionError(
                f"Connection ID expired ({elapsed:.1f}s). Call connect() again."
            )

    def _resolve_dest(self, host: str, port: int) -> tuple:
        """Resolve hostname to an address tuple suitable for sendto.

        Parameters
        ----------
        host : str
            Tracker hostname or IP address.
        port : int
            Tracker UDP port.

        Returns
        -------
        tuple
            Address tuple for sendto.
        """
        try:
            infos = socket.getaddrinfo(
                host, port, 0, socket.SOCK_DGRAM
            )
            if not infos:
                raise TrackerConnectionError(
                    f"Could not resolve hostname {host}:{port}"
                )
            # infos is list of (family, type, proto, canonname, sockaddr)
            af, _, _, _, sockaddr = infos[0]
            if af == socket.AF_INET6:
                self._tracker_af = socket.AF_INET6
            else:
                self._tracker_af = socket.AF_INET
            return sockaddr
        except socket.gaierror as exc:
            raise TrackerConnectionError(
                f"DNS resolution failed for {host}:{port}"
            ) from exc

    # ------------------------------------------------------------------
    # UDP I/O helpers
    # ------------------------------------------------------------------

    def _sendto_recvfrom(
        self,
        data: bytes,
        dest: tuple,
        af: int = socket.AF_INET,
    ) -> bytes:
        """Send *data* to *dest* and receive a response.

        Parameters
        ----------
        data : bytes
            The raw bytes to send.
        dest : tuple
            Destination address tuple.
        af : int
            Address family (AF_INET or AF_INET6).  Defaults to AF_INET.

        Returns
        -------
        bytes
            The response data.

        Raises
        ------
        OSError
            If the socket operation fails.
        """
        sock = socket.socket(af, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(data, dest)
            response, _ = sock.recvfrom(65536)
            return response
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # BEP 15 protocol methods
    # ------------------------------------------------------------------

    def connect(self, host: str, port: int, ip_version: int = 4) -> int:
        """Connect to a UDP tracker and obtain a connection ID.

        Per BEP 15, the client sends a connect request and receives a
        connection ID that can be reused for subsequent requests until
        it expires.

        Parameters
        ----------
        host : str
            The tracker hostname or IP address.
        port : int
            The tracker UDP port.
        ip_version : int
            4 for IPv4, 6 for IPv6.  Defaults to 4.

        Returns
        -------
        int
            The connection ID (64-bit).

        Raises
        ------
        TrackerConnectionError
            If the connection fails after exhausting retries.
        """
        self._tracker_host = host
        self._tracker_port = port

        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                conn_id = self._send_connect(host, port)
                self._connection_id = conn_id
                self._connection_time = time.time()
                self._tracker_host = host
                self._tracker_port = port
                return conn_id
            except (TrackerProtocolError, OSError) as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    interval = _RETRY_BASE_INTERVAL * (2 ** attempt)
                    logger.debug(
                        "Connect failed (attempt %d/%d): %s. Retrying in %ds",
                        attempt + 1,
                        self.max_retries + 1,
                        exc,
                        interval,
                    )
                    time.sleep(min(interval, 3840))
                else:
                    logger.error(
                        "Connect failed after %d attempts",
                        self.max_retries + 1,
                    )

        raise TrackerConnectionError(
            f"Failed to connect after {self.max_retries + 1} attempts: "
            f"{last_exception}"
        ) from last_exception

    def _send_connect(self, host: str, port: int) -> int:
        """Internal: send a connect request and return the connection ID.

        Parameters
        ----------
        host : str
            Tracker hostname.
        port : int
            Tracker UDP port.

        Returns
        -------
        int
            The connection ID.

        Raises
        ------
        TrackerProtocolError
            If the response is malformed.
        """
        tid = self._next_transaction_id()

        # Build connect request:
        #   protocol_id (8) + action (4) + transaction_id (4) = 16 bytes
        request = struct.pack("!QII", _PROTOCOL_MAGIC, _ACTION_CONNECT, tid)

        # Resolve destination address
        dest = self._resolve_dest(host, port)

        # Send & receive
        response = self._sendto_recvfrom(request, dest)

        # Validate response
        if len(response) < 16:
            raise TrackerProtocolError(
                f"Connect response too short: {len(response)} bytes (minimum 16)"
            )

        resp_action, resp_tid = struct.unpack_from("!II", response, 0)
        if resp_action != _ACTION_CONNECT:
            raise TrackerProtocolError(
                f"Unexpected action {resp_action} (expected {_ACTION_CONNECT})"
            )
        if resp_tid != tid:
            raise TrackerProtocolError(
                f"Transaction ID mismatch: expected {tid}, got {resp_tid}"
            )

        conn_id = struct.unpack_from("!Q", response, 8)[0]
        return conn_id

    def announce(
        self,
        info_hash: bytes,
        peer_id: bytes,
        port: int,
        downloaded: int = 0,
        left: int = 0,
        uploaded: int = 0,
        event: int = AnnounceEvent.NONE,
        ip_address: int = 0,
        key: int = 0,
        num_want: int = -1,
        host: Optional[str] = None,
        ip_version: int = 4,
    ) -> AnnounceResponse:
        """Send an announce request to the tracker.

        Parameters
        ----------
        info_hash : bytes
            20-byte info hash of the torrent.
        peer_id : bytes
            20-byte peer ID.
        port : int
            TCP port number for listening peers.
        downloaded : int
            Total bytes downloaded.
        left : int
            Bytes still needed.
        uploaded : int
            Total bytes uploaded.
        event : int
            Event type (NONE/COMPLETED/STARTED/STOPPED).
        ip_address : int
            Client IP as 32-bit integer (0 = auto).
        key : int
            Unique client key.
        num_want : int
            Maximum peers to return (-1 = default).
        host : str, optional
            Tracker hostname.  Defaults to the connected host.
        ip_version : int
            4 for IPv4, 6 for IPv6.  Defaults to 4.

        Returns
        -------
        AnnounceResponse
            The tracker's response.

        Raises
        ------
        TrackerConnectionError
            If not connected or the connection ID has expired.
        TrackerClientError
            If the request parameters are invalid.
        TrackerResponseError
            If the tracker returns an error.
        """
        # Validate inputs
        if len(info_hash) != 20:
            raise TrackerClientError(
                f"info_hash must be 20 bytes, got {len(info_hash)}"
            )
        if len(peer_id) != 20:
            raise TrackerClientError(
                f"peer_id must be 20 bytes, got {len(peer_id)}"
            )
        if not (0 <= port <= 65535):
            raise TrackerClientError(f"port must be 0-65535, got {port}")

        tracker_host = host or self._tracker_host
        if tracker_host is None:
            raise TrackerConnectionError(
                "No tracker address configured. Provide host or call connect() first."
            )

        self._validate_connection()

        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                response = self._send_announce(
                    info_hash=info_hash,
                    peer_id=peer_id,
                    port=port,
                    downloaded=downloaded,
                    left=left,
                    uploaded=uploaded,
                    event=event,
                    ip_address=ip_address,
                    key=key,
                    num_want=num_want,
                    host=tracker_host,
                    ip_version=ip_version,
                )
                return response
            except (TrackerProtocolError, TrackerResponseError, OSError) as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    interval = _RETRY_BASE_INTERVAL * (2 ** attempt)
                    logger.debug(
                        "Announce failed (attempt %d/%d): %s. Retrying in %ds",
                        attempt + 1,
                        self.max_retries + 1,
                        exc,
                        interval,
                    )
                    time.sleep(min(interval, 3840))
                else:
                    logger.error("Announce failed after %d attempts", self.max_retries + 1)

        raise TrackerResponseError(
            f"Announce failed after {self.max_retries + 1} attempts: {last_exception}"
        ) from last_exception

    def _send_announce(
        self,
        info_hash: bytes,
        peer_id: bytes,
        port: int,
        downloaded: int = 0,
        left: int = 0,
        uploaded: int = 0,
        event: int = AnnounceEvent.NONE,
        ip_address: int = 0,
        key: int = 0,
        num_want: int = -1,
        host: Optional[str] = None,
        ip_version: int = 4,
    ) -> AnnounceResponse:
        """Internal: send a single announce request and parse the response.

        Parameters
        ----------
        info_hash : bytes
        peer_id : bytes
        port : int
        downloaded : int
        left : int
        uploaded : int
        event : int
        ip_address : int
        key : int
        num_want : int
        host : str
        ip_version : int

        Returns
        -------
        AnnounceResponse
        """
        tid = self._next_transaction_id()
        tracker_host = host or self._tracker_host

        # Build announce request:
        #   connection_id (8) + action (4) + transaction_id (4) = 16
        #   + info_hash (20) + peer_id (20) = 60
        #   + downloaded (8) + left (8) + uploaded (8) = 84
        #   + event (4) + ip (4) + key (4) + num_want (4) = 100
        #   + port (2) = 102 bytes for IPv4
        ip_bytes = (
            ip_address.to_bytes(4, "big") if ip_address else b"\x00" * 4
        )

        request = struct.pack(
            "!QII",
            self._connection_id,  # type: ignore[arg-type]
            _ACTION_ANNOUNCE,
            tid,
        ) + info_hash + peer_id + struct.pack(
            "!qqqI",
            downloaded,
            left,
            uploaded,
            event,
        ) + ip_bytes + struct.pack("!IIH", key, num_want, port)

        # Determine address family from dest
        dest = self._resolve_dest(tracker_host, self._tracker_port or 0)
        af = socket.AF_INET6 if len(dest) == 4 and isinstance(dest[1], tuple) else socket.AF_INET

        response = self._sendto_recvfrom(request, dest, af=af)

        return self._parse_announce_response(response, tid, ip_version)

    def _parse_announce_response(
        self, data: bytes, expected_tid: int, ip_version: int = 4
    ) -> AnnounceResponse:
        """Parse an announce response from raw bytes.

        Parameters
        ----------
        data : bytes
            Raw response data.
        expected_tid : int
            Expected transaction ID.
        ip_version : int
            4 for IPv4, 6 for IPv6.

        Returns
        -------
        AnnounceResponse
        """
        if len(data) < 20:
            raise TrackerProtocolError(
                f"Announce response too short: {len(data)} bytes (minimum 20)"
            )

        action, tid = struct.unpack_from("!II", data, 0)

        if action == _ACTION_ERROR:
            msg = data[8:].decode("utf-8", errors="replace")
            raise TrackerResponseError(f"Tracker error: {msg}")

        if action != _ACTION_ANNOUNCE:
            raise TrackerProtocolError(
                f"Unexpected action {action} (expected {_ACTION_ANNOUNCE})"
            )

        if tid != expected_tid:
            raise TrackerProtocolError(
                f"Transaction ID mismatch: expected {expected_tid}, got {tid}"
            )

        interval, leechers, seeders = struct.unpack_from("!III", data, 8)

        # Parse peer list starting at offset 20
        peers: list[IPPeer] = []
        offset = 20

        if ip_version == 4:
            while offset + 6 <= len(data):
                ip_bytes = data[offset:offset + 4]
                port = struct.unpack_from("!H", data, offset + 4)[0]
                peers.append(IPPeer(ip=".".join(str(b) for b in ip_bytes), port=port))
                offset += 6
        else:
            while offset + 18 <= len(data):
                ip_bytes = data[offset:offset + 16]
                port = struct.unpack_from("!H", data, offset + 16)[0]
                peer = IPPeer(ip=str(IPv6Address(ip_bytes)), port=port)
                peers.append(peer)
                offset += 18

        return AnnounceResponse(
            interval=interval,
            leechers=leechers,
            seeders=seeders,
            peers=peers,
        )

    def scrape(
        self,
        info_hashes: list[bytes],
        host: Optional[str] = None,
        ip_version: int = 4,
    ) -> ScrapeResponse:
        """Send a scrape request for one or more torrents.

        Parameters
        ----------
        info_hashes : list[bytes]
            List of 20-byte info hashes to query.
        host : str, optional
            Tracker hostname.  Defaults to the connected host.
        ip_version : int
            4 for IPv4, 6 for IPv6.  Defaults to 4.

        Returns
        -------
        ScrapeResponse
            The tracker's response.

        Raises
        ------
        TrackerConnectionError
            If not connected or the connection ID has expired.
        TrackerClientError
            If the infohashes are invalid.
        """
        if not info_hashes:
            raise TrackerClientError("No infohashes provided for scrape")
        for ih in info_hashes:
            if len(ih) != 20:
                raise TrackerClientError(
                    f"Each infohash must be 20 bytes, got {len(ih)}"
                )

        tracker_host = host or self._tracker_host
        if tracker_host is None:
            raise TrackerConnectionError(
                "No tracker address configured. Provide host or call connect() first."
            )

        self._validate_connection()

        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                response = self._send_scrape(info_hashes, tracker_host, ip_version)
                return response
            except (TrackerProtocolError, TrackerResponseError, OSError) as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    interval = _RETRY_BASE_INTERVAL * (2 ** attempt)
                    logger.debug(
                        "Scrape failed (attempt %d/%d): %s. Retrying in %ds",
                        attempt + 1,
                        self.max_retries + 1,
                        exc,
                        interval,
                    )
                    time.sleep(min(interval, 3840))
                else:
                    logger.error("Scrape failed after %d attempts", self.max_retries + 1)

        raise TrackerResponseError(
            f"Scrape failed after {self.max_retries + 1} attempts: {last_exception}"
        ) from last_exception

    def _send_scrape(
        self,
        info_hashes: list[bytes],
        host: str,
        ip_version: int = 4,
    ) -> ScrapeResponse:
        """Internal: send a single scrape request and parse the response.

        Per BEP 15:
          connection_id (8) + action (4) + transaction_id (4) + info_hash (20) * N

        Parameters
        ----------
        info_hashes : list[bytes]
        host : str
        ip_version : int

        Returns
        -------
        ScrapeResponse
        """
        tid = self._next_transaction_id()

        # Build scrape request per BEP 15 spec:
        #   connection_id (8) + action (4) + transaction_id (4) = 16 bytes header
        #   + info_hash (20) * N
        request = struct.pack(
            "!QII",
            self._connection_id,  # type: ignore[arg-type]
            _ACTION_SCRAPES,
            tid,
        )
        for ih in info_hashes:
            request += ih

        dest = self._resolve_dest(host, self._tracker_port or 0)

        response = self._sendto_recvfrom(request, dest)

        return self._parse_scrape_response(response, tid, info_hashes)

    def _parse_scrape_response(
        self,
        data: bytes,
        expected_tid: int,
        requested_hashes: list[bytes],
    ) -> ScrapeResponse:
        """Parse a scrape response from raw bytes.

        Parameters
        ----------
        data : bytes
            Raw response data.
        expected_tid : int
            Expected transaction ID.
        requested_hashes : list[bytes]
            The infohashes that were requested, in order.

        Returns
        -------
        ScrapeResponse
        """
        if len(data) < 12:
            raise TrackerProtocolError(
                f"Scrape response too short: {len(data)} bytes (minimum 12)"
            )

        action, tid = struct.unpack_from("!II", data, 0)

        if action == _ACTION_ERROR:
            msg = data[8:].decode("utf-8", errors="replace")
            raise TrackerResponseError(f"Tracker error: {msg}")

        if action != _ACTION_SCRAPES:
            raise TrackerProtocolError(
                f"Unexpected action {action} (expected {_ACTION_SCRAPES})"
            )

        if tid != expected_tid:
            raise TrackerProtocolError(
                f"Transaction ID mismatch: expected {expected_tid}, got {tid}"
            )

        # Each entry is 12 bytes: seeders(4) + completed(4) + leechers(4)
        response = ScrapeResponse()
        offset = 8
        entry_size = 12

        for idx, ih in enumerate(requested_hashes):
            if offset + entry_size > len(data):
                break
            seeders, completed, leechers = struct.unpack_from(
                "!III", data, offset
            )
            response.files[ih] = ScrapeInfo(
                seeders=seeders,
                completed=completed,
                leechers=leechers,
            )
            offset += entry_size

        return response

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release any resources held by the client."""
        self._connection_id = None
        self._connection_time = 0.0

    def __enter__(self) -> UDPTrackerClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()