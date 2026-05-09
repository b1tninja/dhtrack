"""
BEP-14: Local Service Discovery (LSD).

Provides a SSDP-like mechanism (HTTP over UDP multicast) to announce the presence
of specific swarms to local neighbors. Clients can use this either as a primary
peer source for local transfers or to complement other sources operating on global
unicast addresses.

Multicast Groups
----------------
- IPv4: 239.192.152.143:6771 (org-local)
- IPv6: [ff15::efc0:988f]:6771 (site-local)

Message Format
--------------
    BT-SEARCH * HTTP/1.1\\r\\n
    Host: <host>\\r\\n
    Port: <port>\\r\\n
    Infohash: <ihash>\\r\\n
    cookie: <cookie (optional)>\\r\\n
    \\r\\n

Usage
-----
- Send an announce every 5 minutes on each interface while participating in a swarm.
- Send no more than 1 announce per minute to avoid multicast storms.
- On receiving an announce, determine the remote client's IP from the UDP source address.
"""

from __future__ import annotations

import binascii
import logging
import os
import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BEP-14 Constants
# ---------------------------------------------------------------------------

# Multicast addresses
LSD_MULTICAST_V4 = "239.192.152.143"
LSD_MULTICAST_V6 = "ff15::efc0:988f"
LSD_PORT = 6771

# announce timing
LSD_ANNOUNCE_INTERVAL = 300  # 5 minutes in seconds (while participating in a swarm)
LSD_MIN_ANNOUNCE_INTERVAL = 60  # 60 seconds between announces (rate limit)
LSD_MAX_PACKET_SIZE = 1400  # Max packet size to avoid MTU fragmentation
LSD_DEFAULT_TTL = 1  # Default TTL for multicast packets

# ---------------------------------------------------------------------------
# LSD Packet Format
# ---------------------------------------------------------------------------


@dataclass
class LSDAnnouncement:
    """Represents a BEP-14 LSD announcement message.

    Attributes
    ----------
    host : str
        The multicast group address this was sent to.
    port : int
        The BitTorrent client listening port.
    infohashes : list[bytes]
        List of 20-byte infohashes being announced.
    cookie : str or None
        Optional opaque cookie to filter out own announces.
    source_ip : str or None
        The source IP address (set when parsing received messages).
    source_port : int or None
        The source port (set when parsing received messages).
    is_ipv6 : bool
        Whether this announcement uses IPv6 multicast.
    """

    host: str
    port: int
    infohashes: list[bytes] = field(default_factory=list)
    cookie: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    is_ipv6: bool = False

    def to_bytes(self) -> bytes:
        """Encode the announcement as an UDP packet.

        Returns
        -------
        bytes
            The BEP-14 LSD announcement packet.
        """
        lines = ["BT-SEARCH * HTTP/1.1"]
        lines.append(f"Host: {self.host}")
        lines.append(f"Port: {self.port}")

        for ih in self.infohashes:
            lines.append(f"Infohash: {ih.hex()}")

        if self.cookie:
            lines.append(f"cookie: {self.cookie}")

        lines.append("")  # Empty line to terminate headers
        lines.append("")  # Final CRLF

        return "\r\n".join(lines).encode("latin-1")

    @staticmethod
    def from_bytes(data: bytes, source_ip: str, source_port: int) -> LSDAnnouncement | None:
        """Parse an LSD announcement from a UDP packet.

        Parameters
        ----------
        data : bytes
            The raw UDP payload.
        source_ip : str
            The source IP address of the packet.
        source_port : int
            The source port of the packet.

        Returns
        -------
        LSDAnnouncement or None
            The parsed announcement, or None if the data is invalid.
        """
        try:
            text = data.decode("latin-1").strip()
        except Exception:
            return None

        lines = text.split("\r\n")
        if not lines:
            return None

        # Check the first line for the BT-SEARCH method
        first_line = lines[0]
        if not first_line.startswith("BT-SEARCH "):
            return None

        announcement = LSDAnnouncement(
            host="",
            port=0,
            source_ip=source_ip,
            source_port=source_port,
        )

        # Parse headers
        for line in lines[1:]:
            line = line.strip()
            if not line:
                break

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "host":
                    announcement.host = value
                    # Determine if IPv4 or IPv6 multicast
                    if ":" in value:
                        announcement.is_ipv6 = True
                    else:
                        announcement.is_ipv6 = False
                elif key == "port":
                    try:
                        announcement.port = int(value)
                    except ValueError:
                        return None
                elif key == "infohash":
                    try:
                        ih_bytes = bytes.fromhex(value)
                        if len(ih_bytes) == 20:
                            announcement.infohashes.append(ih_bytes)
                    except ValueError:
                        logger.debug("Invalid infohash hex in LSD announce: %s", value)
                elif key == "cookie":
                    announcement.cookie = value

        return announcement

    def __repr__(self) -> str:
        ih_count = len(self.infohashes)
        return (
            f"LSDAnnouncement(host={self.host!r}, port={self.port}, "
            f"infohashes={ih_count}, src={self.source_ip}:{self.source_port})"
        )


# ---------------------------------------------------------------------------
# LSD Config
# ---------------------------------------------------------------------------


@dataclass
class LSDConfig:
    """Configuration for the LSD (BEP-14) module.

    Attributes
    ----------
    listen_port : int
        The BitTorrent client listening port (advertised in announces).
    infohashes : list[bytes]
        Infohashes to announce participation in.
    cookie : str or None
        Opaque cookie for filtering own announces. If None, a random cookie
        is generated automatically.
    multicast_interface : str or None
        Network interface to use for multicast. If None, uses the default.
    ttl : int
        TTL for multicast packets. Default is 1 (link-local).
    enabled : bool
        Whether LSD is enabled.
    """

    listen_port: int = 6881
    infohashes: list[bytes] = field(default_factory=list)
    cookie: str | None = None
    multicast_interface: str | None = None
    ttl: int = 1
    enabled: bool = True

    def __post_init__(self) -> None:
        """Generate a random cookie if not provided."""
        if self.cookie is None:
            self.cookie = binascii.hexlify(os.urandom(16)).decode("ascii")


# ---------------------------------------------------------------------------
# LSD Manager
# ---------------------------------------------------------------------------


class LSDManager:
    """Manages LSD (BEP-14) announce/send operations and received announce parsing.

    The LSDManager handles:
    - Creating and sending periodic LSD announcements via UDP multicast
    - Receiving and parsing incoming LSD announcements from the network
    - Rate limiting announces to avoid multicast storms
    - Filtering out the client's own announces via cookie matching

    Parameters
    ----------
    config : LSDConfig
        LSD configuration.
    on_announcement_received : callable, optional
        Callback invoked when a valid LSD announcement is received.
        Signature: callback(announcement: LSDAnnouncement) -> None
    """

    def __init__(
        self,
        config: LSDConfig | None = None,
        on_announcement_received: Callable[[LSDAnnouncement], None] | None = None,
    ) -> None:
        self.config = config or LSDConfig()
        self.on_announcement_received = on_announcement_received
        self._sock_v4: socket.socket | None = None
        self._sock_v6: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Timing
        self._last_announce_time: float = 0.0
        self._last_multicast_group: str | None = None

        # BEP 27: infohashes for private torrents — never announced, never accepted
        self._private_infohashes: set[bytes] = set()

        # Peer discovery results: (ip, port, infohash) -> timestamp
        self._discovered_peers: dict[tuple[str, int, bytes], float] = {}

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Whether the LSD manager is currently running."""
        return self._running

    def start(self) -> bool:
        """Start the LSD manager.

        Opens UDP sockets for multicast receive (and send) on both IPv4
        and IPv6 multicast groups.

        Returns
        -------
        bool
            True if started successfully, False otherwise.
        """
        with self._lock:
            if self._running:
                return True

        try:
            if self.config.enabled:
                self._create_sockets()
                self._running = True

                # Start the read loop in a background thread
                if self._sock_v4 or self._sock_v6:
                    self._thread = threading.Thread(
                        target=self._read_loop,
                        daemon=True,
                        name="lsd-reader",
                    )
                    self._thread.start()

                    logger.info("LSD manager started (IPv4=%s, IPv6=%s)", bool(self._sock_v4), bool(self._sock_v6))
                    return True

        except OSError as exc:
            logger.error("Failed to create LSD sockets: %s", exc)
            self._running = False

        return False

    def stop(self) -> None:
        """Stop and close the LSD manager."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        # Close sockets
        if self._sock_v4:
            try:
                self._sock_v4.close()
            except OSError:
                pass
            self._sock_v4 = None

        if self._sock_v6:
            try:
                self._sock_v6.close()
            except OSError:
                pass
            self._sock_v6 = None

        # Wait for read thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

        logger.info("LSD manager stopped")

    def update_infohashes(self, infohashes: list[bytes]) -> None:
        """Update the list of announced infohashes.

        Parameters
        ----------
        infohashes : list[bytes]
            New list of 20-byte infohashes to announce.
        """
        with self._lock:
            self.config.infohashes = [ih for ih in infohashes if len(ih) == 20]

    def set_private(self, info_hash: bytes, private: bool) -> None:
        """Mark or unmark an infohash as belonging to a private torrent (BEP 27).

        Private infohashes are silently excluded from outbound LSD announces and
        from inbound peer-discovery results, per BEP 27.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash to mark.
        private : bool
            True to suppress LSD for this hash; False to restore normal behaviour.
        """
        with self._lock:
            if private:
                self._private_infohashes.add(info_hash)
            else:
                self._private_infohashes.discard(info_hash)

    def send_announcement(self, infohashes: list[bytes] | None = None) -> None:
        """Send an LSD announcement for the given infohashes.

        If infohashes is None, uses the configured infohashes.

        Parameters
        ----------
        infohashes : list[bytes] or None
            Infohashes to announce. If None, uses self.config.infohashes.
        """
        if not self._running:
            return

        # Rate limiting: no more than 1 announce per minute
        now = time.time()
        with self._lock:
            if self._last_announce_time > 0:
                elapsed = now - self._last_announce_time
                if elapsed < LSD_MIN_ANNOUNCE_INTERVAL:
                    logger.debug(
                        "LSD announce rate limited (%.1f seconds since last)",
                        elapsed,
                    )
                    return
            self._last_announce_time = now

        announce_hashes = infohashes or self.config.infohashes
        # BEP 27: exclude private-torrent infohashes from LSD announces
        with self._lock:
            private = self._private_infohashes.copy()
        announce_hashes = [ih for ih in announce_hashes if ih not in private]
        if not announce_hashes:
            return

        # Build announcement
        announcement = LSDAnnouncement(
            host=LSD_MULTICAST_V4,
            port=self.config.listen_port,
            infohashes=announce_hashes,
            cookie=self.config.cookie,
        )

        # Send via IPv4 multicast
        self._send_multicast(announcement, is_ipv6=False)

        # Also send via IPv6 if available
        if self._sock_v6:
            announcement_v6 = LSDAnnouncement(
                host=LSD_MULTICAST_V6,
                port=self.config.listen_port,
                infohashes=announce_hashes,
                cookie=self.config.cookie,
                is_ipv6=True,
            )
            self._send_multicast(announcement_v6, is_ipv6=True)

        logger.debug("LSD announcement sent for %d infohashes", len(announce_hashes))

    def get_discovered_peers(self) -> list[tuple[str, int, bytes]]:
        """Get all peers discovered via LSD.

        Returns
        -------
        list of (ip, port, infohash) tuples
        """
        now = time.time()
        # Filter out old discoveries (> 10 minutes)
        cutoff = now - 600
        with self._lock:
            self._discovered_peers = {k: v for k, v in self._discovered_peers.items() if v >= cutoff}
        return list(self._discovered_peers.keys())

    # -------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------

    def _create_sockets(self) -> None:
        """Create UDP multicast sockets for receiving announcements."""
        # IPv4 socket
        try:
            sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock_v4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_v4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.config.ttl)
            # Join multicast group
            mreq = socket.inet_aton(LSD_MULTICAST_V4) + struct.pack("!I", 0)
            sock_v4.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock_v4.bind(("", LSD_PORT))
            self._sock_v4 = sock_v4
        except OSError as exc:
            logger.warning("Failed to create IPv4 LSD socket: %s", exc)
            self._sock_v4 = None

        # IPv6 socket
        try:
            sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock_v6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Join multicast group for site-local
            mreq6 = struct.pack("@16sI", socket.inet_pton(socket.AF_INET6, LSD_MULTICAST_V6), 0)
            sock_v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
            sock_v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_ADD_MEMBERSHIP, mreq6)
            sock_v6.bind(("::", LSD_PORT, 0, 0))
            self._sock_v6 = sock_v6
        except OSError as exc:
            logger.warning("Failed to create IPv6 LSD socket: %s", exc)
            self._sock_v6 = None

    def _send_multicast(self, announcement: LSDAnnouncement, is_ipv6: bool) -> None:
        """Send an LSD announcement via UDP multicast.

        Parameters
        ----------
        announcement : LSDAnnouncement
            The announcement to send.
        is_ipv6 : bool
            Whether to use IPv6.
        """
        packet = announcement.to_bytes()
        if len(packet) > LSD_MAX_PACKET_SIZE:
            logger.warning("LSD announcement too large (%d bytes), truncating", len(packet))
            # Truncate infohashes to fit
            announcement.infohashes = announcement.infohashes[:1]
            packet = announcement.to_bytes()

        target_ip = LSD_MULTICAST_V6 if is_ipv6 else LSD_MULTICAST_V4
        target_port = LSD_PORT

        sock = self._sock_v6 if is_ipv6 else self._sock_v4
        if sock is None:
            return

        try:
            sock.sendto(packet, (target_ip, target_port, 0, 0) if is_ipv6 else (target_ip, target_port))
        except OSError as exc:
            logger.debug("Failed to send LSD announcement: %s", exc)

    def _read_loop(self) -> None:
        """Main read loop for LSD multicast receive."""
        import select

        sockets = [s for s in (self._sock_v4, self._sock_v6) if s is not None]
        if not sockets:
            return

        while self._running:
            try:
                ready_read, _, _ = select.select(sockets, [], [], 1.0)
                for sock in ready_read:
                    try:
                        data, addr = sock.recvfrom(4096)
                        if isinstance(addr, tuple) and len(addr) == 2:
                            # IPv4: (host, port)
                            source_ip = addr[0]
                            source_port = addr[1]
                            is_ipv6 = False
                        elif isinstance(addr, tuple) and len(addr) == 4:
                            # IPv6: (host, port, flowinfo, scopeid)
                            source_ip = addr[0]
                            source_port = addr[1]
                            is_ipv6 = True
                        else:
                            continue

                        self._handle_packet(data, source_ip, source_port, is_ipv6)
                    except OSError as exc:
                        if self._running:
                            logger.debug("Error reading from LSD socket: %s", exc)
            except OSError:
                break

    def _handle_packet(
        self,
        data: bytes,
        source_ip: str,
        source_port: int,
        is_ipv6: bool,
    ) -> None:
        """Handle a received LSD announcement packet.

        Parameters
        ----------
        data : bytes
            The raw UDP payload.
        source_ip : str
            Source IP address.
        source_port : int
            Source port.
        is_ipv6 : bool
            Whether the packet arrived over IPv6.
        """
        announcement = LSDAnnouncement.from_bytes(data, source_ip, source_port)
        if announcement is None:
            logger.debug("Invalid LSD announcement from %s:%d", source_ip, source_port)
            return

        # Filter out our own announcements
        if announcement.cookie and announcement.cookie == self.config.cookie:
            logger.debug("Skipping our own LSD announcement from multicast loopback")
            return

        logger.info("Received LSD announcement: %s", announcement)

        # BEP 27: drop any infohashes that belong to private torrents
        with self._lock:
            private = self._private_infohashes.copy()
        announcement.infohashes = [ih for ih in announcement.infohashes if ih not in private]
        if not announcement.infohashes:
            logger.debug("LSD announcement from %s contains only private infohashes; ignored", source_ip)
            return

        # Store discovered peer
        now = time.time()
        for ih in announcement.infohashes:
            key = (announcement.source_ip or "", announcement.port, ih)
            self._discovered_peers[key] = now

        # Invoke callback
        if self.on_announcement_received:
            try:
                self.on_announcement_received(announcement)
            except Exception:
                logger.exception("Error in LSD announcement callback")


# ---------------------------------------------------------------------------
# Convenience Function
# ---------------------------------------------------------------------------


def build_lsd_announce(
    port: int,
    infohashes: list[bytes],
    cookie: str | None = None,
) -> bytes:
    """Build a BEP-14 LSD announce packet.

    Parameters
    ----------
    port : int
        The BitTorrent listening port.
    infohashes : list[bytes]
        List of 20-byte infohashes to announce.
    cookie : str or None
        Optional cookie for filtering own announcements.

    Returns
    -------
    bytes
        The encoded LSD announce packet.
    """
    announcement = LSDAnnouncement(
        host=LSD_MULTICAST_V4,
        port=port,
        infohashes=infohashes,
        cookie=cookie,
    )
    return announcement.to_bytes()
