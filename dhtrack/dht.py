"""
DHT (Distributed Hash Table) client for the BitTorrent protocol.

Implements the Kademlia DHT protocol used by BitTorrent clients
to discover peers without centralized trackers.

This module provides:
- DHT node management (IPv4 and IPv6)
- Node discovery via find_node queries
- Peer storage and persistence
- K-bucket routing table (Kademlia)
- Token generation and validation for announce_peer
- Iterative closest-node search
"""

from __future__ import annotations

import asyncio
import binascii
import hashlib
import ipaddress
import logging
import os
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dhtrack import bencode as bencode_module

if TYPE_CHECKING:
    from dhtrack.torrent import Torrent

from dhtrack import dht_address
from dhtrack import quic as quic_module
from dhtrack.bep42 import generate_node_id as _bep42_generate_node_id
from dhtrack.bep42 import (
    is_address_exempt_from_bep42,
)
from dhtrack.bep42 import is_valid_node_id as _bep42_valid_node_id
from dhtrack.bloom_filter import BloomFilter
from dhtrack.dht_address import is_reserved_ipv6
from dhtrack.events import NullEventSink, ProtocolEventSink


@dataclass(frozen=True)
class PendingQuery:
    txid: bytes
    method: str
    args: dict[bytes, Any]
    sent_at: float
    peer_key: tuple[str, int]


@dataclass
class _GetPeersScrapeState:
    """Per-infohash scrape state for aggressively querying newly discovered DHT nodes."""

    q: deque[tuple[bytes, tuple[str, int], bool]] = field(default_factory=deque)
    enqueued: set[bytes] = field(default_factory=set)  # node_id set
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)


def _outgoing_krpc_wire_meta(
    data: bytes,
) -> tuple[str, str, dict[bytes, Any], str]:
    """Best-effort KRPC fields for outgoing datagrams not correlated via PendingQuery."""
    try:
        parsed = bencode_module.decode(data)
    except Exception:
        return "unknown", "", {}, "unknown"
    if not isinstance(parsed, dict):
        return "unknown", "", {}, "unknown"
    t_raw = parsed.get(b"t")
    if isinstance(t_raw, bytes):
        txid_hex = t_raw.hex()
    elif isinstance(t_raw, str):
        txid_hex = t_raw.encode("latin-1").hex()
    else:
        txid_hex = ""
    y = parsed.get(b"y")
    if y == b"q":
        q = parsed.get(b"q")
        msg_type = q.decode("latin-1") if isinstance(q, bytes) else str(q or "unknown")
        a = parsed.get(b"a")
        query_args = a if isinstance(a, dict) else {}
        return msg_type, txid_hex, query_args, "q"
    if y == b"r":
        return "response", txid_hex, {}, "r"
    if y == b"e":
        return "error", txid_hex, {}, "e"
    return "unknown", txid_hex, {}, "unknown"


# Lazy import to avoid circular imports
_torrent_type = None


def _get_torrent_type():
    """Get the Torrent class without circular imports."""
    global _torrent_type
    if _torrent_type is None:
        from dhtrack.torrent import Torrent

        _torrent_type = Torrent
    return _torrent_type


logger = logging.getLogger(__name__)

# Wire-level datagram logger - use a separate logger for raw packet traces
wire_logger = logging.getLogger("dhtrack.wire")

MTU = 1438

# BEP 5 client version string identifier
CLIENT_VERSION = b"dh"
CLIENT_VERSION_STRING = "dh01"

K = 8  # Maximum number of nodes in a bucket / closest nodes
BUCKET_SIZE = K
# KRPC is UDP: responses can legitimately arrive a bit late on the public internet.
# Too-short pending TTL creates lots of "no matching txid" noise and drops late answers.
TIMEOUT = 8  # seconds before a query times out
# How many swarm (TCP) peers to retain per infohash from get_peers "values".
# Historically this was 20; raise default to improve metadata success rates.
PEERSTORE_MAX_PEERS_PER_INFOHASH_DEFAULT = 2500
# Pending-query limits (eviction uses oldest sent_at; TTL uses TIMEOUT above)
MAX_PENDING_PER_PEER = 64
MAX_PENDING_GLOBAL = 16384
REPLACEMENT_TIMEOUT = 600  # seconds before a replacement node is forgotten (10 minutes)
CONTACT_REFRESH_INTERVAL = 900  # 15 minutes in seconds
SECRET_ROTATION_INTERVAL = 300  # 5 minutes in seconds
TOKEN_MAX_AGE = 600  # 10 minutes in seconds

# Aggressive scraping: when get_peers returns DHT nodes, queue them for follow-up get_peers.
# These caps are intentionally conservative enough to avoid query storms while still
# meaningfully expanding the swarm during metadata retrieval.
GET_PEERS_SCRAPE_QPS = 32.0
GET_PEERS_SCRAPE_BURST = 64.0
GET_PEERS_SCRAPE_MAX_INFLIGHT = 64

# Startup warmup: ping a bounded set of persisted peers to quickly refresh liveness
# and converge routing table state without blasting the network.
WARMUP_PING_QPS = 20.0
WARMUP_PING_LIMIT = 128

DEFAULT_PEERS_FILE = "peers.dat"
# Stable DHT node identity (20-byte id); kept beside peers.dat by default.
DEFAULT_NODE_STATE_BASENAME = "dht_node.state"
# peers.dat v2: magic + per-node status/counters (legacy v1: 0x00/0x01 + 26/38 byte rows).
PEERS_FILE_MAGIC_V2 = b"DHT2"
NODE_STATE_MAGIC = b"DHTN"
NODE_STATE_VER = 1

DEFAULT_BOOTSTRAP_NODES: list[tuple[str, int]] = [
    ("router.utorrent.com", 6881),
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("dht.aelitis.com", 6881),
    ("download.deluge-torrent.org", 6881),
    ("ftp.osuosl.org", 6881),
]

# Fallback bootstrap nodes (known working DHT nodes with IP addresses)
FALLBACK_BOOTSTRAP_NODES: list[tuple[str, int]] = [
    ("89.109.220.223", 6881),  # router.bittorrent.com
    ("176.10.104.240", 6881),  # dht.aelitis.com
    ("209.20.73.195", 6881),  # dht.transmissionbt.com
]

# Caps how many persisted peers.dat entries are appended as bootstrap targets per family.
BOOTSTRAP_MAX_PEERS_FILE_TARGETS = 128

# BEP 42 top-level ``ip`` in KRPC responses: distinct responders required per observed address.
OBSERVED_IP_MIN_DISTINCT_RESPONDERS_DEFAULT = 3


def parse_krpc_observed_ip_field(raw: Any) -> tuple[str, int, bool] | None:
    """Parse BEP 42 top-level ``ip`` (compact requestor address as seen by responder).

    Returns ``(ip_str, port, is_ipv6)`` or None if malformed.
    """
    if not isinstance(raw, (bytes, bytearray)):
        return None
    raw = bytes(raw)
    if len(raw) == 6:
        ip_b, port_b = raw[:4], raw[4:6]
        try:
            ip_str = socket.inet_ntop(socket.AF_INET, ip_b)
            port = struct.unpack("!H", port_b)[0]
            return (ip_str, int(port), False)
        except OSError:
            return None
    if len(raw) == 18:
        ip_b, port_b = raw[:16], raw[16:18]
        try:
            ip_str = socket.inet_ntop(socket.AF_INET6, ip_b)
            port = struct.unpack("!H", port_b)[0]
            return (ip_str, int(port), True)
        except OSError:
            return None
    return None


def _xor_distance(a: bytes, b: bytes) -> int:
    """Compute XOR distance between two node IDs.

    BEP 5 specifies: distance(A,B) = |A xor B| (interpreted as unsigned integer).
    Smaller values are closer.

    Parameters
    ----------
    a : bytes
        First node ID (20 bytes).
    b : bytes
        Second node ID (20 bytes).

    Returns
    -------
    int
        The XOR distance as an integer.
    """
    if len(a) != 20 or len(b) != 20:
        raise ValueError("Node IDs must be 20 bytes")
    return int.from_bytes(bytes(x ^ y for x, y in zip(a, b, strict=False)), byteorder="big")


def _compact_node_encode(node_id: bytes, ip: str, port: int, is_ipv6: bool = False) -> bytes:
    """Encode node contact information in compact format.

    BEP 5: Compact node info = 20-byte node ID + 4-byte IPv4 (or 16-byte IPv6) + 2-byte port.

    Parameters
    ----------
    node_id : bytes
        20-byte node ID.
    ip : str
        IP address string.
    port : int
        Port number.
    is_ipv6 : bool
        Whether to use IPv6 encoding (38 bytes total).

    Returns
    -------
    bytes
        Compact node info string.
    """
    if len(node_id) != 20:
        raise ValueError("node_id must be 20 bytes")

    if is_ipv6:
        ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
    else:
        ip_bytes = socket.inet_aton(ip)

    return node_id + ip_bytes + struct.pack("!H", port)


def _compact_node_decode(data: bytes) -> tuple[bytes, str, int, bool]:
    """Decode compact node information.

    Parameters
    ----------
    data : bytes
        Compact node info (26 bytes for IPv4, 38 bytes for IPv6).

    Returns
    -------
    tuple[bytes, str, int, bool]
        (node_id, ip_address, port, is_ipv6)
    """
    if len(data) == 26:
        node_id = data[0:20]
        ip_bytes = data[20:24]
        port = struct.unpack("!H", data[24:26])[0]
        ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
        return node_id, ip, port, False
    elif len(data) == 38:
        node_id = data[0:20]
        ip_bytes = data[20:36]
        port = struct.unpack("!H", data[36:38])[0]
        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        return node_id, ip, port, True
    else:
        raise ValueError(f"Invalid compact node data length: {len(data)} (expected 26 or 38)")


def _compact_peer_encode(ip: str, port: int, is_ipv6: bool = False) -> bytes:
    """Encode peer contact information in compact format.

    BEP 5: Compact peer info = 4-byte IPv4 (or 16-byte IPv6) + 2-byte port.

    Parameters
    ----------
    ip : str
        IP address string.
    port : int
        Port number.
    is_ipv6 : bool
        Whether this is an IPv6 address.

    Returns
    -------
    bytes
        Compact peer info string (6 bytes for IPv4, 18 bytes for IPv6).
    """
    if is_ipv6:
        ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
        return ip_bytes + struct.pack("!H", port)
    else:
        ip_bytes = socket.inet_aton(ip)
        return ip_bytes + struct.pack("!H", port)


def _compact_peer_decode(data: bytes) -> tuple[str, int, bool]:
    """Decode compact peer information.

    Parameters
    ----------
    data : bytes
        Compact peer info (6 bytes for IPv4, 18 bytes for IPv6).

    Returns
    -------
    tuple[str, int, bool]
        (ip_address, port, is_ipv6)
    """
    if len(data) == 6:
        ip = socket.inet_ntop(socket.AF_INET, data[0:4])
        port = struct.unpack("!H", data[4:6])[0]
        return ip, port, False
    elif len(data) == 18:
        ip = socket.inet_ntop(socket.AF_INET6, data[0:16])
        port = struct.unpack("!H", data[16:18])[0]
        return ip, port, True
    else:
        raise ValueError(f"Invalid compact peer data length: {len(data)} (expected 6 or 18)")


# ---------------------------------------------------------------------------
# Token generation and validation (BEP 5)
# ---------------------------------------------------------------------------


class TokenSecret:
    """Manages a rotating secret for token generation.

    BEP 5: The secret rotates every 5 minutes. Tokens are accepted up to
    10 minutes old, meaning we must keep the previous secret available for
    validation during the overlap window.

    The token is SHA1(ip + secret)[:20] bytes.
    """

    def __init__(self) -> None:
        self._secrets: list[tuple[float, bytes]] = []  # (rotation_time, secret)
        self._rotate()

    def _rotate(self) -> None:
        """Generate a new secret and maintain the rotation history."""
        self._secrets.append((time.time(), os.urandom(20)))
        # Keep only the current and previous secret (10 minutes total)
        now = time.time()
        # Remove secrets older than TOKEN_MAX_AGE
        self._secrets = [(t, s) for t, s in self._secrets if now - t < TOKEN_MAX_AGE]

    def rotate_if_needed(self) -> None:
        """Rotate the secret if the rotation interval has elapsed."""
        now = time.time()
        if self._secrets:
            last_time = self._secrets[-1][0]
            if now - last_time >= SECRET_ROTATION_INTERVAL:
                self._rotate()

    def generate_token(self, ip: str) -> bytes:
        """Generate a token for the given IP address.

        BEP 5: "The BitTorrent implementation uses the SHA1 hash of the IP address
        concatenated onto a secret that changes every five minutes."

        Parameters
        ----------
        ip : str
            The IP address to generate a token for.

        Returns
        -------
        bytes
            The token (first 20 bytes of SHA1).
        """
        self.rotate_if_needed()
        # Use the most recent secret for token generation
        _, secret = self._secrets[-1]
        return hashlib.sha1(secret + ip.encode("ascii")).digest()[:20]

    def validate_token(self, token: bytes, ip: str) -> bool:
        """Validate a token against an IP address.

        BEP 5: "tokens up to ten minutes old are accepted."

        Parameters
        ----------
        token : bytes
            The token to validate (must be exactly 20 bytes).
        ip : str
            The IP address to validate against.

        Returns
        -------
        bool
            True if the token is valid and not too old.
        """
        if not token or len(token) != 20:
            return False

        self.rotate_if_needed()

        # Check all active secrets (current + previous)
        for rotation_time, secret in self._secrets:
            expected = hashlib.sha1(secret + ip.encode("ascii")).digest()[:20]
            if token == expected:
                # Ensure token is not older than TOKEN_MAX_AGE
                age = time.time() - rotation_time
                if age <= TOKEN_MAX_AGE:
                    return True
                # If the secret is too old, no need to check older ones
                break

        return False


# ---------------------------------------------------------------------------
# Peer store (BEP 5)
# ---------------------------------------------------------------------------


@dataclass
class StoredPeer:
    """A peer stored in the DHT peer store (for infohash lookups)."""

    ip: str
    port: int
    node_id: bytes | None = None
    is_ipv6: bool = False
    last_seen: float = field(default_factory=time.time)
    info_hash: bytes | None = None


class PeerStore:
    """Stores peer contact information keyed by infohash.

    BEP 5: Nodes store the IP address and port of peers under the infohash
    in response to announce_peer queries.

    BEP 33: Extended with seed tracking to support DHT scrapes via bloom
    filters.  Seeds and peers are tracked separately so that bloom filter
    responses (BFsd for seeds, BFpe for peers) can be generated accurately.
    """

    def __init__(
        self,
        *,
        max_entries: int = 10000,
        max_peers_per_infohash: int = PEERSTORE_MAX_PEERS_PER_INFOHASH_DEFAULT,
    ) -> None:
        # Set of unique <info_hash, ip> tuples for deduplication per BEP 33
        self._seen: dict[bytes, set[tuple[str, int]]] = defaultdict(set)
        self._store: dict[bytes, list[StoredPeer]] = defaultdict(list)
        self._max_entries = max_entries
        self._max_peers_per_infohash = max(1, int(max_peers_per_infohash))

    def add_peer(
        self,
        info_hash: bytes,
        ip: str,
        port: int,
        node_id: bytes | None = None,
        is_ipv6: bool = False,
        is_seed: bool = False,
    ) -> None:
        """Add a peer (or seed) for an infohash.

        Per BEP 33, <Infohash, IP> tuples must be unique in the database.
        Duplicate IP addresses for the same infohash are ignored (only
        the first metadata is retained).

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        ip : str
            Peer IP address.
        port : int
            Peer port.
        node_id : bytes, optional
            Peer node ID.
        is_ipv6 : bool
            Whether the IP is IPv6.
        is_seed : bool
            If True, store as a seed (BEP 33).  Seeds are tracked
            separately from peers for bloom filter scraping.
        """
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")

        # Enforce unique <info_hash, ip> per BEP 33
        dedup_key = (ip, port)
        if dedup_key in self._seen[info_hash]:
            return  # Already stored

        self._seen[info_hash].add(dedup_key)

        peer = StoredPeer(ip=ip, port=port, node_id=node_id, is_ipv6=is_ipv6)
        self._store[info_hash].append(peer)

        # Limit stored peers per infohash
        if len(self._store[info_hash]) > self._max_peers_per_infohash:
            trim = self._max_peers_per_infohash
            self._store[info_hash] = self._store[info_hash][-trim:]

    def add_peer_seed(
        self,
        info_hash: bytes,
        ip: str,
        port: int,
        node_id: bytes | None = None,
        is_ipv6: bool = False,
    ) -> None:
        """Add a seed for an infohash (BEP 33).

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        ip : str
            Seed IP address.
        port : int
            Seed port.
        node_id : bytes, optional
            Seed node ID.
        is_ipv6 : bool
            Whether the IP is IPv6.
        """
        self.add_peer(info_hash, ip, port, node_id=node_id, is_ipv6=is_ipv6, is_seed=True)

    def add_peer_item(
        self,
        info_hash: bytes,
        ip: str,
        port: int,
        node_id: bytes | None = None,
        is_ipv6: bool = False,
    ) -> None:
        """Add a peer item for an infohash (BEP 33).

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        ip : str
            Peer IP address.
        port : int
            Peer port.
        node_id : bytes, optional
            Peer node ID.
        is_ipv6 : bool
            Whether the IP is IPv6.
        """
        self.add_peer(info_hash, ip, port, node_id=node_id, is_ipv6=is_ipv6, is_seed=False)

    def get_peers(self, info_hash: bytes) -> list[StoredPeer]:
        """Get peers for an infohash.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.

        Returns
        -------
        list[StoredPeer]
            List of stored peers.
        """
        return list(self._store.get(info_hash, []))

    def get_seed_bloom_filter(self, info_hash: bytes) -> BloomFilter | None:
        """Generate a bloom filter for all stored seeds for an infohash (BEP 33).

        Returns
        -------
        BloomFilter | None
            A BloomFilter if seeds exist, None otherwise.
        """
        peers = self._store.get(info_hash, [])
        if not peers:
            return None

        bf = BloomFilter()
        for peer in peers:
            bf.insert_ip(peer.ip)
        return bf

    def get_peer_bloom_filter(self, info_hash: bytes) -> BloomFilter | None:
        """Generate a bloom filter for all stored peers for an infohash (BEP 33).

        Returns
        -------
        BloomFilter | None
            A BloomFilter if peers exist, None otherwise.
        """
        peers = self.get_peers(info_hash)
        if not peers:
            return None

        bf = BloomFilter()
        for peer in peers:
            bf.insert_ip(peer.ip)
        return bf

    def get_closest_peers(self, info_hash: bytes, count: int = K) -> list[StoredPeer]:
        """Get the closest peers to an infohash.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        count : int
            Maximum number of peers to return.

        Returns
        -------
        list[StoredPeer]
            List of closest peers.
        """
        peers = self.get_peers(info_hash)
        # Sort by distance to infohash
        peers.sort(key=lambda p: _xor_distance(info_hash, p.node_id or b"\x00" * 20))
        return peers[:count]

    def remove_peer(self, info_hash: bytes, ip: str, port: int) -> bool:
        """Remove a peer from the store.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        ip : str
            Peer IP address.
        port : int
            Peer port.

        Returns
        -------
        bool
            True if the peer was found and removed.
        """
        peers = self._store.get(info_hash, [])
        for i, peer in enumerate(peers):
            if peer.ip == ip and peer.port == port:
                peers.pop(i)
                self._seen[info_hash].discard((ip, port))
                return True
        return False


# ---------------------------------------------------------------------------
# K-bucket routing table (BEP 5 / Kademlia)
# ---------------------------------------------------------------------------


class NodeStatus:
    """Status of a node in the routing table."""

    GOOD = "good"
    QUESTIONABLE = "questionable"
    BAD = "bad"


def _default_node_state_path(peers_file: str) -> str:
    return str(Path(peers_file).with_name(DEFAULT_NODE_STATE_BASENAME))


def _load_node_identity(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            hdr = fh.read(4)
            if hdr != NODE_STATE_MAGIC:
                return None
            ver_b = fh.read(1)
            if not ver_b or ord(ver_b) != NODE_STATE_VER:
                return None
            fh.read(3)  # reserved
            nid = fh.read(20)
            if len(nid) != 20:
                return None
            return nid
    except OSError:
        return None


def _save_node_identity(path: str, node_id: bytes) -> None:
    if len(node_id) != 20:
        raise ValueError("node_id must be 20 bytes")
    tmp_path = path + ".tmp"
    payload = NODE_STATE_MAGIC + bytes([NODE_STATE_VER]) + b"\x00\x00\x00" + node_id
    with open(tmp_path, "wb") as fh:
        fh.write(payload)
    os.replace(tmp_path, path)


def _persist_status_byte(status: str) -> int:
    return {
        NodeStatus.GOOD: 0,
        NodeStatus.QUESTIONABLE: 1,
        NodeStatus.BAD: 2,
    }.get(status, 0)


def _persist_status_from_byte(b: int) -> str:
    return {
        0: NodeStatus.GOOD,
        1: NodeStatus.QUESTIONABLE,
        2: NodeStatus.BAD,
    }.get(int(b), NodeStatus.GOOD)


@dataclass
class BucketNode:
    """A node entry in a K-bucket."""

    node_id: bytes
    endpoint: Any
    status: str = NodeStatus.GOOD
    last_contacted: float = field(default_factory=time.time)
    failure_count: int = 0
    rpc_counter: int = 0  # Number of RPCs received (for good node detection)


class KBucket:
    """A single K-bucket containing up to K nodes."""

    def __init__(self, min_id: bytes = b"", max_id: bytes = b"") -> None:
        self.min_id: bytes = min_id
        self.max_id: bytes = max_id
        self.nodes: list[BucketNode] = []
        self.last_changed: float = time.time()

    @property
    def is_full(self) -> bool:
        return len(self.nodes) >= BUCKET_SIZE

    @property
    def good_nodes(self) -> list[BucketNode]:
        return [n for n in self.nodes if n.status == NodeStatus.GOOD]

    @property
    def questionable_nodes(self) -> list[BucketNode]:
        return [n for n in self.nodes if n.status == NodeStatus.QUESTIONABLE]

    @property
    def bad_nodes(self) -> list[BucketNode]:
        return [n for n in self.nodes if n.status == NodeStatus.BAD]

    def add_node(self, node: BucketNode) -> bool:
        """Add a node to this bucket.

        Returns True if the node was added, False if the bucket is full.
        """
        # Check for duplicates
        for existing in self.nodes:
            if existing.node_id == node.node_id:
                # Update existing node
                existing.endpoint = node.endpoint
                existing.status = node.status
                existing.last_contacted = node.last_contacted
                existing.rpc_counter += node.rpc_counter
                existing.failure_count = 0
                self.last_changed = time.time()
                return True

        if self.is_full:
            return False

        self.nodes.append(node)
        self.last_changed = time.time()
        return True

    def remove_node(self, node_id: bytes) -> None:
        """Remove a node from the bucket by node_id."""
        self.nodes = [n for n in self.nodes if n.node_id != node_id]
        self.last_changed = time.time()

    def mark_good(self, node_id: bytes) -> None:
        """Mark a node as good."""
        for node in self.nodes:
            if node.node_id == node_id:
                node.status = NodeStatus.GOOD
                node.failure_count = 0
                node.last_contacted = time.time()
                self.last_changed = time.time()
                break

    def mark_questionable(self, node_id: bytes) -> None:
        """Mark a node as questionable."""
        for node in self.nodes:
            if node.node_id == node_id:
                node.status = NodeStatus.QUESTIONABLE
                node.last_contacted = time.time()
                self.last_changed = time.time()
                break

    def mark_bad(self, node_id: bytes) -> None:
        """Mark a node as bad."""
        for node in self.nodes:
            if node.node_id == node_id:
                node.status = NodeStatus.BAD
                self.last_changed = time.time()
                break

    def increment_failure_count(self, node_id: bytes) -> None:
        """Increment the failure count for a node."""
        for node in self.nodes:
            if node.node_id == node_id:
                node.failure_count += 1
                if node.failure_count >= 3:
                    node.status = NodeStatus.BAD
                self.last_changed = time.time()
                break

    def increment_rpc_counter(self, node_id: bytes) -> None:
        """Increment the RPC counter for a node (received a query)."""
        for node in self.nodes:
            if node.node_id == node_id:
                node.rpc_counter += 1
                node.last_contacted = time.time()
                self.last_changed = time.time()
                break

    def get_nodes_to_ping(self) -> list[BucketNode]:
        """Get questionable nodes that need to be pinged, sorted by last_contacted (oldest first)."""
        questionable = sorted(self.questionable_nodes, key=lambda n: n.last_contacted)
        return questionable

    def get_closest_nodes(self, target: bytes, count: int = K) -> list[BucketNode]:
        """Get the closest nodes to a target ID."""

        def dist(node: BucketNode) -> int:
            return _xor_distance(target, node.node_id)

        return sorted(self.nodes, key=dist)[:count]

    def split(self) -> tuple[KBucket, KBucket]:
        """Split this bucket into two buckets at the midpoint.

        Returns
        -------
        tuple[KBucket, KBucket]
            The two new buckets.
        """
        # Find the most significant bit position where min and max differ
        mid_byte = 0
        mid_bit = 7
        for i in range(len(self.min_id)):
            diff = self.min_id[i] ^ self.max_id[i]
            if diff != 0:
                mid_byte = i
                mid_bit = diff.bit_length() - 1
                break

        mid_id = bytearray(self.min_id)
        # Set the bit at mid_bit to 1, and all following bits to 0
        mid_id[mid_byte] = self.min_id[mid_byte] | (1 << mid_bit)
        for i in range(mid_byte + 1, len(mid_id)):
            mid_id[i] = 0x00

        mid_id = bytes(mid_id)

        left_bucket = KBucket(self.min_id, mid_id)
        right_bucket = KBucket(mid_id, self.max_id)

        for node in self.nodes:
            if _xor_distance(self.min_id, node.node_id) <= _xor_distance(mid_id, node.node_id):
                left_bucket.nodes.append(node)
            else:
                right_bucket.nodes.append(node)

        left_bucket.last_changed = self.last_changed
        right_bucket.last_changed = self.last_changed

        return left_bucket, right_bucket


class RoutingTable:
    """Kademlia routing table with K-buckets.

    BEP 5: "The routing table is subdivided into buckets that each cover
    a portion of the [node ID] space."
    """

    def __init__(self, my_node_id: bytes) -> None:
        self.my_node_id: bytes = my_node_id
        self.buckets: list[KBucket] = [KBucket(b"\x00" * 20, b"\xff" * 20)]
        self._replacement_cache: dict[tuple[bytes, int], list[BucketNode]] = {}

    def find_bucket(self, node_id: bytes) -> KBucket:
        """Find the bucket that contains the given node ID."""
        for bucket in self.buckets:
            dist_min = _xor_distance(bucket.min_id, node_id)
            dist_max = _xor_distance(bucket.max_id, node_id)
            # Check if node_id is within [min_id, max_id] range
            # Using XOR distance from our node ID as reference
            our_dist_min = _xor_distance(self.my_node_id, bucket.min_id)
            our_dist_max = _xor_distance(self.my_node_id, bucket.max_id)
            if our_dist_min <= our_dist_max:
                if dist_min <= our_dist_max and dist_max >= our_dist_min:
                    # Check actual range
                    if self._id_in_range(node_id, bucket.min_id, bucket.max_id):
                        return bucket
            else:
                if not (dist_min > our_dist_max and dist_max < our_dist_min):
                    if self._id_in_range(node_id, bucket.min_id, bucket.max_id):
                        return bucket
        # Fallback: find closest bucket
        return self._closest_bucket(node_id)

    def _id_in_range(self, node_id: bytes, min_id: bytes, max_id: bytes) -> bool:
        """Check if node_id is in the range [min_id, max_id] based on distance from my_node_id."""
        dist_min = _xor_distance(self.my_node_id, node_id)
        dist_min_range = _xor_distance(self.my_node_id, min_id)
        dist_max_range = _xor_distance(self.my_node_id, max_id)
        return dist_min_range <= dist_min <= dist_max_range

    def _closest_bucket(self, node_id: bytes) -> KBucket:
        """Find the bucket closest to the given node ID."""
        return min(self.buckets, key=lambda b: _xor_distance(b.min_id, node_id))

    def add_node(self, node: BucketNode) -> bool:
        """Add a node to the routing table.

        Returns True if added, False if bucket is full.
        """
        bucket = self.find_bucket(node.node_id)
        if not bucket.add_node(node):
            # Bucket is full - check if we should replace
            if self._node_closer_to_me(node.node_id, bucket):
                # Try to find a replacement in the cache
                cache_key = (bucket.min_id, id(bucket))
                if cache_key in self._replacement_cache and self._replacement_cache[cache_key]:
                    replacement = self._replacement_cache[cache_key].pop(0)
                    bucket.remove_node(replacement.node_id)
                    bucket.add_node(node)
                    return True
                return False
            return False
        self._maybe_split_bucket(bucket)
        return True

    def _node_closer_to_me(self, node_id: bytes, bucket: KBucket) -> bool:
        """Check if a new node is closer to our node ID than any node in the bucket."""
        my_dist = _xor_distance(self.my_node_id, node_id)
        for n in bucket.nodes:
            if _xor_distance(self.my_node_id, n.node_id) < my_dist:
                return True
        return False

    def _maybe_split_bucket(self, bucket: KBucket) -> None:
        """Split a bucket if it's full and covers more than one bit level."""
        if bucket.is_full and len(self.buckets) < 256:
            # Check if the bucket range spans more than one bit
            min_dist = _xor_distance(self.my_node_id, bucket.min_id)
            max_dist = _xor_distance(self.my_node_id, bucket.max_id)
            if min_dist != max_dist or bucket.min_id != bucket.max_id:
                left, right = bucket.split()
                # Replace the bucket with the two new ones
                idx = self.buckets.index(bucket)
                self.buckets[idx] = left
                self.buckets.insert(idx + 1, right)

    def get_closest_nodes(self, target: bytes, count: int = K) -> list[BucketNode]:
        """Get the K closest nodes to a target ID from all buckets."""
        all_nodes: list[BucketNode] = []
        for bucket in self.buckets:
            all_nodes.extend(bucket.nodes)
        all_nodes.sort(key=lambda n: _xor_distance(target, n.node_id))
        return all_nodes[:count]

    def get_nodes_by_status(self, status: str) -> list[BucketNode]:
        """Get all nodes with a given status."""
        result = []
        for bucket in self.buckets:
            result.extend([n for n in bucket.nodes if n.status == status])
        return result

    def refresh_bucket(self, node_id: bytes) -> list[BucketNode]:
        """Refresh a bucket by finding nodes close to the given ID.

        Returns a list of nodes to query for refreshing.
        """
        return self.get_closest_nodes(node_id)

    def remove_node(self, node_id: bytes) -> None:
        """Remove a node from the routing table."""
        for bucket in self.buckets:
            bucket.remove_node(node_id)

    def mark_good(self, node_id: bytes) -> None:
        """Mark a node as good (no-op if unknown)."""
        bucket = self.find_bucket(node_id)
        bucket.mark_good(node_id)

    def mark_questionable(self, node_id: bytes) -> None:
        """Mark a node as questionable (no-op if unknown)."""
        bucket = self.find_bucket(node_id)
        bucket.mark_questionable(node_id)

    def mark_bad(self, node_id: bytes) -> None:
        """Mark a node as bad (no-op if unknown)."""
        bucket = self.find_bucket(node_id)
        bucket.mark_bad(node_id)

    def increment_rpc_counter(self, node_id: bytes) -> None:
        """Increment the RPC counter for a node (received a query)."""
        for bucket in self.buckets:
            for node in bucket.nodes:
                if node.node_id == node_id:
                    node.rpc_counter += 1
                    node.last_contacted = time.time()
                    bucket.last_changed = time.time()
                    return


class DualStackRoutingTable:
    """Facade over IPv4+IPv6 routing tables.

    This keeps address-family selection and routing-table API consistency in one place.
    Call sites should prefer this facade rather than reaching into buckets or keeping
    separate per-family routing-table references.
    """

    def __init__(self, my_node_id: bytes) -> None:
        self.v4: RoutingTable = RoutingTable(my_node_id)
        self.v6: RoutingTable = RoutingTable(my_node_id)

    def table_for(self, endpoint: Endpoint) -> RoutingTable:
        return self.v6 if endpoint.is_ipv6 else self.v4

    def table_for_family(self, is_ipv6: bool) -> RoutingTable:
        return self.v6 if is_ipv6 else self.v4

    def add_node(self, node: BucketNode) -> bool:
        return self.table_for(node.endpoint).add_node(node)

    def add_or_update(
        self,
        *,
        node_id: bytes,
        endpoint: Endpoint,
        status_hint: NodeStatus | None = None,
        last_contacted: float | None = None,
    ) -> bool:
        node = BucketNode(
            node_id=node_id,
            endpoint=endpoint,
            status=status_hint or NodeStatus.QUESTIONABLE,
            last_contacted=last_contacted if last_contacted is not None else time.time(),
        )
        return self.table_for(endpoint).add_node(node)

    def get_closest_nodes(
        self,
        target: bytes,
        count: int = K,
        *,
        endpoint_family: bool | None = None,
    ) -> list[BucketNode]:
        if endpoint_family is None:
            # Default: BEP-32 steady-state favors same-family results; callers that
            # truly want both should call per-family explicitly.
            return self.v4.get_closest_nodes(target, count)
        return self.table_for_family(endpoint_family).get_closest_nodes(target, count)

    def remove_node(self, *, node_id: bytes, endpoint: Endpoint) -> None:
        self.table_for(endpoint).remove_node(node_id)

    def remove_node_all_families(self, node_id: bytes) -> None:
        self.v4.remove_node(node_id)
        self.v6.remove_node(node_id)

    def increment_rpc_counter(self, *, node_id: bytes, endpoint: Endpoint) -> None:
        self.table_for(endpoint).increment_rpc_counter(node_id)

    def mark_good(self, *, node_id: bytes, endpoint: Endpoint) -> None:
        # Implemented on RoutingTable later in the refactor (wrapper around bucket).
        # For now, delegate through table selection; call sites should use facade.
        rt = self.table_for(endpoint)
        if hasattr(rt, "mark_good"):
            rt.mark_good(node_id)  # type: ignore[attr-defined]

    def mark_questionable(self, *, node_id: bytes, endpoint: Endpoint) -> None:
        rt = self.table_for(endpoint)
        if hasattr(rt, "mark_questionable"):
            rt.mark_questionable(node_id)  # type: ignore[attr-defined]

    def mark_bad(self, *, node_id: bytes, endpoint: Endpoint) -> None:
        rt = self.table_for(endpoint)
        if hasattr(rt, "mark_bad"):
            rt.mark_bad(node_id)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# KRPC Message helpers
# ---------------------------------------------------------------------------


def _encode_dht_query(method: str, args: dict[bytes, Any], transaction_id: bytes) -> bytes:
    """Encode a DHT query message per BEP 5.

    BEP 5: KRPC message with 't' (transaction ID), 'y' (type), 'q' (method),
    'a' (arguments), and optionally 'v' (version).

    Parameters
    ----------
    method : str
        The query method name (ping, find_node, get_peers, announce_peer).
    args : dict[bytes, Any]
        The query arguments including 'id'. Keys must be bytes.
    transaction_id : bytes
        The 2-byte transaction ID.

    Returns
    -------
    bytes
        BEncode-encoded KRPC message.
    """
    v_field = CLIENT_VERSION_STRING.encode("ascii") if isinstance(CLIENT_VERSION_STRING, str) else CLIENT_VERSION_STRING
    query: dict[bytes, Any] = {
        b"t": transaction_id,
        b"y": b"q",
        b"q": method.encode("ascii") if isinstance(method, str) else method,
        b"a": args,
        b"v": v_field,
    }
    return bencode_module.encode(query)


def _encode_dht_response(
    transaction_id: bytes,
    result: dict[bytes, Any],
    extra: dict[bytes, Any] | None = None,
) -> bytes:
    """Encode a DHT response message per BEP 5.

    Parameters
    ----------
    transaction_id : bytes
        The 2-byte transaction ID from the query.
    result : dict[bytes, Any]
        The result dictionary. Keys must be bytes.

    Returns
    -------
    bytes
        BEncode-encoded KRPC response message.
    """
    v_field = CLIENT_VERSION_STRING.encode("ascii") if isinstance(CLIENT_VERSION_STRING, str) else CLIENT_VERSION_STRING
    response: dict[bytes, Any] = {
        b"t": transaction_id,
        b"y": b"r",
        b"r": result,
        b"v": v_field,
    }
    if extra:
        response.update(extra)
    return bencode_module.encode(response)


def _encode_dht_error(transaction_id: bytes, error_code: int, error_message: str) -> bytes:
    """Encode a DHT error message per BEP 5.

    BEP 5 error codes:
        201: Generic Error
        202: Server Error
        203: Protocol Error (malformed arguments, or bad token)
        204: Method Unknown

    Parameters
    ----------
    transaction_id : bytes
        The 2-byte transaction ID from the query.
    error_code : int
        The error code.
    error_message : str
        The error message.

    Returns
    -------
    bytes
        BEncode-encoded KRPC error message.
    """
    error: dict[bytes, Any] = {
        b"t": transaction_id,
        b"y": b"e",
        b"e": [error_code, error_message],
    }
    return bencode_module.encode(error)


# ---------------------------------------------------------------------------
# DHTPeer
# ---------------------------------------------------------------------------


@dataclass
class DHTPeer:
    """Represents a peer in the DHT network.

    Attributes
    ----------
    node_id : bytes | None
        The 20-byte node ID, or None if not yet discovered.
    endpoint : Endpoint
        The network endpoint.
    dht_node : DHTNode
        Reference to the parent DHT node.
    queue : dict
        Pending RPC transaction queue.
    """

    dht_node: DHTNode
    endpoint: Endpoint
    node_id: bytes | None = None
    # Restored from peers.dat v2; excludes contact from bootstrap if BAD.
    persisted_rt_status: str | None = None
    queue: dict[bytes, PendingQuery] = field(default_factory=dict)
    last_seen: float = field(default_factory=lambda: time.time())
    # Set in query() immediately before write(); consumed once in write() for logging/GUI.
    _last_outgoing_pending: PendingQuery | None = field(default=None, repr=False)
    # Track recently handled txids so we can classify late/duplicate responses.
    # Note: UDP duplicates can arrive quite late (seconds to tens of seconds).
    # Keep this reasonably large so we can classify duplicates even under high query volume.
    _recent_handled_txids: deque[bytes] = field(default_factory=lambda: deque(maxlen=2048), repr=False)
    _recent_txid_overflow_last_log: float = field(default=0.0, repr=False)

    def _note_handled_txid(self, txid: bytes) -> None:
        """Record a handled txid and warn if the cache is saturated.

        This is best-effort observability: when we're handling more unique txids than
        the cache can retain, late UDP duplicates will be misclassified as "unmatched".
        """
        try:
            maxlen = int(getattr(self._recent_handled_txids, "maxlen", 0) or 0)
            if maxlen > 0 and len(self._recent_handled_txids) >= maxlen:
                now = time.time()
                # Rate limit to avoid log spam on very busy peers.
                if now - float(self._recent_txid_overflow_last_log or 0.0) > 5.0:
                    self._recent_txid_overflow_last_log = now
                    logger.warning(
                        "recent handled-txid cache saturated for %s (maxlen=%d). "
                        "Late UDP duplicates may be logged as unmatched; consider raising cache.",
                        self.endpoint,
                        maxlen,
                    )
        except Exception:
            pass
        self._recent_handled_txids.append(txid)

    def write(self, data: bytes) -> None:
        """Send data to this peer.

        Parameters
        ----------
        data : bytes
            The raw data to send.
        """
        if self.endpoint.is_ipv6:
            addr = f"[{self.endpoint.ip}]:{self.endpoint.port}"
        else:
            addr = f"{self.endpoint.ip}:{self.endpoint.port}"
        nid_e = binascii.b2a_hex(self.node_id).decode("ascii") if self.node_id else "unknown"
        logger.debug("Sending %d bytes to peer %s (node_id=%s)", len(data), addr, nid_e)

        pending = self._last_outgoing_pending
        self._last_outgoing_pending = None

        if pending is not None:
            msg_type = str(pending.method or "unknown")
            txid_hex = pending.txid.hex() if isinstance(pending.txid, bytes) else str(pending.txid)
            query_args = pending.args
            y_wire = "q"
            q_field = msg_type
        else:
            msg_type, txid_hex, query_args, y_wire = _outgoing_krpc_wire_meta(data)
            q_field = msg_type if y_wire == "q" else ""

        # Notify GUI about outgoing message
        if self.dht_node.event_sink is not None:
            try:
                self.dht_node.event_sink.on_outgoing_message(
                    msg_type, self.endpoint.ip, self.endpoint.port, self.endpoint.is_ipv6, len(data)
                )
            except Exception:
                logger.debug("Error in on_outgoing_message callback")

        # Also notify with full message details for the console (outgoing)
        if self.dht_node.event_sink is not None:
            try:
                self.dht_node.event_sink.on_message_parsed(
                    self.endpoint.ip,
                    self.endpoint.port,
                    self.endpoint.is_ipv6,
                    len(data),
                    {
                        "msg_type": msg_type,
                        "y": y_wire,
                        "q": q_field,
                        "t": txid_hex,
                        "direction": "outgoing",
                        "status": "sent",
                        "payload_snippet": "",
                    },
                )
            except Exception:
                logger.debug("Error in on_message_parsed callback")

        method = msg_type
        args_id = query_args.get(b"id", b"")
        node_id_hex = ""
        if isinstance(args_id, bytes) and len(args_id) == 20:
            node_id_hex = args_id.hex()

        sent = False
        actual_sock_family = socket.AF_INET6 if self.endpoint.is_ipv6 else socket.AF_INET

        try:
            # SocketManager handles family selection and loop/thread safety.
            # Normalize IPv4-mapped IPv6 destinations to IPv4.
            endpoint = self.endpoint
            if dht_address.is_ipv4_mapped(endpoint.ip):
                endpoint = Endpoint(ip=endpoint.ip, port=endpoint.port)
                actual_sock_family = socket.AF_INET
            self.dht_node.send_datagram(endpoint, data)
            sent = True
        except Exception as exc:
            logger.warning(
                "Failed to send to %s:%d (is_ipv6=%s): %s",
                self.endpoint.ip,
                self.endpoint.port,
                self.endpoint.is_ipv6,
                exc,
            )

        # Wire-level datagram logging
        if sent:
            is_v6_log = actual_sock_family == socket.AF_INET6
            self.dht_node._log_datagram(
                direction="OUT",
                data=data,
                addr=(self.endpoint.ip, self.endpoint.port),
                is_ipv6=is_v6_log,
                txid_hex=txid_hex,
                method=method,
                note=f"sock={actual_sock_family} nid={node_id_hex}",
            )

        if not sent:
            ipv4_mapped = dht_address.is_ipv4_mapped(self.endpoint.ip)
            logger.error(
                "Failed to send to %s:%d (is_ipv6=%s, ipv4_mapped=%s) - no working socket",
                self.endpoint.ip,
                self.endpoint.port,
                self.endpoint.is_ipv6,
                ipv4_mapped,
            )

    def _recv_normalized(self, data: bytes) -> None:
        """Process received data with raw bytes keys (no normalization).

        This is called from _handle_datagram with decoded data.

        Parameters
        ----------
        data : bytes
            The raw bencoded data.
        """
        parsed = bencode_module.decode(data)
        self._process_parsed_message(parsed)

    def recv(self, data: bytes) -> None:
        """Process received data from this peer.

        Parameters
        ----------
        data : bytes
            The raw received data.
        """
        if self.endpoint.is_ipv6:
            addr = f"[{self.endpoint.ip}]:{self.endpoint.port}"
        else:
            addr = f"{self.endpoint.ip}:{self.endpoint.port}"
        nid_e = binascii.b2a_hex(self.node_id).decode("ascii") if self.node_id else "unknown"
        logger.debug("Received %d bytes from peer %s (node_id=%s)", len(data), addr, nid_e)
        try:
            parsed = bencode_module.decode(data)
        except Exception:
            logger.debug("Failed to parse bencoded data from %s", addr)
            return

        self._process_parsed_message(parsed)

    def _process_parsed_message(self, parsed: dict) -> None:
        """Handle a parsed message with bytes keys (normalization may or may not have been applied).

        All bencode keys are bytes. No string decoding. Compare bytes to bytes.

        Parameters
        ----------
        parsed : dict
            The parsed BEncode message.
        """
        if self.endpoint.is_ipv6:
            addr = f"[{self.endpoint.ip}]:{self.endpoint.port}"
        else:
            addr = f"{self.endpoint.ip}:{self.endpoint.port}"

        y_val = parsed.get(b"y")
        if y_val == b"q":
            logger.debug("Processing query from %s: %s", addr, parsed.get(b"q"))
            self._handle_query(parsed)
        elif y_val == b"r":
            logger.debug("Processing response from %s (transaction: %s)", addr, parsed.get(b"t"))
            self._handle_response(parsed)
        elif y_val == b"e":
            error_val = parsed.get(b"e")
            error_info = error_val if isinstance(error_val, (bytes, str)) else b"unknown error"
            logger.debug("Error response from %s: %s", addr, error_info)
            self._handle_error_response(parsed)
        else:
            # The public DHT includes malformed traffic. Missing 'y' is a useful clue:
            # it means we *decoded* a dict but it doesn't conform to KRPC message shape.
            if y_val is None:
                t_val = parsed.get(b"t")
                if isinstance(t_val, bytes):
                    txid = t_val.hex()
                elif isinstance(t_val, str):
                    txid = t_val.encode("latin-1", "ignore").hex()
                else:
                    txid = "N/A"
                try:
                    keys = list(parsed.keys())
                except Exception:
                    keys = []
                logger.warning(
                    "Unknown KRPC message (missing y) from %s txid=%s keys=%r",
                    addr,
                    txid,
                    keys,
                )
            else:
                logger.warning("Unknown message type '%s' from %s", y_val, addr)

    def _handle_query(self, parsed: dict) -> None:
        """Handle an incoming query from a peer.

        BEP 5: Process ping, find_node, get_peers, and announce_peer queries.
        The 'v' (version) field is optional and may be used for client identification.

        Parameters
        ----------
        parsed : dict
            The parsed BEncode message.
        """
        if self.endpoint.is_ipv6:
            addr = f"[{self.endpoint.ip}]:{self.endpoint.port}"
        else:
            addr = f"{self.endpoint.ip}:{self.endpoint.port}"

        # All bencode keys are bytes; work with bytes directly
        query_type = parsed.get(b"q")
        if not isinstance(query_type, (bytes, str)):
            nid_e = binascii.b2a_hex(self.node_id).decode("ascii") if self.node_id else "unknown"
            logger.debug("Invalid query type from peer %s (node_id=%s)", addr, nid_e)
            return

        transaction_id = parsed.get(b"t")
        if not transaction_id or not isinstance(transaction_id, (bytes, str)):
            logger.debug("Missing or invalid transaction ID from peer %s", addr)
            return

        # Normalize transaction_id to bytes for dict key
        if isinstance(transaction_id, str):
            transaction_id = transaction_id.encode("latin-1")

        # Validate node ID length
        args = parsed.get(b"a", parsed.get(b"args", {}))
        if not isinstance(args, dict):
            args = {}
        query_id = args.get(b"id", args.get("id", b""))
        if isinstance(query_id, str):
            query_id = query_id.encode("latin-1")
        if len(query_id) != 20:
            logger.debug("Invalid node ID length from %s", self.endpoint)
            error_msg = _encode_dht_error(transaction_id, 203, "Invalid node ID")
            self.write(error_msg)
            return

        # Handle v field - log client version if present (BEP 5 optional)
        # We don't reject non-compliant clients based on version string

        if query_type in (b"ping", b"ping".decode()):
            nid_e = binascii.b2a_hex(self.node_id).decode("ascii") if self.node_id else "unknown"
            logger.debug("Processing ping query from peer %s (node_id=%s)", addr, nid_e)
            self._handle_ping(transaction_id, args)
        elif query_type in (b"find_node", b"find_node".decode()):
            target = args.get(b"target", b"")
            if isinstance(target, str):
                target = target.encode("latin-1")
            tgt_repr = binascii.b2a_hex(target).decode("ascii") if len(target) == 20 else "invalid"
            logger.debug(
                "Processing find_node query from peer %s for target %s",
                addr,
                tgt_repr,
            )
            self._handle_find_node(transaction_id, args)
        elif query_type in (b"get_peers", b"get_peers".decode()):
            info_hash = args.get(b"info_hash", b"")
            if isinstance(info_hash, str):
                info_hash = info_hash.encode("latin-1")
            ih_repr = binascii.b2a_hex(info_hash).decode("ascii") if len(info_hash) == 20 else "invalid"
            logger.debug(
                "Processing get_peers query from peer %s for infohash %s",
                addr,
                ih_repr,
            )
            self._handle_get_peers(transaction_id, args)
        elif query_type in (b"announce_peer", b"announce_peer".decode()):
            logger.debug("Processing announce_peer query from peer %s", addr)
            self._handle_announce_peer(transaction_id, args)
        else:
            nid_e = binascii.b2a_hex(self.node_id).decode("ascii") if self.node_id else "unknown"
            logger.debug(
                "Unknown query type '%s' from peer %s (node_id=%s)",
                query_type,
                addr,
                nid_e,
            )
            error_msg = _encode_dht_error(transaction_id, 204, f"Method {query_type} not found")
            self.write(error_msg)

        # Update node status - received a query
        self._mark_node_received_query()

    def _mark_node_received_query(self) -> None:
        """Mark this node as having received a query (for good node tracking).

        BEP 5: Increment the RPC counter to track that this node sent us a query.
        BEP 32: Use the correct routing table based on the peer's address family.
        """
        if self.node_id:
            self.dht_node.routing_table.increment_rpc_counter(
                node_id=self.node_id,
                endpoint=self.endpoint,
            )

    def _handle_ping(self, transaction_id: bytes, args: dict) -> None:
        """Handle a ping query.

        BEP 5: Response contains the responding node's ID.
        """
        response: dict[bytes, Any] = {b"id": self.dht_node.node_id}
        resp_bytes = _encode_dht_response(transaction_id, response)
        self.write(resp_bytes)

    def _handle_find_node(self, transaction_id: bytes, args: dict) -> None:
        """Handle a find_node query.

        BEP 5: Respond with the target node or K closest nodes to the target.
        BEP 32: Include nodes6 when the request includes 'n6' in want or
        the request came from IPv6.
        """
        from dhtrack.bep32 import WANT_N4, WANT_N6, parse_want

        target = args.get(b"target", b"")

        if len(target) != 20:
            error_msg = _encode_dht_error(transaction_id, 203, "Invalid target ID")
            self.write(error_msg)
            return

        # Determine response format per BEP-32
        want = parse_want(args)
        has_want = bool(want)

        if has_want:
            include_n4 = WANT_N4 in want
            include_n6 = WANT_N6 in want
        else:
            # Default: nodes for IPv4 requests, nodes6 for IPv6
            include_n4 = not self.endpoint.is_ipv6
            include_n6 = self.endpoint.is_ipv6

        response: dict[bytes, Any] = {b"id": self.dht_node.node_id}

        if include_n4:
            closest_nodes = self.dht_node.routing_table.v4.get_closest_nodes(target, K)
            logger.debug(
                "find_node response: target=%s, IPv4 closest=%d nodes, node_id=%s",
                binascii.b2a_hex(target).decode("ascii"),
                len(closest_nodes),
                binascii.b2a_hex(self.dht_node.node_id).decode("ascii"),
            )
            if closest_nodes:
                response[b"nodes"] = b"".join(
                    _compact_node_encode(
                        n.node_id,
                        n.endpoint.ip,
                        n.endpoint.port,
                        n.endpoint.is_ipv6,
                    )
                    for n in closest_nodes
                )
            else:
                response[b"nodes"] = b""
                logger.debug("find_node response: NO IPv4 nodes found for target, returning empty nodes")

        if include_n6:
            closest_nodes6 = self.dht_node.routing_table.v6.get_closest_nodes(target, K)
            if closest_nodes6:
                response[b"nodes6"] = b"".join(
                    _compact_node_encode(
                        n.node_id,
                        n.endpoint.ip,
                        n.endpoint.port,
                        n.endpoint.is_ipv6,
                    )
                    for n in closest_nodes6
                )
            else:
                response[b"nodes6"] = b""

        resp_bytes = _encode_dht_response(transaction_id, response)
        self.write(resp_bytes)

    def _handle_get_peers(self, transaction_id: bytes, args: dict) -> None:
        """Handle a get_peers query.

        BEP 5: Respond with peers for the infohash, or closest nodes if no peers,
        plus a token for announce_peer.

        BEP 32: Include nodes6 when the request includes 'n6' in want or
        the request came from IPv6.  Include nodes for IPv4 requests similarly.

        BEP 33: If scrape=1 is set, include bloom filter fields (BFsd, BFpe) in
        the response when database entries exist for the infohash.

        BEP 33: If noseed=1 is set, try to fill the values list with non-seed
        items on a best-effort basis.
        """
        from dhtrack.bep32 import WANT_N4, WANT_N6, parse_want

        info_hash = args.get(b"info_hash", b"")

        if len(info_hash) != 20:
            error_msg = _encode_dht_error(transaction_id, 203, "Invalid info_hash")
            self.write(error_msg)
            return

        # Check for scrape and noseed flags (BEP 33)
        scrape = args.get(b"scrape", 0)
        scrape = scrape == b"1" or scrape is True

        noseed = args.get(b"noseed", 0)
        noseed = noseed == b"1" or noseed is True

        # Generate token for this peer's IP
        token = self.dht_node.token_secret.generate_token(self.endpoint.ip)

        # Check our peer store for peers
        peers = self.dht_node.peer_store.get_peers(info_hash)

        response: dict[bytes, Any] = {b"id": self.dht_node.node_id, b"token": token}

        if scrape and peers:
            bf_seed = self.dht_node.peer_store.get_seed_bloom_filter(info_hash)
            bf_peer = self.dht_node.peer_store.get_peer_bloom_filter(info_hash)
            if bf_seed:
                response[b"BFsd"] = bf_seed.to_bytes()
            if bf_peer:
                response[b"BFpe"] = bf_peer.to_bytes()
        elif peers:
            values = []
            for peer in peers:
                peer_data = _compact_peer_encode(peer.ip, peer.port, peer.is_ipv6)
                values.append(peer_data)
            response[b"values"] = values
        else:
            # No peers - return node info based on BEP-32 rules
            want = parse_want(args)
            has_want = bool(want)

            if has_want:
                include_n4 = WANT_N4 in want
                include_n6 = WANT_N6 in want
            else:
                include_n4 = not self.endpoint.is_ipv6
                include_n6 = self.endpoint.is_ipv6

            if include_n4:
                closest_v4 = self.dht_node.routing_table.v4.get_closest_nodes(info_hash, K)
                if closest_v4:
                    response["nodes"] = b"".join(
                        _compact_node_encode(
                            n.node_id,
                            n.endpoint.ip,
                            n.endpoint.port,
                            n.endpoint.is_ipv6,
                        )
                        for n in closest_v4
                    )
                else:
                    response["nodes"] = b""

            if include_n6:
                closest_v6 = self.dht_node.routing_table.v6.get_closest_nodes(info_hash, K)
                if closest_v6:
                    response["nodes6"] = b"".join(
                        _compact_node_encode(
                            n.node_id,
                            n.endpoint.ip,
                            n.endpoint.port,
                            n.endpoint.is_ipv6,
                        )
                        for n in closest_v6
                    )
                else:
                    response["nodes6"] = b""

        resp_bytes = _encode_dht_response(transaction_id, response)
        self.write(resp_bytes)

    def _handle_announce_peer(self, transaction_id: bytes, args: dict) -> None:
        """Handle an announce_peer query.

        BEP 5: Store the peer's contact information under the infohash.
        Validates the token against the source IP address.
        Supports 'implied_port' for NAT traversal.

        BEP 33: If seed=1 is present, store as a seed.  Otherwise store
        as a peer.  Nodes should try to keep seeds+peers below 6000 to
        avoid bloom filter false positives approaching 1.0.
        """
        info_hash = args.get(b"info_hash", b"")

        token = args.get(b"token", b"")

        if len(info_hash) != 20:
            error_msg = _encode_dht_error(transaction_id, 203, "Invalid info_hash")
            self.write(error_msg)
            return

        # Validate token
        if not self.dht_node.token_secret.validate_token(token, self.endpoint.ip):
            error_msg = _encode_dht_error(transaction_id, 203, "Invalid token")
            self.write(error_msg)
            return

        # Check if this is a seed (BEP 33)
        is_seed = args.get(b"seed", 0)
        is_seed = is_seed == b"1" or is_seed is True

        # Determine port
        implied_port = args.get(b"implied_port", 0)
        if implied_port and implied_port != 0:
            port = self.endpoint.port
        else:
            port_arg = args.get(b"port")
            if port_arg is None:
                error_msg = _encode_dht_error(transaction_id, 203, "Missing port")
                self.write(error_msg)
                return
            port = int(port_arg)

        # Store as seed or peer based on seed flag (BEP 33)
        self.dht_node.peer_store.add_peer(
            info_hash=info_hash,
            ip=self.endpoint.ip,
            port=port,
            node_id=self.dht_node.node_id,
            is_ipv6=self.endpoint.is_ipv6,
            is_seed=is_seed,
        )

        logger.debug(
            "announce_peer: stored %s %s:%d for infohash %s",
            "SEED" if is_seed else "peer",
            self.endpoint.ip,
            port,
            binascii.b2a_hex(info_hash).decode("ascii"),
        )

        # Respond with just the node ID
        response: dict[bytes, Any] = {b"id": self.dht_node.node_id}
        resp_bytes = _encode_dht_response(transaction_id, response)
        self.write(resp_bytes)

    def _handle_error_response(self, parsed: dict) -> None:
        """Handle an incoming error response from a peer.

        BEP 5: Error responses have 'y'='e' and contain 't' (transaction ID)
        and 'e' (error list with code and message). The transaction ID is matched
        against pending queries in self.queue to correlate errors with queries.
        """
        try:
            transaction_id_raw = parsed.get(b"t")
            if not transaction_id_raw:
                logger.debug("Missing transaction ID in error response from %s", self.endpoint)
                return

            # Normalize transaction_id to bytes for dict key lookup
            if isinstance(transaction_id_raw, str):
                transaction_id_bytes = transaction_id_raw.encode("latin-1")
            else:
                transaction_id_bytes = transaction_id_raw

            # Try lookup with both bytes and string keys
            if transaction_id_bytes in self.queue:
                self.queue.pop(transaction_id_bytes)
            else:
                if isinstance(transaction_id_bytes, bytes):
                    transaction_id_str = transaction_id_bytes.decode("latin-1")
                else:
                    transaction_id_str = str(transaction_id_bytes)
                if transaction_id_str in self.queue:
                    self.queue.pop(transaction_id_str)
                else:
                    logger.debug(
                        "No matching transaction for error response from %s (txid=%r)",
                        self.endpoint,
                        transaction_id_bytes,
                    )
                    self.dht_node._increment_errors()
                    return

            # Increment error counter
            self.dht_node._increment_errors()

            # Log the error
            error_info = parsed.get(b"e", parsed.get("e", []))
            error_code = error_info[0] if isinstance(error_info, list) and len(error_info) >= 1 else 0
            error_msg = error_info[1] if isinstance(error_info, list) and len(error_info) >= 2 else "Unknown error"
            logger.warning(
                "Error response for query %s from %s: code=%s, msg=%s",
                transaction_id_bytes.hex(),
                self.endpoint,
                error_code,
                error_msg,
            )

        except Exception:
            logger.debug("Error handling error response from %s", self.endpoint)

    def _handle_response(self, parsed: dict) -> None:
        """Handle an incoming response from a peer.

        BEncoded messages have bytes keys. No normalization needed.

        BEP 5: Response messages have 'y'='r' and contain 't' (transaction ID)
        and 'r' (result dictionary). The transaction ID is matched against
        pending queries in self.queue to correlate responses with queries.
        """
        try:
            transaction_id_raw = parsed.get(b"t")
            if not transaction_id_raw:
                logger.debug("Missing transaction ID in response from %s", self.endpoint)
                return

            # Normalize transaction_id to bytes for dict key lookup
            if isinstance(transaction_id_raw, str):
                transaction_id_bytes = transaction_id_raw.encode("latin-1")
            else:
                transaction_id_bytes = transaction_id_raw

            # Debug: Log the response and available queue keys
            queue_keys_preview = list(self.queue.keys())[:5]
            queue_keys_types = [type(k).__name__ for k in queue_keys_preview]
            logger.debug(
                "_handle_response: txid=%r (type=%s), queue_keys_preview=%r (types=%s)",
                transaction_id_bytes,
                type(transaction_id_bytes).__name__,
                queue_keys_preview,
                queue_keys_types,
            )

            # Try both bytes and string keys for queue lookup
            if transaction_id_bytes in self.queue:
                q = self.queue[transaction_id_bytes]
                delete_key = transaction_id_bytes
                # Legacy test harnesses sometimes store dicts instead of PendingQuery.
                q_method = getattr(q, "method", None)
                if q_method is None and isinstance(q, dict):
                    q_method = q.get("q") or q.get("method")  # type: ignore[assignment]
                logger.debug(
                    "FOUND txid in queue (bytes key): txid=%s, query_type=%s",
                    transaction_id_bytes.hex(),
                    q_method,
                )
            else:
                # This is common on UDP: duplicates or late responses after TIMEOUT/eviction.
                if transaction_id_bytes in self._recent_handled_txids:
                    logger.debug(
                        "Duplicate response from %s (already handled txid=%s)",
                        self.endpoint,
                        transaction_id_bytes.hex(),
                    )
                else:
                    logger.debug(
                        "Unmatched response from %s (txid=%s, pending=%d). Likely late/evicted or unsolicited.",
                        self.endpoint,
                        transaction_id_bytes.hex(),
                        len(self.queue),
                    )
                return

            # Store query info before deletion for use in _process_response
            if hasattr(q, "method") and hasattr(q, "args"):
                query_type = q.method  # type: ignore[assignment]
                query_args = q.args  # type: ignore[assignment]
            elif isinstance(q, dict):
                query_type = q.get("q") or q.get("method") or ""
                query_args = q.get("a") or q.get("args") or {}
            else:
                query_type = ""
                query_args = {}
            del self.queue[delete_key]
            self._note_handled_txid(transaction_id_bytes)

            # Increment response counter
            self.dht_node._increment_responses()

            msg_type = parsed.get(b"y")
            if isinstance(msg_type, bytes):
                msg_type_str = msg_type.decode("latin-1")
            else:
                msg_type_str = str(msg_type) if msg_type else ""

            if msg_type_str == "r" or msg_type == b"r":
                self._process_response(query_type, query_args, parsed)
            else:
                logger.debug("Non-response message for transaction %s", transaction_id_bytes)

        except (KeyError, TypeError):
            logger.debug("Error handling response from %s", self.endpoint)

    def _note_krpc_observed_ip_field(self, outer: dict) -> None:
        """Consume BEP 42 top-level ``ip`` (compact address this peer saw for us)."""
        parsed_ip = parse_krpc_observed_ip_field(outer.get(b"ip"))
        if parsed_ip is None:
            return
        obs_ip, obs_port, obs_is_v6 = parsed_ip
        self.dht_node.record_dht_observed_address(obs_ip, obs_port, obs_is_v6, self)

    def _process_response(self, query_type: str, query_args: dict, response: dict) -> None:
        """Process a response to one of our queries.

        BEncoded messages have bytes keys. No normalization needed.
        """
        logger.debug(
            "Processing response from %s: q_type=%s, response_keys=%s",
            self.endpoint,
            query_type,
            list(response.keys()),
        )

        self._note_krpc_observed_ip_field(response)

        r = response.get(b"r", response.get("r", {}))

        # KRPC: responding node's id appears in every successful 'r' response (BEP 5).
        rid = r.get(b"id")
        if rid:
            if isinstance(rid, str):
                rid = rid.encode("latin-1")
            if isinstance(rid, bytes) and len(rid) == 20:
                self.node_id = rid
                self.last_seen = time.time()
                self.dht_node._mark_node_good(self)

        if query_type == "ping" or query_type == b"ping":
            if self.node_id:
                logger.debug(
                    "Ping response: node_id=%s, endpoint=%s",
                    binascii.b2a_hex(self.node_id).decode("ascii"),
                    self.endpoint,
                )

        elif query_type == "find_node" or query_type == b"find_node":
            nodes_data = r.get(b"nodes", b"")
            if isinstance(nodes_data, bytes) and len(nodes_data) >= 26:
                logger.debug(
                    "find_node response: %d bytes of IPv4 nodes from %s",
                    len(nodes_data),
                    self.endpoint,
                )
                self._parse_nodes(nodes_data, query_args)
            else:
                logger.debug(
                    "find_node response: empty/missing IPv4 nodes from %s",
                    self.endpoint,
                )

            nodes6_data = r.get(b"nodes6", b"")
            if isinstance(nodes6_data, bytes) and len(nodes6_data) >= 38:
                logger.debug(
                    "find_node response: %d bytes of IPv6 nodes from %s",
                    len(nodes6_data),
                    self.endpoint,
                )
                self._parse_ipv6_nodes(nodes6_data, query_args)
            else:
                logger.debug(
                    "find_node response: empty/missing IPv6 nodes from %s",
                    self.endpoint,
                )

        elif query_type == "get_peers" or query_type == b"get_peers":
            info_hash = query_args.get(b"info_hash", b"")
            if isinstance(info_hash, str):
                info_hash = info_hash.encode("latin-1")
            self._process_get_peers_response(response, info_hash=info_hash)

        elif query_type == "sample_infohashes" or query_type == b"sample_infohashes":
            self._process_sample_infohashes_response(response)

    def _process_get_peers_response(self, response: dict, info_hash: bytes = b"") -> None:
        """Process a get_peers response.

        BEncoded messages have bytes keys. No normalization needed.
        Handles:
        - values: list of compact peer info (BEP 5)
        - nodes: node info for follow-up queries (BEP 5/32)
        - token: for announce_peer (BEP 5)

        Parameters
        ----------
        response : dict
            The full parsed response including 'r' key.
        info_hash : bytes
            The 20-byte infohash (passed directly from _process_response to avoid
            looking up from a queue entry that may have been deleted).
        """
        r = response.get(b"r", {})

        # Collect peers from 'values' list
        values = r.get(b"values", [])
        if isinstance(values, list):
            for peer_data in values:
                if isinstance(peer_data, bytes) and len(peer_data) >= 6:
                    try:
                        ip, port, is_ipv6 = _compact_peer_decode(peer_data)
                        # Store this peer under the infohash
                        self.dht_node.peer_store.add_peer(
                            info_hash=info_hash,
                            ip=ip,
                            port=port,
                            is_ipv6=is_ipv6,
                        )
                        logger.debug(
                            "get_peers response: stored peer %s:%d for infohash %s",
                            ip,
                            port,
                            binascii.b2a_hex(info_hash).decode("ascii"),
                        )
                    except (OSError, ValueError):
                        continue

        # Parse nodes for follow-up get_peers queries
        nodes_data = r.get(b"nodes", b"")
        if isinstance(nodes_data, bytes) and len(nodes_data) >= 26:
            self._parse_nodes(
                nodes_data,
                {b"target": info_hash} if info_hash else {},
                followup="get_peers",
                info_hash=info_hash,
            )

        nodes6_data = r.get(b"nodes6", b"")
        if isinstance(nodes6_data, bytes) and len(nodes6_data) >= 38:
            self._parse_ipv6_nodes(
                nodes6_data,
                {b"target": info_hash} if info_hash else {},
                followup="get_peers",
                info_hash=info_hash,
            )

    def _process_sample_infohashes_response(self, response: dict) -> None:
        """Process a sample_infohashes response (BEP 51).

        BEncoded messages have bytes keys. No normalization needed.
        Records the ``interval`` field on DHTNode so the node can schedule
        the next re-query after the peer-specified delay.
        """
        r = response.get(b"r", {})
        samples = r.get(b"samples", b"")
        num = r.get(b"num", 0)
        interval = r.get(b"interval", 3600)
        if not isinstance(interval, int) or interval <= 0:
            interval = 3600

        if isinstance(samples, bytes) and len(samples) > 0:
            # Each infohash is 20 bytes
            infohash_count = len(samples) // 20
            infohashes = []
            for i in range(infohash_count):
                infohash = samples[i * 20 : (i + 1) * 20]
                if len(infohash) == 20:
                    infohashes.append(infohash)
            logger.debug(
                "sample_infohashes response: received %d infohashes (num=%d, interval=%d) from %s",
                len(infohashes),
                num,
                interval,
                self.endpoint,
            )
        else:
            infohashes = []
            logger.debug(
                "sample_infohashes response: no samples from %s (num=%d, interval=%d)",
                self.endpoint,
                num,
                interval,
            )

        # BEP 51: record the next permissible re-query timestamp for this peer
        key = (self.endpoint.ip, self.endpoint.port)
        self.dht_node._sample_next_at[key] = time.time() + interval

    def _parse_nodes(
        self,
        data: bytes,
        args: dict,
        *,
        followup: str = "find_node",
        info_hash: bytes = b"",
    ) -> None:
        """Parse node information from response data.

        BEncoded messages have bytes keys. No normalization needed.
        When the target is our own node_id, this means the responding node
        has propagated our node into its routing table - increment the counter.
        """
        target = args.get(b"target", args.get("target", b""))

        # Check if this response is for our own node_id (self-propagation confirmation)
        if self.dht_node.node_id and target == self.dht_node.node_id:
            for i in range(0, len(data), 26):
                if i + 26 > len(data):
                    break
                node_id = data[i : i + 20]
                if node_id == self.dht_node.node_id:
                    self.dht_node.self_node_id_response_count += 1
                    logger.info(
                        "bootstrap: self-node propagation confirmed - compact IPv4 nodes from %s:%d "
                        "include our node_id (such responses: %d)",
                        self.endpoint.ip,
                        self.endpoint.port,
                        self.dht_node.self_node_id_response_count,
                    )
                    break

        for i in range(0, len(data), 26):
            if i + 26 > len(data):
                break

            node_id = data[i : i + 20]
            ip = data[i + 20 : i + 24]
            port = struct.unpack("!H", data[i + 24 : i + 26])[0]

            try:
                ip_str = socket.inet_ntop(socket.AF_INET, ip)
            except OSError:
                continue

            if len(node_id) != 20:
                continue

            # BEP 42: transitional adoption — enforce only when explicitly enabled.
            if self.dht_node.enforce_bep42 and not _bep42_valid_node_id(node_id, ip_str):
                logger.debug(
                    "BEP 42: dropping node %s from %s (ID fails constraint)",
                    node_id.hex()[:8],
                    ip_str,
                )
                continue

            peer = self.dht_node.add_peer(node_id, ip_str, port)
            if peer and node_id:
                if followup == "get_peers":
                    if len(info_hash) == 20:
                        self.dht_node._enqueue_get_peers_scrape(peer, info_hash=info_hash)
                elif target:
                    # If this node is closer to target than our current node_id, query it
                    if _xor_distance(target, node_id) <= _xor_distance(target, self.node_id or b"\x00" * 20):
                        peer.find_node(target)

    def _parse_ipv6_nodes(
        self,
        data: bytes,
        args: dict,
        *,
        followup: str = "find_node",
        info_hash: bytes = b"",
    ) -> None:
        """Parse IPv6 node information from response data.

        BEncoded messages have bytes keys. No normalization needed.
        """
        target = args.get(b"target", args.get("target", b""))

        if self.dht_node.node_id and target == self.dht_node.node_id:
            for i in range(0, len(data), 38):
                if i + 38 > len(data):
                    break
                node_id = data[i : i + 20]
                if node_id == self.dht_node.node_id:
                    self.dht_node.self_node_id_response_count += 1
                    logger.info(
                        "bootstrap: self-node propagation confirmed - compact IPv6 nodes from %s:%d "
                        "include our node_id (such responses: %d)",
                        self.endpoint.ip,
                        self.endpoint.port,
                        self.dht_node.self_node_id_response_count,
                    )
                    break

        for i in range(0, len(data), 38):
            if i + 38 > len(data):
                break

            node_id = data[i : i + 20]
            ip_bytes = data[i + 20 : i + 36]
            port = struct.unpack("!H", data[i + 36 : i + 38])[0]

            try:
                ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            except OSError:
                continue

            if len(node_id) != 20:
                continue

            # BEP 42: transitional adoption — enforce only when explicitly enabled.
            if self.dht_node.enforce_bep42 and not _bep42_valid_node_id(node_id, ip_str):
                logger.debug(
                    "BEP 42: dropping IPv6 node %s from %s (ID fails constraint)",
                    node_id.hex()[:8],
                    ip_str,
                )
                continue

            peer = self.dht_node.add_peer(node_id, ip_str, port, is_ipv6=True)
            if peer and node_id:
                if followup == "get_peers":
                    if len(info_hash) == 20:
                        self.dht_node._enqueue_get_peers_scrape(peer, info_hash=info_hash)
                elif target:
                    if _xor_distance(target, node_id) <= _xor_distance(target, self.node_id or b"\x00" * 20):
                        peer.find_node(target)

    def respond(self, transaction_id: bytes, result: dict) -> None:
        """Send a response to a peer.

        Parameters
        ----------
        transaction_id : bytes
            The transaction ID to respond to.
        result : dict
            The result data to include in the response.
        """
        # BEP 42: include requestor's observed IP/port in top-level "ip" field.
        # This helps peers discover their external IP and derive a BEP42-compliant node ID.
        try:
            if self.endpoint.is_ipv6:
                ip_bytes = socket.inet_pton(socket.AF_INET6, self.endpoint.ip)
            else:
                ip_bytes = socket.inet_aton(self.endpoint.ip)
            ip_field = ip_bytes + struct.pack("!H", self.endpoint.port)
            extra = {b"ip": ip_field}
        except OSError:
            extra = None

        resp_bytes = _encode_dht_response(transaction_id, result, extra=extra)
        self.write(resp_bytes)

    def query(self, query_type: str, args: dict | None = None) -> bytes:
        """Send a query to this peer.

        BEP 5: Encodes a KRPC query message with transaction ID, method,
        arguments, and version string.

        Each query receives a unique 2-byte transaction ID. We draw high-entropy
        bytes and retry until the ID is not already pending for this endpoint.

        Parameters
        ----------
        query_type : str
            The query type (e.g., 'ping', 'find_node', 'get_peers', 'announce_peer').
        args : dict, optional
            The query arguments.

        Returns
        -------
        bytes
            The transaction ID.
        """
        args = args or {}
        args[b"id"] = self.dht_node.node_id

        # 2-byte wire transaction id; avoid reuse while an older entry is still pending.
        # Ensure we don't overwrite a still-pending query. If we collide repeatedly,
        # fall back to deterministic probing to guarantee we can always find a free slot.
        # (With 16-bit txids, collisions are rare but possible under high concurrency.)
        transaction_id = b""
        last = b""
        for _ in range(16):
            last = os.urandom(2)
            if last not in self.queue:
                transaction_id = last
                break
        if not transaction_id:
            # Fall back to deterministic probing across the txid space.
            base = int.from_bytes(last or b"\x00\x00", "big")
            for off in range(1 << 16):
                cand = ((base + off) & 0xFFFF).to_bytes(2, "big")
                if cand not in self.queue:
                    transaction_id = cand
                    break
            if not transaction_id:
                # This would mean the peer has 65,536 outstanding queries, which we never allow.
                raise RuntimeError("txid space exhausted for peer")

        query_bytes = _encode_dht_query(query_type, args, transaction_id)

        # Record the query sent
        self.dht_node._record_query_sent()

        pq = PendingQuery(
            txid=transaction_id,
            method=str(query_type),
            args=args,
            sent_at=time.time(),
            peer_key=(self.endpoint.ip, self.endpoint.port),
        )
        self.queue[transaction_id] = pq
        self._last_outgoing_pending = pq
        self.write(query_bytes)
        return transaction_id

    def ping(self) -> None:
        """Send a ping query to this peer."""
        self.query("ping")

    def find_node(self, target_id: bytes) -> None:
        """Send a find_node query for a target node ID.

        Parameters
        ----------
        target_id : bytes
            The 20-byte target node ID.
        """
        self.query("find_node", {b"target": target_id})

    def get_peers(self, info_hash: bytes) -> None:
        """Send a get_peers query for an infohash.

        BEP 5: Requests peers that have the given infohash.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        """
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")
        # BEP 32: request node contacts for both families when we have dual-stack transport.
        # This improves discovery when the local host can reach both IPv4 and IPv6 peers.
        args: dict[bytes, Any] = {b"info_hash": info_hash}
        try:
            from dhtrack.bep32 import WANT_N4, WANT_N6

            want: list[bytes] = [WANT_N4]
            if getattr(self.dht_node, "sock6", None) is not None:
                want.append(WANT_N6)
            args[b"want"] = want
        except Exception:
            pass
        self.query("get_peers", args)

    def sample_infohashes(self) -> None:
        """Send a sample_infohashes query (BEP 51).

        BEP 51: Requests a sample of infohashes that this node has in storage.
        """
        self.query("sample_infohashes", {b"target": self.dht_node.node_id})

    def __repr__(self) -> str:
        node_id_hex = binascii.b2a_hex(self.node_id).decode("ascii") if self.node_id else "UNKNOWN"
        return f"DHTPeer({node_id_hex} @ {self.endpoint})"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    """Network endpoint for a peer.

    Attributes
    ----------
    ip : str
        The IP address.
    port : int
        The port number.
    """

    ip: str
    port: int
    # Optional node ID when an endpoint is sourced from DHT/PEX contexts.
    node_id: bytes | None = None

    def __post_init__(self) -> None:
        # Normalize IPv4-mapped IPv6 addresses to IPv4 for consistent routing/I/O.
        addr = ipaddress.ip_address(self.ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            object.__setattr__(self, "ip", str(addr.ipv4_mapped))

    @property
    def is_ipv6(self) -> bool:
        return ipaddress.ip_address(self.ip).version == 6

    def __repr__(self) -> str:
        return f"Endpoint({self.ip}:{self.port})"


# ---------------------------------------------------------------------------
# SocketManager (asyncio)
# ---------------------------------------------------------------------------


class _DHTDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_datagram: Callable[[bytes, tuple], None]) -> None:
        self._on_datagram = on_datagram
        self.transport: asyncio.DatagramTransport | None = None
        self.last_send: tuple[str, int] | None = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        # Store transport so error_received can report socket family if needed.
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:  # type: ignore[override]
        self._on_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        fam = "unknown"
        try:
            if self.transport is not None:
                sock = self.transport.get_extra_info("socket")
                if sock is not None and hasattr(sock, "family"):
                    fam = str(sock.family)
        except Exception:
            pass

        if self.last_send is not None:
            logger.debug(
                "Datagram protocol error (fam=%s last_send=%s:%d): %s",
                fam,
                self.last_send[0],
                self.last_send[1],
                exc,
            )
        else:
            logger.debug("Datagram protocol error (fam=%s): %s", fam, exc)


class SocketManager:
    """Asyncio UDP socket manager for IPv4 + IPv6."""

    def __init__(
        self,
        *,
        bind_addr: tuple[str, int],
        on_datagram: Callable[[bytes, tuple], None],
    ) -> None:
        self._bind_addr = bind_addr
        self._on_datagram = on_datagram

        self.loop: asyncio.AbstractEventLoop | None = None
        self.transport_v4: asyncio.DatagramTransport | None = None
        self.transport_v6: asyncio.DatagramTransport | None = None
        self.protocol_v4: _DHTDatagramProtocol | None = None
        self.protocol_v6: _DHTDatagramProtocol | None = None

    async def start(self) -> None:
        if self.loop is None:
            self.loop = asyncio.get_running_loop()

        host, port = self._bind_addr

        # IPv6 transport (best-effort). Create this first on Windows to avoid
        # dual-stack binding edge-cases where AF_INET bind can block AF_INET6.
        if socket.has_ipv6:
            v6_host = host
            if v6_host in ("", "0.0.0.0"):
                v6_host = "::"
            try:
                transport_v6, proto_v6 = await self.loop.create_datagram_endpoint(
                    lambda: _DHTDatagramProtocol(self._on_datagram),
                    local_addr=(v6_host, port),
                    family=socket.AF_INET6,
                )
                self.transport_v6 = transport_v6  # type: ignore[assignment]
                self.protocol_v6 = proto_v6  # type: ignore[assignment]
            except OSError:
                logger.debug("IPv6 transport creation failed; continuing with IPv4 only")

        # IPv4 transport
        transport_v4, proto_v4 = await self.loop.create_datagram_endpoint(
            lambda: _DHTDatagramProtocol(self._on_datagram),
            local_addr=(host, port),
            family=socket.AF_INET,
        )
        self.transport_v4 = transport_v4  # type: ignore[assignment]
        self.protocol_v4 = proto_v4  # type: ignore[assignment]

    async def close(self) -> None:
        if self.transport_v4 is not None:
            self.transport_v4.close()
            self.transport_v4 = None
        self.protocol_v4 = None
        if self.transport_v6 is not None:
            self.transport_v6.close()
            self.transport_v6 = None
        self.protocol_v6 = None

    def local_endpoint_v4(self) -> Endpoint | None:
        if self.transport_v4 is None:
            return None
        sock = self.transport_v4.get_extra_info("socket")
        if sock is None:
            return None
        ip, port = sock.getsockname()[:2]
        return Endpoint(ip=str(ip), port=int(port))

    def local_endpoint_v6(self) -> Endpoint | None:
        if self.transport_v6 is None:
            return None
        sock = self.transport_v6.get_extra_info("socket")
        if sock is None:
            return None
        ip, port = sock.getsockname()[:2]
        return Endpoint(ip=str(ip), port=int(port))

    def send(self, endpoint: Endpoint, payload: bytes) -> None:
        """Send a datagram from within the owning event loop."""
        transport = self.transport_v6 if endpoint.is_ipv6 else self.transport_v4
        if transport is None:
            raise RuntimeError("SocketManager transport not started for this family")
        if endpoint.is_ipv6:
            if self.protocol_v6 is not None:
                self.protocol_v6.last_send = (endpoint.ip, endpoint.port)
        else:
            if self.protocol_v4 is not None:
                self.protocol_v4.last_send = (endpoint.ip, endpoint.port)
        # On Windows, AF_INET6 sendto expects a 4-tuple: (host, port, flowinfo, scopeid).
        # Passing a 2-tuple can raise WSAEINVAL (10022) and effectively breaks IPv6 DHT.
        if endpoint.is_ipv6:
            transport.sendto(payload, (endpoint.ip, endpoint.port, 0, 0))
        else:
            transport.sendto(payload, (endpoint.ip, endpoint.port))

    def send_threadsafe(self, endpoint: Endpoint, payload: bytes) -> None:
        """Thread-safe send; schedules onto the owning event loop."""
        if self.loop is None:
            raise RuntimeError("SocketManager not started")
        self.loop.call_soon_threadsafe(self.send, endpoint, payload)


def extract_gui_message_info_from_datagram(data: bytes) -> dict[str, Any]:
    """Summarize a bencoded KRPC datagram for GUI / Passive observation.

    For inbound ``y=q`` queries, extracts ``info_hash`` (``get_peers`` / ``announce_peer``)
    and ``target`` (``find_node``) from the ``a`` dict when present.

    Keys always present align with legacy console expectations; optional keys use
    empty string when absent: ``info_hash_hex``, ``find_node_target_hex``.
    """
    result: dict[str, Any] = {
        "msg_type": "unknown",
        "y": "",
        "q": "",
        "t": "",
        "direction": "incoming",
        "status": "",
        "payload_snippet": "",
        "info_hash_hex": "",
        "find_node_target_hex": "",
    }
    try:
        parsed = bencode_module.decode(data)
        if not isinstance(parsed, dict):
            result["payload_snippet"] = f"non_dict_after_decode({len(data)}bytes)"
            return result

        y = parsed.get(b"y")
        if isinstance(y, bytes):
            y = y.decode("latin-1")
        result["y"] = str(y) if y else ""

        q = parsed.get(b"q")
        if isinstance(q, bytes):
            q = q.decode("latin-1")
        result["q"] = str(q) if q else ""

        t = parsed.get(b"t")
        if isinstance(t, bytes):
            result["t"] = t.hex()
        elif isinstance(t, str):
            result["t"] = t

        if result["y"] == "r":
            result["status"] = "response"
            r = parsed.get(b"r")
            if isinstance(r, dict):
                nodes = r.get(b"nodes", b"")
                if isinstance(nodes, bytes) and len(nodes) >= 26:
                    node_count = len(nodes) // 26
                    result["payload_snippet"] = f"nodes={node_count}"
                nodes6 = r.get(b"nodes6", b"")
                if isinstance(nodes6, bytes) and len(nodes6) >= 38:
                    node6_count = len(nodes6) // 38
                    result["payload_snippet"] += f" nodes6={node6_count}"
                values = r.get(b"values", [])
                if isinstance(values, list) and len(values) > 0:
                    result["payload_snippet"] += f" values={len(values)}"
                elif not result["payload_snippet"]:
                    result["payload_snippet"] = "ok"
        elif result["y"] == "e":
            result["status"] = "error"
            e = parsed.get(b"e")
            if isinstance(e, list) and len(e) >= 2:
                result["payload_snippet"] = f"code={e[0]}, msg={e[1]}"
            else:
                result["payload_snippet"] = "error"
        elif result["y"] == "q":
            result["status"] = "query"
            result["payload_snippet"] = f"method={result['q']}"
            args = parsed.get(b"a")
            if isinstance(args, dict):
                iq = result["q"]

                ih = args.get(b"info_hash", b"")
                if isinstance(ih, str):
                    ih = ih.encode("latin-1")
                if isinstance(ih, bytes) and len(ih) == 20:
                    result["info_hash_hex"] = ih.hex()
                elif iq in ("get_peers", "announce_peer") and not result["info_hash_hex"]:
                    # tolerate missing / wrong length silently
                    pass

                if iq == "find_node":
                    tgt = args.get(b"target", b"")
                    if isinstance(tgt, str):
                        tgt = tgt.encode("latin-1")
                    if isinstance(tgt, bytes) and len(tgt) == 20:
                        result["find_node_target_hex"] = tgt.hex()

        if result["q"]:
            result["msg_type"] = result["q"]
        elif result["y"]:
            result["msg_type"] = result["y"]

    except Exception:
        result["payload_snippet"] = f"decode_error({len(data)}bytes)"

    return result


# ---------------------------------------------------------------------------
# DHTNode
# ---------------------------------------------------------------------------


class DHTNode:
    """DHT node that participates in the BitTorrent Kademlia network.

    Manages socket connections, peer discovery, and peer storage.
    Implements the full Kademlia routing table protocol per BEP 5 and BEP 32.

    Per BEP-27, a DHT node MUST NOT perform DHT operations (find_node,
    get_peers, announce_peer) for private torrents.

    Per BEP-32, this node maintains separate IPv4 and IPv6 DHT routing tables
    with independent query semantics. During steady-state operation, IPv4 nodes
    only exchange IPv4 node info and IPv6 nodes only exchange IPv6 node info,
    unless the requestor explicitly asks for both via the "want" parameter.

    Parameters
    ----------
    node_id : bytes, optional
        The 20-byte node ID. Generated randomly if not provided.
    bind_addr : tuple, optional
        The address to bind to (host, port). Defaults to ('', 0).
    peers_file : str, optional
        Path to the file for persisting known peers.
    state_file : str, optional
        Path for persisting our 20-byte ``node_id``. Defaults to ``dht_node.state``
        in the same directory as ``peers_file``.
    persist_node_identity : bool, optional
        If True (default), load/save ``node_id`` to ``state_file`` so restarts reuse
        the same DHT identity (pairs with persisted routers in ``peers.dat``).
    auto_align_bep42_node_id : bool, optional
        If True, after enough BEP 42 ``ip`` quorum samples agree on your public address,
        rotate ``node_id`` to a BEP-42-compliant ID when the current ID does not validate.
    observed_ip_min_distinct_responders : int
        Distinct DHT peers that must report the same observed ``(ip, port)`` before quorum.
    """

    def __init__(
        self,
        node_id: bytes | None = None,
        bind_addr: tuple[str, int] = ("", 0),
        peers_file: str = DEFAULT_PEERS_FILE,
        state_file: str | None = None,
        persist_node_identity: bool = True,
        auto_align_bep42_node_id: bool = True,
        observed_ip_min_distinct_responders: int = OBSERVED_IP_MIN_DISTINCT_RESPONDERS_DEFAULT,
        peerstore_max_peers_per_infohash: int = PEERSTORE_MAX_PEERS_PER_INFOHASH_DEFAULT,
    ) -> None:
        self.peers_file: str = peers_file
        self.persist_node_identity = bool(persist_node_identity)
        self.state_file: str = (
            (state_file or _default_node_state_path(peers_file)) if self.persist_node_identity else ""
        )

        resolved_id = node_id
        if resolved_id is None and self.persist_node_identity and self.state_file:
            loaded = _load_node_identity(self.state_file)
            if loaded is not None:
                resolved_id = loaded

        self.node_id: bytes = resolved_id if resolved_id is not None else os.urandom(20)
        self.auto_align_bep42_node_id: bool = bool(auto_align_bep42_node_id)
        self.observed_ip_min_distinct_responders: int = max(
            1,
            int(observed_ip_min_distinct_responders),
        )
        # BEP 42: transitional adoption — only enforce if explicitly enabled.
        self.enforce_bep42: bool = False
        # BEP-27: Private torrent enforcement flag
        # When True, all DHT operations are disabled (private torrents
        # must not use DHT, PEX, or LSD for peer discovery).
        self._private_mode: bool = False

        # BEP-32: routing tables are separate, but exposed via a single facade.
        self.routing_table: DualStackRoutingTable = DualStackRoutingTable(self.node_id)

        # Peer store for infohash -> peers mapping
        self.peer_store = PeerStore(max_peers_per_infohash=int(peerstore_max_peers_per_infohash))

        # Token secret for announce_peer
        self.token_secret = TokenSecret()

        # Peer contact table (for active peers we've communicated with)
        self.peers: dict[tuple[str, int], DHTPeer] = {}

        # Async I/O (asyncio-native; started explicitly via `await start()`)
        self._bind_addr: tuple[str, int] = bind_addr
        self.socket_manager: SocketManager | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._periodic_task: asyncio.Task | None = None

        # Peer persistence (throttled; avoid writing on every new peer)
        self._peers_dirty: bool = False
        self._last_peers_save: float = 0.0
        self.peers_save_interval: float = 30.0  # seconds
        self._routing_add_reject_count: int = 0

        # Response/query statistics counters (thread-safe via read loop)
        self._responses_received: int = 0
        self._queries_sent: int = 0
        self._queries_timed_out: int = 0
        self._errors_received: int = 0

        # BEP 51: next scheduled sample_infohashes time per peer endpoint
        # Key: (ip, port); value: unix timestamp after which we may re-query
        self._sample_next_at: dict[tuple[str, int], float] = {}

        # Aggressive get_peers scraping state (newly learned DHT nodes → get_peers(info_hash)).
        # Accessed from both recv thread and asyncio loop; protected by _scrape_lock.
        self._scrape_lock = threading.Lock()
        self._get_peers_scrape: dict[bytes, _GetPeersScrapeState] = {}

        # Unified event sink (GUI/CLI can provide an implementation)
        self.event_sink: ProtocolEventSink = NullEventSink()

        # BEP 42: observed external address from top-level ``ip`` in responses (voting).
        self._observed_ip_votes_v4: dict[tuple[str, int], set[tuple[str, int]]] = defaultdict(set)
        self._observed_ip_votes_v6: dict[tuple[str, int], set[tuple[str, int]]] = defaultdict(set)
        self.observed_external_v4: Endpoint | None = None
        self.observed_external_v6: Endpoint | None = None
        self._bep42_align_lock = threading.Lock()
        self._bep42_align_in_progress: bool = False

        # Underlying sockets (transitional compatibility; owned by SocketManager)
        self.sock: socket.socket | None = None
        self.sock6: socket.socket | None = None

        # Note: network I/O is started explicitly via `await start()`.

    # -------------------------------------------------------------------
    # Legacy test compatibility (routing_table_v4/v6)
    # -------------------------------------------------------------------

    @property
    def routing_table_v4(self) -> RoutingTable:
        """Legacy alias for the IPv4 routing table (tests / old call sites)."""
        return self.routing_table.v4

    @routing_table_v4.setter
    def routing_table_v4(self, value: RoutingTable) -> None:
        # Some tests construct DHTNode via __new__ and assign routing_table_v4/v6.
        # Create a facade on-demand if missing.
        if not hasattr(self, "routing_table"):
            self.routing_table = DualStackRoutingTable(self.node_id)
        self.routing_table.v4 = value

    @property
    def routing_table_v6(self) -> RoutingTable:
        """Legacy alias for the IPv6 routing table (tests / old call sites)."""
        return self.routing_table.v6

    @routing_table_v6.setter
    def routing_table_v6(self, value: RoutingTable) -> None:
        if not hasattr(self, "routing_table"):
            self.routing_table = DualStackRoutingTable(self.node_id)
        self.routing_table.v6 = value

    def _get_routing_table(self, is_ipv6: bool) -> RoutingTable:
        """Legacy helper used by older unit tests (BEP 32)."""
        return self.routing_table.v6 if is_ipv6 else self.routing_table.v4

    @property
    def is_private_mode(self) -> bool:
        """Check if DHT is disabled for private torrents (BEP-27).

        Returns
        -------
        bool
            True if DHT operations are restricted (private mode).

        Notes
        -----
        When True, the DHT node MUST NOT perform find_node, get_peers,
        or announce_peer queries.  This enforces BEP-27 which requires
        private torrents to only use the tracker for peer discovery.

        See BEP-27 for details:
        https://www.bittorrent.org/beps/bep_0027.html
        """
        return self._private_mode

    @is_private_mode.setter
    def is_private_mode(self, value: bool) -> None:
        """Enable or disable DHT operations for private torrents.

        Parameters
        ----------
        value : bool
            True to restrict DHT (private mode), False to allow all DHT ops.
        """
        self._private_mode = bool(value)

    def is_dht_allowed(self, info_hash: bytes | None = None) -> bool:
        """Check whether DHT operations are allowed.

        Per BEP-27, DHT is NOT allowed for private torrents.
        This method can be called before any DHT operation to verify
        that the operation is permitted.

        Parameters
        ----------
        info_hash : bytes, optional
            The 20-byte infohash of the torrent (unused in global mode,
            but included for API extensibility).

        Returns
        -------
        bool
            True if DHT operations are allowed, False otherwise.
        """
        return not self._private_mode

    def enforce_private_mode(self, torrent: Torrent | None = None) -> None:
        """Enable or disable private mode based on a torrent.

        Convenience method that checks whether the given torrent is
        private and sets the DHT enforcement accordingly.

        Per BEP-27, if *any* torrent being downloaded is private, the
        client MUST NOT use DHT for *any* torrent (since DHT is used
        to discover peers for all torrents, not just the private one).

        Parameters
        ----------
        torrent : Torrent, optional
            The torrent to check. If True is private, private mode
            is enabled. If None, private mode is disabled.
        """
        if torrent is not None and torrent.is_private:
            self._private_mode = True
        else:
            self._private_mode = False

    def get_observed_external_endpoints(
        self,
    ) -> tuple[Endpoint | None, Endpoint | None]:
        """Return ``(observed_ipv4, observed_ipv6)`` from BEP 42 ``ip`` quorum, if known."""
        return (self.observed_external_v4, self.observed_external_v6)

    def canonical_observed_ip_for_bep42(self) -> str | None:
        """Prefer public IPv4 quorum, else IPv6 (BEP 42 uses one ID for one IP string)."""
        if self.observed_external_v4 is not None:
            ip = self.observed_external_v4.ip
            if not is_address_exempt_from_bep42(ip):
                return ip
        if self.observed_external_v6 is not None:
            ip = self.observed_external_v6.ip
            if not is_address_exempt_from_bep42(ip):
                return ip
        return None

    def record_dht_observed_address(
        self,
        observed_ip: str,
        observed_port: int,
        observed_is_ipv6: bool,
        responder: DHTPeer,
    ) -> None:
        """Record one BEP 42 top-level ``ip`` sample (voting) and maybe align node_id.

        Note: external IP can change over time (Wi-Fi/VPN/NAT rebinding). We therefore
        allow *new* observed endpoints to reach quorum even after an earlier endpoint
        was latched, and update the observed endpoint when a different value wins.
        """
        if is_address_exempt_from_bep42(observed_ip):
            return
        try:
            ep_obs = Endpoint(ip=observed_ip, port=int(observed_port))
        except (TypeError, ValueError, OSError):
            return
        obs_key = (ep_obs.ip, ep_obs.port)
        r_ep = responder.endpoint
        responder_key = (r_ep.ip, r_ep.port)

        bucket = self._observed_ip_votes_v6 if observed_is_ipv6 else self._observed_ip_votes_v4
        field = "observed_external_v6" if observed_is_ipv6 else "observed_external_v4"

        with self._bep42_align_lock:
            current: Endpoint | None = getattr(self, field)

            # Always count votes; if a new endpoint reaches quorum later, it can replace
            # the currently latched endpoint.
            bucket[obs_key].add(responder_key)
            n = len(bucket[obs_key])
            if n >= self.observed_ip_min_distinct_responders:
                if current is None or (current.ip, current.port) != obs_key:
                    setattr(self, field, ep_obs)
                    # Avoid unbounded growth when roaming: keep only the current winner.
                    bucket.clear()
                    bucket[obs_key].add(responder_key)

                    logger.info(
                        "BEP 42: quorum on observed %s address %s:%d from %d distinct responders",
                        "IPv6" if observed_is_ipv6 else "IPv4",
                        ep_obs.ip,
                        ep_obs.port,
                        n,
                    )
                    try:
                        self.event_sink.on_observed_external_ip(
                            family="ipv6" if observed_is_ipv6 else "ipv4",
                            ip=ep_obs.ip,
                            port=ep_obs.port,
                        )
                    except Exception:
                        logger.debug("event_sink.on_observed_external_ip failed", exc_info=True)

            self._maybe_align_bep42_node_id_unlocked()

    def _maybe_align_bep42_node_id_unlocked(self) -> None:
        """Rotate node_id to satisfy BEP 42 for canonical observed IP (caller holds lock)."""
        if not self.auto_align_bep42_node_id or self._bep42_align_in_progress:
            return
        canon = self.canonical_observed_ip_for_bep42()
        if not canon:
            return
        if _bep42_valid_node_id(self.node_id, canon):
            return

        old_hex = binascii.b2a_hex(self.node_id).decode("ascii")
        new_id = _bep42_generate_node_id(canon)
        self._bep42_align_in_progress = True
        try:
            logger.warning(
                "BEP 42: rotating node_id (was %s) to match observed public IP %s",
                old_hex,
                canon,
            )
            self.node_id = new_id
            self.routing_table = DualStackRoutingTable(self.node_id)
            self.peers.clear()
            self._observed_ip_votes_v4.clear()
            self._observed_ip_votes_v6.clear()
            self.observed_external_v4 = None
            self.observed_external_v6 = None
            try:
                self.save_node_state()
            except Exception as exc:
                logger.error("Failed to save node state after BEP 42 rotation: %s", exc)
            try:
                self.bootstrap()
            except Exception as exc:
                logger.error("Bootstrap after BEP 42 rotation failed: %s", exc)
        finally:
            self._bep42_align_in_progress = False

    async def start(self) -> None:
        """Start UDP transports and periodic tasks.

        This must be called from an asyncio event loop.
        """
        if self.socket_manager is not None:
            return

        self._loop = asyncio.get_running_loop()
        self.socket_manager = SocketManager(
            bind_addr=self._bind_addr,
            on_datagram=self._handle_datagram,
        )
        await self.socket_manager.start()

        # Expose underlying sockets (for legacy code paths until fully migrated).
        if self.socket_manager.transport_v4 is not None:
            self.sock = self.socket_manager.transport_v4.get_extra_info("socket")
        if self.socket_manager.transport_v6 is not None:
            self.sock6 = self.socket_manager.transport_v6.get_extra_info("socket")

        # Now that sockets are bound, add self to routing tables.
        self._add_self_to_routing_tables()

        # Periodic tasks (timeouts + GUI status updates).
        self._periodic_task = asyncio.create_task(self._periodic_tasks())

        # Warm up peers restored via load_peers(): ping a bounded subset so we
        # quickly refresh liveness/node_id state and seed the routing table with
        # known-good contacts.
        try:
            if self.peers:
                asyncio.create_task(self.warmup_persisted_peers())
        except Exception:
            pass

    async def warmup_persisted_peers(
        self,
        *,
        limit: int = WARMUP_PING_LIMIT,
        qps: float = WARMUP_PING_QPS,
    ) -> int:
        """Ping a bounded subset of loaded peers at startup.

        This is intentionally rate-limited to avoid query storms. It improves
        bootstrap behavior after restarts by refreshing previously known routers.

        Returns the number of ping queries sent.
        """
        if limit <= 0:
            return 0
        if qps <= 0:
            qps = 1.0

        # Prefer GOOD/QUESTIONABLE peers; exclude BAD.
        candidates: list[DHTPeer] = []
        for p in list(self.peers.values()):
            nid = getattr(p, "node_id", None)
            if not isinstance(nid, (bytes, bytearray)) or len(nid) != 20:
                continue
            pst = getattr(p, "persisted_rt_status", None)
            if pst == NodeStatus.BAD:
                continue
            candidates.append(p)

        # Prefer recently seen; fall back to stable ordering by endpoint.
        candidates.sort(
            key=lambda p: (
                0 if getattr(p, "persisted_rt_status", None) == NodeStatus.GOOD else 1,
                -float(getattr(p, "last_seen", 0.0) or 0.0),
                str(getattr(p.endpoint, "ip", "")),
                int(getattr(p.endpoint, "port", 0)),
            )
        )

        sent = 0
        interval = 1.0 / float(qps)
        for p in candidates[: int(limit)]:
            # Backpressure: don't add warmup pings if this peer is already busy.
            try:
                if len(p.queue) >= max(0, MAX_PENDING_PER_PEER - 4):
                    continue
                p.ping()
                sent += 1
            except Exception:
                continue
            await asyncio.sleep(interval)

        if sent:
            logger.info("warmup_persisted_peers: sent %d ping(s) (limit=%d qps=%.1f)", sent, limit, qps)
        return sent

    async def _periodic_tasks(self) -> None:
        last_status_update = 0.0
        while True:
            await asyncio.sleep(0.1)
            self._check_timeouts()

            now = time.time()
            if self._peers_dirty and (now - self._last_peers_save) >= self.peers_save_interval:
                try:
                    self.save_peers()
                except Exception:
                    pass
                else:
                    self._last_peers_save = now
                    self._peers_dirty = False

            if now - last_status_update >= 5.0:
                last_status_update = now
                if self.event_sink is not None:
                    try:
                        total_v4 = sum(len(b.nodes) for b in self.routing_table.v4.buckets)
                        total_v6 = sum(len(b.nodes) for b in self.routing_table.v6.buckets)
                        self.event_sink.on_status_update(
                            total_peers=len(self.peers),
                            buckets_v4=len(self.routing_table.v4.buckets),
                            nodes_v4=total_v4,
                            buckets_v6=len(self.routing_table.v6.buckets),
                            nodes_v6=total_v6,
                        )
                    except Exception:
                        pass

    def send_datagram(self, endpoint: Endpoint, payload: bytes) -> None:
        if self.socket_manager is None:
            raise RuntimeError("SocketManager not started")
        # When called from within the owning event loop, send directly.
        if self._loop is not None:
            try:
                if self._loop == asyncio.get_running_loop():
                    self.socket_manager.send(endpoint, payload)
                    return
            except RuntimeError:
                # No running loop in this thread; fall back to threadsafe send.
                pass
        # Otherwise, schedule thread-safely.
        self.socket_manager.send_threadsafe(endpoint, payload)

    def _enqueue_get_peers_scrape(self, peer: DHTPeer, *, info_hash: bytes) -> None:
        """Enqueue a newly discovered DHT node for get_peers(info_hash) follow-up."""
        if len(info_hash) != 20:
            return
        if peer.node_id is None or len(peer.node_id) != 20:
            return
        node_id = peer.node_id
        peer_key = (peer.endpoint.ip, peer.endpoint.port)
        is_v6 = bool(peer.endpoint.is_ipv6)

        with self._scrape_lock:
            st = self._get_peers_scrape.get(info_hash)
            if st is None:
                st = _GetPeersScrapeState(tokens=GET_PEERS_SCRAPE_BURST)
                self._get_peers_scrape[info_hash] = st
            if node_id in st.enqueued:
                return
            st.enqueued.add(node_id)
            st.q.append((node_id, peer_key, is_v6))

    def _drain_get_peers_scrape(
        self,
        *,
        info_hash: bytes,
        queried_v4: set[bytes],
        queried_v6: set[bytes],
        max_inflight: int,
    ) -> tuple[int, int]:
        """Drain queued scrape candidates subject to rate-limit + dedupe.

        Returns ``(sent_v4, sent_v6)``.
        """
        if len(info_hash) != 20:
            return (0, 0)

        sent_v4 = 0
        sent_v6 = 0
        now = time.monotonic()

        # Semaphore-like backpressure: don't amplify when KRPC pending queues are already high.
        # This avoids scrape bursts causing excessive pending-query churn.
        try:
            total_pending = sum(len(p.queue) for p in self.peers.values())
        except Exception:
            total_pending = 0
        if total_pending >= int(MAX_PENDING_GLOBAL * 0.75):
            return (0, 0)

        with self._scrape_lock:
            st = self._get_peers_scrape.get(info_hash)
            if st is None or not st.q:
                return (0, 0)

            # Token-bucket refill
            dt = max(0.0, now - st.last_refill)
            st.last_refill = now
            st.tokens = min(GET_PEERS_SCRAPE_BURST, st.tokens + dt * GET_PEERS_SCRAPE_QPS)

            while st.q and st.tokens >= 1.0 and (sent_v4 + sent_v6) < max_inflight:
                node_id, peer_key, is_v6 = st.q.popleft()
                st.tokens -= 1.0

                if is_v6:
                    if node_id in queried_v6:
                        continue
                    queried_v6.add(node_id)
                else:
                    if node_id in queried_v4:
                        continue
                    queried_v4.add(node_id)

                peer = self.peers.get(peer_key)
                if peer is None:
                    continue
                # Per-peer backpressure: keep headroom for non-scrape queries and responses.
                if len(peer.queue) >= max(0, MAX_PENDING_PER_PEER - 4):
                    continue
                try:
                    peer.get_peers(info_hash)
                    if is_v6:
                        sent_v6 += 1
                    else:
                        sent_v4 += 1
                except Exception:
                    # Keep going; peers can be flaky.
                    pass

        return (sent_v4, sent_v6)

    def _log_datagram(
        self,
        direction: str,
        data: bytes,
        addr: tuple,
        is_ipv6: bool,
        txid_hex: str = "",
        method: str = "",
        note: str = "",
    ) -> None:
        """Log a raw datagram at the wire/protocol level.

        This produces a multi-line trace that captures the complete state of
        a DHT packet: direction, transaction ID, target/source, address family,
        packet size, raw hex snippet, full BEncode decode status, and parsed
        field summary.

        For **outgoing** packets the decode is attempted before sendto so that
        encoding errors are caught at the source.

        For **incoming** packets both the raw trace and the decoded result are
        shown so that malformed / partially-malformed packets arriving from the
        network are immediately visible.

        Parameters
        ----------
        direction : str
            "OUT" for outgoing, "IN" for incoming.
        data : bytes
            The raw datagram bytes.
        addr : tuple
            (ip, port) sender or recipient address.
        is_ipv6 : bool
            Whether the address is IPv6.
        txid_hex : str
            Hex-encoded transaction ID (empty string if not available).
        method : str
            Query method name (ping, find_node, get_peers, etc.).
        note : str
            Optional free-form annotation.
        """
        ip, port = addr[0], addr[1]
        family_str = "AF_INET6" if is_ipv6 else "AF_INET"
        addr_str = f"[{ip}]:{port}" if is_ipv6 else f"{ip}:{port}"

        # Build hex dump snippet (first 80 bytes as hex)
        hex_snippet = data[:80].hex()
        if len(data) > 80:
            hex_snippet += "..."

        # Attempt BEncode decode
        decode_ok = False
        decode_error_msg = ""
        parsed = None
        try:
            parsed = bencode_module.decode(data)
            decode_ok = True
        except Exception as exc:
            decode_error_msg = str(exc)

        # Build parsed summary fields (only on successful decode)
        field_summary = ""
        if decode_ok and parsed is not None:
            # Backfill txid/method if caller didn't provide them.
            # (Callers like _handle_datagram() log before correlating to PendingQuery.)
            if not txid_hex:
                _t = parsed.get(b"t")
                if isinstance(_t, bytes):
                    txid_hex = _t.hex()
                elif isinstance(_t, str):
                    txid_hex = _t.encode("latin-1").hex()
            if not method:
                _y = parsed.get(b"y")
                if _y == b"q":
                    _q = parsed.get(b"q")
                    if isinstance(_q, bytes):
                        method = _q.decode("latin-1", "ignore")
                    elif isinstance(_q, str):
                        method = _q
            y_val = parsed.get(b"y")
            if isinstance(y_val, bytes):
                y_val = y_val.decode("latin-1")
            q_val = parsed.get(b"q")
            if isinstance(q_val, bytes):
                q_val = q_val.decode("latin-1")
            t_val = parsed.get(b"t")
            if isinstance(t_val, bytes):
                t_val = t_val.hex()

            msg_type_str = str(y_val) if y_val else "?"
            field_summary = f"y={msg_type_str}"
            if q_val:
                field_summary += f" q={q_val}"
            if t_val:
                field_summary += f" t={t_val}"
            if decode_ok and isinstance(parsed, dict):
                if isinstance(y_val, bytes) and y_val == b"r":
                    r = parsed.get(b"r", {})
                    if isinstance(r, dict):
                        nodes = r.get(b"nodes", b"")
                        if isinstance(nodes, bytes) and len(nodes) >= 26:
                            field_summary += f" nodes={len(nodes)}b"
                        nodes6 = r.get(b"nodes6", b"")
                        if isinstance(nodes6, bytes) and len(nodes6) >= 38:
                            field_summary += f" nodes6={len(nodes6)}b"
                        values = r.get(b"values", [])
                        if isinstance(values, list) and values:
                            field_summary += f" values={len(values)}"
                        id_val = r.get(b"id", b"")
                        if isinstance(id_val, bytes) and len(id_val) == 20:
                            field_summary += f" id={id_val.hex()}"
                elif isinstance(y_val, bytes) and y_val == b"e":
                    e = parsed.get(b"e", [])
                    if isinstance(e, list) and len(e) >= 2:
                        field_summary += f" error=[{e[0]}, {e[1]}]"

        # Build full decoded representation string
        if decode_ok and parsed is not None:
            repr_str = repr(parsed)
        else:
            repr_str = f"<decode error: {decode_error_msg}>"

        # Single-line wire trace header
        note_str = f" ({note})" if note else ""
        decode_status_str = "OK" if decode_ok else f"ERROR: {decode_error_msg}"

        wire_logger.debug(
            "%s txid=%-8s method=%-12s size=%-5d fam=%-8s %s%s\n  HEX(%d): %s\n  DECODE(%s): %s",
            direction,
            txid_hex or "N/A",
            method or "N/A",
            len(data),
            family_str,
            addr_str,
            note_str,
            len(data),
            hex_snippet,
            decode_status_str,
            repr_str,
        )

        # Notify GUI callback about wire datagram
        if self.event_sink is not None:
            try:
                self.event_sink.on_wire_message(
                    direction=direction,
                    addr=addr,
                    size=len(data),
                    hex_str=hex_snippet,
                    decode_status=decode_status_str,
                    decode_repr=repr_str,
                    txid_hex=txid_hex or "",
                    method=method or "",
                    note=note,
                )
            except Exception:
                pass

    def _is_ipv6_addr(self, addr: tuple) -> bool:
        """Check if an address tuple represents an IPv6 address.

        Parameters
        ----------
        addr : tuple
            The sender address (ip, port) or (ip, port, flowinfo, scopeid).

        Returns
        -------
        bool
            True if IPv6, False if IPv4.
        """
        # AF_INET6 addresses may have 4-tuple form; AF_INET has 2-tuple
        return len(addr) > 2 or ":" in addr[0]

    def _extract_message_info(self, data: bytes) -> dict:
        """Extract message type and details from a bencoded datagram."""
        return extract_gui_message_info_from_datagram(data)

    def _check_timeouts(self) -> None:
        """Drop stale pending queries (TTL) and enforce per-peer / global caps.

        Pending state lives on each :class:`DHTPeer`'s ``queue``; this sweeps
        all known peers periodically.
        """
        now = time.time()
        # 1) TTL expiration
        for peer in list(self.peers.values()):
            stale_txids = [txid for txid, pq in list(peer.queue.items()) if now - pq.sent_at > TIMEOUT]
            for txid in stale_txids:
                peer.queue.pop(txid, None)
                self._record_query_timeout()
                logger.debug("Query %s timed out for peer %s", txid, peer.endpoint)

            # 2) Per-peer cap: evict oldest by sent_at (not counted as timeout)
            while len(peer.queue) > MAX_PENDING_PER_PEER:
                oldest_txid, _oldest_pq = min(peer.queue.items(), key=lambda item: item[1].sent_at)
                peer.queue.pop(oldest_txid, None)
                logger.debug(
                    "Evicted pending txid %s for peer %s (per-peer cap)",
                    oldest_txid,
                    peer.endpoint,
                )

        # 3) Global cap: evict globally oldest sent_at
        total_pending = sum(len(p.queue) for p in self.peers.values())
        while total_pending > MAX_PENDING_GLOBAL:
            candidates: list[tuple[float, DHTPeer, bytes]] = []
            for p in self.peers.values():
                for txid, pq in p.queue.items():
                    candidates.append((pq.sent_at, p, txid))
            if not candidates:
                break
            _sent_at, victim_peer, victim_txid = min(candidates, key=lambda x: x[0])
            victim_peer.queue.pop(victim_txid, None)
            total_pending -= 1
            logger.debug(
                "Evicted pending txid %s for peer %s (global cap)",
                victim_txid,
                victim_peer.endpoint,
            )

    def _handle_datagram(self, data: bytes, addr: tuple) -> None:
        """Handle an incoming datagram.

        Parameters
        ----------
        data : bytes
            The received data.
        addr : tuple
            The sender address (ip, port).
        """
        ip, port = addr[0], addr[1]
        is_ipv6 = self._is_ipv6_addr(addr)

        # Warn about reserved IPv6 addresses (BEP 42 equivalent)
        if is_ipv6 and is_reserved_ipv6(ip):
            logger.warning(
                "Reserved IPv6 address detected from %s:%d. "
                "Per BEP 42, such addresses are equivalent to IPv4 "
                "private/reserved ranges and should be treated specially.",
                ip,
                port,
            )

        # Wire-level datagram logging for incoming packets
        self._log_datagram(
            direction="IN",
            data=data,
            addr=(ip, port),
            is_ipv6=is_ipv6,
            note="incoming_datagram",
        )

        Endpoint(ip, port)

        # Check if we know this peer
        peer_key = (ip, port)

        # Check if this is a QUIC packet - parse and handle accordingly
        if quic_module.is_quic_packet(data):
            payload = quic_module.parse_quic_packet(data)
            if payload is not None:
                # Successfully parsed QUIC packet - process as bencode
                try:
                    if peer_key in self.peers:
                        self.peers[peer_key]._recv_normalized(payload)
                    else:
                        # New QUIC peer - add and process
                        peer = self.add_peer(None, ip, port, is_ipv6=is_ipv6)
                        if peer:
                            peer._recv_normalized(payload)
                except bencode_module.DecodeError:
                    # QUIC payload wasn't valid bencode - log and discard (don't crash)
                    logger.debug(
                        "QUIC payload from %s:%d was not valid bencode (%d bytes, first byte 0x%02x)",
                        ip,
                        port,
                        len(payload),
                        payload[0] if payload else 0,
                    )
                except Exception:
                    logger.debug(
                        "Error processing QUIC payload from %s:%d",
                        ip,
                        port,
                        exc_info=True,
                    )
                return

        # Regular UDP DHT datagram - check if we know this peer
        if peer_key in self.peers:
            logger.debug(
                "Handling datagram from known peer: %s:%d (is_ipv6=%s, data_size=%d)",
                ip,
                port,
                is_ipv6,
                len(data),
            )
            try:
                self.peers[peer_key]._recv_normalized(data)
            except bencode_module.DecodeError:
                # Non-bencode data from known peer - log and discard (don't crash)
                logger.debug(
                    "Non-bencode datagram from known peer %s:%d (first byte 0x%02x, size %d)",
                    ip,
                    port,
                    data[0] if data else 0,
                    len(data),
                )
            except Exception:
                logger.debug(
                    "Error handling datagram from known peer %s:%d",
                    ip,
                    port,
                    exc_info=True,
                )
        else:
            # New data from unknown peer - add and ping to verify
            logger.debug(
                "Data from unknown peer: %s:%d (is_ipv6=%s, data_size=%d). Adding to peer table.",
                ip,
                port,
                is_ipv6,
                len(data),
            )
            peer = self.add_peer(None, ip, port, is_ipv6=is_ipv6)
            if peer:
                logger.debug("Sending ping to newly discovered peer: %s:%d", ip, port)
                peer.ping()

        # Notify GUI about incoming message with extracted message details
        if self.event_sink is not None:
            try:
                msg_info = self._extract_message_info(data)
                self.event_sink.on_incoming_message(
                    msg_info["msg_type"],
                    ip,
                    port,
                    is_ipv6,
                    len(data),
                    txid=msg_info["t"],
                    status=msg_info["status"],
                )
            except Exception:
                logger.debug("Error in on_incoming_message callback")

        # Also notify with full message details for the console
        if self.event_sink is not None:
            try:
                msg_info = self._extract_message_info(data)
                msg_info["direction"] = "incoming"
                self.event_sink.on_message_parsed(ip, port, is_ipv6, len(data), msg_info)
            except Exception:
                logger.debug("Error in on_message_parsed callback")

    def _add_self_to_routing_tables(self) -> None:
        """Add this node's own ID to the IPv4 and IPv6 routing tables.

        Essential for DHT bootstrap: a node must know about itself in the
        routing table to respond to find_node queries targeting its own
        node_id.  Per BEP 5, "Upon inserting the first node into its routing
        table and when starting up thereafter, the node should attempt to find
        the closest nodes in the DHT to itself."

        The self-entry uses the socket's actual bound address so that
        responses reference the correct IP/port.
        """
        # IPv4 self-entry
        try:
            sock4_addr = self.sock.getsockname()  # (ip, port)
            self_endpoint = Endpoint(
                ip=sock4_addr[0],
                port=sock4_addr[1],
            )
            self.routing_table.v4.add_node(
                BucketNode(
                    node_id=self.node_id,
                    endpoint=self_endpoint,
                    status=NodeStatus.GOOD,
                    last_contacted=time.time(),
                )
            )
            logger.debug(
                "Added self (node_id=%s) to IPv4 routing table at %s:%d",
                binascii.b2a_hex(self.node_id).decode("ascii"),
                sock4_addr[0],
                sock4_addr[1],
            )
        except OSError:
            logger.warning("Failed to add self to IPv4 routing table")

        # IPv6 self-entry (if socket exists)
        if self.sock6 is not None:
            try:
                sock6_addr = self.sock6.getsockname()  # (ip, port, flowinfo, scopeid)
                self_endpoint6 = Endpoint(
                    ip=sock6_addr[0],
                    port=sock6_addr[1],
                )
                self.routing_table.v6.add_node(
                    BucketNode(
                        node_id=self.node_id,
                        endpoint=self_endpoint6,
                        status=NodeStatus.GOOD,
                        last_contacted=time.time(),
                    )
                )
                logger.debug(
                    "Added self (node_id=%s) to IPv6 routing table at [%s]:%d",
                    binascii.b2a_hex(self.node_id).decode("ascii"),
                    sock6_addr[0],
                    sock6_addr[1],
                )
            except OSError:
                logger.warning("Failed to add self to IPv6 routing table")

    def _mark_node_good(self, peer: DHTPeer) -> None:
        """Mark a peer as good in the routing table.

        Parameters
        ----------
        peer : DHTPeer
            The peer to mark as good.
        """
        if peer.node_id is None:
            return
        peer.persisted_rt_status = None
        self.routing_table.mark_good(node_id=peer.node_id, endpoint=peer.endpoint)

    def _append_peers_dat_bootstrap_targets(
        self,
        all_addresses: list[tuple[str, int]],
        address_family: int,
        *,
        limit: int = BOOTSTRAP_MAX_PEERS_FILE_TARGETS,
    ) -> int:
        """Extend bootstrap address list with DHT routers from peers.dat (`self.peers`).

        load_peers() only registers contacts; unless we enqueue them alongside
        ``DEFAULT_BOOTSTRAP_NODES``, we never send opening ``find_node`` probes
        to refresh routing state.
        """
        if limit <= 0:
            return 0

        occupied = {(host, port) for host, port in all_addresses}
        added = 0

        for pobj in list(self.peers.values()):
            if added >= limit:
                break
            ep = getattr(pobj, "endpoint", None)
            nid = getattr(pobj, "node_id", None)
            if ep is None or not isinstance(nid, (bytes, bytearray)) or len(nid) != 20:
                continue

            pst = getattr(pobj, "persisted_rt_status", None)
            if pst == NodeStatus.BAD:
                continue

            want_v6 = address_family == socket.AF_INET6
            peer_v6 = bool(ep.is_ipv6)
            if want_v6 and not peer_v6:
                continue
            if not want_v6 and peer_v6:
                continue

            key = (ep.ip, ep.port)
            if key in occupied:
                continue

            occupied.add(key)
            all_addresses.append(key)
            added += 1

        return added

    def bootstrap(
        self,
        nodes: list[tuple[str, int]] | None = None,
        address_family: int | None = None,
    ) -> int:
        """Bootstrap the DHT node by connecting to known router nodes.

        Per BEP 32, this method uses strict address family resolution:
        an IPv4 socket always resolves AF_INET and an IPv6 socket always
        resolves AF_INET6.  No fallback or cross-family queries are
        performed.

        BEP 5: "Upon inserting the first node into its routing table and when
        starting up thereafter, the node should attempt to find the closest
        nodes in the DHT to itself."

        Parameters
        ----------
        nodes : list of tuple, optional
            Custom bootstrap nodes. Uses DEFAULT_BOOTSTRAP_NODES if not provided.
        address_family : int, optional
            The socket address family to use for DNS resolution and contact.
            Must be ``socket.AF_INET`` (IPv4) or ``socket.AF_INET6`` (IPv6).
            If not provided, both IPv4 and IPv6 are bootstrapped when an IPv6
            socket exists; otherwise IPv4 only (see :meth:`bootstrap_all`).

        Returns
        -------
        int
            The number of bootstrap nodes successfully contacted.
        """
        if address_family is None:
            if self.sock6 is not None:
                counts = self.bootstrap_all(nodes=nodes)
                return int(counts.get("ipv4", 0)) + int(counts.get("ipv6", 0))
            address_family = socket.AF_INET

        if address_family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError(f"address_family must be socket.AF_INET or socket.AF_INET6, got {address_family}")

        family_name = "AF_INET" if address_family == socket.AF_INET else "AF_INET6"
        self_ip = "0.0.0.0" if address_family == socket.AF_INET else "::/128"

        node_id_hex = binascii.b2a_hex(self.node_id).decode("ascii")

        logger.info(
            "=== Bootstrap: Starting with address_family=%s (self=%s, node_id=%s) ===",
            family_name,
            self_ip,
            node_id_hex,
        )

        # Log routing table state before bootstrap
        v4_nodes_before = sum(len(b.nodes) for b in self.routing_table.v4.buckets)
        v6_nodes_before = sum(len(b.nodes) for b in self.routing_table.v6.buckets)
        logger.info(
            "Routing table state before bootstrap: IPv4 buckets=%d nodes=%d, IPv6 buckets=%d nodes=%d",
            len(self.routing_table.v4.buckets),
            v4_nodes_before,
            len(self.routing_table.v6.buckets),
            v6_nodes_before,
        )

        nodes = nodes or DEFAULT_BOOTSTRAP_NODES
        total_contacted = 0
        total_skipped = 0

        # Collect all candidate addresses (hostnames + fallback IPs)
        all_addresses = []
        for host, port in nodes:
            try:
                addr_infos = socket.getaddrinfo(host, port, address_family, socket.SOCK_DGRAM)
                for addr_info in addr_infos:
                    fam, _, _, _, sockaddr = addr_info
                    if fam == address_family:
                        all_addresses.append((sockaddr[0], port))
            except socket.gaierror:
                logger.debug("DNS resolution failed for '%s:%d'", host, port)
                pass

        # If DNS returned nothing, try fallback IPs
        if not all_addresses and address_family == socket.AF_INET:
            logger.info("DNS returned no results, trying fallback bootstrap nodes...")
            for host, port in FALLBACK_BOOTSTRAP_NODES:
                try:
                    addr_infos = socket.getaddrinfo(host, port, address_family, socket.SOCK_DGRAM)
                    for addr_info in addr_infos:
                        fam, _, _, _, sockaddr = addr_info
                        if fam == address_family:
                            all_addresses.append((sockaddr[0], port))
                except socket.gaierror:
                    pass

        # peers.dat restores `self.peers` but historically we never pinged those
        # contacts during bootstrap — only DEFAULT_BOOTSTRAP_NODES were queried.
        persisted_n = self._append_peers_dat_bootstrap_targets(all_addresses, address_family)
        if persisted_n:
            logger.info(
                "Bootstrap (%s): added %d address(es) from peers.dat for find_node probes (after routers/fallback DNS)",
                family_name,
                persisted_n,
            )

        if not all_addresses:
            logger.warning(
                "No bootstrap addresses available (family=%s). DNS may have failed "
                "and peers.dat may be empty or have no routers for this family.",
                family_name,
            )
            return 0

        logger.info(
            "Bootstrap using %d addresses (%s)",
            len(all_addresses),
            family_name,
        )

        # Process all collected addresses
        seen = set()
        for host_addr, port_addr in all_addresses:
            peer_key = (host_addr, port_addr)
            if peer_key in seen:
                continue
            seen.add(peer_key)

            is_ipv6 = ":" in host_addr

            # Look up existing peer or create new one
            peer = self.peers.get(peer_key)
            if peer is None:
                peer = self.add_peer(None, host_addr, port_addr, is_ipv6=is_ipv6)

            # Always send find_node query to bootstrap nodes, even if already known
            # This is essential: a node must spread our node_id throughout the DHT
            if peer:
                total_contacted += 1
                logger.debug(
                    "  Contacted bootstrap node: %s:%d, sending find_node query",
                    host_addr,
                    port_addr,
                )
                peer.find_node(self.node_id)
            else:
                total_skipped += 1
                logger.debug(
                    "  Failed to add bootstrap node: %s:%d",
                    host_addr,
                    port_addr,
                )

        logger.info(
            "=== Bootstrap complete (%s): %d contacted, %d skipped ===",
            family_name,
            total_contacted,
            total_skipped,
        )
        return total_contacted

    def bootstrap_for_socket(
        self,
        sock: socket.socket,
        nodes: list[tuple[str, int]] | None = None,
    ) -> int:
        """Bootstrap using a specific socket's address family.

        Convenience method that determines the address family from the
        socket and calls :meth:`bootstrap` with the appropriate family.

        Parameters
        ----------
        sock : socket.socket
            The socket to infer the address family from.
        nodes : list of tuple, optional
            Bootstrap host/port list. Same as :meth:`bootstrap`.

        Returns
        -------
        int
            The number of bootstrap nodes successfully contacted.
        """
        # Determine address family from socket
        try:
            family = sock.family  # socket.AF_INET or socket.AF_INET6
        except AttributeError as err:
            raise ValueError("Socket object does not have a 'family' attribute") from err

        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError(f"Unsupported socket family: {family}")

        return self.bootstrap(nodes=nodes, address_family=family)

    def bootstrap_all(self, nodes: list[tuple[str, int]] | None = None) -> dict[str, int]:
        """Bootstrap both IPv4 and IPv6 sockets.

        Convenience method that bootstraps both address families
        independently per BEP 32.

        Parameters
        ----------
        nodes : list of tuple, optional
            Bootstrap host/port list. Same as :meth:`bootstrap`.

        Returns
        -------
        dict[str, int]
            A dictionary with keys 'ipv4' and 'ipv6' containing the
            number of nodes successfully contacted for each family.
        """
        result: dict[str, int] = {}

        # Bootstrap IPv4
        if self.sock:
            result["ipv4"] = self.bootstrap_for_socket(self.sock, nodes=nodes)
        else:
            result["ipv4"] = 0

        # Bootstrap IPv6 (if available)
        if self.sock6:
            result["ipv6"] = self.bootstrap_for_socket(self.sock6, nodes=nodes)
        else:
            logger.info("IPv6 socket not available, skipping IPv6 bootstrap")
            result["ipv6"] = 0

        return result

    def add_peer(
        self,
        node_id: bytes | None,
        ip: str,
        port: int,
        is_ipv6: bool = False,
        *,
        rt_status: str | None = None,
        rpc_counter: int = 0,
        failure_count: int = 0,
        last_contacted: float | None = None,
    ) -> DHTPeer | None:
        """Add a peer to the node's peer table.

        Parameters
        ----------
        node_id : bytes | None
            The 20-byte node ID, or None if unknown.
        ip : str
            The IP address string.
        port : int
            The port number.
        is_ipv6 : bool
            Whether this is an IPv6 address.
        rt_status : str, optional
            Routing-table status when restoring from peers.dat v2 (:data:`NodeStatus`).
        rpc_counter : int
            Persisted RPC counter (peers.dat v2).
        failure_count : int
            Persisted failure count (peers.dat v2).
        last_contacted : float, optional
            Persisted UNIX timestamp.

        Returns
        -------
        DHTPeer | None
            The created peer, or None if already exists.
        """
        # IPv4-mapped IPv6 addresses should be treated as IPv4
        if is_ipv6 and dht_address.is_ipv4_mapped(ip):
            logger.debug("Detected IPv4-mapped IPv6 address %s, treating as IPv4", ip)
            is_ipv6 = False
        endpoint = Endpoint(ip=ip, port=port)
        peer_key = (ip, port)

        if peer_key in self.peers:
            logger.debug("Peer already exists: %s:%d (is_ipv6=%s)", ip, port, is_ipv6)
            ex = self.peers[peer_key]
            if rt_status is not None:
                ex.persisted_rt_status = rt_status
            # If we previously created this peer without a node_id, and we now learned it,
            # attach it and attempt to add it to the routing table.
            if (
                node_id
                and isinstance(node_id, (bytes, bytearray))
                and len(node_id) == 20
                and (ex.node_id is None or ex.node_id == b"")
            ):
                ex.node_id = bytes(node_id)
                self._peers_dirty = True
                bucket_node = BucketNode(
                    node_id=bytes(node_id),
                    endpoint=ex.endpoint,
                    status=NodeStatus.GOOD,
                    last_contacted=time.time(),
                )
                added_rt = self.routing_table.add_node(bucket_node)
                if added_rt:
                    logger.debug(
                        "Updated peer %s:%d with node_id and added to routing table",
                        ip,
                        port,
                    )
                else:
                    self._routing_add_reject_count += 1
            # Preserve legacy behavior: return None for duplicate add attempts.
            return None

        logger.debug(
            "Adding new peer to table: ip=%s, port=%d, is_ipv6=%s, node_id=%s, total_peers=%d",
            ip,
            port,
            is_ipv6,
            binascii.b2a_hex(node_id).decode("ascii") if node_id else "unknown",
            len(self.peers) + 1,
        )
        pst = (
            rt_status
            if rt_status
            in (
                NodeStatus.GOOD,
                NodeStatus.QUESTIONABLE,
                NodeStatus.BAD,
            )
            else None
        )
        peer = DHTPeer(
            dht_node=self,
            endpoint=endpoint,
            node_id=node_id,
            persisted_rt_status=pst,
        )
        if last_contacted is not None:
            try:
                peer.last_seen = float(last_contacted)
            except Exception:
                pass
        self.peers[peer_key] = peer
        self._peers_dirty = True

        # Also add to routing table if we have a node_id
        # BEP-32: Add to the appropriate routing table based on address family
        if node_id and len(node_id) == 20:
            st = (
                rt_status
                if rt_status in (NodeStatus.GOOD, NodeStatus.QUESTIONABLE, NodeStatus.BAD)
                else NodeStatus.GOOD
            )
            bucket_node = BucketNode(
                node_id=node_id,
                endpoint=endpoint,
                status=st,
                last_contacted=last_contacted if last_contacted is not None else time.time(),
                failure_count=int(failure_count),
                rpc_counter=int(rpc_counter),
            )
            added_rt = self.routing_table.add_node(bucket_node)
            if added_rt:
                logger.debug(
                    "Added node %s to routing table (address family: %s)",
                    binascii.b2a_hex(node_id).decode("ascii"),
                    "IPv6" if is_ipv6 else "IPv4",
                )
            else:
                self._routing_add_reject_count += 1
                c = self._routing_add_reject_count
                if c <= 5 or c % 256 == 0:
                    logger.debug(
                        "Routing table rejected node %s at %s:%d (reject #%d); "
                        "peer remains in self.peers for iterative queries",
                        binascii.b2a_hex(node_id).decode("ascii")[:16],
                        ip,
                        port,
                        c,
                    )
            self._peers_dirty = True

        return peer

    def peer_for_bucket_node(self, node: BucketNode) -> DHTPeer | None:
        """Resolve the live :class:`DHTPeer` for a routing candidate.

        Prefer address lookup (``(ip, port)``) so the correct endpoint is used when
        multiple contacts share a ``node_id``.
        """
        ep = getattr(node, "endpoint", None)
        if ep is not None:
            key = (ep.ip, ep.port)
            p = self.peers.get(key)
            if p is not None:
                return p
        nid = getattr(node, "node_id", None)
        if isinstance(nid, (bytes, bytearray)) and len(nid) == 20:
            for p in self.peers.values():
                if p.node_id == nid:
                    return p
        return None

    def iter_query_candidates(
        self,
        target_id: bytes,
        max_nodes: int,
        *,
        endpoint_family: bool | None = None,
    ) -> list[BucketNode]:
        """Closest known nodes for *target_id*, merging routing tables + ``self.peers``.

        Peers discovered on the wire but not inserted into the K-bucket routing
        table are still included (deduped by ``node_id``, XOR-distance tie-break;
        routing-table entries win over peer-only on ties).

        Parameters
        ----------
        target_id
            20-byte node id or infohash.
        max_nodes
            Maximum number of candidates to return (after family filter).
        endpoint_family
            ``None`` = both families; ``False`` = IPv4 only; ``True`` = IPv6 only.
        """
        if len(target_id) != 20:
            raise ValueError("target_id must be 20 bytes")

        scan_rt = max(64, max_nodes * 8, K * 4)

        best: dict[bytes, tuple[BucketNode, int, bool]] = {}

        def _consider(bn: BucketNode, from_rt: bool) -> None:
            nid = bn.node_id
            if not isinstance(nid, (bytes, bytearray)) or len(nid) != 20:
                return
            d = _xor_distance(target_id, nid)
            prev = best.get(nid)
            if prev is None:
                best[nid] = (bn, d, from_rt)
                return
            _prev_bn, prev_d, prev_rt = prev
            if d < prev_d:
                best[nid] = (bn, d, from_rt)
            elif d == prev_d and from_rt and not prev_rt:
                best[nid] = (bn, d, True)

        for n in self.routing_table.v4.get_closest_nodes(target_id, scan_rt):
            _consider(n, True)
        for n in self.routing_table.v6.get_closest_nodes(target_id, scan_rt):
            _consider(n, True)

        for p in self.peers.values():
            pid = p.node_id
            if not pid or len(pid) != 20:
                continue
            pst = getattr(p, "persisted_rt_status", None)
            st = pst if pst in (NodeStatus.GOOD, NodeStatus.QUESTIONABLE, NodeStatus.BAD) else NodeStatus.GOOD
            _consider(
                BucketNode(
                    node_id=pid,
                    endpoint=p.endpoint,
                    status=st,
                    last_contacted=time.time(),
                ),
                False,
            )

        ordered = sorted(best.values(), key=lambda t: t[1])
        out = [t[0] for t in ordered]

        if endpoint_family is None:
            return out[:max_nodes]

        filtered: list[BucketNode] = []
        for n in out:
            ep = getattr(n, "endpoint", None)
            if ep is None:
                continue
            is6 = bool(getattr(ep, "is_ipv6", False))
            if endpoint_family is True and not is6:
                continue
            if endpoint_family is False and is6:
                continue
            filtered.append(n)
            if len(filtered) >= max_nodes:
                break
        return filtered

    @staticmethod
    def _write_peers_v2_record(fh: Any, bn: BucketNode) -> None:
        ep = bn.endpoint
        if ep is None or not bn.node_id or len(bn.node_id) != 20:
            return
        ip = ep.ip
        is_ipv6 = ep.is_ipv6 and not dht_address.is_ipv4_mapped(ip)
        fh.write(b"\x01" if is_ipv6 else b"\x00")
        fh.write(bytes(bn.node_id[:20]))
        if is_ipv6:
            fh.write(socket.inet_pton(socket.AF_INET6, ip))
        else:
            fh.write(socket.inet_aton(ip))
        fh.write(struct.pack("!H", ep.port))
        fh.write(bytes([_persist_status_byte(bn.status)]))
        fh.write(struct.pack("!II", int(bn.rpc_counter), int(bn.failure_count)))
        fh.write(struct.pack("!d", float(bn.last_contacted)))

    def _read_peers_v2_entry(self, fh: Any) -> tuple[Any, ...] | None:
        """Return (nid, ip, port, is_ipv6, rt_status, rpc_counter, failures, last_ct)."""
        fam = fh.read(1)
        if not fam:
            return None
        is_ipv6 = fam == b"\x01"
        nid = fh.read(20)
        ib = fh.read(16 if is_ipv6 else 4)
        pb = fh.read(2)
        sb = fh.read(1)
        rpcb = fh.read(4)
        fb = fh.read(4)
        lb = fh.read(8)
        if (
            len(nid) != 20
            or len(ib) != (16 if is_ipv6 else 4)
            or len(pb) != 2
            or len(sb) != 1
            or len(rpcb) != 4
            or len(fb) != 4
            or len(lb) != 8
        ):
            return None
        port = struct.unpack("!H", pb)[0]
        st = _persist_status_from_byte(sb[0])
        rpc_counter, failures = struct.unpack("!II", rpcb + fb)
        last_ct = struct.unpack("!d", lb)[0]
        try:
            ip = socket.inet_ntop(
                socket.AF_INET6 if is_ipv6 else socket.AF_INET,
                ib,
            )
        except OSError:
            return None
        return (nid, ip, port, is_ipv6, st, rpc_counter, failures, last_ct)

    def diagnostics_snapshot(self) -> dict[str, object]:
        """Read-only internals for GUIs / operators (routing + scrape + RPC queues).

        Thread-safe for scrape aggregates (``_scrape_lock``); other fields are best-effort
        from the current event-loop / peer-map view.
        """
        with self._scrape_lock:
            scrape_states = len(self._get_peers_scrape)
            scrape_backlog_nodes = sum(len(st.q) for st in self._get_peers_scrape.values())
        try:
            pending_krpc = sum(len(getattr(p, "queue", {})) for p in self.peers.values())
        except Exception:
            pending_krpc = 0
        return {
            "scrape_infohashes_with_state": scrape_states,
            "scrape_queued_candidate_nodes": scrape_backlog_nodes,
            "dht_active_peer_wrappers": len(self.peers),
            "queries_sent_total": getattr(self, "_queries_sent", 0),
            "responses_received_total": getattr(self, "_responses_received", 0),
            "queries_timed_out_total": getattr(self, "_queries_timed_out", 0),
            "approx_pending_krpc_enqueued": pending_krpc,
        }

    def save_node_state(self) -> None:
        """Persist our node_id so restarts reuse the same DHT key."""
        if not self.persist_node_identity or not self.state_file:
            return
        try:
            _save_node_identity(self.state_file, self.node_id)
            logger.debug("Saved node identity to %s", self.state_file)
        except OSError as exc:
            logger.error("Failed to save node identity: %s", exc)

    def save_peers(self, path: str | None = None) -> None:
        """Save known DHT routers to peers.dat (format v2 with stats).

        Format ``DHT2`` stores K-bucket status, RPC/failure counters, and
        ``last_contacted``. Legacy loaders only understand the older 0x00/0x01
        prefixed rows — :meth:`load_peers` reads both formats.

        Parameters
        ----------
        path : str, optional
            The file path. Defaults to peers_file.
        """
        path = path or self.peers_file

        records: dict[tuple[str, int], BucketNode] = {}
        try:
            for table in (self.routing_table.v4, self.routing_table.v6):
                for bucket in table.buckets:
                    for n in bucket.nodes:
                        ep = getattr(n, "endpoint", None)
                        if ep is None:
                            continue
                        if not isinstance(n.node_id, (bytes, bytearray)) or len(n.node_id) != 20:
                            continue
                        records[(ep.ip, ep.port)] = n
        except Exception:
            records = {}

        if not records:
            for p in self.peers.values():
                nid = p.node_id
                if nid is None or len(nid) != 20:
                    continue
                pst = getattr(p, "persisted_rt_status", None)
                st = pst if pst in (NodeStatus.GOOD, NodeStatus.QUESTIONABLE, NodeStatus.BAD) else NodeStatus.GOOD
                bn = BucketNode(
                    node_id=nid,
                    endpoint=p.endpoint,
                    status=st,
                    last_contacted=float(p.last_seen),
                )
                records[(p.endpoint.ip, p.endpoint.port)] = bn

        sorted_nodes = sorted(
            (
                bn
                for bn in records.values()
                if bn.node_id and len(bn.node_id) == 20 and getattr(bn, "endpoint", None) is not None
            ),
            key=lambda x: (
                getattr(x.endpoint, "ip", ""),
                getattr(x.endpoint, "port", 0),
            ),
        )

        tmp_path = path + ".tmp"
        try:
            with open(tmp_path, "wb") as fh:
                fh.write(PEERS_FILE_MAGIC_V2)
                fh.write(struct.pack("!I", len(sorted_nodes)))
                for bn in sorted_nodes:
                    self._write_peers_v2_record(fh, bn)
                logger.debug(
                    "Saved %d peer record(s) (v2) to %s",
                    len(sorted_nodes),
                    path,
                )
            os.replace(tmp_path, path)
        except OSError as exc:
            logger.error("Failed to save peers: %s", exc)

    def load_peers(self, path: str | None = None) -> int:
        """Load routers from peers.dat (v2 ``DHT2`` or legacy 0x00/0x01 rows).

        Parameters
        ----------
        path : str, optional
            The file path. Defaults to peers_file.

        Returns
        -------
        int
            The number of peers loaded.
        """
        path = path or self.peers_file
        count = 0

        logger.debug("Loading peers from file: %s", path)
        try:
            with open(path, "rb") as fh:
                header = fh.read(4)
                if header == PEERS_FILE_MAGIC_V2:
                    nraw = fh.read(4)
                    if len(nraw) != 4:
                        return 0
                    (n_rec,) = struct.unpack("!I", nraw)
                    for _ in range(int(n_rec)):
                        parsed = self._read_peers_v2_entry(fh)
                        if parsed is None:
                            break
                        (
                            nid,
                            ip_a,
                            port_a,
                            is6,
                            st,
                            rpc_c,
                            fail_c,
                            last_ct,
                        ) = parsed
                        self.add_peer(
                            nid,
                            ip_a,
                            port_a,
                            is_ipv6=is6,
                            rt_status=st,
                            rpc_counter=int(rpc_c),
                            failure_count=int(fail_c),
                            last_contacted=float(last_ct),
                        )
                        count += 1
                    logger.debug("Loaded %d peers from %s", count, path)
                    return count

                fh.seek(0)

                while True:
                    marker = fh.read(1)
                    if not marker:
                        break

                    is_ipv6 = marker == b"\x01"
                    entry_size = 38 if is_ipv6 else 26
                    chunk = fh.read(entry_size)
                    if len(chunk) < entry_size:
                        logger.debug(
                            "Incomplete peer entry at offset %d",
                            fh.tell() - entry_size - 1,
                        )
                        break

                    offset_l = 0
                    node_id = chunk[offset_l : offset_l + 20]
                    offset_l += 20
                    ip_bytes = chunk[offset_l : offset_l + (16 if is_ipv6 else 4)]
                    offset_l += 16 if is_ipv6 else 4
                    port = struct.unpack("!H", chunk[offset_l : offset_l + 2])[0]

                    try:
                        ip = socket.inet_ntop(
                            socket.AF_INET6 if is_ipv6 else socket.AF_INET,
                            ip_bytes,
                        )
                        self.add_peer(node_id, ip, port, is_ipv6=is_ipv6)
                        count += 1
                        logger.debug(
                            "Loaded peer (legacy): ip=%s, port=%d, is_ipv6=%s",
                            ip,
                            port,
                            is_ipv6,
                        )
                    except OSError:
                        logger.debug(
                            "Failed to parse peer entry at offset %d",
                            fh.tell() - entry_size - 1,
                        )
                        continue
        except FileNotFoundError:
            logger.info("No existing peers file found at %s", path)
        except OSError as exc:
            logger.error("Failed to load peers: %s", exc)

        logger.debug("Loaded %d peers from %s", count, path)
        return count

    def iterative_find_node(self, target_id: bytes) -> list[DHTPeer]:
        """Perform an iterative closest-node search for a target ID.

        BEP 5: "The original node iteratively queries nodes that are closer
        to the target infohash until it cannot find any closer nodes."

        Parameters
        ----------
        target_id : bytes
            The 20-byte target node ID or infohash.

        Returns
        -------
        list[DHTPeer]
            The closest peers found.
        """
        logger.debug(
            "Starting iterative find_node search for target: %s",
            binascii.b2a_hex(target_id).decode("ascii"),
        )
        closest_nodes = list(self.iter_query_candidates(target_id, K))
        logger.debug(
            "Initial closest nodes: %d, current peer count: %d",
            len(closest_nodes),
            len(self.peers),
        )
        queried: set[bytes] = set()

        # Iterative search
        query_count = 0
        while closest_nodes:
            node = closest_nodes.pop(0)
            if node.node_id in queried:
                continue
            queried.add(node.node_id)

            peer = self.peer_for_bucket_node(node)

            if peer:
                query_count += 1
                logger.debug(
                    "Iterative search query #%d: querying node %s for target %s",
                    query_count,
                    binascii.b2a_hex(node.node_id).decode("ascii"),
                    binascii.b2a_hex(target_id).decode("ascii"),
                )
                peer.find_node(target_id)
                # Wait briefly for response
                time.sleep(0.1)

            # Get closer nodes from responses
            closer = self.iter_query_candidates(target_id, K)
            if not closer or all(n.node_id in queried for n in closer):
                logger.debug(
                    "Iterative search complete after %d queries. Queried %d nodes.",
                    query_count,
                    len(queried),
                )
                break

            closest_nodes = [n for n in closer if n.node_id not in queried] + closest_nodes

        final_peers = [p for p in self.peers.values() if p.node_id]
        logger.debug(
            "Iterative find_node completed. Found %d peers with node IDs, queried %d nodes",
            len(final_peers),
            query_count,
        )
        return final_peers

    async def async_iterative_find_node(
        self,
        target_id: bytes,
        *,
        sleep_interval: float = 0.12,
        deadline: float | None = None,
    ) -> list[DHTPeer]:
        """Async variant of :meth:`iterative_find_node` using cooperative sleeps.

        Runs the same iterative widening strategy; stops when the search
        exhausts closer nodes or ``deadline`` (monotonic ``time.time()``) is reached.
        """
        logger.debug(
            "Starting async iterative find_node for target: %s",
            binascii.b2a_hex(target_id).decode("ascii"),
        )
        closest_nodes = list(self.iter_query_candidates(target_id, K))
        queried: set[bytes] = set()

        query_count = 0
        while closest_nodes:
            if deadline is not None and time.time() >= deadline:
                logger.debug("async_iterative_find_node: deadline reached")
                break

            node = closest_nodes.pop(0)
            if node.node_id in queried:
                continue
            queried.add(node.node_id)

            peer = self.peer_for_bucket_node(node)

            if peer:
                query_count += 1
                logger.debug(
                    "Async iterative query #%d: node %s for target %s",
                    query_count,
                    binascii.b2a_hex(node.node_id).decode("ascii"),
                    binascii.b2a_hex(target_id).decode("ascii"),
                )
                peer.find_node(target_id)
                await asyncio.sleep(sleep_interval)

            closer = self.iter_query_candidates(target_id, K)
            if not closer or all(n.node_id in queried for n in closer):
                logger.debug(
                    "Async iterative search stopping after %d queries, %d node ids queried",
                    query_count,
                    len(queried),
                )
                break

            closest_nodes = [n for n in closer if n.node_id not in queried] + closest_nodes

        final_peers = [p for p in self.peers.values() if p.node_id]
        logger.debug(
            "async_iterative_find_node completed: %d peers with ids, %d queries",
            len(final_peers),
            query_count,
        )
        return final_peers

    def find_peer_for_infohash(self, info_hash: bytes) -> list[StoredPeer]:
        """Find peers for a given infohash through iterative search.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.

        Returns
        -------
        list[StoredPeer]
            Stored peers for the infohash.
        """
        logger.debug(
            "Looking for peers for infohash: %s",
            binascii.b2a_hex(info_hash).decode("ascii"),
        )
        # First check our peer store
        peers = self.peer_store.get_peers(info_hash)
        if peers:
            logger.debug(
                "Found %d existing peers for infohash %s in peer store",
                len(peers),
                binascii.b2a_hex(info_hash).decode("ascii"),
            )
            return peers

        logger.debug(
            "No existing peers found, starting iterative search for infohash %s",
            binascii.b2a_hex(info_hash).decode("ascii"),
        )
        # Otherwise do iterative find_node for the infohash
        self.iterative_find_node(info_hash)
        return self.peer_store.get_peers(info_hash)

    def announce_peer(
        self,
        info_hash: bytes,
        port: int,
        target: DHTPeer,
        token: bytes,
        implied_port: bool = False,
    ) -> None:
        """Announce a peer to the DHT.

        BEP 5: Announce that the peer controlling this node is downloading
        a torrent on a specific port.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash of the torrent.
        port : int
            The port the peer is listening on.
        target : DHTPeer
            The target node to announce to.
        token : bytes
            The token received from a previous get_peers query.
        implied_port : bool
            Whether to use the source port instead of the specified port.
        """
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")

        args: dict[str, Any] = {
            "info_hash": info_hash,
            "port": port,
            "token": token,
        }

        if implied_port:
            args["implied_port"] = 1

        target.query("announce_peer", args)

    def iterative_get_peers(
        self,
        info_hash: bytes,
        nodes: list[BucketNode] | None = None,
        depth: int = 0,
        max_depth: int = 3,
        queried: set[bytes] | None = None,
    ) -> list[StoredPeer]:
        """Perform an iterative get_peers search to find peers for an infohash.

        BEP 5: Send get_peers to nodes close to the infohash, follow up with
        responses to discover more peers and more nodes.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        nodes : list of BucketNode, optional
            Starting nodes to query. Uses routing table if not provided.
        depth : int
            Current recursion depth.
        max_depth : int
            Maximum recursion depth.
        queried : set of bytes, optional
            Set of already-queried node IDs (raw bytes).

        Returns
        -------
        list[StoredPeer]
            Stored peers for the infohash.
        """
        if queried is None:
            queried = set()

        if depth >= max_depth:
            logger.debug("iterative_get_peers: max depth %d reached", max_depth)
            return self.peer_store.get_peers(info_hash)

        if nodes is None:
            nodes = self.iter_query_candidates(info_hash, K)

        if not nodes:
            logger.debug("iterative_get_peers: no nodes to query")
            return self.peer_store.get_peers(info_hash)

        logger.debug(
            "iterative_get_peers: depth=%d, querying %d nodes for infohash %s",
            depth,
            len(nodes),
            binascii.b2a_hex(info_hash).decode("ascii"),
        )

        # Query each node for get_peers
        for node in nodes:
            node_id = node.node_id
            if node_id in queried:
                continue
            queried.add(node_id)

            peer = self.peer_for_bucket_node(node)

            if peer:
                logger.debug(
                    "get_peers query #%d: querying node %s for infohash %s",
                    depth,
                    binascii.b2a_hex(node_id).decode("ascii"),
                    binascii.b2a_hex(info_hash).decode("ascii"),
                )
                try:
                    peer.get_peers(info_hash)
                except Exception as exc:
                    logger.debug(
                        "Error sending get_peers to %s: %s",
                        binascii.b2a_hex(node_id).decode("ascii"),
                        exc,
                    )
            else:
                logger.debug(
                    "No peer found for node_id %s",
                    binascii.b2a_hex(node_id).decode("ascii"),
                )

        # Wait for responses to be processed
        time.sleep(0.5)

        # Get updated closest nodes for next iteration
        closer_nodes = self.iter_query_candidates(info_hash, K)
        closer_nodes = [n for n in closer_nodes if n.node_id not in queried]

        if closer_nodes:
            return self.iterative_get_peers(
                info_hash,
                nodes=closer_nodes,
                depth=depth + 1,
                max_depth=max_depth,
                queried=queried,
            )

        return self.peer_store.get_peers(info_hash)

    def sample_infohashes(self, target: DHTPeer | None = None) -> list[bytes]:
        """Request a sample of infohashes from a DHT node (BEP 51).

        Respects the ``interval`` field returned by a previous response for the
        same peer endpoint — the query is silently skipped if the interval has
        not yet elapsed.

        Parameters
        ----------
        target : DHTPeer, optional
            The peer to query. Uses closest nodes if not provided.

        Returns
        -------
        list[bytes]
            Always returns an empty list; infohashes are processed asynchronously
            in ``_process_sample_infohashes_response``.
        """
        if target is None:
            # Query closest nodes
            closest = self.routing_table.v4.get_closest_nodes(self.node_id, K)
            if not closest:
                return []
            target_node = closest[0]
            for p in self.peers.values():
                if p.node_id == target_node.node_id:
                    target = p
                    break

        if target is None:
            return []

        # BEP 51: honour the interval from the last response for this endpoint
        key = (target.endpoint.ip, target.endpoint.port)
        next_allowed = self._sample_next_at.get(key, 0.0)
        if time.time() < next_allowed:
            logger.debug(
                "BEP 51: sample_infohashes to %s deferred (%.0f s remaining)",
                key,
                next_allowed - time.time(),
            )
            return []

        try:
            target.sample_infohashes()
        except Exception:
            pass

        # Infohashes are processed in _process_sample_infohashes_response
        return []

    async def async_get_peers(
        self,
        info_hash: bytes,
        search_timeout: float = 15.0,
        max_nodes: int = K,
        query_interval: float = 3.0,
        on_round: Callable[[int, int, int, int], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> list[StoredPeer]:
        """Perform an async iterative get_peers search to find peers for an infohash.

        BEP 5: Send get_peers to nodes close to the infohash, follow up with
        responses to discover more peers and more nodes.

        This method implements iterative deepening: it repeatedly queries the
        closest nodes to the target infohash from both IPv4 and IPv6 routing
        tables, processing responses that add new nodes to the routing table.
        As new nodes are discovered, they become candidates for future queries,
        progressively expanding the search radius.

        This is fully asynchronous - it uses asyncio.sleep() instead of
        time.sleep() so it doesn't block the event loop. The background read
        thread continues processing incoming messages and populating the peer
        store concurrently.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        search_timeout : float
            How long to search for peers (seconds).
        max_nodes : int
            Maximum nodes to query per round from each routing table.
        query_interval : float
            Seconds between query rounds. Allows time for responses to arrive.
        on_round : callable, optional
            Called after each query round with
            ``(round_num, sent_v4, sent_v6, peers_found_for_infohash)``.
        cancel_requested : callable, optional
            If provided, called each iteration; abort search when it returns True.

        Returns
        -------
        list[StoredPeer]
            Stored peers for the infohash after timeout expires.
        """
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")

        logger.debug(
            "async_get_peers: starting search for infohash %s (timeout=%.1fs, interval=%.1fs)",
            binascii.b2a_hex(info_hash).decode("ascii"),
            search_timeout,
            query_interval,
        )

        # Track which node IDs we've already queried (across all rounds)
        queried_v4: set[bytes] = set()
        queried_v6: set[bytes] = set()

        start_time = asyncio.get_event_loop().time()
        round_num = 0

        while True:
            if cancel_requested is not None and cancel_requested():
                logger.debug("async_get_peers: cancelled")
                break
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed >= search_timeout:
                break

            round_num += 1
            sent_v4 = 0
            sent_v6 = 0

            # Aggressively query newly learned DHT nodes (scrape queue) first.
            # This quickly expands the swarm beyond just the current closest-node slice.
            scrape_sent_v4, scrape_sent_v6 = self._drain_get_peers_scrape(
                info_hash=info_hash,
                queried_v4=queried_v4,
                queried_v6=queried_v6,
                max_inflight=GET_PEERS_SCRAPE_MAX_INFLIGHT,
            )
            sent_v4 += scrape_sent_v4
            sent_v6 += scrape_sent_v6

            # IPv4 candidates: routing table + peers not inserted into RT
            ipv4_nodes = self.iter_query_candidates(info_hash, max_nodes, endpoint_family=False)
            for node in ipv4_nodes:
                node_id = node.node_id
                if not node_id:
                    continue
                if node_id in queried_v4:
                    continue
                queried_v4.add(node_id)

                peer = self.peer_for_bucket_node(node)

                if peer:
                    try:
                        peer.get_peers(info_hash)
                        sent_v4 += 1
                        logger.debug(
                            "Round %d: Sent get_peers to IPv4 node %s:%d (node_id=%s, xor_dist=%d)",
                            round_num,
                            peer.endpoint.ip,
                            peer.endpoint.port,
                            binascii.b2a_hex(node_id).decode("ascii"),
                            _xor_distance(info_hash, node_id),
                        )
                    except Exception as e:
                        logger.debug("Error sending get_peers to %s:%d: %s", peer.endpoint.ip, peer.endpoint.port, e)

            ipv6_nodes = self.iter_query_candidates(info_hash, max_nodes, endpoint_family=True)
            for node in ipv6_nodes:
                node_id = node.node_id
                if not node_id:
                    continue
                if node_id in queried_v6:
                    continue
                queried_v6.add(node_id)

                peer = self.peer_for_bucket_node(node)

                if peer:
                    try:
                        peer.get_peers(info_hash)
                        sent_v6 += 1
                        logger.debug(
                            "Round %d: Sent get_peers to IPv6 node %s:%d (node_id=%s, xor_dist=%d)",
                            round_num,
                            peer.endpoint.ip,
                            peer.endpoint.port,
                            binascii.b2a_hex(node_id).decode("ascii"),
                            _xor_distance(info_hash, node_id),
                        )
                    except Exception as e:
                        logger.debug("Error sending get_peers to %s:%d: %s", peer.endpoint.ip, peer.endpoint.port, e)

            total_sent = sent_v4 + sent_v6
            peers_found_ct = len(self.peer_store.get_peers(info_hash))
            logger.debug(
                "Round %d: Sent get_peers to %d nodes (%d IPv4, %d IPv6). "
                "Routing table: %d IPv4, %d IPv6. Peers found so far: %d",
                round_num,
                total_sent,
                sent_v4,
                sent_v6,
                sum(len(b.nodes) for b in self.routing_table.v4.buckets),
                sum(len(b.nodes) for b in self.routing_table.v6.buckets),
                peers_found_ct,
            )

            if on_round is not None:
                try:
                    on_round(round_num, sent_v4, sent_v6, peers_found_ct)
                except Exception:
                    logger.debug("on_round callback failed", exc_info=True)

            # If we have no nodes to query in either table, we're done
            if total_sent == 0 and round_num > 1:
                logger.debug(
                    "No new nodes to query in round %d, ending search early",
                    round_num,
                )
                break

            # Wait for responses before next round
            remaining = search_timeout - elapsed
            if remaining <= 0:
                break
            wait_time = min(query_interval, remaining)
            await asyncio.sleep(wait_time)

        # Return all discovered peers
        peers = self.peer_store.get_peers(info_hash)
        elapsed = asyncio.get_event_loop().time() - start_time
        logger.debug(
            "async_get_peers: completed after %.1fs (%d rounds). "
            "Found %d peers for infohash %s. "
            "Routing table: %d IPv4 nodes, %d IPv6 nodes. "
            "Queried: %d IPv4, %d IPv6",
            elapsed,
            round_num,
            len(peers),
            binascii.b2a_hex(info_hash).decode("ascii"),
            sum(len(b.nodes) for b in self.routing_table.v4.buckets),
            sum(len(b.nodes) for b in self.routing_table.v6.buckets),
            len(queried_v4),
            len(queried_v6),
        )
        return peers

    #: Number of nodes that responded to our find_node bootstrap requests with our node_id.
    #: This confirms they have propagated our node into their routing tables.
    #: Incremented when responses are processed (not a property).
    #: NOTE: This counter may double-count nodes whose node_ids appear in both
    #: IPv4 and IPv6 routing tables (e.g., dual-stack nodes or IPv4-mapped IPv6
    #: addresses). Use ``self_node_id_count`` for a deduplicated count.
    self_node_id_response_count: int = 0

    @property
    def self_node_id_found(self) -> bool:
        """True if our node_id appeared in at least one find_node compact ``nodes``/``nodes6`` list.

        Remote peers do not use our node_id as their own ``r.id``; propagation is
        confirmed when a *compact node listing* in a response includes our id
        while we were searching for ourselves (see :meth:`_parse_nodes`).
        """
        return self.self_node_id_response_count > 0

    @property
    def self_node_id_count(self) -> int:
        """Dedup count of routing-table/peer entries whose node_id equals ours (usually self only).

        This does not count DHT-wide propagation; see :meth:`self_node_id_found`
        and ``self_node_id_response_count``.
        """
        seen_ids: set[bytes] = set()
        count = 0
        # Check peers
        for peer in self.peers.values():
            if peer.node_id and peer.node_id == self.node_id and peer.node_id not in seen_ids:
                count += 1
                seen_ids.add(peer.node_id)
        # Check routing tables (deduplicated)
        for bucket in self.routing_table.v4.buckets:
            for node in bucket.nodes:
                if node.node_id == self.node_id and node.node_id not in seen_ids:
                    count += 1
                    seen_ids.add(node.node_id)
        for bucket in self.routing_table.v6.buckets:
            for node in bucket.nodes:
                if node.node_id == self.node_id and node.node_id not in seen_ids:
                    count += 1
                    seen_ids.add(node.node_id)
        return count

    async def verify_bootstrap(
        self,
        max_attempts: int = 20,
        query_interval: float = 1.0,
    ) -> bool:
        """Verify that our node_id has been propagated into the DHT.

        This method queries random nodes for find_node(target=our_node_id)
        and checks if any response contains our own node_id. If so, bootstrap
        is successful — our node is visible to the DHT network.

        Per BEP 5, bootstrap is complete when a node can find itself
        through the DHT. This method confirms that by actually searching
        for our own node_id across the network.

        Parameters
        ----------
        max_attempts : int
            Maximum number of verification attempts before giving up.
        query_interval : float
            Seconds between verification query rounds.

        Returns
        -------
        bool
            True if our node_id was found in responses, False otherwise.
        """
        if not self.peers:
            logger.warning("verify_bootstrap: no peers to query")
            return False

        for attempt in range(1, max_attempts + 1):
            all_table_nodes = self.iter_query_candidates(self.node_id, 200)

            if not all_table_nodes:
                logger.debug(
                    "verify_bootstrap: no candidates in routing table or peer list yet, waiting...",
                )
                await asyncio.sleep(query_interval)
                continue

            # Select random nodes to query (prefer nodes we haven't queried recently)
            import random as rnd

            rnd.shuffle(all_table_nodes)
            query_count = min(5, len(all_table_nodes))
            candidates = all_table_nodes[:query_count]

            logger.info(
                "verify_bootstrap: attempt %d/%d, querying %d nodes for self node_id (%d candidates)",
                attempt,
                max_attempts,
                query_count,
                len(all_table_nodes),
            )

            # Send find_node(target=our_node_id) to candidates
            queried_peers = []
            for node in candidates:
                peer = self.peer_for_bucket_node(node)
                if peer:
                    peer.find_node(self.node_id)
                    queried_peers.append(peer)

            # Wait for responses
            await asyncio.sleep(query_interval)

            # Check if any peer now has our node_id
            if self.self_node_id_found:
                logger.info(
                    "verify_bootstrap: SUCCESS on attempt %d - our node_id appeared in "
                    "compact find_node data (%d such responses)",
                    attempt,
                    self.self_node_id_response_count,
                )
                return True

            # Emit progress update (GUI uses event_sink)
            if self.event_sink is not None:
                try:
                    self.event_sink.on_bootstrap_progress(
                        phase="Phase 3: Verifying self-node propagation",
                        depth=attempt,
                        nodes_queried=len(queried_peers),
                        nodes_discovered=0,
                        min_xor_distance=0,
                        total_nodes=len(all_table_nodes),
                        elapsed=time.time(),
                    )
                except Exception:
                    pass

            if attempt < max_attempts:
                await asyncio.sleep(query_interval)

        logger.warning(
            "verify_bootstrap: FAILED after %d attempts - could not find our node_id in the DHT",
            max_attempts,
        )
        return False

    async def bootstrap_recursive(
        self,
        bootstrap_nodes: list[tuple[str, int]] | None = None,
        total_timeout: float = 30.0,
        max_depth: int = 3,
        verify: bool = True,
    ) -> int:
        """Bootstrap the DHT node with recursive node_id propagation and self-verification.

        This method performs three phases:
        1. Initial bootstrap: Contact known bootstrap nodes, send find_node for our node_id
        2. Iterative propagation: :meth:`async_iterative_find_node` toward our own
           node id until ``total_timeout`` elapses
        3. Self-verification: Query random nodes for find_node(target=our_node_id) and
           check if any response contains our own node_id. This confirms that our node
           has been successfully propagated into the DHT network.

        Per BEP 5: "Upon inserting the first node into its routing table and when
        starting up thereafter, the node should attempt to find the closest nodes
        in the DHT to itself." This method ensures our node_id spreads throughout
        the DHT network and verifies propagation by searching for our own node_id.

        This is fully async - uses asyncio.sleep/gather/wait_for for non-blocking
        operation. The background read thread continues processing incoming messages.

        Emits progress updates via on_bootstrap_progress callback if set.

        Parameters
        ----------
        bootstrap_nodes : list of tuple, optional
            Custom bootstrap nodes. Uses DEFAULT_BOOTSTRAP_NODES if not provided.
        total_timeout : float
            Total time budget for the entire bootstrap process (seconds).
        max_depth : int
            Unused; iteration is bounded by ``total_timeout`` (reserved for API
            compatibility).
        verify : bool
            If True, run self-verification after propagation to confirm our node_id
            has been propagated into the DHT.

        Returns
        -------
        int
            The number of bootstrap nodes successfully contacted in phase 1.
        """
        _ = max_depth  # reserved for API compatibility
        logger.info(
            "bootstrap_recursive: starting with total_timeout=%.1fs (max_depth param unused)",
            total_timeout,
        )

        # Emit initial progress
        if self.event_sink is not None:
            try:
                self.event_sink.on_bootstrap_progress(
                    phase="Phase 1: Bootstrap",
                    depth=0,
                    nodes_queried=0,
                    nodes_discovered=0,
                    min_xor_distance=0,
                    total_nodes=0,
                    elapsed=0.0,
                )
            except Exception:
                pass

        # ========== Phase 1: Initial bootstrap ==========
        initial_contacted = self.bootstrap(bootstrap_nodes)
        logger.info(
            "bootstrap_recursive: Phase 1 complete - contacted %d bootstrap endpoints",
            initial_contacted,
        )

        wait_increments = 10
        wait_per_increment = 0.2
        for wi in range(wait_increments):
            await asyncio.sleep(wait_per_increment)
            peers_with_ids = sum(1 for p in self.peers.values() if p.node_id is not None)
            if peers_with_ids > 0:
                logger.debug(
                    "bootstrap_recursive: %d peers have node_id after %.1fs",
                    peers_with_ids,
                    (wi + 1) * wait_per_increment,
                )

        logger.debug(
            "bootstrap_recursive: Phase 1 wait done, %d peers total, %d with node_id",
            len(self.peers),
            sum(1 for p in self.peers.values() if p.node_id is not None),
        )

        # ========== Phase 2: Iterative find_node toward our node id ==========
        phase2_start = time.time()
        phase2_deadline = phase2_start + total_timeout
        logger.info(
            "bootstrap_recursive: Phase 2 iterative find_node(self) (%.1fs budget)",
            total_timeout,
        )
        if self.event_sink is not None:
            try:
                all_table_nodes = list(self.routing_table.v4.get_closest_nodes(self.node_id, 1000))
                all_table_nodes.extend(self.routing_table.v6.get_closest_nodes(self.node_id, 1000))
                min_dist = (
                    min(_xor_distance(self.node_id, n.node_id) for n in all_table_nodes) if all_table_nodes else 0
                )
                self.event_sink.on_bootstrap_progress(
                    phase="Phase 2: Iterative find_node(self)",
                    depth=0,
                    nodes_queried=0,
                    nodes_discovered=len(all_table_nodes),
                    min_xor_distance=min_dist,
                    total_nodes=len(all_table_nodes),
                    elapsed=0.0,
                )
            except Exception:
                pass

        await self.async_iterative_find_node(
            self.node_id,
            sleep_interval=0.12,
            deadline=phase2_deadline,
        )

        rt_v4 = sum(len(b.nodes) for b in self.routing_table.v4.buckets)
        rt_v6 = sum(len(b.nodes) for b in self.routing_table.v6.buckets)
        logger.info(
            "bootstrap_recursive: Phase 2 finished in %.1fs; routing table size IPv4=%d IPv6=%d",
            time.time() - phase2_start,
            rt_v4,
            rt_v6,
        )

        # ========== Phase 3: Self-verification ==========
        if verify:
            logger.info("bootstrap_recursive: starting self-verification...")
            verified = await self.verify_bootstrap()
            if verified:
                logger.info(
                    "bootstrap_recursive: SUCCESS - our node_id has been propagated into the DHT network",
                )
            else:
                logger.warning(
                    "bootstrap_recursive: could not verify self-node propagation after initial bootstrap. "
                    "This may be normal if the DHT is small or new. Continued maintenance will help.",
                )
        else:
            logger.info("bootstrap_recursive: self-verification skipped (verify=False)")

        # Save discovered peers
        self.save_peers()

        return initial_contacted

    @property
    def responses_received(self) -> int:
        """Number of successful responses received from peers."""
        return self._responses_received

    @property
    def queries_sent(self) -> int:
        """Number of queries sent to peers."""
        return self._queries_sent

    @property
    def queries_timed_out(self) -> int:
        """Number of queries that have timed out."""
        return self._queries_timed_out

    @property
    def errors_received(self) -> int:
        """Number of error responses received from peers."""
        return self._errors_received

    def _increment_responses(self) -> None:
        """Increment the response counter (thread-safe, called from read loop)."""
        self._responses_received += 1

    def _increment_errors(self) -> None:
        """Increment the error counter (thread-safe, called from read loop)."""
        self._errors_received += 1

    def _record_query_sent(self) -> None:
        """Record that a query was sent (thread-safe, called from query method)."""
        self._queries_sent += 1

    def _record_query_timeout(self) -> None:
        """Record that a query timed out."""
        self._queries_timed_out += 1

    async def close_async(self) -> None:
        """Stop periodic tasks and close UDP transports."""
        periodic = getattr(self, "_periodic_task", None)
        if periodic is not None:
            periodic.cancel()
            self._periodic_task = None

        sm = getattr(self, "socket_manager", None)
        if sm is not None:
            await sm.close()
            self.socket_manager = None

        self.sock = None
        self.sock6 = None

    def close(self) -> None:
        """Synchronous close wrapper for non-async call sites."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None:
            # Caller is already in an event loop; schedule and return.
            loop.create_task(self.close_async())
            return

        asyncio.run(self.close_async())


def run_dht_node(
    peers_file: str = DEFAULT_PEERS_FILE,
    bootstrap_nodes: list[tuple[str, int]] | None = None,
) -> DHTNode:
    """Create and run a DHT node in a background thread.

    Parameters
    ----------
    peers_file : str
        Path to persist known peers.
    bootstrap_nodes : list of tuple, optional
        Custom bootstrap nodes.

    Returns
    -------
    DHTNode
        The running DHT node.
    """
    node = DHTNode(peers_file=peers_file)
    asyncio.run(node.start())

    # Load existing peers
    node.load_peers()

    # Bootstrap
    node.bootstrap(bootstrap_nodes)

    return node
