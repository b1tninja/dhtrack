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
- Integration with GTK for GUI display
"""

from __future__ import annotations

# Suppress PyGIDeprecationWarning before any gi imports.
# PyGObject 3.56.x internally uses the deprecated GLib.unix_signal_add_full
# during override loading, which triggers spurious deprecation warnings.
# This filter must be set BEFORE importing gi.repository.* to take effect.
import warnings
warnings.filterwarnings("ignore", message=".*unix_signal_add_full.*")

import binascii
import hashlib
import logging
import os
import socket
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dhtrack import bencode as bencode_module
from dhtrack.bloom_filter import BloomFilter

# Specify GTK version before importing to avoid PyGIWarning
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gio, Gtk

# Constants
logger = logging.getLogger(__name__)

MTU = 1438

# BEP 5 client version string identifier
CLIENT_VERSION = b"dh"
CLIENT_VERSION_STRING = "dh01"

K = 8  # Maximum number of nodes in a bucket / closest nodes
BUCKET_SIZE = K
TIMEOUT = 3  # seconds before a query times out
REPLACEMENT_TIMEOUT = 600  # seconds before a replacement node is forgotten (10 minutes)
CONTACT_REFRESH_INTERVAL = 900  # 15 minutes in seconds
SECRET_ROTATION_INTERVAL = 300  # 5 minutes in seconds
TOKEN_MAX_AGE = 600  # 10 minutes in seconds

DEFAULT_PEERS_FILE = "peers.dat"
DEFAULT_BOOTSTRAP_NODES: list[tuple[str, int]] = [
    ("router.bittorrent.com", 6881),
    ("download.deluge-torrent.org", 6881),
    ("ftp.osuosl.org", 6881),
    ("router.utorrent.com", 6881),
    ("router.bitcomet.com", 6881),
    ("dht.transmissionbt.com", 6881),
]


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
    return int.from_bytes(bytes(x ^ y for x, y in zip(a, b)), byteorder="big")


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
        self._secrets = [
            (t, s) for t, s in self._secrets if now - t < TOKEN_MAX_AGE
        ]

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
    node_id: Optional[bytes] = None
    is_ipv6: bool = False
    last_seen: float = field(default_factory=time.time)
    info_hash: Optional[bytes] = None


class PeerStore:
    """Stores peer contact information keyed by infohash.

    BEP 5: Nodes store the IP address and port of peers under the infohash
    in response to announce_peer queries.

    BEP 33: Extended with seed tracking to support DHT scrapes via bloom
    filters.  Seeds and peers are tracked separately so that bloom filter
    responses (BFsd for seeds, BFpe for peers) can be generated accurately.
    """

    def __init__(self, max_entries: int = 10000) -> None:
        # Set of unique <info_hash, ip> tuples for deduplication per BEP 33
        self._seen: dict[bytes, set[tuple[str, int]]] = defaultdict(set)
        self._store: dict[bytes, list[StoredPeer]] = defaultdict(list)
        self._max_entries = max_entries

    def add_peer(self, info_hash: bytes, ip: str, port: int, node_id: Optional[bytes] = None, is_ipv6: bool = False, is_seed: bool = False) -> None:
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
        if len(self._store[info_hash]) > 20:
            self._store[info_hash] = self._store[info_hash][-20:]

    def add_peer_seed(self, info_hash: bytes, ip: str, port: int, node_id: Optional[bytes] = None, is_ipv6: bool = False) -> None:
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

    def add_peer_item(self, info_hash: bytes, ip: str, port: int, node_id: Optional[bytes] = None, is_ipv6: bool = False) -> None:
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

    def get_seed_bloom_filter(self, info_hash: bytes) -> Optional[BloomFilter]:
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

    def get_peer_bloom_filter(self, info_hash: bytes) -> Optional[BloomFilter]:
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

    def split(self) -> tuple["KBucket", "KBucket"]:
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


# ---------------------------------------------------------------------------
# KRPC Message helpers
# ---------------------------------------------------------------------------

def _encode_dht_query(method: str, args: dict[str, Any], transaction_id: bytes) -> bytes:
    """Encode a DHT query message per BEP 5.

    BEP 5: KRPC message with 't' (transaction ID), 'y' (type), 'q' (method),
    'a' (arguments), and optionally 'v' (version).

    Parameters
    ----------
    method : str
        The query method name (ping, find_node, get_peers, announce_peer).
    args : dict[str, Any]
        The query arguments including 'id'.
    transaction_id : bytes
        The 2-byte transaction ID.

    Returns
    -------
    bytes
        BEncode-encoded KRPC message.
    """
    query = {
        "t": transaction_id,
        "y": "q",
        "q": method,
        "a": args,
        "v": CLIENT_VERSION_STRING,
    }
    return bencode_module.encode(query)


def _encode_dht_response(transaction_id: bytes, result: dict[str, Any]) -> bytes:
    """Encode a DHT response message per BEP 5.

    Parameters
    ----------
    transaction_id : bytes
        The 2-byte transaction ID from the query.
    result : dict[str, Any]
        The result dictionary.

    Returns
    -------
    bytes
        BEncode-encoded KRPC response message.
    """
    response = {
        "t": transaction_id,
        "y": "r",
        "r": result,
        "v": CLIENT_VERSION_STRING,
    }
    return bencode_module.encode(response)


def _encode_dht_error(transaction_id: bytes, error_code: int, error_message: str) -> bytes:
    """Encode a DHT error message per BEP 5.

    BEP 5 error codes:
        201: Generic Error
        202: Server Error
        203: Protocol Error (malformed packet, invalid arguments, or bad token)
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
    error = {
        "t": transaction_id,
        "y": "e",
        "e": [error_code, error_message],
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

    dht_node: "DHTNode"
    endpoint: "Endpoint"
    node_id: Optional[bytes] = None
    queue: dict[bytes, dict] = field(default_factory=dict)
    last_seen: float = field(default_factory=lambda: time.time())

    def write(self, data: bytes) -> None:
        """Send data to this peer.

        Parameters
        ----------
        data : bytes
            The raw data to send.
        """
        if self.endpoint.is_ipv6:
            self.dht_node.sock6.sendto(data, (self.endpoint.ip, self.endpoint.port))
        else:
            self.dht_node.sock.sendto(data, (self.endpoint.ip, self.endpoint.port))

    def recv(self, data: bytes) -> None:
        """Process received data from this peer.

        Parameters
        ----------
        data : bytes
            The raw received data.
        """
        try:
            parsed = bencode_module.decode(data)
        except Exception:
            logger.debug("Failed to parse bencoded data from %s", self.endpoint)
            return

        msg_type = parsed.get("y")

        # Query message
        if msg_type == "q":
            self._handle_query(parsed)
        # Response message
        elif msg_type == "r":
            self._handle_response(parsed)
        # Error message
        elif msg_type == "e":
            logger.debug("Error response from %s: %s", self.endpoint, parsed.get("e"))
        else:
            logger.warning("Unknown message type from %s", self.endpoint)

    def _handle_query(self, parsed: dict) -> None:
        """Handle an incoming query from a peer.

        BEP 5: Process ping, find_node, get_peers, and announce_peer queries.
        The 'v' (version) field is optional and may be used for client identification.

        Parameters
        ----------
        parsed : dict
            The parsed BEncode message.
        """
        query_type = parsed.get("q")
        if not isinstance(query_type, (bytes, str)):
            logger.debug("Invalid query type from %s", self.endpoint)
            return

        transaction_id = parsed.get("t", b"")
        if not transaction_id or not isinstance(transaction_id, (bytes, str)):
            logger.debug("Missing or invalid transaction ID from %s", self.endpoint)
            return

        # Normalize transaction_id to bytes
        if isinstance(transaction_id, str):
            transaction_id = transaction_id.encode("latin-1")

        # Validate node ID length
        args = parsed.get("a", {})
        if not isinstance(args, dict):
            args = {}
        query_id = args.get("id", b"")
        if isinstance(query_id, str):
            query_id = query_id.encode("latin-1")
        if len(query_id) != 20:
            logger.debug("Invalid node ID length from %s", self.endpoint)
            error_msg = _encode_dht_error(transaction_id, 203, "Invalid node ID")
            self.write(error_msg)
            return

        # Handle v field - log client version if present (BEP 5 optional)
        # We don't reject non-compliant clients based on version string

        if query_type in (b"ping", "ping"):
            self._handle_ping(transaction_id, args)
        elif query_type in (b"find_node", "find_node"):
            self._handle_find_node(transaction_id, args)
        elif query_type in (b"get_peers", "get_peers"):
            self._handle_get_peers(transaction_id, args)
        elif query_type in (b"announce_peer", "announce_peer"):
            self._handle_announce_peer(transaction_id, args)
        else:
            logger.debug("Unknown query type: %s from %s", query_type, self.endpoint)
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
            rt = self.dht_node._get_routing_table(self.endpoint.is_ipv6)
            rt.increment_rpc_counter(self.node_id)

    def _handle_ping(self, transaction_id: bytes, args: dict) -> None:
        """Handle a ping query.

        BEP 5: Response contains the responding node's ID.
        """
        response = {"id": self.dht_node.node_id}
        resp_bytes = _encode_dht_response(transaction_id, response)
        self.write(resp_bytes)

    def _handle_find_node(self, transaction_id: bytes, args: dict) -> None:
        """Handle a find_node query.

        BEP 5: Respond with the target node or K closest nodes to the target.
        BEP 32: Include nodes6 when the request includes 'n6' in want or
        the request came from IPv6.
        """
        from dhtrack.bep32 import parse_want, WANT_N4, WANT_N6

        target = args.get("target", b"")
        if isinstance(target, str):
            target = target.encode("latin-1")

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

        response: dict[str, Any] = {"id": self.dht_node.node_id}

        if include_n4:
            closest_nodes = self.dht_node.routing_table_v4.get_closest_nodes(target, K)
            if closest_nodes:
                response["nodes"] = b"".join(
                    _compact_node_encode(
                        n.node_id,
                        n.endpoint.ip,
                        n.endpoint.port,
                        n.endpoint.is_ipv6,
                    )
                    for n in closest_nodes
                )
            else:
                response["nodes"] = b""

        if include_n6:
            closest_nodes6 = self.dht_node.routing_table_v6.get_closest_nodes(target, K)
            if closest_nodes6:
                response["nodes6"] = b"".join(
                    _compact_node_encode(
                        n.node_id,
                        n.endpoint.ip,
                        n.endpoint.port,
                        n.endpoint.is_ipv6,
                    )
                    for n in closest_nodes6
                )
            else:
                response["nodes6"] = b""

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
        from dhtrack.bep32 import parse_want, WANT_N4, WANT_N6

        info_hash = args.get("info_hash", b"")
        if isinstance(info_hash, str):
            info_hash = info_hash.encode("latin-1")

        if len(info_hash) != 20:
            error_msg = _encode_dht_error(transaction_id, 203, "Invalid info_hash")
            self.write(error_msg)
            return

        # Check for scrape and noseed flags (BEP 33)
        scrape = args.get("scrape", 0)
        if isinstance(scrape, str):
            scrape = scrape.encode("latin-1")
        scrape = scrape == b"1" or scrape is True

        noseed = args.get("noseed", 0)
        if isinstance(noseed, str):
            noseed = noseed.encode("latin-1")
        noseed = noseed == b"1" or noseed is True

        # Generate token for this peer's IP
        token = self.dht_node.token_secret.generate_token(self.endpoint.ip)

        # Check our peer store for peers
        peers = self.dht_node.peer_store.get_peers(info_hash)

        response: dict[str, Any] = {"id": self.dht_node.node_id, "token": token}

        if scrape and peers:
            bf_seed = self.dht_node.peer_store.get_seed_bloom_filter(info_hash)
            bf_peer = self.dht_node.peer_store.get_peer_bloom_filter(info_hash)
            if bf_seed:
                response["BFsd"] = bf_seed.to_bytes()
            if bf_peer:
                response["BFpe"] = bf_peer.to_bytes()
        elif peers:
            values = []
            for peer in peers:
                peer_data = _compact_peer_encode(peer.ip, peer.port, peer.is_ipv6)
                values.append(peer_data)
            response["values"] = values
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
                closest_v4 = self.dht_node.routing_table_v4.get_closest_nodes(info_hash, K)
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
                closest_v6 = self.dht_node.routing_table_v6.get_closest_nodes(info_hash, K)
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
        info_hash = args.get("info_hash", b"")
        if isinstance(info_hash, str):
            info_hash = info_hash.encode("latin-1")

        token = args.get("token", b"")
        if isinstance(token, str):
            token = token.encode("latin-1")

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
        is_seed = args.get("seed", 0)
        if isinstance(is_seed, str):
            is_seed = is_seed.encode("latin-1")
        is_seed = is_seed == b"1" or is_seed is True

        # Determine port
        implied_port = args.get("implied_port", 0)
        if implied_port and implied_port != 0:
            port = self.endpoint.port
        else:
            port_arg = args.get("port")
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
        response = {"id": self.dht_node.node_id}
        resp_bytes = _encode_dht_response(transaction_id, response)
        self.write(resp_bytes)

    def _handle_response(self, parsed: dict) -> None:
        """Handle an incoming response from a peer.

        Parameters
        ----------
        parsed : dict
            The parsed BEncode message.
        """
        try:
            transaction_id = parsed.get("t")
            if transaction_id not in self.queue:
                logger.debug("No matching transaction for response from %s", self.endpoint)
                return

            q = self.queue[transaction_id]
            del self.queue[transaction_id]

            if parsed.get("y") == "r":
                self._process_response(q, parsed)
            else:
                logger.debug("Non-response message for transaction %s", transaction_id)

        except (KeyError, TypeError):
            logger.debug("Error handling response from %s", self.endpoint)

    def _process_response(self, query: dict, response: dict) -> None:
        """Process a response to one of our queries.

        Parameters
        ----------
        query : dict
            The original query.
        response : dict
            The response received.
        """
        q_type = query.get("q")
        args = query.get("a", {})

        if q_type == "ping":
            node_id = response.get("r", {}).get("id")
            if node_id:
                if isinstance(node_id, str):
                    node_id = node_id.encode("latin-1")
                self.node_id = node_id
                self.last_seen = time.time()
                self.dht_node._mark_node_good(self)

        elif q_type == "find_node":
            nodes_data = response.get("r", {}).get("nodes", b"")
            if isinstance(nodes_data, bytes) and len(nodes_data) >= 26:
                self._parse_nodes(nodes_data, args)

            nodes6_data = response.get("r", {}).get("nodes6", b"")
            if isinstance(nodes6_data, bytes) and len(nodes6_data) >= 38:
                self._parse_ipv6_nodes(nodes6_data, args)

            self.dht_node.save_peers()

        elif q_type == "get_peers":
            values = response.get("r", {}).get("values", [])
            if isinstance(values, list):
                for peer_data in values:
                    if isinstance(peer_data, bytes) and len(peer_data) >= 6:
                        try:
                            ip, port, is_ipv6 = _compact_peer_decode(peer_data)
                            self.dht_node.add_peer(None, ip, port, is_ipv6=is_ipv6)
                        except (ValueError, socket.error):
                            continue

            nodes_data = response.get("r", {}).get("nodes", b"")
            if isinstance(nodes_data, bytes) and len(nodes_data) >= 26:
                self._parse_nodes(nodes_data, args)

            self.dht_node.save_peers()

    def _parse_nodes(self, data: bytes, args: dict) -> None:
        """Parse node information from response data.

        Parameters
        ----------
        data : bytes
            The raw node data (26 bytes per node).
        args : dict
            The original query arguments.
        """
        target = args.get("target", b"")
        for i in range(0, len(data), 26):
            if i + 26 > len(data):
                break

            node_id = data[i : i + 20]
            ip = data[i + 20 : i + 24]
            port = struct.unpack("!H", data[i + 24 : i + 26])[0]

            try:
                ip_str = socket.inet_ntop(socket.AF_INET, ip)
            except (socket.error, OSError):
                continue

            if len(node_id) != 20:
                continue

            peer = self.dht_node.add_peer(node_id, ip_str, port)
            if peer and node_id and target:
                # If this node is closer to target than our current node_id, query it
                if _xor_distance(target, node_id) <= _xor_distance(target, self.node_id or b"\x00" * 20):
                    peer.find_node(target)

    def _parse_ipv6_nodes(self, data: bytes, args: dict) -> None:
        """Parse IPv6 node information from response data.

        Parameters
        ----------
        data : bytes
            The raw node data (38 bytes per node).
        args : dict
            The original query arguments.
        """
        target = args.get("target", b"")
        for i in range(0, len(data), 38):
            if i + 38 > len(data):
                break

            node_id = data[i : i + 20]
            ip_bytes = data[i + 20 : i + 36]
            port = struct.unpack("!H", data[i + 36 : i + 38])[0]

            try:
                ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            except (socket.error, OSError):
                continue

            if len(node_id) != 20:
                continue

            peer = self.dht_node.add_peer(node_id, ip_str, port, is_ipv6=True)
            if peer and node_id and target:
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
        resp_bytes = _encode_dht_response(transaction_id, result)
        self.write(resp_bytes)

    def query(self, query_type: str, args: Optional[dict] = None) -> bytes:
        """Send a query to this peer.

        BEP 5: Encodes a KRPC query message with transaction ID, method,
        arguments, and version string.

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
        # BEP 5: Transaction ID must be a 2-byte hex string (4 ASCII chars)
        transaction_id = os.urandom(2).hex().encode("ascii")
        args = args or {}
        args["id"] = self.dht_node.node_id

        query_bytes = _encode_dht_query(query_type, args, transaction_id)

        self.queue[transaction_id] = {
            "q": query_type,
            "a": args,
            "timestamp": time.time(),
        }
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
        self.query("find_node", {"target": target_id})

    def __repr__(self) -> str:
        node_id_hex = binascii.b2a_hex(self.node_id).decode("ascii") if self.node_id else "UNKNOWN"
        return f"DHTPeer({node_id_hex} @ {self.endpoint})"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@dataclass
class Endpoint:
    """Network endpoint for a peer.

    Attributes
    ----------
    ip : str
        The IP address.
    port : int
        The port number.
    is_ipv6 : bool
        Whether this is an IPv6 address.
    """

    ip: str
    port: int
    is_ipv6: bool = False


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
    """

    def __init__(
        self,
        node_id: Optional[bytes] = None,
        bind_addr: tuple[str, int] = ("", 0),
        peers_file: str = DEFAULT_PEERS_FILE,
    ) -> None:
        self.node_id: bytes = node_id or os.urandom(20)
        self.peers_file: str = peers_file
        # BEP-27: Private torrent enforcement flag
        # When True, all DHT operations are disabled (private torrents
        # must not use DHT, PEX, or LSD for peer discovery).
        self._private_mode: bool = False

        # BEP-32: Separate IPv4 and IPv6 routing tables
        self.routing_table_v4: RoutingTable = RoutingTable(self.node_id)
        self.routing_table_v6: RoutingTable = RoutingTable(self.node_id)

        # Peer store for infohash -> peers mapping
        self.peer_store = PeerStore()

        # Token secret for announce_peer
        self.token_secret = TokenSecret()

        # Peer contact table (for active peers we've communicated with)
        self.peers: dict[tuple[str, int], DHTPeer] = {}

        # Pending queries with timeout tracking
        self._pending_queries: dict[bytes, dict] = {}

        # Create IPv4 socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)
        self.sock.bind(bind_addr)
        self._setup_socket_watch(self.sock, socket.AF_INET)

        # Create IPv6 socket if available
        self.sock6: Optional[socket.socket] = None
        if socket.has_ipv6:
            try:
                self.sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                self.sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if getattr(socket, "IPV6_V6ONLY", False):
                    self.sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
                self.sock6.bind(bind_addr)
                self._setup_socket_watch(self.sock6, socket.AF_INET6)
            except (OSError, socket.error):
                logger.debug("IPv6 socket creation failed, continuing with IPv4 only")

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

    def is_dht_allowed(self, info_hash: Optional[bytes] = None) -> bool:
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

    def enforce_private_mode(self, torrent: Optional["Torrent"] = None) -> None:
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

    def _setup_socket_watch(self, sock: socket.socket, family: int) -> None:
        """Set up a GLib IO watch on a socket.

        Parameters
        ----------
        sock : socket.socket
            The socket to watch.
        family : int
            The address family (AF_INET or AF_INET6).
        """
        fd = sock.fileno()
        GLib.io_add_watch(fd, GLib.PollFlags.IN, self._on_datagram)

    def _on_datagram(self, source: int, condition: GLib.PollFlags) -> bool:
        """Callback for incoming datagrams.

        Parameters
        ----------
        source : int
            The file descriptor source.
        condition : GLib.PollFlags
            The IO condition.

        Returns
        -------
        bool
            True to keep the watch active.
        """
        if condition & GLib.PollFlags.IN:
            try:
                data, addr = self._recvfrom(source)
                if data and addr:
                    self._handle_datagram(data, addr)
            except OSError:
                pass
        return True

    def _recvfrom(self, fd: int) -> tuple[bytes, tuple]:
        """Receive data from a socket file descriptor.

        Parameters
        ----------
        fd : int
            The file descriptor to receive from.

        Returns
        -------
        tuple[bytes, tuple]
            The received data and sender address.
        """
        for sock in [self.sock, self.sock6]:
            if sock and sock.fileno() == fd:
                data, addr = sock.recvfrom(MTU)
                return data, addr
        raise OSError("Socket not found for file descriptor")

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

    def _get_routing_table(self, is_ipv6: bool) -> RoutingTable:
        """Get the appropriate routing table for the address family.

        Parameters
        ----------
        is_ipv6 : bool
            Whether this is an IPv6 address.

        Returns
        -------
        RoutingTable
            The IPv4 or IPv6 routing table.
        """
        if is_ipv6:
            return self.routing_table_v6
        return self.routing_table_v4

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
        endpoint = Endpoint(ip, port, is_ipv6=is_ipv6)

        # Check if we know this peer
        peer_key = (ip, port)
        if peer_key in self.peers:
            self.peers[peer_key].recv(data)
        else:
            # New data from unknown peer - add and ping to verify
            logger.debug("Data from unknown peer: %s", addr)
            peer = self.add_peer(None, ip, port, is_ipv6=is_ipv6)
            if peer:
                peer.ping()

    def _mark_node_good(self, peer: DHTPeer) -> None:
        """Mark a node as good in the routing table.

        Parameters
        ----------
        peer : DHTPeer
            The peer to mark as good.
        """
        if peer.node_id:
            for bucket in self.routing_table.buckets:
                for node in bucket.nodes:
                    if node.node_id == peer.node_id:
                        node.status = NodeStatus.GOOD
                        node.last_contacted = time.time()
                        node.failure_count = 0
                        break

    def _process_pending_queries(self) -> None:
        """Process and timeout any pending queries that have expired."""
        now = time.time()
        expired = []
        for tid, query_info in self._pending_queries.items():
            if now - query_info.get("timestamp", 0) > TIMEOUT:
                expired.append(tid)

        for tid in expired:
            query_info = self._pending_queries.pop(tid, None)
            if query_info:
                logger.debug("Query %s timed out", tid.hex())

    def bootstrap(self, nodes: Optional[list[tuple[str, int]]] = None) -> None:
        """Bootstrap the DHT node by connecting to known router nodes.

        BEP 5: "Upon inserting the first node into its routing table and when
        starting up thereafter, the node should attempt to find the closest
        nodes in the DHT to itself."

        Parameters
        ----------
        nodes : list of tuple, optional
            Custom bootstrap nodes. Uses default nodes if not provided.
        """
        nodes = nodes or DEFAULT_BOOTSTRAP_NODES

        for host, port in nodes:
            try:
                addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
                for addr_info in addr_infos:
                    family, _, _, _, sockaddr = addr_info
                    host_addr = sockaddr[0]
                    port_addr = sockaddr[1]

                    peer = self.add_peer(None, host_addr, port_addr)
                    if peer:
                        # Find our own node ID (closest to our ID = our ID itself)
                        peer.find_node(self.node_id)

            except socket.gaierror:
                logger.warning("Failed to resolve %s", host)

    def add_peer(
        self,
        node_id: Optional[bytes],
        ip: str,
        port: int,
        is_ipv6: bool = False,
    ) -> Optional[DHTPeer]:
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

        Returns
        -------
        DHTPeer | None
            The created peer, or None if already exists.
        """
        endpoint = Endpoint(ip=ip, port=port, is_ipv6=is_ipv6)
        peer_key = (ip, port)

        if peer_key not in self.peers:
            peer = DHTPeer(dht_node=self, endpoint=endpoint, node_id=node_id)
            self.peers[peer_key] = peer

            # Also add to routing table if we have a node_id
            # BEP-32: Add to the appropriate routing table based on address family
            if node_id and len(node_id) == 20:
                bucket_node = BucketNode(
                    node_id=node_id,
                    endpoint=endpoint,
                    status=NodeStatus.GOOD,
                    last_contacted=time.time(),
                )
                rt = self._get_routing_table(is_ipv6)
                rt.add_node(bucket_node)

            return peer
        return None

    def save_peers(self, path: Optional[str] = None) -> None:
        """Save known peers to a file.

        Parameters
        ----------
        path : str, optional
            The file path. Defaults to peers_file.
        """
        path = path or self.peers_file

        try:
            with open(path, "wb") as fh:
                for peer in self.peers.values():
                    if peer.node_id is not None:
                        fh.write(
                            peer.node_id
                            + socket.inet_aton(peer.endpoint.ip)
                            + struct.pack("!H", peer.endpoint.port)
                        )
        except OSError as exc:
            logger.error("Failed to save peers: %s", exc)

    def load_peers(self, path: Optional[str] = None) -> int:
        """Load known peers from a file.

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

        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(26)
                    if len(chunk) < 26:
                        break

                    node_id = chunk[:20]
                    ip_bytes = chunk[20:24]
                    port = struct.unpack("!H", chunk[24:26])[0]

                    try:
                        ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
                        self.add_peer(node_id, ip, port)
                        count += 1
                    except (socket.error, OSError):
                        continue
        except FileNotFoundError:
            logger.info("No existing peers file found at %s", path)
        except OSError as exc:
            logger.error("Failed to load peers: %s", exc)

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
        closest_nodes = self.routing_table.get_closest_nodes(target_id, K)
        queried = set()
        result_peers: list[DHTPeer] = []

        # Find nodes we know about that are closer than what we have
        for peer in self.peers.values():
            if peer.node_id and peer.node_id not in queried:
                if _xor_distance(target_id, peer.node_id) < _xor_distance(
                    target_id,
                    closest_nodes[0].node_id if closest_nodes else b"\x00" * 20,
                ):
                    closest_nodes.append(BucketNode(peer.node_id, peer.endpoint))
                    closest_nodes.sort(key=lambda n: _xor_distance(target_id, n.node_id))
                    closest_nodes = closest_nodes[:K]

        # Iterative search
        while closest_nodes:
            node = closest_nodes.pop(0)
            node_id_hex = binascii.b2a_hex(node.node_id).decode("ascii")

            if node_id_hex in queried:
                continue
            queried.add(node_id_hex)

            # Find the DHTPeer for this node
            peer = None
            for p in self.peers.values():
                if p.node_id == node.node_id:
                    peer = p
                    break

            if peer:
                peer.find_node(target_id)
                # Wait briefly for response
                time.sleep(0.1)

            # Get closer nodes from responses
            closer = self.routing_table.get_closest_nodes(target_id, K)
            if not closer or all(binascii.b2a_hex(n.node_id).decode("ascii") in queried for n in closer):
                break

            closest_nodes = [n for n in closer if binascii.b2a_hex(n.node_id).decode("ascii") not in queried] + closest_nodes

        return [p for p in self.peers.values() if p.node_id]

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
        # First check our peer store
        peers = self.peer_store.get_peers(info_hash)
        if peers:
            return peers

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

    def close(self) -> None:
        """Close all socket connections."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

        if self.sock6:
            try:
                self.sock6.close()
            except OSError:
                pass


def run_dht_node(
    peers_file: str = DEFAULT_PEERS_FILE,
    bootstrap_nodes: Optional[list[tuple[str, int]]] = None,
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

    # Load existing peers
    node.load_peers()

    # Bootstrap
    node.bootstrap(bootstrap_nodes)

    return node


def create_application() -> Gtk.Application:
    """Create a GTK application for the DHT inspector.

    Returns
    -------
    Gtk.Application
        The configured application.
    """
    return Gtk.Application(
        application_id="com.dhtrack.client",
        flags=Gio.ApplicationFlags.FLAGS_NONE,
    )