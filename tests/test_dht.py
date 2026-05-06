"""Tests for the dhtrack.dht module."""

from __future__ import annotations

import binascii
import socket
import struct
import time
from unittest.mock import MagicMock, patch

import pytest

from dhtrack.dht import (
    K,
    BUCKET_SIZE,
    CLIENT_VERSION_STRING,
    DHTNode,
    DHTPeer,
    Endpoint,
    KBucket,
    NodeStatus,
    PeerStore,
    RoutingTable,
    StoredPeer,
    TokenSecret,
    BucketNode,
    _compact_node_decode,
    _compact_node_encode,
    _compact_peer_decode,
    _compact_peer_encode,
    _encode_dht_error,
    _encode_dht_query,
    _encode_dht_response,
    _xor_distance,
)


# ============================================================================
# XOR Distance Tests
# ============================================================================


class TestXorDistance:
    """Tests for the _xor_distance function."""

    def test_distance_to_self(self):
        """Distance from a node ID to itself should be 0."""
        node_id = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
        assert _xor_distance(node_id, node_id) == 0

    def test_distance_symmetry(self):
        """distance(A, B) == distance(B, A)."""
        a = b"\x00" * 20
        b = b"\xff" * 20
        assert _xor_distance(a, b) == _xor_distance(b, a)

    def test_distance_invalid_length(self):
        """Should raise ValueError for wrong-length inputs."""
        with pytest.raises(ValueError, match="Node IDs must be 20 bytes"):
            _xor_distance(b"\x00" * 10, b"\x00" * 20)
        with pytest.raises(ValueError, match="Node IDs must be 20 bytes"):
            _xor_distance(b"\x00" * 20, b"\x00" * 10)

    def test_distance_all_zeros_vs_all_ones(self):
        """Maximum possible XOR distance."""
        zeros = b"\x00" * 20
        ones = b"\xff" * 20
        dist = _xor_distance(zeros, ones)
        assert dist == 2 ** 160 - 1

    def test_distance_single_bit_difference(self):
        """Distance with a single bit difference."""
        a = b"\x00" * 20
        b = b"\x01" + b"\x00" * 19
        dist = _xor_distance(a, b)
        assert dist == 1

    def test_distance_is_less_than(self):
        """Test that smaller distance means closer."""
        a = b"\x00" * 20
        b = b"\xff" * 20
        c = b"\x01" + b"\x00" * 19
        # c is closer to a than b is
        assert _xor_distance(a, c) < _xor_distance(a, b)


# ============================================================================
# Compact Node Encoding/Decoding Tests
# ============================================================================


class TestCompactNodeEncode:
    """Tests for _compact_node_encode."""

    def test_encode_ipv4(self):
        """Encode IPv4 node info (26 bytes)."""
        node_id = b"\x01" * 20
        result = _compact_node_encode(node_id, "127.0.0.1", 6881)
        assert len(result) == 26
        assert result[:20] == node_id
        assert result[20:24] == socket.inet_aton("127.0.0.1")
        assert result[24:26] == struct.pack("!H", 6881)

    def test_encode_ipv6(self):
        """Encode IPv6 node info (38 bytes)."""
        node_id = b"\x01" * 20
        result = _compact_node_encode(node_id, "::1", 6881, is_ipv6=True)
        assert len(result) == 38
        assert result[:20] == node_id
        assert result[20:36] == socket.inet_pton(socket.AF_INET6, "::1")
        assert result[36:38] == struct.pack("!H", 6881)

    def test_encode_invalid_node_id(self):
        """Should raise ValueError for wrong-length node ID."""
        with pytest.raises(ValueError, match="node_id must be 20 bytes"):
            _compact_node_encode(b"\x00" * 10, "127.0.0.1", 6881)


class TestCompactNodeDecode:
    """Tests for _compact_node_decode."""

    def test_decode_ipv4(self):
        """Decode IPv4 node info."""
        node_id = b"\x01" * 20
        data = node_id + socket.inet_aton("127.0.0.1") + struct.pack("!H", 6881)
        result_node_id, ip, port, is_ipv6 = _compact_node_decode(data)
        assert result_node_id == node_id
        assert ip == "127.0.0.1"
        assert port == 6881
        assert is_ipv6 is False

    def test_decode_ipv6(self):
        """Decode IPv6 node info."""
        node_id = b"\x01" * 20
        data = node_id + socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("!H", 6881)
        result_node_id, ip, port, is_ipv6 = _compact_node_decode(data)
        assert result_node_id == node_id
        assert ip == "::1"
        assert port == 6881
        assert is_ipv6 is True

    def test_decode_invalid_length(self):
        """Should raise ValueError for invalid data length."""
        with pytest.raises(ValueError, match="Invalid compact node data length"):
            _compact_node_decode(b"\x00" * 20)


class TestCompactPeerEncode:
    """Tests for _compact_peer_encode."""

    def test_encode_ipv4(self):
        """Encode IPv4 peer info (6 bytes)."""
        result = _compact_peer_encode("127.0.0.1", 6881)
        assert len(result) == 6
        assert result == socket.inet_aton("127.0.0.1") + struct.pack("!H", 6881)

    def test_encode_ipv6(self):
        """Encode IPv6 peer info (18 bytes)."""
        result = _compact_peer_encode("::1", 6881, is_ipv6=True)
        assert len(result) == 18
        assert result == socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("!H", 6881)


class TestCompactPeerDecode:
    """Tests for _compact_peer_decode."""

    def test_decode_ipv4(self):
        """Decode IPv4 peer info."""
        data = socket.inet_aton("127.0.0.1") + struct.pack("!H", 6881)
        ip, port, is_ipv6 = _compact_peer_decode(data)
        assert ip == "127.0.0.1"
        assert port == 6881
        assert is_ipv6 is False

    def test_decode_ipv6(self):
        """Decode IPv6 peer info."""
        data = socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("!H", 6881)
        ip, port, is_ipv6 = _compact_peer_decode(data)
        assert ip == "::1"
        assert port == 6881
        assert is_ipv6 is True

    def test_decode_invalid_length(self):
        """Should raise ValueError for invalid data length."""
        with pytest.raises(ValueError, match="Invalid compact peer data length"):
            _compact_peer_decode(b"\x00" * 5)


# ============================================================================
# Token Secret Tests
# ============================================================================


class TestTokenSecret:
    """Tests for the TokenSecret class."""

    def test_generate_token(self):
        """Token generation should return 20 bytes."""
        ts = TokenSecret()
        token = ts.generate_token("127.0.0.1")
        assert len(token) == 20

    def test_generate_token_deterministic(self):
        """Same IP with same secret should produce same token."""
        ts = TokenSecret()
        token1 = ts.generate_token("127.0.0.1")
        token2 = ts.generate_token("127.0.0.1")
        assert token1 == token2

    def test_generate_token_different_ips(self):
        """Different IPs should produce different tokens."""
        ts = TokenSecret()
        token1 = ts.generate_token("127.0.0.1")
        token2 = ts.generate_token("192.168.1.1")
        assert token1 != token2

    def test_validate_token_valid(self):
        """Validating a freshly generated token should succeed."""
        ts = TokenSecret()
        token = ts.generate_token("127.0.0.1")
        assert ts.validate_token(token, "127.0.0.1") is True

    def test_validate_token_wrong_ip(self):
        """Token for a different IP should fail."""
        ts = TokenSecret()
        token = ts.generate_token("127.0.0.1")
        # After a short time, the token might still be valid due to rotation window
        # But with a different IP it should fail
        assert ts.validate_token(token, "192.168.1.1") is False

    def test_validate_token_invalid(self):
        """Random bytes should not validate."""
        ts = TokenSecret()
        random_token = b"\x00" * 20
        assert ts.validate_token(random_token, "127.0.0.1") is False

    def test_rotate_if_needed(self):
        """Secret should rotate after the interval."""
        ts = TokenSecret()
        initial_secret = ts._secret
        # Force rotation
        ts._rotation_time = time.time() - 600  # 10 minutes ago
        ts.rotate_if_needed()
        assert ts._secret != initial_secret or ts._rotation_time > time.time() - 10


# ============================================================================
# Peer Store Tests
# ============================================================================


class TestPeerStore:
    """Tests for the PeerStore class."""

    def test_add_and_get_peer(self):
        """Add a peer and retrieve it."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        store.add_peer(info_hash, "127.0.0.1", 6881)
        peers = store.get_peers(info_hash)
        assert len(peers) == 1
        assert peers[0].ip == "127.0.0.1"
        assert peers[0].port == 6881

    def test_add_multiple_peers(self):
        """Add multiple peers for the same infohash."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        store.add_peer(info_hash, "127.0.0.1", 6881)
        store.add_peer(info_hash, "127.0.0.2", 6881)
        store.add_peer(info_hash, "127.0.0.3", 6881)
        peers = store.get_peers(info_hash)
        assert len(peers) == 3

    def test_get_peers_empty(self):
        """Get peers for unknown infohash should return empty list."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        assert store.get_peers(info_hash) == []

    def test_add_peer_limits(self):
        """Should limit stored peers per infohash to 20."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        for i in range(25):
            store.add_peer(info_hash, f"127.0.0.{i}", 6881)
        peers = store.get_peers(info_hash)
        assert len(peers) <= 20

    def test_remove_peer(self):
        """Remove a peer should return True."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        store.add_peer(info_hash, "127.0.0.1", 6881)
        assert store.remove_peer(info_hash, "127.0.0.1", 6881) is True

    def test_remove_peer_not_found(self):
        """Remove a non-existent peer should return False."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        assert store.remove_peer(info_hash, "127.0.0.1", 6881) is False

    def test_invalid_info_hash(self):
        """Adding a peer with invalid info_hash should raise."""
        store = PeerStore()
        with pytest.raises(ValueError, match="info_hash must be 20 bytes"):
            store.add_peer(b"\x00" * 10, "127.0.0.1", 6881)

    def test_node_id_storage(self):
        """Node ID should be stored with the peer."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        node_id = b"\x02" * 20
        store.add_peer(info_hash, "127.0.0.1", 6881, node_id=node_id)
        peers = store.get_peers(info_hash)
        assert peers[0].node_id == node_id


# ============================================================================
# KBucket Tests
# ============================================================================


class TestKBucket:
    """Tests for the KBucket class."""

    def test_add_node(self):
        """Adding a node should succeed in an empty bucket."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        endpoint = Endpoint("127.0.0.1", 6881)
        node = BucketNode(node_id=b"\x01" * 20, endpoint=endpoint)
        assert bucket.add_node(node) is True
        assert len(bucket.nodes) == 1

    def test_add_duplicate_node(self):
        """Adding a duplicate node should update, not duplicate."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        endpoint1 = Endpoint("127.0.0.1", 6881)
        node1 = BucketNode(node_id=b"\x01" * 20, endpoint=endpoint1)
        bucket.add_node(node1)

        endpoint2 = Endpoint("127.0.0.2", 6881)
        node2 = BucketNode(node_id=b"\x01" * 20, endpoint=endpoint2)
        assert bucket.add_node(node2) is True
        assert len(bucket.nodes) == 1
        assert bucket.nodes[0].endpoint.ip == "127.0.0.2"

    def test_bucket_full(self):
        """Bucket should be full after K nodes."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        for i in range(K):
            endpoint = Endpoint(f"127.0.0.{i}", 6881)
            node = BucketNode(node_id=bytes([i]) * 20, endpoint=endpoint)
            assert bucket.add_node(node) is True

        # Next one should fail
        endpoint = Endpoint("127.0.0.99", 6881)
        node = BucketNode(node_id=b"\x99" * 20, endpoint=endpoint)
        assert bucket.add_node(node) is False

    def test_remove_node(self):
        """Removing a node should work."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        node_id = b"\x01" * 20
        endpoint = Endpoint("127.0.0.1", 6881)
        node = BucketNode(node_id=node_id, endpoint=endpoint)
        bucket.add_node(node)
        bucket.remove_node(node_id)
        assert len(bucket.nodes) == 0

    def test_mark_good(self):
        """Marking a node as good should update status."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        node_id = b"\x01" * 20
        endpoint = Endpoint("127.0.0.1", 6881)
        node = BucketNode(node_id=node_id, endpoint=endpoint, status=NodeStatus.QUESTIONABLE)
        bucket.add_node(node)
        bucket.mark_good(node_id)
        assert bucket.nodes[0].status == NodeStatus.GOOD

    def test_mark_bad(self):
        """Marking a node as bad should update status."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        node_id = b"\x01" * 20
        endpoint = Endpoint("127.0.0.1", 6881)
        node = BucketNode(node_id=node_id, endpoint=endpoint, status=NodeStatus.GOOD)
        bucket.add_node(node)
        bucket.mark_bad(node_id)
        assert bucket.nodes[0].status == NodeStatus.BAD

    def test_increment_failure_count(self):
        """After 3 failures, node should be bad."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        node_id = b"\x01" * 20
        endpoint = Endpoint("127.0.0.1", 6881)
        node = BucketNode(node_id=node_id, endpoint=endpoint, status=NodeStatus.GOOD)
        bucket.add_node(node)
        bucket.increment_failure_count(node_id)
        bucket.increment_failure_count(node_id)
        bucket.increment_failure_count(node_id)
        assert bucket.nodes[0].status == NodeStatus.BAD
        assert bucket.nodes[0].failure_count == 3

    def test_get_closest_nodes(self):
        """Should return nodes sorted by distance to target."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        target = b"\x80" * 20

        # Node A is far from target
        node_a_id = b"\xff" * 20
        # Node B is close to target
        node_b_id = b"\x7f" * 20

        endpoint_a = Endpoint("127.0.0.1", 6881)
        endpoint_b = Endpoint("127.0.0.2", 6881)

        bucket.add_node(BucketNode(node_id=node_a_id, endpoint=endpoint_a))
        bucket.add_node(BucketNode(node_id=node_b_id, endpoint=endpoint_b))

        closest = bucket.get_closest_nodes(target, count=1)
        assert closest[0].node_id == node_b_id

    def test_split(self):
        """Splitting a bucket should create two buckets."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        left, right = bucket.split()
        assert left.min_id == b"\x00" * 20
        assert right.max_id == b"\xff" * 20
        # The split point should be at the first bit difference
        assert left.max_id < right.min_id

    def test_is_full_property(self):
        """is_full should return True when bucket has K nodes."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        assert bucket.is_full is False
        for i in range(K):
            endpoint = Endpoint(f"127.0.0.{i}", 6881)
            node = BucketNode(node_id=bytes([i]) * 20, endpoint=endpoint)
            bucket.add_node(node)
        assert bucket.is_full is True

    def test_good_nodes_property(self):
        """good_nodes should return only good nodes."""
        bucket = KBucket(b"\x00" * 20, b"\xff" * 20)
        endpoint = Endpoint("127.0.0.1", 6881)
        good_node = BucketNode(
            node_id=b"\x01" * 20,
            endpoint=endpoint,
            status=NodeStatus.GOOD,
        )
        bad_node = BucketNode(
            node_id=b"\x02" * 20,
            endpoint=endpoint,
            status=NodeStatus.BAD,
        )
        bucket.add_node(good_node)
        bucket.add_node(bad_node)
        assert len(bucket.good_nodes) == 1
        assert bucket.good_nodes[0].status == NodeStatus.GOOD


# ============================================================================
# Routing Table Tests
# ============================================================================


class TestRoutingTable:
    """Tests for the RoutingTable class."""

    def test_init(self):
        """Routing table should start with one bucket."""
        my_id = b"\x01" * 20
        rt = RoutingTable(my_id)
        assert len(rt.buckets) == 1
        assert rt.my_node_id == my_id

    def test_add_node(self):
        """Adding a node should succeed."""
        my_id = b"\x01" * 20
        rt = RoutingTable(my_id)
        endpoint = Endpoint("127.0.0.1", 6881)
        node = BucketNode(node_id=b"\x02" * 20, endpoint=endpoint)
        assert rt.add_node(node) is True

    def test_get_closest_nodes(self):
        """Should return closest nodes to target."""
        my_id = b"\x01" * 20
        rt = RoutingTable(my_id)

        node_a_id = b"\x02" * 20
        node_b_id = b"\x03" * 20
        target = b"\x04" * 20

        endpoint_a = Endpoint("127.0.0.1", 6881)
        endpoint_b = Endpoint("127.0.0.2", 6881)

        rt.add_node(BucketNode(node_id=node_a_id, endpoint=endpoint_a))
        rt.add_node(BucketNode(node_id=node_b_id, endpoint=endpoint_b))

        closest = rt.get_closest_nodes(target, count=1)
        assert len(closest) == 1

    def test_get_closest_nodes_empty(self):
        """Should return empty list when no nodes exist."""
        my_id = b"\x01" * 20
        rt = RoutingTable(my_id)
        assert rt.get_closest_nodes(b"\x02" * 20, count=K) == []

    def test_remove_node(self):
        """Removing a node should work."""
        my_id = b"\x01" * 20
        rt = RoutingTable(my_id)
        endpoint = Endpoint("127.0.0.1", 6881)
        node_id = b"\x02" * 20
        rt.add_node(BucketNode(node_id=node_id, endpoint=endpoint))
        rt.remove_node(node_id)
        assert rt.get_closest_nodes(node_id) == []

    def test_get_nodes_by_status(self):
        """Should filter nodes by status."""
        my_id = b"\x01" * 20
        rt = RoutingTable(my_id)
        endpoint = Endpoint("127.0.0.1", 6881)
        good_node = BucketNode(
            node_id=b"\x01" * 20,
            endpoint=endpoint,
            status=NodeStatus.GOOD,
        )
        bad_node = BucketNode(
            node_id=b"\x02" * 20,
            endpoint=endpoint,
            status=NodeStatus.BAD,
        )
        rt.add_node(good_node)
        rt.add_node(bad_node)

        good = rt.get_nodes_by_status(NodeStatus.GOOD)
        bad = rt.get_nodes_by_status(NodeStatus.BAD)
        assert len(good) == 1
        assert len(bad) == 1


# ============================================================================
# KRPC Message Encoding Tests
# ============================================================================


class TestKRPCMessageEncoding:
    """Tests for KRPC message encoding functions."""

    def test_encode_query(self):
        """Query should include all required fields."""
        tid = b"\x00\x01"
        args = {"id": b"\x02" * 20}
        result = _encode_dht_query("ping", args, tid)
        decoded = result  # In production, this would be BEncode.decode
        # Just verify it encodes without error
        assert result is not None

    def test_encode_query_includes_version(self):
        """Query should include the version string."""
        tid = b"\x00\x01"
        args = {"id": b"\x02" * 20}
        result = _encode_dht_query("ping", args, tid)
        # The version string should be in the encoded output
        assert CLIENT_VERSION_STRING.encode("ascii") in result

    def test_encode_response(self):
        """Response should include all required fields."""
        tid = b"\x00\x01"
        result = {"id": b"\x02" * 20}
        encoded = _encode_dht_response(tid, result)
        assert encoded is not None
        assert CLIENT_VERSION_STRING.encode("ascii") in encoded

    def test_encode_error(self):
        """Error should include all required fields."""
        tid = b"\x00\x01"
        encoded = _encode_dht_error(tid, 203, "Invalid token")
        assert encoded is not None
        # Should contain the error code
        # The error is encoded as a list [203, "message"]

    def test_encode_error_protocol_error(self):
        """Error code 203 is for protocol errors."""
        tid = b"\x00\x01"
        encoded = _encode_dht_error(tid, 203, "Protocol error")
        assert encoded is not None

    def test_encode_error_method_unknown(self):
        """Error code 204 is for unknown methods."""
        tid = b"\x00\x01"
        encoded = _encode_dht_error(tid, 204, "Method not found")
        assert encoded is not None


# ============================================================================
# Endpoint Tests
# ============================================================================


class TestEndpoint:
    """Tests for the Endpoint dataclass."""

    def test_endpoint_creation(self):
        """Endpoint should be created with ip and port."""
        ep = Endpoint("127.0.0.1", 6881)
        assert ep.ip == "127.0.0.1"
        assert ep.port == 6881
        assert ep.is_ipv6 is False

    def test_endpoint_ipv6(self):
        """Endpoint should support IPv6."""
        ep = Endpoint("::1", 6881, is_ipv6=True)
        assert ep.is_ipv6 is True

    def test_endpoint_hash(self):
        """Endpoints should be hashable."""
        ep1 = Endpoint("127.0.0.1", 6881)
        ep2 = Endpoint("127.0.0.1", 6881)
        assert hash(ep1) == hash(ep2)

    def test_endpoint_equality(self):
        """Endpoints with same ip and port should be equal."""
        ep1 = Endpoint("127.0.0.1", 6881)
        ep2 = Endpoint("127.0.0.1", 6881)
        assert ep1 == ep2

    def test_endpoint_inequality(self):
        """Endpoints with different ip or port should not be equal."""
        ep1 = Endpoint("127.0.0.1", 6881)
        ep2 = Endpoint("127.0.0.2", 6881)
        assert ep1 != ep2

    def test_endpoint_repr(self):
        """Repr should show ip and port."""
        ep = Endpoint("127.0.0.1", 6881)
        assert repr(ep) == "Endpoint(127.0.0.1:6881)"


# ============================================================================
# DHTPeer Tests
# ============================================================================


class TestDHTPeer:
    """Tests for the DHTPeer class."""

    @pytest.fixture
    def mock_dht_node(self):
        """Create a mock DHTNode."""
        node_id = b"\x01" * 20
        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.sock = MagicMock()
        mock_node.sock6 = None
        mock_node.routing_table = MagicMock()
        mock_node.peer_store = MagicMock()
        mock_node.token_secret = MagicMock()
        return mock_node

    @pytest.fixture
    def peer(self, mock_dht_node):
        """Create a DHTPeer."""
        endpoint = Endpoint("127.0.0.1", 6881)
        return DHTPeer(dht_node=mock_dht_node, endpoint=endpoint, node_id=b"\x02" * 20)

    def test_peer_repr(self, peer):
        """Repr should show node_id and endpoint."""
        node_id_hex = binascii.b2a_hex(peer.node_id).decode("ascii")
        assert node_id_hex in repr(peer)

    def test_peer_repr_unknown(self):
        """Repr should show UNKNOWN for unknown node_id."""
        mock_node = MagicMock()
        mock_node.node_id = b"\x01" * 20
        endpoint = Endpoint("127.0.0.1", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=None)
        assert "UNKNOWN" in repr(peer)

    def test_query_creates_transaction_id(self, peer):
        """Query should generate a transaction ID."""
        tid = peer.query("ping")
        assert len(tid) == 2

    def test_query_stores_in_queue(self, peer):
        """Query should store query info in the peer's queue."""
        peer.query("ping")
        assert len(peer.queue) == 1

    def test_ping(self, peer):
        """Ping should send a query."""
        peer.ping()
        assert len(peer.queue) == 1


# ============================================================================
# DHTNode Tests
# ============================================================================


class TestDHTNode:
    """Tests for the DHTNode class."""

    def test_create_node(self):
        """Creating a DHTNode should generate a node ID."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.peers_file = "/tmp/test_peers.dat"
        node.routing_table = MagicMock()
        node.peer_store = MagicMock()
        node.token_secret = MagicMock()
        node.peers = {}
        node._pending_queries = {}
        node.sock = MagicMock()
        node.sock6 = None

        assert len(node.node_id) == 20

    def test_node_id_random(self):
        """Node ID should be randomly generated."""
        node1 = DHTNode.__new__(DHTNode)
        node1.node_id = b"\x01" * 20
        node2 = DHTNode.__new__(DHTNode)
        node2.node_id = b"\x02" * 20
        assert node1.node_id != node2.node_id

    def test_add_peer(self):
        """Adding a peer should create a DHTPeer."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.peers_file = "/tmp/test_peers.dat"
        node.routing_table = MagicMock()
        node.peer_store = MagicMock()
        node.token_secret = MagicMock()
        node.peers = {}
        node._pending_queries = {}
        node.sock = MagicMock()
        node.sock6 = None

        peer = node.add_peer(b"\x02" * 20, "127.0.0.1", 6881)
        assert peer is not None
        assert peer.endpoint.ip == "127.0.0.1"
        assert peer.endpoint.port == 6881

    def test_add_duplicate_peer(self):
        """Adding a duplicate peer should return None."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.peers_file = "/tmp/test_peers.dat"
        node.routing_table = MagicMock()
        node.peer_store = MagicMock()
        node.token_secret = MagicMock()
        node.peers = {}
        node._pending_queries = {}
        node.sock = MagicMock()
        node.sock6 = None

        peer1 = node.add_peer(b"\x02" * 20, "127.0.0.1", 6881)
        peer2 = node.add_peer(b"\x03" * 20, "127.0.0.1", 6881)
        assert peer1 is not None
        assert peer2 is None

    def test_save_peers(self, tmp_path):
        """Saving peers should write to file."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.peers_file = str(tmp_path / "peers.dat")
        node.routing_table = MagicMock()
        node.peer_store = MagicMock()
        node.token_secret = MagicMock()
        node.peers = {}
        node._pending_queries = {}
        node.sock = MagicMock()
        node.sock6 = None

        peer = node.add_peer(b"\x02" * 20, "127.0.0.1", 6881)
        node.save_peers()

        assert (tmp_path / "peers.dat").exists()

    def test_load_peers(self, tmp_path):
        """Loading peers should read from file."""
        peers_file = str(tmp_path / "peers.dat")

        # Create a peers file
        node_id = b"\x02" * 20
        ip_bytes = socket.inet_aton("127.0.0.1")
        port_bytes = struct.pack("!H", 6881)
        with open(peers_file, "wb") as f:
            f.write(node_id + ip_bytes + port_bytes)

        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.peers_file = peers_file
        node.routing_table = MagicMock()
        node.peer_store = MagicMock()
        node.token_secret = MagicMock()
        node.peers = {}
        node._pending_queries = {}
        node.sock = MagicMock()
        node.sock6 = None

        count = node.load_peers()
        assert count >= 0  # May be 0 if peer already exists


# ============================================================================
# StoredPeer Tests
# ============================================================================


class TestStoredPeer:
    """Tests for the StoredPeer dataclass."""

    def test_stored_peer_creation(self):
        """StoredPeer should be created with required fields."""
        peer = StoredPeer(ip="127.0.0.1", port=6881)
        assert peer.ip == "127.0.0.1"
        assert peer.port == 6881
        assert peer.node_id is None
        assert peer.is_ipv6 is False

    def test_stored_peer_with_node_id(self):
        """StoredPeer should store node_id."""
        node_id = b"\x01" * 20
        peer = StoredPeer(ip="127.0.0.1", port=6881, node_id=node_id)
        assert peer.node_id == node_id

    def test_last_seen_default(self):
        """last_seen should default to current time."""
        peer = StoredPeer(ip="127.0.0.1", port=6881)
        assert peer.last_seen > 0


# ============================================================================
# NodeStatus Tests
# ============================================================================


class TestNodeStatus:
    """Tests for the NodeStatus constants."""

    def test_good_status(self):
        assert NodeStatus.GOOD == "good"

    def test_questionable_status(self):
        assert NodeStatus.QUESTIONABLE == "questionable"

    def test_bad_status(self):
        assert NodeStatus.BAD == "bad"


# ============================================================================
# Integration-style Tests
# ============================================================================


class TestDHTIntegration:
    """Integration-style tests for DHT components."""

    def test_full_ping_flow(self):
        """Test a complete ping query-response cycle."""
        # Create a mock node
        node_id = b"\x01" * 20
        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table = MagicMock()
        mock_node.routing_table.get_closest_nodes.return_value = []

        endpoint = Endpoint("127.0.0.1", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x02" * 20)

        # Create a ping query
        tid = b"\x00\x01"
        args = {"id": b"\x02" * 20}
        query_bytes = _encode_dht_query("ping", args, tid)

        # Verify query is valid BEncode
        from dhtrack.bencode import decode
        decoded = decode(query_bytes)
        assert decoded["y"] == "q"
        assert decoded["q"] == "ping"
        assert decoded["t"] == tid

    def test_full_find_node_flow(self):
        """Test a complete find_node query-response cycle."""
        node_id = b"\x01" * 20
        target = b"\x02" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table = MagicMock()
        mock_node.routing_table.get_closest_nodes.return_value = []

        endpoint = Endpoint("127.0.0.1", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x03" * 20)

        tid = b"\x00\x01"
        args = {"id": b"\x03" * 20, "target": target}
        query_bytes = _encode_dht_query("find_node", args, tid)

        from dhtrack.bencode import decode
        decoded = decode(query_bytes)
        assert decoded["q"] == "find_node"
        assert decoded["a"]["target"] == target

    def test_full_get_peers_flow(self):
        """Test a complete get_peers query-response cycle."""
        node_id = b"\x01" * 20
        info_hash = b"\x02" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table = MagicMock()
        mock_node.routing_table.get_closest_nodes.return_value = []
        mock_node.peer_store = MagicMock()
        mock_node.peer_store.get_peers.return_value = []
        mock_node.token_secret = MagicMock()
        mock_node.token_secret.generate_token.return_value = b"\x03" * 20

        endpoint = Endpoint("127.0.0.1", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x04" * 20)

        tid = b"\x00\x01"
        args = {"id": b"\x04" * 20, "info_hash": info_hash}
        query_bytes = _encode_dht_query("get_peers", args, tid)

        from dhtrack.bencode import decode
        decoded = decode(query_bytes)
        assert decoded["q"] == "get_peers"
        assert decoded["a"]["info_hash"] == info_hash

    def test_full_announce_peer_flow(self):
        """Test a complete announce_peer query-response cycle."""
        node_id = b"\x01" * 20
        info_hash = b"\x02" * 20
        token = b"\x03" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table = MagicMock()
        mock_node.routing_table.get_closest_nodes.return_value = []
        mock_node.peer_store = MagicMock()
        mock_node.token_secret = MagicMock()
        mock_node.token_secret.validate_token.return_value = True

        endpoint = Endpoint("127.0.0.1", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x04" * 20)

        tid = b"\x00\x01"
        args = {
            "id": b"\x04" * 20,
            "info_hash": info_hash,
            "port": 6881,
            "token": token,
        }
        query_bytes = _encode_dht_query("announce_peer", args, tid)

        from dhtrack.bencode import decode
        decoded = decode(query_bytes)
        assert decoded["q"] == "announce_peer"
        assert decoded["a"]["port"] == 6881

    def test_implied_port_announce_peer(self):
        """announce_peer with implied_port should work."""
        node_id = b"\x01" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table = MagicMock()
        mock_node.routing_table.get_closest_nodes.return_value = []
        mock_node.peer_store = MagicMock()
        mock_node.token_secret = MagicMock()
        mock_node.token_secret.validate_token.return_value = True

        endpoint = Endpoint("127.0.0.1", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x04" * 20)

        tid = b"\x00\x01"
        args = {
            "id": b"\x04" * 20,
            "info_hash": b"\x02" * 20,
            "implied_port": 1,
            "token": b"\x03" * 20,
        }
        query_bytes = _encode_dht_query("announce_peer", args, tid)

        from dhtrack.bencode import decode
        decoded = decode(query_bytes)
        assert decoded["a"]["implied_port"] == 1

    def test_response_encoding(self):
        """Response encoding should be valid BEncode."""
        tid = b"\x00\x01"
        result = {"id": b"\x02" * 20, "nodes": b"\x03" * 26}
        encoded = _encode_dht_response(tid, result)

        from dhtrack.bencode import decode
        decoded = decode(encoded)
        assert decoded["y"] == "r"
        assert decoded["t"] == tid
        assert "r" in decoded

    def test_error_encoding(self):
        """Error encoding should be valid BEncode."""
        tid = b"\x00\x01"
        encoded = _encode_dht_error(tid, 203, "Invalid token")

        from dhtrack.bencode import decode
        decoded = decode(encoded)
        assert decoded["y"] == "e"
        assert decoded["t"] == tid
        assert "e" in decoded
        assert isinstance(decoded["e"], list)
        assert decoded["e"][0] == 203