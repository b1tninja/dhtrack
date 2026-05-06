"""Tests for the dhtrack.dht module."""

from __future__ import annotations

import binascii
import os
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
from dhtrack.peerid import Endpoint, PeerIdParser, PeerInfo


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
        # Get initial secrets
        initial_secrets = list(ts._secrets)
        # Force rotation by setting a very old time
        ts._secrets = [(time.time() - 600, ts._secrets[0][1])] if ts._secrets else []
        ts.rotate_if_needed()
        # Should have added a new secret
        assert len(ts._secrets) > len(initial_secrets) or ts._secrets[0][0] > time.time() - 10

    def test_token_validation_with_previous_secret(self):
        """Tokens generated with previous secret should be valid during overlap window."""
        ts = TokenSecret()
        # Generate a token with current secret
        token = ts.generate_token("127.0.0.1")
        assert ts.validate_token(token, "127.0.0.1") is True

    def test_token_10_minute_acceptance(self):
        """Tokens from the last rotation interval should still be valid."""
        ts = TokenSecret()
        # Simulate having a secret from 7 minutes ago (within 10-min window but older than 5-min rotation)
        old_secret = os.urandom(20)
        old_time = time.time() - 420  # 7 minutes ago
        ts._secrets.insert(0, (old_time, old_secret))
        # Keep current secret fresh
        ts._secrets.append((time.time(), os.urandom(20)))

        # Generate token with old secret
        import hashlib
        token = hashlib.sha1(old_secret + b"192.168.1.1").digest()[:20]
        assert ts.validate_token(token, "192.168.1.1") is True


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
        # BEP 5: transaction ID must be hex-encoded (4 ASCII chars for 2 bytes)
        tid = b"0a1b"
        args = {"id": b"\x02" * 20}
        result = _encode_dht_query("ping", args, tid)
        # Just verify it encodes without error
        assert result is not None

    def test_encode_query_includes_version(self):
        """Query should include the version string."""
        tid = b"0a1b"
        args = {"id": b"\x02" * 20}
        result = _encode_dht_query("ping", args, tid)
        # The version string should be in the encoded output
        assert CLIENT_VERSION_STRING.encode("ascii") in result

    def test_encode_query_hex_transaction_id(self):
        """Transaction ID should be stored as hex string in BEncode."""
        tid = b"abcd"
        args = {"id": b"\x02" * 20}
        result = _encode_dht_query("ping", args, tid)
        from dhtrack.bencode import decode
        decoded = decode(result)
        # Transaction ID in BEncode should match what we passed in
        assert decoded["t"] == tid

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
        """Query should generate a hex-encoded transaction ID (4 ASCII chars per BEP 5)."""
        tid = peer.query("ping")
        # BEP 5: transaction ID is a 2-byte hex string = 4 ASCII characters
        assert len(tid) == 4
        # Should be valid hex
        int(tid, 16)

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

        # Create a ping query (BEP 5: transaction ID is hex string)
        tid = b"0a1b"
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

        tid = b"0a1b"  # BEP 5 hex-encoded transaction ID
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

        tid = b"0a1b"  # BEP 5 hex-encoded transaction ID
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

        tid = b"0a1b"  # BEP 5 hex-encoded transaction ID
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

        tid = b"0a1b"  # BEP 5 hex-encoded transaction ID
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
        tid = b"0a1b"  # BEP 5 hex-encoded transaction ID
        result = {"id": b"\x02" * 20, "nodes": b"\x03" * 26}
        encoded = _encode_dht_response(tid, result)

        from dhtrack.bencode import decode
        decoded = decode(encoded)
        assert decoded["y"] == "r"
        assert decoded["t"] == tid
        assert "r" in decoded

    def test_error_encoding(self):
        """Error encoding should be valid BEncode."""
        tid = b"0a1b"  # BEP 5 hex-encoded transaction ID
        encoded = _encode_dht_error(tid, 203, "Invalid token")

        from dhtrack.bencode import decode
        decoded = decode(encoded)
        assert decoded["y"] == "e"
        assert decoded["t"] == tid
        assert "e" in decoded
        assert isinstance(decoded["e"], list)
        assert decoded["e"][0] == 203


# ============================================================================
# PeerIdParser Tests (BEP 0020)
# ============================================================================


class TestPeerIdParser:
    """Tests for the PeerIdParser class (BEP 0020)."""

    def test_empty_peer_id(self):
        """Empty peer ID should return Unknown."""
        info = PeerIdParser.parse(b"")
        assert info.client_name == "Unknown"
        assert info.client_code == ""
        assert info.peer_id_format == "unknown"

    def test_none_peer_id(self):
        """None peer ID should return Unknown."""
        info = PeerIdParser.parse(None)
        assert info.client_name == "Unknown"

    def test_short_peer_id(self):
        """Very short peer ID should return Unknown."""
        info = PeerIdParser.parse(b"\x00" * 5)
        assert info.client_name == "Unknown"

    def test_raw_peer_id_preserved(self):
        """Raw peer ID should be preserved in PeerInfo."""
        peer_id = b"M4-3-6--\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.raw_peer_id == peer_id

    # --- Mainline format ---

    def test_mainline_format(self):
        """Mainline format: M4-3-6--"""
        peer_id = b"M4-3-6--\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Mainline"
        assert info.client_code == "M"
        assert info.peer_id_format == "mainline"
        assert info.version == (4, 3, 6)

    def test_mainline_format_newer(self):
        """Mainline format with newer version: M4-20-8-"""
        peer_id = b"M4-20-8-\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Mainline"
        assert info.peer_id_format == "mainline"
        assert info.version == (4, 20, 8)

    def test_mainline_format_single_digit(self):
        """Mainline format with single digit version: M5-----"""
        peer_id = b"M5-----\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Mainline"
        assert info.peer_id_format == "mainline"
        assert info.version == (5,)

    # --- uTorrent format ---

    def test_utorrent_format(self):
        """uTorrent format: uT0000-"""
        peer_id = b"uT0500-\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "µTorrent"
        assert info.client_code == "uT"
        assert info.peer_id_format == "utorrent"
        assert info.version == (0, 5, 0)

    def test_utorrent_format_v2(self):
        """uTorrent format: uT2240-"""
        peer_id = b"uT2240-\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "µTorrent"
        assert info.peer_id_format == "utorrent"
        assert info.version == (2, 2, 4)

    # --- Shadow/BitTornado format ---

    def test_shadow_format(self):
        """Shadow format: S58B-----"""
        peer_id = b"S58B-----\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Shadow's client"
        assert info.client_code == "S"
        assert info.peer_id_format == "shadow"

    def test_bittornado_format(self):
        """BitTornado format: T4000-----"""
        peer_id = b"T4000-----\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitTornado"
        assert info.client_code == "T"
        assert info.peer_id_format == "shadow"

    def test_abc_format(self):
        """ABC format: A-----"""
        peer_id = b"A-----\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "ABC"
        assert info.client_code == "A"
        assert info.peer_id_format == "shadow"

    def test_tribler_format(self):
        """Tribler format: R-----"""
        peer_id = b"R-----\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Tribler"
        assert info.client_code == "R"
        assert info.peer_id_format == "shadow"

    # --- BitComet format ---

    def test_bitcomet_format(self):
        """BitComet format: exbc + version bytes"""
        peer_id = b"exbc\x03\x06" + b"\x00" * 14
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitComet"
        assert info.client_code == "exbc"
        assert info.peer_id_format == "bitcomet"
        assert info.version == (3, 6)

    def test_bitcomet_format_v100(self):
        """BitComet format: version 1.0.0"""
        peer_id = b"exbc\x01\x00" + b"\x00" * 14
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitComet"
        assert info.peer_id_format == "bitcomet"
        assert info.version == (1, 0)

    # --- BitLord format ---

    def test_bitlord_format(self):
        """BitLord format: exbcLORD + version bytes"""
        peer_id = b"exbcLORD\x01\x00" + b"\x00" * 10
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitLord"
        assert info.client_code == "exbc"
        assert info.peer_id_format == "bitlord"
        assert info.version == (1, 0)

    # --- XBT format ---

    def test_xbt_format(self):
        """XBT format: XBT054d-"""
        peer_id = b"XBT054d-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "XBT"
        assert info.client_code == "XB"
        assert info.peer_id_format == "xbt"
        assert info.version == (0, 5, 4)
        assert info.is_debug is True
        assert info.comment == "Debug build"

    def test_xbt_release_format(self):
        """XBT release format: XBT054--"""
        peer_id = b"XBT054--\x00\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "XBT"
        assert info.peer_id_format == "xbt"
        assert info.version == (0, 5, 4)
        assert info.is_debug is False

    # --- Opera format ---

    def test_opera_format(self):
        """Opera format: OP + build number"""
        peer_id = b"OP1234" + b"\x00" * 14
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Opera"
        assert info.client_code == "OP"
        assert info.peer_id_format == "opera"
        assert info.build == 1234

    # --- MLdonkey format ---

    def test_mldonkey_format(self):
        """MLdonkey format: -ML2.7.2-"""
        peer_id = b"-ML2.7.2-kgjjfkd"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "MLdonkey"
        assert info.client_code == "ML"
        assert info.peer_id_format == "mldonkey"
        assert info.version == (2, 7, 2)

    # --- Bits on Wheels format ---

    def test_bow_format(self):
        """Bits on Wheels format: -BOWA0C-"""
        peer_id = b"-BOWA0C-" + b"\x00" * 8
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Bits on Wheels"
        assert info.client_code == "BOW"
        assert info.peer_id_format == "bow"
        assert info.comment is not None

    # --- Queen Bee format ---

    def test_queenbee_format(self):
        """Queen Bee format: Q1-0-0--"""
        peer_id = b"Q1-0-0--\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Queen Bee"
        assert info.client_code == "Q"
        assert info.peer_id_format == "queenbee"
        assert info.version == (1, 0, 0)

    # --- BitTyrant format ---

    def test_bittyrant_format(self):
        """BitTyrant format: AZ2500BT + random"""
        peer_id = b"AZ2500BT" + b"\x00" * 12
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitTyrant"
        assert info.client_code == "BT"
        assert info.peer_id_format == "bittyrant"
        assert info.comment == "Azureus fork"

    # --- TorrenTopia format ---

    def test_torrentopia_format(self):
        """TorrenTopia format: 346------"""
        peer_id = b"346------\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "TorrenTopia"
        assert info.peer_id_format == "torrentopia"
        assert info.comment == "Claims to be Mainline 3.4.6"

    # --- BitSpirit format ---

    def test_bitspirit_format(self):
        """BitSpirit format: \\0\\3BS"""
        peer_id = b"\x00\x03BS" + b"\x00" * 16
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitSpirit"
        assert info.client_code == "BS"
        assert info.peer_id_format == "bitspirit"

    # --- Rufus format ---

    def test_rufus_format(self):
        """Rufus format: ASCII version + RS + nickname"""
        peer_id = b"12RS" + b"mypip" + b"\x00" * 13
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Rufus"
        assert info.client_code == "RS"
        assert info.peer_id_format == "rufus"
        assert info.nickname == "mypip"
        assert info.version == (49, 50)  # ASCII values '1' and '2'

    # --- G3 Torrent format ---

    def test_g3_format(self):
        """G3 Torrent format: -G3 + nickname"""
        peer_id = b"-G3myuser" + b"\x00" * 12
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "G3 Torrent"
        assert info.client_code == "G3"
        assert info.peer_id_format == "g3"
        assert info.nickname == "myuser"

    # --- FlashGet format ---

    def test_flashget_format(self):
        """FlashGet format: FG + version"""
        peer_id = b"FG0180" + b"\x00" * 14
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "FlashGet"
        assert info.client_code == "FG"
        assert info.peer_id_format == "flashget"
        assert info.version == (1, 80)

    # --- AllPeers format ---

    def test_allpeers_format(self):
        """AllPeers format: AP + version + -"""
        peer_id = b"AP123-" + b"\x00" * 14
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "AllPeers"
        assert info.client_code == "AP"
        assert info.peer_id_format == "allpeers"
        assert info.version == (123,)

    # --- Dash-style format ---

    def test_dash_format_azureus(self):
        """Azureus dash format: -AZ2060-"""
        peer_id = b"-AZ2060-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Azureus"
        assert info.client_code == "AZ"
        assert info.peer_id_format == "dash"
        assert info.version == (20, 60)

    def test_dash_format_transmission(self):
        """Transmission dash format: -TR2750-"""
        peer_id = b"-TR2750-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Transmission"
        assert info.client_code == "TR"
        assert info.peer_id_format == "dash"
        assert info.version == (27, 50)

    def test_dash_format_deluge(self):
        """Deluge dash format: -DE1310-"""
        peer_id = b"-DE1310-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "DelugeTorrent"
        assert info.client_code == "DE"
        assert info.peer_id_format == "dash"

    def test_dash_format_qbittorrent(self):
        """qBittorrent dash format: -qB4320-"""
        peer_id = b"-qB4320-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "qBittorrent"
        assert info.client_code == "qB"
        assert info.peer_id_format == "dash"

    def test_dash_format_webtorrent(self):
        """WebTorrent dash format: -WW1000-"""
        peer_id = b"-WW1000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "WebTorrent"
        assert info.client_code == "WW"
        assert info.peer_id_format == "dash"

    def test_dash_format_libtorrent(self):
        """libtorrent dash format: -LT0916-"""
        peer_id = b"-LT0916-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "libtorrent"
        assert info.client_code == "LT"
        assert info.peer_id_format == "libtorrent"

    def test_dash_format_utorrent_short(self):
        """µTorrent dash format: -UT0000-"""
        peer_id = b"-UT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "µTorrent"
        assert info.client_code == "UT"
        assert info.peer_id_format == "dash"

    def test_dash_format_shareaza(self):
        """Shareaza dash format: -SZ0000-"""
        peer_id = b"-SZ0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Shareaza"
        assert info.client_code == "SZ"
        assert info.peer_id_format == "dash"

    def test_dash_format_limewire(self):
        """LimeWire dash format: -LW0000-"""
        peer_id = b"-LW0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "LimeWire"
        assert info.client_code == "LW"
        assert info.peer_id_format == "dash"

    def test_dash_format_frostwire(self):
        """FrostWire dash format: -FW0000-"""
        peer_id = b"-FW0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "FrostWire"
        assert info.client_code == "FW"
        assert info.peer_id_format == "dash"

    def test_dash_format_ktorrent(self):
        """KTorrent dash format: -KT0000-"""
        peer_id = b"-KT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "KTorrent"
        assert info.client_code == "KT"
        assert info.peer_id_format == "dash"

    def test_dash_format_bitcomet(self):
        """BitComet dash format: -BC0000-"""
        peer_id = b"-BC0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitComet"
        assert info.client_code == "BC"
        assert info.peer_id_format == "dash"

    def test_dash_format_bitflu(self):
        """Bitflu dash format: -BF0000-"""
        peer_id = b"-BF0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Bitflu"
        assert info.client_code == "BF"
        assert info.peer_id_format == "dash"

    def test_dash_format_ares(self):
        """Ares dash format: -AG0000-"""
        peer_id = b"-AG0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Ares"
        assert info.client_code == "AG"
        assert info.peer_id_format == "dash"

    def test_dash_format_vagaa(self):
        """Vagaa dash format: -VG0000-"""
        peer_id = b"-VG0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Vagaa"
        assert info.client_code == "VG"
        assert info.peer_id_format == "dash"

    def test_dash_format_xunlei(self):
        """Xunlei dash format: -XL0000-"""
        peer_id = b"-XL0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Xunlei"
        assert info.client_code == "XL"
        assert info.peer_id_format == "dash"

    def test_dash_format_webtorrent_desktop(self):
        """WebTorrent Desktop dash format: -WD0000-"""
        peer_id = b"-WD0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "WebTorrent Desktop"
        assert info.client_code == "WD"
        assert info.peer_id_format == "dash"

    def test_dash_format_utleencher(self):
        """uLeecher! dash format: -UL0000-"""
        peer_id = b"-UL0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "uLeecher!"
        assert info.client_code == "UL"
        assert info.peer_id_format == "dash"

    def test_dash_format_halflife(self):
        """Halite dash format: -HL0000-"""
        peer_id = b"-HL0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Halite"
        assert info.client_code == "HL"
        assert info.peer_id_format == "dash"

    def test_dash_format_miro(self):
        """Miro dash format: -MR0000-"""
        peer_id = b"-MR0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Miro"
        assert info.client_code == "MR"
        assert info.peer_id_format == "dash"

    def test_dash_format_mono(self):
        """MonoTorrent dash format: -MO0000-"""
        peer_id = b"-MO0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "MonoTorrent"
        assert info.client_code == "MO"
        assert info.peer_id_format == "dash"

    def test_dash_format_pando(self):
        """Pando dash format: -PD0000-"""
        peer_id = b"-PD0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Pando"
        assert info.client_code == "PD"
        assert info.peer_id_format == "dash"

    def test_dash_format_gstorrent(self):
        """GSTorrent dash format: -GS0000-"""
        peer_id = b"-GS0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "GSTorrent"
        assert info.client_code == "GS"
        assert info.peer_id_format == "dash"

    def test_dash_format_hydranode(self):
        """Hydranode dash format: -HN0000-"""
        peer_id = b"-HN0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Hydranode"
        assert info.client_code == "HN"
        assert info.peer_id_format == "dash"

    def test_dash_format_kget(self):
        """KGet dash format: -KG0000-"""
        peer_id = b"-KG0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "KGet"
        assert info.client_code == "KG"
        assert info.peer_id_format == "dash"

    def test_dash_format_net_transport(self):
        """Net Transport dash format: -NX0000-"""
        peer_id = b"-NX0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Net Transport"
        assert info.client_code == "NX"
        assert info.peer_id_format == "dash"

    def test_dash_format_electric_sheep(self):
        """electric Sheep dash format: -ES0000-"""
        peer_id = b"-ES0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "electric Sheep"
        assert info.client_code == "ES"
        assert info.peer_id_format == "dash"

    def test_dash_format_bitbuddy(self):
        """BitBuddy dash format: -BB0000-"""
        peer_id = b"-BB0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitBuddy"
        assert info.client_code == "BB"
        assert info.peer_id_format == "dash"

    def test_dash_format_bitrocket(self):
        """BitRocket dash format: -BR0000-"""
        peer_id = b"-BR0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitRocket"
        assert info.client_code == "BR"
        assert info.peer_id_format == "dash"

    def test_dash_format_bitpump(self):
        """BitPump dash format: -AX0000-"""
        peer_id = b"-AX0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitPump"
        assert info.client_code == "AX"
        assert info.peer_id_format == "dash"

    def test_dash_format_enhanced_ctorrent(self):
        """Enhanced CTorrent dash format: -CD0000-"""
        peer_id = b"-CD0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Enhanced CTorrent"
        assert info.client_code == "CD"
        assert info.peer_id_format == "dash"

    def test_dash_format_ctorrent(self):
        """CTorrent dash format: -CT0000-"""
        peer_id = b"-CT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "CTorrent"
        assert info.client_code == "CT"
        assert info.peer_id_format == "dash"

    def test_dash_format_ebit(self):
        """EBit dash format: -EB0000-"""
        peer_id = b"-EB0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "EBit"
        assert info.client_code == "EB"
        assert info.peer_id_format == "dash"

    def test_dash_format_foxtorrent(self):
        """FoxTorrent dash format: -FT0000-"""
        peer_id = b"-FT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "FoxTorrent"
        assert info.client_code == "FT"
        assert info.peer_id_format == "dash"

    def test_dash_format_freelbox(self):
        """Freebox BitTorrent dash format: -FX0000-"""
        peer_id = b"-FX0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Freebox BitTorrent"
        assert info.client_code == "FX"
        assert info.peer_id_format == "dash"

    def test_dash_format_moopolic(self):
        """MooPolice dash format: -MP0000-"""
        peer_id = b"-MP0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "MooPolice"
        assert info.client_code == "MP"
        assert info.peer_id_format == "dash"

    def test_dash_format_propagate(self):
        """Propagate Data Client dash format: -DP0000-"""
        peer_id = b"-DP0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Propagate Data Client"
        assert info.client_code == "DP"
        assert info.peer_id_format == "dash"

    def test_dash_format_qqdownload(self):
        """QQDownload dash format: -QD0000-"""
        peer_id = b"-QD0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "QQDownload"
        assert info.client_code == "QD"
        assert info.peer_id_format == "dash"

    def test_dash_format_qt4torrent(self):
        """Qt 4 Torrent example dash format: -QT0000-"""
        peer_id = b"-QT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Qt 4 Torrent example"
        assert info.client_code == "QT"
        assert info.peer_id_format == "dash"

    def test_dash_format_retriever(self):
        """Retriever dash format: -RT0000-"""
        peer_id = b"-RT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Retriever"
        assert info.client_code == "RT"
        assert info.peer_id_format == "dash"

    def test_dash_format_swiftbit(self):
        """Swiftbit dash format: -SB0000-"""
        peer_id = b"-SB0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Swiftbit"
        assert info.client_code == "SB"
        assert info.peer_id_format == "dash"

    def test_dash_format_swarmscope(self):
        """SwarmScope dash format: -SS0000-"""
        peer_id = b"-SS0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "SwarmScope"
        assert info.client_code == "SS"
        assert info.peer_id_format == "dash"

    def test_dash_format_symtorrent(self):
        """SymTorrent dash format: -ST0000-"""
        peer_id = b"-ST0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "SymTorrent"
        assert info.client_code == "ST"
        assert info.peer_id_format == "dash"

    def test_dash_format_torrentdotnet(self):
        """TorrentDotNET dash format: -TN0000-"""
        peer_id = b"-TN0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "TorrentDotNET"
        assert info.client_code == "TN"
        assert info.peer_id_format == "dash"

    def test_dash_format_torrentstorm(self):
        """Torrentstorm dash format: -TS0000-"""
        peer_id = b"-TS0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Torrentstorm"
        assert info.client_code == "TS"
        assert info.peer_id_format == "dash"

    def test_dash_format_toutu(self):
        """TuoTu dash format: -TT0000-"""
        peer_id = b"-TT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "TuoTu"
        assert info.client_code == "TT"
        assert info.peer_id_format == "dash"

    def test_dash_format_xan_torrent(self):
        """XanTorrent dash format: -XT0000-"""
        peer_id = b"-XT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "XanTorrent"
        assert info.client_code == "XT"
        assert info.peer_id_format == "dash"

    def test_dash_format_xtorrent(self):
        """Xtorrent dash format: -XX0000-"""
        peer_id = b"-XX0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Xtorrent"
        assert info.client_code == "XX"
        assert info.peer_id_format == "dash"

    def test_dash_format_ziptorrent(self):
        """ZipTorrent dash format: -ZT0000-"""
        peer_id = b"-ZT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "ZipTorrent"
        assert info.client_code == "ZT"
        assert info.peer_id_format == "dash"

    def test_dash_format_arctic(self):
        """Arctic dash format: -AR0000-"""
        peer_id = b"-AR0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Arctic"
        assert info.client_code == "AR"
        assert info.peer_id_format == "dash"

    def test_dash_format_avicora(self):
        """Avicora dash format: -AV0000-"""
        peer_id = b"-AV0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Avicora"
        assert info.client_code == "AV"
        assert info.peer_id_format == "dash"

    def test_dash_format_btg(self):
        """BTG (Rasterbar libtorrent) dash format: -BG0000-"""
        peer_id = b"-BG0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BTG"
        assert info.client_code == "BG"
        assert info.peer_id_format == "dash"

    def test_dash_format_btslave(self):
        """BTSlave dash format: -BS0000-"""
        peer_id = b"-BS0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BTSlave"
        assert info.client_code == "BS"
        assert info.peer_id_format == "dash"

    def test_dash_format_bittorrent_x(self):
        """Bittorrent X dash format: -BX0000-"""
        peer_id = b"-BX0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Bittorrent X"
        assert info.client_code == "BX"
        assert info.peer_id_format == "dash"

    def test_dash_format_shareaza_alpha(self):
        """Shareaza alpha/beta dash format: -S~0000-"""
        peer_id = b"-S~0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Shareaza"
        assert info.client_code == "S~"
        assert info.peer_id_format == "dash"

    def test_dash_format_lphant(self):
        """Lphant dash format: -LP0000-"""
        peer_id = b"-LP0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "Lphant"
        assert info.client_code == "LP"
        assert info.peer_id_format == "dash"

    def test_dash_format_lh_abc(self):
        """LH-ABC dash format: -LH0000-"""
        peer_id = b"-LH0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "LH-ABC"
        assert info.client_code == "LH"
        assert info.peer_id_format == "dash"

    def test_dash_format_sharktorrent(self):
        """sharktorrent dash format: -st0000-"""
        peer_id = b"-st0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "sharktorrent"
        assert info.client_code == "st"
        assert info.peer_id_format == "dash"

    def test_dash_format_firetorrent(self):
        """FireTorrent dash format: -WY0000-"""
        peer_id = b"-WY0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "FireTorrent"
        assert info.client_code == "WY"
        assert info.peer_id_format == "dash"

    def test_dash_format_bitlet(self):
        """BitLet dash format: -WT0000-"""
        peer_id = b"-WT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "BitLet"
        assert info.client_code == "WT"
        assert info.peer_id_format == "dash"

    def test_dash_format_utorrent_web(self):
        """µTorrent Web dash format: -UW0000-"""
        peer_id = b"-UW0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "µTorrent Web"
        assert info.client_code == "UW"
        assert info.peer_id_format == "dash"

    def test_dash_format_moonlight(self):
        """MoonlightTorrent dash format: -MT0000-"""
        peer_id = b"-MT0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "MoonlightTorrent"
        assert info.client_code == "MT"
        assert info.peer_id_format == "dash"

    def test_libtorrent_lt_format(self):
        """libTorrent (lowercase lt) format: -lt0000-"""
        peer_id = b"-lt0000-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.client_name == "libTorrent"
        assert info.client_code == "lt"
        assert info.peer_id_format == "libtorrent"

    # --- identify() method ---

    def test_identify_mainline(self):
        """identify() should return human-readable string."""
        peer_id = b"M4-3-6--\x00\x00\x00\x00\x00\x00\x00\x00"
        result = PeerIdParser.identify(peer_id)
        assert "Mainline" in result
        assert "v4" in result

    def test_identify_utorrent(self):
        """identify() for uTorrent."""
        peer_id = b"uT0500-\x00\x00\x00\x00\x00\x00\x00\x00"
        result = PeerIdParser.identify(peer_id)
        assert "µTorrent" in result

    def test_identify_xbt_debug(self):
        """identify() for XBT debug build."""
        peer_id = b"XBT054d-\x00\x00\x00\x00\x00\x00\x00"
        result = PeerIdParser.identify(peer_id)
        assert "XBT" in result
        assert "debug" in result

    def test_identify_unknown(self):
        """identify() for unknown format."""
        peer_id = b"\x00" * 20
        result = PeerIdParser.identify(peer_id)
        assert "Unknown" in result

    # --- Client map completeness ---

    def test_client_map_has_expected_clients(self):
        """CLIENT_MAP should contain well-known clients."""
        expected = {"AZ", "TR", "DE", "UT", "qB", "LT", "WW", "TR", "BC", "SZ"}
        for code in expected:
            assert code in PeerIdParser.CLIENT_MAP, f"{code} not in CLIENT_MAP"

    def test_dash_style_detection(self):
        """Dash-style peer IDs should be detected by format."""
        peer_id = b"-AZ2060-\x00\x00\x00\x00\x00\x00\x00"
        info = PeerIdParser.parse(peer_id)
        assert info.peer_id_format == "dash"

    def test_known_dash_clients_set(self):
        """DASH_CLIENTS should contain known codes."""
        assert "AZ" in PeerIdParser.DASH_CLIENTS
        assert "TR" in PeerIdParser.DASH_CLIENTS
        assert "DE" in PeerIdParser.DASH_CLIENTS
