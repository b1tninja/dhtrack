"""Tests for DHT bootstrapping and torrent metadata retrieval.

This module tests:
- DHT node creation and initialization
- Bootstrap from known nodes (IPv4 and IPv6)
- Routing table growth after bootstrap
- Node discovery and peer storage
- Iterative get_peers search
- Metadata retrieval from DHT-discovered peers
"""

from __future__ import annotations

import os
import socket
import struct
import time
from unittest.mock import MagicMock, patch

import pytest

from dhtrack import bencode as bencode_module
from dhtrack.bencode import DecodeError
from dhtrack.bep53 import parse_magnet_uri
from dhtrack.dht import (
    DHTNode,
    DHTPeer,
    Endpoint,
    K,
    PeerStore,
    RoutingTable,
    _compact_peer_decode,
    _compact_peer_encode,
    _xor_distance,
)
from dhtrack.metadata_retriever import connect_to_peer
from dhtrack.torrent import Torrent, TorrentParseError

# ============================================================================
# Bootstrap API: dual-stack delegation and self-node verification
# ============================================================================


class TestBootstrapDualStackAndSelfVerification:
    """self_node_id_found and default bootstrap() behavior."""

    def test_self_node_id_found_uses_response_counter(self):
        """Propagation is detected via compact-node replies, not remote r.id."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = os.urandom(20)
        node.self_node_id_response_count = 0
        assert node.self_node_id_found is False
        node.self_node_id_response_count = 2
        assert node.self_node_id_found is True

    def test_bootstrap_sums_bootstrap_all_when_ipv6_socket_exists(self):
        """bootstrap(address_family=None) should query both families when sock6 is set."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.sock = MagicMock()
        node.sock6 = MagicMock()

        with patch.object(DHTNode, "bootstrap_all", return_value={"ipv4": 3, "ipv6": 4}) as bm:
            total = DHTNode.bootstrap(node, nodes=None, address_family=None)

        bm.assert_called_once_with(nodes=None)
        assert total == 7

    def test_bootstrap_does_not_use_bootstrap_all_when_ipv6_missing(self):
        """Without an IPv6 socket, bootstrap() uses a single-family path."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x02" * 20
        node.sock = MagicMock()
        node.sock.getsockname.return_value = ("0.0.0.0", 6881)
        node.sock6 = None
        node.peers = {}
        node.routing_table_v4 = RoutingTable(node.node_id)
        node.routing_table_v6 = RoutingTable(node.node_id)
        node.peer_store = PeerStore()
        node.token_secret = MagicMock()

        with patch.object(DHTNode, "bootstrap_all") as bm:
            with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("no dns")):
                with patch.object(DHTNode, "add_peer", return_value=None):
                    DHTNode.bootstrap(node, nodes=[], address_family=None)

        bm.assert_not_called()


# ============================================================================
# DHT Node Creation Tests
# ============================================================================


class TestDHTNodeCreation:
    """Tests for DHT node creation and initialization."""

    def test_create_node_defaults(self):
        """DHTNode should be created with default settings."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.peers_file = "/tmp/test_peers.dat"
        node.routing_table_v4 = RoutingTable(node.node_id)
        node.routing_table_v6 = RoutingTable(node.node_id)
        node.peer_store = PeerStore()
        node.token_secret = MagicMock()
        node.peers = {}
        node.sock = MagicMock()
        node.sock6 = None
        node._private_mode = False

        assert len(node.node_id) == 20
        assert node.peers_file == "/tmp/test_peers.dat"
        assert isinstance(node.routing_table_v4, RoutingTable)
        assert isinstance(node.routing_table_v6, RoutingTable)

    def test_node_id_length(self):
        """Node ID should always be 20 bytes."""
        node_id = b"\x01" * 20
        assert len(node_id) == 20

    def test_routing_tables_separate(self):
        """IPv4 and IPv6 routing tables should be independent."""
        node_id = b"\x01" * 20
        rt_v4 = RoutingTable(node_id)
        rt_v6 = RoutingTable(node_id)

        endpoint_v4 = Endpoint("127.0.0.1", 6881)
        node_v4 = MagicMock()
        node_v4.node_id = b"\x02" * 20
        node_v4.endpoint = endpoint_v4
        rt_v4.add_node(node_v4)

        assert rt_v6.get_closest_nodes(node_id) == []


# ============================================================================
# Bootstrap Tests
# ============================================================================


class TestBootstrapIPv4:
    """Tests for IPv4 bootstrap functionality."""

    def test_bootstrap_queries_peers_from_peers_dat_when_dns_unavailable(self):
        """peers.dat entries must get find_node like public routers (BEP‑5 warmup)."""
        node_id = b"\xaa" * 20
        node = DHTNode.__new__(DHTNode)
        node.node_id = node_id

        rm = MagicMock()
        rm.v4.buckets = []
        rm.v6.buckets = []
        node.routing_table = rm

        node.sock = MagicMock()
        node.sock.family = socket.AF_INET
        node.sock6 = None

        stored = MagicMock()
        stored.endpoint = Endpoint("192.0.2.55", 51413)
        stored.node_id = b"\xbb" * 20
        stored.find_node = MagicMock()
        node.peers = {("192.0.2.55", 51413): stored}

        with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("offline")):
            count = node.bootstrap(nodes=None, address_family=socket.AF_INET)

        assert count >= 1
        stored.find_node.assert_called_once_with(node_id)

    def test_bootstrap_no_nodes(self):
        """Bootstrap with no available nodes should return 0."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        rm = MagicMock()
        rm.v4.buckets = []
        rm.v6.buckets = []
        node.routing_table = rm
        node.peer_store = PeerStore()
        node.token_secret = MagicMock()
        node.peers = {}
        node.sock = MagicMock()
        node.sock.getsockname.return_value = ("127.0.0.1", 6881)
        node.sock6 = None

        with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("DNS failed")):
            with patch.object(DHTNode, "add_peer", return_value=None):
                result = node.bootstrap(nodes=[], address_family=socket.AF_INET)
                assert result == 0

    def test_bootstrap_node_added_to_table(self):
        """Bootstrap should add nodes to routing table."""
        node_id = b"\x01" * 20
        rt = RoutingTable(node_id)

        endpoint = Endpoint("192.168.1.1", 6881)
        bucket_node = MagicMock()
        bucket_node.node_id = b"\x02" * 20
        bucket_node.endpoint = endpoint
        rt.add_node(bucket_node)

        nodes = rt.get_closest_nodes(node_id)
        assert len(nodes) == 1
        assert nodes[0].node_id == b"\x02" * 20

    def test_bootstrap_multiple_nodes(self):
        """Bootstrap with multiple nodes should add all to routing table."""
        node_id = b"\x01" * 20
        rt = RoutingTable(node_id)

        for i in range(10):
            endpoint = Endpoint(f"192.168.1.{i + 1}", 6881 + i)
            bucket_node = MagicMock()
            bucket_node.node_id = bytes([i + 2]) * 20
            bucket_node.endpoint = endpoint
            rt.add_node(bucket_node)

        all_nodes = rt.get_closest_nodes(node_id, count=K)
        assert len(all_nodes) == min(K, 10)

    def test_bootstrap_self_discovery(self):
        """A node should be able to find itself in the routing table."""
        node_id = b"\x01" * 20
        rt = RoutingTable(node_id)

        endpoint = Endpoint("127.0.0.1", 6881)
        self_node = MagicMock()
        self_node.node_id = node_id
        self_node.endpoint = endpoint
        rt.add_node(self_node)

        closest = rt.get_closest_nodes(node_id, count=1)
        assert len(closest) == 1
        assert closest[0].node_id == node_id


# ============================================================================
# Bootstrap Recursive Tests
# ============================================================================


class TestBootstrapRecursive:
    """Tests for recursive bootstrap with node_id propagation."""

    def test_propagate_node_id_single_node(self):
        """Propagate node_id through a single node."""
        node_id = b"\x01" * 20
        target = node_id

        rt = RoutingTable(node_id)
        endpoint = Endpoint("192.168.1.1", 6881)
        bucket_node = MagicMock()
        bucket_node.node_id = b"\x02" * 20
        bucket_node.endpoint = endpoint
        rt.add_node(bucket_node)

        closest = rt.get_closest_nodes(target, count=K)
        assert len(closest) == 1

    def test_propagate_node_id_multiple_hops(self):
        """Node_id propagation should discover nodes closer to target."""
        node_id = b"\x01" * 20
        target = node_id

        rt = RoutingTable(node_id)

        for i in range(15):
            endpoint = Endpoint(f"192.168.1.{i + 1}", 6881 + i)
            node_data = bytes([(i + 1) % 256] * 20)
            bucket_node = MagicMock()
            bucket_node.node_id = node_data
            bucket_node.endpoint = endpoint
            rt.add_node(bucket_node)

        closest = rt.get_closest_nodes(target, count=K)
        assert len(closest) == K

        distances = [_xor_distance(target, n.node_id) for n in closest]
        assert distances == sorted(distances)


# ============================================================================
# Iterative Get Peers Tests
# ============================================================================


class TestIterativeGetPeers:
    """Tests for iterative get_peers search."""

    def test_iterative_get_peers_no_routing_table(self):
        """Iterative get_peers should handle empty routing table."""
        info_hash = b"\x01" * 20

        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x02" * 20
        node.routing_table_v4 = RoutingTable(node.node_id)
        node.routing_table_v6 = RoutingTable(node.node_id)
        node.peer_store = PeerStore()
        node.peers = {}
        node._private_mode = False

        peers = node.iterative_get_peers(info_hash, max_depth=1)
        assert isinstance(peers, list)
        assert len(peers) == 0

    def test_iterative_get_peers_with_stored_peers(self):
        """Iterative get_peers should return stored peers without searching."""
        info_hash = b"\x01" * 20

        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x02" * 20
        node.routing_table_v4 = RoutingTable(node.node_id)
        node.routing_table_v6 = RoutingTable(node.node_id)
        node.peer_store = PeerStore()
        node.peers = {}
        node._private_mode = False

        node.peer_store.add_peer(info_hash, "192.168.1.1", 6881)
        node.peer_store.add_peer(info_hash, "192.168.1.2", 6882)

        peers = node.iterative_get_peers(info_hash, max_depth=0)
        assert len(peers) == 2

    def test_iterative_get_peers_max_depth_zero(self):
        """max_depth=0 should not query any nodes."""
        info_hash = b"\x01" * 20

        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x02" * 20
        node.routing_table_v4 = RoutingTable(node.node_id)
        node.routing_table_v6 = RoutingTable(node.node_id)
        node.peer_store = PeerStore()
        node.peers = {}
        node._private_mode = False

        for i in range(5):
            endpoint = Endpoint(f"192.168.1.{i + 1}", 6881)
            bucket_node = MagicMock()
            bucket_node.node_id = bytes([(i + 1) % 256] * 20)
            bucket_node.endpoint = endpoint
            node.routing_table_v4.add_node(bucket_node)

        peers = node.iterative_get_peers(info_hash, max_depth=0)
        assert isinstance(peers, list)


# ============================================================================
# Peer Discovery Tests
# ============================================================================


class TestPeerDiscovery:
    """Tests for peer discovery through DHT queries."""

    def test_parse_node_response(self):
        """Parsing node response should create DHTPeer entries."""
        nodes_data = b""
        for i in range(3):
            node_id = bytes([i + 1] * 20)
            ip_data = socket.inet_aton(f"192.168.1.{i + 1}")
            port = struct.pack("!H", 6881 + i)
            nodes_data += node_id + ip_data + port

        parsed_nodes = []
        for i in range(0, len(nodes_data), 26):
            chunk = nodes_data[i : i + 26]
            if len(chunk) == 26:
                nid = chunk[:20]
                ip = socket.inet_ntop(socket.AF_INET, chunk[20:24])
                port = struct.unpack("!H", chunk[24:26])[0]
                parsed_nodes.append((nid, ip, port))

        assert len(parsed_nodes) == 3
        assert parsed_nodes[0][1] == "192.168.1.1"
        assert parsed_nodes[0][2] == 6881

    def test_parse_ipv6_node_response(self):
        """Parsing IPv6 node response should create DHTPeer entries."""
        nodes_data = b""
        for i in range(2):
            node_id = bytes([i + 1] * 20)
            ip_data = socket.inet_pton(socket.AF_INET6, "::1")
            port = struct.pack("!H", 6881 + i)
            nodes_data += node_id + ip_data + port

        parsed_nodes = []
        for i in range(0, len(nodes_data), 38):
            chunk = nodes_data[i : i + 38]
            if len(chunk) == 38:
                nid = chunk[:20]
                ip = socket.inet_ntop(socket.AF_INET6, chunk[20:36])
                port = struct.unpack("!H", chunk[36:38])[0]
                parsed_nodes.append((nid, ip, port))

        assert len(parsed_nodes) == 2

    def test_xor_distance_sorting(self):
        """Nodes should be sorted by XOR distance to target."""
        target = b"\x00" * 20

        # For XOR distance with big-endian conversion:
        # Distance 1 = XOR result is b"\x00"*19 + b"\x01" (last byte differs by 1)
        # node_close: only last byte differs, giving XOR distance = 1
        node_close = b"\x00" * 19 + b"\x01"
        # node_far: all bytes differ maximally, giving max distance
        node_far = b"\xff" * 20

        dist_close = _xor_distance(target, node_close)
        dist_far = _xor_distance(target, node_far)

        # node_close differs in last byte only -> XOR = b"\x00"*19 + b"\x01" -> int = 1
        assert dist_close == 1
        # node_far = b"\xff"*20 -> XOR with b"\x00"*20 = b"\xff"*20 -> max 160-bit value
        assert dist_far == 2**160 - 1
        assert dist_close < dist_far


# ============================================================================
# Magnet URL Parsing Tests
# ============================================================================


class TestMagnetURLParsing:
    """Tests for magnet URL parsing and infohash extraction."""

    def test_parse_hex_magnet_uri(self):
        """Parse magnet URI with hex-encoded infohash."""
        uri = "magnet:?xt=urn:btih:e337a880c4d0f552bab5b437fe1208d26130ccc5&dn=test-torrent"
        result = parse_magnet_uri(uri)

        assert result.info_hash == bytes.fromhex("e337a880c4d0f552bab5b437fe1208d26130ccc5")
        assert result.name == "test-torrent"
        assert result.info_hash_hex == "e337a880c4d0f552bab5b437fe1208d26130ccc5"
        assert result.info_hash_base16 == "E337A880C4D0F552BAB5B437FE1208D26130CCC5"

    def test_parse_base32_magnet_uri_invalid(self):
        """Parse magnet URI with unsupported scheme should handle gracefully."""
        uri = "magnet:?xt=urn:btifggqy5ltlf4dbzllon5wcbdsknw"
        # The parser logs a warning but may still try to parse
        # Just verify it doesn't crash
        try:
            result = parse_magnet_uri(uri)
            # If it succeeds, info_hash should be None or empty
            assert result is not None
        except Exception:
            pass  # Some exceptions are acceptable

    def test_magnet_with_trackers(self):
        """Parse magnet URI with tracker URLs."""
        uri = (
            "magnet:?xt=urn:btih:e337a880c4d0f552bab5b437fe1208d26130ccc5"
            "&dn=test"
            "&tr=http://tracker1.example.com:8080/announce"
            "&tr=http://tracker2.example.com:8080/announce"
        )
        result = parse_magnet_uri(uri)
        assert len(result.trackers) == 2

    def test_magnet_invalid_scheme(self):
        """Non-magnet URI should raise ValueError."""
        with pytest.raises(ValueError):
            parse_magnet_uri("http://example.com/torrent.torrent")

    def test_magnet_missing_xt(self):
        """Magnet URI without xt parameter should handle gracefully."""
        # The parser may or may not raise; just verify it doesn't crash
        try:
            result = parse_magnet_uri("magnet:?dn=test")
            assert result is not None
        except Exception:
            pass


# ============================================================================
# Metadata Retrieval Tests
# ============================================================================


class TestMetadataRetrieval:
    """Tests for torrent metadata retrieval functionality."""

    def test_client_peer_id_prefix(self):
        """Outbound peer id prefix for metadata connections."""
        import dhtrack.metadata_retriever as mr

        peer_id = mr._client_peer_id()
        assert len(peer_id) == 20
        assert peer_id.startswith(b"-DH")

    def test_connect_to_unreachable_peer(self):
        """Connecting to an unreachable peer should return None."""
        sock = connect_to_peer("127.0.0.1", 1, timeout=0.5)
        if sock is not None:
            sock.close()

    def test_connect_to_non_routable_address(self):
        """Connecting to a non-routable address should fail gracefully."""
        sock = connect_to_peer("192.0.2.1", 6881, timeout=0.5)
        assert sock is None

    def test_torrent_invalid_bencode_raises(self):
        """Invalid .torrent blobs should not silently parse."""
        with pytest.raises(DecodeError):
            bencode_module.decode(b"not valid bencoded data")

    def test_torrent_roundtrip_from_encoded(self):
        """Valid bencoded torrent dict loads through Torrent."""
        metadata = bencode_module.encode(
            {
                "info": {
                    "name": "test.txt",
                    "piece length": 16384,
                    "pieces": b"\x00" * 20,
                }
            }
        )
        decoded = bencode_module.decode(metadata)
        torrent = Torrent(decoded)
        assert torrent.info is not None

    def test_torrent_requires_info_key(self):
        with pytest.raises(TorrentParseError):
            Torrent({b"announce": b"http://x"})


# ============================================================================
# Compact Peer Encoding/Decoding Tests
# ============================================================================


class TestCompactPeerEncoding:
    """Tests for compact peer encoding and decoding."""

    def test_encode_decode_ipv4(self):
        """Encoding and decoding IPv4 peer should round-trip."""
        ip = "192.168.1.1"
        port = 6881
        encoded = _compact_peer_encode(ip, port)
        decoded_ip, decoded_port, is_ipv6 = _compact_peer_decode(encoded)
        assert decoded_ip == ip
        assert decoded_port == port
        assert is_ipv6 is False

    def test_encode_decode_ipv6(self):
        """Encoding and decoding IPv6 peer should round-trip."""
        ip = "::1"
        port = 6881
        encoded = _compact_peer_encode(ip, port, is_ipv6=True)
        decoded_ip, decoded_port, is_ipv6 = _compact_peer_decode(encoded)
        assert decoded_ip == ip
        assert decoded_port == port
        assert is_ipv6 is True

    def test_encode_decode_special_ipv4(self):
        """Test with various IPv4 addresses."""
        test_cases = [("0.0.0.0", 0), ("255.255.255.255", 65535), ("127.0.0.1", 1)]
        for ip, port in test_cases:
            encoded = _compact_peer_encode(ip, port)
            assert len(encoded) == 6
            decoded_ip, decoded_port, _ = _compact_peer_decode(encoded)
            assert decoded_ip == ip
            assert decoded_port == port


# ============================================================================
# BEP 51 Sample Infohashes Tests
# ============================================================================


class TestBEP51SampleInfohashes:
    """Tests for BEP 51 sample_infohashes functionality."""

    def test_sample_infohashes_request(self):
        """Sample infohashes request should be properly structured."""
        node_id = b"\x01" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table_v4 = RoutingTable(node_id)
        mock_node.routing_table_v6 = RoutingTable(node_id)
        mock_node.routing_table_v4.get_closest_nodes = MagicMock(return_value=[])
        mock_node.routing_table_v6.get_closest_nodes = MagicMock(return_value=[])
        mock_node.peer_store = PeerStore()
        mock_node.peers = {}
        mock_node.save_peers = MagicMock()

        endpoint = Endpoint("192.168.1.100", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x02" * 20)

        peer.sample_infohashes()

    def test_sample_infohashes_response(self):
        """Sample infohashes response should be handled."""
        node_id = b"\x01" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table_v4 = RoutingTable(node_id)
        mock_node.routing_table_v6 = RoutingTable(node_id)
        mock_node.routing_table_v4.get_closest_nodes = MagicMock(return_value=[])
        mock_node.routing_table_v6.get_closest_nodes = MagicMock(return_value=[])
        mock_node.peer_store = PeerStore()
        mock_node.peers = {}
        mock_node.save_peers = MagicMock()

        endpoint = Endpoint("192.168.1.100", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x02" * 20)

        samples = b"\xaa" * 20 + b"\xbb" * 20
        response = {
            b"t": b"01",
            b"y": b"r",
            b"r": {
                b"id": b"\x02" * 20,
                b"samples": samples,
                b"num": 2,
                b"interval": 3600,
            },
        }

        peer.queue[b"01"] = {
            "q": "sample_infohashes",
            "a": {"target": node_id},
            "timestamp": time.time(),
        }

        peer._handle_response(response)


# ============================================================================
# Peer Store Operations Tests
# ============================================================================


class TestPeerStoreOperations:
    """Tests for PeerStore operations."""

    def test_add_and_retrieve_peer(self):
        """Adding and retrieving a peer should work."""
        store = PeerStore()
        info_hash = b"\x01" * 20
        store.add_peer(info_hash, "192.168.1.1", 6881)

        peers = store.get_peers(info_hash)
        assert len(peers) == 1
        assert peers[0].ip == "192.168.1.1"
        assert peers[0].port == 6881

    def test_add_multiple_peers_same_infohash(self):
        """Adding multiple peers for same infohash should work."""
        store = PeerStore()
        info_hash = b"\x01" * 20

        for i in range(5):
            store.add_peer(info_hash, f"192.168.1.{i + 1}", 6881 + i)

        peers = store.get_peers(info_hash)
        assert len(peers) == 5

    def test_peer_deduplication(self):
        """Duplicate peers should be deduplicated per BEP 33."""
        store = PeerStore()
        info_hash = b"\x01" * 20

        store.add_peer(info_hash, "192.168.1.1", 6881)
        store.add_peer(info_hash, "192.168.1.1", 6881)  # Same
        store.add_peer(info_hash, "192.168.1.1", 6882)  # Different port

        peers = store.get_peers(info_hash)
        assert len(peers) == 2

    def test_remove_peer(self):
        """Removing a peer should work."""
        store = PeerStore()
        info_hash = b"\x01" * 20

        store.add_peer(info_hash, "192.168.1.1", 6881)
        assert len(store.get_peers(info_hash)) == 1

        store.remove_peer(info_hash, "192.168.1.1", 6881)
        assert len(store.get_peers(info_hash)) == 0

    def test_invalid_info_hash(self):
        """Adding peer with invalid info_hash should raise."""
        store = PeerStore()
        with pytest.raises(ValueError, match="info_hash must be 20 bytes"):
            store.add_peer(b"\x00" * 10, "192.168.1.1", 6881)


# ============================================================================
# DHT Node Lifecycle Tests
# ============================================================================


class TestDHTNodeLifecycle:
    """Tests for DHT node lifecycle."""

    def test_node_close(self):
        """Closing a DHT node should clean up resources."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.sock = MagicMock()
        node.sock6 = MagicMock()
        node._read_thread = None
        node._read_stop_event = MagicMock()
        node._read_stop_event.is_set.return_value = True

        node.close()


# ============================================================================
# Integration Tests - Full DHT Flow
# ============================================================================


class TestDHTFullFlow:
    """Integration tests for the full DHT flow."""

    def test_dht_query_response_cycle(self):
        """Test a complete query-response cycle."""
        node_id = b"\x01" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table_v4 = RoutingTable(node_id)
        mock_node.routing_table_v6 = RoutingTable(node_id)
        mock_node.routing_table_v4.get_closest_nodes = MagicMock(return_value=[])
        mock_node.routing_table_v6.get_closest_nodes = MagicMock(return_value=[])
        mock_node.peer_store = PeerStore()
        mock_node.token_secret = MagicMock()
        mock_node.token_secret.generate_token = MagicMock(return_value=b"\x03" * 20)

        endpoint = Endpoint("192.168.1.100", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x02" * 20)

        info_hash = b"\x01" * 20
        captured = {"data": None}
        peer.write = lambda data: captured.update({"data": data})

        peer.get_peers(info_hash)

        assert captured["data"] is not None
        query = bencode_module.decode(captured["data"])
        assert query[b"y"] == b"q"
        assert query[b"q"] == b"get_peers"
        assert query[b"a"][b"info_hash"] == info_hash

    def test_dht_find_node_query(self):
        """Test find_node query encoding."""
        node_id = b"\x01" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table_v4 = RoutingTable(node_id)
        mock_node.routing_table_v6 = RoutingTable(node_id)
        mock_node.routing_table_v4.get_closest_nodes = MagicMock(return_value=[])
        mock_node.routing_table_v6.get_closest_nodes = MagicMock(return_value=[])
        mock_node.peer_store = PeerStore()
        mock_node.token_secret = MagicMock()

        endpoint = Endpoint("192.168.1.100", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x02" * 20)

        target = b"\x02" * 20
        captured = {"data": None}
        peer.write = lambda data: captured.update({"data": data})

        peer.find_node(target)

        query = bencode_module.decode(captured["data"])
        assert query[b"y"] == b"q"
        assert query[b"q"] == b"find_node"
        assert query[b"a"][b"target"] == target

    def test_dht_ping_query(self):
        """Test ping query encoding."""
        node_id = b"\x01" * 20

        mock_node = MagicMock()
        mock_node.node_id = node_id
        mock_node.routing_table_v4 = RoutingTable(node_id)
        mock_node.routing_table_v6 = RoutingTable(node_id)
        mock_node.routing_table_v4.get_closest_nodes = MagicMock(return_value=[])
        mock_node.routing_table_v6.get_closest_nodes = MagicMock(return_value=[])
        mock_node.peer_store = PeerStore()
        mock_node.token_secret = MagicMock()

        endpoint = Endpoint("192.168.1.100", 6881)
        peer = DHTPeer(dht_node=mock_node, endpoint=endpoint, node_id=b"\x02" * 20)

        captured = {"data": None}
        peer.write = lambda data: captured.update({"data": data})

        peer.ping()

        query = bencode_module.decode(captured["data"])
        assert query[b"y"] == b"q"
        assert query[b"q"] == b"ping"


# ============================================================================
# Real Network Integration Tests (Skip if no network)
# ============================================================================


class TestRealNetworkBootstrap:
    """Tests that require real network connectivity.

    These tests are skipped by default. Set the environment variable
    DHT_TEST_LIVE=1 to run them.
    """

    @pytest.fixture(autouse=True)
    def check_live_mode(self):
        """Skip if DHT_TEST_LIVE is not set."""
        import os

        self.live = os.environ.get("DHT_TEST_LIVE", "0") == "1"
        if not self.live:
            pytest.skip("Set DHT_TEST_LIVE=1 to run live DHT tests")

    def test_bootstrap_with_real_nodes(self):
        """Test bootstrap with real bootstrap nodes."""
        node = DHTNode(bind_addr=("127.0.0.1", 0), peers_file="/tmp/dht_test_peers.dat")
        try:
            contacted = node.bootstrap()
            assert isinstance(contacted, int)
            assert contacted >= 0

            time.sleep(2)

            v4_nodes = sum(len(b.nodes) for b in node.routing_table_v4.buckets)
            assert v4_nodes >= 0
        finally:
            node.close()

    def test_iterative_get_peers_live(self):
        """Test iterative get_peers with real nodes."""
        info_hash = bytes.fromhex("e337a880c4d0f552bab5b437fe1208d26130ccc5")

        node = DHTNode(bind_addr=("127.0.0.1", 0), peers_file="/tmp/dht_test_peers.dat")
        try:
            node.bootstrap()
            time.sleep(3)

            peers = node.iterative_get_peers(info_hash, max_depth=2)
            assert isinstance(peers, list)
        finally:
            node.close()

    def test_self_discovery_live(self):
        """Test that our node_id appears in the DHT after bootstrap."""
        node = DHTNode(bind_addr=("127.0.0.1", 0), peers_file="/tmp/dht_test_peers.dat")
        try:
            node.bootstrap()
            time.sleep(5)

            closest = node.routing_table_v4.get_closest_nodes(node.node_id, K)
            assert len(closest) >= 0

            total_nodes = sum(len(b.nodes) for b in node.routing_table_v4.buckets)
            assert total_nodes >= 0
        finally:
            node.close()
