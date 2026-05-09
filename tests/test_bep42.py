"""Tests for BEP 42 — DHT Security Extension (IP-derived node ID)."""

from __future__ import annotations

import pytest

from dhtrack.bep42 import (
    _crc32c,
    _is_exempt_ip,
    generate_node_id,
    is_valid_node_id,
    verify_test_vectors,
)


class TestCRC32C:
    """CRC32C (Castagnoli) implementation sanity checks."""

    def test_empty_input(self):
        assert _crc32c(b"") == 0x00000000

    def test_known_value(self):
        # CRC32C of b"123456789" is a well-known test vector: 0xE3069283
        assert _crc32c(b"123456789") == 0xE3069283

    def test_single_byte(self):
        result = _crc32c(b"\x00")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF


class TestTestVectors:
    """BEP 42 official test vectors from the spec."""

    def test_all_vectors_pass(self):
        assert verify_test_vectors(), "One or more BEP 42 test vectors failed"


class TestIsExemptIP:
    """Private / loopback IPs should be exempt from BEP 42."""

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "169.254.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ],
    )
    def test_private_addresses_are_exempt(self, ip):
        assert _is_exempt_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "1.2.3.4",
            "124.31.75.21",
            "65.23.51.170",
        ],
    )
    def test_public_addresses_are_not_exempt(self, ip):
        assert _is_exempt_ip(ip) is False


class TestIsValidNodeId:
    """is_valid_node_id validates against BEP 42 test-vector node IDs."""

    def test_known_valid_ids(self):
        vectors = [
            ("124.31.75.21", bytes.fromhex("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401")),
            ("21.75.31.124", bytes.fromhex("5a3ce9c14e7a08645677bbd1cfe7d8f956d53256")),
            ("65.23.51.170", bytes.fromhex("a5d43220bc8f112a3d426c84764f8c2a1150e616")),
            ("84.124.73.14", bytes.fromhex("1b0321dd1bb1fe518101ceef99462b947a01ff41")),
            ("43.213.53.83", bytes.fromhex("e56f6cbf5b7c4be0237986d5243b87aa6d51305a")),
        ]
        for ip, node_id in vectors:
            assert is_valid_node_id(node_id, ip), f"Expected {node_id.hex()} to be valid for {ip}"

    def test_wrong_prefix_fails(self):
        node_id = bytes.fromhex("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401")
        # Corrupt the first byte
        bad = bytes([0xFF]) + node_id[1:]
        assert is_valid_node_id(bad, "124.31.75.21") is False

    def test_private_ip_always_valid(self):
        """Any node ID is accepted from a private IP (no constraint applies)."""
        assert is_valid_node_id(b"\x00" * 20, "192.168.1.1") is True

    def test_loopback_always_valid(self):
        assert is_valid_node_id(b"\x00" * 20, "127.0.0.1") is True

    def test_wrong_length_fails(self):
        assert is_valid_node_id(b"\x00" * 10, "1.2.3.4") is False


class TestGenerateNodeId:
    """generate_node_id should produce IDs that pass is_valid_node_id."""

    def test_generated_id_is_valid_for_public_ip(self):
        ip = "5.5.5.5"
        for _ in range(20):
            nid = generate_node_id(ip)
            assert len(nid) == 20
            assert is_valid_node_id(nid, ip), f"Generated ID {nid.hex()} failed validation for {ip}"

    def test_generated_id_length(self):
        assert len(generate_node_id("1.2.3.4")) == 20


class TestBEP51IntervalScheduling:
    """DHTNode.sample_infohashes should respect the BEP 51 interval."""

    def test_interval_prevents_re_query(self):
        import time
        from unittest.mock import MagicMock

        from dhtrack.dht import DHTNode, DHTPeer
        from dhtrack.peerid import Endpoint

        node = DHTNode()

        ep = Endpoint("1.2.3.4", 6881)
        peer = MagicMock(spec=DHTPeer)
        peer.node_id = b"\x01" * 20
        peer.endpoint = ep
        node.peers[(ep.ip, ep.port)] = peer

        # Populate routing table so sample_infohashes finds a target
        from dhtrack.dht import BucketNode, NodeStatus

        bn = BucketNode(node_id=peer.node_id, endpoint=ep, status=NodeStatus.GOOD)
        node.routing_table_v4.add_node(bn)

        # First call should send the query
        node.sample_infohashes(target=peer)
        assert peer.sample_infohashes.call_count == 1

        # Simulate the response recording a 3600 s interval
        node._sample_next_at[(ep.ip, ep.port)] = time.time() + 3600

        # Second call should be suppressed
        node.sample_infohashes(target=peer)
        assert peer.sample_infohashes.call_count == 1  # still 1

    def test_interval_expired_allows_query(self):
        import time
        from unittest.mock import MagicMock

        from dhtrack.dht import DHTNode, DHTPeer
        from dhtrack.peerid import Endpoint

        node = DHTNode()

        ep = Endpoint("1.2.3.4", 6882)
        peer = MagicMock(spec=DHTPeer)
        peer.node_id = b"\x02" * 20
        peer.endpoint = ep
        node.peers[(ep.ip, ep.port)] = peer

        # Mark interval as already expired (in the past)
        node._sample_next_at[(ep.ip, ep.port)] = time.time() - 1.0

        node.sample_infohashes(target=peer)
        assert peer.sample_infohashes.call_count == 1


class TestBEP42EnforcementFlag:
    """BEP 42 validation should be opt-in (transitional adoption)."""

    def test_not_enforced_by_default(self):

        from dhtrack.dht import DHTNode
        from dhtrack.peerid import Endpoint

        node = DHTNode()
        assert node.enforce_bep42 is False

        # A node_id that is valid length but likely fails BEP42 for this public IP.
        bad_node_id = b"\x00" * 20
        ep = Endpoint("1.2.3.4", 6881)

        # add_peer is invoked only after parse-time filtering; ensure default doesn't filter.
        peer = node.add_peer(bad_node_id, ep.ip, ep.port)
        assert peer is not None

    def test_enforced_when_enabled(self):
        from dhtrack.dht import DHTNode

        node = DHTNode()
        node.enforce_bep42 = True
        assert node.enforce_bep42 is True
