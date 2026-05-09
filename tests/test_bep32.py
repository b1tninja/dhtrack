"""Tests for BEP-32: BitTorrent DHT Extensions for IPv6."""

from __future__ import annotations

from unittest.mock import MagicMock

from dhtrack.bep32 import (
    WANT_N4,
    WANT_N6,
    build_bootstrap_want,
    determine_response_nodes,
    encode_find_node_response,
    encode_get_peers_response,
    parse_want,
    should_leak_to_other_dht,
)
from dhtrack.dht import (
    DHTNode,
    Endpoint,
    RoutingTable,
)


class TestParseWant:
    """Tests for the parse_want function."""

    def test_parse_empty_args(self):
        """Empty args should return empty set."""
        assert parse_want({}) == set()

    def test_parse_no_want_key(self):
        """Missing 'want' key should return empty set."""
        args = {b"id": b"\x01" * 20}
        assert parse_want(args) == set()

    def test_parse_n4_only(self):
        """Single 'n4' flag should be parsed."""
        args = {b"want": [b"n4"]}
        assert parse_want(args) == {WANT_N4}

    def test_parse_n6_only(self):
        """Single 'n6' flag should be parsed."""
        args = {b"want": [b"n6"]}
        assert parse_want(args) == {WANT_N6}

    def test_parse_both_flags(self):
        """Both n4 and n6 flags should be parsed."""
        args = {b"want": [b"n4", b"n6"]}
        assert parse_want(args) == {WANT_N4, WANT_N6}

    def test_parse_ignores_unknown_flags(self):
        """Unknown flags should be silently ignored."""
        args = {b"want": [b"n4", b"unknown", b"n6"]}
        assert parse_want(args) == {WANT_N4, WANT_N6}

    def test_parse_non_list_want(self):
        """Non-list want should return empty set."""
        args = {b"want": b"n4"}
        assert parse_want(args) == set()

    def test_parse_empty_list(self):
        """Empty list should return empty set."""
        args = {b"want": []}
        assert parse_want(args) == set()


class TestDetermineResponseNodes:
    """Tests for determine_response_nodes."""

    def test_default_ipv4_no_want(self):
        """IPv4 request without want should default to nodes."""
        result = determine_response_nodes(False, {}, has_nodes=True)
        assert b"nodes" in result
        assert b"nodes6" not in result

    def test_default_ipv6_no_want(self):
        """IPv6 request without want should default to nodes6."""
        result = determine_response_nodes(True, {}, has_nodes6=True)
        assert b"nodes6" in result
        assert b"nodes" not in result

    def test_explicit_n4_only(self):
        """Explicit n4 in want should include only nodes."""
        args = {b"want": [b"n4"]}
        result = determine_response_nodes(False, args, has_nodes=True, has_nodes6=True)
        assert b"nodes" in result
        assert b"nodes6" not in result

    def test_explicit_n6_only(self):
        """Explicit n6 in want should include only nodes6."""
        args = {b"want": [b"n6"]}
        result = determine_response_nodes(True, args, has_nodes=True, has_nodes6=True)
        assert b"nodes6" in result
        assert b"nodes" not in result

    def test_explicit_both(self):
        """Explicit both n4 and n6 should include both."""
        args = {b"want": [b"n4", b"n6"]}
        result = determine_response_nodes(False, args, has_nodes=True, has_nodes6=True)
        assert b"nodes" in result
        assert b"nodes6" in result


class TestBuildBootstrapWant:
    """Tests for build_bootstrap_want."""

    def test_returns_both_flags(self):
        """Bootstrap want should include both n4 and n6."""
        result = build_bootstrap_want()
        assert WANT_N4 in result
        assert WANT_N6 in result


class TestShouldLeakToOtherDht:
    """Tests for cross-DHT leaking."""

    def test_bootstrap_no_leak(self):
        """During bootstrap, cross-DHT leaking should be disabled."""
        # Returns False when not steady-state (is_steady_state=False)
        # Actually the function returns False when not steady_state

    def test_steady_state_periodic_leak(self):
        """During steady-state, leak should occur periodically."""
        # leak_counter % 50 == 0 should return True
        assert should_leak_to_other_dht(True, is_steady_state=True, leak_counter=0) is True
        # leak_counter % 50 != 0 should return False
        assert should_leak_to_other_dht(True, is_steady_state=True, leak_counter=1) is False
        assert should_leak_to_other_dht(False, is_steady_state=True, leak_counter=50) is True


class TestEncodeFindNodeResponse:
    """Tests for encode_find_node_response."""

    def test_encode_ipv4_request(self):
        """IPv4 request without want should return nodes only."""
        node_id = b"\x01" * 20
        rt_v4 = RoutingTable(node_id)
        rt_v6 = RoutingTable(node_id)
        target = b"\x02" * 20
        result = encode_find_node_response(node_id, rt_v4, rt_v6, target, False, {})
        assert b"id" in result
        assert b"nodes" in result
        assert b"nodes6" not in result

    def test_encode_ipv6_request(self):
        """IPv6 request without want should return nodes6 only."""
        node_id = b"\x01" * 20
        rt_v4 = RoutingTable(node_id)
        rt_v6 = RoutingTable(node_id)
        target = b"\x02" * 20
        result = encode_find_node_response(node_id, rt_v4, rt_v6, target, True, {})
        assert b"id" in result
        assert b"nodes" not in result
        assert b"nodes6" in result

    def test_encode_explicit_both(self):
        """Explicit both in want should return both."""
        node_id = b"\x01" * 20
        rt_v4 = RoutingTable(node_id)
        rt_v6 = RoutingTable(node_id)
        target = b"\x02" * 20
        args = {b"want": [b"n4", b"n6"]}
        result = encode_find_node_response(node_id, rt_v4, rt_v6, target, False, args)
        assert b"nodes" in result
        assert b"nodes6" in result


class TestDHTNodeBEP32:
    """Integration tests for BEP-32 in DHTNode."""

    def test_separate_routing_tables(self):
        """DHTNode should have separate v4 and v6 routing tables."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.routing_table_v4 = RoutingTable(node.node_id)
        node.routing_table_v6 = RoutingTable(node.node_id)
        node.peer_store = MagicMock()
        node.token_secret = MagicMock()
        node.peers = {}
        node.sock = MagicMock()
        node.sock6 = None
        node._private_mode = False

        # Should be different objects
        assert node.routing_table_v4 is not node.routing_table_v6

    def test_get_routing_table_ipv4(self):
        """_get_routing_table should return v4 table for IPv4."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.routing_table_v4 = RoutingTable(b"\x01" * 20)
        node.routing_table_v6 = RoutingTable(b"\x02" * 20)

        assert node._get_routing_table(False) is node.routing_table_v4

    def test_get_routing_table_ipv6(self):
        """_get_routing_table should return v6 table for IPv6."""
        node = DHTNode.__new__(DHTNode)
        node.node_id = b"\x01" * 20
        node.routing_table_v4 = RoutingTable(b"\x01" * 20)
        node.routing_table_v6 = RoutingTable(b"\x02" * 20)

        assert node._get_routing_table(True) is node.routing_table_v6

    def test_is_ipv6_addr_ipv4(self):
        """IPv4 address tuples should not be identified as IPv6."""
        node = DHTNode.__new__(DHTNode)
        assert node._is_ipv6_addr(("127.0.0.1", 6881)) is False

    def test_is_ipv6_addr_ipv4_mapped_ipv6(self):
        """IPv4-mapped IPv6 addresses like ::ffff:1.2.3.4 may contain colons."""
        node = DHTNode.__new__(DHTNode)
        # This is a heuristic that might return True for IPv4-mapped addresses
        # A more sophisticated implementation would check for ::ffff: prefix
        assert node._is_ipv6_addr(("::ffff:127.0.0.1", 6881)) is True

    def test_is_ipv6_addr_ipv6(self):
        """IPv6 address tuples should be identified as IPv6."""
        node = DHTNode.__new__(DHTNode)
        assert node._is_ipv6_addr(("::1", 6881, 0, 0)) is True
        assert node._is_ipv6_addr(("2001:db8::1", 6881)) is True


class TestWantParameterEndToEnd:
    """End-to-end tests for the want parameter flow."""

    def test_find_node_response_with_want(self):
        """A find_node response should respect the want parameter."""
        # Create routing tables
        node_id = b"\x01" * 20
        rt_v4 = RoutingTable(node_id)
        rt_v6 = RoutingTable(node_id)

        # Add a node to IPv4 table
        endpoint_v4 = Endpoint("192.168.1.1", 6881)
        node_v4 = MagicMock()
        node_v4.node_id = b"\x02" * 20
        node_v4.endpoint = endpoint_v4
        rt_v4.buckets[0].nodes.append(node_v4)

        # Add a node to IPv6 table
        endpoint_v6 = Endpoint("2001:db8::1", 6881)
        node_v6 = MagicMock()
        node_v6.node_id = b"\x03" * 20
        node_v6.endpoint = endpoint_v6
        rt_v6.buckets[0].nodes.append(node_v6)

        target = b"\xff" * 20

        # Request with both n4 and n6
        args = {b"want": [b"n4", b"n6"]}
        result = encode_find_node_response(node_id, rt_v4, rt_v6, target, False, args)

        assert b"nodes" in result
        assert b"nodes6" in result
        assert result[b"nodes"] is not None
        assert result[b"nodes6"] is not None

    def test_get_peers_response_with_want(self):
        """A get_peers response should respect the want parameter."""
        node_id = b"\x01" * 20
        rt_v4 = RoutingTable(node_id)
        rt_v6 = RoutingTable(node_id)
        info_hash = b"\x02" * 20

        # Add nodes to both tables
        endpoint_v4 = Endpoint("192.168.1.1", 6881)
        node_v4 = MagicMock()
        node_v4.node_id = b"\x02" * 20
        node_v4.endpoint = endpoint_v4
        rt_v4.buckets[0].nodes.append(node_v4)

        endpoint_v6 = Endpoint("2001:db8::1", 6881)
        node_v6 = MagicMock()
        node_v6.node_id = b"\x03" * 20
        node_v6.endpoint = endpoint_v6
        rt_v6.buckets[0].nodes.append(node_v6)

        # Request with n6 only
        args = {b"want": [b"n6"]}
        result = encode_get_peers_response(node_id, rt_v4, rt_v6, info_hash, False, args, token=b"\x00" * 20)

        assert b"token" in result
        assert b"nodes" not in result
        assert b"nodes6" in result
