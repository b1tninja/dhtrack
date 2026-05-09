"""BEP-32: BitTorrent DHT Extensions for IPv6.

This module provides helper functions for BEP-32 compliant DHT operations,
including:
- Parsing the 'want' parameter from requests
- Encoding/decoding 'nodes6' in responses
- Determining which routing table to use based on address family
- Bootstrap acceleration via cross-DHT data leaking
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Valid flags for the 'want' parameter
WANT_N4 = b"n4"  # Request nodes key (IPv4)
WANT_N6 = b"n6"  # Request nodes6 key (IPv6)
VALID_WANT_FLAGS = {WANT_N4, WANT_N6}


def parse_want(args: dict[bytes, Any]) -> set[bytes]:
    """Parse the 'want' parameter from a DHT request.

    BEP-32: The 'want' parameter is a list of strings that may include
    'n4' (request nodes key) and/or 'n6' (request nodes6 key).

    Parameters
    ----------
    args : dict
        The 'a' (arguments) portion of a DHT request.

    Returns
    -------
    set[str]
        A set of requested flags. Only VALID_WANT_FLAGS are included;
        unknown strings are silently ignored per BEP-32.
    """
    want = args.get(b"want")
    if not isinstance(want, list):
        return set()

    result: set[bytes] = set()
    for flag in want:
        if not isinstance(flag, bytes):
            continue
        if flag in VALID_WANT_FLAGS:
            result.add(flag)
        elif flag:  # Ignore empty/non-empty non-valid strings silently
            logger.debug("Unknown want flag: %s", flag)
    return result


def determine_response_nodes(
    requesting_endpoint_is_ipv6: bool, args: dict[bytes, Any], has_nodes: bool = True, has_nodes6: bool = False
) -> dict[bytes, Any]:
    """Determine which node keys to include in a response.

    BEP-32: In the absence of a 'want' parameter, the reply should include
    'nodes' if the request was sent over IPv4, and 'nodes6' if the request
    was sent over IPv6.

    Parameters
    ----------
    requesting_endpoint_is_ipv6 : bool
        Whether the requesting peer is on IPv6.
    args : dict
        The request arguments (may contain 'want').
    has_nodes : bool
        Whether IPv4 node data is available.
    has_nodes6 : bool
        Whether IPv6 node data is available.

    Returns
    -------
    dict[str, Any]
        A dict with 'nodes' and/or 'nodes6' keys as appropriate.
    """
    want = parse_want(args)
    has_want = bool(want)

    result: dict[bytes, Any] = {}

    if has_want:
        # Explicit want parameter: include only what's requested
        if WANT_N4 in want and has_nodes:
            result[b"nodes"] = True
        if WANT_N6 in want and has_nodes6:
            result[b"nodes6"] = True
    else:
        # No want parameter: default to address family of the request
        if requesting_endpoint_is_ipv6:
            if has_nodes6:
                result[b"nodes6"] = True
        else:
            if has_nodes:
                result[b"nodes"] = True

    return result


def encode_find_node_response(
    node_id: bytes, routing_table_v4, routing_table_v6, target: bytes, is_request_ipv6: bool, args: dict[bytes, Any]
) -> dict[bytes, Any]:
    """Encode a find_nodes response according to BEP-32 rules.

    Parameters
    ----------
    node_id : bytes
        The local node ID.
    routing_table_v4 : RoutingTable
        The IPv4 routing table.
    routing_table_v6 : RoutingTable
        The IPv6 routing table.
    target : bytes
        The 20-byte target node ID.
    is_request_ipv6 : bool
        Whether the request came over IPv6.
    args : dict
        The request arguments (may contain 'want').

    Returns
    -------
    dict[str, Any]
        The response dictionary suitable for BEncode.
    """
    want = parse_want(args)
    has_want = bool(want)

    response: dict[bytes, Any] = {b"id": node_id}

    # Determine which node keys to include
    if has_want:
        include_n4 = WANT_N4 in want
        include_n6 = WANT_N6 in want
    else:
        # Default: include nodes for IPv4 requests, nodes6 for IPv6
        include_n4 = not is_request_ipv6
        include_n6 = is_request_ipv6

    from .dht import K, _compact_node_encode

    if include_n4:
        closest = routing_table_v4.get_closest_nodes(target, K)
        if closest:
            response[b"nodes"] = b"".join(
                _compact_node_encode(
                    n.node_id,
                    n.endpoint.ip,
                    n.endpoint.port,
                    n.endpoint.is_ipv6,
                )
                for n in closest
            )
        else:
            response[b"nodes"] = b""

    if include_n6:
        closest = routing_table_v6.get_closest_nodes(target, K)
        if closest:
            response[b"nodes6"] = b"".join(
                _compact_node_encode(
                    n.node_id,
                    n.endpoint.ip,
                    n.endpoint.port,
                    n.endpoint.is_ipv6,
                )
                for n in closest
            )
        else:
            response[b"nodes6"] = b""

    return response


def encode_get_peers_response(
    node_id: bytes,
    routing_table_v4,
    routing_table_v6,
    info_hash: bytes,
    is_request_ipv6: bool,
    args: dict[bytes, Any],
    values: list | None = None,
    token: bytes = b"",
) -> dict[bytes, Any]:
    """Encode a get_peers response according to BEP-32 rules.

    Parameters
    ----------
    node_id : bytes
        The local node ID.
    routing_table_v4 : RoutingTable
        The IPv4 routing table.
    routing_table_v6 : RoutingTable
        The IPv6 routing table.
    info_hash : bytes
        The 20-byte infohash.
    is_request_ipv6 : bool
        Whether the request came over IPv6.
    args : dict
        The request arguments (may contain 'want').
    values : list, optional
        Compact peer info values.
    token : bytes
        Token for announce_peer.

    Returns
    -------
    dict[str, Any]
        The response dictionary suitable for BEncode.
    """
    want = parse_want(args)
    has_want = bool(want)

    response: dict[bytes, Any] = {b"id": node_id}

    if values is not None:
        response[b"values"] = values
    response[b"token"] = token

    from .dht import K, _compact_node_encode

    if has_want:
        include_n4 = WANT_N4 in want
        include_n6 = WANT_N6 in want
    else:
        include_n4 = not is_request_ipv6
        include_n6 = is_request_ipv6

    if include_n4:
        closest = routing_table_v4.get_closest_nodes(info_hash, K)
        if closest:
            response[b"nodes"] = b"".join(
                _compact_node_encode(
                    n.node_id,
                    n.endpoint.ip,
                    n.endpoint.port,
                    n.endpoint.is_ipv6,
                )
                for n in closest
            )
        else:
            response[b"nodes"] = b""

    if include_n6:
        closest = routing_table_v6.get_closest_nodes(info_hash, K)
        if closest:
            response[b"nodes6"] = b"".join(
                _compact_node_encode(
                    n.node_id,
                    n.endpoint.ip,
                    n.endpoint.port,
                    n.endpoint.is_ipv6,
                )
                for n in closest
            )
        else:
            response[b"nodes6"] = b""

    return response


def should_leak_to_other_dht(is_request_ipv6: bool, is_steady_state: bool = True, leak_counter: int = 0) -> bool:
    """Determine whether to request cross-DHT node information.

    BEP-32: "In order to increase the reliability of the DHT after a
    single-protocol network outage, however, a node may *ocasionally*
    send a request for IPv4 node information to an IPv6 node, or a
    request for IPv6 node information to an IPv4 node."

    Parameters
    ----------
    is_request_ipv6 : bool
        Whether the request originated from IPv6.
    is_steady_state : bool
        Whether we are in steady-state operation (not bootstrapping).
    leak_counter : int
        A counter used to control the frequency of cross-DHT leaks.

    Returns
    -------
    bool
        True if cross-DHT leaking should be performed.
    """
    if not is_steady_state:
        # During bootstrap, always request both address families
        return False

    # During steady-state, occasionally leak (roughly 1 in 50 requests)
    # This is a simplified implementation; a real implementation might
    # use a more sophisticated probability model.
    return (leak_counter % 50) == 0


def build_bootstrap_want() -> list[str]:
    """Build a want parameter for bootstrap queries.

    During bootstrapping, request both IPv4 and IPv6 node information
    to accelerate routing table population.

    Returns
    -------
    list[str]
        The want parameter containing both "n4" and "n6".
    """
    return [WANT_N4, WANT_N6]
