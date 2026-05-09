#!/usr/bin/env python3
"""
DHT Test Harness - Live DHT Debugging Tool

This script provides a comprehensive test harness for debugging DHT operations
against the real internet. It bootstraps a DHT node, performs self-discovery,
resolves magnet URLs, and retrieves torrent metadata from peers.

Reference: BEP 5 (DHT Protocol), BEP 51 (DHT Infohash Indexing)
"""

from __future__ import annotations

import argparse
import binascii
import logging
import os
import socket
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dhtrack.bep53 import parse_magnet_uri
from dhtrack.dht import (
    DEFAULT_BOOTSTRAP_NODES,
    FALLBACK_BOOTSTRAP_NODES,
    DHTNode,
    K,
)
from dhtrack.metadata_retriever import download_torrent_metadata

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------


class DebugFormatter(logging.Formatter):
    """Custom log formatter with stage indicators."""

    STAGES = {
        "SETUP": "\033[96m[SETUP]\033[0m",  # Cyan - Setup phase
        "NET": "\033[94m[NET ]\033[0m",  # Blue - Network
        "BOOT": "\033[92m[BOOT]\033[0m",  # Green - Bootstrap
        "ROUT": "\033[93m[ROUT]\033[0m",  # Yellow - Routing table
        "QUERY": "\033[95m[QUERY]\033[0m",  # Magenta - Query operations
        "RESP": "\033[97m[RESP]\033[0m",  # White - Response processing
        "PEER": "\033[91m[PEER]\033[0m",  # Red - Peer operations
        "MAG": "\033[96m[MAG ]\033[0m",  # Cyan - Magnet URL
        "INFO": "\033[92m[INFO]\033[0m",  # Green - General info
        "FAIL": "\033[101m[FAIL]\033[0m",  # Red background - Errors/failures
        "SUM": "\033[102m[SUMMARY]\033[0m",  # Green background - Summary
        "WIRE": "\033[103m[WIRE]\033[0m",  # Yellow background - Wire-level datagrams
    }

    def format(self, record):
        stage = record.name.upper()[:4]
        if stage in self.STAGES:
            record.stage = self.STAGES[stage]
        else:
            record.stage = f"[{stage:>5}]"
        record.stage = record.stage[:9]  # Ensure fixed width
        return super().format(record)


def setup_logging(
    level: int = logging.DEBUG,
    logfile: str | None = None,
    wire_logfile: str | None = None,
    wire_console: bool = False,
) -> None:
    """Configure comprehensive logging for the test harness.

    Parameters
    ----------
    level : int
        Logging level (default: DEBUG).
    logfile : str, optional
        Path to write log file. None for no file logging.
    wire_logfile : str, optional
        Path to write wire-level datagram trace. None for no wire file logging.
    wire_console : bool
        If True, write wire-level datagram trace to console as well.
    """
    # Clear existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    formatter = DebugFormatter(
        fmt="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(stage)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler - use DEBUG level so wire-level logs and debug output
    # are visible on the console when --wire-console is used or for verbose output
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG)
    root_logger.addHandler(console)

    # Wire-level console handler (if requested)
    if wire_console:
        wire_console_handler = logging.StreamHandler(sys.stdout)
        wire_console_handler.setFormatter(
            DebugFormatter(
                fmt="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(stage)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        wire_console_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(wire_console_handler)

    # File handler (if specified)
    if logfile:
        file_handler = logging.FileHandler(logfile, mode="w")
        file_handler.setFormatter(
            DebugFormatter(
                fmt="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(stage)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        file_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)

    # Wire-level file handler (if specified)
    if wire_logfile:
        wire_file_handler = logging.FileHandler(wire_logfile, mode="w")
        wire_file_handler.setFormatter(
            DebugFormatter(
                fmt="%(asctime)s.%(msecs)03d %(levelname)s %(name)s - %(stage)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        wire_file_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(wire_file_handler)

    # Set specific log levels for dhtrack modules
    for module in ["dhtrack.dht", "dhtrack.bencode", "dhtrack.bep53", "dhtrack.torrent"]:
        mod_logger = logging.getLogger(module)
        mod_logger.setLevel(logging.DEBUG)

    # Wire logger
    wire_mod_logger = logging.getLogger("dhtrack.wire")
    wire_mod_logger.setLevel(logging.DEBUG)

    # Root dhtrack logger
    dhtrack_logger = logging.getLogger("dhtrack")
    dhtrack_logger.setLevel(logging.DEBUG)

    root_logger.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Diagnostic Functions
# ---------------------------------------------------------------------------


def print_system_info() -> None:
    """Print system information for diagnostics."""
    log = logging.getLogger("SETUP")
    log.info("=" * 60)
    log.info("SYSTEM INFORMATION")
    log.info("=" * 60)

    try:
        hostname = socket.gethostname()
        log.info(f"Hostname: {hostname}")
    except Exception as e:
        log.warning(f"Could not get hostname: {e}")

    # Get local IP addresses
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
        s.close()
        log.info(f"Local IP (via 8.8.8.8): {local_ip}")
    except Exception as e:
        log.warning(f"Could not determine local IP: {e}")
        local_ip = "unknown"

    # Check network interfaces
    try:
        interfaces = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM)
        seen = set()
        for inf in interfaces:
            addr = inf[4][0]
            if addr not in seen:
                seen.add(addr)
                log.info(f"  Network address: {addr}")
    except Exception as e:
        log.warning(f"Could not list network interfaces: {e}")

    log.info(f"Python version: {sys.version}")
    log.info(f"Working directory: {os.getcwd()}")
    log.info(f"Platform: {sys.platform}")


def check_bootstrap_nodes() -> None:
    """Check connectivity to bootstrap nodes."""
    log = logging.getLogger("NET")
    log.info("=" * 60)
    log.info("BOOTSTRAP NODE CONNECTIVITY CHECK")
    log.info("=" * 60)

    all_nodes = DEFAULT_BOOTSTRAP_NODES + FALLBACK_BOOTSTRAP_NODES
    seen_ips = set()

    for host, port in all_nodes:
        if host in seen_ips:
            continue
        seen_ips.add(host)

        log.info(f"Checking {host}:{port}...")

        start = time.time()
        try:
            # Try DNS resolution
            addrs = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
            elapsed = time.time() - start
            for _family, _, _, _, sockaddr in addrs:
                ip = sockaddr[0]
                log.info(f"  DNS resolved {host} -> {ip}:{port} ({elapsed * 1000:.0f}ms)")
        except socket.gaierror as e:
            elapsed = time.time() - start
            log.warning(f"  DNS FAILED for {host}: {e} ({elapsed * 1000:.0f}ms)")
        except Exception as e:
            elapsed = time.time() - start
            log.warning(f"  DNS error for {host}: {e} ({elapsed * 1000:.0f}ms)")


# ---------------------------------------------------------------------------
# Stats Collector
# ---------------------------------------------------------------------------


@dataclass
class DHTStats:
    """Collects statistics for the DHT test run."""

    queries_sent: int = 0
    responses_received: int = 0
    queries_timed_out: int = 0
    peers_discovered: int = 0
    nodes_added: int = 0
    buckets_v4: int = 0
    nodes_v4: int = 0
    buckets_v6: int = 0
    nodes_v6: int = 0
    bootstrap_time: float = 0.0
    total_time: float = 0.0
    infohash_results: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    response_times: list = field(default_factory=list)
    query_types: dict = field(default_factory=lambda: defaultdict(int))
    response_types: dict = field(default_factory=lambda: defaultdict(int))


stats = DHTStats()
stats_start = 0.0


# ---------------------------------------------------------------------------
# Custom DHTNode with Enhanced Logging
# ---------------------------------------------------------------------------


class LoggedDHTNode(DHTNode):
    """DHTNode with enhanced debug logging for test harness."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._log = logging.getLogger("BOOT")

    def add_peer(self, node_id, ip, port, is_ipv6=False):
        """Override to add logging."""
        peer = super().add_peer(node_id, ip, port, is_ipv6=is_ipv6)
        if peer:
            stats.nodes_added += 1
            log = logging.getLogger("PEER")
            nid = binascii.b2a_hex(node_id).decode() if node_id else "unknown"
            log.debug(f"New peer: {ip}:{port} (is_ipv6={is_ipv6}, node_id={nid})")
        else:
            log = logging.getLogger("PEER")
            log.debug(f"Duplicate peer skipped: {ip}:{port}")
        return peer

    def save_peers(self, path=None):
        """Override to add logging."""
        super().save_peers(path)
        log = logging.getLogger("PEER")
        log.debug(f"Peers saved to {path or self.peers_file}")


# ---------------------------------------------------------------------------
# Bootstrap with Logging
# ---------------------------------------------------------------------------


def bootstrap_with_logging(node: DHTNode, bootstrap_nodes: list | None = None) -> None:
    """Bootstrap the DHT node with detailed logging.

    Parameters
    ----------
    node : DHTNode
        The DHT node to bootstrap.
    bootstrap_nodes : list, optional
        Custom bootstrap nodes. Uses defaults if not provided.
    """
    log = logging.getLogger("BOOT")
    global stats

    log.info("=" * 60)
    log.info("BOOTSTRAPPING DHT NODE")
    log.info("=" * 60)

    bootstrap_nodes = bootstrap_nodes or DEFAULT_BOOTSTRAP_NODES

    # Log bootstrap configuration
    log.info(f"Bootstrap nodes ({len(bootstrap_nodes)}):")
    for host, port in bootstrap_nodes:
        log.info(f"  - {host}:{port}")
    log.info(f"Fallback nodes ({len(FALLBACK_BOOTSTRAP_NODES)}):")
    for host, port in FALLBACK_BOOTSTRAP_NODES:
        log.info(f"  - {host}:{port}")

    # Log initial routing table state
    initial_v4 = sum(len(b.nodes) for b in node.routing_table_v4.buckets)
    initial_v6 = sum(len(b.nodes) for b in node.routing_table_v6.buckets)
    log.info("Initial routing table state:")
    log.info(f"  IPv4: {len(node.routing_table_v4.buckets)} buckets, {initial_v4} nodes")
    log.info(f"  IPv6: {len(node.routing_table_v6.buckets)} buckets, {initial_v6} nodes")

    # Log socket state
    log.info("Socket binding:")
    log.info(f"  IPv4 socket: {node.sock.getsockname()}")
    if node.sock6:
        log.info(f"  IPv6 socket: {node.sock6.getsockname()}")
    else:
        log.info("  IPv6 socket: Not available")

    # Perform bootstrap
    start = time.time()
    contacted = node.bootstrap()
    bootstrap_time = time.time() - start
    stats.bootstrap_time = bootstrap_time

    log.info(f"Bootstrap completed in {bootstrap_time * 1000:.0f}ms")
    log.info(f"  Bootstrap nodes contacted: {contacted}")
    log.info(f"  Queries sent: {stats.queries_sent}")
    log.info(f"  Responses received: {stats.responses_received}")

    # Log routing table state after bootstrap
    after_v4 = sum(len(b.nodes) for b in node.routing_table_v4.buckets)
    after_v6 = sum(len(b.nodes) for b in node.routing_table_v6.buckets)
    log.info("Routing table after bootstrap:")
    log.info(f"  IPv4: {len(node.routing_table_v4.buckets)} buckets, {after_v4} nodes")
    log.info(f"  IPv6: {len(node.routing_table_v6.buckets)} buckets, {after_v6} nodes")
    log.info(f"  Growth: IPv4 +{after_v4 - initial_v4}, IPv6 +{after_v6 - initial_v6}")

    # Log discovered nodes
    if after_v4 > 0:
        log.info("Sample IPv4 nodes (up to 5):")
        nodes = node.routing_table_v4.get_closest_nodes(node.node_id, 5)
        for n in nodes:
            log.info(
                f"  node_id={binascii.b2a_hex(n.node_id).decode()}, "
                f"ip={n.endpoint.ip}, port={n.endpoint.port}, "
                f"status={n.status}"
            )


# ---------------------------------------------------------------------------
# Self-Discovery Test
# ---------------------------------------------------------------------------


def test_self_discovery(node: DHTNode) -> bool:
    """Test that the node can find itself in the DHT.

    Parameters
    ----------
    node : DHTNode
        The DHT node to test.

    Returns
    -------
    bool
        True if self-discovery was successful.
    """
    log = logging.getLogger("QUERY")
    log.info("=" * 60)
    log.info("TESTING SELF-DISCOVERY")
    log.info("=" * 60)

    node_id_hex = binascii.b2a_hex(node.node_id).decode("ascii")
    log.info(f"Our node ID: {node_id_hex}")

    # Find nodes closest to our node_id
    closest = node.routing_table_v4.get_closest_nodes(node.node_id, K)
    log.info(f"Closest nodes to our ID: {len(closest)}")

    found_self = False
    for i, n in enumerate(closest):
        dist = binascii.b2a_hex(n.node_id).decode("ascii")
        log.info(f"  [{i + 1}] node_id={dist}, ip={n.endpoint.ip}, port={n.endpoint.port}")
        if n.node_id == node.node_id:
            found_self = True
            log.info("  ^^^ SELF FOUND! Our node ID is in the routing table.")

    if not found_self:
        log.info("Self not found in routing table (this is normal for fresh bootstrap)")
        log.info("This is expected - self-discovery happens as nodes query each other")

    # Try to find_node for our own ID
    log.info("Attempting to find_node for our own ID...")
    log.info("Note: This will find nodes CLOSE to our ID, not necessarily us")

    # Wait for responses
    time.sleep(2)

    log.info("Self-discovery complete:")
    log.info(f"  Closest nodes found: {len(closest)}")
    log.info(f"  Our ID in table: {found_self}")

    return found_self


# ---------------------------------------------------------------------------
# Magnet URL Resolution
# ---------------------------------------------------------------------------


def resolve_magnet_url(magnet_uri: str) -> None:
    """Parse and log information from a magnet URL.

    Parameters
    ----------
    magnet_uri : str
        The magnet URI to parse.
    """
    log = logging.getLogger("MAG")
    log.info("=" * 60)
    log.info("PARSING MAGNET URL")
    log.info("=" * 60)

    try:
        result = parse_magnet_uri(magnet_uri)
        log.info("Successfully parsed magnet URI")
        log.info(f"  Infohash (hex):   {result.info_hash_hex}")
        log.info(f"  Infohash (base16):{result.info_hash_base16}")
        log.info(f"  Name:             {result.name}")
        log.info(f"  Trackers:         {len(result.trackers)}")
        for i, tracker in enumerate(result.trackers):
            log.info(f"    [{i + 1}] {tracker}")
        if hasattr(result, "select_only") and result.select_only is not None:
            log.info(f"  Select-only:      {result.select_only}")
    except Exception as e:
        log.fail(f"Failed to parse magnet URI: {e}")
        raise


# ---------------------------------------------------------------------------
# Iterative get_peers with Logging
# ---------------------------------------------------------------------------


def perform_iterative_get_peers(node: DHTNode, info_hash: bytes, max_depth: int = 3) -> None:
    """Perform iterative get_peers search with detailed logging.

    Parameters
    ----------
    node : DHTNode
        The DHT node performing the search.
    info_hash : bytes
        The 20-byte infohash to search for.
    max_depth : int
        Maximum recursion depth for the search.
    """
    log = logging.getLogger("QUERY")
    log.info("=" * 60)
    log.info("PERFORMING ITERATIVE GET_PEERS")
    log.info("=" * 60)
    log.info(f"Infohash: {binascii.b2a_hex(info_hash).decode('ascii')}")
    log.info(f"Max depth: {max_depth}")

    binascii.b2a_hex(info_hash).decode("ascii")

    # Log initial state
    initial_peers = len(node.peer_store.get_peers(info_hash))
    log.info(f"Initial peers in store for this infohash: {initial_peers}")

    # Log routing table
    v4_nodes = sum(len(b.nodes) for b in node.routing_table_v4.buckets)
    v6_nodes = sum(len(b.nodes) for b in node.routing_table_v6.buckets)
    log.info(
        "Routing table: IPv4 %d nodes, IPv6 %d nodes",
        v4_nodes,
        v6_nodes,
    )

    if v4_nodes == 0:
        log.fail("No nodes in routing table - cannot perform get_peers search")
        log.fail("Please run bootstrap first!")
        return

    # Start iterative search
    log.info("Starting iterative get_peers search...")
    start = time.time()

    # Query closest nodes to infohash
    closest = node.routing_table_v4.get_closest_nodes(info_hash, K)
    log.info(f"Querying {len(closest)} closest nodes to infohash:")

    for i, n in enumerate(closest):
        log.debug(
            f"  [{i + 1}] node_id={binascii.b2a_hex(n.node_id).decode()}, ip={n.endpoint.ip}, port={n.endpoint.port}"
        )

    # Send get_peers to each node
    for node_entry in closest:
        node_id_hex = binascii.b2a_hex(node_entry.node_id).decode("ascii")
        peer = None
        for p in node.peers.values():
            if p.node_id == node_entry.node_id:
                peer = p
                break

        if peer:
            log.info(f"Sending get_peers to {peer.endpoint} (node_id={node_id_hex[:16]}...)")
            try:
                peer.get_peers(info_hash)
                stats.queries_sent += 1
                stats.query_types["get_peers"] += 1
            except Exception as e:
                log.fail(f"Failed to send get_peers: {e}")
                stats.errors.append(str(e))
        else:
            log.info(f"No peer found for node_id={node_id_hex[:16]}... (skipping)")

    # Wait for responses
    wait_start = time.time()
    log.info("Waiting for responses (5 seconds)...")
    time.sleep(5)
    wait_time = time.time() - wait_start

    # Check results
    final_peers = node.peer_store.get_peers(info_hash)
    elapsed = time.time() - start

    log.info("=" * 60)
    log.info("GET_PEERS SEARCH RESULTS")
    log.info("=" * 60)
    log.info(f"Time elapsed: {elapsed:.1f}s (including {wait_time:.1f}s wait)")
    log.info(f"Queries sent: {stats.queries_sent}")
    log.info(f"Responses received: {stats.responses_received}")
    log.info(f"Peers discovered for infohash: {len(final_peers)}")

    if final_peers:
        log.info("Discovered peers:")
        for i, p in enumerate(final_peers):
            log.info(
                f"  [{i + 1}] ip={p.ip}, port={p.port}, "
                f"node_id={binascii.b2a_hex(p.node_id).decode() if p.node_id else 'N/A'}"
            )
    else:
        log.info("No peers discovered (this is common in small DHTs)")

    # Check for timeout queries
    log.info(f"Queries timed out: {stats.queries_timed_out}")
    if stats.errors:
        log.info(f"Errors: {len(stats.errors)}")
        for e in stats.errors[:5]:
            log.info(f"  - {e}")


# ---------------------------------------------------------------------------
# Monitor Routing Table
# ---------------------------------------------------------------------------


def monitor_routing_table(node: DHTNode) -> None:
    """Print current routing table state.

    Parameters
    ----------
    node : DHTNode
        The DHT node to monitor.
    """
    log = logging.getLogger("ROUT")
    log.info("=" * 60)
    log.info("ROUTING TABLE STATE")
    log.info("=" * 60)

    # IPv4
    v4_total = sum(len(b.nodes) for b in node.routing_table_v4.buckets)
    v4_active = sum(1 for b in node.routing_table_v4.buckets if b.nodes)
    log.info("IPv4 Routing Table:")
    log.info(f"  Total buckets: {len(node.routing_table_v4.buckets)}")
    log.info(f"  Active buckets: {v4_active}")
    log.info(f"  Total nodes: {v4_total}")

    for i, bucket in enumerate(node.routing_table_v4.buckets):
        if bucket.nodes:
            node_ids = [binascii.b2a_hex(n.node_id).decode()[:8] for n in bucket.nodes]
            log.info(
                f"  Bucket[{i}] ({bucket.min_id[:4].hex()} - {bucket.max_id[:4].hex()}): "
                f"{len(bucket.nodes)} nodes, {node_ids}"
            )

    # IPv6
    v6_total = sum(len(b.nodes) for b in node.routing_table_v6.buckets)
    v6_active = sum(1 for b in node.routing_table_v6.buckets if b.nodes)
    log.info("\nIPv6 Routing Table:")
    log.info(f"  Total buckets: {len(node.routing_table_v6.buckets)}")
    log.info(f"  Active buckets: {v6_active}")
    log.info(f"  Total nodes: {v6_total}")

    stats.bucket_stats = (v4_total, v4_active, v6_total, v6_active)


# ---------------------------------------------------------------------------
# Peer Store Inspection
# ---------------------------------------------------------------------------


def inspect_peer_store(node: DHTNode) -> None:
    """Print peer store contents.

    Parameters
    ----------
    node : DHTNode
        The DHT node to inspect.
    """
    log = logging.getLogger("PEER")
    log.info("=" * 60)
    log.info("PEER STORE STATE")
    log.info("=" * 60)

    # Get all unique infohashes
    infohashes = set()
    for peer in node.peer_store._store.values():
        for p in peer:
            infohashes.add(p.info_hash)

    log.info(f"Unique infohashes: {len(infohashes)}")
    for ih in sorted(infohashes):
        peers = node.peer_store.get_peers(ih)
        log.info(f"  infohash={binascii.b2a_hex(ih).decode()}: {len(peers)} peers")
        for p in peers[:5]:  # Show first 5
            log.info(f"    ip={p.ip}, port={p.port}")


# ---------------------------------------------------------------------------
# Summary Report
# ---------------------------------------------------------------------------


def print_summary(node: DHTNode, stats: DHTStats) -> None:
    """Print a summary report of the test run.

    Parameters
    ----------
    node : DHTNode
        The DHT node.
    stats : DHTStats
        Collected statistics.
    """
    log = logging.getLogger("SUM")
    log.info("=" * 60)
    log.info("TEST RUN SUMMARY")
    log.info("=" * 60)

    total_time = time.time() - stats_start

    log.info(f"Total time: {total_time:.1f}s")
    log.info(f"Bootstrap time: {stats.bootstrap_time * 1000:.0f}ms")

    log.info("\nDHT Statistics:")
    log.info("  Bootstrap nodes contacted: N/A (bootstrap() returns total)")
    log.info(f"  Queries sent: {node.queries_sent}")
    log.info(f"  Responses received: {node.responses_received}")
    log.info(f"  Queries timed out: {node.queries_timed_out}")
    log.info(f"  Errors received: {node.errors_received}")
    log.info(f"  Nodes added: {stats.nodes_added}")

    log.info("\nRouting Table:")
    v4_nodes = sum(len(b.nodes) for b in node.routing_table_v4.buckets)
    v6_nodes = sum(len(b.nodes) for b in node.routing_table_v6.buckets)
    log.info(f"  IPv4: {len(node.routing_table_v4.buckets)} buckets, {v4_nodes} nodes")
    log.info(f"  IPv6: {len(node.routing_table_v6.buckets)} buckets, {v6_nodes} nodes")

    log.info("\nPeer Store:")
    total_peers = sum(len(node.peer_store.get_peers(ih)) for ih in node.peer_store._store.keys())
    log.info(f"  Total peers stored: {total_peers}")

    log.info("\nQuery Types Sent:")
    for q, c in stats.query_types.items():
        log.info(f"  {q}: {c}")

    log.info("\nResponse Types Received:")
    for r, c in stats.response_types.items():
        log.info(f"  {r}: {c}")

    if stats.errors:
        log.info(f"\nErrors ({len(stats.errors)}):")
        for e in stats.errors[:10]:
            log.info(f"  - {e}")

    log.info("=" * 60)


# ---------------------------------------------------------------------------
# Main Test Harness
# ---------------------------------------------------------------------------


def run_test_harness(
    magnet_url: str | None = None,
    bootstrap_nodes: list | None = None,
    wait_time: int = 30,
    max_depth: int = 3,
    logfile: str | None = None,
    no_network: bool = False,
    wire_log: str | None = None,
    wire_console: bool = False,
) -> None:
    """Run the complete DHT test harness.

    Parameters
    ----------
    magnet_url : str, optional
        Magnet URI to resolve. If None, only bootstrap and self-discovery are tested.
    bootstrap_nodes : list, optional
        Custom bootstrap nodes.
    wait_time : int
        Seconds to wait for DHT convergence.
    max_depth : int
        Maximum depth for iterative get_peers.
    logfile : str, optional
        Path to write log file.
    no_network : bool
        If True, skip actual network operations (useful for dry-run testing).
    wire_log : str, optional
        Path to write wire-level datagram trace.
    wire_console : bool
        If True, write wire-level datagram trace to console output.
    """
    global stats_start

    if no_network:
        print("=== DHT Test Harness (DRY RUN - No Network) ===")
        print("This is a dry run. Set no_network=False for live testing.")
        return

    setup_logging(logfile=logfile, wire_logfile=wire_log, wire_console=wire_console)
    log = logging.getLogger("SETUP")

    log.info("╔" + "═" * 58 + "╗")
    log.info("║" + " DHT TEST HARNESS ".center(58) + "║")
    log.info("║" + " Live DHT Debugging Tool ".center(58) + "║")
    log.info("╚" + "═" * 58 + "╝")
    log.info("")

    stats_start = time.time()

    # Phase 1: System Diagnostics
    log.info("PHASE 1: SYSTEM DIAGNOSTICS")
    print_system_info()
    check_bootstrap_nodes()
    log.info("")

    # Phase 2: Create and Bootstrap DHT Node
    log.info("PHASE 2: DHT NODE CREATION & BOOTSTRAP")
    bind_port = 6881  # Common DHT port
    try:
        node = LoggedDHTNode(
            bind_addr=("0.0.0.0", bind_port),
            peers_file=str(Path(__file__).parent / "peers_test.dat"),
        )
        log.info("DHT node created successfully!")
        log.info(f"  Node ID: {binascii.b2a_hex(node.node_id).decode('ascii')}")
        log.info(f"  Bind address: {node.sock.getsockname()}")
    except Exception as e:
        log.fail(f"Failed to create DHT node: {e}")
        import traceback

        traceback.print_exc()
        return

    # Bootstrap
    bootstrap_with_logging(node, bootstrap_nodes)
    log.info("")

    # Phase 3: Wait for DHT convergence
    log.info("PHASE 3: WAITING FOR DHT CONVERGENCE")
    log.info(f"Waiting {wait_time} seconds for DHT to converge...")
    time.sleep(wait_time)
    monitor_routing_table(node)
    log.info("")

    # Phase 4: Self-Discovery
    log.info("PHASE 4: SELF-DISCOVERY TEST")
    test_self_discovery(node)
    log.info("")

    # Phase 5: Magnet URL Resolution (if provided)
    if magnet_url:
        log.info("PHASE 5: MAGNET URL RESOLUTION")
        resolve_magnet_url(magnet_url)
        log.info("")

        # Phase 6: Iterative get_peers
        log.info("PHASE 6: ITERATIVE GET_PEERS")
        try:
            result = parse_magnet_uri(magnet_url)
            if result.info_hash:
                perform_iterative_get_peers(node, result.info_hash, max_depth)
            else:
                log.fail("Magnet URI has no valid infohash")
        except Exception as e:
            log.fail(f"Failed to process magnet URL: {e}")
            import traceback

            traceback.print_exc()
        log.info("")

    # Phase 7: Download torrent metadata from peers
    if magnet_url:
        log.info("PHASE 7: DOWNLOADING TORRENT METADATA FROM PEERS")
        try:
            result = parse_magnet_uri(magnet_url)
            if result.info_hash:
                # Collect all peers from peer store
                peers_to_try = []
                for ih in node.peer_store._store.keys():
                    peers = node.peer_store.get_peers(ih)
                    for p in peers:
                        peers_to_try.append((p.ip, p.port, p.is_ipv6))

                if peers_to_try:
                    log.info(f"Found {len(peers_to_try)} peers to try for metadata download")
                    log.info("Attempting to retrieve .torrent metadata...")

                    metadata = download_torrent_metadata(
                        peers=peers_to_try,
                        info_hash=result.info_hash,
                        timeout=60.0,
                    )

                    if metadata:
                        log.info("SUCCESS! Downloaded torrent metadata:")
                        log.info(f"  Size: {len(metadata)} bytes")
                        try:
                            node.peer_store._store.get(result.info_hash, [])
                            from dhtrack import bencode as bencode_module

                            parsed = bencode_module.decode(metadata)
                            if isinstance(parsed, dict):
                                info = parsed.get(b"info" if isinstance(parsed.get(b"info"), dict) else None)
                                if info:
                                    # For string keys
                                    info_str = parsed.get("info", parsed.get(b"info"))
                                    if isinstance(info_str, dict):
                                        name = info_str.get("name", info_str.get(b"name", "unknown"))
                                        piece_length = info_str.get("piece length", info_str.get(b"piece length", 0))
                                        pieces = info_str.get(b"pieces", info_str.get(b"pieces", b""))
                                        files = info_str.get(b"files", info_str.get(b"files", []))

                                        log.info(f"  Torrent name: {name}")
                                        log.info(f"  Piece length: {piece_length} bytes")
                                        log.info(f"  Number of pieces: {len(pieces) // 20}")
                                        log.info(f"  Total size: {len(metadata)} bytes")

                                        if isinstance(files, list):
                                            for i, f in enumerate(files[:5]):
                                                if isinstance(f, dict):
                                                    path = f.get(b"path", f.get("path", []))
                                                    length = f.get(b"length", f.get("length", 0))
                                                    log.info(f"    File[{i}]: {path} ({length} bytes)")
                            else:
                                log.info(f"  Parsed: {list(parsed.keys())}")
                        except Exception as e:
                            log.info(f"  Error parsing metadata: {e}")
                            log.info(f"  Raw metadata (first 200 bytes): {metadata[:200]}")
                    else:
                        log.info("Failed to retrieve metadata from any peer")
                        log.info("This is expected for torrents that:")
                        log.info("  1. Have no active/seeding peers")
                        log.info("  2. Are behind firewalls/NAT")
                        log.info("  3. Have expired from the DHT")
                else:
                    log.info("No peers found for this infohash")
                    log.info("This is expected - the torrent may have no active peers")
        except Exception as e:
            log.info(f"Metadata download failed: {e}")
            import traceback

            traceback.print_exc()
        log.info("")

    # Phase 8: Final Summary
    log.info("PHASE 8: FINAL SUMMARY")
    inspect_peer_store(node)
    print_summary(node, stats)
    log.info("")

    # Close DHT node
    log.info("SHUTTING DOWN")
    node.close()
    log.info("Done!")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point for the test harness."""
    parser = argparse.ArgumentParser(
        description="DHT Test Harness - Live DHT Debugging Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Live test with Arch Linux magnet URL
  %(prog)s --magnet "magnet:?xt=urn:btih:e337a880c4d0f552bab5b437fe1208d26130ccc5"

  # Quick test (30 second wait)
  %(prog)s --magnet "magnet:?xt=urn:btih:..." --wait 30

  # Dry run (no network)
  %(prog)s --no-network

  # Custom bootstrap nodes
  %(prog)s --bootstrap router.utorrent.com:6881 dht.transmissionbt.com:6881

  # Save logs to file
  %(prog)s --magnet "..." --logfile /tmp/dht_test.log
        """,
    )

    parser.add_argument(
        "--magnet",
        "-m",
        type=str,
        default=None,
        help="Magnet URI to resolve (e.g., magnet:?xt=urn:btih:...)",
    )

    parser.add_argument(
        "--bootstrap",
        "-b",
        nargs="+",
        default=None,
        help="Custom bootstrap nodes (host:port format)",
    )

    parser.add_argument(
        "--wait",
        "-w",
        type=int,
        default=30,
        help="Seconds to wait for DHT convergence (default: 30)",
    )

    parser.add_argument(
        "--max-depth",
        "-d",
        type=int,
        default=3,
        help="Maximum depth for iterative get_peers (default: 3)",
    )

    parser.add_argument(
        "--logfile",
        "-l",
        type=str,
        default=None,
        help="Path to write log file",
    )

    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Skip actual network operations (dry run)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=True,
        help="Enable verbose output (default)",
    )

    parser.add_argument(
        "--wire-log",
        "-W",
        type=str,
        default=None,
        help="Path to write wire-level datagram trace (raw packet log)",
    )

    parser.add_argument(
        "--wire-console",
        action="store_true",
        default=False,
        help="Write wire-level datagram trace to console output",
    )

    args = parser.parse_args()

    # Parse bootstrap nodes
    bootstrap_nodes = None
    if args.bootstrap:
        bootstrap_nodes = []
        for node_str in args.bootstrap:
            if ":" in node_str:
                host, port = node_str.rsplit(":", 1)
                bootstrap_nodes.append((host, int(port)))
            else:
                print(f"Invalid bootstrap node: {node_str}")
                sys.exit(1)

    print_system_info()

    run_test_harness(
        magnet_url=args.magnet,
        bootstrap_nodes=bootstrap_nodes,
        wait_time=args.wait,
        max_depth=args.max_depth,
        logfile=args.logfile,
        no_network=args.no_network,
        wire_log=args.wire_log,
        wire_console=args.wire_console,
    )


if __name__ == "__main__":
    main()
