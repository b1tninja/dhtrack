"""
Command-line interface for dhtrack.

Provides a CLI for running a DHT node and inspecting the BitTorrent
DHT network from the terminal, as well as scraping trackers for
swarm metadata (BEP 48).

Examples
--------
>>> # Run a DHT node with default settings
>>> python -m dhtrack.cli dht
>>>
>>> # Scrape a tracker for swarm info
>>> python -m dhtrack.cli scrape http://tracker.example.com/announce <infohash_hex>
>>>
>>> # Run in verbose mode
>>> python -m dhtrack.cli -v dht
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time

from dhtrack.bep53 import magnet_peer_strings_to_triplets, parse_magnet_uri
from dhtrack.dht import DEFAULT_BOOTSTRAP_NODES, DEFAULT_PEERS_FILE, DHTNode
from dhtrack.dht_manager import DHTManager
from dhtrack.tracker import TrackerClient


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application.

    Parameters
    ----------
    verbose : bool
        If True, set log level to DEBUG. Otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    if level == logging.DEBUG:
        logger = logging.getLogger("dhtrack")
        logger.debug("Debug logging enabled")


# ---------------------------------------------------------------------------
# Resolve command: iterative DHT peer discovery + metadata retrieval
# ---------------------------------------------------------------------------


def _print_progress(msg: str) -> None:
    """Simple progress printer for the CLI."""
    print(f"  {msg}")


def _parse_resolve_args(subparser: argparse.ArgumentParser) -> None:
    """Configure arguments for the resolve subcommand.

    Parameters
    ----------
    subparser : argparse.ArgumentParser
        The subparser to add arguments to.
    """
    subparser.add_argument(
        "infohash",
        help="40-char hex infohash or a magnet:?… URI (BEP 53)",
    )
    subparser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=120.0,
        help="Total timeout in seconds (default: %(default)s)",
    )
    subparser.add_argument(
        "--peers-file",
        default=DEFAULT_PEERS_FILE,
        help="Path to the file for persisting known peers (default: %(default)s)",
    )
    subparser.add_argument(
        "--max-peers",
        type=int,
        default=10,
        help="Max peers to try for metadata (default: %(default)s)",
    )


def _parse_resolve_target(
    raw: str,
) -> tuple[bytes, str | None, list[tuple[str, int]]]:
    """Parse CLI resolve target: hex infohash or ``magnet:?…`` URI.

    Returns
    -------
    tuple
        ``(info_hash, display_name or None, initial (ip, port) pairs from pe=)``
    """
    s = raw.strip()
    if not s:
        raise ValueError("Empty infohash / magnet URI")
    if s.lower().startswith("magnet:?"):
        info = parse_magnet_uri(s)
        ih = info.info_hash
        if ih is None or len(ih) != 20:
            raise ValueError("Magnet URI has no valid btih (xt=urn:btih:…)")

        triplets = magnet_peer_strings_to_triplets(info.peers)
        initial = [(h, p) for h, p, _ in triplets]
        return ih, info.name, initial

    try:
        info_hash = bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"Invalid hex infohash: {raw!r}") from exc
    if len(info_hash) != 20:
        raise ValueError(
            f"Infohash must be 20 bytes (40 hex chars); got {len(info_hash)} bytes",
        )
    return info_hash, None, []


def _resolve_command(args: argparse.Namespace) -> int:
    """Execute the resolve command.

    Iteratively discover peers for an infohash via DHT, then retrieve
    torrent metadata from discovered peers.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed arguments.

    Returns
    -------
    int
        Exit code (0 for success, 1 for error).
    """
    try:
        info_hash, display_name, magnet_initial = _parse_resolve_target(args.infohash)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    timeout = args.timeout
    max_peers = args.max_peers
    peers_file = getattr(args, "peers_file", DEFAULT_PEERS_FILE)

    print("Resolve Request")
    print("=" * 60)
    print(f"Infohash      : {info_hash.hex()}")
    if display_name:
        print(f"Display (dn)  : {display_name}")
    if magnet_initial:
        print(f"Magnet pe=    : {len(magnet_initial)} peer hint(s)")
    print(f"Timeout       : {timeout}s")
    print(f"Max peers     : {max_peers}")
    print(f"Peers file    : {os.path.abspath(peers_file)}")
    print()

    manager = DHTManager(peers_file=peers_file)

    try:
        manager.start()
        print(f"DHT Node ID   : {manager.node.node_id.hex()}")
        print(f"DHT Peers     : {manager.get_peer_count()}")
        print()

        # Retrieve metadata
        metadata = manager.retrieve_metadata(
            info_hash,
            timeout=timeout,
            max_peers=max_peers,
            on_progress=_print_progress,
            initial_peers=magnet_initial if magnet_initial else None,
        )

        if metadata is None:
            print()
            print("Result: FAILED")
            print("Could not retrieve metadata from any peer.")
            return 1

        # Parse torrent
        torrent = manager.create_torrent(metadata)
        if torrent is None:
            print()
            print("Result: FAILED")
            print("Metadata retrieved but failed to parse as torrent.")
            return 1

        print()
        print("Result: SUCCESS")
        print(f"Torrent name: {torrent.name}")
        print(f"Piece count : {torrent.num_pieces}")
        print(f"Piece size  : {torrent.piece_length}")
        print(f"Info hash   : {torrent.info_hash.hex()}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        manager.stop()


def _parse_scrape_args(subparser: argparse.ArgumentParser) -> None:
    """Configure arguments for the scrape subcommand.

    Parameters
    ----------
    subparser : argparse.ArgumentParser
        The subparser to add arguments to.
    """
    subparser.add_argument(
        "announce_url",
        help="Tracker announce URL (e.g., http://tracker.example.com/announce)",
    )
    subparser.add_argument(
        "info_hashes",
        nargs="+",
        help="One or more 20-byte infohashes (hex-encoded) to scrape",
    )
    subparser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: %(default)s)",
    )
    subparser.add_argument(
        "-u",
        "--user-agent",
        default="dhtrack",
        help="User-Agent header (default: %(default)s)",
    )


def _scrape_command(args: argparse.Namespace) -> int:
    """Execute the scrape command.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed arguments.

    Returns
    -------
    int
        Exit code (0 for success, 1 for error).
    """
    # Parse and validate infohashes
    info_hashes: list[bytes] = []
    for hex_str in args.info_hashes:
        try:
            ih = bytes.fromhex(hex_str)
        except ValueError:
            print(f"Error: Invalid hex infohash: {hex_str}")
            return 1
        if len(ih) != 20:
            print(f"Error: Infohash must be 20 bytes (40 hex chars), got {len(ih)} bytes: {hex_str}")
            return 1
        info_hashes.append(ih)

    announce_url = args.announce_url
    timeout = args.timeout
    user_agent = args.user_agent

    print("Scrape Request (BEP 48)")
    print("=" * 60)
    print(f"Tracker URL : {announce_url}")
    print(f"Infohashes  : {len(info_hashes)}")
    for ih in info_hashes:
        print(f"            {ih.hex()}")
    print(f"Timeout     : {timeout}s")
    print(f"User-Agent  : {user_agent}")
    print()

    client = TrackerClient(timeout=timeout, user_agent=user_agent)

    try:
        response = client.scrape(info_hashes, announce_url)
    except Exception as exc:
        print(f"Error: Scrape failed: {exc}")
        return 1

    # Print response
    print("Scrape Response")
    print("=" * 60)

    if response.is_error:
        print("Status      : ERROR")
        print(f"Failure     : {response.failure_reason}")
    else:
        print("Status      : OK")
        print(f"Swarm count : {len(response.files)}")
        print()

    if response.files:
        print(f"{'Infohash':<42} {'Complete':>10} {'Incomplete':>12} {'Downloaded':>12}")
        print(f"{'-' * 42} {'-' * 10} {'-' * 12} {'-' * 12}")
        for infohash, info in response.files.items():
            print(f"{infohash.hex():<42} {info.complete:>10} {info.incomplete:>12} {info.downloaded:>12}")

    print()
    return 0


def _parse_dht_args(args: argparse.Namespace) -> dict:
    """Extract DHT node arguments.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed arguments.

    Returns
    -------
    dict
        Keyword arguments for DHTNode construction.
    """
    return {
        "peers_file": getattr(args, "peers_file", DEFAULT_PEERS_FILE),
        "bind_addr": ("0.0.0.0", getattr(args, "bind_port", 0)),
    }


def _dht_command(args: argparse.Namespace) -> int:
    """Execute the DHT node command.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed arguments.

    Returns
    -------
    int
        Exit code (0 for success, 1 for error).
    """
    getattr(args, "bootstrap", None) or DEFAULT_BOOTSTRAP_NODES

    try:
        node = DHTNode(
            bind_addr=("0.0.0.0", getattr(args, "bind_port", 0)),
            peers_file=getattr(args, "peers_file", DEFAULT_PEERS_FILE),
        )
        manager = DHTManager(node=node, peers_file=getattr(args, "peers_file", DEFAULT_PEERS_FILE))
        manager.start()

        node_id_hex = manager.node.node_id.hex() if manager.node.node_id else "unknown"
        print(f"DHT Node ID: {node_id_hex}")
        print(f"Peers discovered: {len(manager.node.peers)}")
        print(f"Peers file: {os.path.abspath(getattr(args, 'peers_file', DEFAULT_PEERS_FILE))}")
        print()

        # Run the DHT loop
        save_interval = getattr(args, "save_interval", 60)
        run_time = getattr(args, "run_time", 0)
        save_timer = 0
        start_time = time.monotonic()

        while True:
            elapsed = time.monotonic() - start_time

            # Check run time limit
            if run_time > 0 and elapsed >= run_time:
                print(f"\nRun time limit reached ({run_time}s). Shutting down...")
                break

            # Periodic peer save
            if save_interval > 0:
                save_timer += 1
                if save_timer >= save_interval:
                    manager.node.save_peers()
                    save_timer = 0

            # Keep the process alive; datagrams are handled by the node's asyncio transports.
            try:
                time.sleep(1.0)
            except KeyboardInterrupt:
                print("\nInterrupted by user.")
                break

        # Final save
        manager.stop()
        print(f"\nFinal peer save complete. {len(manager.node.peers)} peers stored.")

        return 0

    except KeyboardInterrupt:
        print("\nShutting down...")
        return 0
    except Exception as exc:
        print(f"Fatal error: {exc}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands.

    Returns
    -------
    argparse.ArgumentParser
        The fully configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="dhtrack",
        description="DHT swarm inspector for the BitTorrent protocol",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging (verbose mode)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (same as -v/--verbose)",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
    )

    # DHT node runner (default command)
    dht_parser = subparsers.add_parser("dht", help="Run a DHT node (default)")
    dht_parser.add_argument(
        "--peers-file",
        default=DEFAULT_PEERS_FILE,
        help="Path to the file for persisting known peers (default: %(default)s)",
    )
    dht_parser.add_argument(
        "--bootstrap",
        nargs=2,
        action="append",
        metavar=("HOST", "PORT"),
        help="Add a custom bootstrap node (can be specified multiple times)",
    )
    dht_parser.add_argument(
        "--bind-port",
        type=int,
        default=0,
        help="Port to bind the DHT node to (default: 0 = random)",
    )
    dht_parser.add_argument(
        "--save-interval",
        type=int,
        default=60,
        help="Interval in seconds between peer saves (default: %(default)s)",
    )
    dht_parser.add_argument(
        "--run-time",
        type=int,
        default=0,
        help="Run for this many seconds then exit (0 = run forever, default: %(default)s)",
    )

    # Resolve command (DHT peer discovery + metadata retrieval)
    resolve_help_parser = subparsers.add_parser(
        "resolve",
        help="Resolve torrent metadata via DHT peer discovery",
    )
    _parse_resolve_args(resolve_help_parser)

    # Scrape command (BEP 48)
    scrape_help_parser = subparsers.add_parser(
        "scrape",
        help="Scrape tracker for swarm info (BEP 48)",
    )
    _parse_scrape_args(scrape_help_parser)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI.

    Parameters
    ----------
    argv : list of str, optional
        Command-line arguments.

    Returns
    -------
    int
        Exit code (0 for success, 1 for error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    # Enable debug if either --verbose or --debug is set
    enable_debug = getattr(args, "verbose", False) or getattr(args, "debug", False)
    setup_logging(enable_debug)

    logging.getLogger("dhtrack.cli")

    if args.command is None or args.command == "dht":
        # Default to DHT command
        return _dht_command(args)
    elif args.command == "resolve":
        return _resolve_command(args)
    elif args.command == "scrape":
        return _scrape_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
