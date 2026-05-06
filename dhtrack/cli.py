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
from typing import Optional

from dhtrack.dht import DHTNode, DEFAULT_BOOTSTRAP_NODES, DEFAULT_PEERS_FILE
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
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )


def _parse_scrape_args(subparser: argparse.ArgumentParser) -> None:
    """Configure arguments for the scrape subcommand.

    Parameters
    ----------
    subparser : argparse.ArgumentParser
        The subparser to add arguments to.
    """
    subparser.add_argument(
        'announce_url',
        help='Tracker announce URL (e.g., http://tracker.example.com/announce)',
    )
    subparser.add_argument(
        'info_hashes',
        nargs='+',
        help='One or more 20-byte infohashes (hex-encoded) to scrape',
    )
    subparser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: %(default)s)',
    )
    subparser.add_argument(
        '-u', '--user-agent',
        default='dhtrack',
        help='User-Agent header (default: %(default)s)',
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
            print(f'Error: Invalid hex infohash: {hex_str}')
            return 1
        if len(ih) != 20:
            print(
                f'Error: Infohash must be 20 bytes (40 hex chars), '
                f'got {len(ih)} bytes: {hex_str}'
            )
            return 1
        info_hashes.append(ih)

    announce_url = args.announce_url
    timeout = args.timeout
    user_agent = args.user_agent

    print('Scrape Request (BEP 48)')
    print('=' * 60)
    print(f'Tracker URL : {announce_url}')
    print(f'Infohashes  : {len(info_hashes)}')
    for ih in info_hashes:
        print(f'            {ih.hex()}')
    print(f'Timeout     : {timeout}s')
    print(f'User-Agent  : {user_agent}')
    print()

    client = TrackerClient(timeout=timeout, user_agent=user_agent)

    try:
        response = client.scrape(info_hashes, announce_url)
    except Exception as exc:
        print(f'Error: Scrape failed: {exc}')
        return 1

    # Print response
    print('Scrape Response')
    print('=' * 60)

    if response.is_error:
        print(f'Status      : ERROR')
        print(f'Failure     : {response.failure_reason}')
    else:
        print(f'Status      : OK')
        print(f'Swarm count : {len(response.files)}')
        print()

    if response.files:
        print(
            f'{"Infohash":<42} {"Complete":>10} {"Incomplete":>12} {"Downloaded":>12}'
        )
        print(
            f'{"-" * 42} {"-" * 10} {"-" * 12} {"-" * 12}'
        )
        for infohash, info in response.files.items():
            print(
                f'{infohash.hex():<42} {info.complete:>10} {info.incomplete:>12} {info.downloaded:>12}'
            )

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
        'peers_file': getattr(args, 'peers_file', DEFAULT_PEERS_FILE),
        'bind_addr': ('0.0.0.0', getattr(args, 'bind_port', 0)),
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
    bootstrap_nodes = getattr(args, 'bootstrap', None) or DEFAULT_BOOTSTRAP_NODES

    try:
        # Create DHT node
        node = DHTNode(
            bind_addr=('0.0.0.0', getattr(args, 'bind_port', 0)),
            peers_file=getattr(args, 'peers_file', DEFAULT_PEERS_FILE),
        )

        # Load existing peers
        loaded = node.load_peers()
        if loaded > 0:
            print(f'Loaded {loaded} existing peers')

        # Bootstrap with default or custom nodes
        node.bootstrap(bootstrap_nodes)

        # Print node info
        node_id_hex = node.node_id.hex() if hasattr(node, 'node_id') and node.node_id else 'unknown'
        print(f'DHT Node ID: {node_id_hex}')
        print(f'Peers discovered: {len(node.peers)}')
        print(f'Peers file: {os.path.abspath(getattr(args, "peers_file", DEFAULT_PEERS_FILE))}')
        print()

        # Run the DHT loop
        save_interval = getattr(args, 'save_interval', 60)
        run_time = getattr(args, 'run_time', 0)
        save_timer = 0
        start_time = time.monotonic()

        while True:
            elapsed = time.monotonic() - start_time

            # Check run time limit
            if run_time > 0 and elapsed >= run_time:
                print(f'\nRun time limit reached ({run_time}s). Shutting down...')
                break

            # Periodic peer save
            if save_interval > 0:
                save_timer += 1
                if save_timer >= save_interval:
                    node.save_peers()
                    save_timer = 0

            # Check for timeout
            if run_time > 0:
                remaining = run_time - elapsed
                if remaining <= 0:
                    break
                timeout = min(1.0, remaining)
            else:
                timeout = 1.0

            # Process incoming datagrams
            try:
                node.sock.settimeout(timeout)
                try:
                    data, addr = node.sock.recvfrom(1438)
                    ip, port = addr
                    if (ip, port) in node.peers:
                        node.peers[(ip, port)].recv(data)
                    else:
                        peer = node.add_peer(None, ip, port)
                        if peer:
                            peer.ping()
                except (TimeoutError, OSError):
                    pass

                if node.sock6:
                    node.sock6.settimeout(timeout)
                    try:
                        data, addr = node.sock6.recvfrom(1438)
                        ip, port = addr
                        if (ip, port) in node.peers:
                            node.peers[(ip, port)].recv(data)
                        else:
                            peer = node.add_peer(None, ip, port)
                            if peer:
                                peer.ping()
                    except (TimeoutError, OSError):
                        pass

            except KeyboardInterrupt:
                print('\nInterrupted by user.')
                break

        # Final save
        node.save_peers()
        print(f'\nFinal peer save complete. {len(node.peers)} peers stored.')

        return 0

    except KeyboardInterrupt:
        print('\nShutting down...')
        return 0
    except Exception as exc:
        print(f'Fatal error: {exc}')
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands.

    Returns
    -------
    argparse.ArgumentParser
        The fully configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog='dhtrack',
        description='DHT swarm inspector for the BitTorrent protocol',
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable debug logging',
    )

    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
    )

    # DHT node runner (default command)
    dht_parser = subparsers.add_parser('dht', help='Run a DHT node (default)')
    dht_parser.add_argument(
        '--peers-file',
        default=DEFAULT_PEERS_FILE,
        help='Path to the file for persisting known peers (default: %(default)s)',
    )
    dht_parser.add_argument(
        '--bootstrap',
        nargs=2,
        action='append',
        metavar=('HOST', 'PORT'),
        help='Add a custom bootstrap node (can be specified multiple times)',
    )
    dht_parser.add_argument(
        '--bind-port',
        type=int,
        default=0,
        help='Port to bind the DHT node to (default: 0 = random)',
    )
    dht_parser.add_argument(
        '--save-interval',
        type=int,
        default=60,
        help='Interval in seconds between peer saves (default: %(default)s)',
    )
    dht_parser.add_argument(
        '--run-time',
        type=int,
        default=0,
        help='Run for this many seconds then exit (0 = run forever, default: %(default)s)',
    )

    # Scrape command (BEP 48)
    scrape_help_parser = subparsers.add_parser(
        'scrape',
        help='Scrape tracker for swarm info (BEP 48)',
    )
    _parse_scrape_args(scrape_help_parser)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
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
    setup_logging(getattr(args, 'verbose', False))

    logger = logging.getLogger('dhtrack.cli')

    if args.command is None or args.command == 'dht':
        # Default to DHT command
        return _dht_command(args)
    elif args.command == 'scrape':
        return _scrape_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())