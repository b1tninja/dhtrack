"""
Command-line interface for dhtrack.

Provides a CLI for running a DHT node and inspecting the BitTorrent
DHT network from the terminal.

Examples
--------
>>> # Run a DHT node with default settings
>>> python -m dhtrack.cli
>>>
>>> # Run with custom peers file
>>> python -m dhtrack.cli --peers-file /tmp/dht_peers.dat
>>>
>>> # Run in verbose mode
>>> python -m dhtrack.cli --verbose
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from dhtrack.dht import DHTNode, DEFAULT_BOOTSTRAP_NODES, DEFAULT_PEERS_FILE


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


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Parameters
    ----------
    argv : list of str, optional
        Command-line arguments. Uses sys.argv if not provided.

    Returns
    -------
    argparse.Namespace
        The parsed arguments.
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

    parser.add_argument(
        '--peers-file',
        default=DEFAULT_PEERS_FILE,
        help='Path to the file for persisting known peers (default: %(default)s)',
    )

    parser.add_argument(
        '--bootstrap',
        nargs=2,
        action='append',
        metavar=('HOST', 'PORT'),
        help='Add a custom bootstrap node (can be specified multiple times)',
    )

    parser.add_argument(
        '--bind-port',
        type=int,
        default=0,
        help='Port to bind the DHT node to (default: 0 = random)',
    )

    parser.add_argument(
        '--save-interval',
        type=int,
        default=60,
        help='Interval in seconds between peer saves (default: %(default)s)',
    )

    parser.add_argument(
        '--run-time',
        type=int,
        default=0,
        help='Run for this many seconds then exit (0 = run forever, default: %(default)s)',
    )

    return parser.parse_args(argv)


def run_dht_loop(
    node: DHTNode,
    save_interval: int = 60,
    run_time: int = 0,
) -> None:
    """Run the DHT node event loop.

    Parameters
    ----------
    node : DHTNode
        The DHT node to run.
    save_interval : int
        Seconds between peer saves.
    run_time : int
        Seconds to run before exiting (0 = forever).
    """
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
    args = parse_args(argv)
    setup_logging(args.verbose)

    logger = logging.getLogger('dhtrack.cli')

    try:
        # Create DHT node
        bind_addr: tuple[str, int] = ('0.0.0.0', args.bind_port)

        node = DHTNode(
            bind_addr=bind_addr,
            peers_file=args.peers_file,
        )

        # Load existing peers
        loaded = node.load_peers()
        if loaded > 0:
            logger.info('Loaded %d existing peers', loaded)

        # Bootstrap with default or custom nodes
        bootstrap_nodes = args.bootstrap or DEFAULT_BOOTSTRAP_NODES
        logger.info('Bootstrapping with %d nodes...', len(bootstrap_nodes))
        node.bootstrap(bootstrap_nodes)

        # Print node info
        node_id_hex = os.urandom(20).hex() if not hasattr(node, 'node_id') else node.node_id.hex()
        print(f'DHT Node ID: {node_id_hex}')
        print(f'Peers discovered: {len(node.peers)}')
        print(f'Peers file: {os.path.abspath(args.peers_file)}')
        print()

        # Run the DHT loop
        run_dht_loop(
            node=node,
            save_interval=args.save_interval,
            run_time=args.run_time,
        )

        # Final save
        node.save_peers()
        logger.info('Final peer save complete. %d peers stored.', len(node.peers))

        return 0

    except KeyboardInterrupt:
        print('\nShutting down...')
        return 0
    except Exception as exc:
        logger.error('Fatal error: %s', exc, exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())