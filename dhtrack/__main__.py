"""
Entry point for running dhtrack as a module.

Usage
-----
    python -m dhtrack [--cli | --gui] [options]

This module provides a simple CLI entry point that dispatches to
either the CLI or GUI application based on command-line arguments.
"""

from __future__ import annotations

import argparse
import sys

from dhtrack.cli import main as cli_main
from dhtrack.gui import main as gui_main


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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
        '--cli',
        action='store_true',
        help='Run in command-line mode (default if no mode specified)',
    )

    parser.add_argument(
        '--gui',
        action='store_true',
        help='Run in graphical mode',
    )

    return parser.parse(argv)


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the dhtrack package.

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

    if args.gui:
        try:
            gui_main()
            return 0
        except Exception as exc:
            print(f'GUI error: {exc}', file=sys.stderr)
            return 1
    else:
        return cli_main(argv)


if __name__ == '__main__':
    sys.exit(main())