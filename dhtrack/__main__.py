"""
Entry point for running dhtrack as a module.

Usage
-----
    python -m dhtrack [options]

This module provides a simple CLI entry point for the DHT swarm inspector.
"""

from __future__ import annotations

import sys

from dhtrack.cli import main as cli_main


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the dhtrack package.

    Parameters
    ----------
    argv : list of str, optional
        Command-line arguments. If None, uses sys.argv.

    Returns
    -------
    int
        Exit code (0 for success, 1 for error).
    """
    # Pass None when argv is not provided so cli_main uses sys.argv
    if argv is None:
        return cli_main(None)
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
