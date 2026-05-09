"""
dhtrack - BitTorrent DHT client library.

Provides tools for interacting with the BitTorrent Distributed Hash Table
(DHT) network, including DHT node management, peer discovery, and metadata
retrieval.
"""

from __future__ import annotations

import logging
import sys

# ---------------------------------------------------------------------------
# Default logging configuration
# ---------------------------------------------------------------------------


def setup_logging(level: int = logging.WARNING) -> None:
    """Configure default logging for the dhtrack package.

    Sets up a basic console handler with a formatted message pattern.
    All dhtrack submodules inherit from the root ``dhtrack`` logger,
    so configuring this logger affects the whole package.

    Parameters
    ----------
    level : int
        The logging level to use (default: WARNING).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )

    root = logging.getLogger("dhtrack")
    root.setLevel(level)

    # Remove any existing handlers to avoid duplicates
    for h in root.handlers[:]:
        root.removeHandler(h)
    root.addHandler(handler)


# Configure on import so logging works out of the box
setup_logging()
