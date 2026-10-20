"""Experimental MCP surface for DHT inspect workflows.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
See ``docs/proposals/mcp.md``.

Importing this package does not import the MCP SDK and does not open a
socket. The stdio server lives in :mod:`dhtrack.experimental.mcp.server` and
is loaded only when someone runs ``python -m dhtrack.experimental.mcp``.
"""

from __future__ import annotations

from dhtrack.experimental.mcp.capabilities import FEATURES, SURFACE_VERSION, TOOLS, capabilities

__all__ = [
    "FEATURES",
    "SURFACE_VERSION",
    "TOOLS",
    "capabilities",
]
