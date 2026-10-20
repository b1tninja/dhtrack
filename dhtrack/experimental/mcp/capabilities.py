"""Advertise version and feature flags so agents detect a stale MCP server.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

The shape follows hardly's ``capabilities()``: name, version, features,
tools, modes, and a ``next`` hint. Feature flags bump when the tool surface
changes. This is the v0 DHT surface, not hardly's HAR catalog.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from typing import Any

# Bump when tools or gates change in a way agents must notice.
SURFACE_VERSION = "0.1.0"

FEATURES = (
    "archive_mode",
    "observe_mode",
    "analyze_mode",
    "session_sqlite",
    "catalog",
    "swarm_watch",
    "peer_analytics",
    "confirm_gate",
    "write_overwrite_guard",
    "pagination",
    "peer_id_truncation",
    "guide_mode",
    "guide_task_plan",
    "guide_help",
    "server_status",
    "node_lifecycle",
    "sample_transport",
    "cli_parity",
    "api_surface_v0",
)

# Grouped by family. The token after ``dhtrack_`` is the effect marker when
# there is one: ``send_`` is confirm-gated, ``write_`` refuses to overwrite.
TOOLS = (
    "dhtrack_server_status",
    "dhtrack_guide_help",
    "dhtrack_guide_mode",
    "dhtrack_guide_task_plan",
    "dhtrack_session_open",
    "dhtrack_session_close",
    "dhtrack_session_list",
    "dhtrack_session_overview",
    "dhtrack_session_report",
    "dhtrack_catalog_list",
    "dhtrack_catalog_get",
    "dhtrack_write_catalog_snapshot",
    "dhtrack_send_catalog_sample_round",
    "dhtrack_swarm_observe",
    "dhtrack_write_swarm_alerts",
    "dhtrack_swarm_analyze",
    "dhtrack_peer_report",
    "dhtrack_write_peer_report",
    "dhtrack_node_status",
    "dhtrack_node_start",
    "dhtrack_node_stop",
    "dhtrack_send_get_peers",
    "dhtrack_send_sample_infohashes",
)

_NEXT = (
    "Pick a mode with dhtrack_guide_mode. "
    "send_ tools and dhtrack_node_start return a plan until confirm=true. "
    "write_ tools refuse to replace a file unless overwrite=true. "
    "If this tool list is missing expected names, restart the dhtrack MCP server."
)


def package_version() -> str:
    """Installed distribution version, or the pyproject version when unpacked."""
    try:
        return version("dhtrack")
    except PackageNotFoundError:
        return "2.0.0"


def capabilities() -> dict[str, Any]:
    """Server advertisement. ``node_running`` is live; it does not start a node."""
    from dhtrack.experimental.mcp.modes import list_modes
    from dhtrack.experimental.mcp.node import node_running

    return {
        "name": "dhtrack",
        "version": SURFACE_VERSION,
        "package_version": package_version(),
        "features": list(FEATURES),
        "tools": list(TOOLS),
        "tool_count": len(TOOLS),
        "modes": list_modes()["modes"],
        "node_running": node_running(),
        "next": _NEXT,
    }
