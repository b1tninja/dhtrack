"""Stdio MCP server. Imported only when the optional ``mcp`` extra is installed.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

Naming matches the experimental CLI and hardly's effect markers:

* ``dhtrack_send_*`` returns a plan unless ``confirm=true``.
* ``dhtrack_node_start`` binds a UDP socket only when ``confirm=true``, and
  dials bootstrap routers only when that call listed them.
* ``dhtrack_write_*`` refuses to replace a file unless ``overwrite=true``.
* Every other tool only reads or updates the in-process session.
"""

from __future__ import annotations

import functools
import json
from typing import Any

from dhtrack.experimental.mcp.capabilities import SURFACE_VERSION, TOOLS
from dhtrack.experimental.mcp.errors import ToolError
from dhtrack.experimental.mcp.service import HANDLERS

INSTRUCTIONS = """\
dhtrack (experimental) inspects BitTorrent DHT observations: an infohash catalog,
swarm-health alerts, and peer-population reports. It is a draft. Prefer it when
asked to sample or describe DHT peers without the PyQt inspector.

Start: dhtrack_guide_task_plan(goal, path, infohash) or dhtrack_guide_mode.
Names tell the effect. dhtrack_send_* and dhtrack_node_start do nothing on the
network until confirm=true (they return a plan). dhtrack_write_* refuses to
replace a file unless overwrite=true. Other tools only read the session or
score peer tables already in hand.

Modes:
1. archive — dhtrack_session_open on a sqlite file (or memory if path is omitted),
   then overview, catalog_list, session_report.
2. observe — dhtrack_node_start plan first. confirm=true binds UDP. Bootstrap
   routers are contacted only if you passed them; the public defaults are not used.
   Then one dhtrack_send_get_peers or dhtrack_send_sample_infohashes. Stop the node.
3. analyze — dhtrack_peer_report or dhtrack_swarm_observe on a peer list. No socket.

Rules:
- Do not ask this server to announce, seed, or download metadata. Those tools are not in v0.
- Peer lists in tool results are paged (default 50, cap 200) and peer/node ids are truncated
  to an 8-hex prefix. Full ids stay in the session sqlite or a write_ file.
- dhtrack_send_catalog_sample_round replays a replies map. It does not open a socket.
- A missing tool means this server is stale: call dhtrack_server_status and restart it.
"""


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _wrap(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return _json(fn(*args, **kwargs))
        except ToolError as exc:
            return _json(exc.to_dict())
        except (OSError, ValueError, KeyError) as exc:
            return _json({"error": str(exc), "code": "invalid_argument"})

    return wrapper


def build_server():
    """Register the v0 tools on an official MCP ``MCPServer``.

    The import of :mod:`mcp` happens here so the rest of dhtrack stays stdlib-only.
    """
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        "dhtrack",
        instructions=INSTRUCTIONS,
        version=SURFACE_VERSION,
    )
    for name in TOOLS:
        server.add_tool(_wrap(HANDLERS[name]), name=name, structured_output=False)
    return server


def serve(transport: str = "stdio") -> None:
    """Block, speaking MCP on stdio."""
    if transport != "stdio":
        raise ToolError(f"unsupported transport {transport!r}", code="invalid_argument", hint="Use stdio.")
    build_server().run(transport="stdio")
