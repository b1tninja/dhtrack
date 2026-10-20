"""Page and redact tool payloads so a peer list cannot fill the context.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, TypeVar

from dhtrack.experimental.mcp.errors import ToolError

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
ID_PREFIX_HEX = 8

T = TypeVar("T")


def page(items: Sequence[T], limit: int | None, offset: int | None) -> dict[str, Any]:
    """Return a window of ``items``.

    ``limit`` defaults to 50 and is clamped to 200. ``offset`` defaults to 0.
    """
    window_limit = DEFAULT_LIMIT if limit is None else limit
    window_offset = 0 if offset is None else offset
    if isinstance(window_limit, bool) or not isinstance(window_limit, int) or window_limit < 1:
        raise ToolError("limit must be a positive integer", code="invalid_argument")
    if isinstance(window_offset, bool) or not isinstance(window_offset, int) or window_offset < 0:
        raise ToolError("offset must be an integer >= 0", code="invalid_argument")
    window_limit = min(window_limit, MAX_LIMIT)
    total = len(items)
    chosen = list(items[window_offset : window_offset + window_limit])
    return {
        "total": total,
        "limit": window_limit,
        "offset": window_offset,
        "count": len(chosen),
        "truncated": window_offset + len(chosen) < total,
        "items": chosen,
    }


def redact_id(name: str, raw: bytes | None) -> dict[str, object]:
    """Expose an 8-hex prefix of a 20-byte id. Full ids stay in the session file."""
    if raw is None:
        return {f"{name}_hex": None, f"{name}_truncated": False}
    hexed = raw.hex()
    if len(hexed) <= ID_PREFIX_HEX:
        return {f"{name}_hex": hexed, f"{name}_truncated": False}
    return {f"{name}_prefix": hexed[:ID_PREFIX_HEX], f"{name}_truncated": True}


def public_peer(row: dict[str, Any]) -> dict[str, object]:
    """Peer row safe to return from a tool: address, port, truncated ids."""
    payload: dict[str, object] = {
        "ip": row.get("ip"),
        "port": row.get("port"),
        "is_seeder": row.get("is_seeder"),
    }
    payload.update(redact_id("peer_id", _optional_bytes(row.get("peer_id"))))
    payload.update(redact_id("node_id", _optional_bytes(row.get("node_id"))))
    return payload


def _optional_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return None
