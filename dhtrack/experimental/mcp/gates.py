"""Confirm and overwrite gates shared by the CLI and the MCP tools.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

Names tell the effect, matching hardly's authoring rule:

* ``send_`` and ``node_start`` do nothing observable until ``confirm=true``.
  Without it they return a plan.
* ``write_`` refuses to replace an existing file unless ``overwrite=true``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dhtrack.experimental.mcp.errors import ToolError

CONFIRM_HINT = "Nothing was sent. Tell the person what will happen, then repeat the same call with confirm=true."


# Set by the MCP server. When set, every file a tool writes or opens must
# resolve inside it, so an agent (or text injected into its context) cannot
# aim a write at ~/.bashrc or an autostart directory. The CLI leaves it unset:
# there a person types the path.
_write_root: Path | None = None

WRITE_ROOT_ENV = "DHTRACK_MCP_ROOT"


def set_write_root(root: str | os.PathLike[str] | None) -> Path | None:
    """Confine tool file access to ``root`` (``None`` lifts the limit). Returns the resolved root."""
    global _write_root
    _write_root = None if root is None else Path(root).expanduser().resolve()
    return _write_root


def write_root() -> Path | None:
    """The directory tool file access is confined to, if any."""
    return _write_root


def confine(path: Path, label: str) -> Path:
    """Resolve ``path`` and refuse it when it falls outside the write root.

    Relative paths are taken relative to the root, so ``report.json`` lands
    inside it rather than in whatever the process working directory is.
    """
    root = _write_root
    if root is None:
        return path
    candidate = path if path.is_absolute() else root / path
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ToolError(
            f"{label} is outside the allowed directory {root}: {resolved}",
            code="path_outside_root",
            hint=f"Pass a path under {root}. The server's operator sets it with {WRITE_ROOT_ENV}.",
        ) from None
    return resolved


def dry_run(plan: dict[str, Any]) -> dict[str, Any]:
    """The reply of a confirm-gated tool called without ``confirm=true``."""
    return {"confirmed": False, "sent": False, "plan": plan, "hint": CONFIRM_HINT}


def prepare_write(output_path: str | None, overwrite: bool) -> Path:
    """Resolve a ``write_`` target. An existing file is kept unless ``overwrite`` is true."""
    if not output_path or not str(output_path).strip():
        raise ToolError(
            "output_path is required",
            code="missing_argument",
            hint="write_ tools never choose a path. Pass output_path=<file>.",
        )
    path = confine(Path(output_path).expanduser(), "output_path")
    if path.exists() and path.is_dir():
        raise ToolError(
            f"output_path is a directory: {path}",
            code="output_is_directory",
            hint="Pass a file path, not a directory.",
        )
    if path.exists() and not overwrite:
        raise ToolError(
            f"output_path already exists: {path}",
            code="output_exists",
            hint="Pass overwrite=true to replace it, or choose another path.",
        )
    if path.exists() and not path.is_file():
        raise ToolError(
            f"output_path is not a file: {path}",
            code="output_is_directory",
            hint="Pass a file path.",
        )
    return path
