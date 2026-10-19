"""Confirm and overwrite gates shared by the CLI and the MCP tools.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

Names tell the effect, matching hardly's authoring rule:

* ``send_`` and ``node_start`` do nothing observable until ``confirm=true``.
  Without it they return a plan.
* ``write_`` refuses to replace an existing file unless ``overwrite=true``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dhtrack.experimental.mcp.errors import ToolError

CONFIRM_HINT = "Nothing was sent. Tell the person what will happen, then repeat the same call with confirm=true."


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
    path = Path(output_path).expanduser()
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
