"""``python -m dhtrack.experimental.mcp`` — experimental MCP stdio server.

EXPERIMENTAL PROPOSAL. See ``docs/proposals/mcp.md``.
``--help`` does not import the MCP SDK. Serving does, and exits with a
message when the ``mcp`` extra is not installed.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and serve. ``--help`` is handled by argparse before any SDK import."""
    parser = argparse.ArgumentParser(
        prog="python -m dhtrack.experimental.mcp",
        description=(
            "Experimental dhtrack MCP server (stdio). Requires the optional mcp extra: pip install 'dhtrack[mcp]'."
        ),
    )
    parser.add_argument("--transport", choices=("stdio",), default="stdio", help="MCP transport (default: stdio)")
    args = parser.parse_args(argv)
    try:
        from dhtrack.experimental.mcp.server import serve
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing == "mcp" or missing.startswith("mcp."):
            print(
                "error: the mcp extra is not installed. pip install 'dhtrack[mcp]'",
                file=sys.stderr,
            )
            return 1
        raise
    serve(transport=args.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
