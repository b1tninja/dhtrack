"""``python -m dhtrack.experimental`` entry point.

EXPERIMENTAL PROPOSAL. See ``docs/proposals/``.
"""

from __future__ import annotations

import sys

from dhtrack.experimental.cli import main

if __name__ == "__main__":
    sys.exit(main())
