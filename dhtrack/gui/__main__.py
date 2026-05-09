"""
Entry point for running the DHT Network Inspector GUI.

Usage:
    python -m dhtrack.gui               # Launch GUI without attached node
    dhtrack-gui                         # Same (console scripts entry point)
    dhtrack-inspector                   # Windowed launcher (gui-scripts; no extra console on Windows)
    python -m dhtrack.gui --headless    # Launch GUI and auto-start DHT node
"""

from __future__ import annotations

import argparse
import logging
import sys

from PyQt6.QtWidgets import QApplication

logger = logging.getLogger("dhtrack.gui")


def main() -> int:
    """Main entry point for the GUI application.

    Returns
    -------
    int
        Exit code (0 for success, 1 for error).
    """
    parser = argparse.ArgumentParser(description="DHT Network Inspector - GUI for examining the BitTorrent DHT")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Start DHT node automatically on launch",
    )
    parser.add_argument(
        "--bind-port",
        type=int,
        default=0,
        help="Port to bind the DHT node (default: 0 = random)",
    )
    parser.parse_args()

    try:
        from dhtrack.gui.main import DHTInspectorWindow

        app = QApplication(sys.argv)
        app.setApplicationName("DHT Network Inspector")
        app.setOrganizationName("dhtrack")

        window = DHTInspectorWindow()
        window.show()

        return app.exec()
    except Exception as e:
        print(f"Failed to start GUI: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
