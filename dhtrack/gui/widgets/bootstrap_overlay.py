"""
Bootstrap Overlay widget - loading screen for the DHT bootstrap process.

Shows real-time progress during DHT bootstrap including:
- Phase indicator (Phase 1: Bootstrap, Phase 2: Recursive propagation)
- Current depth level
- Nodes queried and discovered counts
- XOR distance to self (smaller = closer to bootstrap complete)
- Elapsed time and progress metrics
"""

from __future__ import annotations

import math
import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


class BootstrapOverlay(QWidget):
    """Full-screen overlay widget showing bootstrap progress.

    Displays real-time statistics about the DHT bootstrap process including
    phase, depth, nodes queried/discovered, XOR distance to self, and elapsed time.

    Parameters
    ----------
    parent : QWidget, optional
        The parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._visible = False
        self._start_time: float = 0.0
        self._phase: str = ""
        self._depth: int = 0
        self._nodes_queried: int = 0
        self._nodes_discovered: int = 0
        self._min_xor_distance: int = 0
        self._total_nodes: int = 0
        self._bucket_count: int = 0
        self._active_buckets: int = 0
        self._ipv4_nodes: int = 0
        self._ipv6_nodes: int = 0
        self._status: str = "Initializing..."
        self._timer: QTimer | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the overlay UI."""
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.setAutoFillBackground(False)
        self._visible = False
        self.hide()

        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Create container frame
        self._container = QFrame()
        self._container.setObjectName("BootstrapContainer")
        self._container.setStyleSheet("""
            #BootstrapContainer {
                background-color: rgba(15, 15, 26, 220);
                border: none;
                border-radius: 12px;
            }
            QLabel {
                color: #cdd6f4;
                background: transparent;
            }
        """)

        container_layout = QVBoxLayout(self._container)
        container_layout.setContentsMargins(40, 30, 40, 30)
        container_layout.setSpacing(16)

        # Title
        self._title_label = QLabel("DHT Bootstrap")
        self._title_label.setStyleSheet("""
            QLabel {
                color: #89b4fa;
                font-size: 24px;
                font-weight: bold;
                background: transparent;
            }
        """)
        container_layout.addWidget(self._title_label)

        # Status
        self._status_label = QLabel("Initializing...")
        self._status_label.setStyleSheet("""
            QLabel {
                color: #a6adc8;
                font-size: 14px;
                font-style: italic;
                background: transparent;
            }
        """)
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self._status_label)

        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet("QFrame { background-color: #313244; border: none; }")
        container_layout.addWidget(separator)

        # Phase info
        self._phase_label = QLabel("Phase: Initializing")
        self._phase_label.setStyleSheet("""
            QLabel {
                color: #89b4fa;
                font-size: 14px;
                background: transparent;
            }
        """)
        container_layout.addWidget(self._phase_label)

        # Depth
        self._depth_label = QLabel("Depth: 0")
        self._depth_label.setStyleSheet("""
            QLabel {
                color: #cdd6f4;
                font-size: 14px;
                background: transparent;
            }
        """)
        container_layout.addWidget(self._depth_label)

        # Nodes queried
        self._queried_label = QLabel("Nodes queried: 0")
        self._queried_label.setStyleSheet("""
            QLabel {
                color: #cdd6f4;
                font-size: 14px;
                background: transparent;
            }
        """)
        container_layout.addWidget(self._queried_label)

        # Nodes discovered
        self._discovered_label = QLabel("Nodes discovered: 0 (IPv4: 0, IPv6: 0)")
        self._discovered_label.setStyleSheet("""
            QLabel {
                color: #cdd6f4;
                font-size: 14px;
                background: transparent;
            }
        """)
        container_layout.addWidget(self._discovered_label)

        # Bucket info
        self._bucket_label = QLabel("Active buckets: 0 / 0")
        self._bucket_label.setStyleSheet("""
            QLabel {
                color: #cdd6f4;
                font-size: 14px;
                background: transparent;
            }
        """)
        container_layout.addWidget(self._bucket_label)

        # Separator
        separator2 = QFrame()
        separator2.setFrameShape(QFrame.Shape.HLine)
        separator2.setStyleSheet("QFrame { background-color: #313244; border: none; }")
        container_layout.addWidget(separator2)

        # XOR distance (main metric)
        self._xor_label = QLabel("XOR distance to self: 0")
        self._xor_label.setStyleSheet("""
            QLabel {
                color: #94e185;
                font-size: 16px;
                font-weight: bold;
                background: transparent;
            }
        """)
        self._xor_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self._xor_label)

        # Progress indicator
        self._progress_label = QLabel("Progress: 0%")
        self._progress_label.setStyleSheet("""
            QLabel {
                color: #a6adc8;
                font-size: 14px;
                background: transparent;
            }
        """)
        self._progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self._progress_label)

        # Elapsed time
        self._elapsed_label = QLabel("Elapsed: 0s")
        self._elapsed_label.setStyleSheet("""
            QLabel {
                color: #a6adc8;
                font-size: 14px;
                background: transparent;
            }
        """)
        self._elapsed_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self._elapsed_label)

        layout.addWidget(self._container)

        # Start the timer for updates
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_timer)
        self._timer.start(200)  # Update every 200ms

    def _update_timer(self) -> None:
        """Timer callback to update elapsed time display."""
        if self._start_time > 0:
            elapsed = time.time() - self._start_time
            if elapsed < 60:
                self._elapsed_label.setText(f"Elapsed: {elapsed:.1f}s")
            elif elapsed < 3600:
                self._elapsed_label.setText(f"Elapsed: {elapsed / 60:.1f}m")
            else:
                self._elapsed_label.setText(f"Elapsed: {elapsed / 3600:.1f}h")

    def show_overlay(self) -> None:
        """Show the bootstrap overlay."""
        self._visible = True
        self._start_time = time.time()
        self._phase = "Phase 1: Bootstrap"
        self._status = "Contacting bootstrap nodes..."
        self.update_display()
        self.show()

    def hide_overlay(self) -> None:
        """Hide the bootstrap overlay."""
        self._visible = False
        self.hide()

    def update_progress(
        self,
        phase: str,
        depth: int,
        nodes_queried: int,
        nodes_discovered: int,
        min_xor_distance: int,
        total_nodes: int,
        bucket_count: int = 0,
        active_buckets: int = 0,
        ipv4_nodes: int = 0,
        ipv6_nodes: int = 0,
        status: str = "",
    ) -> None:
        """Update the bootstrap progress display.

        Parameters
        ----------
        phase : str
            Current phase description.
        depth : int
            Current recursion depth.
        nodes_queried : int
            Total nodes queried.
        nodes_discovered : int
            Total nodes discovered.
        min_xor_distance : int
            Minimum XOR distance to self (smaller = better).
        total_nodes : int
            Total nodes in routing table.
        bucket_count : int
            Total bucket count.
        active_buckets : int
            Active bucket count.
        ipv4_nodes : int
            IPv4 node count.
        ipv6_nodes : int
            IPv6 node count.
        status : str
            Status message.
        """
        self._phase = phase
        self._depth = depth
        self._nodes_queried = nodes_queried
        self._nodes_discovered = nodes_discovered
        self._min_xor_distance = min_xor_distance
        self._total_nodes = total_nodes
        self._bucket_count = bucket_count
        self._active_buckets = active_buckets
        self._ipv4_nodes = ipv4_nodes
        self._ipv6_nodes = ipv6_nodes
        if status:
            self._status = status
        self.update_display()

    def update_display(self) -> None:
        """Update all display elements with current values."""
        # Phase
        if "Phase 1" in self._phase:
            self._phase_label.setText("Phase: Bootstrap nodes")
            self._status_label.setText(self._status)
        elif "Phase 2" in self._phase:
            self._phase_label.setText("Phase: Recursive propagation")
            self._status_label.setText(self._status)
        else:
            self._phase_label.setText(f"Phase: {self._phase}")

        # Depth
        self._depth_label.setText(f"Depth: {self._depth}")

        # Nodes queried
        self._queried_label.setText(f"Nodes queried: {self._nodes_queried}")

        # Nodes discovered
        self._discovered_label.setText(
            f"Nodes discovered: {self._nodes_discovered} (IPv4: {self._ipv4_nodes}, IPv6: {self._ipv6_nodes})"
        )

        # Bucket info
        if self._bucket_count > 0:
            self._bucket_label.setText(f"Active buckets: {self._active_buckets} / {self._bucket_count}")
        else:
            self._bucket_label.setText(f"Nodes in routing table: {self._total_nodes}")

        # XOR distance - smaller is better
        if self._min_xor_distance == 0:
            self._xor_label.setText("XOR distance to self: FOUND! (0)")
            self._xor_label.setStyleSheet("""
                QLabel {
                    color: #94e185;
                    font-size: 18px;
                    font-weight: bold;
                    background: transparent;
                }
            """)
        else:
            # Format XOR distance in hex
            xor_hex = f"{self._min_xor_distance:040x}"
            # Show first 20 chars + ellipsis for readability
            xor_display = f"{xor_hex[:16]}...{xor_hex[-4:]}"
            self._xor_label.setText(f"XOR distance to self: {xor_display}")

            # Color based on magnitude (log scale)
            log_dist = math.log10(self._min_xor_distance + 1)
            if log_dist < 10:
                color = "#94e185"  # Green - very close
            elif log_dist < 12:
                color = "#a6e3a1"  # Light green
            elif log_dist < 14:
                color = "#f9e2af"  # Yellow - medium
            elif log_dist < 16:
                color = "#f38ba8"  # Red - far
            else:
                color = "#f38ba8"  # Red - very far
            self._xor_label.setStyleSheet(f"""
                QLabel {{
                    color: {color};
                    font-size: 16px;
                    font-weight: bold;
                    background: transparent;
                }}
            """)

        # Progress - based on how small the XOR distance is
        # Max possible XOR distance for 20 bytes is 2^160
        max_dist = 2**160
        if self._min_xor_distance > 0:
            progress = max(0, min(100, int((1 - self._min_xor_distance / max_dist) * 100)))
        else:
            progress = 100
        self._progress_label.setText(f"Progress: {progress}%")

        # Elapsed time is updated by timer

    def set_status(self, status: str) -> None:
        """Set the status message.

        Parameters
        ----------
        status : str
            The status message.
        """
        self._status = status
        self._status_label.setText(status)
