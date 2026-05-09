"""
Traffic Monitor widget for the DHT Network Inspector.

Displays real-time traffic statistics including message counts,
response rates, and traffic visualization.
"""

from __future__ import annotations

import time
from collections import defaultdict
from enum import Enum

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class DHTMessageType(Enum):
    """DHT protocol message type enumerator.

    Normalizes raw bencoded protocol codes (bytes) to human-readable names.
    """

    QUERY = "Query"
    RESPONSE = "Response"
    ERROR = "Error"

    @classmethod
    def normalize(cls, code: bytes | str) -> str:
        """Convert a protocol code to a human-readable message type name.

        Parameters
        ----------
        code : bytes | str
            The raw protocol code (e.g., b"q", "q", b"r", "r", b"e", "e").

        Returns
        -------
        str
            Human-readable name (e.g., "Query", "Response", "Error")
            or the original code if not recognized.
        """
        if isinstance(code, bytes):
            code = code.decode("ascii", errors="ignore")
        code_upper = code.upper()
        mapping = {
            "Q": cls.QUERY.value,
            "R": cls.RESPONSE.value,
            "E": cls.ERROR.value,
        }
        return mapping.get(code_upper, str(code))


class TrafficStats:
    """Tracks DHT traffic statistics."""

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all counters."""
        self.outgoing: dict[str, int] = defaultdict(int)
        self.incoming: dict[str, int] = defaultdict(int)
        self.responses: int = 0
        self.errors: int = 0
        self.timeouts: int = 0
        self.total_bytes_out: int = 0
        self.total_bytes_in: int = 0
        self.start_time: float = time.time()
        self._last_reset = time.time()

    def update(self, direction: str, msg_type: str, size: int = 0, status: str = ""):
        """Update statistics with a new message.

        Parameters
        ----------
        direction : str
            "outgoing" or "incoming".
        msg_type : str
            Message type (ping, find_node, get_peers, etc.)
        size : int
            Approximate message size.
        status : str
            "response", "error", "timeout", etc.
        """
        if direction == "outgoing":
            self.outgoing[msg_type] += 1
            self.total_bytes_out += size
        else:
            self.incoming[msg_type] += 1
            self.total_bytes_in += size

        if status == "response":
            self.responses += 1
        elif status == "error":
            self.errors += 1
        elif status == "timeout":
            self.timeouts += 1

    def get_uptime(self) -> str:
        """Get formatted uptime."""
        elapsed = time.time() - self.start_time
        if elapsed < 60:
            return f"{elapsed:.0f}s"
        elif elapsed < 3600:
            return f"{elapsed / 60:.1f}m"
        else:
            return f"{elapsed / 3600:.2f}h"

    def get_response_rate(self) -> float:
        """Get response rate as a percentage."""
        total = self.responses + self.errors + self.timeouts
        if total == 0:
            return 0.0
        return (self.responses / total) * 100

    def reset_counters(self):
        """Reset counters but keep uptime."""
        self.outgoing.clear()
        self.incoming.clear()
        self.responses = 0
        self.errors = 0
        self.timeouts = 0
        self.total_bytes_out = 0
        self.total_bytes_in = 0
        self._last_reset = time.time()


class TrafficMonitorWidget(QWidget):
    """Widget displaying real-time DHT traffic monitoring stats."""

    def __init__(self, dht_node: object, parent: QWidget | None = None):
        super().__init__(parent)
        self.dht_node = dht_node
        self._stats = TrafficStats()
        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self) -> None:
        """Build the traffic monitor UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Title
        title = QLabel("DHT Traffic Monitor")
        title.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        # Summary row
        summary_frame = QWidget()
        summary_frame.setProperty("role", "toolbar_strip")
        summary_layout = QGridLayout(summary_frame)
        summary_layout.setSpacing(4)

        self.uptime_card = QLabel("Uptime: 0s")
        self.response_rate_card = QLabel("Response Rate: 0%")
        self.total_out_card = QLabel("Total Out: 0")
        self.total_in_card = QLabel("Total In: 0")
        self.bytes_out_card = QLabel("Bytes Out: 0")
        self.bytes_in_card = QLabel("Bytes In: 0")

        summary_layout.addWidget(self.uptime_card, 0, 0)
        summary_layout.addWidget(self.response_rate_card, 0, 1)
        summary_layout.addWidget(self.total_out_card, 1, 0)
        summary_layout.addWidget(self.total_in_card, 1, 1)
        summary_layout.addWidget(self.bytes_out_card, 2, 0)
        summary_layout.addWidget(self.bytes_in_card, 2, 1)

        layout.addWidget(summary_frame)

        # Message flow section
        flow_section = QWidget()
        flow_layout = QVBoxLayout(flow_section)
        flow_layout.setSpacing(6)

        flow_title = QLabel("Message Flow")
        flow_title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        flow_layout.addWidget(flow_title)

        # Outgoing messages
        outgoing_carrier = QWidget()
        outgoing_layout = QVBoxLayout(outgoing_carrier)
        outgoing_layout.setSpacing(2)

        outgoing_label = QLabel("Outgoing Messages:")
        outgoing_label.setStyleSheet("color: #f9e2af; font-weight: bold;")
        outgoing_layout.addWidget(outgoing_label)

        self.outgoing_list = QTextEdit()
        self.outgoing_list.setReadOnly(True)
        self.outgoing_list.setMaximumHeight(120)
        self.outgoing_list.setStyleSheet(
            "QTextEdit { background-color: #1e1e2e; color: #a6e3a1; font-family: monospace; border: none; }"
        )
        outgoing_layout.addWidget(self.outgoing_list)
        flow_layout.addWidget(outgoing_carrier)

        # Incoming messages
        incoming_carrier = QWidget()
        incoming_layout = QVBoxLayout(incoming_carrier)
        incoming_layout.setSpacing(2)

        incoming_label = QLabel("Incoming Messages:")
        incoming_label.setStyleSheet("color: #89b4fa; font-weight: bold;")
        incoming_layout.addWidget(incoming_label)

        self.incoming_list = QTextEdit()
        self.incoming_list.setReadOnly(True)
        self.incoming_list.setMaximumHeight(120)
        self.incoming_list.setStyleSheet(
            "QTextEdit { background-color: #1e1e2e; color: #cdd6f4; font-family: monospace; border: none; }"
        )
        incoming_layout.addWidget(self.incoming_list)
        flow_layout.addWidget(incoming_carrier)

        layout.addWidget(flow_section)

        # Response/Error breakdown
        breakdown_carrier = QWidget()
        breakdown_layout = QVBoxLayout(breakdown_carrier)

        breakdown_title = QLabel("Response Breakdown")
        breakdown_title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        breakdown_layout.addWidget(breakdown_title)

        breakdown_grid = QGridLayout()

        self.responses_label = QLabel("Responses: 0")
        self.errors_label = QLabel("Errors: 0")
        self.timeouts_label = QLabel("Timeouts: 0")
        self.success_rate_label = QLabel("Success Rate: 0%")

        breakdown_grid.addWidget(self.responses_label, 0, 0)
        breakdown_grid.addWidget(self.errors_label, 0, 1)
        breakdown_grid.addWidget(self.timeouts_label, 1, 0)
        breakdown_grid.addWidget(self.success_rate_label, 1, 1)

        breakdown_layout.addLayout(breakdown_grid)
        layout.addWidget(breakdown_carrier)

        # Message type statistics
        msg_type_carrier = QWidget()
        msg_type_layout = QVBoxLayout(msg_type_carrier)

        msg_type_title = QLabel("Message Type Statistics")
        msg_type_title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        msg_type_layout.addWidget(msg_type_title)

        # Outgoing messages table
        outgoing_label = QLabel("Outgoing Messages:")
        outgoing_label.setStyleSheet("color: #f9e2af; font-weight: bold;")
        msg_type_layout.addWidget(outgoing_label)

        self.msg_type_out = QTableView()
        self.msg_type_out.setAlternatingRowColors(True)
        self.msg_type_out.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.msg_type_out.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.msg_type_out.setSortingEnabled(True)
        self.msg_type_out.horizontalHeader().setStretchLastSection(True)
        self.msg_type_out.horizontalHeader().setHighlightSections(False)
        self.msg_type_out.setStyleSheet(
            "QTableView { background-color: #1e1e2e; color: #a6e3a1; "
            "border: 1px solid #313244; font-family: monospace; }"
            "QTableView::item { padding: 4px; }"
            "QTableView::section { background-color: #181825; color: #89b4fa; "
            "padding: 4px; border: 1px solid #313244; }"
        )
        msg_type_layout.addWidget(self.msg_type_out)

        # Incoming messages table
        incoming_label = QLabel("Incoming Messages:")
        incoming_label.setStyleSheet("color: #89b4fa; font-weight: bold;")
        msg_type_layout.addWidget(incoming_label)

        self.msg_type_in = QTableView()
        self.msg_type_in.setAlternatingRowColors(True)
        self.msg_type_in.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.msg_type_in.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.msg_type_in.setSortingEnabled(True)
        self.msg_type_in.horizontalHeader().setStretchLastSection(True)
        self.msg_type_in.horizontalHeader().setHighlightSections(False)
        self.msg_type_in.setStyleSheet(
            "QTableView { background-color: #1e1e2e; color: #89b4fa; "
            "border: 1px solid #313244; font-family: monospace; }"
            "QTableView::item { padding: 4px; }"
            "QTableView::section { background-color: #181825; color: #89b4fa; "
            "padding: 4px; border: 1px solid #313244; }"
        )
        msg_type_layout.addWidget(self.msg_type_in)

        layout.addWidget(msg_type_carrier)

        # Control buttons
        control_layout = QHBoxLayout()

        reset_btn = QPushButton("Reset Counters")
        reset_btn.clicked.connect(self._reset_counters)
        control_layout.addWidget(reset_btn)

        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self._clear_log)
        control_layout.addWidget(clear_btn)

        control_layout.addStretch()

        layout.addLayout(control_layout)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #a6adc8;")
        layout.addWidget(self.status_label)

    def _setup_timer(self) -> None:
        """Setup the refresh timer."""
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_display)
        self._timer.start(1000)

    def _update_display(self) -> None:
        """Update all display elements."""
        # Update summary
        self.uptime_card.setText(f"Uptime: {self._stats.get_uptime()}")
        rate = self._stats.get_response_rate()
        color = "#a6e3a1" if rate >= 70 else "#f9e2af" if rate >= 50 else "#f38ba8"
        self.response_rate_card.setText(f"Response Rate: {rate:.1f}%")
        self.response_rate_card.setStyleSheet(f"color: {color};")

        self.total_out_card.setText(f"Total Out: {sum(self._stats.outgoing.values())}")
        self.total_in_card.setText(f"Total In: {sum(self._stats.incoming.values())}")
        self.bytes_out_card.setText(f"Bytes Out: {self._stats.total_bytes_out:,}")
        self.bytes_in_card.setText(f"Bytes In: {self._stats.total_bytes_in:,}")

        # Update breakdown
        self.responses_label.setText(f"Responses: {self._stats.responses}")
        self.errors_label.setText(f"Errors: {self._stats.errors}")
        self.timeouts_label.setText(f"Timeouts: {self._stats.timeouts}")
        success = self._stats.get_response_rate()
        self.success_rate_label.setText(f"Success Rate: {success:.1f}%")

        # Update message type stats
        self._update_msg_type_display()

    def _update_msg_type_display(self) -> None:
        """Update the message type statistics display."""
        total_out = sum(self._stats.outgoing.values())
        total_in = sum(self._stats.incoming.values())

        # Update outgoing messages table
        from dhtrack.gui.models.msg_type_model import MessageTypeModel

        if not hasattr(self, "_out_model"):
            self._out_model = MessageTypeModel("Outgoing", dict(self._stats.outgoing), total_out)
            self.msg_type_out.setModel(self._out_model)
        else:
            self._out_model.update_data(dict(self._stats.outgoing), total_out)

        # Update incoming messages table
        if not hasattr(self, "_in_model"):
            self._in_model = MessageTypeModel("Incoming", dict(self._stats.incoming), total_in)
            self.msg_type_in.setModel(self._in_model)
        else:
            self._in_model.update_data(dict(self._stats.incoming), total_in)

    def _reset_counters(self) -> None:
        """Reset all counters."""
        self._stats.reset_counters()
        self.status_label.setText("Counters reset")

    def _clear_log(self) -> None:
        """Clear the log displays."""
        self.outgoing_list.clear()
        self.incoming_list.clear()
        self.status_label.setText("Log cleared")

    def on_outgoing_message(self, msg_type: str, size: int = 0, status: str = "") -> None:
        """Called when an outgoing message is sent.

        Parameters
        ----------
        msg_type : str
            The message type (ping, find_node, get_peers, announce_peer, or protocol code).
        size : int
            Approximate message size in bytes.
        status : str
            Optional status indicator.
        """
        readable = DHTMessageType.normalize(msg_type) if msg_type else msg_type
        self._stats.update("outgoing", readable, max(size, 0), status)

        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] → {readable} ({size} bytes)\n"
        self.outgoing_list.append(entry)
        self.outgoing_list.verticalScrollBar().setValue(self.outgoing_list.verticalScrollBar().maximum())

    def on_incoming_message(self, msg_type: str, size: int = 0, status: str = "") -> None:
        """Called when an incoming message is received.

        Parameters
        ----------
        msg_type : str
            The message type (ping, find_node, get_peers, announce_peer, or protocol code).
        size : int
            Approximate message size in bytes.
        status : str
            Optional status indicator (e.g., "response", "error").
        """
        readable = DHTMessageType.normalize(msg_type) if msg_type else msg_type
        self._stats.update("incoming", readable, max(size, 0), status)

        timestamp = time.strftime("%H:%M:%S")
        status_str = f" [{status}]" if status else ""
        entry = f"[{timestamp}] ← {readable} ({size} bytes){status_str}\n"
        self.incoming_list.append(entry)
        self.incoming_list.verticalScrollBar().setValue(self.incoming_list.verticalScrollBar().maximum())
