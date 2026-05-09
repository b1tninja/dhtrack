"""
DHT Monitor widget for the DHT Network Inspector.

Provides a comprehensive dashboard for spying on the DHT network, including:
- BEP 33 DHT Scrape visualization (seed/peer counts)
- BEP 42 Security monitoring (failed authentications, suspicious nodes)
- BEP 43 Read-only node detection (nodes that don't send queries)
- BEP 46 Mutable item tracking (DHT-published data)
- BEP 50 Pub/sub topic monitoring (active topics and participants)
"""

from __future__ import annotations

import binascii
import time
from collections import defaultdict
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from dhtrack.gui.widgets.stat_card import StatCard

if TYPE_CHECKING:
    from dhtrack.dht import DHTNode


class DHTMonitorWidget(QWidget):
    """Comprehensive DHT network monitoring dashboard.

    Features:
    - BEP 33 DHT Scrape visualization
    - BEP 42 Security monitoring
    - BEP 43 Read-only node detection
    - BEP 46 Mutable item tracking
    - BEP 50 Pub/sub topic monitoring
    """

    def __init__(self, dht_node: DHTNode, parent: QWidget | None = None):
        super().__init__(parent)
        self.dht_node = dht_node
        self._start_time = time.time()

        # BEP 33 Scrape tracking
        self._scrape_requests: dict[str, int] = defaultdict(int)  # infohash -> count
        self._scrape_responses: dict[str, dict] = {}  # infohash -> {seeds, peers, downloaded}

        # BEP 42 Security tracking
        self._security_events: list[dict] = []  # List of security events
        self._security_counter: int = 0  # Count of security events

        # BEP 43 Read-only node tracking
        self._queried_nodes: set[tuple[str, int]] = set()  # Nodes that sent queries
        self._responded_nodes: set[tuple[str, int]] = set()  # Nodes that responded

        # BEP 46 Mutable item tracking
        self._mutable_items: dict[str, dict] = {}  # key -> item info

        # BEP 50 Pub/sub tracking
        self._pubsub_topics: dict[str, int] = defaultdict(int)  # topic -> message count

        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self) -> None:
        """Build the monitoring UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(8)

        # Title
        title = QLabel("DHT Network Monitor")
        title.setProperty("role", "title")
        main_layout.addWidget(title)

        # Summary cards row
        cards_layout = QGridLayout()
        cards_layout.setSpacing(6)

        self.scrape_count_card = StatCard("BEP 33 Scrape Requests", "0")
        self.security_alert_card = StatCard("BEP 42 Security Alerts", "0")
        self.readonly_node_card = StatCard("BEP 43 Read-Only Nodes", "0")
        self.mutable_item_card = StatCard("BEP 46 Mutable Items", "0")
        self.pubsub_topic_card = StatCard("BEP 50 Pub/Sub Topics", "0")

        cards_layout.addWidget(self.scrape_count_card, 0, 0)
        cards_layout.addWidget(self.security_alert_card, 0, 1)
        cards_layout.addWidget(self.readonly_node_card, 0, 2)
        cards_layout.addWidget(self.mutable_item_card, 1, 0)
        cards_layout.addWidget(self.pubsub_topic_card, 1, 1)

        main_layout.addLayout(cards_layout)

        # Scrape requests log
        self.scrape_log = QTextEdit()
        self.scrape_log.setReadOnly(True)
        self.scrape_log.setMaximumHeight(150)
        self.scrape_log.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; "
            "font-family: monospace; border: 1px solid #313244; }"
        )
        self.scrape_log.setPlaceholderText("BEP 33 Scrape requests and responses will appear here...")
        main_layout.addWidget(self.scrape_log)

        # Security events log
        self.security_log = QTextEdit()
        self.security_log.setReadOnly(True)
        self.security_log.setMaximumHeight(150)
        self.security_log.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; "
            "font-family: monospace; border: 1px solid #313244; }"
        )
        self.security_log.setPlaceholderText("BEP 42 Security events will appear here...")
        main_layout.addWidget(self.security_log)

        # Read-only nodes log
        self.readonly_log = QTextEdit()
        self.readonly_log.setReadOnly(True)
        self.readonly_log.setMaximumHeight(150)
        self.readonly_log.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; "
            "font-family: monospace; border: 1px solid #313244; }"
        )
        self.readonly_log.setPlaceholderText("BEP 43 Read-only nodes will appear here...")
        main_layout.addWidget(self.readonly_log)

        # Mutable items log
        self.mutable_log = QTextEdit()
        self.mutable_log.setReadOnly(True)
        self.mutable_log.setMaximumHeight(150)
        self.mutable_log.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; "
            "font-family: monospace; border: 1px solid #313244; }"
        )
        self.mutable_log.setPlaceholderText("BEP 46 Mutable items will appear here...")
        main_layout.addWidget(self.mutable_log)

        # Pub/sub topics log
        self.pubsub_log = QTextEdit()
        self.pubsub_log.setReadOnly(True)
        self.pubsub_log.setMaximumHeight(150)
        self.pubsub_log.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; "
            "font-family: monospace; border: 1px solid #313244; }"
        )
        self.pubsub_log.setPlaceholderText("BEP 50 Pub/sub topics will appear here...")
        main_layout.addWidget(self.pubsub_log)

        # Control buttons
        control_layout = QHBoxLayout()

        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.clicked.connect(self._on_refresh)
        control_layout.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("Export Log")
        self.export_btn.clicked.connect(self._on_export_log)
        control_layout.addWidget(self.export_btn)

        self.reset_btn = QPushButton("Reset Counters")
        self.reset_btn.clicked.connect(self._on_reset)
        control_layout.addWidget(self.reset_btn)

        control_layout.addStretch()

        main_layout.addLayout(control_layout)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #a6adc8;")
        main_layout.addWidget(self.status_label)

    def _setup_timer(self) -> None:
        """Setup the refresh timer."""
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start(2000)  # Update every 2 seconds

    def _on_timer(self) -> None:
        """Periodic update."""
        self._update_dashboard()

    def _update_dashboard(self) -> None:
        """Update all dashboard elements."""
        elapsed = time.time() - self._start_time
        if elapsed < 60:
            pass
        elif elapsed < 3600:
            f"{elapsed / 60:.1f}m"
        else:
            f"{elapsed / 3600:.2f}h"

        # Update scrape count
        self.scrape_count_card.update_value(str(len(self._scrape_requests) + len(self._scrape_responses)))

        # Update security alerts
        self.security_alert_card.update_value(str(self._security_counter), "#f38ba8")

        # Update read-only nodes
        self.readonly_node_card.update_value(str(len(self._queried_nodes) - len(self._responded_nodes)))

        # Update mutable items
        self.mutable_item_card.update_value(str(len(self._mutable_items)))

        # Update pub/sub topics
        self.pubsub_topic_card.update_value(str(len(self._pubsub_topics)))

    def _on_refresh(self) -> None:
        """Force immediate refresh."""
        self._update_dashboard()
        self.status_label.setText("Refreshed")

    def _on_export_log(self) -> None:
        """Export all logs to a file."""
        from PyQt6.QtWidgets import QFileDialog

        path, _ = QFileDialog.getSaveFileName(self, "Export DHT Monitor Log", "", "Text Files (*.txt);;All Files (*)")
        if path:
            with open(path, "w") as f:
                f.write("DHT Network Monitor Log\n")
                f.write("=" * 80 + "\n\n")
                f.write("BEP 33 Scrape Requests:\n")
                for infohash, count in self._scrape_requests.items():
                    f.write(f"  {infohash}: {count} requests\n")
                f.write("\nBEP 42 Security Events:\n")
                for event in self._security_events:
                    f.write(f"  {event}\n")
                f.write("\nBEP 43 Read-Only Nodes:\n")
                for node in self._queried_nodes - self._responded_nodes:
                    f.write(f"  {node[0]}:{node[1]}\n")
                f.write("\nBEP 46 Mutable Items:\n")
                for key, info in self._mutable_items.items():
                    f.write(f"  {key}: {info}\n")
                f.write("\nBEP 50 Pub/Sub Topics:\n")
                for topic, count in self._pubsub_topics.items():
                    f.write(f"  {topic}: {count} messages\n")
            self.status_label.setText(f"Exported to {path}")

    def _on_reset(self) -> None:
        """Reset all counters."""
        self._scrape_requests.clear()
        self._scrape_responses.clear()
        self._security_events.clear()
        self._security_counter = 0
        self._queried_nodes.clear()
        self._responded_nodes.clear()
        self._mutable_items.clear()
        self._pubsub_topics.clear()
        self.status_label.setText("Counters reset")

    def on_message_parsed(self, ip: str, port: int, is_ipv6: bool, size: int, msg_info: dict) -> None:
        """Called when a full message has been parsed with all details.

        Parameters
        ----------
        ip : str
            Source (incoming) or destination (outgoing) IP.
        port : int
            Source (incoming) or destination (outgoing) port.
        is_ipv6 : bool
            Whether the address is IPv6.
        size : int
            Message size in bytes.
        msg_info : dict
            Parsed message info with keys: msg_type, y, q, t, direction,
            status, payload_snippet.
        """
        direction = msg_info.get("direction", "incoming")
        msg_type = msg_info.get("msg_type", "unknown")
        status = msg_info.get("status", "")
        payload = msg_info.get("payload_snippet", "")

        # Track queried nodes (nodes that send queries)
        if direction == "outgoing":
            self._queried_nodes.add((ip, port))
        else:
            self._responded_nodes.add((ip, port))

        # BEP 33 Scrape tracking
        if msg_type == "get_peers" or msg_type == "scrape":
            if direction == "outgoing":
                # Extract infohash from payload
                self._scrape_requests[binascii.b2a_hex(ip.encode()).decode()] += 1
                timestamp = time.strftime("%H:%M:%S")
                self.scrape_log.append(f"[{timestamp}] Scrape request to {ip}:{port}")
            elif status == "response":
                self._scrape_responses[binascii.b2a_hex(ip.encode()).decode()] = {
                    "seeds": 0,
                    "peers": 0,
                }
                timestamp = time.strftime("%H:%M:%S")
                self.scrape_log.append(f"[{timestamp}] Scrape response from {ip}:{port}")

        # BEP 42 Security tracking
        if status == "error" or "security" in payload.lower():
            self._security_counter += 1
            timestamp = time.strftime("%H:%M:%S")
            self.security_log.append(f"[{timestamp}] Security event: {msg_type} from {ip}:{port}")
            self._security_events.append(f"[{timestamp}] {msg_type} from {ip}:{port}: {payload}")

        # BEP 46 Mutable item tracking
        if msg_type == "get_data" or msg_type == "put_data":
            if direction == "incoming" and status == "response":
                timestamp = time.strftime("%H:%M:%S")
                self.mutable_log.append(f"[{timestamp}] Mutable item from {ip}:{port}")

        # BEP 50 Pub/sub topic tracking
        if "pubsub" in payload.lower() or "topic" in payload.lower():
            self._pubsub_topics[binascii.b2a_hex(ip.encode()).decode()] += 1
            timestamp = time.strftime("%H:%M:%S")
            self.pubsub_log.append(f"[{timestamp}] Pub/sub message from {ip}:{port}")

    def on_query_sent(self, msg_type: str, target_id: bytes, ip: str, port: int, is_ipv6: bool) -> None:
        """Called when a query is sent to a node.

        Parameters
        ----------
        msg_type : str
            The message type (find_node, get_peers, etc.)
        target_id : bytes
            The target node ID or infohash.
        ip : str
            Target IP address.
        port : int
            Target port.
        is_ipv6 : bool
            Whether the target is IPv6.
        """
        self._queried_nodes.add((ip, port))

    def on_response_received(self, msg_type: str, src_ip: str, src_port: int, is_ipv6: bool) -> None:
        """Called when a response is received from a node.

        Parameters
        ----------
        msg_type : str
            The message type.
        src_ip : str
            Source IP address.
        src_port : int
            Source port.
        is_ipv6 : bool
            Whether the source is IPv6.
        """
        self._responded_nodes.add((src_ip, src_port))
