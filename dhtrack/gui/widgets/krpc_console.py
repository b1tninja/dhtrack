"""
kRPC Console for the DHT Network Inspector.

Provides a table-based view for sending kRPC queries
to DHT peers and viewing traffic logs.
"""

from __future__ import annotations

import binascii
import time
from collections import deque

from PyQt6.QtCore import QAbstractTableModel, Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from dhtrack.dht import DHTNode
from dhtrack.gui.krpc_actions import (
    send_announce_peer,
    send_find_node,
    send_get_peers,
    send_ping,
)


class TrafficTableModel(QAbstractTableModel):
    """Model for kRPC console traffic table."""

    def __init__(self, parent: object | None = None):
        super().__init__(parent)
        self._data: list[dict] = []

    def set_data(self, data: list[dict]) -> None:
        """Update the model with traffic data."""
        self.layoutAboutToBeChanged.emit()
        self._data = list(data)
        self.layoutChanged.emit()

    def rowCount(self, parent=None, index=None) -> int:
        return len(self._data)

    def columnCount(self, parent=None, index=None) -> int:
        return 8

    def headerData(self, section: int, orientation: Qt.Orientation, role: int):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            headers = ["Time", "Dir", "Type", "Source", "Destination", "TXID", "Status", "Payload"]
            if section < len(headers):
                return headers[section]
        return None

    def data(self, index, role: int):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row < 0 or row >= len(self._data):
            return None

        entry = self._data[row]

        if role == Qt.ItemDataRole.DisplayRole:
            fields = [
                entry.get("time", ""),  # 0: Time
                entry.get("direction", ""),  # 1: Direction
                entry.get("msg_type", ""),  # 2: Message type
                entry.get("src", ""),  # 3: Source
                entry.get("dst", ""),  # 4: Destination
                entry.get("txid", ""),  # 5: TXID
                entry.get("status", ""),  # 6: Status
                entry.get("payload", ""),  # 7: Payload
            ]
            if col < len(fields):
                return str(fields[col]) if fields[col] is not None else ""

        return None

    def sort(self, col: int, order: Qt.SortOrder) -> None:
        """Sort the table by column."""
        self.layoutAboutToBeChanged.emit()
        self._data.sort(key=lambda e: str(e.get(list(e.keys())[col % len(e.keys())], "")))
        self.layoutChanged.emit()

    def add_wire_entry(
        self,
        direction: str,
        ip: str,
        port: int,
        is_ipv6: bool,
        size: int,
        hex_str: str,
        decode_status: str,
        decode_repr: str,
        txid_hex: str = "",
        method: str = "",
        note: str = "",
    ) -> None:
        """Add a wire-level datagram entry to the table model.

        Wire entries have a distinct msg_type prefix "WIRE" so they
        stand out in the table alongside regular RPC messages.
        """
        addr_str = f"[{ip}]:{port}" if is_ipv6 else f"{ip}:{port}"
        status_str = decode_status
        payload_str = f"size={size}B txid={txid_hex} method={method}{' ' + note if note else ''}"

        entry = {
            "time": time.strftime("%H:%M:%S", time.localtime()),
            "direction": "\u2192" if direction == "OUT" else "\u2190",
            "msg_type": "WIRE",
            "src": addr_str if direction == "IN" else "LOCAL",
            "dst": addr_str if direction == "OUT" else "LOCAL",
            "txid": txid_hex,
            "status": status_str,
            "payload": payload_str,
        }

        self._data.append(entry)
        self.layoutChanged.emit()


class TrafficEntry:
    """Represents a single traffic log entry."""

    def __init__(
        self,
        timestamp: float,
        direction: str,
        msg_type: str,
        src: str,
        dst: str,
        txid: str = "",
        status: str = "",
        payload: str = "",
    ):
        self.timestamp = timestamp
        self.direction = direction  # "→" or "←"
        self.msg_type = msg_type
        self.src = src
        self.dst = dst
        self.txid = txid
        self.status = status  # "✓ response", "✗ error", "⏱ timeout"
        self.payload = payload

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    def to_dict(self) -> dict:
        """Convert to dict for table display."""
        return {
            "time": self.time_str,
            "direction": self.direction,
            "msg_type": self.msg_type,
            "src": self.src,
            "dst": self.dst,
            "txid": self.txid,
            "status": self.status,
            "payload": self.payload,
        }


class KRPConsoleWidget(QWidget):
    """Interactive kRPC console for DHT traffic inspection."""

    LOG_MAX_LINES = 5000

    # Commands: (command, description)
    COMMANDS = [
        ("ping <ip> <port> [is_ipv6]", "Send ping to a node"),
        ("find_node <ip> <port> <target_id> [is_ipv6]", "Send find_node query"),
        ("get_peers <ip> <port> <infohash> [is_ipv6]", "Query for peers"),
        ("announce_peer <ip> <port> <infohash> [port|implied] [is_ipv6]", "Announce yourself"),
        ("ping_all_questionable", "Ping all questionable nodes"),
        ("find_all_nodes", "Find nodes close to random ID"),
        ("status", "Show connection status"),
        ("clear", "Clear the console"),
        ("help", "Show available commands"),
        ("export_log <filename>", "Export traffic log to file"),
        ("toggle_filter <ping|find_node|get_peers|announce_peer|all>", "Filter messages"),
    ]

    def __init__(self, dht_node: DHTNode, parent: QWidget | None = None):
        super().__init__(parent)
        self.dht_node = dht_node
        self._traffic_log: deque[TrafficEntry] = deque(maxlen=self.LOG_MAX_LINES)
        self._command_history: list[str] = []
        self._history_index = -1
        self._msg_filter: str = "all"
        self._log_enabled: bool = True

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the console UI with table view."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Header with controls
        header_layout = QHBoxLayout()

        QLabel("Traffic Log:", self)

        # Filter combo
        self.filter_combo = QComboBox(self)
        self.filter_combo.addItems(["All", "ping", "find_node", "get_peers", "announce_peer", "error"])
        self.filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        header_layout.addWidget(self.filter_combo)

        # Enable/Disable toggle
        self.enable_btn = QPushButton("Capture: ON")
        self.enable_btn.clicked.connect(self._on_toggle_capture)
        header_layout.addWidget(self.enable_btn)

        # Clear button
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear)
        header_layout.addWidget(clear_btn)

        # Export button
        export_btn = QPushButton("Export Log")
        export_btn.clicked.connect(self._on_export_log)
        header_layout.addWidget(export_btn)

        # Entry count
        self.entry_label = QLabel("Entries: 0")
        self.entry_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        header_layout.addWidget(self.entry_label)

        layout.addLayout(header_layout)

        # Table view
        self.table_view = QTableView()
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table_view.setSortingEnabled(True)

        self.table_model = TrafficTableModel()
        self.table_view.setModel(self.table_model)

        self._traffic_data: list[dict] = []

        # Resize columns
        header = self.table_view.horizontalHeader()
        header.resizeSection(0, 80)  # Time
        header.resizeSection(1, 40)  # Dir
        header.resizeSection(2, 110)  # Type
        header.resizeSection(3, 100)  # Source
        header.resizeSection(4, 100)  # Destination
        header.resizeSection(5, 50)  # TXID
        header.resizeSection(6, 100)  # Status
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)  # Payload

        layout.addWidget(self.table_view)

        # Command input area
        input_layout = QHBoxLayout()

        self.prompt_label = QLabel(">>>")
        self.prompt_label.setStyleSheet("color: #f9e2af; font-weight: bold;")
        self.prompt_label.setFont(QFont("Cascadia Code", 11))
        input_layout.addWidget(self.prompt_label)

        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command (type 'help' for options)...")
        self.command_input.setFont(QFont("Cascadia Code", 11))
        self.command_input.returnPressed.connect(self._on_send_command)
        input_layout.addWidget(self.command_input)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._on_send_command)
        input_layout.addWidget(send_btn)

        layout.addLayout(input_layout)

        # Help area at bottom
        help_frame = QFrame()
        help_frame.setStyleSheet("QFrame { background-color: #181825; border: none; }")
        help_layout = QVBoxLayout(help_frame)
        help_layout.setContentsMargins(4, 4, 4, 4)

        help_label = QLabel("Commands:")
        help_label.setStyleSheet("color: #89b4fa; font-weight: bold;")
        help_layout.addWidget(help_label)

        self.help_text = QLabel()
        self.help_text.setStyleSheet(
            "QLabel { background-color: #181825; color: #a6adc8; "
            "font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; "
            "border: none; }"
        )
        self.help_text.setFont(QFont("Cascadia Code", 10))
        self.help_text.setWordWrap(True)
        self._update_help_text()
        help_layout.addWidget(self.help_text)

        layout.addWidget(help_frame)

    def _update_help_text(self) -> None:
        """Update the help text display."""
        text = ""
        for cmd, desc in self.COMMANDS:
            text += f"  {cmd} — {desc}\n"
        self.help_text.setText(text)

    def _on_filter_changed(self, index: int) -> None:
        """Handle filter changes."""
        selected = self.filter_combo.currentText()
        if selected == "All":
            self._msg_filter = "all"
        else:
            self._msg_filter = selected.lower()
        self._add_to_table("System", "→", "filter", "N/A", "N/A", "", f"Filter: {selected}")

    def _on_toggle_capture(self) -> None:
        """Toggle traffic capture."""
        self._log_enabled = not self._log_enabled
        self.enable_btn.setText(f"Capture: {'ON' if self._log_enabled else 'OFF'}")
        self._add_to_table(
            "System", "→", "status", "N/A", "N/A", "", f"Capture {'ENABLED' if self._log_enabled else 'DISABLED'}"
        )

    def _on_clear(self) -> None:
        """Clear the console output."""
        self._traffic_log.clear()
        self._traffic_data = []
        self.table_model.set_data([])
        self.entry_label.setText("Entries: 0")
        self._add_to_table("System", "→", "status", "N/A", "N/A", "", "Console cleared.")

    def _on_export_log(self) -> None:
        """Export traffic log to file."""
        from PyQt6.QtWidgets import QFileDialog

        path, _ = QFileDialog.getSaveFileName(self, "Export Traffic Log", "", "Text Files (*.txt);;All Files (*)")
        if path:
            with open(path, "w") as f:
                f.write("DHT Traffic Log\n")
                f.write("=" * 100 + "\n")
                _hdr = (
                    f"{'Time':<10} {'Dir':<4} {'Type':<16} {'Source':<20} "
                    f"{'Dest':<20} {'TXID':<8} {'Status':<10} {'Payload'}\n"
                )
                f.write(_hdr)
                f.write("-" * 100 + "\n")
                for entry in self._traffic_log:
                    if self._msg_filter != "all" and entry.msg_type != self._msg_filter:
                        continue
                    f.write(
                        f"{entry.time_str:<10} {entry.direction:<4} "
                        f"{entry.msg_type:<16} {entry.src:<20} {entry.dst:<20} "
                        f"{entry.txid:<8} {entry.status:<10} {entry.payload}\n"
                    )
            self._add_to_table("System", "→", "export", "N/A", "N/A", "", f"Exported to: {path}")

    def _on_send_command(self) -> None:
        """Process the entered command."""
        command = self.command_input.text().strip()
        if not command:
            return

        # Add to history (but not duplicates at the end)
        if not self._command_history or self._command_history[-1] != command:
            self._command_history.append(command)
        self._history_index = len(self._command_history)

        self.command_input.clear()
        self._add_to_table("Console", "→", "command", "N/A", "N/A", command, command)

        try:
            self._execute_command(command)
        except Exception as e:
            self._add_to_table("System", "←", "error", "N/A", "N/A", "", f"Error: {e}")

    def _execute_command(self, command: str) -> None:
        """Execute a command string."""
        parts = command.split()
        if not parts:
            return

        cmd = parts[0].lower()

        if cmd == "help":
            self._add_to_table("System", "→", "help", "N/A", "N/A", "", "Available commands:")
            for c, desc in self.COMMANDS:
                self._add_to_table("System", "→", "help", "N/A", "N/A", "", f"  {c} — {desc}")

        elif cmd == "ping":
            if len(parts) < 3:
                self._add_to_table("System", "←", "error", "N/A", "N/A", "", "Usage: ping <ip> <port> [is_ipv6]")
                return
            ip = parts[1]
            port = int(parts[2])
            is_ipv6 = len(parts) > 3 and parts[3].lower() in ("yes", "true", "1", "v6")
            self._send_ping(ip, port, is_ipv6)

        elif cmd == "find_node":
            if len(parts) < 4:
                self._add_to_table(
                    "System",
                    "←",
                    "error",
                    "N/A",
                    "N/A",
                    "",
                    "Usage: find_node <ip> <port> <target_id_hex> [is_ipv6]",
                )
                return
            ip = parts[1]
            port = int(parts[2])
            target_id = bytes.fromhex(parts[3])
            is_ipv6 = len(parts) > 4 and parts[4].lower() in ("yes", "true", "1", "v6")
            if len(target_id) != 20:
                self._add_to_table(
                    "System",
                    "←",
                    "error",
                    "N/A",
                    "N/A",
                    "",
                    "Target ID must be 20 bytes (40 hex chars)",
                )
                return
            self._send_find_node(ip, port, target_id, is_ipv6)

        elif cmd == "get_peers":
            if len(parts) < 4:
                self._add_to_table(
                    "System",
                    "←",
                    "error",
                    "N/A",
                    "N/A",
                    "",
                    "Usage: get_peers <ip> <port> <infohash_hex> [is_ipv6]",
                )
                return
            ip = parts[1]
            port = int(parts[2])
            infohash = bytes.fromhex(parts[3])
            is_ipv6 = len(parts) > 4 and parts[4].lower() in ("yes", "true", "1", "v6")
            if len(infohash) != 20:
                self._add_to_table("System", "←", "error", "N/A", "N/A", "", "Infohash must be 20 bytes (40 hex chars)")
                return
            self._send_get_peers(ip, port, infohash, is_ipv6)

        elif cmd == "announce_peer":
            if len(parts) < 4:
                self._add_to_table(
                    "System",
                    "←",
                    "error",
                    "N/A",
                    "N/A",
                    "",
                    "Usage: announce_peer <ip> <port> <infohash> [port|implied] [is_ipv6]",
                )
                return
            ip = parts[1]
            port = int(parts[2])
            infohash = bytes.fromhex(parts[3])
            if len(infohash) != 20:
                self._add_to_table("System", "←", "error", "N/A", "N/A", "", "Infohash must be 20 bytes (40 hex chars)")
                return
            port_mode = parts[4].lower() if len(parts) > 4 else "port"
            is_ipv6 = len(parts) > 5 and parts[5].lower() in ("yes", "true", "1", "v6")

            if port_mode == "implied":
                self._send_announce_peer(ip, port, infohash, implied_port=True, is_ipv6=is_ipv6)
            else:
                self._send_announce_peer(ip, port, infohash, implied_port=False, is_ipv6=is_ipv6)

        elif cmd == "ping_all_questionable":
            self._ping_all_questionable()

        elif cmd == "find_all_nodes":
            self._find_nodes_random()

        elif cmd == "status":
            self._show_status()

        elif cmd == "clear":
            self._on_clear()

        elif cmd == "export_log":
            if len(parts) > 1:
                filename = " ".join(parts[1:])
                self._export_to_file(filename)
            else:
                self._add_to_table("System", "←", "error", "N/A", "N/A", "", "Usage: export_log <filename>")

        elif cmd == "toggle_filter":
            if len(parts) > 1:
                filter_val = parts[1].lower()
                self._msg_filter = filter_val if filter_val != "all" else "all"
                self.filter_combo.setCurrentText("All" if filter_val == "all" else filter_val.capitalize())
                self._add_to_table("System", "→", "filter", "N/A", "N/A", "", f"Filter set to: {filter_val}")
            else:
                self._add_to_table(
                    "System",
                    "←",
                    "error",
                    "N/A",
                    "N/A",
                    "",
                    "Usage: toggle_filter <ping|find_node|get_peers|announce_peer|all>",
                )

        else:
            self._add_to_table("System", "←", "error", "N/A", "N/A", "", f"Unknown command: {cmd}")
            self._add_to_table("System", "→", "help", "N/A", "N/A", "", "Type 'help' for available commands.")

    def _send_ping(self, ip: str, port: int, is_ipv6: bool) -> None:
        """Send a ping query to the specified node."""
        r = send_ping(self.dht_node, ip, port, is_ipv6=is_ipv6, create_if_missing=True)
        if r.ok:
            self._add_to_table(
                "Console",
                "→",
                "ping",
                "N/A",
                f"{ip}:{port}",
                self.dht_node.node_id.hex()[:4],
                r.detail,
            )
        else:
            self._add_to_table("System", "←", "error", "N/A", f"{ip}:{port}", "", r.detail)

    def _send_find_node(self, ip: str, port: int, target_id: bytes, is_ipv6: bool) -> None:
        """Send a find_node query."""
        target_hex = binascii.b2a_hex(target_id).decode("ascii")[:16] + "…"
        r = send_find_node(
            self.dht_node,
            ip,
            port,
            target_id=target_id,
            is_ipv6=is_ipv6,
            create_if_missing=True,
        )
        if r.ok:
            self._add_to_table(
                "Console",
                "→",
                "find_node",
                "N/A",
                f"{ip}:{port}",
                self.dht_node.node_id.hex()[:4],
                f"{r.detail} (target={target_hex})",
            )
        else:
            self._add_to_table("System", "←", "error", "N/A", f"{ip}:{port}", "", r.detail)

    def _send_get_peers(self, ip: str, port: int, infohash: bytes, is_ipv6: bool) -> None:
        """Send a get_peers query."""
        r = send_get_peers(
            self.dht_node,
            ip,
            port,
            info_hash=infohash,
            is_ipv6=is_ipv6,
            create_if_missing=True,
        )
        if r.ok:
            self._add_to_table(
                "Console",
                "→",
                "get_peers",
                "N/A",
                f"{ip}:{port}",
                self.dht_node.node_id.hex()[:4],
                r.detail,
            )
        else:
            self._add_to_table("System", "←", "error", "N/A", f"{ip}:{port}", "", r.detail)

    def _send_announce_peer(
        self, ip: str, port: int, infohash: bytes, implied_port: bool = False, is_ipv6: bool = False
    ) -> None:
        """Send an announce_peer query."""
        r = send_announce_peer(
            self.dht_node,
            ip,
            port,
            info_hash=infohash,
            implied_port=implied_port,
            is_ipv6=is_ipv6,
            create_if_missing=True,
        )
        if r.ok:
            self._add_to_table(
                "Console",
                "→",
                "announce_peer",
                "N/A",
                f"{ip}:{port}",
                self.dht_node.node_id.hex()[:4],
                r.detail,
            )
        else:
            self._add_to_table("System", "←", "error", "N/A", f"{ip}:{port}", "", r.detail)

    def _ping_all_questionable(self) -> None:
        """Ping all questionable nodes in the routing table."""
        count = 0
        for table in [self.dht_node.routing_table.v4, self.dht_node.routing_table.v6]:
            for bucket in table.buckets:
                for node in bucket.nodes:
                    if node.status == "questionable":
                        peer_key = (node.endpoint.ip, node.endpoint.port)
                        if peer_key in self.dht_node.peers:
                            self.dht_node.peers[peer_key].ping()
                            count += 1
        self._add_to_table("System", "→", "command", "N/A", "N/A", "", f"Pinged {count} questionable nodes.")

    def _find_nodes_random(self) -> None:
        """Find nodes close to a random target ID."""
        import os

        random_id = os.urandom(20)
        target_hex = binascii.b2a_hex(random_id).decode("ascii")[:20] + "…"
        self._add_to_table("System", "→", "command", "N/A", "N/A", "", f"Searching for nodes close to: {target_hex}")

        n_sent = 0
        for table in [self.dht_node.routing_table.v4, self.dht_node.routing_table.v6]:
            closest = table.get_closest_nodes(random_id, 3)
            for node in closest:
                peer_key = (node.endpoint.ip, node.endpoint.port)
                if peer_key in self.dht_node.peers:
                    self.dht_node.peers[peer_key].find_node(random_id)
                    n_sent += 1

        self._add_to_table("System", "→", "command", "N/A", "N/A", "", f"Sent find_node queries to {n_sent} nodes.")

    def _show_status(self) -> None:
        """Show connection status."""
        self._add_to_table("System", "→", "status", "N/A", "N/A", "", "--- DHT Node Status ---")
        self._add_to_table(
            "System",
            "→",
            "status",
            "N/A",
            "N/A",
            "",
            f"Node ID: {binascii.b2a_hex(self.dht_node.node_id).decode('ascii')}",
        )
        try:
            if self.dht_node.socket_manager is not None:
                ep4 = self.dht_node.socket_manager.local_endpoint_v4()
                if ep4 is not None:
                    self._add_to_table("System", "→", "status", "N/A", "N/A", "", f"IPv4 Socket: {ep4.ip}:{ep4.port}")
                ep6 = self.dht_node.socket_manager.local_endpoint_v6()
                if ep6 is not None:
                    self._add_to_table("System", "→", "status", "N/A", "N/A", "", f"IPv6 Socket: [{ep6.ip}]:{ep6.port}")
        except Exception:
            pass

        total_v4 = sum(len(b.nodes) for b in self.dht_node.routing_table.v4.buckets)
        total_v6 = sum(len(b.nodes) for b in self.dht_node.routing_table.v6.buckets)
        self._add_to_table(
            "System",
            "→",
            "status",
            "N/A",
            "N/A",
            "",
            (f"IPv4 Routing Table: {len(self.dht_node.routing_table.v4.buckets)} buckets, {total_v4} nodes"),
        )
        self._add_to_table(
            "System",
            "→",
            "status",
            "N/A",
            "N/A",
            "",
            (f"IPv6 Routing Table: {len(self.dht_node.routing_table.v6.buckets)} buckets, {total_v6} nodes"),
        )
        self._add_to_table("System", "→", "status", "N/A", "N/A", "", f"Active Peers: {len(self.dht_node.peers)}")

        good_v4 = sum(1 for b in self.dht_node.routing_table.v4.buckets for n in b.nodes if n.status == "good")
        bad_v4 = sum(1 for b in self.dht_node.routing_table.v4.buckets for n in b.nodes if n.status == "bad")
        self._add_to_table("System", "→", "status", "N/A", "N/A", "", f"IPv4 Node Status: {good_v4} good, {bad_v4} bad")

        self._add_to_table("System", "→", "status", "N/A", "N/A", "", f"Traffic Log: {len(self._traffic_log)} entries")

    def _export_to_file(self, filename: str) -> None:
        """Export traffic log to file."""
        with open(filename, "w") as f:
            for entry in self._traffic_log:
                if self._msg_filter != "all" and entry.msg_type != self._msg_filter:
                    continue
                f.write(
                    f"{entry.time_str} {entry.direction} {entry.msg_type} "
                    f"{entry.src}:{entry.dst} {entry.txid} {entry.status}\n"
                )
        self._add_to_table(
            "System", "→", "export", "N/A", "N/A", "", f"Exported {len(self._traffic_log)} entries to {filename}"
        )

    def _add_to_table(
        self, direction: str, msg_type: str, src: str, dst: str, txid: str, status: str, payload: str = ""
    ) -> None:
        """Add an entry to the table view."""
        entry = TrafficEntry(
            timestamp=time.time(),
            direction="→" if direction == "→" else "←",
            msg_type=msg_type,
            src=src,
            dst=dst,
            txid=txid,
            status=status,
            payload=payload,
        )

        self._traffic_log.append(entry)

        # Apply filter
        if self._msg_filter != "all" and msg_type != self._msg_filter:
            return

        # Only add to visible data if filter matches
        if self._msg_filter == "all" or msg_type == self._msg_filter:
            self._traffic_data.append(entry.to_dict())
            self.table_model.set_data(self._traffic_data)

        # Update entry count
        self.entry_label.setText(f"Entries: {len(self._traffic_log)}")

    def on_incoming_message(
        self, msg_type: str, src_ip: str, src_port: int, is_ipv6: bool, txid: str = "", status: str = ""
    ) -> None:
        """Called when an incoming message is received."""
        self._add_to_table("←", msg_type, src_ip, str(src_port), txid=txid, status=status)

    def on_outgoing_message(self, msg_type: str, dst_ip: str, dst_port: int, is_ipv6: bool, txid: str = "") -> None:
        """Called when an outgoing message is sent."""
        self._add_to_table(
            "→", msg_type, dst_ip, str(dst_port), txid if txid else self.dht_node.node_id.hex()[:4], "sent"
        )

    def get_command_history(self) -> list[str]:
        """Get the command history.

        Returns
        -------
        list[str]
            List of previously executed commands.
        """
        return list(self._command_history)

    def on_full_message(self, ip: str, port: int, is_ipv6: bool, size: int, msg_info: dict) -> None:
        """Called when a full message has been parsed with all details."""
        if not self._log_enabled:
            return

        txid = msg_info.get("t", "")
        msg_type = msg_info.get("msg_type", "unknown")
        direction = msg_info.get("direction", "incoming")
        status_info = msg_info.get("status", "")
        payload = msg_info.get("payload_snippet", "")

        if direction == "outgoing":
            self._add_to_table(
                "→", msg_type, ip, str(port), txid=txid, status=f"sent{f' [{payload}]' if payload else ''}"
            )
        else:
            if status_info == "response":
                icon = "✓"
            elif status_info == "error":
                icon = "✗"
            else:
                icon = ""

            payload_str = f" [{payload}]" if payload else ""
            self._add_to_table("←", msg_type, ip, str(port), txid=txid, status=f"{icon} [{status_info}{payload_str}]")

    def on_wire_message(
        self,
        direction: str,
        ip: str,
        port: int,
        is_ipv6: bool,
        size: int,
        hex_str: str,
        decode_status: str,
        decode_repr: str,
        txid_hex: str = "",
        method: str = "",
        note: str = "",
    ) -> None:
        """Handle wire-level datagram log from DHTNode.

        Wire messages are displayed with a distinct yellow/amber background
        so they stand out from regular RPC messages.

        Parameters
        ----------
        direction : str
            "IN" for incoming, "OUT" for outgoing.
        ip : str
            IP address of the peer.
        port : int
            Port of the peer.
        is_ipv6 : bool
            Whether this is an IPv6 address.
        size : int
            Datagram size in bytes.
        hex_str : str
            Hex dump of the first 80 bytes of the raw datagram.
        decode_status : str
            "OK" on successful decode, "ERROR: <message>" on failure.
        decode_repr : str
            Full repr() of the decoded BEncode structure.
        txid_hex : str
            Transaction ID hex string.
        method : str
            Query method (ping, find_node, etc.) or response type.
        note : str
            Optional free-form annotation.
        """
        if not self._log_enabled:
            return

        from PyQt6.QtCore import QTimer

        # Marshal to main thread using QTimer
        def _add():
            self.table_model.add_wire_entry(
                direction=direction,
                ip=ip,
                port=port,
                is_ipv6=is_ipv6,
                size=size,
                hex_str=hex_str,
                decode_status=decode_status,
                decode_repr=decode_repr,
                txid_hex=txid_hex,
                method=method,
                note=note,
            )

        QTimer.singleShot(0, _add)
