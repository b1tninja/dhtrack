"""
Peer Store widget for the DHT Network Inspector.

Displays and manages DHT routing table nodes (both IPv4 and IPv6) with
filtering, search, and status visualization. Shows discovered peer nodes
from the Kademlia routing tables.
"""

from __future__ import annotations

import binascii
import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from dhtrack.gui.models.peer_model import RoutingTableModel

try:
    from dhtrack.peerid import PeerIdParser
except ImportError:
    PeerIdParser = None


class PeerStoreWidget(QWidget):
    """Widget displaying and managing DHT routing table nodes."""

    def __init__(self, dht_node: object, parent: QWidget | None = None):
        super().__init__(parent)
        self.dht_node = dht_node
        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self) -> None:
        """Build the peer store UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Title
        title = QLabel("DHT Routing Table")
        title.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        # Summary strip
        summary_frame = QWidget()
        summary_frame.setProperty("role", "toolbar_strip")
        summary_layout = QGridLayout(summary_frame)
        summary_layout.setSpacing(4)

        self.total_peers_label = QLabel("Nodes: 0 (v4=0, v6=0)")
        self.infohashes_label = QLabel("Good: 0")
        self.seeds_label = QLabel("Questionable: 0")
        self.ips_label = QLabel("Bad: 0")

        summary_layout.addWidget(self.total_peers_label, 0, 0)
        summary_layout.addWidget(self.infohashes_label, 0, 1)
        summary_layout.addWidget(self.seeds_label, 0, 2)
        summary_layout.addWidget(self.ips_label, 0, 3)

        layout.addWidget(summary_frame)

        # Filter row
        filter_frame = QWidget()
        filter_frame.setProperty("role", "toolbar_strip")
        filter_layout = QHBoxLayout(filter_frame)

        filter_layout.addWidget(QLabel("Search (Node ID or IP):"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter node ID hex or IP...")
        self.search_input.returnPressed.connect(self._refresh)
        filter_layout.addWidget(self.search_input)

        # Status filter
        filter_layout.addSpacing(16)
        filter_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Good", "Questionable", "Bad"])
        self.status_filter.currentIndexChanged.connect(self._refresh)
        filter_layout.addWidget(self.status_filter)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_filter)
        clear_btn.setStyleSheet("background-color: #313244; color: #cdd6f4;")
        filter_layout.addWidget(clear_btn)

        filter_layout.addStretch()

        layout.addWidget(filter_frame)

        # Table view
        self.table_view = QTableView()
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table_view.setSortingEnabled(True)
        self.table_model = RoutingTableModel()
        self.table_view.setModel(self.table_model)

        # Resize columns
        header = self.table_view.horizontalHeader()
        header.resizeSection(0, 280)
        header.resizeSection(1, 170)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(self.table_view)

        # Details (no nested frame chrome)
        details_wrap = QWidget()
        details_layout = QVBoxLayout(details_wrap)
        details_layout.setContentsMargins(0, 4, 0, 0)
        details_layout.setSpacing(4)

        details_title = QLabel("Node Details:")
        details_title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        details_layout.addWidget(details_title)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(120)
        self.details_text.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; font-family: monospace; border: none; }"
        )
        details_layout.addWidget(self.details_text)

        layout.addWidget(details_wrap)

        # Control buttons
        control_layout = QHBoxLayout()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh)
        control_layout.addWidget(refresh_btn)

        control_layout.addStretch()

        layout.addLayout(control_layout)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #a6adc8;")
        layout.addWidget(self.status_label)

        # Connect selection changed signal
        self.table_view.selectionModel().selectionChanged.connect(self._on_selection_changed)

        # Enable context menu on the table view
        self.table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self._on_context_menu)

    def _setup_timer(self) -> None:
        """Setup the refresh timer."""
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start(3000)

    def _on_timer(self) -> None:
        """Periodic update - refresh both summary and table."""
        self._update_summary()
        self._refresh()

    def _update_summary(self) -> None:
        """Update the summary bar."""
        try:
            v4_nodes = self._get_all_routing_nodes()
            v4_count = len(v4_nodes)
            v6_nodes = self._get_ipv6_routing_nodes()
            v6_count = len(v6_nodes)
            total_nodes = v4_count + v6_count
            good = sum(1 for n in v4_nodes + v6_nodes if n.get("status") == "good")
            questionable = sum(1 for n in v4_nodes + v6_nodes if n.get("status") == "questionable")
            bad = sum(1 for n in v4_nodes + v6_nodes if n.get("status") == "bad")

            self.total_peers_label.setText(f"Nodes: {total_nodes} (v4={v4_count}, v6={v6_count})")
            self.infohashes_label.setText(f"Good: {good}")
            self.seeds_label.setText(f"Questionable: {questionable}")
            self.ips_label.setText(f"Bad: {bad}")
        except AttributeError:
            self.total_peers_label.setText("Nodes: 0 (v4=0, v6=0)")
            self.infohashes_label.setText("Good: 0")
            self.seeds_label.setText("Questionable: 0")
            self.ips_label.setText("Bad: 0")

    def _get_all_routing_nodes(self) -> list:
        """Get all routing table nodes (IPv4)."""
        try:
            rt = self.dht_node.routing_table.v4
            nodes = []
            for bucket in rt.buckets:
                for node in bucket.nodes:
                    nodes.append(
                        {
                            "node_id": node.node_id,
                            "ip": node.endpoint.ip,
                            "port": node.endpoint.port,
                            "is_ipv6": node.endpoint.is_ipv6,
                            "status": node.status,
                            "last_contacted": node.last_contacted,
                            "rpc_counter": node.rpc_counter,
                            "failure_count": node.failure_count,
                        }
                    )
            return nodes
        except AttributeError:
            return []

    def _get_ipv6_routing_nodes(self) -> list:
        """Get IPv6 routing table nodes."""
        try:
            rt = self.dht_node.routing_table.v6
            nodes = []
            for bucket in rt.buckets:
                for node in bucket.nodes:
                    nodes.append(
                        {
                            "node_id": node.node_id,
                            "ip": node.endpoint.ip,
                            "port": node.endpoint.port,
                            "is_ipv6": node.endpoint.is_ipv6,
                            "status": node.status,
                            "last_contacted": node.last_contacted,
                            "rpc_counter": node.rpc_counter,
                            "failure_count": node.failure_count,
                        }
                    )
            return nodes
        except AttributeError:
            return []

    def _on_selection_changed(self) -> None:
        """Handle row selection."""
        selection = self.table_view.selectionModel().selection()
        if not selection.indexes():
            return

        idx = selection.indexes()[0]
        row = idx.row()
        nodes = self._get_filtered_nodes()
        if row < 0 or row >= len(nodes):
            return

        node = nodes[row]
        self.details_text.setPlainText(self._build_node_details(node))

    def _on_context_menu(self, position: object) -> None:
        """Show context menu on right-click."""
        selection = self.table_view.selectionModel().selection()
        if not selection.indexes():
            return

        idx = selection.indexes()[0]
        row = idx.row()
        nodes = self._get_filtered_nodes()
        if row < 0 or row >= len(nodes):
            self.status_label.setText("No node selected")
            return

        node = nodes[row]
        menu = self._build_context_menu(node)
        if menu is not None:
            menu.exec(self.table_view.viewport().mapToGlobal(position))

    def _build_context_menu(self, node: dict) -> object:
        """Build the context menu for a node.

        Parameters
        ----------
        node : dict
            Node data dictionary.

        Returns
        -------
        object or None
            The context menu, or None if node is invalid.
        """
        node_id = node.get("node_id")
        if not node_id:
            return None

        ip = node.get("ip", "")
        port = node.get("port", 0)
        if not ip or not port:
            self.status_label.setText("Invalid node IP/port")
            return None

        from PyQt6.QtWidgets import QMenu

        menu = QMenu(self.table_view)

        # Ping action
        menu.addAction("Ping", self._make_action(node, self._send_ping))

        # Find Node action
        menu.addAction("Find Node (random target)", self._make_action(node, self._send_find_node))

        # Get Peers action - requires infohash input
        menu.addAction("Get Peers...", self._make_action(node, self._send_get_peers))

        # Get Value action
        menu.addAction("Get Value (info_hash)", self._make_action(node, self._send_get_value))

        return menu

    def _make_action(self, node: dict, handler: callable) -> callable:
        """Create a bound action handler.

        Parameters
        ----------
        node : dict
            Node data dictionary.
        handler : callable
            Handler function.

        Returns
        -------
        callable
            Bound handler.
        """

        def wrapper():
            try:
                handler(node)
            except Exception as e:
                self.status_label.setText(f"Error: {e}")

        return wrapper

    def _send_ping(self, node: dict) -> None:
        """Send a PING query to a node.

        Parameters
        ----------
        node : dict
            Node data dictionary.
        """
        try:
            ip = node["ip"]
            port = node["port"]
            is_ipv6 = node.get("is_ipv6", False)
            node_id = node["node_id"]

            import binascii as _ba

            peer = self.dht_node.peers.get((ip, port)) or self.dht_node.add_peer(node_id, ip, port, is_ipv6=is_ipv6)
            if peer is None:
                self.status_label.setText("Cannot ping: failed to add peer")
                return
            peer.ping()

            self.status_label.setText(
                f"Sent PING to {ip}:{port} (node_id={_ba.b2a_hex(node_id).decode('ascii')[:16]}...)"
            )

        except Exception as e:
            self.status_label.setText(f"Ping failed: {e}")

    def _send_find_node(self, node: dict) -> None:
        """Send a FIND_NODE query with a random target to a node.

        Parameters
        ----------
        node : dict
            Node data dictionary.
        """
        try:
            ip = node["ip"]
            port = node["port"]
            is_ipv6 = node.get("is_ipv6", False)

            import os

            target_id = os.urandom(20)

            peer = self.dht_node.peers.get((ip, port)) or self.dht_node.add_peer(None, ip, port, is_ipv6=is_ipv6)
            if peer is None:
                self.status_label.setText("Cannot find_node: failed to add peer")
                return
            peer.find_node(target_id)

            target_hex = binascii.b2a_hex(target_id).decode("ascii")[:16]
            self.status_label.setText(f"Sent FIND_NODE (target={target_hex}...) to {ip}:{port}")

        except Exception as e:
            self.status_label.setText(f"Find Node failed: {e}")

    def _send_get_peers(self, node: dict) -> None:
        """Send a GET_PEERS query to a node (requires infohash input).

        Parameters
        ----------
        node : dict
            Node data dictionary.
        """
        try:
            from PyQt6.QtWidgets import QInputDialog

            info_hash_hex, ok = QInputDialog.getText(
                self,
                "Get Peers",
                "Enter info_hash (hex, 40 chars):\n(SHA-1 hash of the info dictionary, found in .torrent files)",
            )

            if not ok or not info_hash_hex:
                self.status_label.setText("Get Peers cancelled")
                return

            # Validate infohash length
            try:
                binascii.b2a_hex(binascii.unhexlify(info_hash_hex))
            except Exception:
                self.status_label.setText("Invalid info_hash format")
                return

            ip = node["ip"]
            port = node["port"]
            is_ipv6 = node.get("is_ipv6", False)
            peer = self.dht_node.peers.get((ip, port)) or self.dht_node.add_peer(None, ip, port, is_ipv6=is_ipv6)
            if peer is None:
                self.status_label.setText("Cannot get_peers: failed to add peer")
                return
            peer.get_peers(binascii.unhexlify(info_hash_hex))

            self.status_label.setText(f"Sent GET_PEERS (infohash={info_hash_hex[:16]}...) to {ip}:{port}")

        except Exception as e:
            self.status_label.setText(f"Get Peers failed: {e}")

    def _send_get_value(self, node: dict) -> None:
        """Send a GET_VALUE query to a node (requires key input).

        Parameters
        ----------
        node : dict
            Node data dictionary.
        """
        try:
            from PyQt6.QtWidgets import QInputDialog

            key_hex, ok = QInputDialog.getText(
                self, "Get Value", "Enter key (hex):\nIn BEP 4/53, this is typically the infohash of a torrent."
            )

            if not ok or not key_hex:
                self.status_label.setText("Get Value cancelled")
                return

            try:
                key = binascii.b2a_hex(binascii.unhexlify(key_hex))
            except Exception:
                self.status_label.setText("Invalid key format")
                return

            ip = node["ip"]
            port = node["port"]
            is_ipv6 = node.get("is_ipv6", False)
            peer = self.dht_node.peers.get((ip, port)) or self.dht_node.add_peer(None, ip, port, is_ipv6=is_ipv6)
            if peer is None:
                self.status_label.setText("Cannot get_value: failed to add peer")
                return
            peer.query("get_value", {"key": key})

            self.status_label.setText(f"SENT GET_VALUE (key={key_hex[:16]}...) to {ip}:{port}")
        except Exception as e:
            self.status_label.setText(f"Get Value failed: {e}")

    def _get_filtered_nodes(self) -> list:
        """Get filtered node data from both routing tables."""
        v4_nodes = self._get_all_routing_nodes()
        v6_nodes = self._get_ipv6_routing_nodes()
        all_nodes = v4_nodes + v6_nodes

        search_text = self.search_input.text().lower()
        status_filter = self.status_filter.currentText()

        if not search_text and status_filter == "All":
            return all_nodes

        filtered = []
        for node in all_nodes:
            # Apply status filter
            if status_filter != "All":
                node_status = node.get("status", "good")
                if status_filter.lower() != node_status:
                    continue

            # Apply search filter
            if search_text:
                node_hex = binascii.b2a_hex(node.get("node_id", b"")).decode("ascii")
                ip = node.get("ip", "")
                if search_text not in node_hex.lower() and search_text not in ip.lower():
                    continue

            filtered.append(node)

        return filtered

    def _build_node_details(self, node: dict) -> str:
        """Build detailed node info display.

        Parameters
        ----------
        node : dict
            Node data dictionary.

        Returns
        -------
        str
            Formatted node details string.
        """
        node_id = node.get("node_id", b"")
        node_id_hex = binascii.b2a_hex(node_id).decode("ascii") if node_id else "UNKNOWN"
        ip = node.get("ip", "")
        port = node.get("port", 0)
        is_ipv6 = node.get("is_ipv6", False)
        status = node.get("status", "good")
        last_contacted = node.get("last_contacted", 0)
        rpc_counter = node.get("rpc_counter", 0)
        failure_count = node.get("failure_count", 0)

        # Client identification from node ID
        client_info = None
        if node_id and len(node_id) == 20:
            if PeerIdParser is not None:
                client_info = PeerIdParser.parse(node_id)

        text = f"Node ID:      {node_id_hex}\n"
        text += f"IP:Port:      {ip}:{port}\n"
        text += f"Address Family: {'IPv6' if is_ipv6 else 'IPv4'}\n"
        text += f"Status:       {status}\n"
        text += f"RPC Count:    {rpc_counter}\n"
        text += f"Failures:     {failure_count}\n"

        if last_contacted:
            ago = time.time() - last_contacted
            if ago < 60:
                text += f"Last Contact: {ago:.0f} seconds ago\n"
            elif ago < 3600:
                text += f"Last Contact: {ago / 60:.1f} minutes ago\n"
            else:
                text += f"Last Contact: {ago / 3600:.2f} hours ago\n"
        else:
            text += "Last Contact: Never\n"

        if client_info:
            version_str = ".".join(str(v) for v in client_info.version) if client_info.version else "N/A"
            text += f"Client:       {client_info.client_name} ({client_info.client_code})\n"
            text += f"Version:      {version_str}\n"
            text += f"Format:       {client_info.peer_id_format}\n"
            if client_info.comment:
                text += f"Comment:      {client_info.comment}\n"
            if client_info.nickname:
                text += f"Nickname:     {client_info.nickname}\n"
        else:
            text += "Client:       Unknown\n"

        return text

    def _clear_filter(self) -> None:
        """Clear all filters."""
        self.search_input.clear()
        self.status_filter.setCurrentIndex(0)
        self._refresh()

    def _refresh(self) -> None:
        """Refresh the entire view."""
        nodes = self._get_filtered_nodes()

        # Add search info to each node for display purposes
        search_text = self.search_input.text().lower()
        for node in nodes:
            node["_search_text"] = search_text

        self.table_model.set_nodes(nodes)
        self._update_summary()
        self.status_label.setText(f"Showing {len(nodes)} nodes")

    def _export_csv(self) -> None:
        """Export node data to CSV."""
        path, _ = QFileDialog.getSaveFileName(self, "Export Nodes", "", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return

        try:
            all_nodes = self._get_all_routing_nodes() + self._get_ipv6_routing_nodes()
            with open(path, "w") as f:
                f.write("Node ID,IP,Port,IPv6,Status,Last Seen,RPCs\n")
                for node in all_nodes:
                    node_id_hex = binascii.b2a_hex(node["node_id"]).decode("ascii") if node.get("node_id") else ""
                    ip = node.get("ip", "")
                    port = node.get("port", 0)
                    ipv6 = "Yes" if node.get("is_ipv6") else "No"
                    status = node.get("status", "good")
                    if node.get("last_contacted"):
                        last_seen = time.strftime(
                            "%Y-%m-%d %H:%M:%S",
                            time.localtime(node["last_contacted"]),
                        )
                    else:
                        last_seen = "Never"
                    rpcs = node.get("rpc_counter", 0)
                    f.write(f"{node_id_hex},{ip},{port},{ipv6},{status},{last_seen},{rpcs}\n")
            self.status_label.setText(f"Exported to {path}")
        except Exception as e:
            self.status_label.setText(f"Export failed: {e}")
