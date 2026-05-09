"""
Routing Table widget for the DHT Network Inspector.

Displays K-buckets and their nodes in a tree view with filtering and
controls for DHT maintenance operations.
"""

from __future__ import annotations

import binascii

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from dhtrack.gui.models.routing_model import RoutingTableModel


class RoutingTableWidget(QWidget):
    """Widget displaying the DHT routing table in detail."""

    def __init__(self, dht_node: object, parent: QWidget | None = None):
        super().__init__(parent)
        self.dht_node = dht_node
        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self) -> None:
        """Build the routing table UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Title
        title = QLabel("DHT Routing Table")
        title.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        # Summary strip (theme: QWidget[role="toolbar_strip"])
        summary_frame = QWidget()
        summary_frame.setProperty("role", "toolbar_strip")
        summary_layout = QGridLayout(summary_frame)
        summary_layout.setSpacing(4)

        self.v4_bucket_label = QLabel("IPv4 Buckets: 0")
        self.v4_node_label = QLabel("IPv4 Nodes: 0")
        self.v6_bucket_label = QLabel("IPv6 Buckets: 0")
        self.v6_node_label = QLabel("IPv6 Nodes: 0")
        self.v4_depth_label = QLabel("IPv4 Depth: 0")
        self.v6_depth_label = QLabel("IPv6 Depth: 0")
        self.v4_active_label = QLabel("IPv4 Active/Inactive: 0 / 0")
        self.v6_active_label = QLabel("IPv6 Active/Inactive: 0 / 0")
        self.v4_range_label = QLabel("IPv4 Range: —")
        self.v6_range_label = QLabel("IPv6 Range: —")

        summary_layout.addWidget(self.v4_bucket_label, 0, 0)
        summary_layout.addWidget(self.v4_node_label, 0, 1)
        summary_layout.addWidget(self.v6_bucket_label, 0, 2)
        summary_layout.addWidget(self.v6_node_label, 0, 3)
        summary_layout.addWidget(self.v4_depth_label, 1, 0)
        summary_layout.addWidget(self.v4_active_label, 1, 1)
        summary_layout.addWidget(self.v6_depth_label, 1, 2)
        summary_layout.addWidget(self.v6_active_label, 1, 3)
        summary_layout.addWidget(self.v4_range_label, 2, 0, 1, 2)
        summary_layout.addWidget(self.v6_range_label, 2, 2, 1, 2)

        layout.addWidget(summary_frame)

        # Tab widget for IPv4 / IPv6
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # IPv4 tab
        ipv4_tab = QWidget()
        ipv4_layout = QVBoxLayout(ipv4_tab)
        ipv4_layout.setContentsMargins(0, 0, 0, 0)

        # IPv4 routing table tree view
        self.ipv4_tree = QTreeView()
        self.ipv4_tree.setHeaderHidden(True)
        self.ipv4_tree.setIndentation(16)
        self.ipv4_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ipv4_model = RoutingTableModel()
        self.ipv4_tree.setModel(self.ipv4_model)
        self.ipv4_tree.expandAll()
        ipv4_layout.addWidget(self.ipv4_tree)

        # IPv4 details panel
        self.ipv4_details = QTextEdit()
        self.ipv4_details.setReadOnly(True)
        self.ipv4_details.setMaximumHeight(150)
        self.ipv4_details.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; "
            "font-family: monospace; border: 1px solid #313244; }"
        )
        ipv4_layout.addWidget(self.ipv4_details)

        self.tab_widget.addTab(ipv4_tab, "IPv4 Routing Table")

        # IPv6 tab
        ipv6_tab = QWidget()
        ipv6_layout = QVBoxLayout(ipv6_tab)
        ipv6_layout.setContentsMargins(0, 0, 0, 0)

        self.ipv6_tree = QTreeView()
        self.ipv6_tree.setHeaderHidden(True)
        self.ipv6_tree.setIndentation(16)
        self.ipv6_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ipv6_model = RoutingTableModel()
        self.ipv6_tree.setModel(self.ipv6_model)
        self.ipv6_tree.expandAll()
        ipv6_layout.addWidget(self.ipv6_tree)

        self.ipv6_details = QTextEdit()
        self.ipv6_details.setReadOnly(True)
        self.ipv6_details.setMaximumHeight(150)
        self.ipv6_details.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; "
            "font-family: monospace; border: 1px solid #313244; }"
        )
        ipv6_layout.addWidget(self.ipv6_details)

        self.tab_widget.addTab(ipv6_tab, "IPv6 Routing Table")

        # Control buttons
        control_layout = QHBoxLayout()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._on_refresh)
        control_layout.addWidget(self.refresh_btn)

        self.v4_ping_btn = QPushButton("Ping IPv4 Questionable")
        self.v4_ping_btn.clicked.connect(self._ping_questionable_v4)
        control_layout.addWidget(self.v4_ping_btn)

        self.v6_ping_btn = QPushButton("Ping IPv6 Questionable")
        self.v6_ping_btn.clicked.connect(self._ping_questionable_v6)
        control_layout.addWidget(self.v6_ping_btn)

        self.v4_search_btn = QPushButton("Search IPv4 (Random ID)")
        self.v4_search_btn.clicked.connect(self._search_random_v4)
        control_layout.addWidget(self.v4_search_btn)

        self.v6_search_btn = QPushButton("Search IPv6 (Random ID)")
        self.v6_search_btn.clicked.connect(self._search_random_v6)
        control_layout.addWidget(self.v6_search_btn)

        layout.addLayout(control_layout)

        # Add status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #a6adc8;")
        layout.addWidget(self.status_label)

        # Connect selection signals
        self.ipv4_tree.selectionModel().selectionChanged.connect(self._on_ipv4_selection_changed)
        self.ipv6_tree.selectionModel().selectionChanged.connect(self._on_ipv6_selection_changed)

    def _setup_timer(self) -> None:
        """Setup the refresh timer."""
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start(2000)

    def _on_timer(self) -> None:
        """Periodic update."""
        self._update_summary()
        self._refresh_tables()

    def _update_summary(self) -> None:
        """Update the summary bar."""
        if not self.dht_node:
            return
        try:
            rt_v4 = self.dht_node.routing_table.v4
            rt_v6 = self.dht_node.routing_table.v6

            total_v4 = sum(len(b.nodes) for b in rt_v4.buckets)
            total_v6 = sum(len(b.nodes) for b in rt_v6.buckets)

            def _depth(rt) -> int:
                # "Depth" = highest non-empty bucket index + 1
                for i in range(len(rt.buckets) - 1, -1, -1):
                    if getattr(rt.buckets[i], "nodes", None):
                        if len(rt.buckets[i].nodes) > 0:
                            return i + 1
                return 0

            def _active_inactive(rt) -> tuple[int, int]:
                active = 0
                inactive = 0
                for b in rt.buckets:
                    for n in b.nodes:
                        status = getattr(n, "status", "good")
                        if str(status).lower() == "good":
                            active += 1
                        else:
                            inactive += 1
                return active, inactive

            def _range(rt) -> str:
                if not rt.buckets:
                    return "—"
                b0 = rt.buckets[0]
                mn = getattr(b0, "min_id", b"")
                mx = getattr(b0, "max_id", b"")
                if isinstance(mn, (bytes, bytearray)) and isinstance(mx, (bytes, bytearray)) and mn and mx:
                    mn_hex = binascii.b2a_hex(bytes(mn)[:4]).decode("ascii") + "···"
                    mx_hex = binascii.b2a_hex(bytes(mx)[:4]).decode("ascii") + "···"
                    return f"{mn_hex} ← {mx_hex}"
                return "—"

            self.v4_bucket_label.setText(f"IPv4 Buckets: {len(rt_v4.buckets)}")
            self.v4_node_label.setText(f"IPv4 Nodes: {total_v4}")
            self.v6_bucket_label.setText(f"IPv6 Buckets: {len(rt_v6.buckets)}")
            self.v6_node_label.setText(f"IPv6 Nodes: {total_v6}")

            d4 = _depth(rt_v4)
            d6 = _depth(rt_v6)
            a4, i4 = _active_inactive(rt_v4)
            a6, i6 = _active_inactive(rt_v6)
            self.v4_depth_label.setText(f"IPv4 Depth: {d4}")
            self.v6_depth_label.setText(f"IPv6 Depth: {d6}")
            self.v4_active_label.setText(f"IPv4 Active/Inactive: {a4} / {i4}")
            self.v6_active_label.setText(f"IPv6 Active/Inactive: {a6} / {i6}")
            self.v4_range_label.setText(f"IPv4 Range: {_range(rt_v4)}")
            self.v6_range_label.setText(f"IPv6 Range: {_range(rt_v6)}")
        except Exception:
            pass

    def _on_refresh(self) -> None:
        """Refresh the view."""
        self._refresh_tables()
        self.status_label.setText("Refreshed")

    def _refresh_tables(self) -> None:
        """Refresh both IPv4 and IPv6 routing tables."""
        if not self.dht_node:
            return
        try:
            self.ipv4_model.refresh(self.dht_node.routing_table.v4)
            self.ipv6_model.refresh(self.dht_node.routing_table.v6)

            # layoutChanged collapses QTreeView rows; re-expand so buckets stay open
            self.ipv4_tree.expandAll()
            self.ipv6_tree.expandAll()

            self._update_details(0)
            self._update_details(1)

            self.ipv4_tree.resizeColumnToContents(0)
        except Exception:
            pass

    def _on_ipv4_selection_changed(self) -> None:
        """Handle selection change in IPv4 tree."""
        self._update_details(0)

    def _on_ipv6_selection_changed(self) -> None:
        """Handle selection change in IPv6 tree."""
        self._update_details(1)

    def _update_details(self, tab_idx: int) -> None:
        """Update the details panel for the selected item."""
        if not self.dht_node:
            return
        try:
            from dhtrack.gui.models.routing_model import _BucketItem, _NodeItem

            if tab_idx == 0:
                tree = self.ipv4_tree
                details = self.ipv4_details
            else:
                tree = self.ipv6_tree
                details = self.ipv6_details

            selection = tree.selectionModel().selection()
            if not selection.indexes():
                details.setPlainText("")
                return

            idx = selection.indexes()[0]
            item = idx.internalPointer()

            if not item:
                details.setPlainText("")
                return

            # Build details text - use isinstance to check type
            if isinstance(item, _BucketItem):
                # It's a bucket
                text = f"Bucket Index: {item.index}\n"
                text += f"Total Nodes: {len(item.children)}\n"
                good = sum(1 for c in item.children if isinstance(c, _NodeItem) and c.status == "good")
                questionable = sum(1 for c in item.children if isinstance(c, _NodeItem) and c.status == "questionable")
                bad = sum(1 for c in item.children if isinstance(c, _NodeItem) and c.status == "bad")
                text += f"Good: {good}, Questionable: {questionable}, Bad: {bad}\n\n"
                text += "Nodes:\n"
                for child in item.children:
                    if isinstance(child, _NodeItem) and child.node_id:
                        node_id_hex = binascii.b2a_hex(child.node_id).decode("ascii")[:20] + "…"
                        text += f"  {node_id_hex}  {child.ip}:{child.port}  [{child.status}]  "
                        text += f"RPCs: {child.rpc_counter}  Last: {child.last_contacted_str()}\n"
            elif isinstance(item, _NodeItem):
                # It's a node
                text = "Node Details:\n"
                text += f"  Node ID:  {binascii.b2a_hex(item.node_id).decode('ascii') if item.node_id else 'UNKNOWN'}\n"
                text += f"  IP:Port:  {item.ip}:{item.port}\n"
                text += f"  Status:   {item.status}\n"
                text += f"  IPv6:     {'Yes' if item.is_ipv6 else 'No'}\n"
                text += f"  Last:     {item.last_contacted_str()}\n"
                text += f"  RPCs:     {item.rpc_counter}\n"
                text += f"  Failures: {item.failure_count}\n"
            else:
                text = "Unknown item type"

            details.setPlainText(text)
        except Exception:
            pass

    def _ping_questionable_v4(self) -> None:
        """Ping all questionable IPv4 nodes."""
        count = 0
        for bucket in self.dht_node.routing_table.v4.buckets:
            for node in bucket.nodes:
                if node.status == "questionable":
                    peer_key = (node.endpoint.ip, node.endpoint.port)
                    if peer_key in self.dht_node.peers:
                        self.dht_node.peers[peer_key].ping()
                        count += 1
        self.status_label.setText(f"Pinged {count} IPv4 questionable nodes")

    def _ping_questionable_v6(self) -> None:
        """Ping all questionable IPv6 nodes."""
        count = 0
        for bucket in self.dht_node.routing_table.v6.buckets:
            for node in bucket.nodes:
                if node.status == "questionable":
                    peer_key = (node.endpoint.ip, node.endpoint.port)
                    if peer_key in self.dht_node.peers:
                        self.dht_node.peers[peer_key].ping()
                        count += 1
        self.status_label.setText(f"Pinged {count} IPv6 questionable nodes")

    def _search_random_v4(self) -> None:
        """Send find_node for a random target to IPv4 closest nodes."""
        import os

        random_id = os.urandom(20)
        self.status_label.setText("Sending find_node to IPv4 closest nodes...")
        closest = self.dht_node.routing_table.v4.get_closest_nodes(random_id, 3)
        for node in closest:
            peer_key = (node.endpoint.ip, node.endpoint.port)
            if peer_key in self.dht_node.peers:
                self.dht_node.peers[peer_key].find_node(random_id)
        self.status_label.setText(f"Searched {len(closest)} IPv4 nodes")

    def _search_random_v6(self) -> None:
        """Send find_node for a random target to IPv6 closest nodes."""
        import os

        random_id = os.urandom(20)
        self.status_label.setText("Sending find_node to IPv6 closest nodes...")
        closest = self.dht_node.routing_table.v6.get_closest_nodes(random_id, 3)
        for node in closest:
            peer_key = (node.endpoint.ip, node.endpoint.port)
            if peer_key in self.dht_node.peers:
                self.dht_node.peers[peer_key].find_node(random_id)
        self.status_label.setText(f"Searched {len(closest)} IPv6 nodes")
