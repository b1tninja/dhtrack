"""
Network Overview Dashboard for the DHT Network Inspector.

Displays key metrics about the DHT network status including node ID,
peer counts, bucket statistics, and network activity.
"""

from __future__ import annotations

import binascii
import time
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

import dhtrack.dht as dht_mod
from dhtrack.gui.widgets.stat_card import StatCard

if TYPE_CHECKING:
    from dhtrack.dht import DHTNode


class NetworkOverviewWidget(QWidget):
    """Dashboard widget showing DHT network statistics."""

    def __init__(self, dht_node: DHTNode, parent: QWidget | None = None):
        super().__init__(parent)
        self.dht_node = dht_node
        self._start_time = time.time()
        self._query_count = 0
        self._response_count = 0

        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self) -> None:
        """Build the dashboard UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(8)

        # Title
        title = QLabel("DHT Network Overview")
        title.setProperty("role", "title")
        main_layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        scroll_inner = QWidget()
        scroll_inner.setProperty("role", "page_header")
        inner_layout = QVBoxLayout(scroll_inner)
        inner_layout.setContentsMargins(0, 0, 8, 0)
        inner_layout.setSpacing(8)

        # Summary cards row 1
        cards_layout = QGridLayout()
        cards_layout.setSpacing(6)

        # Create stat cards
        self.my_node_card = StatCard("My Node ID", binascii.b2a_hex(self.dht_node.node_id).decode("ascii")[:16] + "…")
        self.ipv4_bucket_card = StatCard("IPv4 Buckets", "0")
        self.ipv4_nodes_card = StatCard("IPv4 Nodes", "0")
        self.ipv6_bucket_card = StatCard("IPv6 Buckets", "0")
        self.ipv6_nodes_card = StatCard("IPv6 Nodes", "0")

        cards_layout.addWidget(self.my_node_card, 0, 0)
        cards_layout.addWidget(self.ipv4_bucket_card, 0, 1)
        cards_layout.addWidget(self.ipv4_nodes_card, 0, 2)
        cards_layout.addWidget(self.ipv6_bucket_card, 1, 0)
        cards_layout.addWidget(self.ipv6_nodes_card, 1, 1)

        inner_layout.addLayout(cards_layout)

        # Summary cards row 2
        self.active_peers_card = StatCard("Active Peers", "0")
        self.stored_peers_card = StatCard("Stored Peers", "0")
        self.queries_sent_card = StatCard("Queries Sent", "0")
        self.responses_card = StatCard("Responses", "0")
        self.self_propagated_card = StatCard("Self-Propagated", "0")
        self.uptime_card = StatCard("Uptime", "0s")
        self.private_mode_card = StatCard("Private Mode", "No")

        cards2_layout = QGridLayout()
        cards2_layout.setSpacing(6)
        cards2_layout.addWidget(self.active_peers_card, 0, 0)
        cards2_layout.addWidget(self.stored_peers_card, 0, 1)
        cards2_layout.addWidget(self.queries_sent_card, 0, 2)
        cards2_layout.addWidget(self.responses_card, 1, 0)
        cards2_layout.addWidget(self.self_propagated_card, 1, 1)
        cards2_layout.addWidget(self.uptime_card, 1, 2)
        cards2_layout.addWidget(self.private_mode_card, 2, 0)

        inner_layout.addLayout(cards2_layout)

        self.gp_scrape_card = StatCard("GP scrape (qps / burst / max)", "—")
        self.scrape_ih_card = StatCard("Scrape IH with state", "0")
        self.scrape_queue_card = StatCard("Scrape peer backlog", "0")
        self.krpc_queue_card = StatCard("kRPC queued (approx)", "0")
        self.node_totals_card = StatCard("Node RPC totals (s/r/to)", "—")

        cards3_layout = QGridLayout()
        cards3_layout.setSpacing(6)
        cards3_layout.addWidget(self.gp_scrape_card, 0, 0)
        cards3_layout.addWidget(self.scrape_ih_card, 0, 1)
        cards3_layout.addWidget(self.scrape_queue_card, 0, 2)
        cards3_layout.addWidget(self.krpc_queue_card, 1, 0)
        cards3_layout.addWidget(self.node_totals_card, 1, 1)
        inner_layout.addLayout(cards3_layout)

        inner_layout.addSpacing(4)

        # Socket info — flat group (no framed box chrome)
        socket_group = QGroupBox("Socket Information")
        socket_group.setFlat(True)
        socket_group.setStyleSheet("color: #89b4fa; font-weight: bold;")
        socket_layout = QGridLayout()

        self.ipv4_socket_label = QLabel("IPv4: Not bound")
        self.ipv6_socket_label = QLabel("IPv6: Not bound")
        self.bind_addr_label = QLabel("Bind: 0.0.0.0:0")
        self.observed_ipv4_label = QLabel("Observed (BEP 42 ip): —")
        self.observed_ipv6_label = QLabel("Observed (BEP 42 ip): —")

        socket_layout.addWidget(QLabel("IPv4:"), 0, 0)
        socket_layout.addWidget(self.ipv4_socket_label, 0, 1)
        socket_layout.addWidget(QLabel("IPv6:"), 1, 0)
        socket_layout.addWidget(self.ipv6_socket_label, 1, 1)
        socket_layout.addWidget(QLabel("Bind:"), 2, 0)
        socket_layout.addWidget(self.bind_addr_label, 2, 1)
        socket_layout.addWidget(QLabel("Observed IPv4:"), 3, 0)
        socket_layout.addWidget(self.observed_ipv4_label, 3, 1)
        socket_layout.addWidget(QLabel("Observed IPv6:"), 4, 0)
        socket_layout.addWidget(self.observed_ipv6_label, 4, 1)

        socket_group.setLayout(socket_layout)
        inner_layout.addWidget(socket_group)

        inner_layout.addStretch(1)
        scroll.setWidget(scroll_inner)
        main_layout.addWidget(scroll, stretch=1)

        # Control buttons
        control_layout = QHBoxLayout()

        self.ping_btn = QPushButton("Ping All Questionable")
        self.ping_btn.setProperty("variant", "warning")
        self.ping_btn.clicked.connect(self._on_ping_questionable)
        control_layout.addWidget(self.ping_btn)

        self.save_btn = QPushButton("Save Peers")
        self.save_btn.clicked.connect(self._on_save_peers)
        control_layout.addWidget(self.save_btn)

        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.clicked.connect(self._on_refresh)
        control_layout.addWidget(self.refresh_btn)

        main_layout.addLayout(control_layout)

        main_layout.addStretch()

        # Status bar
        self.status_label = QLabel("Connected")
        self.status_label.setStyleSheet("color: #a6e3a1;")
        main_layout.addWidget(self.status_label)

    def _setup_timer(self) -> None:
        """Setup the refresh timer."""
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start(1000)  # Update every second

    def _on_timer(self) -> None:
        """Periodic update."""
        # Update uptime
        elapsed = time.time() - self._start_time
        if elapsed < 60:
            self.uptime_card.update_value(f"{elapsed:.0f}s", "#a6e3a1")
        elif elapsed < 3600:
            self.uptime_card.update_value(f"{elapsed / 60:.1f}m", "#a6e3a1")
        else:
            self.uptime_card.update_value(f"{elapsed / 3600:.2f}h", "#a6e3a1")

        # Update DHT stats
        self._update_dht_stats()

    def _update_dht_stats(self) -> None:
        """Update all DHT-related statistics."""
        if not self.dht_node:
            return

        try:
            # Node ID
            node_id_hex = binascii.b2a_hex(self.dht_node.node_id).decode("ascii")[:16] + "…"
            self.my_node_card.update_value(node_id_hex, "#89b4fa")

            # IPv4 stats
            rt_v4 = self.dht_node.routing_table.v4
            self.ipv4_bucket_card.update_value(str(len(rt_v4.buckets)), "#f9e2af")

            total_v4 = sum(len(b.nodes) for b in rt_v4.buckets)
            self.ipv4_nodes_card.update_value(str(total_v4), "#a6e3a1")

            # IPv6 stats
            rt_v6 = self.dht_node.routing_table.v6
            self.ipv6_bucket_card.update_value(str(len(rt_v6.buckets)), "#f9e2af")

            total_v6 = sum(len(b.nodes) for b in rt_v6.buckets)
            self.ipv6_nodes_card.update_value(str(total_v6), "#a6e3a1")

            # Active peers
            self.active_peers_card.update_value(str(len(self.dht_node.peers)), "#89b4fa")

            # Stored peers
            total_stored = 0
            if hasattr(self.dht_node, "peer_store") and self.dht_node.peer_store:
                total_stored = sum(len(peers) for peers in self.dht_node.peer_store._store.values())
            self.stored_peers_card.update_value(str(total_stored), "#f9e2af")

            # Queries and responses
            self.queries_sent_card.update_value(str(self._query_count), "#f38ba8")
            self.responses_card.update_value(str(self._response_count), "#a6e3a1")

            # Self-propagated count
            self.update_self_propagated(self.dht_node.self_node_id_response_count)

            # Private mode
            self.private_mode_card.update_value(
                "Yes" if self.dht_node.is_private_mode else "No",
                "#f38ba8" if self.dht_node.is_private_mode else "#a6e3a1",
            )

            # Socket info
            try:
                addr_v4 = self.dht_node.sock.getsockname()
                self.ipv4_socket_label.setText(f"{addr_v4[0]}:{addr_v4[1]}")
            except Exception:
                self.ipv4_socket_label.setText("IPv4: Not bound")

            if self.dht_node.sock6:
                try:
                    addr_v6 = self.dht_node.sock6.getsockname()
                    self.ipv6_socket_label.setText(f"[{addr_v6[0]}]:{addr_v6[1]}")
                except Exception:
                    self.ipv6_socket_label.setText("IPv6: Not bound")
            else:
                self.ipv6_socket_label.setText("IPv6: Not available")

            try:
                sockname = self.dht_node.sock.getsockname()
                self.bind_addr_label.setText(f"Bind: {sockname[0]}:{sockname[1]}")
            except Exception:
                self.bind_addr_label.setText("Bind: unknown")

            obs_v4, obs_v6 = self.dht_node.get_observed_external_endpoints()
            if obs_v4 is not None:
                self.observed_ipv4_label.setText(f"{obs_v4.ip}:{obs_v4.port}")
            else:
                self.observed_ipv4_label.setText("— (need BEP 42 ip quorum)")
            if obs_v6 is not None:
                self.observed_ipv6_label.setText(f"[{obs_v6.ip}]:{obs_v6.port}")
            else:
                self.observed_ipv6_label.setText("— (need BEP 42 ip quorum)")

            qps = float(getattr(dht_mod, "GET_PEERS_SCRAPE_QPS", 0) or 0)
            burst = float(getattr(dht_mod, "GET_PEERS_SCRAPE_BURST", 0) or 0)
            mx = int(getattr(dht_mod, "GET_PEERS_SCRAPE_MAX_INFLIGHT", 0) or 0)
            self.gp_scrape_card.update_value(
                f"{qps:g} / {burst:g} / {mx}",
                "#a6adc8" if (qps == 0 and burst == 0 and mx == 0) else "#f9e2af",
            )

            snap_raw: object = {}
            ds = getattr(self.dht_node, "diagnostics_snapshot", None)
            if callable(ds):
                try:
                    snap_raw = ds()
                except Exception:
                    snap_raw = {}
            snap = snap_raw if isinstance(snap_raw, dict) else {}
            scrape_states = snap.get("scrape_infohashes_with_state")
            scrape_backlog_nodes = snap.get("scrape_queued_candidate_nodes")
            krpc_pend = snap.get("approx_pending_krpc_enqueued")
            qs_tot = snap.get("queries_sent_total")
            rr_tot = snap.get("responses_received_total")
            to_tot = snap.get("queries_timed_out_total")
            self.scrape_ih_card.update_value(
                str(int(scrape_states)) if scrape_states is not None else "—",
                "#cba6f7",
            )
            self.scrape_queue_card.update_value(
                str(int(scrape_backlog_nodes)) if scrape_backlog_nodes is not None else "—",
                "#fab387",
            )
            self.krpc_queue_card.update_value(
                str(int(krpc_pend)) if krpc_pend is not None else "—",
                "#89dceb",
            )
            self.node_totals_card.update_value(
                f"{qs_tot}/{rr_tot}/{to_tot}" if all(x is not None for x in (qs_tot, rr_tot, to_tot)) else "—",
                "#94e2d5",
            )
        except Exception:
            # Fallback: show error state
            self.my_node_card.update_value("ERROR", "#f38ba8")

    def _on_ping_questionable(self) -> None:
        """Ping all questionable nodes."""
        self.status_label.setText("Pinging questionable nodes...")
        for table in [self.dht_node.routing_table.v4, self.dht_node.routing_table.v6]:
            for bucket in table.buckets:
                for node in bucket.nodes:
                    if node.status == "questionable":
                        peer_key = (node.endpoint.ip, node.endpoint.port)
                        if peer_key in self.dht_node.peers:
                            self.dht_node.peers[peer_key].ping()
        self.status_label.setText("Ping sent")

    def _on_save_peers(self) -> None:
        """Save peers to file."""
        try:
            self.dht_node.save_peers()
            self.status_label.setText("Peers saved")
        except Exception as e:
            self.status_label.setText(f"Save failed: {e}")

    def _on_refresh(self) -> None:
        """Force immediate refresh."""
        self._update_dht_stats()
        self.status_label.setText("Refreshed")

    def _on_ping_all(self) -> None:
        """Ping all known peers."""
        for peer in self.dht_node.peers.values():
            peer.ping()
        self.status_label.setText("Pinged all peers")

    def update_activity(self, queries: int, responses: int) -> None:
        """Update activity counters.

        Parameters
        ----------
        queries : int
            Number of queries sent.
        responses : int
            Number of responses received.
        """
        self._query_count = queries
        self._response_count = responses

    def update_self_propagated(self, count: int) -> None:
        """Update the self-propagation count displayed in the GUI.

        This is the number of nodes that responded with our node_id
        in find_node responses, confirming our node has been propagated
        into the DHT network.

        Parameters
        ----------
        count : int
            Number of nodes that responded with our node_id.
        """
        if count > 0:
            self.self_propagated_card.update_value(str(count), "#a6e3a1")
        else:
            self.self_propagated_card.update_value("0", "#f38ba8")
