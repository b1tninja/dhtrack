"""
QAbstractTableModel for DHT routing table visualization.

Provides a table model for displaying nodes from the DHT routing tables
(both IPv4 and IPv6 combined into a single unified view).
"""

from __future__ import annotations

import binascii
import threading
import time

from PyQt6.QtCore import QAbstractTableModel, Qt
from PyQt6.QtGui import QColor

from dhtrack.swarm_peer_display import is_active_swarm_peer_row


class RoutingTableModel(QAbstractTableModel):
    """Model for displaying routing table nodes.

    Table columns:
    - Node ID: 20-byte node ID (hex)
    - IP:Port: IP address and port
    - IPv6: Whether the node is IPv6
    - Status: Node status (good/questionable/bad)
    - Last Contacted: Time since last contact
    - RPC Count: Number of RPCs received
    """

    def __init__(self, parent: object | None = None):
        super().__init__(parent)
        self._nodes: list[dict] = []
        self._search_text: str = ""
        self._lock = threading.Lock()

    def set_nodes(self, nodes: list[dict]) -> None:
        """Update the model with node data.

        Parameters
        ----------
        nodes : list[dict]
            List of node dicts with keys: node_id, ip, port, is_ipv6,
            status, last_contacted, rpc_counter, failure_count
        """
        with self._lock:
            self._nodes = list(nodes)  # copy to avoid race conditions
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()

    def set_search(self, text: str) -> None:
        """Set the search filter.

        Parameters
        ----------
        text : str
            Search text to filter by.
        """
        with self._lock:
            self._search_text = text.lower()
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()

    def rowCount(self, parent=None, index=None) -> int:
        with self._lock:
            nodes_copy = list(self._nodes)
        search_text = self._search_text
        return len(
            [
                n
                for n in nodes_copy
                if not search_text
                or any(
                    search_text in s
                    for s in [
                        binascii.b2a_hex(n["node_id"]).decode("ascii") if n.get("node_id") else "",
                        n.get("ip", ""),
                    ]
                )
            ]
        )

    def columnCount(self, parent=None, index=None) -> int:
        return 6

    def headerData(self, section: int, orientation: Qt.Orientation, role: int):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            headers = [
                "Node ID",
                "IP:Port",
                "IPv6",
                "Status",
                "Last Seen",
                "RPCs",
            ]
            if section < len(headers):
                return headers[section]
        return None

    def data(self, index, role: int):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        with self._lock:
            nodes_copy = list(self._nodes)

        if row < 0 or row >= len(nodes_copy):
            return None

        node = nodes_copy[row]

        # Column 0: Node ID
        if col == 0 and role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            node_id = node.get("node_id")
            if node_id:
                return binascii.b2a_hex(node_id).decode("ascii")
            # Swarm peers (from DHT get_peers "values") generally do not have a DHT node id.
            # Only show UNKNOWN for actual DHT nodes.
            if node.get("source") == "dht":
                return "UNKNOWN"
            return "—"

        # Column 1: IP:Port
        elif col == 1 and role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            ip = node.get("ip", "")
            port = node.get("port", 0)
            return f"{ip}:{port}"

        # Column 2: IPv6
        elif col == 2 and role == Qt.ItemDataRole.DisplayRole:
            return "Yes" if node.get("is_ipv6", False) else "No"

        # Column 3: Status
        elif col == 3 and role == Qt.ItemDataRole.DisplayRole:
            status = node.get("status", "good")
            status_map = {
                "good": "Good",
                "questionable": "Questionable",
                "bad": "Bad",
            }
            return status_map.get(status, status)

        # Column 4: Last Seen
        elif col == 4 and role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            last_contacted = node.get("last_contacted", 0)
            if last_contacted == 0:
                return "Never"
            ago = time.time() - last_contacted
            if ago < 60:
                return f"{ago:.0f}s ago"
            elif ago < 3600:
                return f"{ago / 60:.1f}m ago"
            else:
                return f"{ago / 3600:.1f}h ago"

        # Column 5: RPC Count
        elif col == 5 and role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return str(node.get("rpc_counter", 0))

        # Status colors
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 3:
                status = node.get("status", "good")
                if status == "good":
                    return QColor(166, 227, 161)  # Green
                elif status == "questionable":
                    return QColor(249, 226, 175)  # Yellow
                else:
                    return QColor(243, 139, 168)  # Red

        if role == Qt.ItemDataRole.BackgroundRole:
            status = node.get("status", "good")
            if status == "good":
                return QColor(24, 24, 37)  # Dark
            elif status == "questionable":
                return QColor(30, 28, 40)  # Slightly lighter
            else:
                return QColor(35, 20, 30)  # Reddish dark

        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def sort(self, col: int, order: Qt.SortOrder) -> None:
        """Sort the table by column."""
        self.layoutAboutToBeChanged.emit()
        with self._lock:
            nodes_copy = list(self._nodes)

        if col == 0:
            nodes_copy.sort(key=lambda n: binascii.b2a_hex(n.get("node_id", b"")).decode("ascii"))
        elif col == 1:
            nodes_copy.sort(key=lambda n: (n.get("ip", ""), n.get("port", 0)))
        elif col == 4:
            reverse = order == Qt.SortOrder.DescendingOrder
            nodes_copy.sort(key=lambda n: n.get("last_contacted", 0), reverse=reverse)

        with self._lock:
            self._nodes = nodes_copy
        self.layoutChanged.emit()


class SwarmPeerModel(QAbstractTableModel):
    """Model for displaying swarm peers (TCP peers) discovered for an infohash."""

    COL_IP = 0
    COL_V6 = 1
    COL_STATUS = 2
    COL_REMOTE_CHOKING = 3
    COL_WE_INTERESTED = 4
    COL_PHASE = 5
    COL_LAST_SEEN = 6
    COL_SOURCE = 7
    COL_ERROR = 8

    def __init__(self, parent: object | None = None):
        super().__init__(parent)
        self._peers: list[dict] = []
        self._lock = threading.Lock()
        self._show_active_only: bool = False

    def set_show_active_only(self, on: bool) -> None:
        with self._lock:
            self._show_active_only = bool(on)
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()

    def show_active_only(self) -> bool:
        with self._lock:
            return self._show_active_only

    def _visible_peers(self) -> list[dict]:
        with self._lock:
            peers = list(self._peers)
            active_only = self._show_active_only
        if active_only:
            return [p for p in peers if is_active_swarm_peer_row(p)]
        return peers

    @staticmethod
    def _tri(v: object) -> str:
        if v is True:
            return "yes"
        if v is False:
            return "no"
        return "—"

    def set_peers(self, peers: list[dict]) -> None:
        with self._lock:
            self._peers = list(peers)
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()

    def rowCount(self, parent=None, index=None) -> int:
        return len(self._visible_peers())

    def columnCount(self, parent=None, index=None) -> int:
        return 9

    def headerData(self, section: int, orientation: Qt.Orientation, role: int):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            headers = [
                "IP:Port",
                "IPv6",
                "Status",
                "Peer chokes us",
                "We interested",
                "Phase",
                "Last seen",
                "Source",
                "Last error",
            ]
            if section < len(headers):
                return headers[section]
        return None

    def data(self, index, role: int):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        visible = self._visible_peers()
        if row < 0 or row >= len(visible):
            return None
        peer = visible[row]

        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return None

        if col == self.COL_IP:
            return f"{peer.get('ip', '')}:{peer.get('port', 0)}"
        if col == self.COL_V6:
            return "Yes" if peer.get("is_ipv6", False) else "No"
        if col == self.COL_STATUS:
            status = peer.get("status")
            if not status:
                last = peer.get("last_seen", 0) or peer.get("last_contacted", 0)
                if not last:
                    return "unknown"
                try:
                    ago = time.time() - float(last)
                    if ago < 30:
                        return "fresh"
                    if ago < 5 * 60:
                        return "recent"
                    if ago < 60 * 60:
                        return "stale"
                except Exception:
                    pass
                return "stale"
            return str(status)
        if col == self.COL_REMOTE_CHOKING:
            if "peer_chokes_us" in peer:
                return self._tri(peer.get("peer_chokes_us"))
            return "—"
        if col == self.COL_WE_INTERESTED:
            return self._tri(peer.get("we_interested"))
        if col == self.COL_PHASE:
            ph = peer.get("phase")
            return str(ph) if ph else "—"
        if col == self.COL_LAST_SEEN:
            last = peer.get("last_seen", 0) or peer.get("last_contacted", 0)
            if not last:
                return "Never"
            ago = time.time() - float(last)
            if ago < 60:
                return f"{ago:.0f}s ago"
            if ago < 3600:
                return f"{ago / 60:.1f}m ago"
            return f"{ago / 3600:.1f}h ago"
        if col == self.COL_SOURCE:
            return str(peer.get("source", "swarm"))
        if col == self.COL_ERROR:
            err = peer.get("last_error")
            if not err:
                return "—"
            return str(err)
        return None

    def peer_at(self, row: int) -> dict | None:
        visible = self._visible_peers()
        if row < 0 or row >= len(visible):
            return None
        return dict(visible[row])

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
