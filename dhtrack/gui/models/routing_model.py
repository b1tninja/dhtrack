"""
QAbstractTableModel for DHT routing table visualization.

Provides a tree-style model for displaying K-buckets and their nodes
in a QTreeView or QTreeWidget.
"""

from __future__ import annotations

import binascii
import time

from PyQt6.QtCore import QAbstractItemModel, QModelIndex, Qt
from PyQt6.QtGui import QColor, QFont

# Qt role aliases for PyQt6 compatibility
_ItemDataRole = Qt.ItemDataRole


class _BucketItem:
    """Represents a K-bucket in the routing table."""

    def __init__(self, index: int, min_id: bytes, max_id: bytes, nodes: list):
        self.index: int = index
        self.min_id: bytes = min_id
        self.max_id: bytes = max_id
        self.nodes: list = nodes
        self.children: list[_NodeItem] = []
        self.expanded: bool = False

        for node in nodes:
            self.children.append(_NodeItem(node, self))

    @property
    def total_count(self) -> int:
        return len(self.children)

    @property
    def good_count(self) -> int:
        return sum(1 for n in self.children if n.status == "good")

    @property
    def questionable_count(self) -> int:
        return sum(1 for n in self.children if n.status == "questionable")

    @property
    def bad_count(self) -> int:
        return sum(1 for n in self.children if n.status == "bad")

    def distance_to_mid(self, my_node_id: bytes) -> int:
        """XOR distance from my node to the midpoint of this bucket's range."""
        mid_id = bytearray(self.min_id)
        for i in range(len(self.min_id)):
            diff = self.min_id[i] ^ self.max_id[i]
            if diff != 0:
                mid_bit = diff.bit_length() - 1
                mid_id[i] = self.min_id[i] | (1 << mid_bit)
                for j in range(i + 1, len(mid_id)):
                    mid_id[j] = 0x00
                break
        return int.from_bytes(bytes(mid_id), "big") ^ int.from_bytes(my_node_id, "big")


class _NodeItem:
    """Represents a node within a K-bucket."""

    def __init__(self, node: object, parent: _BucketItem):
        self.node = node
        self.parent = parent
        self.child_items: list = []

    @property
    def node_id(self) -> bytes | None:
        return getattr(self.node, "node_id", None)

    @property
    def ip(self) -> str:
        return getattr(getattr(self.node, "endpoint", None), "ip", "unknown")

    @property
    def port(self) -> int:
        return getattr(getattr(self.node, "endpoint", None), "port", 0)

    @property
    def status(self) -> str:
        return getattr(self.node, "status", "good").lower()

    @property
    def last_contacted(self) -> float:
        return getattr(self.node, "last_contacted", 0)

    @property
    def rpc_counter(self) -> int:
        return getattr(self.node, "rpc_counter", 0)

    @property
    def failure_count(self) -> int:
        return getattr(self.node, "failure_count", 0)

    @property
    def is_ipv6(self) -> bool:
        return getattr(getattr(self.node, "endpoint", None), "is_ipv6", False)

    def last_contacted_str(self) -> str:
        if self.last_contacted == 0:
            return "Never"
        ago = time.time() - self.last_contacted
        if ago < 60:
            return f"{ago:.0f}s ago"
        elif ago < 3600:
            return f"{ago / 60:.1f}m ago"
        else:
            return f"{ago / 3600:.1f}h ago"


class _RootItem:
    """Root item for the model tree."""

    def __init__(self):
        self.children = []

    def header(self) -> list[str]:
        return [
            "Node ID",
            "IP:Port",
            "Status",
            "Last Contacted",
            "RPCs",
        ]


class RoutingTableModel(QAbstractItemModel):
    """Model for displaying DHT routing table in a tree view.

    Tree structure:
    - Root
      - Bucket 0 (0x00xxxx...) [expandable]
        - Node 1
        - Node 2
      - Bucket 1 (0x01xxxx...) [expandable]
        - Node 1
      ...
    """

    def __init__(self, parent: object | None = None):
        super().__init__(parent)
        self._root = _RootItem()
        self._buckets: list[_BucketItem] = []
        self._refresh_timestamp = time.time()

    def refresh(self, routing_table, is_ipv6: bool = False) -> None:
        """Refresh the model with data from a routing table.

        Parameters
        ----------
        routing_table : RoutingTable
            The routing table to visualize.
        is_ipv6 : bool
            Whether this is the IPv6 routing table.
        """
        my_node_id = routing_table.my_node_id
        buckets_data = routing_table.buckets

        self._buckets = []
        for idx, bucket in enumerate(buckets_data):
            # Calculate bucket range based on distance from my node
            # Bucket N covers the range of IDs at bit distance N
            min_id = bytearray(my_node_id)
            max_id = bytearray(my_node_id)

            if idx < 160:
                # Set bit at position (159 - idx)
                bit_pos = 159 - idx
                byte_idx = bit_pos // 8
                bit_in_byte = 7 - (bit_pos % 8)

                # max_id has bit set
                max_id[byte_idx] |= 1 << bit_in_byte
                # min_id has bit unset, all following bits set
                min_id[byte_idx] &= ~(1 << bit_in_byte)
                for i in range(byte_idx + 1, 20):
                    min_id[i] = 0xFF
            else:
                # Bucket 160+ is beyond 160 bits, use all 1s or all 0s
                pass

            nodes = []
            for bucket_node in bucket.nodes:
                nodes.append(bucket_node)

            self._buckets.append(
                _BucketItem(
                    index=idx,
                    min_id=bytes(min_id),
                    max_id=bytes(max_id),
                    nodes=nodes,
                )
            )

        self.layoutChanged.emit()

    def index(self, row: int, column: int, parent: QModelIndex) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            # Top level: buckets
            if row < len(self._buckets):
                return self.createIndex(row, column, self._buckets[row])
        else:
            parent_item = parent.internalPointer()
            if isinstance(parent_item, _BucketItem):
                if row < len(parent_item.children):
                    return self.createIndex(row, column, parent_item.children[row])

        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()

        item = index.internalPointer()
        if isinstance(item, _BucketItem):
            # Top-level items (buckets) have no parent.
            return QModelIndex()

        if isinstance(item, _NodeItem):
            bucket = item.parent
            bucket_idx = self._buckets.index(bucket) if bucket in self._buckets else -1
            if bucket_idx >= 0:
                return self.createIndex(bucket_idx, 0, bucket)

        return QModelIndex()

    def rowCount(self, parent: QModelIndex = None) -> int:
        if parent is None or not parent.isValid():
            return len(self._buckets)

        item = parent.internalPointer()
        if isinstance(item, _BucketItem):
            return len(item.children)
        return 0

    def columnCount(self, parent: QModelIndex = None) -> int:
        return 5

    def headerData(self, section: int, orientation: Qt.Orientation, role: int):
        if role == _ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            headers = [
                "Node ID",
                "IP:Port",
                "Status",
                "Last Contacted",
                "RPCs",
            ]
            if section < len(headers):
                return headers[section]
        return None

    def data(self, index: QModelIndex, role: int):
        if not index.isValid():
            return None

        item = index.internalPointer()

        if role == _ItemDataRole.BackgroundRole:
            if isinstance(item, _BucketItem):
                # Color code bucket based on fill ratio
                fill_ratio = item.total_count / 8  # K=8
                if fill_ratio >= 1.0:
                    return QColor(49, 26, 26)  # Dark red
                elif fill_ratio >= 0.75:
                    return QColor(49, 40, 26)  # Dark orange
                elif fill_ratio >= 0.5:
                    return QColor(26, 40, 49)  # Dark blue
                else:
                    return QColor(24, 24, 37)  # Dark background
            elif isinstance(item, _NodeItem):
                if item.status == "bad":
                    return QColor(49, 26, 26)
                elif item.status == "questionable":
                    return QColor(49, 40, 26)

        if role == _ItemDataRole.ForegroundRole:
            if isinstance(item, _NodeItem):
                if item.status == "bad":
                    return QColor(243, 139, 168)  # Red
                elif item.status == "questionable":
                    return QColor(249, 226, 175)  # Yellow
                else:
                    return QColor(166, 227, 161)  # Green

        if role == _ItemDataRole.DisplayRole:
            if isinstance(item, _BucketItem):
                bucket_min_hex = binascii.b2a_hex(item.min_id[:4]).decode("ascii") + "···"
                bucket_max_hex = binascii.b2a_hex(item.max_id[:4]).decode("ascii") + "···"
                bucket_label = f"Bucket {item.index}: {bucket_min_hex} ← {bucket_max_hex}"
                return bucket_label
            elif isinstance(item, _NodeItem):
                column = index.column()
                if column == 0:
                    if item.node_id:
                        node_id_hex = binascii.b2a_hex(item.node_id).decode("ascii")
                        return node_id_hex[:16] + "…"
                    else:
                        return "UNKNOWN"
                elif column == 1:
                    ipv6_suffix = " (v6)" if item.is_ipv6 else ""
                    return f"{item.ip}:{item.port}{ipv6_suffix}"
                elif column == 2:
                    status_map = {
                        "good": "✓ Good",
                        "questionable": "⚠ Questionable",
                        "bad": "✗ Bad",
                    }
                    return status_map.get(item.status, item.status)
                elif column == 3:
                    return item.last_contacted_str()
                elif column == 4:
                    return str(item.rpc_counter)

        if role == _ItemDataRole.FontRole:
            if isinstance(item, _BucketItem):
                font = QFont()
                font.setBold(True)
                return font

        if role == _ItemDataRole.UserRole:
            return item

        return None

    def flags(self, index: QModelIndex):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        item = index.internalPointer()
        if isinstance(item, _BucketItem):
            return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def setExpanded(self, index: QModelIndex, expanded: bool) -> None:
        item = index.internalPointer()
        if isinstance(item, _BucketItem):
            item.expanded = expanded
        super().setExpanded(index, expanded)
