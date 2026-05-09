"""
QAbstractTableModel for message type statistics in traffic monitoring.

Provides a sortable, filterable table for displaying DHT message type
counts with percentage calculations and visual indicators.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QColor


class MessageTypeModel(QAbstractTableModel):
    """Model for displaying message type statistics in a table view.

    Columns:
    - Type: Message type (ping, find_node, get_peers, etc.)
    - Count: Number of messages of this type
    - Percentage: Percentage of total messages
    - Direction: "Outgoing" or "Incoming"
    """

    def __init__(
        self,
        direction: str,
        stats: dict[str, int],
        total: int,
        parent: object | None = None,
    ):
        """Initialize the model.

        Parameters
        ----------
        direction : str
            "Outgoing" or "Incoming".
        stats : dict
            Dictionary mapping message types to counts.
        total : int
            Total number of messages.
        parent : object, optional
            Parent QObject.
        """
        super().__init__(parent)
        self._direction = direction
        self._stats = stats
        self._total = total
        self._sort_column: int = 1  # Sort by count by default
        self._sort_order: Qt.SortOrder = Qt.SortOrder.DescendingOrder

    def rowCount(self, parent: QModelIndex = None) -> int:
        """Get the number of rows (message types)."""
        if parent and parent.isValid():
            return 0
        return len(self._stats)

    def columnCount(self, parent: QModelIndex = None) -> int:
        """Get the number of columns."""
        return 4

    def data(
        self,
        index: QModelIndex,
        role: int,
    ) -> Any:
        """Get data for a cell.

        Parameters
        ----------
        index : QModelIndex
            Cell index.
        role : int
            Display role.
        """
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            msg_type = list(self._stats.keys())[row]
            count = self._stats[msg_type]

            if col == 0:
                return msg_type
            elif col == 1:
                return str(count)
            elif col == 2:
                pct = (count / self._total * 100) if self._total > 0 else 0
                return f"{pct:.1f}%"
            elif col == 3:
                return self._direction

        elif role == Qt.ItemDataRole.BackgroundRole:
            # Color code by count
            count = list(self._stats.values())[row]
            pct = (count / self._total * 100) if self._total > 0 else 0
            if pct >= 30:
                return QColor(52, 120, 213)  # High frequency - blue
            elif pct >= 10:
                return QColor(30, 60, 90)  # Medium frequency - dark blue
            else:
                return QColor(24, 24, 37)  # Low frequency - dark

        elif role == Qt.ItemDataRole.ForegroundRole:
            count = list(self._stats.values())[row]
            pct = (count / self._total * 100) if self._total > 0 else 0
            if pct >= 30:
                return QColor(174, 217, 255)  # Light blue for high frequency

        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (1, 2):
                return Qt.AlignmentFlag.AlignCenter

        return None

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int,
    ) -> Any:
        """Get header data."""
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal:
                headers = ["Message Type", "Count", "Percentage", "Direction"]
                if section < len(headers):
                    return headers[section]
            elif orientation == Qt.Orientation.Vertical:
                return str(section + 1)

        return None

    def sort(self, column: int, order: Qt.SortOrder) -> None:
        """Sort the table by a column."""
        self.layoutAboutToBeChanged.emit()
        self._sort_column = column
        self._sort_order = order

        # Sort the stats dictionary by value or key
        items = list(self._stats.items())
        if column == 0:
            # Sort by message type (name)
            items.sort(key=lambda x: x[0], reverse=(order == Qt.SortOrder.DescendingOrder))
        elif column == 1:
            # Sort by count
            items.sort(key=lambda x: x[1], reverse=(order == Qt.SortOrder.DescendingOrder))
        elif column == 2:
            # Sort by percentage (same as count)
            items.sort(key=lambda x: x[1], reverse=(order == Qt.SortOrder.DescendingOrder))

        self._stats = dict(items)
        self.layoutChanged.emit()

    def update_data(self, stats: dict[str, int], total: int) -> None:
        """Update the model with new data.

        Parameters
        ----------
        stats : dict
            New message type statistics.
        total : int
            New total count.
        """
        self.layoutAboutToBeChanged.emit()
        self._stats = stats
        self._total = total
        self.layoutChanged.emit()

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        """Get item flags."""
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
