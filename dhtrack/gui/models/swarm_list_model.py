from __future__ import annotations

import time

from PyQt6.QtCore import QAbstractTableModel, Qt

from dhtrack.swarm import Swarm, SwarmManager


class SwarmListModel(QAbstractTableModel):
    """Table model that lists all tracked swarms."""

    def __init__(self, manager: SwarmManager, parent: object | None = None):
        super().__init__(parent)
        self._mgr = manager
        self._rows: list[Swarm] = []
        self.refresh()

    def refresh(self) -> None:
        self.layoutAboutToBeChanged.emit()
        self._rows = self._mgr.list()
        self.layoutChanged.emit()

    def rowCount(self, parent=None, index=None) -> int:
        return len(self._rows)

    def columnCount(self, parent=None, index=None) -> int:
        return 7

    def headerData(self, section: int, orientation: Qt.Orientation, role: int):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            headers = ["Name", "Infohash", "State", "Swarm peers", "Progress", "Downloaded", "Updated"]
            if section < len(headers):
                return headers[section]
        return None

    def data(self, index, role: int):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self._rows):
            return None
        sw = self._rows[row]

        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if col == 0:
            return sw.display_name or ""
        if col == 1:
            return sw.short_id
        if col == 2:
            return sw.state
        if col == 3:
            return str(sw.peers_found)
        if col == 4:
            if sw.total_bytes > 0:
                pct = (sw.downloaded_bytes / sw.total_bytes) * 100.0
                return f"{pct:.2f}%"
            if sw.total_pieces > 0:
                pct = (sw.completed_pieces / sw.total_pieces) * 100.0
                return f"{pct:.2f}%"
            return "—"
        if col == 5:
            if sw.total_bytes > 0:
                mb = sw.downloaded_bytes / (1024 * 1024)
                total_mb = sw.total_bytes / (1024 * 1024)
                return f"{mb:.1f}/{total_mb:.1f} MiB"
            if sw.total_pieces > 0:
                return f"{sw.completed_pieces}/{sw.total_pieces} pcs"
            return "—"
        if col == 6:
            if not sw.last_updated:
                return "—"
            ago = time.time() - sw.last_updated
            if ago < 60:
                return f"{ago:.0f}s"
            if ago < 3600:
                return f"{ago / 60:.1f}m"
            return f"{ago / 3600:.1f}h"
        return None

    def swarm_at(self, row: int) -> Swarm | None:
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]
