"""Torrent Manager: registered torrents table with per-row detail (main window tab)."""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from dhtrack.gui.inspector_session import InspectorSession
from dhtrack.gui.torrent_display_utils import (
    format_throughput_human,
    tcp_active_peer_count,
    torrent_status_display,
)
from dhtrack.swarm import Swarm, SwarmManager
from dhtrack.torrent_track import (
    TORRENT_STATUS_COMPLETE,
    TORRENT_STATUS_DOWNLOADING,
    TORRENT_STATUS_ERROR,
    TORRENT_STATUS_IDLE,
    TORRENT_STATUS_PENDING_METADATA,
    TORRENT_STATUS_QUEUED,
    TorrentManager,
    TrackedTorrent,
)


@runtime_checkable
class TorrentManagerInspectBridge(Protocol):
    """Swarm Inspector download/EWMA + worker control used by Torrent Manager."""

    def download_ewma_bps_for_infohash(self, ih: bytes) -> float: ...

    def completion_percent_for_registered(self, tt: TrackedTorrent, sw: Swarm | None) -> str: ...

    def payload_worker_running(self, ih: bytes) -> bool: ...

    def remove_managed_torrent_row(self, ih: bytes) -> None: ...

    def stop_managed_payload_row(self, ih: bytes) -> str: ...

    def dequeue_managed_payload_row(self, ih: bytes) -> None: ...

    def start_managed_payload_download(self, ih: bytes, parent: QWidget | None = None) -> str: ...


class TorrentManagerTableModel(QAbstractTableModel):
    """Merged ``TorrentManager`` + ``SwarmManager`` row snapshot."""

    COL_NAME = 0
    COL_LOC = 1
    COL_SWARM = 2
    COL_ACTIVE_PEERS = 3
    COL_DOWN = 4
    COL_UP = 5
    COL_PCT = 6
    COL_STATUS = 7

    def __init__(
        self,
        manager: TorrentManager,
        swarm_manager: SwarmManager,
        bridge: TorrentManagerInspectBridge | None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._mgr = manager
        self._sm = swarm_manager
        self._bridge = bridge
        self._rows: list[TrackedTorrent] = []
        self.refresh()

    def set_bridge(self, bridge: TorrentManagerInspectBridge | None) -> None:
        self._bridge = bridge
        self.layoutChanged.emit()

    def refresh(self) -> None:
        self.layoutAboutToBeChanged.emit()
        self._rows = list(self._mgr.list())
        self.layoutChanged.emit()

    def rowCount(self, parent: QModelIndex | None = None, *args: object, **kw: object) -> int:
        if parent is None:
            parent = QModelIndex()
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex | None = None, *args: object, **kw: object) -> int:
        return 8

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = int(Qt.ItemDataRole.DisplayRole),
    ):
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        headers = [
            "Name",
            "Location",
            "Swarm peers",
            "Active TCP",
            "Down",
            "Up",
            "%",
            "Status",
        ]
        return headers[section] if section < len(headers) else None

    def data(self, index: QModelIndex, role: int = int(Qt.ItemDataRole.DisplayRole)):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        r, c = index.row(), index.column()
        if r < 0 or r >= len(self._rows):
            return None
        t = self._rows[r]
        ih = t.info_hash
        sw = self._sm.get(ih)
        br = self._bridge
        if c == self.COL_NAME:
            name = (t.display_name or (sw.display_name if sw else None) or "").strip()
            return name or t.short_id
        if c == self.COL_LOC:
            return str(t.download_directory) if t.download_directory else "—"
        if c == self.COL_SWARM:
            return str(len(sw.swarm_peers or [])) if sw else "0"
        if c == self.COL_ACTIVE_PEERS:
            return str(tcp_active_peer_count(sw))
        if c == self.COL_DOWN:
            if br is None:
                return "—"
            return format_throughput_human(br.download_ewma_bps_for_infohash(ih))
        if c == self.COL_UP:
            return "—"
        if c == self.COL_PCT:
            if br is None:
                return "—"
            return br.completion_percent_for_registered(t, sw)
        if c == self.COL_STATUS:
            return torrent_status_display(t)
        return None

    def torrent_at(self, row: int) -> TrackedTorrent | None:
        if row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]


def _swarm_state_line(sw: Swarm | None) -> str:
    if sw is None:
        return "Swarm: not tracked (add in Swarm Tracker)"
    st = getattr(sw, "state", None) or "—"
    return f"Swarm.state: {st}"


def _detail_blurb_for_status(tt: TrackedTorrent, max_concurrent_downloads: int) -> str:
    if tt.status == TORRENT_STATUS_IDLE:
        return (
            "Registered in the library with no active download job. "
            "Use Start download when a .torrent is on disk or metadata was cached in-session, "
            "or open Swarm Inspector for magnet / ut_metadata flows."
        )
    if tt.status == TORRENT_STATUS_PENDING_METADATA:
        return (
            "Waiting for usable .torrent metadata (info dict). "
            "Retrieve metadata in Swarm Inspector (Torrent Metadata tab) for this info-hash."
        )
    if tt.status == TORRENT_STATUS_QUEUED:
        return (
            "Download is queued until a concurrent payload slot is free "
            f"(at most {max_concurrent_downloads} simultaneous downloads)."
        )
    if tt.status == TORRENT_STATUS_DOWNLOADING:
        return (
            "A payload worker should be transferring pieces into the chosen folder "
            "(or starting). Down speed reflects recent progress EWMA."
        )
    if tt.status == TORRENT_STATUS_COMPLETE:
        return (
            "Payload finished for this registration. Locally this is treated as seeding-ready; "
            "full upload seeding is not started automatically."
        )
    if tt.status == TORRENT_STATUS_ERROR:
        return "Library status is error — see Last error below."
    return ""


class TorrentManagerWidget(QWidget):
    """Table of registered torrents plus a detail panel driven by selection."""

    def __init__(
        self,
        inspector_session: InspectorSession,
        inspect_bridge: TorrentManagerInspectBridge | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._inspector_session = inspector_session
        self._torrent_mgr = inspector_session.torrent_manager
        self._swarm_mgr = inspector_session.swarm_manager
        self._bridge = inspect_bridge

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        title = QLabel("Torrent Manager")
        title.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold;")
        outer.addWidget(title)

        hint = QLabel(
            "Registered torrents and payload jobs. Select a row for state-specific notes. "
            "Bounded concurrent downloads — rows may stay Queued until a slot frees."
        )
        hint.setStyleSheet("color: #a6adc8; font-size: 10px;")
        hint.setWordWrap(True)
        outer.addWidget(hint)

        btns = QHBoxLayout()
        self._start_btn = QPushButton("Start download…")
        self._start_btn.setToolTip(
            "Start payload download using a library .torrent file or swarm-cached metadata.",
        )
        self._start_btn.setStyleSheet(
            "background-color: #89b4fa; color: #1e1e2e; font-weight: bold;",
        )
        self._start_btn.clicked.connect(self._on_start_download)

        self._remove_btn = QPushButton("Remove selected")
        self._remove_btn.setToolTip(
            "Remove from library only; tracked swarm unchanged. Stops worker if downloading.",
        )
        self._remove_btn.setStyleSheet(
            "background-color: #f38ba8; color: #1e1e2e; font-weight: bold;",
        )
        self._remove_btn.clicked.connect(self._on_remove)

        self._stop_btn = QPushButton("Stop download")
        self._stop_btn.setStyleSheet("background-color: #313244; color: #cdd6f4;")
        self._stop_btn.clicked.connect(self._on_stop_download)

        self._dequeue_btn = QPushButton("Dequeue")
        self._dequeue_btn.setToolTip(
            "Remove pending download slot from queue without removing the library row.",
        )
        self._dequeue_btn.setStyleSheet("background-color: #313244; color: #cdd6f4;")
        self._dequeue_btn.clicked.connect(self._on_dequeue)

        self._open_folder_btn = QPushButton("Open folder")
        self._open_folder_btn.setStyleSheet("background-color: #313244; color: #cdd6f4;")
        self._open_folder_btn.clicked.connect(self._on_open_folder)

        for w in (
            self._start_btn,
            self._remove_btn,
            self._stop_btn,
            self._dequeue_btn,
            self._open_folder_btn,
        ):
            btns.addWidget(w)
        btns.addStretch(1)
        outer.addLayout(btns)

        self._status = QLabel("")
        self._status.setStyleSheet("color: #a6adc8; font-size: 11px;")
        outer.addWidget(self._status)

        split = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableView()
        self._model = TorrentManagerTableModel(
            self._torrent_mgr,
            self._swarm_mgr,
            inspect_bridge,
        )
        self._table.setModel(self._model)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        hdr = self._table.horizontalHeader()
        for mc in range(8):
            if mc == TorrentManagerTableModel.COL_NAME:
                hdr.setSectionResizeMode(mc, QHeaderView.ResizeMode.Stretch)
            elif mc == TorrentManagerTableModel.COL_LOC:
                hdr.setSectionResizeMode(mc, QHeaderView.ResizeMode.Stretch)
            else:
                hdr.setSectionResizeMode(mc, QHeaderView.ResizeMode.ResizeToContents)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMinimumHeight(160)
        self._detail.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #cdd6f4; font-family: monospace; }",
        )

        split.addWidget(self._table)
        split.addWidget(self._detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        outer.addWidget(split, stretch=1)

        sm = self._table.selectionModel()
        if sm is not None:
            sm.selectionChanged.connect(self._on_selection_changed)

        self._timer = QTimer(self)
        self._timer.setInterval(800)
        self._timer.timeout.connect(self._model.refresh)
        self._timer.timeout.connect(self._refresh_detail_keep_selection)
        self._timer.start()

        self._detail.setPlainText("Select a torrent row.")

    def set_inspect_bridge(self, bridge: TorrentManagerInspectBridge | None) -> None:
        """When Swarm Inspector is recreated, reconnect EWMA/worker delegation."""
        self._bridge = bridge
        self._model.set_bridge(bridge)

    def refresh_from_manager(self) -> None:
        self._model.refresh()
        self._refresh_detail_keep_selection()

    def _current_torrent(self) -> TrackedTorrent | None:
        sm = self._table.selectionModel()
        if sm is None:
            return None
        sel = sm.selection()
        if not sel.indexes():
            return None
        return self._model.torrent_at(sel.indexes()[0].row())

    def _on_selection_changed(self, *_args: object) -> None:
        self._update_detail_text(self._current_torrent())

    def _refresh_detail_keep_selection(self) -> None:
        self._update_detail_text(self._current_torrent())

    def _update_detail_text(self, tt: TrackedTorrent | None) -> None:
        if tt is None:
            self._detail.setPlainText("Select a torrent row.")
            return
        sw = self._swarm_mgr.get(tt.info_hash)
        ih_hex = tt.info_hash.hex()
        lines = [
            f"Info-hash: {ih_hex}",
            f"Display name: {(tt.display_name or '—').strip() or '—'}",
            f"Metadata file (.torrent): {tt.metadata_path or '—'}",
            f"Payload download directory: {tt.download_directory or '—'}",
            "",
            "Library status:",
            f"  {torrent_status_display(tt)}",
            "",
            _detail_blurb_for_status(tt, self._torrent_mgr.max_concurrent_payload_downloads),
            "",
            _swarm_state_line(sw),
        ]
        if sw is not None:
            lines.extend(
                [
                    f"Swarm peers (DHT list): {len(sw.swarm_peers or [])}",
                    f"Active TCP (approx.): {tcp_active_peer_count(sw)}",
                ],
            )
        br = self._bridge
        pct = br.completion_percent_for_registered(tt, sw) if br is not None else "—"
        spd = format_throughput_human(br.download_ewma_bps_for_infohash(tt.info_hash)) if br is not None else "—"
        worker = br.payload_worker_running(tt.info_hash) if br is not None else False
        lines.extend(
            [
                "",
                "Progress:",
                f"  {pct}",
                "",
                "Download speed (EWMA):",
                f"  {spd}",
                "",
                "Payload worker:",
                f"  {'running' if worker else 'not running'}",
            ],
        )

        registered_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tt.registered_at))
        lines.extend(["", f"Registered at: {registered_at}"])

        if tt.last_error:
            lines.extend(["", "Last error:", f"  {tt.last_error}"])

        self._detail.setPlainText("\n".join(lines))

    def _on_start_download(self) -> None:
        if self._bridge is None:
            self._status.setText("Swarm Inspector is unavailable.")
            return
        tt = self._current_torrent()
        if tt is None:
            self._status.setText("No row selected.")
            return
        self._status.setText(
            self._bridge.start_managed_payload_download(tt.info_hash, parent=self),
        )

    def _on_remove(self) -> None:
        if self._bridge is None:
            self._status.setText("Swarm Inspector is unavailable.")
            return
        tt = self._current_torrent()
        if tt is None:
            self._status.setText("No row selected.")
            return
        self._bridge.remove_managed_torrent_row(tt.info_hash)
        self._status.setText(f"Removed {tt.short_id} from library (if present).")

    def _on_stop_download(self) -> None:
        if self._bridge is None:
            self._status.setText("Swarm Inspector is unavailable.")
            return
        tt = self._current_torrent()
        if tt is None:
            self._status.setText("No row selected.")
            return
        msg = self._bridge.stop_managed_payload_row(tt.info_hash)
        self._status.setText(msg)

    def _on_dequeue(self) -> None:
        if self._bridge is None:
            self._status.setText("Swarm Inspector is unavailable.")
            return
        tt = self._current_torrent()
        if tt is None:
            self._status.setText("No row selected.")
            return
        self._bridge.dequeue_managed_payload_row(tt.info_hash)
        self._status.setText(f"Dequeued {tt.short_id} if it was queued.")

    def _on_open_folder(self) -> None:
        tt = self._current_torrent()
        if tt is None:
            self._status.setText("No row selected.")
            return
        if tt.download_directory is None:
            self._status.setText("Selected row has no download folder.")
            return
        p = tt.download_directory.expanduser().resolve()
        if not p.is_dir():
            self._status.setText("Folder does not exist yet.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))
        self._status.setText("")
