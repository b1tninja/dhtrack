"""Swarm Tracker tab: add/remove tracked swarms (hex or magnet)."""

from __future__ import annotations

import binascii
from collections.abc import Callable

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from dhtrack.bep53 import magnet_peer_strings_to_triplets, parse_magnet_uri
from dhtrack.gui.models.swarm_list_model import SwarmListModel
from dhtrack.swarm import SwarmManager


class SwarmTrackerWidget(QWidget):
    """Manage which infohashes are tracked for the shared ``SwarmManager``."""

    registry_changed = pyqtSignal()

    def __init__(
        self,
        swarm_manager: SwarmManager,
        parent: QWidget | None = None,
        *,
        before_remove_swarm: Callable[[bytes], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._swarm_mgr = swarm_manager
        self._before_remove_swarm = before_remove_swarm
        self._setup_ui()

    def refresh_table(self) -> None:
        """Refresh the tracked-swarm table (e.g. after inspector updates swarm state)."""
        self._model.refresh()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title = QLabel("Swarm Tracker")
        title.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        hint = QLabel(
            "Track infohashes for DHT discovery and inspection. "
            "Enter 40-character hex or paste a magnet URI, then Track."
        )
        hint.setStyleSheet("color: #a6adc8; font-size: 10px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        row = QWidget()
        row.setProperty("role", "toolbar_strip")
        h = QHBoxLayout(row)
        self._input = QLineEdit()
        self._input.setPlaceholderText("Hex infohash (40 chars) or magnet:?…")
        h.addWidget(self._input)

        pb = QPushButton("Parse Magnet")
        pb.setStyleSheet("background-color: #313244; color: #cdd6f4;")
        pb.clicked.connect(self._parse_magnet)
        h.addWidget(pb)

        track_btn = QPushButton("Track swarm")
        track_btn.setStyleSheet("background-color: #89b4fa; color: #1e1e2e; font-weight: bold;")
        track_btn.clicked.connect(self._track_swarm)
        h.addWidget(track_btn)

        layout.addWidget(row)

        tbl_frame = QWidget()
        tv_layout = QVBoxLayout(tbl_frame)
        tv_layout.setContentsMargins(0, 4, 0, 0)
        self._table = QTableView()
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._model = SwarmListModel(self._swarm_mgr)
        self._table.setModel(self._model)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i, w in enumerate([140, 80, 80, 80, 120, 60], start=1):
            hdr.resizeSection(i, w)
        tv_layout.addWidget(self._table)

        btns = QHBoxLayout()
        rm = QPushButton("Remove selected")
        rm.setStyleSheet("background-color: #f38ba8; color: #1e1e2e; font-weight: bold;")
        rm.clicked.connect(self._remove_selected)
        btns.addWidget(rm)
        btns.addStretch(1)
        tv_layout.addLayout(btns)

        layout.addWidget(tbl_frame)

    def _emit_changed(self) -> None:
        self._model.refresh()
        self.registry_changed.emit()

    def _parse_magnet(self) -> None:
        try:
            from PyQt6.QtWidgets import QApplication

            text = QApplication.clipboard().text().strip()
        except Exception:
            text = ""
        if not text.startswith("magnet:?"):
            text = self._input.text().strip()
        if not text.startswith("magnet:?"):
            return
        self._input.setText(text)
        try:
            info = parse_magnet_uri(text)
        except ValueError:
            return
        ih = info.info_hash
        if ih is None or len(ih) != 20:
            return
        triplets = magnet_peer_strings_to_triplets(info.peers)
        self._swarm_mgr.upsert(
            ih,
            display_name=info.name or None,
            magnet_peer_triplets=triplets,
        )
        self._input.setText(ih.hex())
        self._swarm_mgr.select(ih)
        self._emit_changed()

    def _track_swarm(self) -> None:
        raw = self._input.text().strip()
        if not raw:
            return
        if raw.startswith("magnet:?"):
            try:
                info = parse_magnet_uri(raw)
            except ValueError:
                return
            ih = info.info_hash
            if ih is None or len(ih) != 20:
                return
            self._swarm_mgr.upsert(
                ih,
                display_name=info.name or None,
                magnet_peer_triplets=magnet_peer_strings_to_triplets(info.peers),
            )
        else:
            try:
                ih = binascii.unhexlify(raw)
            except Exception:
                return
            if len(ih) != 20:
                return
            self._swarm_mgr.upsert(ih)
        self._swarm_mgr.select(ih)
        self._emit_changed()

    def _remove_selected(self) -> None:
        sel = self._table.selectionModel().selection()
        if not sel.indexes():
            return
        row = sel.indexes()[0].row()
        sw = self._model.swarm_at(row)
        if sw is None:
            return
        if self._before_remove_swarm is not None:
            try:
                self._before_remove_swarm(sw.info_hash)
            except Exception:
                pass
        self._swarm_mgr.remove(sw.info_hash)
        self._emit_changed()
