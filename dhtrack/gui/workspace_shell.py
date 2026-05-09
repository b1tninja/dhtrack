"""Sidebar + stacked pages layout for expert DHT inspector."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


class MainWorkspaceShell(QWidget):
    """Left navigation list + ``QStackedWidget`` content area."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(3)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("workspaceSidebar")
        self.sidebar.setFixedWidth(200)
        self.sidebar.setSpacing(2)
        self.sidebar.setAlternatingRowColors(False)
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.sidebar.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.sidebar.setUniformItemSizes(True)

        self.stack = QStackedWidget()

        split.addWidget(self.sidebar)
        split.addWidget(self.stack)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)

        lay.addWidget(split)

        self._pages: list[tuple[str, QWidget]] = []

    def set_pages(self, pages: list[tuple[str, QWidget]]) -> None:
        """Rebuild sidebar entries and stacked widgets."""
        try:
            self.sidebar.currentRowChanged.disconnect()
        except TypeError:
            pass

        self._pages = list(pages)
        self.sidebar.clear()
        while self.stack.count():
            w = self.stack.widget(0)
            self.stack.removeWidget(w)

        for title, widget in self._pages:
            self.stack.addWidget(widget)
            QListWidgetItem(title, self.sidebar)

        if self._pages:
            self.sidebar.setCurrentRow(0)
            self.stack.setCurrentIndex(0)

        self.sidebar.currentRowChanged.connect(self.stack.setCurrentIndex)
