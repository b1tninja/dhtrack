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
        self._row_to_stack: list[int | None] = []

    def set_pages(self, pages: list[tuple[str, QWidget | None]]) -> None:
        """Rebuild sidebar entries and stacked widgets.

        A ``None`` widget is a non-selectable section header. Selecting a
        header moves to the next real page. Headers are not stacked.
        """
        try:
            self.sidebar.currentRowChanged.disconnect()
        except TypeError:
            pass

        self._pages = [(title, widget) for title, widget in pages if widget is not None]
        self._row_to_stack = []
        self.sidebar.clear()
        while self.stack.count():
            w = self.stack.widget(0)
            self.stack.removeWidget(w)

        stack_index = 0
        first_selectable = -1
        for title, widget in pages:
            item = QListWidgetItem(title)
            if widget is None:
                item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                font = item.font()
                font.setBold(True)
                item.setFont(font)
                self._row_to_stack.append(None)
            else:
                self.stack.addWidget(widget)
                self._row_to_stack.append(stack_index)
                if first_selectable < 0:
                    first_selectable = self.sidebar.count()
                stack_index += 1
            self.sidebar.addItem(item)

        self._last_row = first_selectable
        if first_selectable >= 0:
            mapped = self._row_to_stack[first_selectable]
            self.sidebar.setCurrentRow(first_selectable)
            if mapped is not None:
                self.stack.setCurrentIndex(mapped)

        self.sidebar.currentRowChanged.connect(self._select_sidebar_row)

    def _select_sidebar_row(self, row: int) -> None:
        if row < 0 or row >= len(self._row_to_stack):
            return
        mapped = self._row_to_stack[row]
        if mapped is None:
            # A section header is not a page: skip it in the direction the
            # selection moved, so Up can still reach the previous section.
            if row < self._last_row:
                order = list(range(row - 1, -1, -1)) + list(range(row + 1, len(self._row_to_stack)))
            else:
                order = list(range(row + 1, len(self._row_to_stack))) + list(range(row - 1, -1, -1))
            for nxt in order:
                if self._row_to_stack[nxt] is not None:
                    self.sidebar.setCurrentRow(nxt)
                    return
            return
        self._last_row = row
        self.stack.setCurrentIndex(mapped)
