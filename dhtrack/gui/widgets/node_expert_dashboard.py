"""Combined node metrics tab + dormant BEP monitor tab."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from dhtrack.gui.widgets.dht_monitor import DHTMonitorWidget
from dhtrack.gui.widgets.network_overview import NetworkOverviewWidget

if TYPE_CHECKING:
    from dhtrack.dht import DHTNode


class NodeExpertDashboard(QWidget):
    """Metrics (overview) plus deep BEP monitor in one workspace page."""

    def __init__(self, dht_node: DHTNode, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        tabs = QTabWidget()
        self.overview_tab = NetworkOverviewWidget(dht_node)
        self.monitor_tab = DHTMonitorWidget(dht_node)
        tabs.addTab(self.overview_tab, "Metrics")
        tabs.addTab(self.monitor_tab, "BEP monitor")
        v.addWidget(tabs)
