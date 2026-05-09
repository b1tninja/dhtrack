"""GUI widgets for the DHT Network Inspector."""

from __future__ import annotations

from dhtrack.gui.widgets.dht_monitor import DHTMonitorWidget
from dhtrack.gui.widgets.krpc_console import KRPConsoleWidget
from dhtrack.gui.widgets.network_overview import NetworkOverviewWidget
from dhtrack.gui.widgets.peer_store import PeerStoreWidget
from dhtrack.gui.widgets.routing_table import RoutingTableWidget
from dhtrack.gui.widgets.settings_dialog import SettingsDialog
from dhtrack.gui.widgets.traffic_monitor import TrafficMonitorWidget

__all__ = [
    "NetworkOverviewWidget",
    "RoutingTableWidget",
    "PeerStoreWidget",
    "KRPConsoleWidget",
    "TrafficMonitorWidget",
    "DHTMonitorWidget",
    "SettingsDialog",
]
