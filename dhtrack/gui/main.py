"""
Main window for the DHT Network Inspector.

Provides the main application window with tabs for:
- Dashboard: Network overview and statistics
- Routing Table: K-bucket visualization
- Peer Store: Peer management and inspection
- kRPC Console: Interactive DHT console
- Peer Scope: Per-endpoint wire tail, outbound shortcuts, swarm hints from passive queries
- Traffic Monitor: Real-time traffic stats
- Torrent Manager: Registered torrents, queue, and payloads
"""

from __future__ import annotations

import binascii
import dataclasses
import logging
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from dhtrack.dht import DEFAULT_BOOTSTRAP_NODES, DHTNode
from dhtrack.dht_manager import DHTManager
from dhtrack.gui import settings as gui_settings
from dhtrack.gui.inspector_session import InspectorSession
from dhtrack.swarm import SwarmManager
from dhtrack.torrent_track import TorrentManager

# Import widgets
try:
    from dhtrack.gui.widgets.bootstrap_overlay import BootstrapOverlay
    from dhtrack.gui.widgets.download_manager_widget import DownloadManagerWidget
    from dhtrack.gui.widgets.krpc_console import KRPConsoleWidget
    from dhtrack.gui.widgets.node_expert_dashboard import NodeExpertDashboard
    from dhtrack.gui.widgets.peer_endpoint_scope import PeerEndpointScopeWidget
    from dhtrack.gui.widgets.peer_store import PeerStoreWidget
    from dhtrack.gui.widgets.routing_table import RoutingTableWidget
    from dhtrack.gui.widgets.settings_dialog import SettingsDialog
    from dhtrack.gui.widgets.swarm_tracker import SwarmTrackerWidget
    from dhtrack.gui.widgets.torrent_manager_widget import TorrentManagerWidget
    from dhtrack.gui.widgets.torrent_resolver import TorrentResolverWidget
    from dhtrack.gui.widgets.traffic_monitor import TrafficMonitorWidget
    from dhtrack.gui.workspace_shell import MainWorkspaceShell
except ImportError as e:
    print(f"Failed to import GUI widgets: {e}")
    sys.exit(1)

logger = logging.getLogger("dhtrack.gui")


def _load_gui_window_icon() -> QIcon | None:
    res = Path(__file__).resolve().parent / "resources"
    for name in ("app_icon.ico", "app_icon.png"):
        path = res / name
        if path.is_file():
            return QIcon(str(path))
    return None


# Sidebar labels — order must match `_create_tabs` assembly (no-node placeholders use same list).
_WORKSPACE_PAGE_TITLES: tuple[str, ...] = (
    "Overview",
    "Routing table",
    "Peer store",
    "kRPC console",
    "Peer scope",
    "Traffic monitor",
    "Swarm tracker",
    "Torrent manager",
    "Download manager",
    "Swarm inspector",
)


class PlaceholderWidget(QWidget):
    """A placeholder widget shown when no DHT node is available."""

    def __init__(self, message: str = "Start or connect to a DHT node to view this section."):
        super().__init__()
        layout = QVBoxLayout(self)
        label = QLabel(message)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet(
            "color: #89b4fa; font-size: 16px; font-weight: bold; "
            "font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;"
        )
        layout.addWidget(label)


class DHTInspectorWindow(QMainWindow):
    """Main window for the DHT Network Inspector."""

    # Emitted from :meth:`schedule_blocking_manager_start` worker; slots run on GUI thread.
    _sig_manager_started = pyqtSignal()
    _sig_manager_start_failed = pyqtSignal(object)
    # marshal hide / status updates from asyncio Future callbacks (non-GUI thread)
    _sig_hide_bootstrap_overlay = pyqtSignal()
    _sig_status_label_text = pyqtSignal(str)

    def __init__(self, dht_node: DHTNode | None = None):
        super().__init__()
        win_icon = _load_gui_window_icon()
        if win_icon is not None:
            self.setWindowIcon(win_icon)
        self.dht_node: DHTNode | None = None
        self._node_running = False
        self._start_time: float | None = None
        self._bootstrap_overlay: BootstrapOverlay | None = None
        self._debug_logging_enabled = False
        self._dht_manager: DHTManager | None = None
        self._pending_manager_start: (
            tuple[
                DHTManager,
                Callable[[], None],
                Callable[[BaseException], None],
            ]
            | None
        ) = None
        # Store callback references for later wiring
        self._outgoing_callback: callable | None = None
        self._incoming_callback: callable | None = None
        # Persisted settings (loaded by run_gui() before construction; this
        # default keeps the window usable when constructed standalone).
        self._gui_settings: gui_settings.GuiSettings = gui_settings.load()
        self._shared_swarm_manager: SwarmManager | None = None
        self._shared_torrent_manager: TorrentManager | None = None
        self.workspace_shell: MainWorkspaceShell | None = None
        self.dht_monitor_tab: Any | None = None

        self.setWindowTitle("dhtrack — DHT expert inspector")
        self.setMinimumSize(1024, 600)
        self.resize(1280, 800)

        # Create and setup bootstrap overlay
        self._setup_bootstrap_overlay()

        # Load stylesheet
        self._load_stylesheet()

        # Create central widget
        self._setup_central_widget()

        # Create menu bar
        self._setup_menubar()

        # Create status bar
        self._setup_statusbar()

        self._sig_manager_started.connect(self._deliver_manager_start_ok)
        self._sig_manager_start_failed.connect(self._deliver_manager_start_failed)
        self._sig_hide_bootstrap_overlay.connect(self.hide_bootstrap_overlay)
        self._sig_status_label_text.connect(self.status_label.setText)

        # If a node was provided, attach to it
        if dht_node is not None:
            self.attach_to_node(dht_node)

    def _ensure_registry_managers(self) -> tuple[SwarmManager, TorrentManager]:
        """Lazily create session-scoped swarm + torrent registries (survive tab rebuilds)."""
        if self._shared_swarm_manager is None:
            self._shared_swarm_manager = SwarmManager()
            lib_dir = gui_settings.resolved_torrent_library_directory(self._gui_settings)
            self._shared_torrent_manager = TorrentManager(
                self._shared_swarm_manager,
                torrent_library_directory=lib_dir,
            )
            try:
                n = self._shared_torrent_manager.load_saved_metainfo_from_disk()
                if n > 0:
                    logger.info("Loaded %d torrent library file(s) from %s", n, lib_dir)
            except Exception as exc:
                logger.warning("Torrent library startup scan failed: %s", exc)
        assert self._shared_torrent_manager is not None
        return self._shared_swarm_manager, self._shared_torrent_manager

    def schedule_blocking_manager_start(
        self,
        manager: DHTManager,
        on_ready: Callable[[], None],
        on_error: Callable[[BaseException], None],
    ) -> None:
        """Run :meth:`DHTManager.start` on a worker thread; invoke callbacks on the GUI thread.

        ``QTimer.singleShot`` from a worker does **not** marshal to the GUI thread; we use
        ``pyqtSignal`` so Qt queues ``on_ready`` / ``on_error`` onto this window's thread.
        """
        if self._pending_manager_start is not None:
            logger.warning("Replacing pending DHTManager.start job (overlapping schedule)")
        self._pending_manager_start = (manager, on_ready, on_error)

        def _work() -> None:
            try:
                manager.start()
            except BaseException as exc:
                logger.exception("DHTManager.start failed")
                self._sig_manager_start_failed.emit(exc)
                return
            self._sig_manager_started.emit()

        threading.Thread(target=_work, daemon=True, name="dhtrack-dhtmgr-start").start()

    def _deliver_manager_start_ok(self) -> None:
        pending = self._pending_manager_start
        if pending is None:
            return
        _mgr, on_ready, _on_err = pending
        self._pending_manager_start = None
        try:
            on_ready()
        except Exception:
            logger.exception("GUI on_ready after DHTManager.start")

    def _deliver_manager_start_failed(self, exc: object) -> None:
        pending = self._pending_manager_start
        if pending is None:
            return
        _mgr, _on_ok, on_error = pending
        self._pending_manager_start = None
        base_exc = exc if isinstance(exc, BaseException) else RuntimeError(repr(exc))
        try:
            on_error(base_exc)
        except Exception:
            logger.exception("GUI on_error after DHTManager.start failure")

    def _load_stylesheet(self) -> None:
        """Load the dark theme stylesheet."""
        try:
            style_path = str(__file__).rsplit("/", 1)[0] + "/styles/dark_theme.qss"
            with open(style_path) as f:
                self.setStyleSheet(f.read())
        except (FileNotFoundError, OSError):
            # Fallback to basic styling
            self.setStyleSheet("")

    def _setup_central_widget(self) -> None:
        """Set up the main layout."""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top control bar
        control_frame = QFrame()
        control_frame.setObjectName("controlBar")
        control_frame.setStyleSheet(
            "QFrame#controlBar { background-color: #181825; border-bottom: 1px solid #313244; padding: 6px; }"
        )
        control_layout = QHBoxLayout(control_frame)
        control_layout.setSpacing(8)

        # Node connection controls
        connect_grp = QHBoxLayout()

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Bootstrap host (optional)")
        self.host_input.setText("")
        connect_grp.addWidget(self.host_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port")
        self.port_input.setText("6881")
        connect_grp.addWidget(self.port_input)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self._on_connect)
        connect_grp.addWidget(self.connect_btn)

        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.setEnabled(False)
        self.disconnect_btn.clicked.connect(self._on_disconnect)
        connect_grp.addWidget(self.disconnect_btn)

        control_layout.addLayout(connect_grp)
        control_layout.addSpacing(16)

        # Bootstrap nodes
        bootstrap_grp = QHBoxLayout()
        bootstrap_grp.addWidget(QLabel("Bootstrap:"))
        self.bootstrap_check = QComboBox()
        self.bootstrap_check.addItems(["Default", "Custom"])
        bootstrap_grp.addWidget(self.bootstrap_check)
        control_layout.addLayout(bootstrap_grp)
        control_layout.addSpacing(16)

        # Bind port
        bind_grp = QHBoxLayout()
        bind_grp.addWidget(QLabel("Bind Port:"))
        self.bind_port_input = QLineEdit()
        self.bind_port_input.setText("0")
        bind_grp.addWidget(self.bind_port_input)
        control_layout.addLayout(bind_grp)
        control_layout.addSpacing(16)

        # Start button
        self.start_btn = QPushButton("Start DHT Node")
        self.start_btn.clicked.connect(self._on_start_node)
        control_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop_node)
        control_layout.addWidget(self.stop_btn)

        control_layout.addSpacing(16)

        # Debug logging toggle
        self.debug_log_btn = QPushButton("Debug Log: OFF")
        self.debug_log_btn.setCheckable(True)
        self.debug_log_btn.clicked.connect(self._on_toggle_debug_logging)
        self.debug_log_btn.setStyleSheet(
            "QPushButton { "
            "background-color: #2d2d2d; "
            "color: #e0e0e0; "
            "border: 1px solid #3d3d3d; "
            "border-radius: 3px; "
            "padding: 4px 10px; "
            "font-size: 11px; "
            "font-weight: bold; "
            "} "
            "QPushButton:checked { "
            "background-color: #3a1a1a; "
            "color: #ff6b6b; "
            "border: 1px solid #ff6b6b; "
            "} "
            "QPushButton:!checked { "
            "background-color: #1a2d1a; "
            "color: #6bff6b; "
            "border: 1px solid #3d3d3d; "
            "}"
        )
        control_layout.addWidget(self.debug_log_btn)

        control_layout.addSpacing(12)
        ctl_posture_label = QLabel("DHT scrape:")
        ctl_posture_label.setStyleSheet("color: #a6adc8; font-size: 11px;")
        control_layout.addWidget(ctl_posture_label)
        self._radio_probe = QRadioButton("Probe")
        self._radio_observe = QRadioButton("Observe")
        for _rb in (self._radio_probe, self._radio_observe):
            _rb.setStyleSheet("color: #cdd6f4; font-size: 11px;")
        self._dht_posture_group = QButtonGroup(self)
        self._dht_posture_group.setExclusive(True)
        self._dht_posture_group.addButton(self._radio_probe)
        self._dht_posture_group.addButton(self._radio_observe)
        self._radio_probe.setChecked(True)
        self._radio_observe.toggled.connect(self._on_observe_posture_toggled)
        self._radio_probe.toggled.connect(self._on_probe_posture_toggled)
        control_layout.addWidget(self._radio_probe)
        control_layout.addWidget(self._radio_observe)

        control_layout.addStretch()

        main_layout.addWidget(control_frame)

        self.workspace_shell = MainWorkspaceShell()
        main_layout.addWidget(self.workspace_shell, 1)

        # Create initial placeholder pages (no node yet)
        self._create_tabs()

    def _on_observe_posture_toggled(self, checked: bool) -> None:
        if not checked:
            return
        self._apply_dht_posture_observe()

    def _on_probe_posture_toggled(self, checked: bool) -> None:
        if not checked:
            return
        self._apply_dht_posture_probe()

    def _apply_dht_posture_observe(self, *, announce: bool = True) -> None:
        obs = dataclasses.replace(
            self._gui_settings,
            dht_get_peers_scrape_qps=0.0,
            dht_get_peers_scrape_burst=0.0,
            dht_get_peers_scrape_max_inflight=0,
        )
        try:
            gui_settings.apply_to_runtime(obs, node=self.dht_node, manager=self._dht_manager)
        except Exception as exc:
            logger.warning("Observe posture apply failed: %s", exc)
            if announce:
                self.status_label.setText(f"Observe mode apply failed: {exc}")
            return
        if announce:
            self.status_label.setText("DHT posture: Observe (get_peers scrape minimized)")

    def _apply_dht_posture_probe(self, *, announce: bool = True) -> None:
        try:
            gui_settings.apply_to_runtime(
                self._gui_settings,
                node=self.dht_node,
                manager=self._dht_manager,
            )
        except Exception as exc:
            logger.warning("Probe posture apply failed: %s", exc)
            if announce:
                self.status_label.setText(f"Probe mode apply failed: {exc}")
            return
        if announce:
            self.status_label.setText("DHT posture: Probe (Preferences values)")

    def _create_tabs(self) -> None:
        """Populate workspace sidebar + stacked pages."""
        shell = self.workspace_shell
        if shell is None:
            return

        self.dht_monitor_tab = None

        if self.dht_node is None:
            pages: list[tuple[str, QWidget]] = [
                (title, PlaceholderWidget(f"{title}: start or attach a DHT node to use this workspace."))
                for title in _WORKSPACE_PAGE_TITLES
            ]
            shell.set_pages(pages)
            self.dashboard_tab = None
            return

        pages: list[tuple[str, QWidget]] = []

        try:
            node_dashboard = NodeExpertDashboard(self.dht_node)
            self.dashboard_tab = node_dashboard.overview_tab
            self.dht_monitor_tab = node_dashboard.monitor_tab
            overview_page: QWidget = node_dashboard
        except Exception as e:
            logger.warning("Failed to create node expert dashboard: %s", e)
            self.dashboard_tab = None
            self.dht_monitor_tab = None
            overview_page = PlaceholderWidget(f"Failed to create Overview: {e}")
        pages.append(("Overview", overview_page))

        try:
            self.routing_tab = RoutingTableWidget(self.dht_node)
            routing_page: QWidget = self.routing_tab
        except Exception as e:
            logger.warning(f"Failed to create routing table: {e}")
            self.routing_tab = PlaceholderWidget("Failed to create routing table: " + str(e))
            routing_page = self.routing_tab
        pages.append(("Routing table", routing_page))

        try:
            self.peer_tab = PeerStoreWidget(self.dht_node)
            self.peer_tab._refresh()
            peer_page: QWidget = self.peer_tab
        except Exception as e:
            logger.warning(f"Failed to create peer store: {e}")
            self.peer_tab = PlaceholderWidget("Failed to create peer store: " + str(e))
            peer_page = self.peer_tab
        pages.append(("Peer store", peer_page))

        try:
            self.console_tab = KRPConsoleWidget(self.dht_node)
            console_page: QWidget = self.console_tab
        except Exception as e:
            logger.warning(f"Failed to create console: {e}")
            self.console_tab = PlaceholderWidget("Failed to create console: " + str(e))
            console_page = self.console_tab
        pages.append(("kRPC console", console_page))

        try:
            self.peer_scope_tab = PeerEndpointScopeWidget(self.dht_node)
            peer_scope_page: QWidget = self.peer_scope_tab
        except Exception as e:
            logger.warning(f"Failed to create peer scope: {e}")
            self.peer_scope_tab = PlaceholderWidget("Failed to create Peer Scope: " + str(e))
            peer_scope_page = self.peer_scope_tab
        pages.append(("Peer scope", peer_scope_page))

        try:
            self.traffic_tab = TrafficMonitorWidget(self.dht_node)
            traffic_page: QWidget = self.traffic_tab
        except Exception as e:
            logger.warning(f"Failed to create traffic monitor: {e}")
            self.traffic_tab = PlaceholderWidget("Failed to create traffic monitor: " + str(e))
            traffic_page = self.traffic_tab
        pages.append(("Traffic monitor", traffic_page))

        try:
            resolver_ref = getattr(self, "_dht_manager", None) or self.dht_node
            swarm_mgr, torrent_mgr = self._ensure_registry_managers()
            inspector_session = InspectorSession(
                swarm_manager=swarm_mgr,
                torrent_manager=torrent_mgr,
            )
            self.resolver_tab = TorrentResolverWidget(resolver_ref, inspector_session)
            self.swarm_tracker_tab = SwarmTrackerWidget(
                swarm_mgr,
                before_remove_swarm=self.resolver_tab.teardown_swarm_workers,
            )
            self.swarm_tracker_tab.registry_changed.connect(self.resolver_tab.reload_swarm_combo)
            self.resolver_tab.swarm_list_changed.connect(self.swarm_tracker_tab.refresh_table)
            self.torrent_manager_tab = TorrentManagerWidget(inspector_session, self.resolver_tab)
            self.download_manager_tab = DownloadManagerWidget(inspector_session, self.resolver_tab)
            self.resolver_tab.torrent_jobs_changed.connect(self.torrent_manager_tab.refresh_from_manager)
            self.resolver_tab.torrent_jobs_changed.connect(self.download_manager_tab.refresh_from_manager)
            swarm_tracker_page: QWidget = self.swarm_tracker_tab
            torrent_manager_page: QWidget = self.torrent_manager_tab
            download_manager_page: QWidget = self.download_manager_tab
            swarm_inspector_page: QWidget = self.resolver_tab
        except Exception as e:
            logger.warning(f"Failed to create swarm tracker / inspector: {e}")
            self.swarm_tracker_tab = PlaceholderWidget(
                "Failed to create swarm tracker: " + str(e),
            )
            self.resolver_tab = PlaceholderWidget("Failed to create resolver: " + str(e))
            try:
                swarm_mgr_fallback, torrent_mgr_fallback = self._ensure_registry_managers()
                inspector_session_fallback = InspectorSession(
                    swarm_manager=swarm_mgr_fallback,
                    torrent_manager=torrent_mgr_fallback,
                )
                self.torrent_manager_tab = TorrentManagerWidget(
                    inspector_session_fallback,
                    None,
                )
                self.download_manager_tab = DownloadManagerWidget(
                    inspector_session_fallback,
                    None,
                )
            except Exception:
                self.torrent_manager_tab = PlaceholderWidget(
                    "Failed to create Torrent Manager: " + str(e),
                )
                self.download_manager_tab = PlaceholderWidget(
                    "Failed to create Download manager: " + str(e),
                )
            swarm_tracker_page = self.swarm_tracker_tab
            torrent_manager_page = self.torrent_manager_tab
            download_manager_page = self.download_manager_tab
            swarm_inspector_page = self.resolver_tab
        pages.append(("Swarm tracker", swarm_tracker_page))
        pages.append(("Torrent manager", torrent_manager_page))
        pages.append(("Download manager", download_manager_page))
        pages.append(("Swarm inspector", swarm_inspector_page))

        shell.set_pages(pages)

        if self._radio_observe.isChecked():
            self._apply_dht_posture_observe(announce=False)

    def _setup_bootstrap_overlay(self) -> None:
        """Set up the bootstrap overlay widget."""
        self._bootstrap_overlay = BootstrapOverlay(self)
        self._bootstrap_overlay.hide()

    def show_bootstrap_overlay(self) -> None:
        """Show the bootstrap overlay."""
        if self._bootstrap_overlay:
            self._bootstrap_overlay.show_overlay()

    def hide_bootstrap_overlay(self) -> None:
        """Hide the bootstrap overlay."""
        if self._bootstrap_overlay:
            self._bootstrap_overlay.hide_overlay()

    def update_bootstrap_progress(
        self,
        phase: str,
        depth: int,
        nodes_queried: int,
        nodes_discovered: int,
        min_xor_distance: int,
        total_nodes: int,
        elapsed: float = 0.0,
    ) -> None:
        """Update the bootstrap progress display."""
        if self._bootstrap_overlay:
            if hasattr(self, "dht_node") and self.dht_node:
                ipv4_count = sum(len(b.nodes) for b in self.dht_node.routing_table.v4.buckets)
                ipv6_count = sum(len(b.nodes) for b in self.dht_node.routing_table.v6.buckets)
                bucket_count = len(self.dht_node.routing_table.v4.buckets) + len(self.dht_node.routing_table.v6.buckets)
                active_buckets = sum(1 for b in self.dht_node.routing_table.v4.buckets if b.nodes) + sum(
                    1 for b in self.dht_node.routing_table.v6.buckets if b.nodes
                )
            else:
                ipv4_count = 0
                ipv6_count = 0
                bucket_count = 0
                active_buckets = 0

            self._bootstrap_overlay.update_progress(
                phase=phase,
                depth=depth,
                nodes_queried=nodes_queried,
                nodes_discovered=nodes_discovered,
                min_xor_distance=min_xor_distance,
                total_nodes=total_nodes,
                bucket_count=bucket_count,
                active_buckets=active_buckets,
                ipv4_nodes=ipv4_count,
                ipv6_nodes=ipv6_count,
            )

    def _setup_menubar(self) -> None:
        """Set up the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        save_peers_action = file_menu.addAction("&Save Peers")
        save_peers_action.triggered.connect(self._on_save_peers)
        save_peers_action.setShortcut("Ctrl+S")

        export_log_action = file_menu.addAction("&Export Traffic Log...")
        export_log_action.triggered.connect(self._on_export_log)
        export_log_action.setShortcut("Ctrl+E")

        file_menu.addSeparator()

        exit_action = file_menu.addAction("E&xit")
        exit_action.triggered.connect(self.close)
        exit_action.setShortcut("Ctrl+Q")

        # View menu
        view_menu = menubar.addMenu("&View")

        refresh_action = view_menu.addAction("&Refresh")
        refresh_action.triggered.connect(self._on_refresh)
        refresh_action.setShortcut("F5")

        view_menu.addSeparator()

        ping_action = view_menu.addAction("Ping &All Questionable")
        ping_action.triggered.connect(self._on_ping_questionable)
        ping_action.setShortcut("Ctrl+P")

        # DHT menu
        dht_menu = menubar.addMenu("&DHT")

        bootstrap_action = dht_menu.addAction("&Bootstrap Nodes")
        bootstrap_action.triggered.connect(self._on_bootstrap)

        find_random_action = dht_menu.addAction("Find &Nodes (Random ID)")
        find_random_action.triggered.connect(self._on_find_random)

        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        prefs_action = tools_menu.addAction("&Preferences\u2026")
        prefs_action.setShortcut("Ctrl+,")
        prefs_action.triggered.connect(self._on_preferences)

        # About menu
        about_menu = menubar.addMenu("&Help")

        about_action = about_menu.addAction("&About")
        about_action.triggered.connect(self._on_about)

        try:
            about_qt_action = about_menu.addAction("About Qt")
            about_qt_action.triggered.connect(QApplication.aboutQt)
        except Exception:
            pass  # About Qt may not be available in all environments

    def _setup_statusbar(self) -> None:
        """Set up the status bar."""
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #a6adc8;")
        self.statusBar().addWidget(self.status_label, 0)

        self.node_id_label = QLabel("")
        self.node_id_label.setStyleSheet("color: #89b4fa;")
        self.statusBar().addWidget(self.node_id_label, 0)

        self.peer_count_label = QLabel("Peers: 0")
        self.statusBar().addPermanentWidget(self.peer_count_label, 0)

        self.bucket_count_label = QLabel("Buckets: 0")
        self.statusBar().addPermanentWidget(self.bucket_count_label, 0)

    def attach_to_node(self, node: DHTNode) -> None:
        """Attach the GUI to an existing DHTNode.

        Parameters
        ----------
        node : DHTNode
            The DHT node to attach to.
        """
        self.dht_node = node
        self._start_time = time.time()

        # Update UI with node info
        node_id_hex = binascii.b2a_hex(node.node_id).decode("ascii")
        self.node_id_label.setText(f"Node: {node_id_hex[:16]}...")

        # Re-create tabs with the node reference (must happen BEFORE wiring callbacks)
        self._create_tabs()

        # Wire up GUI callbacks on the DHT node (after tabs exist)
        self._wire_up_callbacks()

        self.status_label.setText("Attached to DHT node")

    def _wire_up_callbacks(self) -> None:
        """Connect DHT node callbacks to GUI update methods.

        The callbacks use lambda closures that capture self, so they can
        dynamically look up self.console_tab and self.traffic_tab at call
        time (when the tabs may have been created after this function runs).
        """
        if self.dht_node is None:
            return

        win = self

        # Wire-level datagram callback - invokes a console method to display
        # wire traces so they appear in the kRPC Console tab.
        def on_wire_message(
            direction: str,
            addr: tuple,
            size: int,
            hex_str: str,
            decode_status: str,
            decode_repr: str,
            txid_hex: str,
            method: str,
            note: str = "",
        ) -> None:
            try:
                ip_addr, pt = addr[0], addr[1]
                looks_v6 = ip_addr.count(":") > 1
                console = getattr(win, "console_tab", None)
                if console is not None and hasattr(console, "on_wire_message"):
                    console.on_wire_message(
                        direction,
                        ip_addr,
                        pt,
                        looks_v6,
                        size,
                        hex_str,
                        decode_status,
                        decode_repr,
                        txid_hex,
                        method,
                        note,
                    )
                peer_scope = getattr(win, "peer_scope_tab", None)
                if peer_scope is not None and hasattr(peer_scope, "marshal_wire_tail"):
                    from PyQt6.QtCore import QTimer

                    QTimer.singleShot(
                        0,
                        lambda: peer_scope.marshal_wire_tail(
                            direction=direction,
                            ip=str(ip_addr),
                            port=int(pt),
                            is_ipv6=looks_v6,
                            size=int(size),
                            hex_str=hex_str,
                            decode_status=decode_status,
                            decode_repr=decode_repr,
                            txid_hex=txid_hex,
                            method=method,
                            note=note,
                        ),
                    )
            except Exception:
                pass

        # Bootstrap progress callback
        def on_bootstrap_progress(
            phase: str,
            depth: int,
            nodes_queried: int,
            nodes_discovered: int,
            min_xor_distance: int,
            total_nodes: int,
            elapsed: float,
        ) -> None:
            # Use QTimer to update GUI from background thread
            try:
                from PyQt6.QtCore import QTimer

                QTimer.singleShot(
                    0,
                    win.update_bootstrap_progress,
                    phase,
                    depth,
                    nodes_queried,
                    nodes_discovered,
                    min_xor_distance,
                    total_nodes,
                    elapsed,
                )
            except Exception:
                pass

        # Outgoing message callback - invoked from DHT background thread
        def on_outgoing(msg_type: str, ip: str, port: int, is_ipv6: bool, size: int) -> None:
            try:
                # Update kRPC console
                console = getattr(win, "console_tab", None)
                if console is not None and hasattr(console, "on_outgoing_message"):
                    console.on_outgoing_message(msg_type, ip, port, is_ipv6)
                # Update traffic monitor
                traffic = getattr(win, "traffic_tab", None)
                if traffic is not None and hasattr(traffic, "on_outgoing_message"):
                    traffic.on_outgoing_message(msg_type, size=size)
                # Update query count
                dashboard = getattr(win, "dashboard_tab", None)
                if dashboard is not None and hasattr(dashboard, "_query_count"):
                    dashboard._query_count += 1
            except Exception:
                pass

        # Incoming message callback - invoked from DHT background thread
        def on_incoming(
            msg_type: str, ip: str, port: int, is_ipv6: bool, size: int, txid: str = "", status: str = ""
        ) -> None:
            try:
                # Update kRPC console with full message details
                console = getattr(win, "console_tab", None)
                if console is not None and hasattr(console, "on_incoming_message"):
                    console.on_incoming_message(msg_type, ip, port, is_ipv6, txid, status)
                # Update traffic monitor
                traffic = getattr(win, "traffic_tab", None)
                if traffic is not None and hasattr(traffic, "on_incoming_message"):
                    traffic.on_incoming_message(msg_type, size=size)
                # Update response count
                dashboard = getattr(win, "dashboard_tab", None)
                if dashboard is not None and hasattr(dashboard, "_response_count"):
                    dashboard._response_count += 1
            except Exception:
                pass

        # Full message details callback for the console (includes full parsed info)
        def on_message_parsed_cb(ip: str, port: int, is_ipv6: bool, size: int, msg_info: dict) -> None:
            try:
                console = getattr(win, "console_tab", None)
                if console is not None and hasattr(console, "on_full_message"):
                    console.on_full_message(ip, port, is_ipv6, size, msg_info)
                peer_scope = getattr(win, "peer_scope_tab", None)
                if peer_scope is not None and hasattr(peer_scope, "ingest_message_parsed"):
                    direction = msg_info.get("direction", "")
                    dup_ps = dict(msg_info)

                    def _sink_ps() -> None:
                        peer_scope.ingest_message_parsed(
                            str(ip),
                            int(port),
                            bool(is_ipv6),
                            dup_ps,
                            direction=str(direction),
                        )

                    QTimer.singleShot(0, _sink_ps)

                dup_mon = dict(msg_info)

                def _sink_mon() -> None:
                    mon = getattr(win, "dht_monitor_tab", None)
                    if mon is not None and hasattr(mon, "on_message_parsed"):
                        try:
                            mon.on_message_parsed(ip, port, is_ipv6, size, dup_mon)
                        except Exception:
                            pass

                QTimer.singleShot(0, _sink_mon)
            except Exception:
                pass

        class _GuiEventSink:
            def __init__(self, outer: DHTInspectorWindow) -> None:
                self._outer = outer

            def on_outgoing_message(self, msg_type: str, dst_ip: str, dst_port: int, is_ipv6: bool, size: int) -> None:
                on_outgoing(msg_type, dst_ip, dst_port, is_ipv6, size)

            def on_incoming_message(
                self,
                msg_type: str,
                src_ip: str,
                src_port: int,
                is_ipv6: bool,
                size: int,
                *,
                txid: str = "",
                status: str = "",
            ) -> None:
                on_incoming(msg_type, src_ip, src_port, is_ipv6, size, txid, status)

            def on_status_update(
                self,
                *,
                total_peers: int,
                buckets_v4: int,
                nodes_v4: int,
                buckets_v6: int,
                nodes_v6: int,
            ) -> None:
                return

            def on_message_parsed(self, ip: str, port: int, is_ipv6: bool, size: int, msg_info: dict) -> None:
                on_message_parsed_cb(ip, port, is_ipv6, size, msg_info)

            def on_bootstrap_progress(
                self,
                *,
                phase: str,
                depth: int,
                nodes_queried: int,
                nodes_discovered: int,
                min_xor_distance: int,
                total_nodes: int,
                elapsed: float,
            ) -> None:
                on_bootstrap_progress(
                    phase,
                    depth,
                    nodes_queried,
                    nodes_discovered,
                    min_xor_distance,
                    total_nodes,
                    elapsed,
                )

            def on_observed_external_ip(self, *, family: str, ip: str, port: int) -> None:
                return

            def on_wire_message(
                self,
                *,
                direction: str,
                addr: tuple,
                size: int,
                hex_str: str,
                decode_status: str,
                decode_repr: str,
                txid_hex: str,
                method: str,
                note: str,
            ) -> None:
                on_wire_message(direction, addr, size, hex_str, decode_status, decode_repr, txid_hex, method, note)

        self.dht_node.event_sink = _GuiEventSink(self)  # type: ignore[assignment]

    def _teardown_partial_start(self) -> None:
        """Release node/manager after a failed GUI startup."""
        if self._dht_manager is not None:
            try:
                self._dht_manager.stop()
            except Exception:
                logger.debug("DHTManager.stop after failed start", exc_info=True)
            self._dht_manager = None
        elif self.dht_node is not None:
            try:
                self.dht_node.save_peers()
            except Exception:
                pass
            try:
                self.dht_node.close()
            except Exception:
                logger.debug("DHTNode.close after failed start", exc_info=True)
        self.dht_node = None
        self._node_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(False)

    def _on_connect(self) -> None:
        """Connect to a bootstrap node."""
        host = self.host_input.text()
        port_str = self.port_input.text()

        if not host or not port_str:
            self.status_label.setText("Enter host and port")
            return

        try:
            port = int(port_str)
        except ValueError:
            self.status_label.setText("Invalid port number")
            return

        bootstrap_nodes = [(host, port)]

        # Check if custom bootstrap
        if self.bootstrap_check.currentText() == "Custom":
            # Allow multiple custom nodes
            pass

        self.status_label.setText(f"Connecting to {host}:{port}...")

        if self.dht_node:
            if self._dht_manager is None:
                mgr = DHTManager(
                    node=self.dht_node,
                    peers_file=getattr(self.dht_node, "peers_file", "peers.dat"),
                )
                self._dht_manager = mgr

                def _connect_after_start() -> None:
                    try:
                        count = self.dht_node.bootstrap(bootstrap_nodes)
                        self.status_label.setText(f"Connected! {count} nodes contacted")
                    except Exception as e:
                        self.status_label.setText(f"Connection failed: {e}")

                def _connect_start_failed(exc: BaseException) -> None:
                    self.status_label.setText(f"Connection failed: {exc}")
                    logger.exception("DHTManager.start failed (connect path)")
                    try:
                        mgr.stop()
                    except Exception:
                        pass
                    self._dht_manager = None

                self.schedule_blocking_manager_start(mgr, _connect_after_start, _connect_start_failed)
            else:
                try:
                    count = self.dht_node.bootstrap(bootstrap_nodes)
                    self.status_label.setText(f"Connected! {count} nodes contacted")
                except Exception as e:
                    self.status_label.setText(f"Connection failed: {e}")
        else:
            self.status_label.setText("No DHT node attached")

    def _on_disconnect(self) -> None:
        """Disconnect from bootstrap nodes."""
        self.status_label.setText("Disconnected")

    def _on_start_node(self) -> None:
        """Start a new DHT node.

        Creates a DHTNode, loads peers, bootstraps with default nodes,
        then launches the async recursive bootstrap as a background task.
        """
        if self._node_running:
            return

        bind_port_str = self.bind_port_input.text()
        try:
            bind_port = int(bind_port_str) if bind_port_str else 0
        except ValueError:
            self.status_label.setText("Invalid bind port")
            return

        # Push current settings into module globals before constructing the
        # DHTNode so that path/identity-time settings take effect.
        try:
            gui_settings.apply_to_runtime(self._gui_settings)
        except Exception as exc:
            logger.warning("Failed to apply settings before node start: %s", exc)

        # Create DHT node and manager; blocking :meth:`DHTManager.start` runs off the GUI thread.
        try:
            self.dht_node = DHTNode(bind_addr=("0.0.0.0", bind_port))
            self._dht_manager = DHTManager(
                node=self.dht_node,
                peers_file=getattr(self.dht_node, "peers_file", "peers.dat"),
            )

            self.show_bootstrap_overlay()
            self.status_label.setText("Starting DHT (bind, peers, bootstrap)…")

            mgr = self._dht_manager

            def _manual_start_ready() -> None:
                try:
                    self._start_time = time.time()
                    try:
                        gui_settings.apply_to_runtime(
                            self._gui_settings,
                            node=self.dht_node,
                            manager=mgr,
                        )
                    except Exception as exc:
                        logger.warning("Failed to apply settings to live node: %s", exc)

                    self._wire_up_callbacks()
                    self.status_label.setText("DHT node up — deepening routing table…")
                    self.attach_to_node(self.dht_node)

                    bootstrap_nodes = DEFAULT_BOOTSTRAP_NODES
                    async_coro = self.dht_node.bootstrap_recursive(
                        bootstrap_nodes=bootstrap_nodes,
                        total_timeout=float(getattr(self._gui_settings, "bootstrap_total_timeout", 30.0)),
                        max_depth=int(getattr(self._gui_settings, "bootstrap_max_depth", 3)),
                    )
                    fut = mgr.run_coroutine(async_coro)

                    def _on_done(_fut):
                        try:
                            _ = _fut.result()
                        except Exception as exc:
                            logger.exception("bootstrap_recursive failed: %s", exc)
                            self._sig_status_label_text.emit(f"Bootstrap failed: {exc}")
                        finally:
                            self._sig_hide_bootstrap_overlay.emit()

                    fut.add_done_callback(_on_done)

                    self._node_running = True
                    self.start_btn.setEnabled(False)
                    self.stop_btn.setEnabled(True)
                    self.connect_btn.setEnabled(False)
                    self.disconnect_btn.setEnabled(True)
                    self.status_label.setText("DHT node started with recursive bootstrap")
                except Exception as e:
                    self.status_label.setText(f"Failed to start: {e}")
                    logger.exception("Post-start wiring failed")
                    self.hide_bootstrap_overlay()
                    self._teardown_partial_start()

            def _manual_start_failed(exc: BaseException) -> None:
                self.status_label.setText(f"Failed to start: {exc}")
                logger.exception("DHTManager.start failed (manual start)")
                self.hide_bootstrap_overlay()
                self._teardown_partial_start()

            self.schedule_blocking_manager_start(mgr, _manual_start_ready, _manual_start_failed)

        except Exception as e:
            self.status_label.setText(f"Failed to start: {e}")
            logger.exception("Failed to start DHT node")
            self.hide_bootstrap_overlay()

    def _on_stop_node(self) -> None:
        """Stop the DHT node."""
        if not self._node_running or not self.dht_node:
            return

        try:
            if self._dht_manager is not None:
                self._dht_manager.stop()
                self._dht_manager = None
            else:
                self.dht_node.save_peers()
                self.dht_node.close()
            self.dht_node = None
            self._node_running = False

            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(False)

            # Reset debug logging to OFF when node stops
            self._debug_logging_enabled = False
            self.debug_log_btn.setChecked(False)

            self.node_id_label.setText("")
            self.status_label.setText("DHT node stopped")

            # Recreate placeholder tabs
            self._create_tabs()

            # Hide bootstrap overlay
            self.hide_bootstrap_overlay()

        except Exception as e:
            self.status_label.setText(f"Stop failed: {e}")

    def _on_save_peers(self) -> None:
        """Save peers to file."""
        if self.dht_node:
            try:
                self.dht_node.save_peers()
                self.status_label.setText("Peers saved")
            except Exception as e:
                self.status_label.setText(f"Save failed: {e}")

    def _on_export_log(self) -> None:
        """Export traffic log to file."""
        if self.console_tab:
            self.console_tab._on_export_log()

    def _on_refresh(self) -> None:
        """Refresh the current view."""
        if self.dht_node:
            self.status_label.setText("Refreshed")

    def _on_ping_questionable(self) -> None:
        """Ping all questionable nodes."""
        if self.dht_node:
            count = 0
            for table in [self.dht_node.routing_table.v4, self.dht_node.routing_table.v6]:
                for bucket in table.buckets:
                    for node in bucket.nodes:
                        if node.status == "questionable":
                            peer_key = (node.endpoint.ip, node.endpoint.port)
                            if peer_key in self.dht_node.peers:
                                self.dht_node.peers[peer_key].ping()
                                count += 1
            self.status_label.setText(f"Pinged {count} nodes")

    def _on_bootstrap(self) -> None:
        """Bootstrap with default nodes."""
        if self.dht_node:
            try:
                count = self.dht_node.bootstrap()
                self.status_label.setText(f"Bootstrapped: {count} nodes contacted")
            except Exception as e:
                self.status_label.setText(f"Bootstrap failed: {e}")

    def _on_find_random(self) -> None:
        """Find nodes close to a random ID."""
        if self.dht_node:
            import os

            random_id = os.urandom(20)
            self.status_label.setText("Searching for random ID...")

            for table in [self.dht_node.routing_table.v4, self.dht_node.routing_table.v6]:
                closest = table.get_closest_nodes(random_id, 3)
                for node in closest:
                    peer_key = (node.endpoint.ip, node.endpoint.port)
                    if peer_key in self.dht_node.peers:
                        self.dht_node.peers[peer_key].find_node(random_id)

            self.status_label.setText(f"Searched {len(closest)} nodes")

    def _on_preferences(self) -> None:
        """Open the Preferences dialog and apply / persist on accept."""
        dlg = SettingsDialog(self._gui_settings, parent=self)

        def _apply(new_settings: gui_settings.GuiSettings) -> None:
            self._gui_settings = new_settings
            if self._shared_torrent_manager is not None:
                self._shared_torrent_manager.set_torrent_library_directory(
                    gui_settings.resolved_torrent_library_directory(new_settings),
                )
            try:
                effective = new_settings
                if self._radio_observe.isChecked():
                    effective = dataclasses.replace(
                        new_settings,
                        dht_get_peers_scrape_qps=0.0,
                        dht_get_peers_scrape_burst=0.0,
                        dht_get_peers_scrape_max_inflight=0,
                    )
                gui_settings.apply_to_runtime(
                    effective,
                    node=self.dht_node,
                    manager=self._dht_manager,
                )
            except Exception as exc:
                logger.exception("Failed to apply settings: %s", exc)
                self.status_label.setText(f"Apply failed: {exc}")
                return
            try:
                gui_settings.save(new_settings)
            except Exception as exc:
                logger.exception("Failed to save settings: %s", exc)
                self.status_label.setText(f"Saved settings to memory only: {exc}")
                return
            self.status_label.setText("Settings applied")

        dlg.settingsApplied.connect(_apply)
        dlg.exec()

    def _on_about(self) -> None:
        """Show about dialog."""
        from PyQt6.QtWidgets import QMessageBox

        QMessageBox.about(
            self,
            "About DHT Network Inspector",
            "<h3>DHT Network Inspector</h3>"
            "<p>Version 0.1.0</p>"
            "<p>A graphical interface for examining the BitTorrent "
            "DHT (Distributed Hash Table) network.</p>"
            "<p>Features:</p>"
            "<ul>"
            "<li>Network overview and statistics</li>"
            "<li>K-bucket routing table visualization</li>"
            "<li>Peer store management</li>"
            "<li>Interactive kRPC console</li>"
            "<li>Real-time traffic monitoring</li>"
            "</ul>"
            "<p>Powered by PyQt6 and the dhtrack library.</p>",
        )

    def _on_toggle_debug_logging(self) -> None:
        """Toggle debug-level logging for all dhtrack modules and the wire logger.

        When enabled, the button becomes checked and all dhtrack loggers
        are set to DEBUG level so that wire-level datagram traces and
        debug output appear in the console.  When disabled, loggers
        revert to WARNING level.
        """
        self._debug_logging_enabled = not self._debug_logging_enabled
        self.debug_log_btn.setChecked(self._debug_logging_enabled)

        # Update all dhtrack loggers
        for name in ["dhtrack", "dhtrack.dht", "dhtrack.wire", "dhtrack.bencode", "dhtrack.bep53", "dhtrack.torrent"]:
            logger_obj = logging.getLogger(name)
            if self._debug_logging_enabled:
                logger_obj.setLevel(logging.DEBUG)
            else:
                logger_obj.setLevel(logging.WARNING)

        # Update root dhtrack logger too
        root_dhtrack = logging.getLogger("dhtrack")
        if self._debug_logging_enabled:
            root_dhtrack.setLevel(logging.DEBUG)
        else:
            root_dhtrack.setLevel(logging.WARNING)

        status = "ENABLED" if self._debug_logging_enabled else "DISABLED"
        self.status_label.setText(f"Debug logging {status}")

    def update_status_bar(self) -> None:
        """Update the status bar with current state."""
        if not self.dht_node:
            return

        # Update peer count
        total_peers = len(self.dht_node.peers)
        for table in [self.dht_node.routing_table.v4, self.dht_node.routing_table.v6]:
            for bucket in table.buckets:
                total_peers += len(bucket.nodes)

        self.peer_count_label.setText(f"Peers: {total_peers}")

        # Update bucket count
        total_buckets = len(self.dht_node.routing_table.v4.buckets) + len(self.dht_node.routing_table.v6.buckets)
        self.bucket_count_label.setText(f"Buckets: {total_buckets}")

        # Update status bar text
        uptime_text = ""
        if self._start_time:
            elapsed = time.time() - self._start_time
            if elapsed < 60:
                uptime_text = f"{elapsed:.0f}s"
            elif elapsed < 3600:
                uptime_text = f"{elapsed / 60:.1f}m"
            else:
                uptime_text = f"{elapsed / 3600:.2f}h"

        self.statusBar().showMessage(f"Uptime: {uptime_text} | Peers: {total_peers} | Buckets: {total_buckets}")

    def timer_update(self) -> None:
        """Periodic timer update."""
        if self.dht_node:
            self.update_status_bar()


def run_gui() -> None:
    """Launch the DHT Network Inspector GUI.

    Creates and runs the main application window.  On launch, a new DHT node
    is created and the recursive bootstrap process is started automatically
    with the bootstrap overlay visible.
    """
    app = QApplication.instance() or QApplication(sys.argv)
    app_icon = _load_gui_window_icon()
    if app_icon is not None:
        app.setWindowIcon(app_icon)

    # Load persisted settings BEFORE constructing the DHTNode/DHTManager so
    # path-time settings (peers_file, bind_port, persist_node_identity, etc.)
    # take effect.
    persisted = gui_settings.load()
    try:
        gui_settings.apply_to_runtime(persisted)
    except Exception as exc:
        logger.warning("Failed to apply persisted settings: %s", exc)

    # Create window
    window = DHTInspectorWindow()
    window._gui_settings = persisted
    window.show()
    QApplication.processEvents()

    manager = DHTManager(peers_file=persisted.peers_file or "peers.dat")

    def _on_startup_ready() -> None:
        try:
            window._start_time = time.time()
            window._node_running = True
            window._dht_manager = manager
            try:
                gui_settings.apply_to_runtime(persisted, node=manager.node, manager=manager)
            except Exception as exc:
                logger.warning("Failed to apply settings to live node: %s", exc)

            window.show_bootstrap_overlay()
            window.status_label.setText("DHT node started — deepening routing table…")
            window.attach_to_node(manager.node)

            bootstrap_nodes = DEFAULT_BOOTSTRAP_NODES
            fut = manager.run_coroutine(
                window.dht_node.bootstrap_recursive(
                    bootstrap_nodes=bootstrap_nodes,
                    total_timeout=float(getattr(persisted, "bootstrap_total_timeout", 30.0)),
                    max_depth=int(getattr(persisted, "bootstrap_max_depth", 3)),
                )
            )

            def _bootstrap_recursive_done(_f: object) -> None:
                fut = _f  # concurrent.futures.Future
                try:
                    fut.result()
                except Exception as exc:
                    logger.exception("bootstrap_recursive failed")
                    window._sig_status_label_text.emit(f"Bootstrap failed: {exc}")
                finally:
                    window._sig_hide_bootstrap_overlay.emit()

            fut.add_done_callback(_bootstrap_recursive_done)
            window.status_label.setText("DHT manager ready")
        except Exception as e:
            window.status_label.setText(f"Failed to start: {e}")
            logger.exception("Failed after DHTManager.start")
            window.hide_bootstrap_overlay()
            window._dht_manager = None
            window._node_running = False

    def _on_startup_failed(exc: BaseException) -> None:
        window.status_label.setText(f"Failed to start: {exc}")
        logger.exception("Failed to start DHT node")
        window.hide_bootstrap_overlay()
        try:
            manager.stop()
        except Exception:
            pass
        window._dht_manager = None
        window._node_running = False

    window.status_label.setText("Starting DHT (loading peers and bootstrap)…")
    window.show_bootstrap_overlay()
    window.schedule_blocking_manager_start(manager, _on_startup_ready, _on_startup_failed)

    # Store manager reference on the window so widgets can access it
    # (run_gui creates the manager after the window exists)

    # Single timer for all periodic updates
    timer = QTimer()
    timer.timeout.connect(window.timer_update)
    timer.start(2000)  # Update every 2 seconds

    app.exec()


if __name__ == "__main__":
    run_gui()
