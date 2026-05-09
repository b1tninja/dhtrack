"""
Settings dialog for the DHT Network Inspector.

Provides a tabbed ``QDialog`` for editing every tunable exposed by
:mod:`dhtrack.gui.settings`.  Most fields apply live; a few are baked in
at construction time (paths, bind port, uTP/QUIC packet sizes) and are
labelled with a "(restart)" badge.

The dialog signals ``settingsApplied(GuiSettings)`` whenever Apply or OK
is pressed, allowing the host window to call
:func:`dhtrack.gui.settings.apply_to_runtime` and persist via
:func:`dhtrack.gui.settings.save`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, fields, replace
from pathlib import Path
from typing import Any

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from dhtrack.gui.settings import GuiSettings

logger = logging.getLogger(__name__)


_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _restart_badge() -> QLabel:
    """Return a small yellow label indicating the field needs a node restart."""
    badge = QLabel("(restart)")
    badge.setToolTip("Takes effect when the DHT node is next started")
    badge.setStyleSheet(
        "color: #f9e2af; font-size: 10px; font-weight: bold; "
        "background-color: #2a2517; border: 1px solid #6b5e25; "
        "border-radius: 3px; padding: 0 4px;"
    )
    return badge


def _wrap_with_badge(widget: QWidget, restart: bool) -> QWidget:
    """Return ``widget``, optionally followed by a "(restart)" badge."""
    if not restart:
        return widget
    container = QWidget()
    h = QHBoxLayout(container)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(6)
    h.addWidget(widget, 1)
    h.addWidget(_restart_badge(), 0)
    return container


class _BootstrapNodesEditor(QWidget):
    """Tiny editor for the bootstrap node list ``list[(host, port)]``."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._items: list[tuple[str, int]] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._list = QListWidget()
        self._list.setMaximumHeight(140)
        layout.addWidget(self._list)

        btn_row = QHBoxLayout()
        self._add_btn = QPushButton("Add…")
        self._remove_btn = QPushButton("Remove")
        self._reset_btn = QPushButton("Reset to Defaults")
        btn_row.addWidget(self._add_btn)
        btn_row.addWidget(self._remove_btn)
        btn_row.addStretch()
        btn_row.addWidget(self._reset_btn)
        layout.addLayout(btn_row)

        self._add_btn.clicked.connect(self._on_add)
        self._remove_btn.clicked.connect(self._on_remove)
        self._reset_btn.clicked.connect(self._on_reset)

    def set_nodes(self, nodes: list[tuple[str, int]]) -> None:
        self._items = [(str(h), int(p)) for h, p in nodes]
        self._refresh_list()

    def get_nodes(self) -> list[tuple[str, int]]:
        return list(self._items)

    def _refresh_list(self) -> None:
        self._list.clear()
        for host, port in self._items:
            self._list.addItem(QListWidgetItem(f"{host}:{port}"))

    def _on_add(self) -> None:
        text, ok = QInputDialog.getText(
            self,
            "Add bootstrap node",
            "Format: host:port",
            text="router.bittorrent.com:6881",
        )
        if not ok or not text.strip():
            return
        if ":" not in text:
            QMessageBox.warning(self, "Invalid", "Use the format host:port")
            return
        host, _, port_str = text.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            QMessageBox.warning(self, "Invalid", "Port must be an integer")
            return
        self._items.append((host.strip(), port))
        self._refresh_list()

    def _on_remove(self) -> None:
        row = self._list.currentRow()
        if row < 0 or row >= len(self._items):
            return
        del self._items[row]
        self._refresh_list()

    def _on_reset(self) -> None:
        from dhtrack.gui.settings import _DEFAULT_BOOTSTRAP_NODES  # type: ignore[attr-defined]

        self._items = list(_DEFAULT_BOOTSTRAP_NODES)
        self._refresh_list()


class SettingsDialog(QDialog):
    """Tabbed settings dialog.

    Parameters
    ----------
    settings : GuiSettings
        The settings to display.  Mutated copies are emitted via
        :attr:`settingsApplied`; the original is not modified.
    parent : QWidget, optional
        Parent window.
    """

    settingsApplied = pyqtSignal(object)  # noqa: N815  # emits GuiSettings; Qt signal naming

    def __init__(self, settings: GuiSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Preferences — DHT Network Inspector")
        self.setMinimumSize(720, 600)
        self.resize(900, 720)

        # Working copy.  Original is preserved for Cancel.
        self._settings = replace(settings)
        # Map of field name -> getter callable returning the widget value.
        self._getters: dict[str, Any] = {}
        # Per-tab logger combo boxes for the Logging tab.
        self._log_level_combos: dict[str, QComboBox] = {}
        # Bootstrap nodes editor lives separately from the simple getter map.
        self._bootstrap_editor: _BootstrapNodesEditor | None = None

        self._setup_ui()
        self._populate_from_settings(self._settings)

    # ------------------------------------------------------------------
    # UI assembly
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        self._tabs = QTabWidget()
        layout.addWidget(self._tabs, 1)

        self._tabs.addTab(self._build_dht_tab(), "DHT")
        self._tabs.addTab(self._build_routing_tab(), "Routing")
        self._tabs.addTab(self._build_peerstore_tab(), "Peer Store")
        self._tabs.addTab(self._build_bootstrap_tab(), "Bootstrap")
        self._tabs.addTab(self._build_metadata_tab(), "Metadata")
        self._tabs.addTab(self._build_peerwire_tab(), "Peer Wire")
        self._tabs.addTab(self._build_trackers_tab(), "Trackers")
        self._tabs.addTab(self._build_lsd_webseed_tab(), "LSD / WebSeed")
        self._tabs.addTab(self._build_persistence_tab(), "Persistence")
        self._tabs.addTab(self._build_advanced_tab(), "Advanced")
        self._tabs.addTab(self._build_logging_tab(), "Logging")

        # Bottom button row.
        btn_row = QHBoxLayout()
        self._restore_btn = QPushButton("Restore Defaults")
        self._import_btn = QPushButton("Import…")
        self._export_btn = QPushButton("Export…")
        btn_row.addWidget(self._restore_btn)
        btn_row.addWidget(self._import_btn)
        btn_row.addWidget(self._export_btn)
        btn_row.addStretch()

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Apply
        )
        btn_row.addWidget(self._buttons)
        layout.addLayout(btn_row)

        self._buttons.button(QDialogButtonBox.StandardButton.Ok).clicked.connect(self._on_ok)
        self._buttons.button(QDialogButtonBox.StandardButton.Cancel).clicked.connect(self.reject)
        self._buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self._on_apply)
        self._restore_btn.clicked.connect(self._on_restore_defaults)
        self._import_btn.clicked.connect(self._on_import)
        self._export_btn.clicked.connect(self._on_export)

    # ----- Helpers -----

    def _scrollable(self, inner: QWidget) -> QWidget:
        """Wrap ``inner`` in a scroll area so dense tabs stay usable on small screens."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll

    def _add_int_row(
        self,
        form: QFormLayout,
        field_name: str,
        label: str,
        description: str,
        *,
        minimum: int = 0,
        maximum: int = 1_000_000_000,
        step: int = 1,
        suffix: str = "",
        restart: bool = False,
    ) -> None:
        sb = QSpinBox()
        sb.setRange(minimum, maximum)
        sb.setSingleStep(step)
        if suffix:
            sb.setSuffix(suffix)
        sb.setMinimumWidth(140)
        sb.setToolTip(description)
        self._getters[field_name] = sb.value
        form.addRow(self._label(label, description), _wrap_with_badge(sb, restart))
        # Tag for repopulation
        sb.setObjectName(f"set_{field_name}")

    def _add_float_row(
        self,
        form: QFormLayout,
        field_name: str,
        label: str,
        description: str,
        *,
        minimum: float = 0.0,
        maximum: float = 1e9,
        step: float = 0.5,
        decimals: int = 2,
        suffix: str = "",
        restart: bool = False,
    ) -> None:
        sb = QDoubleSpinBox()
        sb.setRange(minimum, maximum)
        sb.setSingleStep(step)
        sb.setDecimals(decimals)
        if suffix:
            sb.setSuffix(suffix)
        sb.setMinimumWidth(140)
        sb.setToolTip(description)
        self._getters[field_name] = sb.value
        form.addRow(self._label(label, description), _wrap_with_badge(sb, restart))
        sb.setObjectName(f"set_{field_name}")

    def _add_bool_row(
        self,
        form: QFormLayout,
        field_name: str,
        label: str,
        description: str,
        *,
        restart: bool = False,
    ) -> None:
        cb = QCheckBox()
        cb.setToolTip(description)
        self._getters[field_name] = cb.isChecked
        form.addRow(self._label(label, description), _wrap_with_badge(cb, restart))
        cb.setObjectName(f"set_{field_name}")

    def _add_str_row(
        self,
        form: QFormLayout,
        field_name: str,
        label: str,
        description: str,
        *,
        placeholder: str = "",
        restart: bool = False,
    ) -> None:
        le = QLineEdit()
        if placeholder:
            le.setPlaceholderText(placeholder)
        le.setToolTip(description)
        self._getters[field_name] = le.text
        form.addRow(self._label(label, description), _wrap_with_badge(le, restart))
        le.setObjectName(f"set_{field_name}")

    def _add_dir_row(
        self,
        form: QFormLayout,
        field_name: str,
        label: str,
        description: str,
        *,
        placeholder: str = "",
        restart: bool = False,
    ) -> None:
        row_w = QWidget()
        hl = QHBoxLayout(row_w)
        hl.setContentsMargins(0, 0, 0, 0)
        le = QLineEdit()
        if placeholder:
            le.setPlaceholderText(placeholder)
        le.setToolTip(description)
        btn = QPushButton("Browse…")
        btn.setToolTip(description)

        def _pick_dir() -> None:
            picked = QFileDialog.getExistingDirectory(
                self,
                "Select torrent library folder",
                le.text().strip() or str(Path.cwd()),
                QFileDialog.Option.ShowDirsOnly,
            )
            if picked:
                le.setText(picked)

        btn.clicked.connect(_pick_dir)
        hl.addWidget(le, stretch=1)
        hl.addWidget(btn)
        form.addRow(self._label(label, description), _wrap_with_badge(row_w, restart))
        self._getters[field_name] = le.text
        le.setObjectName(f"set_{field_name}")

    def _label(self, text: str, description: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setToolTip(description)
        lbl.setStyleSheet("font-weight: bold; color: #cdd6f4;")
        return lbl

    def _section_header(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold; padding: 6px 0;")
        return lbl

    def _info(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet("color: #a6adc8; font-size: 11px; padding-bottom: 6px;")
        return lbl

    # ------------------------------------------------------------------
    # Tabs
    # ------------------------------------------------------------------

    def _build_dht_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info(
                "Core kRPC parameters.  Pending-query limits act as backpressure to "
                "prevent runaway memory use; the TXID handled-cache prevents "
                "duplicate processing of late responses."
            )
        )
        form = QFormLayout()
        v.addLayout(form)

        self._add_float_row(
            form,
            "dht_timeout",
            "Query timeout",
            "Seconds before a kRPC query is considered timed out.",
            minimum=1.0,
            maximum=120.0,
            step=1.0,
            decimals=1,
            suffix=" s",
        )
        self._add_int_row(
            form,
            "dht_k",
            "K (bucket size)",
            "Kademlia bucket size / closest-nodes count (BEP 5 default: 8).",
            minimum=2,
            maximum=64,
            restart=True,
        )
        self._add_int_row(
            form,
            "dht_max_pending_per_peer",
            "Max pending per peer",
            "Per-peer outstanding kRPC query cap.",
            minimum=4,
            maximum=4096,
        )
        self._add_int_row(
            form,
            "dht_max_pending_global",
            "Max pending (global)",
            "Global outstanding kRPC query cap across all peers.",
            minimum=64,
            maximum=1_000_000,
        )
        self._add_int_row(
            form,
            "dht_txid_handled_cache_size",
            "TXID handled-cache size",
            "Recently-handled transaction IDs cache (deduplicates late responses).",
            minimum=128,
            maximum=131072,
        )
        self._add_float_row(
            form,
            "dht_get_peers_scrape_qps",
            "get_peers scrape QPS",
            "Aggressive scraping rate (queries/sec) for newly discovered nodes.",
            minimum=0.0,
            maximum=1024.0,
            step=1.0,
            decimals=1,
        )
        self._add_float_row(
            form,
            "dht_get_peers_scrape_burst",
            "get_peers scrape burst",
            "Token-bucket burst capacity for scrape QPS.",
            minimum=0.0,
            maximum=4096.0,
            step=1.0,
            decimals=1,
        )
        self._add_int_row(
            form,
            "dht_get_peers_scrape_max_inflight",
            "Scrape max inflight",
            "Max simultaneously inflight scrape get_peers queries.",
            minimum=1,
            maximum=4096,
        )
        self._add_float_row(
            form,
            "dht_warmup_ping_qps",
            "Warmup ping QPS",
            "Rate of liveness pings for persisted peers at startup.",
            minimum=0.0,
            maximum=512.0,
            step=1.0,
            decimals=1,
        )
        self._add_int_row(
            form,
            "dht_warmup_ping_limit",
            "Warmup ping limit",
            "Maximum number of persisted peers pinged at startup.",
            minimum=0,
            maximum=8192,
        )
        self._add_int_row(
            form,
            "dht_mtu",
            "DHT MTU",
            "Assumed MTU (bytes) for DHT UDP datagrams.",
            minimum=512,
            maximum=65535,
            suffix=" B",
            restart=True,
        )

        return self._scrollable(page)

    def _build_routing_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info(
                "Cadences for routing-table maintenance.  Default values are "
                "tuned per BEP 5; changing them affects bucket churn and "
                "announce-token validity."
            )
        )
        form = QFormLayout()
        v.addLayout(form)

        self._add_int_row(
            form,
            "dht_replacement_timeout",
            "Replacement timeout",
            "Seconds a replacement-cache node is remembered.",
            minimum=30,
            maximum=86400,
            suffix=" s",
        )
        self._add_int_row(
            form,
            "dht_contact_refresh_interval",
            "Contact refresh interval",
            "Seconds between routing-table refreshes.",
            minimum=60,
            maximum=86400,
            suffix=" s",
        )
        self._add_int_row(
            form,
            "dht_secret_rotation_interval",
            "Secret rotation interval",
            "Seconds between announce-token secret rotations.",
            minimum=60,
            maximum=86400,
            suffix=" s",
        )
        self._add_int_row(
            form,
            "dht_token_max_age",
            "Token max age",
            "Maximum age of an accepted announce-token (seconds).",
            minimum=60,
            maximum=86400,
            suffix=" s",
        )

        return self._scrollable(page)

    def _build_peerstore_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info(
                "Peer store retains TCP peers learned via get_peers.  Larger caps "
                "improve metadata success rates at the cost of memory."
            )
        )
        form = QFormLayout()
        v.addLayout(form)

        self._add_int_row(
            form,
            "peerstore_max_peers_per_infohash",
            "Max peers per infohash",
            "Peer count cap per infohash (BEP 5 stored peers).",
            minimum=4,
            maximum=10000,
        )
        self._add_int_row(
            form,
            "peerstore_max_entries",
            "Max total entries",
            "Total peer-store entry cap across all infohashes.",
            minimum=128,
            maximum=1_000_000,
            restart=True,
        )
        self._add_float_row(
            form,
            "peers_save_interval",
            "Peers-file save interval",
            "Seconds between throttled persists of peers.dat.",
            minimum=1.0,
            maximum=3600.0,
            step=1.0,
            decimals=1,
            suffix=" s",
        )

        return self._scrollable(page)

    def _build_bootstrap_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info(
                "Bootstrap nodes are queried first when starting the DHT node.  "
                "Edits affect subsequent bootstrap rounds."
            )
        )

        v.addWidget(self._section_header("Bootstrap node list"))
        self._bootstrap_editor = _BootstrapNodesEditor()
        v.addWidget(self._bootstrap_editor)

        form = QFormLayout()
        v.addLayout(form)
        self._add_int_row(
            form,
            "bootstrap_max_peers_file_targets",
            "Peers-file bootstrap targets",
            "Persisted peers appended as extra bootstrap probes per family.",
            minimum=0,
            maximum=4096,
        )
        self._add_float_row(
            form,
            "bootstrap_total_timeout",
            "Recursive total timeout",
            "Total time budget for recursive bootstrap (seconds).",
            minimum=1.0,
            maximum=600.0,
            step=1.0,
            decimals=1,
            suffix=" s",
        )
        self._add_int_row(
            form,
            "bootstrap_max_depth",
            "Recursive max depth",
            "Maximum bootstrap recursion depth.",
            minimum=1,
            maximum=16,
        )

        return self._scrollable(page)

    def _build_metadata_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info(
                "Tunables for ut_metadata exchange (BEP 9).  Higher concurrency "
                "speeds up metadata retrieval but uses more sockets."
            )
        )
        form = QFormLayout()
        v.addLayout(form)

        self._add_int_row(
            form,
            "metadata_peer_concurrency",
            "Peer concurrency",
            "Concurrent outbound ut_metadata attempts.",
            minimum=1,
            maximum=128,
        )
        self._add_int_row(
            form,
            "metadata_max_pieces_inflight",
            "Max pieces inflight",
            "Concurrent metadata-piece requests per peer attempt.",
            minimum=1,
            maximum=64,
        )
        self._add_float_row(
            form,
            "metadata_request_timeout",
            "Request timeout",
            "Per-peer total budget for completing the metadata exchange.",
            minimum=1.0,
            maximum=3600.0,
            step=5.0,
            decimals=1,
            suffix=" s",
        )
        self._add_float_row(
            form,
            "metadata_piece_timeout",
            "Piece timeout",
            "Time budget waiting for a single metadata piece.",
            minimum=1.0,
            maximum=600.0,
            step=1.0,
            decimals=1,
            suffix=" s",
        )
        self._add_int_row(
            form,
            "metadata_max_retries",
            "Max retries",
            "Per-piece retry attempts before giving up.",
            minimum=0,
            maximum=64,
        )
        self._add_int_row(
            form,
            "metadata_max_size",
            "Max metadata size",
            "DoS-protection cap on accepted metadata size.",
            minimum=1024,
            maximum=512 * 1024 * 1024,
            step=65536,
            suffix=" B",
        )
        self._add_int_row(
            form,
            "metadata_block_size",
            "Metadata block size",
            "ut_metadata block size (BEP 9 norm: 16384).",
            minimum=1024,
            maximum=131072,
            step=1024,
            suffix=" B",
        )

        return self._scrollable(page)

    def _build_peerwire_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(self._info("BitTorrent peer-wire tunables for piece downloads and PEX."))
        form = QFormLayout()
        v.addLayout(form)

        self._add_int_row(
            form,
            "peer_max_pending_requests",
            "Max pending requests",
            "Max in-flight piece requests per peer connection.",
            minimum=1,
            maximum=4096,
        )
        self._add_int_row(
            form,
            "peer_max_pex_peers",
            "Max PEX peers",
            "Max peers advertised in a single PEX message.",
            minimum=1,
            maximum=512,
        )
        self._add_int_row(
            form,
            "peer_block_len",
            "Block length",
            "Block size for piece downloads (16 KiB is the BitTorrent norm).",
            minimum=1024,
            maximum=262144,
            step=1024,
            suffix=" B",
        )
        self._add_int_row(
            form,
            "peer_max_request_size",
            "Max request size",
            "Max block request size accepted from peers.",
            minimum=1024,
            maximum=262144,
            step=1024,
            suffix=" B",
        )
        self._add_float_row(
            form,
            "peer_connect_timeout",
            "Connect timeout",
            "TCP/uTP connect timeout (seconds).",
            minimum=0.5,
            maximum=300.0,
            step=1.0,
            decimals=1,
            suffix=" s",
        )
        self._add_float_row(
            form,
            "peer_handshake_timeout",
            "Handshake timeout",
            "Handshake & first-message receive timeout (seconds).",
            minimum=0.5,
            maximum=300.0,
            step=1.0,
            decimals=1,
            suffix=" s",
        )

        return self._scrollable(page)

    def _build_trackers_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info("HTTP and UDP tracker behaviour (announce timeouts, retries, and the requested peer count).")
        )

        v.addWidget(self._section_header("HTTP tracker"))
        f1 = QFormLayout()
        v.addLayout(f1)
        self._add_int_row(
            f1,
            "tracker_http_timeout",
            "HTTP timeout",
            "Per-request socket timeout for HTTP trackers (seconds).",
            minimum=1,
            maximum=300,
            suffix=" s",
        )
        self._add_int_row(
            f1,
            "tracker_http_max_retries",
            "Max retries",
            "Number of retry attempts per announce.",
            minimum=0,
            maximum=32,
        )
        self._add_float_row(
            f1,
            "tracker_http_retry_delay",
            "Retry delay",
            "Delay between retries (seconds).",
            minimum=0.0,
            maximum=60.0,
            step=0.5,
            decimals=2,
            suffix=" s",
        )
        self._add_int_row(
            f1, "tracker_http_numwant", "numwant", "Number of peers requested per announce.", minimum=0, maximum=1000
        )

        v.addWidget(self._section_header("UDP tracker"))
        f2 = QFormLayout()
        v.addLayout(f2)
        self._add_int_row(
            f2,
            "tracker_udp_retry_base_interval",
            "Retry base interval",
            "Seconds for the UDP tracker exponential-backoff base.",
            minimum=1,
            maximum=600,
            suffix=" s",
        )
        self._add_int_row(
            f2, "tracker_udp_max_retries", "Max retries", "Maximum UDP tracker retry attempts.", minimum=0, maximum=32
        )
        self._add_int_row(
            f2,
            "tracker_udp_conn_id_use_limit",
            "Connection-ID use limit",
            "Max requests per UDP-tracker connection ID before re-handshake.",
            minimum=1,
            maximum=10000,
        )

        return self._scrollable(page)

    def _build_lsd_webseed_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(self._info("Local Service Discovery (BEP 14) and HTTP/FTP web-seed (BEP 19) settings."))

        v.addWidget(self._section_header("LSD"))
        f1 = QFormLayout()
        v.addLayout(f1)
        self._add_int_row(
            f1,
            "lsd_announce_interval",
            "Announce interval",
            "Seconds between LSD multicast announces while in a swarm.",
            minimum=10,
            maximum=3600,
            suffix=" s",
        )
        self._add_int_row(
            f1,
            "lsd_min_announce_interval",
            "Min announce interval",
            "Minimum seconds between LSD announces (rate limit).",
            minimum=1,
            maximum=3600,
            suffix=" s",
        )
        self._add_int_row(
            f1, "lsd_default_ttl", "Multicast TTL", "Default TTL for LSD multicast packets.", minimum=1, maximum=255
        )
        self._add_int_row(
            f1,
            "lsd_listen_port",
            "Advertised listen port",
            "Listening port advertised in LSD announces.",
            minimum=1,
            maximum=65535,
            restart=True,
        )
        self._add_int_row(
            f1,
            "lsd_max_packet_size",
            "Max packet size",
            "LSD packet size cap to avoid IP fragmentation.",
            minimum=512,
            maximum=65535,
            suffix=" B",
        )

        v.addWidget(self._section_header("WebSeed (BEP 19)"))
        f2 = QFormLayout()
        v.addLayout(f2)
        self._add_int_row(
            f2,
            "webseed_http_timeout",
            "HTTP timeout",
            "HTTP web-seed socket timeout (seconds).",
            minimum=1,
            maximum=600,
            suffix=" s",
        )
        self._add_int_row(
            f2,
            "webseed_ftp_timeout",
            "FTP timeout",
            "FTP web-seed socket timeout (seconds).",
            minimum=1,
            maximum=600,
            suffix=" s",
        )
        self._add_int_row(
            f2, "webseed_max_redirects", "Max redirects", "Maximum HTTP redirects to follow.", minimum=0, maximum=32
        )
        self._add_int_row(
            f2,
            "webseed_http_buffer_size",
            "HTTP buffer size",
            "HTTP read buffer size (bytes).",
            minimum=1024,
            maximum=8 * 1024 * 1024,
            step=4096,
            suffix=" B",
        )
        self._add_int_row(
            f2,
            "webseed_ftp_buffer_size",
            "FTP buffer size",
            "FTP read buffer size (bytes).",
            minimum=1024,
            maximum=8 * 1024 * 1024,
            step=4096,
            suffix=" B",
        )
        self._add_str_row(
            f2,
            "webseed_user_agent",
            "User-Agent",
            "User-Agent header sent on HTTP web-seed requests.",
            placeholder="dhtrack/2.0 (BEP 19 WebSeed)",
        )

        return self._scrollable(page)

    def _build_persistence_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info(
                "On-disk persistence and BEP 42 (secure node-ID) policy.  Path changes apply at the next node startup."
            )
        )
        form = QFormLayout()
        v.addLayout(form)

        self._add_dir_row(
            form,
            "torrent_library_directory",
            "Torrent library folder",
            "Saved retrieved .torrent metainfo (*.torrent here) on disk; resume/state lives "
            'in the "resume" subfolder here. Leave empty for the default beside settings.json.',
            placeholder="(default: …/torrents next to GUI config)",
        )
        self._add_str_row(
            form,
            "peers_file",
            "Peers file path",
            "Path to the persisted peers.dat (relative to working directory).",
            placeholder="peers.dat",
            restart=True,
        )
        self._add_str_row(
            form,
            "state_file",
            "Node-state file path",
            "Path to the DHT node-state file (empty = sibling of peers file).",
            placeholder="(auto: dht_node.state next to peers file)",
            restart=True,
        )
        self._add_bool_row(
            form,
            "persist_node_identity",
            "Persist node identity",
            "Reuse the same node ID across restarts (privacy vs. stability).",
            restart=True,
        )
        self._add_bool_row(
            form,
            "auto_align_bep42_node_id",
            "Auto-align BEP 42 node ID",
            "Rotate node ID to satisfy BEP 42 once external IP quorum agrees.",
        )
        self._add_int_row(
            form,
            "observed_ip_min_distinct_responders",
            "BEP 42 quorum",
            "Distinct responders required before trusting observed external IP.",
            minimum=1,
            maximum=64,
        )
        self._add_int_row(
            form,
            "bind_port",
            "DHT bind port",
            "UDP bind port for the DHT node (0 = ephemeral).",
            minimum=0,
            maximum=65535,
            restart=True,
        )

        return self._scrollable(page)

    def _build_advanced_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        warn = QLabel("Advanced — incorrect values may break connectivity. Most uTP/QUIC fields are restart-required.")
        warn.setWordWrap(True)
        warn.setStyleSheet(
            "color: #f38ba8; background-color: #2a1a1f; "
            "border: 1px solid #6b2530; border-radius: 4px; "
            "padding: 6px; font-weight: bold;"
        )
        v.addWidget(warn)

        v.addWidget(self._section_header("uTP (BEP 29)"))
        f1 = QFormLayout()
        v.addLayout(f1)
        self._add_int_row(
            f1,
            "utp_default_packet_size",
            "Default packet size",
            "uTP default payload size (BEP 29 recommends 1400).",
            minimum=150,
            maximum=65535,
            suffix=" B",
            restart=True,
        )
        self._add_int_row(
            f1,
            "utp_min_packet_size",
            "Min packet size",
            "Minimum uTP packet size (BEP 29: 150).",
            minimum=64,
            maximum=65535,
            suffix=" B",
            restart=True,
        )
        self._add_int_row(
            f1,
            "utp_max_packet_size",
            "Max packet size",
            "Maximum uTP packet size (payload cap).",
            minimum=512,
            maximum=65535,
            suffix=" B",
            restart=True,
        )
        self._add_int_row(
            f1,
            "utp_initial_congestion_window",
            "Initial congestion window",
            "Initial congestion window in packets.",
            minimum=1,
            maximum=64,
            restart=True,
        )
        self._add_int_row(
            f1,
            "utp_ccontrol_target",
            "Target one-way delay",
            "Congestion-control target one-way delay (ms).",
            minimum=10,
            maximum=10000,
            suffix=" ms",
            restart=True,
        )
        self._add_int_row(
            f1,
            "utp_initial_timeout_ms",
            "Initial timeout",
            "Initial RTO (ms).",
            minimum=100,
            maximum=60000,
            suffix=" ms",
            restart=True,
        )
        self._add_int_row(
            f1,
            "utp_keepalive_interval",
            "Keepalive interval",
            "Seconds between uTP keepalives.",
            minimum=5,
            maximum=600,
            suffix=" s",
            restart=True,
        )
        self._add_int_row(
            f1,
            "utp_max_pending_packets",
            "Max pending packets",
            "Send-buffer cap (packets).",
            minimum=4,
            maximum=4096,
            restart=True,
        )

        v.addWidget(self._section_header("QUIC"))
        f2 = QFormLayout()
        v.addLayout(f2)
        self._add_int_row(
            f2, "quic_default_port", "QUIC port", "QUIC listener UDP port.", minimum=1, maximum=65535, restart=True
        )
        self._add_int_row(
            f2,
            "quic_max_packet_size",
            "QUIC max packet size",
            "Maximum QUIC datagram size (bytes).",
            minimum=512,
            maximum=65535,
            suffix=" B",
            restart=True,
        )

        return self._scrollable(page)

    def _build_logging_tab(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(
            self._info(
                "Per-logger levels.  The wire-trace toggle forces "
                "dhtrack.wire to DEBUG so raw packet hex appears in the kRPC console."
            )
        )

        form = QFormLayout()
        v.addLayout(form)

        # Wire logging toggle
        self._add_bool_row(
            form, "wire_logging_enabled", "Enable wire logging", "Set dhtrack.wire to DEBUG (raw packet hex traces)."
        )

        v.addWidget(self._section_header("Per-logger levels"))
        log_form = QFormLayout()
        v.addLayout(log_form)

        for name in (
            "dhtrack",
            "dhtrack.dht",
            "dhtrack.wire",
            "dhtrack.bencode",
            "dhtrack.bep53",
            "dhtrack.torrent",
            "dhtrack.metadata_retriever",
            "dhtrack.peer",
            "dhtrack.utp",
        ):
            combo = QComboBox()
            combo.addItems(_LOG_LEVELS)
            combo.setCurrentText("WARNING")
            self._log_level_combos[name] = combo
            log_form.addRow(self._label(name, f"Log level for the '{name}' logger."), combo)

        v.addStretch()
        return self._scrollable(page)

    # ------------------------------------------------------------------
    # Populate / collect
    # ------------------------------------------------------------------

    def _populate_from_settings(self, settings: GuiSettings) -> None:
        """Push values from ``settings`` into all input widgets."""
        d = asdict(settings)
        for f in fields(GuiSettings):
            if f.name in ("bootstrap_nodes", "log_levels"):
                continue
            widget = self._find_widget(f"set_{f.name}")
            if widget is None:
                continue
            value = d.get(f.name)
            try:
                if isinstance(widget, QSpinBox):
                    widget.setValue(int(value))
                elif isinstance(widget, QDoubleSpinBox):
                    widget.setValue(float(value))
                elif isinstance(widget, QCheckBox):
                    widget.setChecked(bool(value))
                elif isinstance(widget, QLineEdit):
                    widget.setText("" if value is None else str(value))
            except (TypeError, ValueError):
                pass

        if self._bootstrap_editor is not None:
            self._bootstrap_editor.set_nodes(settings.bootstrap_nodes)

        for name, combo in self._log_level_combos.items():
            level = settings.log_levels.get(name, "WARNING")
            idx = combo.findText(str(level).upper())
            combo.setCurrentIndex(idx if idx >= 0 else combo.findText("WARNING"))

    def _find_widget(self, object_name: str) -> QWidget | None:
        return self.findChild(QWidget, object_name)

    def _collect_settings(self) -> GuiSettings:
        """Build a :class:`GuiSettings` from the current widget values."""
        out = replace(self._settings)
        d = asdict(out)
        for f in fields(GuiSettings):
            if f.name in ("bootstrap_nodes", "log_levels"):
                continue
            widget = self._find_widget(f"set_{f.name}")
            if widget is None:
                continue
            try:
                if isinstance(widget, QSpinBox):
                    d[f.name] = int(widget.value())
                elif isinstance(widget, QDoubleSpinBox):
                    d[f.name] = float(widget.value())
                elif isinstance(widget, QCheckBox):
                    d[f.name] = bool(widget.isChecked())
                elif isinstance(widget, QLineEdit):
                    d[f.name] = widget.text()
            except (TypeError, ValueError):
                pass

        if self._bootstrap_editor is not None:
            d["bootstrap_nodes"] = self._bootstrap_editor.get_nodes()

        d["log_levels"] = {name: combo.currentText() for name, combo in self._log_level_combos.items()}

        return GuiSettings.from_dict(d)

    # ------------------------------------------------------------------
    # Button slots
    # ------------------------------------------------------------------

    def _on_apply(self) -> None:
        try:
            new_settings = self._collect_settings()
        except Exception as exc:
            QMessageBox.critical(self, "Settings", f"Failed to collect settings: {exc}")
            return
        self._settings = new_settings
        self.settingsApplied.emit(new_settings)

    def _on_ok(self) -> None:
        self._on_apply()
        self.accept()

    def _on_restore_defaults(self) -> None:
        ans = QMessageBox.question(
            self,
            "Restore Defaults",
            "Restore every setting to its built-in default?  "
            "Click Apply or OK afterwards to make the change take effect.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        self._populate_from_settings(GuiSettings())

    def _on_export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export settings",
            "dhtrack_settings.json",
            "JSON (*.json);;All files (*)",
        )
        if not path:
            return
        try:
            settings = self._collect_settings()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(settings.to_dict(), f, indent=2, sort_keys=True)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Export complete", f"Settings written to:\n{path}")

    def _on_import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import settings",
            "",
            "JSON (*.json);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        if not isinstance(data, dict):
            QMessageBox.critical(self, "Import failed", "Top-level JSON must be an object.")
            return
        try:
            imported = GuiSettings.from_dict(data)
        except Exception as exc:
            QMessageBox.critical(self, "Import failed", f"Invalid settings file: {exc}")
            return
        self._populate_from_settings(imported)
        QMessageBox.information(
            self,
            "Import complete",
            "Imported settings.  Click Apply or OK to make them take effect.",
        )

    # ------------------------------------------------------------------
    # Public accessor
    # ------------------------------------------------------------------

    @property
    def current_settings(self) -> GuiSettings:
        """Most-recently applied settings (or the originals if nothing applied)."""
        return self._settings


__all__ = ["SettingsDialog"]
