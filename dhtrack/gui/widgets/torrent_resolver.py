"""
Swarm Inspector widget for the DHT Network Inspector.

DHT resolve, magnet parsing, ut_metadata retrieval, payload download,
peer wire state (choke / interested), and a torrent metadata + local
piece completion view.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import threading
import time
from pathlib import Path
from typing import Any, cast

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from dhtrack.bep53 import merge_peer_triplets_preferred
from dhtrack.dht import DHTNode
from dhtrack.dht_manager import DHTManager
from dhtrack.downloader import bitfield_from_hex, bitfield_has
from dhtrack.gui.inspector_session import InspectorSession
from dhtrack.gui.models.peer_model import RoutingTableModel, SwarmPeerModel
from dhtrack.resume import ResumeState
from dhtrack.storage import piece_hashes, torrent_files, total_length
from dhtrack.swarm import Swarm
from dhtrack.swarm_peer_display import format_peer_expert_detail, merge_peer_detail_fields
from dhtrack.torrent_track import TrackedTorrent

_resolver_log = logging.getLogger(__name__)

try:
    from dhtrack.peerid import PeerIdParser
except ImportError:
    PeerIdParser = None


def _ewma_throughput_bps(
    *,
    alpha: float,
    prev_rate: float | None,
    prev_bytes: int | None,
    prev_time: float | None,
    cur_bytes: int,
    cur_time: float,
) -> tuple[float, int, float]:
    """Rough bytes/sec EWMA between progress callbacks."""
    if prev_time is None or prev_bytes is None:
        return 0.0, int(cur_bytes), cur_time
    dt = cur_time - prev_time
    if dt <= 0:
        rate = prev_rate if prev_rate is not None else 0.0
        return rate, int(cur_bytes), cur_time
    inst = float(max(0, cur_bytes - prev_bytes)) / dt
    if prev_rate is None:
        new_r = inst
    else:
        new_r = alpha * inst + (1.0 - alpha) * prev_rate
    return new_r, int(cur_bytes), cur_time


def _format_torrent_bencode_tree(
    obj: Any,
    indent: int = 0,
    *,
    field_name: str | None = None,
) -> list[str]:
    """Recursive text dump of decoded bencode (full structure; ``pieces`` summarized)."""
    pad = "  " * indent
    if isinstance(obj, dict):
        lines: list[str] = []
        for raw_key, val in obj.items():
            key_str = raw_key.decode("utf-8", errors="replace") if isinstance(raw_key, bytes) else str(raw_key)
            lines.append(f"{pad}{key_str}:")
            lines.extend(_format_torrent_bencode_tree(val, indent + 1, field_name=key_str))
        return lines
    if isinstance(obj, list):
        lines = []
        for i, item in enumerate(obj):
            lines.append(f"{pad}[{i}]")
            lines.extend(_format_torrent_bencode_tree(item, indent + 1))
        return lines
    if isinstance(obj, int):
        return [f"{pad}{obj}"]
    if isinstance(obj, bytes):
        if field_name == "pieces" and len(obj) >= 20 and len(obj) % 20 == 0:
            return [f"{pad}<{len(obj) // 20} SHA-1 piece digests ({len(obj)} bytes total)>"]
        if len(obj) <= 1024:
            try:
                txt = obj.decode("utf-8")
                if all(c.isprintable() or c in "\n\r\t" for c in txt):
                    return [f"{pad}{txt!r}"]
            except UnicodeDecodeError:
                pass
            return [f"{pad}{obj!r}"]
        return [f"{pad}<bytes len={len(obj)} head={obj[:24]!r}...>"]
    return [f"{pad}{obj!r}"]


class PeerResolveWorker(QThread):
    """Background worker: iterative get_peers plus periodic peer-store snapshots."""

    progress_updated = pyqtSignal(str)
    peers_updated = pyqtSignal(list)
    dht_nodes_updated = pyqtSignal(list)

    def __init__(
        self,
        dht_manager_or_node: object,
        info_hash: bytes,
        timeout: float = 45.0,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._ref = dht_manager_or_node
        self.info_hash = info_hash
        self._running = True
        self.timeout = timeout

    def _underlying_node(self):
        return getattr(self._ref, "node", self._ref)

    def _stored_peers_to_dicts(self, dht) -> list[dict]:
        out: list[dict] = []
        if not hasattr(dht, "peer_store"):
            return out
        for peer in dht.peer_store.get_peers(self.info_hash):
            out.append(
                {
                    "ip": peer.ip,
                    "port": peer.port,
                    "is_ipv6": getattr(peer, "is_ipv6", False),
                    "node_id": getattr(peer, "node_id", b"") or b"",
                    "last_seen": getattr(peer, "last_seen", time.time()),
                    "status": "good",
                    "rpc_counter": 0,
                    "failure_count": 0,
                    "last_contacted": getattr(peer, "last_seen", 0),
                    "source": "swarm",
                }
            )
        return out

    def _dht_candidates_to_dicts(self, dht) -> list[dict]:
        """DHT nodes near the infohash (routing/query candidates)."""
        out: list[dict] = []
        if not hasattr(dht, "iter_query_candidates"):
            return out
        try:
            nodes = dht.iter_query_candidates(self.info_hash, 200)
        except Exception:
            nodes = []
        for node in nodes:
            ep = getattr(node, "endpoint", None)
            if ep is None:
                continue
            out.append(
                {
                    "node_id": getattr(node, "node_id", b"") or b"",
                    "ip": ep.ip,
                    "port": ep.port,
                    "is_ipv6": getattr(ep, "is_ipv6", False),
                    "status": getattr(node, "status", "good"),
                    "last_contacted": getattr(node, "last_contacted", 0),
                    "rpc_counter": getattr(node, "rpc_counter", 0),
                    "failure_count": getattr(node, "failure_count", 0),
                    "source": "dht",
                }
            )
        return out

    def run(self) -> None:
        """Run async peer discovery with polling."""
        dht = self._underlying_node()
        has_manager = callable(getattr(self._ref, "async_find_peers", None))

        async def poll_loop() -> None:
            while self._running:
                self.peers_updated.emit(self._stored_peers_to_dicts(dht))
                self.dht_nodes_updated.emit(self._dht_candidates_to_dicts(dht))
                await asyncio.sleep(1.0)

        async def discover() -> None:
            def cancel_cb():
                return not self._running

            if has_manager:
                mgr = cast(Any, self._ref)

                def on_prog(p: Any) -> None:
                    self.progress_updated.emit(
                        f"Round {p.round_num}: {p.peers_found} swarm peers — "
                        f"RT nodes v4/v6 {p.ipv4_nodes}/{p.ipv6_nodes}, "
                        f"get_peers sent (cum.) v4+v6 = {p.ipv4_queried}+{p.ipv6_queried}",
                    )

                await mgr.async_find_peers(
                    self.info_hash,
                    timeout=self.timeout,
                    query_interval=1.0,
                    max_nodes=32,
                    on_progress=on_prog,
                    cancel_requested=cancel_cb,
                )
            elif hasattr(dht, "async_get_peers"):

                def on_round(rn: int, s4: int, s6: int, pf: int) -> None:
                    self.progress_updated.emit(
                        f"Round {rn}: {pf} swarm peers ({s4} IPv4 + {s6} IPv6 queries)",
                    )

                await dht.async_get_peers(
                    self.info_hash,
                    search_timeout=self.timeout,
                    max_nodes=32,
                    query_interval=1.0,
                    on_round=on_round,
                    cancel_requested=cancel_cb,
                )
            else:
                self.progress_updated.emit("DHT node has no async_get_peers — cannot search")
                return

        async def main_async() -> None:
            self.progress_updated.emit("Starting DHT get_peers search...")
            poll_task = asyncio.create_task(poll_loop())
            try:
                await discover()
            finally:
                poll_task.cancel()
                try:
                    await poll_task
                except asyncio.CancelledError:
                    pass
            self.peers_updated.emit(self._stored_peers_to_dicts(dht))
            self.dht_nodes_updated.emit(self._dht_candidates_to_dicts(dht))
            n = len(dht.peer_store.get_peers(self.info_hash))
            self.progress_updated.emit(
                f"Discovery finished — {n} swarm peer(s) in store",
            )

        try:
            if isinstance(self._ref, DHTManager) and self._ref.loop is not None:
                import asyncio as _asyncio

                _asyncio.run_coroutine_threadsafe(main_async(), self._ref.loop).result(timeout=self.timeout + 10.0)
            else:
                asyncio.run(main_async())
        except Exception as exc:
            self.progress_updated.emit(f"Error: {exc}")

    def terminate_thread(self) -> None:
        """Request cooperative cancel (async_get_peers checks _running)."""
        self._running = False


class MetadataRetrievalWorker(QThread):
    """Retrieve metadata via ut_metadata from swarm TCP peers."""

    metadata_ready = pyqtSignal(bytes)
    error_occurred = pyqtSignal(str)
    progress_updated = pyqtSignal(str)
    peer_detail_updated = pyqtSignal(str, int, object)

    def __init__(
        self,
        info_hash: bytes,
        swarm_triplets: list[tuple[str, int, bool]],
        manager: DHTManager | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.info_hash = info_hash
        self.swarm_triplets = swarm_triplets
        self._manager = manager

    def run(self) -> None:
        """Execute metadata retrieval."""
        try:

            def _prog(msg: str) -> None:
                self.progress_updated.emit(msg)

            def _peer_status(ip: str, port: int, status: str, err: str | None) -> None:
                # Encode as a progress line so the GUI thread can merge it into the peer table.
                if err:
                    self.progress_updated.emit(f"peer_status {ip}:{port} {status} {err}")
                else:
                    self.progress_updated.emit(f"peer_status {ip}:{port} {status}")

            def _peer_detail(ip: str, port: int, detail: dict) -> None:
                self.peer_detail_updated.emit(ip, int(port), detail)

            if self._manager is not None:
                self.progress_updated.emit(
                    "Trying ut_metadata while continuing DHT discovery...",
                )
                initial = [(ip, port) for (ip, port, _is_v6) in list(self.swarm_triplets or [])]
                metadata = self._manager.retrieve_metadata(
                    self.info_hash,
                    timeout=210.0,
                    max_peers=200,
                    on_progress=_prog,
                    initial_peers=initial,
                    peer_status_observer=_peer_status,
                    peer_detail_observer=_peer_detail,
                )
            else:
                from dhtrack.metadata_retriever import download_torrent_metadata

                peers_to_try = list(self.swarm_triplets)
                if not peers_to_try:
                    self.error_occurred.emit(
                        "No DHT swarm peers to try. Resolve until at least one peer appears.",
                    )
                    return

                self.progress_updated.emit(
                    f"Trying ut_metadata on {len(peers_to_try)} peer(s)...",
                )

                # Overall deadline must exceed per-peer METADATA_REQUEST_TIMEOUT slots
                # (handshake + all ut_metadata pieces), similar in spirit to async_find_peers.
                metadata = download_torrent_metadata(
                    peers=peers_to_try,
                    info_hash=self.info_hash,
                    timeout=210.0,
                    progress_callback=_prog,
                    peer_detail_observer=_peer_detail,
                )

            if metadata:
                self.metadata_ready.emit(metadata)
            else:
                self.error_occurred.emit(
                    "Failed to retrieve metadata from any peer. "
                    "Peers may not seed metadata, may be unreachable, or "
                    "the swarm may be stale.",
                )

        except Exception as e:
            self.error_occurred.emit(f"Error during metadata retrieval: {e}")
            import traceback

            self.error_occurred.emit(traceback.format_exc())


class DownloadWorker(QThread):
    """End-to-end magnet-start download (metadata + payload)."""

    progress_updated = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    finished_ok = pyqtSignal()
    peer_wire_snapshot = pyqtSignal(str, int, object)
    payload_progress = pyqtSignal(bytes, object)

    def __init__(
        self,
        info_hash: bytes,
        download_dir: str,
        manager: DHTManager,
        parent: QObject | None = None,
        *,
        resume_dir: str,
        use_utp: bool = False,
        cancel_event: threading.Event | None = None,
        metainfo_override: bytes | None = None,
    ) -> None:
        super().__init__(parent)
        self.info_hash = info_hash
        self.download_dir = download_dir
        self.resume_dir = resume_dir
        self._manager = manager
        self.use_utp = use_utp
        self._cancel = cancel_event or threading.Event()
        self._metainfo_override = metainfo_override

    def request_cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:

            def _prog(msg: str) -> None:
                self.progress_updated.emit(msg)

            def _dl_prog(p) -> None:
                # p is dhtrack.downloader.DownloadProgress
                try:
                    pct = p.fraction * 100.0
                    self.progress_updated.emit(
                        f"Downloading… {pct:.2f}% ({p.completed_pieces}/{p.total_pieces} pieces)",
                    )
                except Exception:
                    pass
                self.payload_progress.emit(self.info_hash, p)

            def _peer_snap(ip: str, port: int, snap: dict) -> None:
                self.peer_wire_snapshot.emit(ip, int(port), dict(snap))

            if self._metainfo_override is not None:
                self._manager.download_payload_with_known_metainfo(
                    self.info_hash,
                    self._metainfo_override,
                    download_dir=self.download_dir,
                    resume_dir=self.resume_dir,
                    use_utp=self.use_utp,
                    on_progress=_prog,
                    on_download_progress=_dl_prog,
                    on_peer_snapshot=_peer_snap,
                    cancel_requested=self._cancel.is_set,
                )
            else:
                self._manager.download_from_infohash(
                    self.info_hash,
                    download_dir=self.download_dir,
                    resume_dir=self.resume_dir,
                    timeout=240.0,
                    use_utp=self.use_utp,
                    on_progress=_prog,
                    on_download_progress=_dl_prog,
                    on_peer_snapshot=_peer_snap,
                    cancel_requested=self._cancel.is_set,
                )
            self.finished_ok.emit()
        except Exception as e:
            self.error_occurred.emit(str(e))
            import traceback

            self.error_occurred.emit(traceback.format_exc())


class TorrentResolverWidget(QWidget):
    """Widget for resolving torrent peers via DHT."""

    swarm_list_changed = pyqtSignal()
    torrent_jobs_changed = pyqtSignal()

    def __init__(
        self,
        dht_manager_or_node: object,
        inspector_session: InspectorSession,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._session = inspector_session
        self._swarm_mgr = inspector_session.swarm_manager
        self._torrent_mgr = inspector_session.torrent_manager
        self._dht_ref = dht_manager_or_node
        self.dht_node = dht_manager_or_node.node if isinstance(dht_manager_or_node, DHTManager) else dht_manager_or_node
        self._manager: DHTManager | None = dht_manager_or_node if isinstance(dht_manager_or_node, DHTManager) else None
        # Ensure the resolver/metadata pipeline uses the richer DHTManager APIs even when
        # the GUI is only given a live DHTNode instance. We intentionally do NOT call
        # start() here; the GUI owns the node lifecycle already.
        if self._manager is None and isinstance(self.dht_node, DHTNode):
            try:
                self._manager = DHTManager(
                    node=self.dht_node,
                    peers_file=getattr(self.dht_node, "peers_file", "peers.dat"),
                )
            except Exception:
                self._manager = None
        self._resolved_peers: list[dict] = []
        self._current_infohash: bytes | None = None
        self._resolved_infohash: bytes | None = None
        self._swarm_peers: list[dict] = []
        self._dht_nodes: list[dict] = []
        self._resolve_worker: PeerResolveWorker | None = None
        self._metadata_worker: MetadataRetrievalWorker | None = None
        self._download_worker: DownloadWorker | None = None
        self._download_workers: dict[bytes, DownloadWorker] = {}
        self._meta_retrieval_succeeded = False
        self._workers: dict[bytes, PeerResolveWorker] = {}
        self._combo_programmatic = False
        self._payload_ewma_bps: dict[bytes, float] = {}
        self._payload_ewma_prev_bytes: dict[bytes, int] = {}
        self._payload_ewma_prev_time: dict[bytes, float] = {}
        self._download_cancel_requested: set[bytes] = set()
        self._torrent_teardown_pending: set[bytes] = set()
        self._payload_finish_ok: set[bytes] = set()
        self._payload_finish_err: dict[bytes, str] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build Swarm Inspector: swarm bar + actions above subtabs (Peers, Metadata, …)."""
        from PyQt6.QtWidgets import QHeaderView

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(8)

        title = QLabel("Swarm Inspector")
        title.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold;")
        root_layout.addWidget(title)

        swarm_pick = QHBoxLayout()
        swarm_pick.addWidget(QLabel("Tracked swarm:"))
        self._swarm_combo = QComboBox()
        self._swarm_combo.setMinimumWidth(320)
        self._swarm_combo.currentIndexChanged.connect(self._on_swarm_combo_changed)
        swarm_pick.addWidget(self._swarm_combo, stretch=1)
        root_layout.addLayout(swarm_pick)

        actions = QHBoxLayout()
        self.resolve_btn = QPushButton("Resolve")
        self.resolve_btn.clicked.connect(self._resolve_selected_swarm)
        self.resolve_btn.setStyleSheet("background-color: #89b4fa; color: #1e1e2e; font-weight: bold;")
        actions.addWidget(self.resolve_btn)

        self.stop_resolve_btn = QPushButton("Stop")
        self.stop_resolve_btn.clicked.connect(self._stop_resolve)
        self.stop_resolve_btn.setEnabled(False)
        self.stop_resolve_btn.setStyleSheet("background-color: #f38ba8; color: #1e1e2e; font-weight: bold;")
        actions.addWidget(self.stop_resolve_btn)

        self.retrieve_meta_from_peers_btn = QPushButton("Retrieve metadata")
        self.retrieve_meta_from_peers_btn.setToolTip(
            "Open the Torrent Metadata tab and start ut_metadata retrieval for the selected swarm.",
        )
        self.retrieve_meta_from_peers_btn.clicked.connect(self._open_metadata_tab_and_retrieve)
        self.retrieve_meta_from_peers_btn.setEnabled(False)
        self.retrieve_meta_from_peers_btn.setStyleSheet("background-color: #a6e3a1; color: #1e1e2e; font-weight: bold;")
        actions.addWidget(self.retrieve_meta_from_peers_btn)

        self.download_btn = QPushButton("Download")
        self.download_btn.clicked.connect(self._download_payload)
        self.download_btn.setEnabled(False)
        self.download_btn.setStyleSheet("background-color: #89b4fa; color: #1e1e2e; font-weight: bold;")
        actions.addWidget(self.download_btn)

        self.stop_download_btn = QPushButton("Stop download")
        self.stop_download_btn.clicked.connect(self._stop_download)
        self.stop_download_btn.setEnabled(False)
        self.stop_download_btn.setStyleSheet("background-color: #f38ba8; color: #1e1e2e; font-weight: bold;")
        actions.addWidget(self.stop_download_btn)

        actions.addStretch(1)
        root_layout.addLayout(actions)

        status_frame = QFrame()
        status_frame.setStyleSheet("QFrame { background-color: #181825; border: none; }")
        status_layout = QHBoxLayout(status_frame)
        self.status_label = QLabel("Add swarms in the Swarm Tracker tab, pick one above, then Resolve.")
        self.status_label.setStyleSheet("color: #a6adc8;")
        status_layout.addWidget(self.status_label)
        root_layout.addWidget(status_frame)

        self._inspector_tabs = QTabWidget()
        self._inspector_tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #313244; border-radius: 4px; }"
            "QTabBar::tab { background: #181825; color: #a6adc8; padding: 8px; }"
            "QTabBar::tab:selected { background: #313244; color: #cdd6f4; }"
        )

        peers_page = QWidget()
        layout = QVBoxLayout(peers_page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        detail_splitter = QSplitter(Qt.Orientation.Vertical)

        # Peers table
        peers_frame = QFrame()
        peers_frame.setStyleSheet(
            "QFrame { background-color: #1e1e2e; border: 1px solid #313244; border-radius: 4px; padding: 4px; }"
        )
        peers_layout = QVBoxLayout(peers_frame)
        peers_layout.setContentsMargins(4, 4, 4, 4)

        peers_title = QLabel("Discovered Peers:")
        peers_title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        peers_layout.addWidget(peers_title)

        filter_row = QHBoxLayout()
        self._active_peers_only_cb = QCheckBox("Show only good / active peers")
        self._active_peers_only_cb.setStyleSheet("color: #a6adc8;")
        self._active_peers_only_cb.toggled.connect(self._on_active_peers_filter_toggled)
        filter_row.addWidget(self._active_peers_only_cb)
        filter_row.addStretch(1)
        peers_layout.addLayout(filter_row)

        self.peers_tabs = QTabWidget()
        self.peers_tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #313244; border-radius: 4px; }"
            "QTabBar::tab { background: #181825; color: #a6adc8; padding: 6px; }"
            "QTabBar::tab:selected { background: #313244; color: #cdd6f4; }"
        )

        # Swarm peers (TCP)
        self.swarm_table_view = QTableView()
        self.swarm_table_view.setAlternatingRowColors(True)
        self.swarm_table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.swarm_table_view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.swarm_model = SwarmPeerModel()
        self.swarm_table_view.setModel(self.swarm_model)
        header = self.swarm_table_view.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.resizeSection(1, 52)
        header.resizeSection(2, 88)
        header.resizeSection(3, 100)
        header.resizeSection(4, 90)
        header.resizeSection(5, 110)
        header.resizeSection(6, 90)
        header.resizeSection(7, 72)
        header.resizeSection(8, 160)

        # DHT nodes
        self.dht_table_view = QTableView()
        self.dht_table_view.setAlternatingRowColors(True)
        self.dht_table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.dht_table_view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.dht_model = RoutingTableModel()
        self.dht_table_view.setModel(self.dht_model)

        self.peers_tabs.addTab(self.swarm_table_view, "Swarm peers (TCP)")
        self.peers_tabs.addTab(self.dht_table_view, "DHT nodes")
        peers_layout.addWidget(self.peers_tabs)
        detail_splitter.addWidget(peers_frame)

        # Details panel
        details_frame = QFrame()
        details_frame.setStyleSheet(
            "QFrame { background-color: #0f0f1a; border: 1px solid #313244; border-radius: 4px; padding: 8px; }"
        )
        details_layout = QVBoxLayout(details_frame)
        details_layout.setContentsMargins(4, 4, 4, 4)

        details_title = QLabel("Peer Details:")
        details_title.setStyleSheet("color: #89b4fa; font-weight: bold;")
        details_layout.addWidget(details_title)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(200)
        self.details_text.setMaximumHeight(480)
        self.details_text.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; font-family: monospace; border: none; }"
        )
        details_layout.addWidget(self.details_text)
        detail_splitter.addWidget(details_frame)

        detail_splitter.setStretchFactor(0, 2)
        detail_splitter.setStretchFactor(1, 1)

        layout.addWidget(detail_splitter)

        self.swarm_table_view.selectionModel().selectionChanged.connect(self._on_swarm_selection_changed)
        self.swarm_table_view.doubleClicked.connect(self._on_swarm_peer_double_clicked)
        self.dht_table_view.selectionModel().selectionChanged.connect(self._on_dht_selection_changed)

        self._inspector_tabs.addTab(peers_page, "Peers")

        self._metadata_tab = QWidget()
        meta_page_layout = QVBoxLayout(self._metadata_tab)
        meta_page_layout.setContentsMargins(0, 0, 0, 0)
        meta_page_layout.setSpacing(8)
        meta_intro = QLabel("Torrent metadata retrieval (BEP 9 ut_metadata). Output appears below once peers respond.")
        meta_intro.setStyleSheet("color: #a6adc8; font-size: 10px;")
        meta_intro.setWordWrap(True)
        meta_page_layout.addWidget(meta_intro)
        self._add_metadata_section(meta_page_layout)

        self._inspector_tabs.addTab(self._metadata_tab, "Torrent Metadata")

        self._torrent_tab = QWidget()
        tt_layout = QVBoxLayout(self._torrent_tab)
        tt_layout.setContentsMargins(4, 4, 4, 4)
        tt_layout.setSpacing(6)
        t_hint = QLabel(
            "Torrent structure and local piece completion for the swarm selected above "
            "(metadata + download / resume). Use Torrent Metadata to fetch ut_metadata."
        )
        t_hint.setStyleSheet("color: #a6adc8; font-size: 10px;")
        t_hint.setWordWrap(True)
        tt_layout.addWidget(t_hint)
        self._torrent_summary = QTextEdit()
        self._torrent_summary.setReadOnly(True)
        self._torrent_summary.setMaximumHeight(140)
        self._torrent_summary.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #cdd6f4; font-family: monospace; }"
        )
        tt_layout.addWidget(QLabel("Summary"))
        tt_layout.addWidget(self._torrent_summary)
        self._torrent_files_table = QTableWidget(0, 2)
        self._torrent_files_table.setHorizontalHeaderLabels(["Path", "Size (bytes)"])
        self._torrent_files_table.horizontalHeader().setStretchLastSection(True)
        self._torrent_files_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._torrent_files_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tt_layout.addWidget(QLabel("Files"))
        tt_layout.addWidget(self._torrent_files_table, stretch=1)
        self._torrent_pieces_table = QTableWidget(0, 3)
        self._torrent_pieces_table.setHorizontalHeaderLabels(["Piece", "Bytes", "Have"])
        self._torrent_pieces_table.horizontalHeader().setStretchLastSection(True)
        self._torrent_pieces_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._torrent_pieces_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tt_layout.addWidget(QLabel("Pieces"))
        tt_layout.addWidget(self._torrent_pieces_table, stretch=2)
        self._torrent_progress = QProgressBar()
        self._torrent_progress.setRange(0, 100)
        tt_layout.addWidget(self._torrent_progress)

        self._inspector_tabs.addTab(self._torrent_tab, "Torrent")

        self._inspector_tabs.currentChanged.connect(self._on_inspector_tab_changed)

        root_layout.addWidget(self._inspector_tabs, stretch=1)

        self.reload_swarm_combo()

    def _emit_swarm_list_changed(self) -> None:
        self.swarm_list_changed.emit()

    def reload_swarm_combo(self) -> None:
        """Rebuild swarm selector from ``SwarmManager`` (called when tracker edits the registry)."""
        preserve = self._swarm_mgr.selected()
        preserve_ih = preserve.info_hash if preserve else None
        self._swarm_combo.blockSignals(True)
        self._swarm_combo.clear()
        rows = self._swarm_mgr.list()
        for sw in rows:
            label = (sw.display_name or "").strip() or sw.short_id
            self._swarm_combo.addItem(label)
            self._swarm_combo.setItemData(
                self._swarm_combo.count() - 1,
                sw.info_hash,
                Qt.ItemDataRole.UserRole,
            )
        self._swarm_combo.blockSignals(False)
        if not rows:
            self._apply_empty_swarm_selection()
            return
        idx = 0
        if preserve_ih is not None:
            for i in range(self._swarm_combo.count()):
                d = self._swarm_combo.itemData(i, Qt.ItemDataRole.UserRole)
                if d == preserve_ih:
                    idx = i
                    break
        self._combo_programmatic = True
        self._swarm_combo.setCurrentIndex(idx)
        self._combo_programmatic = False
        self._apply_combo_index(idx)

    def download_ewma_bps_for_infohash(self, ih: bytes) -> float:
        return float(self._payload_ewma_bps.get(bytes(ih), 0.0))

    def _resume_state_dir(self) -> Path:
        try:
            p = self._torrent_mgr.resume_subdirectory()
            p.mkdir(parents=True, exist_ok=True)
            return p
        except RuntimeError:
            return Path(".dhtrack-resume")

    def completion_percent_for_registered(self, tt: TrackedTorrent, sw: Swarm | None) -> str:
        sw = sw or self._swarm_mgr.get(tt.info_hash)
        if sw is not None:
            tp = sw.total_pieces
            dc = sw.completed_pieces
            tb = sw.total_bytes
            db = sw.downloaded_bytes
            if tp > 0:
                return f"{int(round(100.0 * dc / tp))}%"
            if tb > 0:
                return f"{int(round(100.0 * db / tb))}%"

        meta_disk: bytes | None = None
        try:
            if tt.metadata_path is not None:
                mp = tt.metadata_path.expanduser().resolve()
                if mp.is_file():
                    meta_disk = mp.read_bytes()
        except OSError:
            meta_disk = None

        meta_b: bytes | None = None
        if sw is not None and sw.cached_metadata_bytes:
            meta_b = sw.cached_metadata_bytes
        elif meta_disk is not None:
            meta_b = meta_disk

        if meta_b and self._manager is not None:
            try:
                tor = self._manager.create_torrent(meta_b)
                pcs = piece_hashes(tor)
                n = len(pcs)
                if n <= 0:
                    return "0%"
                bf: bytes | None = sw.local_piece_bitfield if sw is not None else None
                if not bf:
                    resume_path = self._resume_state_dir() / f"{tor.infohash.hex()}.resume.json"
                    rs = ResumeState.load(resume_path)
                    if rs and rs.infohash_hex == tor.infohash.hex() and rs.num_pieces == n:
                        bf = bitfield_from_hex(rs.completed, n)
                done_ct = 0
                if bf is not None:
                    for i in range(n):
                        if bitfield_has(bf, i):
                            done_ct += 1
                return f"{int(round(100.0 * done_ct / n))}%"
            except Exception:
                pass

        return "—"

    def _emit_torrent_jobs_changed(self) -> None:
        self.torrent_jobs_changed.emit()

    def payload_worker_running(self, ih: bytes) -> bool:
        w = self._download_workers.get(bytes(ih))
        return w is not None and w.isRunning()

    def remove_managed_torrent_row(self, ih: bytes) -> None:
        ih_b = bytes(ih)
        w = self._download_workers.get(ih_b)
        if w is not None and w.isRunning():
            self._download_cancel_requested.add(ih_b)
            try:
                w.request_cancel()
            except Exception:
                pass
        starters = self._torrent_mgr.remove(ih_b)
        self._spawn_payload_workers_list(starters)
        self._emit_swarm_list_changed()
        self._emit_torrent_jobs_changed()

    def stop_managed_payload_row(self, ih: bytes) -> str:
        ih_b = bytes(ih)
        w = self._download_workers.get(ih_b)
        if w is None or not w.isRunning():
            return "No active download worker for this torrent."
        self._download_cancel_requested.add(ih_b)
        w.request_cancel()
        sw = self._swarm_mgr.get(ih_b)
        if sw is not None:
            sw.state = "inactive"
        self._emit_swarm_list_changed()
        self._emit_torrent_jobs_changed()
        return "Cancelling download…"

    def dequeue_managed_payload_row(self, ih: bytes) -> None:
        self._torrent_mgr.dequeue_payload_waiting(bytes(ih))
        self._emit_torrent_jobs_changed()

    def _metadata_bytes_for_payload_worker(self, ih: bytes) -> bytes | None:
        tt = self._torrent_mgr.get(bytes(ih))
        if tt is not None and tt.metadata_path is not None:
            try:
                mp = tt.metadata_path.expanduser().resolve()
                if mp.is_file():
                    return mp.read_bytes()
            except OSError:
                pass
        sw = self._swarm_mgr.get(bytes(ih))
        if sw is not None and sw.cached_metadata_bytes:
            return bytes(sw.cached_metadata_bytes)
        return None

    def start_managed_payload_download(self, ih: bytes, parent: QWidget | None = None) -> str:
        """Enqueue payload job using on-disk .torrent or swarm-cached metainfo (no ut_metadata)."""
        from PyQt6.QtWidgets import QFileDialog

        ih_b = bytes(ih)
        if self._manager is None:
            return "DHT manager is not available."
        tt = self._torrent_mgr.get(ih_b)
        if tt is None:
            return "Torrent is not in the library."
        meta_b = self._metadata_bytes_for_payload_worker(ih_b)
        if meta_b is None:
            return (
                "No local .torrent file and no cached metadata. "
                "Use Swarm Inspector to retrieve metadata or add a .torrent to the library folder."
            )
        tor = self._manager.create_torrent(meta_b)
        if tor is None or tor.infohash != ih_b:
            return "Library metainfo does not match this info-hash."

        out_dir = tt.download_directory
        dlg_parent = parent if parent is not None else self
        if out_dir is None:
            picked = QFileDialog.getExistingDirectory(dlg_parent, "Select download directory")
            if not picked:
                return "No folder selected."
            self._torrent_mgr.set_download_directory(ih_b, Path(picked))
            out_dir = self._torrent_mgr.get(ih_b).download_directory

        if out_dir is None:
            return "Could not set download directory."

        existing = self._download_workers.get(ih_b)
        if existing is not None and existing.isRunning():
            return "Download already running for this torrent."

        display_name = (tt.display_name or "").strip() or tor.name
        starters = self._torrent_mgr.enqueue_payload_download(
            ih_b,
            out_dir,
            display_name=display_name or None,
        )
        self._spawn_payload_workers_list(starters)
        self._emit_torrent_jobs_changed()
        if ih_b in starters:
            return "Starting download…"
        return "Queued for download (waiting for a concurrent slot)."

    def _open_metadata_tab_and_retrieve(self) -> None:
        mdx = self._inspector_tabs.indexOf(self._metadata_tab)
        if mdx >= 0:
            self._inspector_tabs.setCurrentIndex(mdx)
        self._retrieve_metadata()

    def _stash_payload_err(self, ih: bytes, msg: str) -> None:
        ix = bytes(ih)
        if ix in self._payload_finish_err:
            return
        line = msg.strip().splitlines()[0] if msg.strip() else "download error"
        self._payload_finish_err[ix] = line[:600]

    def _on_payload_ok_marker(self, ih: bytes) -> None:
        self._payload_finish_ok.add(bytes(ih))

    def _spawn_payload_workers_list(self, starters: list[bytes]) -> None:
        for s in starters:
            self._spawn_payload_worker_for_infohash(s)

    def _spawn_payload_worker_for_infohash(self, ih_raw: bytes) -> None:
        if self._manager is None:
            return
        ih = bytes(ih_raw)
        ex = self._download_workers.get(ih)
        if ex is not None and ex.isRunning():
            return
        tt = self._torrent_mgr.get(ih)
        if tt is None or tt.download_directory is None:
            starters_err = self._torrent_mgr.release_payload_slot(
                ih,
                error_message="Missing download directory.",
            )
            self._spawn_payload_workers_list(starters_err)
            return
        sw = self._swarm_mgr.get(ih)
        if sw is not None:
            sw.state = "downloading"
        out_dir = str(tt.download_directory)
        meta_ov = self._metadata_bytes_for_payload_worker(ih)
        w = DownloadWorker(
            ih,
            out_dir,
            manager=self._manager,
            resume_dir=str(self._resume_state_dir()),
            metainfo_override=meta_ov,
        )
        self._download_workers[ih] = w
        self._download_worker = w
        _qc = Qt.ConnectionType.QueuedConnection

        def _prog(msg: str, ix: bytes = ih) -> None:
            sel = self._swarm_mgr.selected()
            if sel is not None and sel.info_hash == ix:
                self.status_label.setText(msg)

        w.progress_updated.connect(_prog, _qc)
        w.peer_wire_snapshot.connect(
            lambda ip_a, po, snap, ix=ih: self._merge_peer_runtime_for_swarm(ix, ip_a, int(po), snap),
            _qc,
        )
        w.payload_progress.connect(self._on_payload_progress, _qc)
        w.error_occurred.connect(lambda m, ix=ih: self._stash_payload_err(ix, m))
        w.finished_ok.connect(lambda ix=ih: self._on_payload_ok_marker(ix), _qc)
        w.finished.connect(lambda ix=ih: self._finish_payload_download_worker(ix))
        try:
            w.start()
        except Exception as exc:
            self._stash_payload_err(ih, str(exc))
            self._finish_payload_download_worker(ih)

    def _finish_payload_download_worker(self, ih_b: bytes) -> None:
        ih = bytes(ih_b)
        self._download_workers.pop(ih, None)
        self._download_worker = None
        if self._torrent_mgr.get(ih) is None:
            self._payload_ewma_bps.pop(ih, None)
            self._payload_ewma_prev_bytes.pop(ih, None)
            self._payload_ewma_prev_time.pop(ih, None)
            self._payload_finish_ok.discard(ih)
            self._payload_finish_err.pop(ih, None)
            self._torrent_teardown_pending.discard(ih)
            self._download_cancel_requested.discard(ih)
            return

        teardown = ih in self._torrent_teardown_pending
        cancelled = teardown or ih in self._download_cancel_requested
        self._torrent_teardown_pending.discard(ih)
        self._download_cancel_requested.discard(ih)
        ok_marker = ih in self._payload_finish_ok
        self._payload_finish_ok.discard(ih)
        err_first = self._payload_finish_err.pop(ih, None)
        starters: list[bytes] = []
        sw = self._swarm_mgr.get(ih)

        self._payload_ewma_bps.pop(ih, None)
        self._payload_ewma_prev_bytes.pop(ih, None)
        self._payload_ewma_prev_time.pop(ih, None)

        if cancelled:
            starters = self._torrent_mgr.release_payload_slot(ih, cancelled=True)
            if sw is not None:
                sw.state = "inactive"
        elif err_first:
            starters = self._torrent_mgr.release_payload_slot(ih, error_message=err_first)
            if sw is not None:
                sw.state = "error"
                sw.last_error = err_first
        elif ok_marker:
            starters = self._torrent_mgr.release_payload_slot(ih, complete=True)
            if sw is not None:
                sw.state = "seeding_disabled_complete"
        else:
            starters = self._torrent_mgr.release_payload_slot(
                ih,
                error_message="Download ended unexpectedly.",
            )
            if sw is not None:
                sw.state = "error"

        self._spawn_payload_workers_list(starters)
        self._emit_swarm_list_changed()

        sel = self._swarm_mgr.selected()
        if sel is not None:
            ww = self._download_workers.get(sel.info_hash)
            self.stop_download_btn.setEnabled(bool(ww is not None and ww.isRunning()))
            self.download_btn.setEnabled(
                bool(self._manager is not None and sel.cached_metadata_bytes),
            )

        tw = self._inspector_tabs.currentWidget()
        if tw is self._torrent_tab:
            self._refresh_torrent_tab()
        self._emit_torrent_jobs_changed()

    def _merge_peer_runtime_for_swarm(self, ih: bytes, ip: str, port: int, snap_obj: object) -> None:
        if not isinstance(snap_obj, dict):
            return
        sw = self._swarm_mgr.get(bytes(ih))
        if sw is None:
            return
        p = self._ensure_swarm_peer_row(sw, ip, port)
        merge_peer_detail_fields(p, snap_obj)
        p["last_seen"] = time.time()
        sw.last_updated = time.time()
        self._swarm_mgr.update_swarm_peers(sw.info_hash, list(sw.swarm_peers))
        sel = self._swarm_mgr.selected()
        if sel is not None and sel.info_hash == sw.info_hash:
            self._refresh_selected_swarm_views()

    def _register_library_from_metadata(self) -> None:
        """Register selected swarm metadata in Torrent Manager library (no enqueue)."""
        sw = self._swarm_mgr.selected()
        if sw is None:
            self.status_label.setText("Select a tracked swarm first.")
            return
        meta_b = sw.cached_metadata_bytes
        if not meta_b:
            self.status_label.setText("Retrieve metadata first.")
            return
        display_name = sw.display_name
        if display_name is None and self._manager is not None:
            try:
                tor = self._manager.create_torrent(meta_b)
                if tor is not None:
                    display_name = tor.name
            except Exception:
                pass
        self._torrent_mgr.register_library_metadata_only(sw.info_hash, display_name=display_name)
        self._emit_torrent_jobs_changed()
        self._emit_swarm_list_changed()
        self.status_label.setText("Registered in Torrent Manager.")

    def _apply_empty_swarm_selection(self) -> None:
        self._swarm_mgr.deselect()
        self.status_label.setText("No tracked swarms — use the Swarm Tracker tab.")
        for w in (
            self.resolve_btn,
            self.stop_resolve_btn,
            self.download_btn,
            self.retrieve_meta_from_peers_btn,
            self.retrieve_meta_btn,
            self.register_library_btn,
            self.stop_download_btn,
        ):
            w.setEnabled(False)
        self.swarm_model.set_peers([])
        self.dht_model.set_nodes([])
        self._emit_torrent_jobs_changed()

    def _apply_combo_index(self, idx: int) -> None:
        if idx < 0:
            self._apply_empty_swarm_selection()
            return
        ih = self._swarm_combo.itemData(idx, Qt.ItemDataRole.UserRole)
        if not ih or not isinstance(ih, (bytes, memoryview)):
            return
        ihb = bytes(ih)
        self._swarm_mgr.select(ihb)
        w = self._download_workers.get(ihb)
        self.stop_download_btn.setEnabled(bool(w is not None and w.isRunning()))
        self.resolve_btn.setEnabled(True)
        self._refresh_selected_swarm_views()
        if self._inspector_tabs.currentWidget() is self._torrent_tab:
            self._refresh_torrent_tab()

    def _on_swarm_combo_changed(self, idx: int) -> None:
        if getattr(self, "_combo_programmatic", False):
            return
        if idx < 0:
            return
        self._apply_combo_index(idx)

    def teardown_swarm_workers(self, info_hash: bytes) -> None:
        """Stop resolve/download/metadata work for ``info_hash`` (e.g. before swarm removed)."""
        ih = bytes(info_hash)
        self._torrent_mgr.dequeue_payload_waiting(ih)
        w = self._download_workers.get(ih)
        if w is not None and w.isRunning():
            self._torrent_teardown_pending.add(ih)
            self._download_cancel_requested.add(ih)
            try:
                w.request_cancel()
            except Exception:
                pass
        rw = self._workers.pop(ih, None)
        if rw is not None and rw.isRunning():
            try:
                rw.terminate_thread()
            except Exception:
                pass
        mw = self._metadata_worker
        if mw is not None and mw.isRunning() and mw.info_hash == ih:
            try:
                mw.terminate()
                mw.wait(3000)
            except Exception:
                pass
            self._metadata_worker = None
        self._emit_torrent_jobs_changed()

    def _on_active_peers_filter_toggled(self, checked: bool) -> None:
        self.swarm_model.set_show_active_only(bool(checked))

    def _on_inspector_tab_changed(self, idx: int) -> None:
        widget = self._inspector_tabs.widget(idx)
        if widget is self._torrent_tab:
            self._refresh_torrent_tab()

    def _piece_byte_len(self, piece_len: int, total_len: int, index: int, num_pieces: int) -> int:
        if num_pieces <= 0:
            return 0
        if index == num_pieces - 1:
            remain = total_len - index * piece_len
            return max(0, int(remain))
        return int(piece_len)

    def _refresh_torrent_tab(self) -> None:
        sw = self._swarm_mgr.selected()
        if sw is None:
            self._torrent_summary.setPlainText("Select a swarm with retrieved metadata.")
            self._torrent_files_table.setRowCount(0)
            self._torrent_pieces_table.setRowCount(0)
            self._torrent_progress.setValue(0)
            return
        meta_b = sw.cached_metadata_bytes
        if not meta_b or self._manager is None:
            self._torrent_summary.setPlainText(
                "No cached metadata yet. Open Torrent Metadata and run Retrieve.",
            )
            self._torrent_files_table.setRowCount(0)
            self._torrent_pieces_table.setRowCount(0)
            self._torrent_progress.setValue(0)
            return
        tor = self._manager.create_torrent(meta_b)
        if tor is None:
            self._torrent_summary.setPlainText("Failed to parse cached metadata.")
            return
        pcs = piece_hashes(tor)
        n = len(pcs)
        pl = tor.get_piece_length()
        tl = total_length(tor)
        summary = "\n".join(
            [
                f"Name:         {tor.name!r}",
                f"Info hash:    {tor.infohash.hex()}",
                f"Piece length: {pl}",
                f"Pieces:       {n}",
                f"Total bytes:  {tl}",
            ]
        )
        self._torrent_summary.setPlainText(summary)

        try:
            pairs = torrent_files(tor)
        except Exception:
            pairs = []
        self._torrent_files_table.setRowCount(len(pairs))
        for r, (path, ln) in enumerate(pairs):
            self._torrent_files_table.setItem(r, 0, QTableWidgetItem(str(path)))
            self._torrent_files_table.setItem(r, 1, QTableWidgetItem(str(ln)))

        bf: bytes | None = sw.local_piece_bitfield
        if not bf and n > 0:
            resume_path = self._resume_state_dir() / f"{tor.infohash.hex()}.resume.json"
            rs = ResumeState.load(resume_path)
            if rs and rs.infohash_hex == tor.infohash.hex() and rs.num_pieces == n:
                bf = bitfield_from_hex(rs.completed, n)

        self._torrent_pieces_table.setRowCount(n)
        done_ct = 0
        for i in range(n):
            sz = self._piece_byte_len(pl, tl, i, n)
            self._torrent_pieces_table.setItem(i, 0, QTableWidgetItem(str(i)))
            self._torrent_pieces_table.setItem(i, 1, QTableWidgetItem(str(sz)))
            has = bool(bf is not None and bitfield_has(bf, i))
            if has:
                done_ct += 1
            self._torrent_pieces_table.setItem(
                i,
                2,
                QTableWidgetItem("yes" if has else "no"),
            )
        pct = int(round(100.0 * done_ct / n)) if n else 0
        self._torrent_progress.setValue(pct)

    def _ensure_swarm_peer_row(self, sw: Swarm, ip: str, port: int) -> dict:
        for p in sw.swarm_peers:
            if str(p.get("ip")) == str(ip) and int(p.get("port", 0)) == int(port):
                return p
        try:
            is_v6 = ipaddress.ip_address(ip).version == 6
        except ValueError:
            is_v6 = False
        row: dict = {
            "ip": ip,
            "port": int(port),
            "is_ipv6": is_v6,
            "source": "wire",
            "status": "connected",
            "last_seen": time.time(),
        }
        sw.swarm_peers.append(row)
        sw.last_updated = time.time()
        return row

    def _merge_peer_runtime_detail(self, ip: str, port: int, detail: dict) -> None:
        sw = self._swarm_mgr.selected()
        if sw is None:
            return
        p = self._ensure_swarm_peer_row(sw, ip, port)
        merge_peer_detail_fields(p, detail)
        p["last_seen"] = time.time()
        sw.last_updated = time.time()

    def _on_peer_detail_from_metadata(self, ip: str, port: int, detail_obj: object) -> None:
        if not isinstance(detail_obj, dict):
            return
        self._merge_peer_runtime_detail(ip, port, detail_obj)
        sw = self._swarm_mgr.selected()
        if sw is not None:
            self._swarm_mgr.update_swarm_peers(sw.info_hash, list(sw.swarm_peers))
            self._refresh_selected_swarm_views()

    def _on_payload_peer_snap(self, ip: str, port: int, snap_obj: object) -> None:
        """Legacy path (selected swarm); concurrent downloads use per-ih snapshots."""
        if not isinstance(snap_obj, dict):
            return
        self._merge_peer_runtime_detail(ip, port, snap_obj)
        sw = self._swarm_mgr.selected()
        if sw is not None:
            self._swarm_mgr.update_swarm_peers(sw.info_hash, list(sw.swarm_peers))
            self._refresh_selected_swarm_views()

    def _on_payload_progress(self, info_hash: bytes, prog_obj: object) -> None:
        ix = bytes(info_hash)
        sw = self._swarm_mgr.get(ix)
        if sw is None:
            return
        p = prog_obj
        try:
            self._swarm_mgr.update_download_progress(
                ix,
                completed_pieces=int(getattr(p, "completed_pieces", 0)),
                total_pieces=int(getattr(p, "total_pieces", 0)),
                downloaded_bytes=int(getattr(p, "downloaded_bytes", 0)),
                total_bytes=int(getattr(p, "total_bytes", 0)),
            )
            bf = getattr(p, "have_bitfield", None)
            if bf is not None:
                self._swarm_mgr.update_local_piece_bitfield(ix, bytes(bf))
            now_m = time.time()
            cur_b = int(getattr(p, "downloaded_bytes", 0))
            rate, nb, nt = _ewma_throughput_bps(
                alpha=0.35,
                prev_rate=self._payload_ewma_bps.get(ix),
                prev_bytes=self._payload_ewma_prev_bytes.get(ix),
                prev_time=self._payload_ewma_prev_time.get(ix),
                cur_bytes=cur_b,
                cur_time=now_m,
            )
            self._payload_ewma_bps[ix] = rate
            self._payload_ewma_prev_bytes[ix] = nb
            self._payload_ewma_prev_time[ix] = nt
        except Exception:
            pass
        self._emit_swarm_list_changed()
        sel = self._swarm_mgr.selected()
        if sel is not None and sel.info_hash == ix:
            if self._inspector_tabs.currentWidget() is self._torrent_tab:
                self._refresh_torrent_tab()

    def _add_metadata_section(self, layout: QVBoxLayout) -> None:
        """Add torrent metadata retrieval section."""
        # Metadata frame
        meta_frame = QFrame()
        meta_frame.setStyleSheet(
            "QFrame { background-color: #1e1e2e; border: 1px solid #a6e3a1; border-radius: 4px; padding: 8px; }"
        )
        meta_layout = QVBoxLayout(meta_frame)
        meta_layout.setContentsMargins(8, 8, 8, 8)

        # Title
        meta_title = QLabel("Torrent Metadata Retrieval (BEP 9)")
        meta_title.setStyleSheet("color: #a6e3a1; font-size: 12px; font-weight: bold;")
        meta_layout.addWidget(meta_title)

        # Info
        meta_info = QLabel("Retrieve the .torrent metadata file from DHT peers using the ut_metadata (BEP 9) protocol.")
        meta_info.setStyleSheet("color: #cdd6f4; font-size: 10px;")
        meta_layout.addWidget(meta_info)

        # Retrieve button
        self.retrieve_meta_btn = QPushButton("Retrieve Metadata")
        self.retrieve_meta_btn.clicked.connect(self._retrieve_metadata)
        self.retrieve_meta_btn.setStyleSheet(
            "background-color: #a6e3a1; color: #1e1e2e; font-weight: bold; padding: 6px;"
        )
        self.retrieve_meta_btn.setEnabled(False)
        meta_layout.addWidget(self.retrieve_meta_btn)

        self.register_library_btn = QPushButton("Register in library")
        self.register_library_btn.setToolTip(
            "Add this swarm to Torrent Manager metadata library (does not enqueue download). "
            "Requires retrieved metadata.",
        )
        self.register_library_btn.clicked.connect(self._register_library_from_metadata)
        self.register_library_btn.setStyleSheet("background-color: #313244; color: #cdd6f4; padding: 6px;")
        self.register_library_btn.setEnabled(False)
        meta_layout.addWidget(self.register_library_btn)

        # Progress
        self.meta_progress_label = QLabel("")
        self.meta_progress_label.setStyleSheet("color: #f5c2e7; font-size: 10px;")
        meta_layout.addWidget(self.meta_progress_label)

        # Metadata output
        meta_output = QFrame()
        meta_output.setStyleSheet(
            "QFrame { background-color: #0f0f1a; border: 1px solid #313244; border-radius: 4px; padding: 4px; }"
        )
        meta_output_layout = QVBoxLayout(meta_output)
        meta_output_layout.setContentsMargins(4, 4, 4, 4)

        meta_out_title = QLabel("Metadata Contents:")
        meta_out_title.setStyleSheet("color: #89b4fa; font-weight: bold; font-size: 10px;")
        meta_output_layout.addWidget(meta_out_title)

        self.meta_output_text = QTextEdit()
        self.meta_output_text.setReadOnly(True)
        self.meta_output_text.setMinimumHeight(280)
        self.meta_output_text.setStyleSheet(
            "QTextEdit { background-color: #0f0f1a; color: #a6adc8; font-family: monospace; border: none; }"
        )
        meta_output_layout.addWidget(self.meta_output_text)

        meta_layout.addWidget(meta_output)
        layout.addWidget(meta_frame)

    def _resolve_selected_swarm(self) -> None:
        """Start DHT peer discovery for the swarm selected in the combo box."""
        sw = self._swarm_mgr.selected()
        if sw is None:
            self.status_label.setText("Select a tracked swarm in the list above (Swarm Tracker tab).")
            return
        sw.state = "active"
        self._emit_swarm_list_changed()
        self._start_swarm_worker(sw)
        self.download_btn.setEnabled(self._manager is not None)

    def _start_swarm_worker(self, sw: Swarm) -> None:
        # Start a resolve worker per swarm if not already running.
        w = self._workers.get(sw.info_hash)
        if w is not None and w.isRunning():
            self.status_label.setText(f"Swarm {sw.short_id} already resolving...")
            return

        self.status_label.setText(f"Resolving swarm {sw.short_id}…")
        self.resolve_btn.setEnabled(False)
        self.stop_resolve_btn.setEnabled(True)

        # Prefer DHTManager when available so resolve uses the shared manager pipeline.
        resolve_ref: object = self._manager if self._manager is not None else self._dht_ref
        w = PeerResolveWorker(resolve_ref, sw.info_hash, timeout=60.0)
        w.peers_updated.connect(lambda peers, ih=sw.info_hash: self._on_swarm_peers_updated(ih, peers))
        w.dht_nodes_updated.connect(lambda nodes, ih=sw.info_hash: self._on_swarm_dht_nodes_updated(ih, nodes))
        w.progress_updated.connect(self._on_resolve_progress)
        w.finished.connect(lambda ih=sw.info_hash: self._on_swarm_worker_finished(ih))
        self._workers[sw.info_hash] = w
        w.start()

    def _get_all_routing_nodes(self) -> list:
        """Get routing table nodes for display."""
        nodes = []
        try:
            for table in [
                self.dht_node.routing_table.v4,
                self.dht_node.routing_table.v6,
            ]:
                for bucket in table.buckets:
                    for node in bucket.nodes:
                        nodes.append(
                            {
                                "node_id": node.node_id,
                                "ip": node.endpoint.ip,
                                "port": node.endpoint.port,
                                "is_ipv6": node.endpoint.is_ipv6,
                                "status": node.status,
                                "last_contacted": node.last_contacted,
                                "rpc_counter": node.rpc_counter,
                                "failure_count": node.failure_count,
                                "source": "routing_table",
                            }
                        )
        except AttributeError:
            pass
        return nodes

    def _on_swarm_peers_updated(self, info_hash: bytes, swarm_peers: list) -> None:
        self._swarm_mgr.update_swarm_peers(info_hash, list(swarm_peers or []))
        self._emit_swarm_list_changed()
        self._refresh_selected_swarm_views()

    def _on_swarm_dht_nodes_updated(self, info_hash: bytes, nodes: list) -> None:
        self._swarm_mgr.update_dht_nodes(info_hash, list(nodes or []))
        self._emit_swarm_list_changed()
        self._refresh_selected_swarm_views()

    def _refresh_selected_swarm_views(self) -> None:
        sw = self._swarm_mgr.selected()
        if sw is None:
            return
        self._swarm_peers = list(sw.swarm_peers or [])
        self._dht_nodes = list(sw.dht_nodes or [])
        self.swarm_model.set_peers(sw.swarm_peers)
        self.dht_model.set_nodes(sw.dht_nodes)
        peer_or_magnet = bool(sw.swarm_peers or getattr(sw, "magnet_peer_triplets", ()))
        self.retrieve_meta_btn.setEnabled(peer_or_magnet)
        self.retrieve_meta_from_peers_btn.setEnabled(peer_or_magnet)
        has_meta = bool(sw.cached_metadata_bytes)
        mgr_ok = self._manager is not None
        self.download_btn.setEnabled(bool(mgr_ok and has_meta))
        self.register_library_btn.setEnabled(bool(has_meta))
        w = self._download_workers.get(sw.info_hash)
        self.stop_download_btn.setEnabled(bool(w is not None and w.isRunning()))

    def _on_resolve_progress(self, message: str) -> None:
        """Discovery progress line."""
        self.status_label.setText(message)

    def _on_swarm_worker_finished(self, info_hash: bytes) -> None:
        sw = self._swarm_mgr.get(info_hash)
        if sw is not None:
            sw.state = "inactive"
        self._emit_swarm_list_changed()
        self.resolve_btn.setEnabled(True)
        self.stop_resolve_btn.setEnabled(False)
        self._refresh_selected_swarm_views()

    def _stop_resolve(self) -> None:
        """Cancel in-flight get_peers search."""
        sw = self._swarm_mgr.selected()
        if sw is None:
            return
        w = self._workers.get(sw.info_hash)
        if w is not None and w.isRunning():
            w.terminate_thread()
            self.status_label.setText("Stopping peer discovery…")

    def _swarm_peer_at_row(self, row: int) -> dict[str, Any] | None:
        peer: dict[str, Any] | None = None
        if hasattr(self, "swarm_model") and hasattr(self.swarm_model, "peer_at"):
            peer = self.swarm_model.peer_at(row)  # type: ignore[attr-defined, assignment]
        if peer is None:
            if row < 0 or row >= len(self._swarm_peers):
                return None
            peer = self._swarm_peers[row]
        return peer

    def _on_swarm_peer_double_clicked(self, index) -> None:  # type: ignore[no-untyped-def]
        try:
            peer = self._swarm_peer_at_row(int(index.row()))
            if peer is None:
                return
            self.details_text.setPlainText(format_peer_expert_detail(peer))
        except Exception as exc:
            self.details_text.setPlainText(f"(error showing peer details: {exc})")

    def _on_swarm_selection_changed(self) -> None:
        try:
            selection = self.swarm_table_view.selectionModel().selection()
            if not selection.indexes():
                return
            row = selection.indexes()[0].row()
            peer = self._swarm_peer_at_row(row)
            if peer is None:
                return
            self.details_text.setPlainText(format_peer_expert_detail(peer))
        except Exception as exc:
            # Never crash the app from a UI selection handler.
            self.details_text.setPlainText(f"(error showing peer details: {exc})")

    def _on_dht_selection_changed(self) -> None:
        selection = self.dht_table_view.selectionModel().selection()
        if not selection.indexes():
            return
        idx = selection.indexes()[0]
        row = idx.row()
        if row < 0 or row >= len(self._dht_nodes):
            return
        peer = self._dht_nodes[row]
        self.details_text.setPlainText(format_peer_expert_detail(peer))

    def _retrieve_metadata(self) -> None:
        """Start retrieving torrent metadata from peers."""
        sw = self._swarm_mgr.selected()
        infohash = sw.info_hash if sw is not None else None
        if not infohash:
            self.status_label.setText("Select a tracked swarm first.")
            return

        from_swarm: list[tuple[str, int, bool]] = []
        swarm_peers = sw.swarm_peers if sw is not None else []
        for p in list(swarm_peers or []):
            ip = p.get("ip")
            port = p.get("port")
            if ip and isinstance(port, int):
                from_swarm.append((str(ip), int(port), bool(p.get("is_ipv6", False))))

        if not from_swarm and hasattr(self.dht_node, "peer_store"):
            for sp in self.dht_node.peer_store.get_peers(infohash):
                from_swarm.append((sp.ip, sp.port, getattr(sp, "is_ipv6", False)))

        magnet_hints = list(getattr(sw, "magnet_peer_triplets", ()) or [])
        triplets = merge_peer_triplets_preferred(magnet_hints, from_swarm)

        if not triplets:
            self.status_label.setText(
                "No peers to try — add a magnet with pe= hints or run Resolve until swarm peers appear.",
            )
            return

        self._resolved_infohash = infohash

        # Disable button and clear output
        self._meta_retrieval_succeeded = False
        self.retrieve_meta_btn.setEnabled(False)
        self.meta_output_text.setPlainText("")
        self.meta_progress_label.setText("Retrieving metadata...")

        # Start metadata retrieval worker (queued cross-thread delivery like resolve)
        self._metadata_worker = MetadataRetrievalWorker(infohash, triplets, manager=self._manager)
        _qc = Qt.ConnectionType.QueuedConnection
        self._metadata_worker.progress_updated.connect(self._on_meta_progress, _qc)
        self._metadata_worker.peer_detail_updated.connect(self._on_peer_detail_from_metadata, _qc)
        self._metadata_worker.metadata_ready.connect(self._on_meta_success, _qc)
        self._metadata_worker.error_occurred.connect(self._on_meta_error, _qc)
        self._metadata_worker.finished.connect(self._on_metadata_worker_finished)
        self._metadata_worker.start()

    def _download_payload(self) -> None:
        sw = self._swarm_mgr.selected()
        if sw is None:
            self.status_label.setText("Select a tracked swarm first.")
            return
        if self._manager is None:
            self.status_label.setText("Download requires DHTManager.")
            return
        if not sw.cached_metadata_bytes:
            self.status_label.setText("Retrieve metadata first (Torrent Metadata tab).")
            mdx = self._inspector_tabs.indexOf(self._metadata_tab)
            if mdx >= 0:
                self._inspector_tabs.setCurrentIndex(mdx)
            return

        out_dir = QFileDialog.getExistingDirectory(self, "Select download directory")
        if not out_dir:
            return

        existing = self._download_workers.get(sw.info_hash)
        if existing is not None and existing.isRunning():
            self.status_label.setText("Download already running for this swarm.")
            return

        display_name = sw.display_name
        if display_name is None:
            try:
                tor = self._manager.create_torrent(sw.cached_metadata_bytes)
                if tor is not None:
                    display_name = tor.name
            except Exception:
                pass

        starters = self._torrent_mgr.enqueue_payload_download(
            sw.info_hash,
            Path(out_dir),
            display_name=display_name,
        )
        self._spawn_payload_workers_list(starters)

        ww = self._download_workers.get(sw.info_hash)
        self.stop_download_btn.setEnabled(bool(ww is not None and ww.isRunning()))
        self.download_btn.setEnabled(bool(self._manager is not None and sw.cached_metadata_bytes))
        msg = (
            "Queued payload download — see Torrent Manager for status."
            if sw.info_hash not in starters
            else "Starting payload download…"
        )
        self.status_label.setText(msg)
        self._emit_swarm_list_changed()
        self._emit_torrent_jobs_changed()

    def _stop_download(self) -> None:
        sw = self._swarm_mgr.selected()
        if sw is None:
            return
        ih = sw.info_hash
        w = self._download_workers.get(ih)
        if w is None or not w.isRunning():
            self.status_label.setText("No download running for the selected swarm.")
            self.stop_download_btn.setEnabled(False)
            return
        self._download_cancel_requested.add(ih)
        w.request_cancel()
        self.status_label.setText("Cancelling download…")
        sw.state = "inactive"
        self._emit_swarm_list_changed()
        self._emit_torrent_jobs_changed()

    def _on_metadata_worker_finished(self) -> None:
        """Re-enable controls if the retrieval thread exits (success, error, or crash)."""
        self._refresh_selected_swarm_views()

    def _on_meta_progress(self, message: str) -> None:
        """Handle metadata retrieval progress updates."""
        # Executor threads may still queue signals; ignore after we've shown metadata.
        if self._meta_retrieval_succeeded:
            return
        # Special internal signal to update per-peer status in the swarm peer table.
        if message.startswith("peer_status "):
            try:
                rest = message[len("peer_status ") :]
                parts = rest.split(" ", 2)
                host = parts[0]
                status = parts[1] if len(parts) > 1 else "unknown"
                err = parts[2] if len(parts) > 2 else None
                if ":" in host:
                    ip, port_s = host.rsplit(":", 1)
                    port = int(port_s)
                    self._set_peer_runtime_status(ip, port, status, err)
                    self._refresh_selected_swarm_views()
            except Exception:
                pass
            return
        self.meta_progress_label.setText(message)

    def _set_peer_runtime_status(self, ip: str, port: int, status: str, err: str | None) -> None:
        sw = self._swarm_mgr.selected()
        if sw is None:
            return
        changed = False
        for p in sw.swarm_peers:
            if str(p.get("ip")) == str(ip) and int(p.get("port", 0)) == int(port):
                p["status"] = status
                if err:
                    p["last_error"] = err
                changed = True
        if changed:
            sw.last_updated = time.time()

    def _on_meta_success(self, metadata: bytes) -> None:
        """Handle successful metadata retrieval."""
        self._meta_retrieval_succeeded = True
        self.meta_progress_label.setText(f"Metadata retrieved successfully! ({len(metadata)} bytes)")
        sw = self._swarm_mgr.selected()
        if sw is not None:
            self._swarm_mgr.update_cached_metadata(sw.info_hash, metadata)
            try:
                self._torrent_mgr.save_metadata_blob(sw.info_hash, metadata)
            except RuntimeError:
                pass
            except Exception as exc:
                _resolver_log.warning("Could not persist torrent metainfo: %s", exc)
        if getattr(self, "_inspector_tabs", None) and self._inspector_tabs.currentWidget() is self._torrent_tab:
            self._refresh_torrent_tab()
        self._refresh_selected_swarm_views()
        self._emit_torrent_jobs_changed()

        # Parse and display the metadata (ut_metadata returns raw *info* dict bytes)
        try:
            from dhtrack import bencode as bencode_module

            computed_ih = hashlib.sha1(metadata).hexdigest()

            torrent_obj = None
            if self._manager is not None:
                try:
                    torrent_obj = self._manager.create_torrent(metadata)
                except Exception:
                    torrent_obj = None

            parsed = bencode_module.decode(metadata)
            lines_out = [
                f"Torrent Metadata ({len(metadata)} bytes)",
                f"SHA-1(info): {computed_ih}",
            ]
            if torrent_obj is not None:
                lines_out.append(
                    f"Torrent (parsed): name={torrent_obj.name!r} "
                    f"piece_length={torrent_obj.get_piece_length()} "
                    f"infohash={torrent_obj.infohash.hex()}",
                )
            lines_out.append("")
            lines_out.append("Full decoded metadata (structure):")
            lines_out.append("─" * 60)
            if isinstance(parsed, (dict, list)):
                lines_out.extend(_format_torrent_bencode_tree(parsed))
            else:
                lines_out.extend(_format_torrent_bencode_tree(parsed))
            lines_out.append("")
            lines_out.append("─" * 60)
            lines_out.append(
                f"Raw bencoded blob: {len(metadata)} bytes "
                "(see structure above; piece digests summarized, not dumped as hex)."
            )

            self.meta_output_text.setPlainText("\n".join(lines_out))
        except Exception as e:
            self.meta_output_text.setPlainText(
                f"Error parsing metadata: {e}\n\nRaw (first 500 bytes):\n{metadata[:500]}"
            )

    def _on_meta_error(self, error_msg: str) -> None:
        """Handle metadata retrieval error."""
        self._meta_retrieval_succeeded = False
        self.meta_progress_label.setText("Metadata retrieval failed")
        self.meta_output_text.setPlainText(
            f"Error: {error_msg}\n\n"
            "This is expected for torrents that:\n"
            "  1. Have no active/seeding peers\n"
            "  2. Are behind firewalls/NAT\n"
            "  3. Have expired from the DHT"
        )
