"""
GUI Settings — runtime-tunable configuration for the dhtrack inspector.

This module exposes a ``GuiSettings`` dataclass that mirrors every tunable
constant scattered across the dhtrack core (``dht``, ``metadata_retriever``,
``peer``, ``tracker``, ``udp_tracker``, ``lsd``, ``webseed``, ``utp``,
``quic``, ``downloader``).

Settings are persisted as JSON in the platform user-config directory:

* Windows: ``%APPDATA%\\dhtrack\\settings.json``
* macOS / Linux: ``~/.config/dhtrack/settings.json``  (or ``$XDG_CONFIG_HOME``)

The dhtrack core uses module-level constants like
``dhtrack.dht.MAX_PENDING_PER_PEER``.  Python looks these up in the module
global namespace at call time, so writing
``dhtrack.dht.MAX_PENDING_PER_PEER = N`` from outside takes effect for
subsequent uses of that name.  This module exploits that to avoid a
core-wide refactor.

A few values that are baked in at construction time (the per-node
``_recent_handled_txids`` deque, ``peers_save_interval``, BEP 42 quorum)
are pushed onto the live ``DHTNode`` instance via attribute assignment.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import sys
from collections import deque
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default values — must mirror the constants in the core modules.
# Keep these in sync if the core defaults change.  We intentionally hard-code
# them here (rather than ``from dhtrack.dht import ...``) so that ``settings``
# stays importable even if the core layout shifts, and so the "Restore
# Defaults" button always restores a known-good baseline.
# ---------------------------------------------------------------------------


_DEFAULT_BOOTSTRAP_NODES: list[tuple[str, int]] = [
    ("router.utorrent.com", 6881),
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("dht.aelitis.com", 6881),
    ("download.deluge-torrent.org", 6881),
    ("ftp.osuosl.org", 6881),
]


_LOGGER_NAMES: tuple[str, ...] = (
    "dhtrack",
    "dhtrack.dht",
    "dhtrack.wire",
    "dhtrack.bencode",
    "dhtrack.bep53",
    "dhtrack.torrent",
    "dhtrack.metadata_retriever",
    "dhtrack.peer",
    "dhtrack.utp",
)


@dataclass
class GuiSettings:
    """Mirror of every tunable in the dhtrack core that is GUI-configurable."""

    # -------- DHT / kRPC --------
    dht_timeout: float = 8.0
    dht_k: int = 8
    dht_max_pending_per_peer: int = 64
    dht_max_pending_global: int = 16384
    dht_txid_handled_cache_size: int = 2048
    dht_get_peers_scrape_qps: float = 32.0
    dht_get_peers_scrape_burst: float = 64.0
    dht_get_peers_scrape_max_inflight: int = 64
    dht_warmup_ping_qps: float = 20.0
    dht_warmup_ping_limit: int = 128
    dht_mtu: int = 1438

    # -------- Routing --------
    dht_replacement_timeout: int = 600
    dht_contact_refresh_interval: int = 900
    dht_secret_rotation_interval: int = 300
    dht_token_max_age: int = 600

    # -------- Peer Store --------
    peerstore_max_peers_per_infohash: int = 2500
    peerstore_max_entries: int = 10000
    peers_save_interval: float = 30.0

    # -------- Bootstrap --------
    bootstrap_nodes: list[tuple[str, int]] = field(
        default_factory=lambda: list(_DEFAULT_BOOTSTRAP_NODES),
    )
    bootstrap_max_peers_file_targets: int = 128
    bootstrap_total_timeout: float = 30.0
    bootstrap_max_depth: int = 3

    # -------- Metadata retriever (ut_metadata) --------
    metadata_peer_concurrency: int = 8
    metadata_max_pieces_inflight: int = 4
    metadata_request_timeout: float = 120.0
    metadata_piece_timeout: float = 30.0
    metadata_max_retries: int = 5
    metadata_max_size: int = 10 * 1024 * 1024
    metadata_block_size: int = 16384

    # -------- Peer Wire (BitTorrent) --------
    peer_max_pending_requests: int = 100
    peer_max_pex_peers: int = 50
    peer_block_len: int = 16 * 1024
    peer_max_request_size: int = 16384
    peer_connect_timeout: float = 8.0
    peer_handshake_timeout: float = 30.0

    # -------- Trackers (HTTP / UDP) --------
    tracker_http_timeout: int = 10
    tracker_http_max_retries: int = 2
    tracker_http_retry_delay: float = 1.0
    tracker_http_numwant: int = 50
    tracker_udp_retry_base_interval: int = 15
    tracker_udp_max_retries: int = 8
    tracker_udp_conn_id_use_limit: int = 120

    # -------- LSD (BEP 14) --------
    lsd_announce_interval: int = 300
    lsd_min_announce_interval: int = 60
    lsd_default_ttl: int = 1
    lsd_listen_port: int = 6881
    lsd_max_packet_size: int = 1400

    # -------- WebSeed (BEP 19) --------
    webseed_http_timeout: int = 30
    webseed_ftp_timeout: int = 30
    webseed_max_redirects: int = 5
    webseed_http_buffer_size: int = 65536
    webseed_ftp_buffer_size: int = 65536
    webseed_user_agent: str = "dhtrack/2.0 (BEP 19 WebSeed)"

    # -------- Persistence & BEP 42 --------
    # -------- Torrent inspector (saved .torrent / resume) --------
    # Empty uses :func:`default_torrent_library_directory` (alongside ``settings.json``).
    torrent_library_directory: str = ""

    peers_file: str = "peers.dat"
    state_file: str = ""  # empty -> derived from peers_file
    persist_node_identity: bool = True
    auto_align_bep42_node_id: bool = True
    observed_ip_min_distinct_responders: int = 3
    bind_port: int = 0  # 0 -> ephemeral

    # -------- Advanced uTP --------
    utp_default_packet_size: int = 1400
    utp_min_packet_size: int = 150
    utp_max_packet_size: int = 65536
    utp_initial_congestion_window: int = 3
    utp_ccontrol_target: int = 100
    utp_initial_timeout_ms: int = 1000
    utp_keepalive_interval: int = 45
    utp_max_pending_packets: int = 100

    # -------- Advanced QUIC --------
    quic_default_port: int = 6881
    quic_max_packet_size: int = 1438

    # -------- Logging --------
    log_levels: dict[str, str] = field(
        default_factory=lambda: dict.fromkeys(_LOGGER_NAMES, "WARNING"),
    )
    wire_logging_enabled: bool = False

    # ----- Helpers -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict.  Tuples become lists."""
        d = dataclasses.asdict(self)
        # bootstrap_nodes contains tuples; coerce to nested lists for JSON.
        d["bootstrap_nodes"] = [list(t) for t in self.bootstrap_nodes]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuiSettings:
        """Build a ``GuiSettings`` from a dict (typically loaded from JSON).

        Unknown keys are ignored; missing keys fall back to defaults.
        """
        defaults = cls()
        kwargs: dict[str, Any] = {}
        known = {f.name for f in fields(cls)}
        for k, v in data.items():
            if k not in known:
                continue
            if k == "bootstrap_nodes":
                try:
                    v = [(str(host), int(port)) for host, port in v]
                except Exception:
                    v = list(getattr(defaults, k))
            kwargs[k] = v
        out = cls(**{**dataclasses.asdict(defaults), **kwargs})
        # Re-tuple bootstrap_nodes (asdict above stripped tuples).
        out.bootstrap_nodes = [(str(h), int(p)) for h, p in (kwargs.get("bootstrap_nodes") or _DEFAULT_BOOTSTRAP_NODES)]
        return out


# ---------------------------------------------------------------------------
# JSON load / save
# ---------------------------------------------------------------------------


def _user_config_dir() -> Path:
    """Return the per-user config directory for dhtrack.

    Honours ``%APPDATA%`` on Windows and ``$XDG_CONFIG_HOME`` (falling back
    to ``~/.config``) on Unix.  The directory is *not* created here.
    """
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return Path(base) / "dhtrack"
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "dhtrack"


def settings_path() -> Path:
    """Return the canonical path to ``settings.json``."""
    return _user_config_dir() / "settings.json"


def default_torrent_library_directory() -> Path:
    """Default folder for persisted ``*.torrent`` metainfo next to GUI config."""
    return _user_config_dir() / "torrents"


def resolved_torrent_library_directory(settings: GuiSettings) -> Path:
    """Absolute torrent library dir from GUI settings."""
    raw = (settings.torrent_library_directory or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return default_torrent_library_directory()


def torrent_resume_subdirectory(settings: GuiSettings) -> Path:
    """Resume JSON subdirectory under the torrent library (co-located with metainfo)."""
    return resolved_torrent_library_directory(settings) / "resume"


def load(path: Path | None = None) -> GuiSettings:
    """Load settings from ``path`` (default: :func:`settings_path`).

    Missing or unreadable files yield default settings with no exception.
    """
    p = Path(path) if path is not None else settings_path()
    if not p.is_file():
        return GuiSettings()
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load settings from %s: %s", p, exc)
        return GuiSettings()
    if not isinstance(data, dict):
        return GuiSettings()
    return GuiSettings.from_dict(data)


def save(settings: GuiSettings, path: Path | None = None) -> None:
    """Save ``settings`` to ``path`` (default: :func:`settings_path`).

    The parent directory is created if missing.  Writes are atomic via a
    ``.tmp`` rename.
    """
    p = Path(path) if path is not None else settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(settings.to_dict(), f, indent=2, sort_keys=True)
    os.replace(tmp, p)


# ---------------------------------------------------------------------------
# Apply to runtime — the actual "make settings take effect" logic.
# ---------------------------------------------------------------------------


def _set_module_attr(module_name: str, attr: str, value: Any) -> None:
    """Best-effort ``setattr(module, attr, value)`` with a single import."""
    try:
        import importlib

        mod = importlib.import_module(module_name)
        setattr(mod, attr, value)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Failed to set %s.%s = %r: %s", module_name, attr, value, exc)


def _apply_log_levels(settings: GuiSettings) -> None:
    """Apply per-logger log levels."""
    for name, level_str in settings.log_levels.items():
        try:
            level = getattr(logging, str(level_str).upper(), logging.WARNING)
            logging.getLogger(name).setLevel(level)
        except Exception:
            pass

    # Wire-trace toggle: forces dhtrack.wire to DEBUG when enabled.
    if settings.wire_logging_enabled:
        logging.getLogger("dhtrack.wire").setLevel(logging.DEBUG)


def _apply_dht_globals(settings: GuiSettings) -> None:
    """Push DHT-related module globals into ``dhtrack.dht``."""
    g = [
        ("TIMEOUT", settings.dht_timeout),
        ("K", settings.dht_k),
        ("BUCKET_SIZE", settings.dht_k),
        ("MAX_PENDING_PER_PEER", settings.dht_max_pending_per_peer),
        ("MAX_PENDING_GLOBAL", settings.dht_max_pending_global),
        ("GET_PEERS_SCRAPE_QPS", settings.dht_get_peers_scrape_qps),
        ("GET_PEERS_SCRAPE_BURST", settings.dht_get_peers_scrape_burst),
        ("GET_PEERS_SCRAPE_MAX_INFLIGHT", settings.dht_get_peers_scrape_max_inflight),
        ("WARMUP_PING_QPS", settings.dht_warmup_ping_qps),
        ("WARMUP_PING_LIMIT", settings.dht_warmup_ping_limit),
        ("MTU", settings.dht_mtu),
        ("REPLACEMENT_TIMEOUT", settings.dht_replacement_timeout),
        ("CONTACT_REFRESH_INTERVAL", settings.dht_contact_refresh_interval),
        ("SECRET_ROTATION_INTERVAL", settings.dht_secret_rotation_interval),
        ("TOKEN_MAX_AGE", settings.dht_token_max_age),
        ("PEERSTORE_MAX_PEERS_PER_INFOHASH_DEFAULT", settings.peerstore_max_peers_per_infohash),
        ("BOOTSTRAP_MAX_PEERS_FILE_TARGETS", settings.bootstrap_max_peers_file_targets),
        ("OBSERVED_IP_MIN_DISTINCT_RESPONDERS_DEFAULT", settings.observed_ip_min_distinct_responders),
        ("DEFAULT_PEERS_FILE", settings.peers_file),
    ]
    for name, value in g:
        _set_module_attr("dhtrack.dht", name, value)

    # Bootstrap node list — mutate in place so existing references see the
    # new entries.
    try:
        import dhtrack.dht as _dht

        if hasattr(_dht, "DEFAULT_BOOTSTRAP_NODES"):
            _dht.DEFAULT_BOOTSTRAP_NODES[:] = [(str(h), int(p)) for h, p in settings.bootstrap_nodes]
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Failed to update DEFAULT_BOOTSTRAP_NODES: %s", exc)


def _apply_metadata_globals(settings: GuiSettings) -> None:
    g = [
        ("METADATA_PEER_CONCURRENCY_DEFAULT", settings.metadata_peer_concurrency),
        ("MAX_PIECES_INFLIGHT", settings.metadata_max_pieces_inflight),
        ("METADATA_REQUEST_TIMEOUT", settings.metadata_request_timeout),
        ("PIECE_TIMEOUT", settings.metadata_piece_timeout),
        ("MAX_RETRIES", settings.metadata_max_retries),
    ]
    for name, value in g:
        _set_module_attr("dhtrack.metadata_retriever", name, value)


def _apply_peer_globals(settings: GuiSettings) -> None:
    g = [
        ("MAX_METADATA_SIZE", settings.metadata_max_size),
        ("METADATA_BLOCK_SIZE", settings.metadata_block_size),
        ("MAX_PENDING_REQUESTS", settings.peer_max_pending_requests),
        ("MAX_PEX_PEERS", settings.peer_max_pex_peers),
        ("MAX_REQUEST_SIZE", settings.peer_max_request_size),
    ]
    for name, value in g:
        _set_module_attr("dhtrack.peer", name, value)


def _apply_downloader_globals(settings: GuiSettings) -> None:
    _set_module_attr("dhtrack.downloader", "BLOCK_LEN", settings.peer_block_len)


def _apply_tracker_globals(settings: GuiSettings) -> None:
    _set_module_attr("dhtrack.udp_tracker", "_RETRY_BASE_INTERVAL", settings.tracker_udp_retry_base_interval)
    _set_module_attr("dhtrack.udp_tracker", "_MAX_RETRIES", settings.tracker_udp_max_retries)
    _set_module_attr("dhtrack.udp_tracker", "_CONN_ID_USE_LIMIT", settings.tracker_udp_conn_id_use_limit)


def _apply_lsd_globals(settings: GuiSettings) -> None:
    g = [
        ("LSD_ANNOUNCE_INTERVAL", settings.lsd_announce_interval),
        ("LSD_MIN_ANNOUNCE_INTERVAL", settings.lsd_min_announce_interval),
        ("LSD_DEFAULT_TTL", settings.lsd_default_ttl),
        ("LSD_PORT", settings.lsd_listen_port),
        ("LSD_MAX_PACKET_SIZE", settings.lsd_max_packet_size),
    ]
    for name, value in g:
        _set_module_attr("dhtrack.lsd", name, value)


def _apply_webseed_globals(settings: GuiSettings) -> None:
    g = [
        ("HTTP_TIMEOUT", settings.webseed_http_timeout),
        ("FTP_TIMEOUT", settings.webseed_ftp_timeout),
        ("MAX_REDIRECTS", settings.webseed_max_redirects),
        ("HTTP_BUFFER_SIZE", settings.webseed_http_buffer_size),
        ("FTP_BUFFER_SIZE", settings.webseed_ftp_buffer_size),
        ("USER_AGENT", settings.webseed_user_agent),
    ]
    for name, value in g:
        _set_module_attr("dhtrack.webseed", name, value)


def _apply_utp_globals(settings: GuiSettings) -> None:
    g = [
        ("DEFAULT_PACKET_SIZE", settings.utp_default_packet_size),
        ("MIN_PACKET_SIZE", settings.utp_min_packet_size),
        ("MAX_PACKET_SIZE", settings.utp_max_packet_size),
        ("INITIAL_CONGESTION_WINDOW", settings.utp_initial_congestion_window),
        ("CCONTROL_TARGET", settings.utp_ccontrol_target),
        ("INITIAL_TIMEOUT_MS", settings.utp_initial_timeout_ms),
        ("KEEPALIVE_INTERVAL", settings.utp_keepalive_interval),
        ("MAX_PENDING_PACKETS", settings.utp_max_pending_packets),
    ]
    for name, value in g:
        _set_module_attr("dhtrack.utp", name, value)


def _apply_quic_globals(settings: GuiSettings) -> None:
    _set_module_attr("dhtrack.quic", "QUIC_DEFAULT_PORT", settings.quic_default_port)
    _set_module_attr("dhtrack.quic", "QUIC_MAX_PACKET_SIZE", settings.quic_max_packet_size)


def _apply_node_instance(settings: GuiSettings, node: Any) -> None:
    """Push instance-attribute settings onto a live ``DHTNode``."""
    if node is None:
        return

    # peers_save_interval is a plain attribute we can update in-place.
    try:
        node.peers_save_interval = float(settings.peers_save_interval)
    except Exception:
        pass

    # observed_ip_min_distinct_responders likewise.
    try:
        node.observed_ip_min_distinct_responders = max(
            1,
            int(settings.observed_ip_min_distinct_responders),
        )
    except Exception:
        pass

    # auto_align_bep42_node_id is an instance bool.
    try:
        node.auto_align_bep42_node_id = bool(settings.auto_align_bep42_node_id)
    except Exception:
        pass

    # Resize the recently-handled-txid cache: the deque's ``maxlen`` is
    # immutable, so we rebuild the deque copying the current items.
    try:
        new_maxlen = int(settings.dht_txid_handled_cache_size)
        if new_maxlen > 0 and hasattr(node, "_recent_handled_txids"):
            old = node._recent_handled_txids
            node._recent_handled_txids = deque(old, maxlen=new_maxlen)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Failed to resize TXID handled cache: %s", exc)


def apply_to_runtime(
    settings: GuiSettings,
    *,
    node: Any | None = None,
    manager: Any | None = None,
) -> None:
    """Apply ``settings`` to the live dhtrack runtime.

    Most settings update module-level globals (which are looked up at
    call time inside the core).  A subset is pushed directly onto the
    ``DHTNode`` instance (when provided), or onto the ``DHTManager``'s
    underlying node.

    Parameters
    ----------
    settings : GuiSettings
        The settings to apply.
    node : DHTNode, optional
        Live node — receives instance-attribute updates.
    manager : DHTManager, optional
        If provided and ``node`` is ``None``, ``manager.node`` is used.

    Notes
    -----
    Some settings are restart-required (e.g. ``bind_port``,
    ``peers_file``, uTP/QUIC packet/buffer sizes are baked into sockets
    at construction time).  These are still written into module globals
    so that the *next* node construction picks them up.
    """
    _apply_log_levels(settings)
    _apply_dht_globals(settings)
    _apply_metadata_globals(settings)
    _apply_peer_globals(settings)
    _apply_downloader_globals(settings)
    _apply_tracker_globals(settings)
    _apply_lsd_globals(settings)
    _apply_webseed_globals(settings)
    _apply_utp_globals(settings)
    _apply_quic_globals(settings)

    target_node = node
    if target_node is None and manager is not None:
        target_node = getattr(manager, "node", None)
    _apply_node_instance(settings, target_node)


__all__ = [
    "GuiSettings",
    "apply_to_runtime",
    "default_torrent_library_directory",
    "load",
    "resolved_torrent_library_directory",
    "save",
    "settings_path",
    "torrent_resume_subdirectory",
]
