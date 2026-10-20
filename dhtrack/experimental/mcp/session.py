"""SQLite or in-memory session over the experimental catalog and swarm watch.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

The session stores observations. Scoring still happens in
:class:`~dhtrack.experimental.swarm_watch.SwarmWatch` and
:class:`~dhtrack.experimental.infohash_catalog.InfohashCatalog`; this module
only keeps their JSON state, the peer tables, and the alert log.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from dhtrack.experimental.infohash_catalog import CatalogState
from dhtrack.experimental.mcp.errors import ToolError
from dhtrack.experimental.mcp.gates import confine
from dhtrack.experimental.persist import expect_int, expect_number
from dhtrack.experimental.swarm_watch import Alert, SwarmWatch, WatchThresholds

SESSION_KIND = "dhtrack.experimental.mcp.session"
SESSION_VERSION = 1
MAX_STORED_PEERS = 500
MAX_STORED_ALERTS = 1000
# Each open session holds a sqlite connection (a file descriptor for a file
# session); an agent looping session_open must not exhaust them.
MAX_OPEN_SESSIONS = 32

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    info_hash_hex TEXT NOT NULL,
    observed_at REAL NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peer_table (
    info_hash_hex TEXT PRIMARY KEY,
    observed_at REAL NOT NULL,
    peer_count INTEGER NOT NULL,
    stored INTEGER NOT NULL,
    payload TEXT NOT NULL
);
"""


def _dumps(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _connect(location: str) -> sqlite3.Connection:
    # The MCP server runs tools on worker threads but serializes every call
    # (server._TOOL_LOCK), so a connection may be used from any one thread
    # at a time.
    connection = sqlite3.connect(location, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


class Session:
    """One open index. Not thread-safe; the MCP server runs one tool call at a time."""

    def __init__(
        self,
        session_id: str,
        connection: sqlite3.Connection,
        *,
        path: str | None,
        catalog: CatalogState,
        watch: SwarmWatch,
    ) -> None:
        self.id = session_id
        self.connection = connection
        self.path = path
        self.catalog = catalog
        self.watch = watch
        self.created = False
        self._closed = False

    @property
    def durable(self) -> bool:
        return self.path is not None

    def overview(self) -> dict[str, Any]:
        """Counts only. Peer ids and infohash rows stay behind the list tools."""
        infohashes = len(self.catalog.catalog)
        peers = self.connection.execute("SELECT COALESCE(SUM(peer_count), 0) AS n FROM peer_table").fetchone()
        alerts = self.connection.execute("SELECT COUNT(*) AS n FROM alert").fetchone()
        watch_state = self.watch.to_dict()
        latest = watch_state.get("latest", {})
        last_observe = None
        if isinstance(latest, dict) and latest:
            last_observe = max(float(row["observed_at"]) for row in latest.values())
        active = watch_state.get("active_alerts", {})
        return {
            "session_id": self.id,
            "path": self.path,
            "durable": self.durable,
            "infohashes": infohashes,
            "peers": int(peers["n"]) if peers is not None else 0,
            "alerts": int(alerts["n"]) if alerts is not None else 0,
            "last_sample_at": _optional_meta_float(self._meta_get("last_sample_at")),
            "last_observe_at": (
                last_observe if last_observe is not None else _optional_meta_float(self._meta_get("last_observe_at"))
            ),
            "active_alert_kinds": len(active) if isinstance(active, dict) else 0,
        }

    def add_alerts(self, alerts: list[Alert]) -> None:
        """Append alerts emitted by :meth:`SwarmWatch.observe` and cap the log."""
        for alert in alerts:
            self.connection.execute(
                "INSERT INTO alert (info_hash_hex, observed_at, severity, kind, payload) VALUES (?, ?, ?, ?, ?)",
                (alert.info_hash_hex, alert.observed_at, alert.severity, alert.kind, _dumps(alert.to_dict())),
            )
        self.connection.execute(
            """
            DELETE FROM alert
            WHERE id NOT IN (SELECT id FROM alert ORDER BY id DESC LIMIT ?)
            """,
            (MAX_STORED_ALERTS,),
        )

    def alert_rows(self) -> list[dict[str, Any]]:
        """Stored alerts, newest first."""
        rows = self.connection.execute("SELECT payload FROM alert ORDER BY id DESC").fetchall()
        return [_load_object(row["payload"]) for row in rows]

    def alert_severity_counts(self) -> dict[str, int]:
        rows = self.connection.execute(
            "SELECT severity, COUNT(*) AS n FROM alert GROUP BY severity ORDER BY severity"
        ).fetchall()
        return {str(row["severity"]): int(row["n"]) for row in rows}

    def put_peers(self, info_hash_hex: str, peers: list[dict[str, Any]], *, observed_at: float) -> dict[str, Any]:
        """Replace the stored peer table. Only the first 500 rows are kept."""
        total = len(peers)
        stored = peers[:MAX_STORED_PEERS]
        self.connection.execute(
            """
            INSERT INTO peer_table (info_hash_hex, observed_at, peer_count, stored, payload)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(info_hash_hex) DO UPDATE SET
                observed_at = excluded.observed_at,
                peer_count = excluded.peer_count,
                stored = excluded.stored,
                payload = excluded.payload
            """,
            (info_hash_hex, observed_at, total, len(stored), _dumps(stored)),
        )
        return {"peer_count": total, "stored": len(stored), "truncated": len(stored) < total}

    def get_peers(self, info_hash_hex: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT observed_at, peer_count, stored, payload FROM peer_table WHERE info_hash_hex = ?",
            (info_hash_hex,),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload"])
        if not isinstance(payload, list):
            raise ToolError("stored peer table is corrupt", code="invalid_session_file")
        return {
            "observed_at": float(row["observed_at"]),
            "peer_count": int(row["peer_count"]),
            "stored": int(row["stored"]),
            "truncated": int(row["stored"]) < int(row["peer_count"]),
            "peers": payload,
        }

    def mark_sample(self, when: float) -> None:
        self._meta_set("last_sample_at", str(when))

    def mark_observe(self, when: float) -> None:
        self._meta_set("last_observe_at", str(when))

    def flush(self) -> None:
        """Write catalog, watch, and threshold documents into the sqlite meta table."""
        if self._closed:
            return
        self._meta_set("catalog", _dumps(self.catalog.to_dict()))
        self._meta_set("watch", _dumps(self.watch.to_dict()))
        self._meta_set("thresholds", _dumps(_thresholds_dict(self.watch.thresholds)))
        self.connection.commit()

    def close(self) -> None:
        """Flush and close the sqlite connection."""
        if self._closed:
            return
        try:
            self.flush()
        finally:
            self._closed = True
            self.connection.close()

    def _meta_get(self, key: str) -> str | None:
        row = self.connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return str(row["value"])

    def _meta_set(self, key: str, value: str) -> None:
        self.connection.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


class Registry:
    """Sessions open in this process. Ids are ``s1``, ``s2``, ... and restart with :meth:`reset`."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._next = 1

    def new_id(self) -> str:
        session_id = f"s{self._next}"
        self._next += 1
        return session_id

    def add(self, session: Session) -> None:
        self._sessions[session.id] = session

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def find_path(self, path: str) -> Session | None:
        """The open session backed by ``path``, if any."""
        for session in self._sessions.values():
            if session.path == path:
                return session
        return None

    def pop(self, session_id: str) -> Session | None:
        return self._sessions.pop(session_id, None)

    def values(self) -> list[Session]:
        return list(self._sessions.values())

    def reset(self) -> None:
        for session in list(self._sessions.values()):
            try:
                session.close()
            except sqlite3.Error:
                pass
        self._sessions.clear()
        self._next = 1


registry = Registry()


def open_session(*, path: str | None = None, output_path: str | None = None) -> Session:
    """Open or create a session.

    ``path`` and ``output_path`` are sqlite files. Omit both for an in-memory
    session. When only ``output_path`` is set, it is the durable file (created
    or resumed). When both are set and ``output_path`` already exists as a
    different file, the call refuses rather than clobbering it.
    """
    source = _resolve_optional(path, "path")
    sink = _resolve_optional(output_path, "output_path")
    if len(registry.values()) >= MAX_OPEN_SESSIONS:
        raise ToolError(
            f"too many open sessions (limit {MAX_OPEN_SESSIONS})",
            code="too_many_sessions",
            hint="Close one with dhtrack_session_close, or reuse an open session_id.",
        )
    # Two Session objects on one file would each flush their own in-memory
    # catalog and watch state over the other's.
    for candidate in (source, sink):
        if candidate is not None:
            already = registry.find_path(str(candidate))
            if already is not None:
                raise ToolError(
                    f"session file is already open as {already.id}: {candidate}",
                    code="session_already_open",
                    hint=f"Pass session_id={already.id!r}, or close it first.",
                )
    created = False
    if source is None and sink is None:
        connection = _connect(":memory:")
        _initialize(connection, created=True)
        location = None
        created = True
    elif source is not None and sink is not None and source != sink:
        if not source.exists():
            raise ToolError(
                f"path does not exist: {source}",
                code="invalid_session_file",
                hint="path= copies an existing session into output_path. Omit path to start a new one there.",
            )
        if sink.exists():
            raise ToolError(
                f"output_path already exists: {sink}",
                code="output_exists",
                hint="Resume with path= that file, or choose another output_path.",
            )
        connection, created = _open_file(source)
        connection.close()
        _copy_sqlite(source, sink)
        connection = _connect(str(sink))
        location = str(sink)
    else:
        location_path = source if source is not None else sink
        assert location_path is not None
        connection, created = _open_file(location_path)
        location = str(location_path)

    catalog, watch = _load_models(connection)
    session = Session(registry.new_id(), connection, path=location, catalog=catalog, watch=watch)
    session.created = created
    session.flush()
    registry.add(session)
    return session


def _resolve_optional(value: str | None, label: str) -> Path | None:
    if value is None or not str(value).strip():
        return None
    path = confine(Path(value).expanduser(), label).resolve()
    if path.exists() and path.is_dir():
        raise ToolError(f"{label} is a directory: {path}", code="invalid_session_file", hint="Pass a sqlite file path.")
    return path


def _open_file(path: Path) -> tuple[sqlite3.Connection, bool]:
    if path.exists() and path.stat().st_size == 0:
        # Not something this server wrote: refuse rather than turn an
        # unrelated empty file (a lock file, a placeholder) into a database.
        raise ToolError(
            f"session file exists but is empty: {path}",
            code="invalid_session_file",
            hint="Pass a new path, or a session previously written by dhtrack_session_open.",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    try:
        connection = _connect(str(path))
        _initialize(connection, created=created or not _has_tables(connection))
    except sqlite3.DatabaseError as exc:
        raise ToolError(
            f"session file is not a dhtrack sqlite database: {path}",
            code="invalid_session_file",
            hint="Pass a new path, or a session previously written by dhtrack_session_open.",
        ) from exc
    return connection, created


def _has_tables(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name != 'sqlite_sequence'"
    ).fetchone()
    return row is not None and int(row["n"]) > 0


def _initialize(connection: sqlite3.Connection, *, created: bool) -> None:
    if not _has_tables(connection):
        connection.executescript(_SCHEMA)
        connection.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("kind", SESSION_KIND))
        connection.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("version", str(SESSION_VERSION)))
        connection.commit()
        return
    row = connection.execute("SELECT value FROM meta WHERE key = 'kind'").fetchone()
    if row is None or row["value"] != SESSION_KIND:
        raise ToolError(
            "session file kind mismatch",
            code="invalid_session_file",
            hint="This sqlite file was not written by the experimental MCP session.",
        )
    version = connection.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
    if version is None or version["value"] != str(SESSION_VERSION):
        raise ToolError(
            f"unsupported session version: {None if version is None else version['value']!r}",
            code="invalid_session_file",
        )


def _copy_sqlite(source: Path, sink: Path) -> None:
    sink.parent.mkdir(parents=True, exist_ok=True)
    src = _connect(str(source))
    try:
        dest = _connect(str(sink))
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()


def _load_models(connection: sqlite3.Connection) -> tuple[CatalogState, SwarmWatch]:
    catalog_raw = _meta(connection, "catalog")
    catalog = CatalogState() if catalog_raw is None else CatalogState.from_dict(json.loads(catalog_raw))
    watch = SwarmWatch()
    watch_raw = _meta(connection, "watch")
    if watch_raw is not None:
        _load_watch(watch, json.loads(watch_raw))
    thresholds_raw = _meta(connection, "thresholds")
    if thresholds_raw is not None:
        watch.thresholds = _thresholds_from_dict(json.loads(thresholds_raw))
    return catalog, watch


def _load_watch(watch: SwarmWatch, payload: object) -> None:
    """Restore spike baselines and firing alerts from a stored watch state."""
    watch.load_state(payload)


def _meta(connection: sqlite3.Connection, key: str) -> str | None:
    row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    return str(row["value"])


def _thresholds_dict(thresholds: WatchThresholds) -> dict[str, object]:
    return {
        "min_peers": thresholds.min_peers,
        "min_diversity": thresholds.min_diversity,
        "min_peers_for_diversity": thresholds.min_peers_for_diversity,
        "max_prefix_share": thresholds.max_prefix_share,
        "min_seeders": thresholds.min_seeders,
        "spike_ratio": thresholds.spike_ratio,
        "spike_min_previous": thresholds.spike_min_previous,
    }


def _thresholds_from_dict(raw: object) -> WatchThresholds:
    if not isinstance(raw, dict):
        raise ToolError("stored thresholds are corrupt", code="invalid_session_file")
    min_seeders = raw.get("min_seeders")
    return WatchThresholds(
        min_peers=expect_int(raw.get("min_peers", 1), "min_peers"),
        min_diversity=expect_number(raw.get("min_diversity", 0.25), "min_diversity"),
        min_peers_for_diversity=expect_int(raw.get("min_peers_for_diversity", 8), "min_peers_for_diversity"),
        max_prefix_share=expect_number(raw.get("max_prefix_share", 0.8), "max_prefix_share"),
        min_seeders=None if min_seeders is None else expect_int(min_seeders, "min_seeders"),
        spike_ratio=expect_number(raw.get("spike_ratio", 5.0), "spike_ratio"),
        spike_min_previous=expect_int(raw.get("spike_min_previous", 4), "spike_min_previous"),
    )


def _optional_meta_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    return float(value)


def _load_object(payload: str) -> dict[str, Any]:
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ToolError("stored alert is corrupt", code="invalid_session_file")
    return parsed
