"""Local DHT node lifecycle for observe mode.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

The controller does not construct a :class:`~dhtrack.dht.DHTNode` until a
caller has confirmed ``node_start``. Bootstrap routers are contacted only
when that confirmed call listed them. Tests replace the runtime factory so
the confirm path can be exercised without a socket.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from dhtrack.experimental.mcp.errors import ToolError


class NodeRuntime(Protocol):
    """What observe-mode tools need from a node. The live adapter is one implementation."""

    def start(self, *, port: int, bootstrap: list[tuple[str, int]], bind_host: str) -> dict[str, Any]:
        """Bind, and optionally bootstrap. Return a status document."""

    def stop(self) -> dict[str, Any]:
        """Release the socket. Idempotent."""

    def status(self) -> dict[str, Any]:
        """Current bind state. Must not send a query."""

    def get_peers(self, info_hash: bytes) -> list[dict[str, Any]]:
        """One iterative lookup. Each row may include ``node_id`` bytes.

        A runtime may set ``last_lookup_sent`` to False when the lookup had
        nobody to query; callers treat a missing attribute as True.
        """

    def sample_infohashes(self) -> dict[str, Any]:
        """One BEP 51 query. No follow-up loop. May include ``sent`` (default True)."""


def stopped_status() -> dict[str, Any]:
    """Status document used when nothing is bound."""
    return {
        "running": False,
        "bind_host": None,
        "port": None,
        "bootstrap": [],
        "outbound": False,
        "node_id_hex": None,
        "live": False,
    }


class LiveNodeRuntime:
    """Thin adapter over :class:`~dhtrack.dht.DHTNode`.

    ``start`` binds a UDP socket on a private loop thread. It does not call
    ``load_peers`` and does not call ``bootstrap`` unless ``bootstrap`` is
    non-empty, so a confirm with no routers does not dial the public DHT.
    """

    def __init__(self) -> None:
        self._node: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._workdir: Path | None = None
        self._bind_host: str | None = None
        self._port: int | None = None
        self._bootstrap: list[tuple[str, int]] = []
        self._outbound = False
        self.last_lookup_sent = False

    def start(self, *, port: int, bootstrap: list[tuple[str, int]], bind_host: str) -> dict[str, Any]:
        if self._node is not None:
            raise ToolError(
                "node already running",
                code="node_already_running",
                hint="Call dhtrack_node_stop before starting another one.",
            )
        from dhtrack.dht import DHTNode

        workdir = Path(tempfile.mkdtemp(prefix="dhtrack-mcp-node-"))
        self._workdir = workdir
        node = DHTNode(
            bind_addr=(bind_host, port),
            peers_file=str(workdir / "peers.dat"),
            persist_node_identity=False,
        )
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def _runner() -> None:
            asyncio.set_event_loop(loop)
            ready.set()
            loop.run_forever()

        thread = threading.Thread(target=_runner, name="dhtrack-mcp-node", daemon=True)
        thread.start()
        self._loop = loop
        self._thread = thread
        if not ready.wait(timeout=2.0):
            self._abort_thread()
            raise ToolError("node loop did not start", code="node_start_failed")
        try:
            asyncio.run_coroutine_threadsafe(node.start(), loop).result(timeout=5)
        except Exception as exc:
            self._abort_thread()
            raise ToolError(f"node failed to bind: {exc}", code="node_start_failed") from exc
        self._node = node
        self._bind_host = bind_host
        self._port = _bound_port(node, port)
        self._bootstrap = list(bootstrap)
        self._outbound = False
        status = self.status()
        if bootstrap:
            status["bootstrap_contacted"] = int(node.bootstrap(list(bootstrap)))
            self._outbound = True
            status["outbound"] = True
        return status

    def stop(self) -> dict[str, Any]:
        node = self._node
        loop = self._loop
        self._node = None
        if node is not None and loop is not None and loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(node.close_async(), loop).result(timeout=5)
            except Exception:
                pass
        self._abort_thread()
        self._bind_host = None
        self._port = None
        self._bootstrap = []
        self._outbound = False
        return stopped_status()

    def status(self) -> dict[str, Any]:
        node = self._node
        if node is None:
            return stopped_status()
        node_id = getattr(node, "node_id", None)
        return {
            "running": True,
            "bind_host": self._bind_host,
            "port": self._port,
            "bootstrap": [{"ip": ip, "port": port} for ip, port in self._bootstrap],
            "outbound": self._outbound,
            "node_id_hex": node_id.hex() if isinstance(node_id, bytes) else None,
            "live": True,
        }

    def get_peers(self, info_hash: bytes) -> list[dict[str, Any]]:
        node = self._require()
        # With an empty routing table the lookup queries nobody; say so
        # rather than report a send that never happened.
        table = getattr(node, "routing_table", None)
        if table is None:
            self.last_lookup_sent = True
        else:
            self.last_lookup_sent = any(b.nodes for rt in (table.v4, table.v6) for b in rt.buckets)
        rows: list[dict[str, Any]] = []
        for peer in node.iterative_get_peers(info_hash):
            node_id = getattr(peer, "node_id", None)
            is_seed = getattr(peer, "is_seed", None)
            rows.append(
                {
                    "ip": peer.ip,
                    "port": int(peer.port),
                    "node_id": node_id if isinstance(node_id, bytes) else None,
                    "is_seeder": is_seed if isinstance(is_seed, bool) else None,
                }
            )
        return rows

    def sample_infohashes(self) -> dict[str, Any]:
        node = self._require()
        # DHTNode.sample_infohashes returns True when a query went out, and
        # False when it was skipped (interval not elapsed, no routing node)
        # or the send failed. Samples arrive later through the response path.
        sent = node.sample_infohashes()
        return {
            "calls": 1,
            "sent": bool(sent) if isinstance(sent, bool) else True,
            "returned_infohashes": 0,
            "respects_interval": True,
            "autonomous_loop": False,
            "note": (
                "DHTNode.sample_infohashes sends at most one query; sent is False when it was skipped. "
                "The node itself skips the send when the peer's BEP 51 interval has not elapsed. "
                "Replies are not ingested here; pass captured replies to "
                "dhtrack_send_catalog_sample_round."
            ),
        }

    def _require(self) -> Any:
        if self._node is None:
            raise ToolError(
                "node is not running",
                code="node_not_running",
                hint="dhtrack_node_start(confirm=true) binds a UDP port. Omit bootstrap to avoid dialing routers.",
            )
        return self._node

    def _abort_thread(self) -> None:
        loop = self._loop
        thread = self._thread
        self._loop = None
        self._thread = None
        if loop is not None:
            try:
                if loop.is_running():
                    loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                pass
        if thread is not None:
            thread.join(timeout=2)
        if loop is not None and not loop.is_closed() and (thread is None or not thread.is_alive()):
            loop.close()
        workdir = self._workdir
        self._workdir = None
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)


def _bound_port(node: Any, requested: int) -> int:
    sock = getattr(node, "sock", None)
    if sock is None:
        return requested
    try:
        return int(sock.getsockname()[1])
    except OSError:
        return requested


class NodeController:
    """Process-wide node. The factory is replaceable so tests never bind for real."""

    def __init__(self, factory: Callable[[], NodeRuntime] | None = None) -> None:
        self._factory: Callable[[], NodeRuntime] = factory or LiveNodeRuntime
        self._runtime: NodeRuntime | None = None
        self._starting = False
        self._lock = threading.Lock()

    def set_factory(self, factory: Callable[[], NodeRuntime]) -> None:
        """Use ``factory`` the next time a confirmed start runs."""
        with self._lock:
            self._factory = factory

    def running(self) -> bool:
        with self._lock:
            return self._runtime is not None

    def status(self) -> dict[str, Any]:
        with self._lock:
            runtime = self._runtime
        if runtime is None:
            return stopped_status()
        return runtime.status()

    def start(self, *, port: int, bootstrap: list[tuple[str, int]], bind_host: str) -> dict[str, Any]:
        with self._lock:
            # _starting reserves the slot while the bind runs outside the
            # lock, so two concurrent starts cannot both bind and orphan one.
            if self._runtime is not None or self._starting:
                raise ToolError(
                    "node already running",
                    code="node_already_running",
                    hint="Call dhtrack_node_stop before starting another one.",
                )
            self._starting = True
            runtime = self._factory()
        try:
            status = runtime.start(port=port, bootstrap=bootstrap, bind_host=bind_host)
        except Exception:
            with self._lock:
                self._starting = False
            try:
                runtime.stop()
            except Exception:
                pass
            raise
        with self._lock:
            self._runtime = runtime
            self._starting = False
        return status

    def stop(self) -> dict[str, Any]:
        with self._lock:
            runtime = self._runtime
            self._runtime = None
        if runtime is None:
            return stopped_status()
        return runtime.stop()

    def get_peers(self, info_hash: bytes) -> tuple[list[dict[str, Any]], bool]:
        """Rows from one lookup, and whether it actually queried anyone."""
        runtime = self._require()
        rows = runtime.get_peers(info_hash)
        return rows, bool(getattr(runtime, "last_lookup_sent", True))

    def sample_infohashes(self) -> dict[str, Any]:
        runtime = self._require()
        return runtime.sample_infohashes()

    def reset(self) -> None:
        """Stop any node and restore the live factory. Tests call this."""
        self.stop()
        with self._lock:
            self._factory = LiveNodeRuntime

    def _require(self) -> NodeRuntime:
        with self._lock:
            runtime = self._runtime
        if runtime is None:
            raise ToolError(
                "node is not running",
                code="node_not_running",
                hint="dhtrack_node_start(confirm=true) binds a UDP port. Omit bootstrap to avoid dialing routers.",
            )
        return runtime


controller = NodeController()


def node_running() -> bool:
    """True when a confirmed start has bound a runtime that has not been stopped."""
    return controller.running()


def install_node_runtime(runtime: NodeRuntime) -> None:
    """Make the next confirmed ``node_start`` use this object. Tests and fakes only."""
    controller.set_factory(lambda: runtime)
