"""
DHT Manager - Unified high-level interface for DHT operations.

Provides peer discovery and metadata retrieval driven by the DHTNode's
iterative query mechanism. All heavy lifting (iterative peer discovery,
TCP metadata exchange) is handled through this manager so that both
the GUI and CLI share the same code path.

Examples
--------
>>> from dhtrack.dht_manager import DHTManager
>>> manager = DHTManager()
>>> manager.start()
>>> manager.bootstrap()
>>> peers = manager.find_peers(info_hash, timeout=30.0)
>>> for peer in peers:
...     print(f"{peer.ip}:{peer.port}")
>>> manager.stop()
"""

from __future__ import annotations

import asyncio
import binascii
import ipaddress
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dhtrack.dht import (
    OBSERVED_IP_MIN_DISTINCT_RESPONDERS_DEFAULT,
    DHTNode,
)
from dhtrack.dht import StoredPeer as _StoredPeer

if TYPE_CHECKING:
    from dhtrack.torrent import Torrent

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryProgress:
    """Tracks progress of a peer discovery operation."""

    info_hash: bytes
    round_num: int = 0
    nodes_queried: int = 0
    nodes_discovered: int = 0
    peers_found: int = 0
    elapsed: float = 0.0
    status: str = "starting"
    ipv4_nodes: int = 0
    ipv6_nodes: int = 0
    ipv4_queried: int = 0
    ipv6_queried: int = 0


class DHTManager:
    """High-level DHT manager for peer discovery and metadata retrieval.

    Wraps a :class:`DHTNode` and provides blocking and async APIs for
    iterative peer discovery and torrent metadata retrieval.

    Parameters
    ----------
    node : DHTNode, optional
        A pre-configured DHTNode. A new node is created if not provided.
    peers_file : str, optional
        Path to persist known peers.
    state_file : str | None, optional
        Path to persist this node's stable ``node_id`` (default sibling of ``peers_file``).
    persist_node_identity : bool, optional
        When True (default), reload the same ``node_id`` across restarts.
    auto_align_bep42_node_id : bool, optional
        When True, rotate ``node_id`` to satisfy BEP 42 once quorum agrees on your public IP.
    observed_ip_min_distinct_responders : int, optional
        Distinct responders required before treating BEP 42 ``ip`` as quorum.
    """

    def __init__(
        self,
        node: DHTNode | None = None,
        peers_file: str = "peers.dat",
        state_file: str | None = None,
        persist_node_identity: bool = True,
        auto_align_bep42_node_id: bool = True,
        observed_ip_min_distinct_responders: int = OBSERVED_IP_MIN_DISTINCT_RESPONDERS_DEFAULT,
        peerstore_max_peers_per_infohash: int = 2500,
    ) -> None:
        self._node = node or DHTNode(
            peers_file=peers_file,
            state_file=state_file,
            persist_node_identity=persist_node_identity,
            auto_align_bep42_node_id=auto_align_bep42_node_id,
            observed_ip_min_distinct_responders=observed_ip_min_distinct_responders,
            peerstore_max_peers_per_infohash=int(peerstore_max_peers_per_infohash),
        )
        self.peers_file: str = peers_file

        # Own an explicit asyncio loop thread for the node (Phase 2)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None

        # Progress tracking
        self._active_operations: dict[str, DiscoveryProgress] = {}
        self._operation_id = 0

        # Callback lock (callbacks may be called from the DHT read thread)
        self._callback_lock = threading.Lock()

    @property
    def node(self) -> DHTNode:
        """The underlying DHTNode."""
        return self._node

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    def get_observed_external_endpoints(self):
        """Return ``(observed_ipv4, observed_ipv6)`` from BEP 42 ``ip`` quorum (see :class:`DHTNode`)."""
        return self._node.get_observed_external_endpoints()

    def run_coroutine(self, coro: Any):
        """Schedule a coroutine onto the manager-owned loop thread.

        Returns the Future from asyncio.run_coroutine_threadsafe so callers
        (e.g. the GUI) can attach done callbacks.
        """
        if self._loop is None:
            raise RuntimeError("DHTManager loop not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def start(self) -> None:
        """Start the DHT node (bootstrap + load peers)."""
        logger.info("Starting DHTManager...")
        if self._loop_thread is None:
            self._start_loop_thread()
            assert self._loop is not None
            asyncio.run_coroutine_threadsafe(self._node.start(), self._loop).result(timeout=5)
        self._node.load_peers()
        self.bootstrap()

    def stop(self) -> None:
        """Stop the DHT node and save peers."""
        logger.info("Stopping DHTManager...")
        self._node.save_node_state()
        self._node.save_peers()
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._node.close_async(), self._loop).result(timeout=5)
            self._stop_loop_thread()
        else:
            self._node.close()

    def _start_loop_thread(self) -> None:
        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            loop.run_forever()
            loop.close()

        self._loop_thread = threading.Thread(target=_runner, daemon=True)
        self._loop_thread.start()

        # Spin until loop is ready
        t0 = time.time()
        while self._loop is None and time.time() - t0 < 2.0:
            time.sleep(0.01)

    def _stop_loop_thread(self) -> None:
        if self._loop is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._loop.stop)
        except RuntimeError:
            pass
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=2)
        self._loop_thread = None
        self._loop = None

    def bootstrap(
        self,
        nodes: list[tuple[str, int]] | None = None,
    ) -> int:
        """Bootstrap the DHT node with known router nodes.

        Parameters
        ----------
        nodes : list of tuple, optional
            Custom bootstrap nodes. Uses defaults if not provided.

        Returns
        -------
        int
            Number of bootstrap nodes successfully contacted.
        """
        return self._node.bootstrap(nodes)

    # -----------------------------------------------------------------------
    # Peer discovery (blocking)
    # -----------------------------------------------------------------------

    def find_peers(
        self,
        info_hash: bytes,
        timeout: float = 30.0,
        query_interval: float = 3.0,
        max_nodes: int = 8,
        on_progress: Callable[[DiscoveryProgress], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> list[_StoredPeer]:
        """Find peers for an infohash using iterative deepening.

        This is a blocking call. It runs the async iterative get_peers
        search in a background thread and waits for completion.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        timeout : float
            How long to search for peers (seconds).
        query_interval : float
            Seconds between query rounds.
        max_nodes : int
            Maximum nodes to query per round.
        on_progress : callable, optional
            Called with DiscoveryProgress on each round.

        Returns
        -------
        list[StoredPeer]
            Discovered peers.
        """
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")

        return asyncio.run(
            self.async_find_peers(
                info_hash,
                timeout=timeout,
                query_interval=query_interval,
                max_nodes=max_nodes,
                on_progress=on_progress,
                cancel_requested=cancel_requested,
            )
        )

    async def async_find_peers(
        self,
        info_hash: bytes,
        timeout: float = 30.0,
        query_interval: float = 3.0,
        max_nodes: int = 8,
        on_progress: Callable[[DiscoveryProgress], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> list[_StoredPeer]:
        """Async iterative peer discovery.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        timeout : float
            Search timeout (seconds).
        query_interval : float
            Seconds between query rounds.
        max_nodes : int
            Max nodes per round.
        on_progress : callable, optional
            Progress callback.

        Returns
        -------
        list[StoredPeer]
            Discovered peers.
        """
        self._operation_id += 1
        op_id = f"find_peers_{self._operation_id}"

        progress = DiscoveryProgress(
            info_hash=info_hash,
            status="starting",
        )
        self._active_operations[op_id] = progress

        t_start = time.time()
        v4_cum = 0
        v6_cum = 0

        try:

            def _on_round_cb(rn: int, s4: int, s6: int, pfound: int) -> None:
                nonlocal v4_cum, v6_cum
                v4_cum += s4
                v6_cum += s6
                progress.round_num = rn
                progress.peers_found = pfound
                progress.status = "searching"
                progress.elapsed = time.time() - t_start
                progress.nodes_queried = v4_cum + v6_cum
                progress.ipv4_queried = v4_cum
                progress.ipv6_queried = v6_cum
                # The DHT receive thread can mutate routing tables concurrently.
                # Take best-effort snapshots to avoid "dictionary changed size during iteration".
                try:
                    b4 = list(self._node.routing_table_v4.buckets)
                    progress.ipv4_nodes = sum(len(getattr(b, "nodes", []) or []) for b in b4)
                except RuntimeError:
                    # Keep previous value
                    pass
                try:
                    b6 = list(self._node.routing_table_v6.buckets)
                    progress.ipv6_nodes = sum(len(getattr(b, "nodes", []) or []) for b in b6)
                except RuntimeError:
                    pass
                if on_progress is not None:
                    try:
                        on_progress(progress)
                    except Exception:
                        logger.debug("on_progress callback failed", exc_info=True)

            peers = await self._node.async_get_peers(
                info_hash,
                search_timeout=timeout,
                max_nodes=max_nodes,
                query_interval=query_interval,
                on_round=_on_round_cb,
                cancel_requested=cancel_requested,
            )

            progress.status = "complete"
            progress.peers_found = len(peers)
            progress.elapsed = time.time() - t_start

            if on_progress is not None:
                try:
                    on_progress(progress)
                except Exception:
                    pass

            logger.info(
                "find_peers %s: %d peers found in %.1fs (%d rounds)",
                binascii.b2a_hex(info_hash).decode("ascii"),
                len(peers),
                progress.elapsed,
                progress.round_num,
            )
            return peers

        except Exception as exc:
            progress.status = f"error: {exc}"
            logger.error("find_peers %s failed: %s", binascii.b2a_hex(info_hash).decode("ascii"), exc)
            raise

        finally:
            self._active_operations.pop(op_id, None)

    # -----------------------------------------------------------------------
    # Metadata retrieval pipeline
    # -----------------------------------------------------------------------

    def retrieve_metadata(
        self,
        info_hash: bytes,
        timeout: float = 120.0,
        max_peers: int = 10,
        on_progress: Callable[[str], None] | None = None,
        initial_peers: list[tuple[str, int]] | None = None,
        peer_status_observer: Callable[[str, int, str, str | None], None] | None = None,
        peer_detail_observer: Callable[[str, int, dict], None] | None = None,
    ) -> bytes | None:
        """Retrieve torrent metadata for an infohash.

        Pipeline:
        1. Iteratively discover peers via DHT
        2. Connect to discovered peers via TCP
        3. Exchange ut_metadata to retrieve .torrent data

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        timeout : float
            Total timeout (seconds).
        max_peers : int
            Max distinct peers queued for metadata tries. Values ``<= 0`` use an internal cap
            (currently 2048) so feeders never grow without bound.
        on_progress : callable, optional
            Progress message callback (str).

        Returns
        -------
        bytes or None
            Bencoded .torrent metadata, or None on failure.
        """
        from dhtrack.metadata_retriever import download_torrent_metadata_dynamic

        if on_progress is not None:
            on_progress("Discovering peers via DHT (in parallel with metadata retrieval)...")

        peer_q: queue.Queue[tuple[str, int]] = queue.Queue()
        stop_flag = threading.Event()
        seen: set[tuple[str, int]] = set()
        max_peer_cap = max_peers if max_peers > 0 else 2048

        # Seed with any peers the caller already knows about (e.g. GUI-discovered swarm peers).
        if initial_peers:
            for ip, port in list(initial_peers):
                key = (str(ip), int(port))
                if key in seen:
                    continue
                if len(seen) >= max_peer_cap:
                    break
                seen.add(key)
                try:
                    peer_q.put_nowait(key)
                except Exception:
                    pass

        def observe_dht_port(ip: str, _tcp_port: int, dht_port: int) -> None:
            try:
                is_v6 = ipaddress.ip_address(ip).version == 6
            except ValueError:
                return
            try:
                peer = self._node.add_peer(None, ip, int(dht_port), is_ipv6=is_v6)
                if peer is not None:
                    peer.ping()
            except Exception:
                pass

        def feeder_loop() -> None:
            # Poll peer_store and enqueue newly found swarm peers.
            while not stop_flag.is_set():
                try:
                    for p in self._node.peer_store.get_peers(info_hash):
                        key = (p.ip, int(p.port))
                        if key in seen:
                            continue
                        if len(seen) >= max_peer_cap:
                            stop_flag.set()
                            break
                        seen.add(key)
                        try:
                            peer_q.put_nowait(key)
                        except Exception:
                            pass
                except Exception:
                    pass
                time.sleep(0.25)

        def discover_loop() -> None:
            try:
                # This fills peer_store asynchronously as responses arrive.
                self.find_peers(info_hash, timeout=min(timeout * 0.6, 72.0))
            except Exception as exc:
                try:
                    if on_progress is not None:
                        on_progress(f"DHT discovery thread failed: {exc}")
                except Exception:
                    pass
                logger.debug("discover_loop failed", exc_info=True)

        feeder_t = threading.Thread(target=feeder_loop, name="dhtrack-metadata-feeder", daemon=True)
        discover_t = threading.Thread(target=discover_loop, name="dhtrack-metadata-discovery", daemon=True)
        feeder_t.start()
        discover_t.start()

        try:
            return download_torrent_metadata_dynamic(
                peer_queue=peer_q,
                info_hash=info_hash,
                timeout=timeout,
                progress_callback=on_progress,
                initial_peers=list(seen),
                dht_port_observer=observe_dht_port,
                peer_status_observer=peer_status_observer,
                peer_detail_observer=peer_detail_observer,
            )
        finally:
            stop_flag.set()
            try:
                feeder_t.join(timeout=1.0)
            except Exception:
                pass
            try:
                discover_t.join(timeout=1.0)
            except Exception:
                pass

    async def async_retrieve_metadata(
        self,
        info_hash: bytes,
        timeout: float = 120.0,
        max_peers: int = 10,
        on_progress: Callable[[str], None] | None = None,
    ) -> bytes | None:
        """Async metadata retrieval.

        Parameters
        ----------
        info_hash : bytes
            20-byte infohash.
        timeout : float
            Total timeout (seconds).
        max_peers : int
            Max peers to try.
        on_progress : callable, optional
            Progress callback.

        Returns
        -------
        bytes or None
            Bencoded .torrent metadata.
        """
        from dhtrack.metadata_retriever import download_torrent_metadata_dynamic

        if on_progress is not None:
            on_progress("Discovering peers via DHT (in parallel with metadata retrieval)...")

        peer_q: queue.Queue[tuple[str, int]] = queue.Queue()
        seen: set[tuple[str, int]] = set()
        stop_event = asyncio.Event()
        max_peer_cap = max_peers if max_peers > 0 else 2048

        def observe_dht_port(ip: str, _tcp_port: int, dht_port: int) -> None:
            try:
                is_v6 = ipaddress.ip_address(ip).version == 6
            except ValueError:
                return
            try:
                peer = self._node.add_peer(None, ip, int(dht_port), is_ipv6=is_v6)
                if peer is not None:
                    peer.ping()
            except Exception:
                pass

        async def feeder_loop() -> None:
            while not stop_event.is_set():
                try:
                    for p in self._node.peer_store.get_peers(info_hash):
                        key = (p.ip, int(p.port))
                        if key in seen:
                            continue
                        if len(seen) >= max_peer_cap:
                            stop_event.set()
                            break
                        seen.add(key)
                        try:
                            peer_q.put_nowait(key)
                        except Exception:
                            pass
                except Exception:
                    pass
                await asyncio.sleep(0.25)

        def cancel_cb():
            return stop_event.is_set()

        discover_task = asyncio.create_task(
            self.async_find_peers(info_hash, timeout=min(timeout * 0.6, 72.0), cancel_requested=cancel_cb)
        )
        feeder_task = asyncio.create_task(feeder_loop())

        loop = asyncio.get_running_loop()
        try:
            # Run the blocking metadata resolver in a thread so DHT discovery can continue.
            meta = await loop.run_in_executor(
                None,
                lambda: download_torrent_metadata_dynamic(
                    peer_queue=peer_q,
                    info_hash=info_hash,
                    timeout=timeout,
                    progress_callback=on_progress,
                    initial_peers=list(seen),
                    dht_port_observer=observe_dht_port,
                ),
            )
            return meta
        finally:
            stop_event.set()
            try:
                discover_task.cancel()
            except Exception:
                pass
            try:
                feeder_task.cancel()
            except Exception:
                pass
            try:
                await asyncio.gather(discover_task, feeder_task, return_exceptions=True)
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Torrent creation
    # -----------------------------------------------------------------------

    def create_torrent(self, metadata: bytes) -> Torrent | None:
        """Create a Torrent object from bencoded metadata.

        Parameters
        ----------
        metadata : bytes
            Bencoded .torrent data.

        Returns
        -------
        Torrent or None
            The parsed Torrent, or None on failure.
        """
        from dhtrack import bencode as bencode_module
        from dhtrack.torrent import Torrent

        try:
            decoded = bencode_module.decode(metadata)
            if not isinstance(decoded, dict):
                return None
            # ut_metadata returns the raw bencoded *info* dict; wrap if needed.
            if b"info" in decoded or "info" in decoded:
                torrent = Torrent(decoded)
            else:
                torrent = Torrent({b"info": decoded})
            logger.info(
                "Created torrent: name=%s, infohash=%s",
                torrent.name,
                torrent.infohash.hex(),
            )
            return torrent
        except Exception as exc:
            logger.error("Failed to create torrent from metadata: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Full download entrypoints (BEP 3 payload)
    # -----------------------------------------------------------------------

    def download_from_infohash(
        self,
        info_hash: bytes,
        *,
        download_dir: str,
        resume_dir: str = ".dhtrack-resume",
        timeout: float = 120.0,
        use_utp: bool = False,
        on_progress: Callable[[str], None] | None = None,
        on_download_progress: Callable[[Any], None] | None = None,
        on_peer_snapshot: Callable[[str, int, dict], None] | None = None,
        max_peers_for_metadata: int = 25,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> None:
        """Magnet-start download: metadata via DHT + full payload via BEP 3."""
        from dhtrack.downloader import DownloadCoordinator

        if on_progress is not None:
            on_progress("Retrieving torrent metadata (ut_metadata)…")
        meta = self.retrieve_metadata(
            info_hash,
            timeout=timeout,
            max_peers=max_peers_for_metadata,
            on_progress=on_progress,
        )
        if meta is None:
            raise RuntimeError("failed to retrieve metadata")

        torrent = self.create_torrent(meta)
        if torrent is None:
            raise RuntimeError("failed to parse torrent metadata")

        if torrent.infohash != info_hash:
            raise RuntimeError("download metadata infohash mismatch")

        peers = [(p.ip, int(p.port)) for p in self._node.peer_store.get_peers(info_hash)]
        if on_progress is not None:
            on_progress(f"Starting BEP 3 download from {len(peers)} peer(s)…")

        coord = DownloadCoordinator(
            torrent=torrent,
            download_dir=Path(download_dir),
            resume_dir=Path(resume_dir),
            use_utp=bool(use_utp),
            on_progress=on_download_progress,
            on_peer_snapshot=on_peer_snapshot,
        )
        coord.download_from_peers(peers, cancel_requested=cancel_requested)

    def download_payload_with_known_metainfo(
        self,
        info_hash: bytes,
        metainfo: bytes | Torrent,
        *,
        download_dir: str,
        resume_dir: str = ".dhtrack-resume",
        use_utp: bool = False,
        on_progress: Callable[[str], None] | None = None,
        on_download_progress: Callable[[Any], None] | None = None,
        on_peer_snapshot: Callable[[str, int, dict], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> None:
        """BEP 3 payload download using an already-known ``.torrent`` / ``info`` metainfo."""
        from dhtrack.downloader import DownloadCoordinator
        from dhtrack.torrent import Torrent

        ih = bytes(info_hash)
        if isinstance(metainfo, Torrent):
            torrent = metainfo
        else:
            torrent = self.create_torrent(metainfo)
            if torrent is None:
                raise RuntimeError("failed to parse torrent metadata")
        if torrent.infohash != ih:
            raise RuntimeError("download metadata infohash mismatch")

        peers = [(p.ip, int(p.port)) for p in self._node.peer_store.get_peers(ih)]
        if on_progress is not None:
            on_progress(f"Starting BEP 3 download from {len(peers)} peer(s)…")

        coord = DownloadCoordinator(
            torrent=torrent,
            download_dir=Path(download_dir),
            resume_dir=Path(resume_dir),
            use_utp=bool(use_utp),
            on_progress=on_download_progress,
            on_peer_snapshot=on_peer_snapshot,
        )
        coord.download_from_peers(peers, cancel_requested=cancel_requested)

    def download_from_magnet(
        self,
        magnet_uri: str,
        *,
        download_dir: str,
        resume_dir: str = ".dhtrack-resume",
        timeout: float = 120.0,
        use_utp: bool = False,
        on_progress: Callable[[str], None] | None = None,
        on_download_progress: Callable[[Any], None] | None = None,
        max_peers_for_metadata: int = 25,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> bytes:
        """Download from a magnet URI. Returns the binary infohash."""
        from dhtrack.bep53 import parse_magnet_uri

        mi = parse_magnet_uri(magnet_uri)
        if mi.info_hash is None:
            raise ValueError("magnet missing btih")
        self.download_from_infohash(
            mi.info_hash,
            download_dir=download_dir,
            resume_dir=resume_dir,
            timeout=timeout,
            use_utp=use_utp,
            on_progress=on_progress,
            on_download_progress=on_download_progress,
            max_peers_for_metadata=max_peers_for_metadata,
            cancel_requested=cancel_requested,
        )
        return mi.info_hash

    # -----------------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------------

    def get_peer_count(self) -> int:
        """Get the number of known DHT peers."""
        return len(self._node.peers)

    def get_peer_store_count(self, info_hash: bytes | None = None) -> int:
        """Get the number of stored peers (under infohashes).

        Parameters
        ----------
        info_hash : bytes, optional
            If provided, count peers for this infohash only.
        """
        if info_hash:
            return len(self._node.peer_store.get_peers(info_hash))
        return sum(len(peers) for peers in self._node.peer_store._store.values())


def _retrieve_metadata_from_peers(
    peers: list[tuple[str, int, bool]],
    info_hash: bytes,
    timeout: float = 90.0,
    on_progress: Callable[[str], None] | None = None,
) -> bytes | None:
    """Try to retrieve metadata from a list of peers.

    Uses an iterative resolver: maintains up to N concurrent outbound ut_metadata
    sessions (see ``download_torrent_metadata``). As failures complete, queued peers
    are tried until metadata is fetched or the overall timeout elapses.

    Parameters
    ----------
    peers : list of (ip, port, is_ipv6)
        Peer addresses to try.
    info_hash : bytes
        20-byte infohash.
    timeout : float
        Total timeout (seconds).
    on_progress : callable, optional
        Progress callback.

    Returns
    -------
    bytes or None
        Bencoded .torrent metadata.
    """
    from dhtrack.metadata_retriever import download_torrent_metadata

    if not peers:
        if on_progress is not None:
            on_progress("No peers supplied for metadata retrieval")
        return None

    logger.info(
        "Retrieving metadata for %s from %d peer(s)",
        binascii.b2a_hex(info_hash).decode("ascii"),
        len(peers),
    )

    result = download_torrent_metadata(
        peers=peers,
        info_hash=info_hash,
        timeout=timeout,
        progress_callback=on_progress,
    )
    if result is None:
        logger.warning("Failed to retrieve metadata from %d peers (within timeout)", len(peers))
    return result
