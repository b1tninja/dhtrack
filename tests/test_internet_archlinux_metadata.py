from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections.abc import Callable
from typing import TypeVar

import pytest

from dhtrack.bep53 import parse_magnet_uri
from dhtrack.dht_manager import DHTManager

ARCH_MAGNET = "magnet:?xt=urn:btih:e337a880c4d0f552bab5b437fe1208d26130ccc5&dn=archlinux-2026.05.01-x86_64.iso"
ARCH_INFOHASH_HEX = "e337a880c4d0f552bab5b437fe1208d26130ccc5"

T = TypeVar("T")


def _run_with_timeout(
    fn: Callable[[], T],
    *,
    timeout_s: float,
    label: str,
) -> T:
    """Run a blocking callable in a thread with a hard timeout."""
    out: dict[str, object] = {}

    def _target() -> None:
        try:
            out["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - we want to propagate any failure
            out["exc"] = exc

    t = threading.Thread(target=_target, name=f"test-timeout-{label}", daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if t.is_alive():
        raise TimeoutError(f"timeout while {label} after {timeout_s:.1f}s")
    if "exc" in out:
        raise out["exc"]  # type: ignore[misc]
    return out["value"]  # type: ignore[misc]


def test_parse_archlinux_magnet_to_expected_infohash() -> None:
    info = parse_magnet_uri(ARCH_MAGNET)
    assert info.info_hash is not None
    assert info.info_hash.hex() == ARCH_INFOHASH_HEX


@pytest.mark.slow
def test_internet_retrieve_archlinux_metadata_via_dht() -> None:
    """Live internet integration test: DHT peer discovery + ut_metadata.

    This test is skipped by default. Enable with:
      - DHTRACK_RUN_INTERNET_TESTS=1  (preferred, consistent with conftest)
        OR
      - DHT_TEST_LIVE=1              (legacy tests use this)
    """
    live = os.environ.get("DHTRACK_RUN_INTERNET_TESTS") in ("1", "true", "TRUE", "yes", "YES")
    live = live or os.environ.get("DHT_TEST_LIVE", "0") == "1"
    if not live:
        pytest.skip("internet DHT test disabled (set DHTRACK_RUN_INTERNET_TESTS=1)")

    info_hash = bytes.fromhex(ARCH_INFOHASH_HEX)

    # Make sure we see detailed peer-wire progress in test output.
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("dhtrack.metadata_retriever").setLevel(logging.DEBUG)

    mgr = DHTManager()
    try:
        t0 = time.time()
        hard_deadline_s = float(os.environ.get("DHTRACK_TEST_DEADLINE_S", "300"))

        progress_lines: list[str] = []

        def prog(msg: str) -> None:
            dt = time.time() - t0
            line = f"[{dt:7.1f}s] {msg}"
            progress_lines.append(line)
            print(line, flush=True)

        # Hard timeout for startup/bootstrapping so we don't hang forever.
        _run_with_timeout(mgr.start, timeout_s=min(30.0, hard_deadline_s), label="starting DHTManager")

        try:
            n = mgr.node
            sock4 = getattr(n, "sock", None)
            sock6 = getattr(n, "sock6", None)
            prog(f"dht sockets: ipv4={'yes' if sock4 else 'no'} ipv6={'yes' if sock6 else 'no'}")
            try:
                if sock4:
                    prog(f"dht ipv4 getsockname: {sock4.getsockname()!r}")
            except Exception as exc:
                prog(f"dht ipv4 getsockname failed: {exc}")
            try:
                if sock6:
                    prog(f"dht ipv6 getsockname: {sock6.getsockname()!r}")
            except Exception as exc:
                prog(f"dht ipv6 getsockname failed: {exc}")
            try:
                rt4 = sum(len(b.nodes) for b in n.routing_table.v4.buckets)
                rt6 = sum(len(b.nodes) for b in n.routing_table.v6.buckets)
                prog(f"dht routing table sizes: v4={rt4} v6={rt6}")
            except Exception:
                pass
        except Exception:
            pass

        # Give bootstrap a little time to populate tables before attempting metadata.
        time.sleep(2.0)

        remaining = max(5.0, hard_deadline_s - (time.time() - t0))

        # Do a quick discovery phase up front so the metadata resolver is seeded with
        # an initial peer list (helps distinguish scheduling vs response issues).
        def _discover() -> None:
            mgr.find_peers(info_hash, timeout=min(30.0, remaining), max_nodes=8, on_progress=None)

        _run_with_timeout(_discover, timeout_s=min(35.0, remaining), label="discovering peers")

        seeded = [(p.ip, int(p.port)) for p in mgr.node.peer_store.get_peers(info_hash)]
        prog(f"seeded peers from store: {len(seeded)}")

        def _retrieve() -> bytes | None:
            return mgr.retrieve_metadata(
                info_hash,
                timeout=min(240.0, remaining),
                max_peers=400,
                on_progress=prog,
                initial_peers=seeded,
                peer_status_observer=(
                    lambda ip, port, status, err: prog(
                        f"peer_status {ip}:{port} {status}" + (f" err={err}" if err else "")
                    )
                ),
            )

        meta = _run_with_timeout(
            _retrieve,
            timeout_s=remaining,
            label="retrieving torrent metadata",
        )
        # If this fails, the printed progress should include piece scheduling and/or
        # a concrete failure reason (connect_failed / rejects / timeouts / sha1 mismatch).
        assert any(
            "requested metadata piece" in ln for ln in progress_lines
        ), "metadata retrieval did not appear to schedule any piece requests; check progress trace above"
        assert meta is not None
        assert hashlib.sha1(meta).digest() == info_hash
        # Basic sanity: should look like bencoded dict.
        assert meta[:1] == b"d"
    finally:
        try:
            mgr.stop()
        except Exception:
            pass
