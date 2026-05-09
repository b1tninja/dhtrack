from __future__ import annotations

import hashlib
import logging
import math
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dhtrack.peer_session import PeerSession
from dhtrack.peerid import Endpoint
from dhtrack.resume import ResumeState
from dhtrack.storage import TorrentStorage, piece_hashes, total_length
from dhtrack.torrent import Torrent

logger = logging.getLogger(__name__)

BLOCK_LEN = 16 * 1024


def _bitfield_num_bytes(num_pieces: int) -> int:
    return (num_pieces + 7) // 8


def bitfield_has(bitfield: bytes | bytearray, index: int) -> bool:
    byte_i = index // 8
    if byte_i >= len(bitfield):
        return False
    bit = 7 - (index % 8)
    return bool(bitfield[byte_i] & (1 << bit))


def bitfield_set(bitfield: bytearray, index: int) -> None:
    byte_i = index // 8
    bit = 7 - (index % 8)
    bitfield[byte_i] |= 1 << bit


def bitfield_from_hex(hex_str: str, num_pieces: int) -> bytes:
    if not hex_str:
        return bytes(_bitfield_num_bytes(num_pieces))
    try:
        b = bytes.fromhex(hex_str)
    except ValueError:
        return bytes(_bitfield_num_bytes(num_pieces))
    need = _bitfield_num_bytes(num_pieces)
    if len(b) < need:
        return b + bytes(need - len(b))
    return b[:need]


def bitfield_to_hex(bitfield: bytes) -> str:
    return bitfield.hex()


@dataclass
class DownloadProgress:
    completed_pieces: int
    total_pieces: int
    downloaded_bytes: int
    total_bytes: int
    have_bitfield: bytes | None = None

    @property
    def fraction(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return min(1.0, self.downloaded_bytes / self.total_bytes)


class DownloadCoordinator:
    def __init__(
        self,
        torrent: Torrent,
        download_dir: Path,
        resume_dir: Path,
        *,
        use_utp: bool = False,
        on_progress: Callable[[DownloadProgress], None] | None = None,
        on_peer_snapshot: Callable[[str, int, dict[str, Any]], None] | None = None,
    ) -> None:
        self.torrent = torrent
        self.download_dir = Path(download_dir)
        self.resume_dir = Path(resume_dir)
        self.use_utp = use_utp
        self.on_progress = on_progress
        self.on_peer_snapshot = on_peer_snapshot

        self._piece_length = torrent.get_piece_length()
        self._piece_hashes = piece_hashes(torrent)
        self._total_len = total_length(torrent)
        if self._piece_length <= 0 or not self._piece_hashes:
            raise ValueError("torrent missing piece metadata")

        self._num_pieces = len(self._piece_hashes)
        self.storage = TorrentStorage(torrent, self.download_dir)
        self.storage.ensure_files()

        ih_hex = torrent.infohash.hex()
        self.resume_path = self.resume_dir / f"{ih_hex}.resume.json"

        existing = ResumeState.load(self.resume_path)
        if existing and existing.infohash_hex == ih_hex and existing.num_pieces == self._num_pieces:
            self.resume = existing
        else:
            self.resume = ResumeState(
                infohash_hex=ih_hex,
                piece_length=self._piece_length,
                total_length=self._total_len,
                num_pieces=self._num_pieces,
            )

        self._completed = bytearray(bitfield_from_hex(self.resume.completed, self._num_pieces))
        self.reconcile_completed_pieces_with_disk()

    def reconcile_completed_pieces_with_disk(
        self,
        *,
        on_progress_msg: Callable[[str], None] | None = None,
        progress_every: int = 256,
    ) -> int:
        """Hash-verify bytes already on disk for pieces not marked complete; update resume.

        Returns the number of pieces newly marked complete.
        """
        to_check = [i for i in range(self._num_pieces) if not bitfield_has(self._completed, i)]
        total = len(to_check)
        n_new = 0
        for j, idx in enumerate(to_check):
            if on_progress_msg is not None and total and j % progress_every == 0:
                on_progress_msg(f"Verifying existing data… {j}/{total} pieces checked")
            sz = self._piece_size(idx)
            offset = idx * self._piece_length
            try:
                raw = self.storage.read_at(offset, sz)
            except OSError:
                continue
            if len(raw) != sz:
                continue
            digest = hashlib.sha1(memoryview(raw)).digest()
            if digest != self._piece_hashes[idx]:
                continue
            bitfield_set(self._completed, idx)
            n_new += 1

        if n_new:
            self.resume.completed = bitfield_to_hex(bytes(self._completed))
            self.resume.save(self.resume_path)
        if on_progress_msg is not None and total:
            on_progress_msg(f"Verifying existing data… done ({n_new} piece(s) matched on disk)")
        self._emit_progress()
        return n_new

    def _emit_progress(self) -> None:
        if not self.on_progress:
            return
        done = sum(1 for i in range(self._num_pieces) if bitfield_has(self._completed, i))
        downloaded = done * self._piece_length
        self.on_progress(
            DownloadProgress(
                completed_pieces=done,
                total_pieces=self._num_pieces,
                downloaded_bytes=min(downloaded, self._total_len),
                total_bytes=self._total_len,
                have_bitfield=bytes(self._completed),
            )
        )

    def _piece_size(self, index: int) -> int:
        if index < 0 or index >= self._num_pieces:
            raise IndexError(index)
        if index == self._num_pieces - 1:
            # last piece may be shorter
            remain = self._total_len - (index * self._piece_length)
            return int(remain)
        return self._piece_length

    def _verify_and_commit(self, index: int, piece: bytes | bytearray) -> bool:
        h_ctx = hashlib.sha1()
        h_ctx.update(memoryview(piece))
        if h_ctx.digest() != self._piece_hashes[index]:
            return False
        self.storage.write_at(index * self._piece_length, bytes(piece))
        bitfield_set(self._completed, index)
        self.resume.completed = bitfield_to_hex(bytes(self._completed))
        self.resume.save(self.resume_path)
        return True

    def _next_missing_piece(self) -> int | None:
        for i in range(self._num_pieces):
            if not bitfield_has(self._completed, i):
                return i
        return None

    def download_from_peers(
        self,
        peers: Iterable[tuple[str, int]],
        *,
        connect_timeout: float = 8.0,
        peer_timeout: float = 30.0,
        max_piece_failures: int = 5,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> None:
        failures = 0
        peer_list = list(peers)
        if not peer_list:
            raise ValueError("no peers provided")

        try:
            while True:
                if cancel_requested and cancel_requested():
                    raise RuntimeError("download cancelled")
                missing = self._next_missing_piece()
                if missing is None:
                    self._emit_progress()
                    return

                # simple round-robin: try peers until one yields the piece
                got = False
                for ip, port in peer_list:
                    if cancel_requested and cancel_requested():
                        raise RuntimeError("download cancelled")
                    ep = Endpoint(ip=ip, port=int(port), node_id=None)
                    sess = PeerSession(endpoint=ep, info_hash=self.torrent.infohash, use_utp=self.use_utp)
                    try:
                        sess.connect(timeout=connect_timeout)
                        sess.handshake(timeout=peer_timeout)
                        sess.send_interested()
                        sess.recv_until_unchoked(timeout=peer_timeout)

                        if self.on_peer_snapshot is not None:
                            try:
                                self.on_peer_snapshot(
                                    ip,
                                    int(port),
                                    {
                                        "peer_chokes_us": bool(sess.peer_choked),
                                        "we_interested": bool(getattr(sess, "we_interested", False)),
                                        "phase": "payload_transfer",
                                        "have_peer_bitfield_bytes": (
                                            len(sess.peer_bitfield) if sess.peer_bitfield else 0
                                        ),
                                    },
                                )
                            except Exception:
                                pass

                        piece_len = self._piece_size(missing)
                        blocks = math.ceil(piece_len / BLOCK_LEN)
                        buf = bytearray(piece_len)
                        for b in range(blocks):
                            if cancel_requested and cancel_requested():
                                raise RuntimeError("download cancelled")
                            begin = b * BLOCK_LEN
                            req_len = min(BLOCK_LEN, piece_len - begin)
                            sess.request_block(missing, begin, req_len)
                            data = sess.recv_piece_block(
                                expect_index=missing,
                                expect_begin=begin,
                                timeout=peer_timeout,
                            )
                            if data is None or len(data) != req_len:
                                raise TimeoutError("missing or short piece block")
                            buf[begin : begin + req_len] = data

                        if not self._verify_and_commit(missing, buf):
                            raise ValueError("piece hash mismatch")

                        got = True
                        self._emit_progress()
                        break
                    except Exception as e:
                        logger.debug("peer %s:%s failed for piece %s: %s", ip, port, missing, e)
                    finally:
                        sess.close()

                if not got:
                    failures += 1
                    if failures >= max_piece_failures:
                        raise RuntimeError(f"failed to download piece {missing} after {failures} failures")
                    time.sleep(0.2)
        finally:
            self.storage.close()
