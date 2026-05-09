"""Torrent metadata retrieval from peers via ut_metadata (BEP 9).

Per BEP 9 / BEP 10: TCP peer wire handshake (LTEP bit), extended handshake,
then ut_metadata requests with responses carrying raw trailing bytes after the
bencoded dict (standard wire format).

Reference: BEP 9 — https://www.bittorrent.org/beps/bep_0009.html
Reference: BEP 10 — https://www.bittorrent.org/beps/bep_0010.html
"""

from __future__ import annotations

import concurrent.futures
import errno
import hashlib
import ipaddress
import logging
import os
import queue
import socket
import struct
import threading
import time
from collections.abc import Callable
from typing import Any

from dhtrack import bencode as bencode_module
from dhtrack import bep4
from dhtrack.bencode import DecodeError
from dhtrack.peer import (
    MAX_METADATA_SIZE,
    METADATA_BLOCK_SIZE,
    MSG_CHOKE,
    MSG_HAVE_NONE,
    MSG_INTERESTED,
    MSG_LTEP_HANDSHAKE,
    MSG_PORT,
    MSG_UNCHOKE,
    UT_METADATA,
    UT_METADATA_DATA,
    UT_METADATA_REJECT,
    UT_METADATA_REQUEST,
    UT_PEX,
    ExtensionError,
    create_handshake,
    parse_handshake,
    serialize_peer_message,
)

logger = logging.getLogger(__name__)

PeerDetailObserver = Callable[[str, int, dict[str, Any]], None] | None


def _peer_detail_emit(obs: PeerDetailObserver, ip: str, port: int, d: dict[str, Any]) -> None:
    if obs is None:
        return
    try:
        obs(ip, int(port), d)
    except Exception:
        pass


def _should_disable_ipv6_from_error(exc: OSError) -> bool:
    msg = str(exc).lower()
    # Windows WSA codes often surface only in message text.
    if "network is unreachable" in msg:
        return True
    if "no route to host" in msg:
        return True
    if "address not available" in msg:
        return True
    if "invalid argument" in msg:
        return True
    if "unreachable" in msg:
        return True
    # errno may be set on some platforms
    if getattr(exc, "errno", None) in (errno.EADDRNOTAVAIL, errno.ENETUNREACH, errno.EHOSTUNREACH):
        return True
    return False


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

METADATA_REQUEST_TIMEOUT = 120.0
MAX_RETRIES = 5
PIECE_TIMEOUT = 60.0
MAX_PIECES_INFLIGHT = 4
# Bounded concurrent outbound ut_metadata tries; frees slots as peers fail/time out.
METADATA_PEER_CONCURRENCY_DEFAULT = 8
# Cap peer-wire payloads during metadata fetch (was 4MiB): hostile/huge LTEP bursts were
# amplifying allocations once we decoded real ut_metadata traffic on the correct recv channel.
MAX_METADATA_PEER_WIRE_MSG_LEN = 512 * 1024
# BEP 9 piece + bencoded dict; anything larger cannot be legitimate ut_metadata on the wire.
_MAX_UT_METADATA_INNER_LEN = METADATA_BLOCK_SIZE + 8192

ProgressCallback = Callable[[str], None] | None

# LTEP + DHT + BEP 6 "fast extensions" (HAVE_NONE / HAVE_ALL) — many peers expect this on metadata-only joins.
_LTEP_RESERVED = bytes([0, 0, 0, 0, 0, bep4.RESERVED_LTEP, 0, bep4.RESERVED_DHT | bep4.RESERVED_FAST_EXTENSIONS])
# LTEP outbound handshake: IDs the remote uses when *they* emit extension messages *to us* (BEP 10).
# Must stay aligned with `_send_ltep_handshake(...)` in `retrieve_metadata`.
OUR_LTEP_EXTENSIONS_TO_US: dict[bytes, int] = {UT_METADATA: 1, UT_PEX: 2}


def _client_peer_id() -> bytes:
    """20-byte peer id for outbound metadata connections."""
    return b"-DH0001-" + os.urandom(12)


def _read_exact(sock: socket.socket, n: int, deadline: float) -> bytes | None:
    """Read exactly n bytes or None on EOF/timeout."""
    buf = bytearray()
    while len(buf) < n:
        if time.monotonic() > deadline:
            return None
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            chunk = sock.recv(n - len(buf))
        except TimeoutError:
            continue
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _read_peer_message(
    sock: socket.socket,
    deadline: float,
    *,
    max_msg_len: int = 4 * 1024 * 1024,
) -> tuple[int, bytes] | None:
    """Read one BitTorrent peer-wire message: (msg_type, payload_after_type).

    ``max_msg_len`` bounds the decoded length-prefix (including the 1-byte wire type byte)
    before ``msg_len`` bytes are read — oversized frames are abandoned without buffering
    (caller should drop the TCP session).
    """
    lb = _read_exact(sock, 4, deadline)
    if lb is None or len(lb) < 4:
        return None
    msg_len = struct.unpack("!I", lb)[0]
    if msg_len == 0:
        return -1, b""  # keepalive sentinel
    if msg_len < 1 or msg_len > max_msg_len:
        return None
    rest = _read_exact(sock, msg_len, deadline)
    if rest is None or len(rest) != msg_len:
        return None
    msg_type = rest[0]
    payload = rest[1:]
    return msg_type, payload


def connect_to_peer(
    ip: str,
    port: int,
    timeout: float = 10.0,
    is_ipv6: bool = False,
    *,
    peer_status_observer: Callable[[str, int, str, str | None], None] | None = None,
    peer_detail_observer: PeerDetailObserver = None,
) -> socket.socket | None:
    """TCP connect to peer."""
    try:
        fam = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # On Windows, AF_INET6 connect may require a 4-tuple.
        if is_ipv6 and os.name == "nt":
            sock.connect((ip, port, 0, 0))
        else:
            sock.connect((ip, port))
        if peer_status_observer is not None:
            try:
                peer_status_observer(ip, int(port), "connected", None)
            except Exception:
                pass
        _peer_detail_emit(
            peer_detail_observer,
            ip,
            port,
            {"phase": "tcp_connected", "status": "connected"},
        )
        return sock
    except OSError as e:
        logger.debug("connect %s:%s failed: %s", ip, port, e)
        if peer_status_observer is not None:
            try:
                # Common cases: refused, timed out, unreachable
                peer_status_observer(ip, int(port), "connect_failed", str(e))
            except Exception:
                pass
        return None


def _build_ltep_handshake_payload(
    m_map: dict[bytes, int],
    v: bytes = b"dhtrack",
) -> bytes:
    """BEP 10 LTEP handshake dict (bytes keys)."""
    return bencode_module.encode(
        {
            b"m": m_map,
            b"v": v,
        }
    )


def _send_ltep_handshake(sock: socket.socket, m_map: dict[bytes, int]) -> None:
    """Send extended handshake (ext message id 0)."""
    inner = _build_ltep_handshake_payload(m_map)
    payload = bytes([0]) + inner
    sock.sendall(serialize_peer_message(MSG_LTEP_HANDSHAKE, payload))


def _send_ut_metadata_message(
    sock: socket.socket,
    ut_ext_id: int,
    bencoded_inner: bytes,
) -> None:
    """Send an LTEP message with given extended id (ut_metadata channel)."""
    payload = bytes([ut_ext_id & 0xFF]) + bencoded_inner
    sock.sendall(serialize_peer_message(MSG_LTEP_HANDSHAKE, payload))


def _parse_peer_ltep_handshake_payload(payload: bytes) -> tuple[dict[bytes, int], int]:
    """Parse LTEP handshake body after leading ext id byte.

    Returns
    -------
    ext_map : dict mapping extension name bytes -> message id (int)
    metadata_size : int from ut_metadata handshake (0 if absent)
    """
    if not payload or payload[0] != 0:
        raise ExtensionError("expected LTEP handshake ext id 0")
    body = payload[1:]
    parsed = bencode_module.decode(body)
    if not isinstance(parsed, dict):
        raise ExtensionError("LTEP handshake not a dict")

    ext_map: dict[bytes, int] = {}
    m = parsed.get(b"m")
    if isinstance(m, dict):
        for k, v in m.items():
            if isinstance(k, bytes) and isinstance(v, int):
                ext_map[k] = v
    elif isinstance(m, list):
        # Legacy / mistaken list form — ignore mapping
        pass

    meta_sz = parsed.get(b"metadata_size", 0)
    if isinstance(meta_sz, int):
        md_size = meta_sz
    else:
        md_size = 0

    return ext_map, md_size


def _wait_for_ltep_handshake(
    sock: socket.socket,
    deadline: float,
    progress: ProgressCallback,
    *,
    dht_port_observer: Callable[[int], None] | None = None,
) -> tuple[dict[bytes, int], int]:
    """Skip non-LTEP messages until peer LTEP handshake (msg 20, ext 0)."""
    while time.monotonic() < deadline:
        msg = _read_peer_message(sock, deadline, max_msg_len=MAX_METADATA_PEER_WIRE_MSG_LEN)
        if msg is None:
            break
        mtype, payload = msg
        if mtype == -1:
            continue
        if mtype == MSG_PORT and len(payload) >= 2 and dht_port_observer is not None:
            # BEP 6: payload is 2-byte big-endian DHT UDP port.
            try:
                dht_port = struct.unpack("!H", payload[:2])[0]
                if 1 <= int(dht_port) <= 65535:
                    dht_port_observer(int(dht_port))
            except Exception:
                pass
        if mtype != MSG_LTEP_HANDSHAKE:
            continue
        try:
            ext_map, md_size = _parse_peer_ltep_handshake_payload(payload)
            return ext_map, md_size
        except ExtensionError:
            continue
    raise ExtensionError("timeout waiting for peer LTEP handshake")


def _extract_ut_metadata_piece(
    payload: bytes,
    ut_ext_id: int,
) -> tuple[int, int, bytes] | None:
    """Parse ut_metadata LTEP payload into (msg_type, piece_index, data_bytes).

    Supports standard BEP 9 trailing raw bytes after bencoded dict.
    """
    if not payload or payload[0] != ut_ext_id:
        return None
    inner = payload[1:]
    if len(inner) > _MAX_UT_METADATA_INNER_LEN:
        return None
    try:
        parsed, off = bencode_module.decode_item(inner, 0)
    except DecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    msg_type = parsed.get(b"msg_type")
    piece = parsed.get(b"piece")
    if not isinstance(msg_type, int) or not isinstance(piece, int):
        return None

    data = inner[off:]
    if b"buffer" in parsed and isinstance(parsed[b"buffer"], bytes):
        data = parsed[b"buffer"]

    return msg_type, piece, data


def _download_metadata(
    sock: socket.socket,
    info_hash: bytes,
    ut_send_id: int,
    ut_recv_id: int,
    metadata_size: int,
    deadline: float,
    progress: ProgressCallback,
    *,
    opener_remote_choking: bool | None = None,
    peer_detail_observer: PeerDetailObserver = None,
    peer_ip: str = "",
    peer_port: int = 0,
) -> tuple[bytes | None, str]:
    """Download all metadata pieces and verify SHA-1(info) == info_hash.

    Per BEP 10, the peer's LTEP ``m`` gives the extended message id we use when *sending*
    ut_metadata requests *to them* (``ut_send_id``). Inbound DATA uses the id we advertised
    in our own LTEP handshake for ut_metadata (``ut_recv_id``).
    """
    if metadata_size <= 0 or metadata_size > MAX_METADATA_SIZE:
        logger.warning("invalid metadata_size %s", metadata_size)
        return None, f"invalid metadata_size {metadata_size}"

    num_pieces = (metadata_size + METADATA_BLOCK_SIZE - 1) // METADATA_BLOCK_SIZE
    buffers: list[bytes | None] = [None] * num_pieces

    def expected_piece_len(idx: int) -> int:
        if idx == num_pieces - 1:
            return metadata_size - idx * METADATA_BLOCK_SIZE
        return METADATA_BLOCK_SIZE

    def send_request(piece: int) -> None:
        req = bencode_module.encode(
            {
                b"msg_type": UT_METADATA_REQUEST,
                b"piece": piece,
            }
        )
        _send_ut_metadata_message(sock, ut_send_id, req)

    last_progress_emit = 0.0
    # Track remote choke state while waiting for ut_metadata responses.
    # Some peers will not serve ut_metadata while choking us.
    choked: bool | None = None

    # If opener thought we were choked, wait for UNCHOKE before blasting ut_metadata REQUESTs.
    if opener_remote_choking is True:
        gate_deadline = min(deadline, time.monotonic() + 45.0)
        while time.monotonic() < gate_deadline:
            raw = _read_peer_message(sock, gate_deadline, max_msg_len=MAX_METADATA_PEER_WIRE_MSG_LEN)
            if raw is None:
                break
            gm, _gp = raw
            if gm == -1:
                continue
            if gm == MSG_UNCHOKE:
                break
            if gm == MSG_CHOKE:
                continue

    for target in range(num_pieces):
        if buffers[target] is not None:
            continue
        for attempt in range(MAX_RETRIES):
            if time.monotonic() > deadline:
                msg = "metadata download deadline exceeded"
                if progress:
                    progress(msg)
                return None, msg
            # Pipeline requests: many peers answer pieces out-of-order or only after seeing
            # multiple in-flight requests; a single-request loop often times out on slow peers.
            missing = [i for i in range(num_pieces) if buffers[i] is None]
            if not missing:
                break
            to_send = missing[:MAX_PIECES_INFLIGHT]
            for idx in to_send:
                send_request(idx)
                logger.debug(
                    "ut_metadata: sent request piece=%d/%d attempt=%d (pipelined)",
                    idx,
                    num_pieces - 1,
                    attempt + 1,
                )
                if progress:
                    progress(f"requested metadata piece {idx}/{num_pieces - 1} (attempt {attempt + 1})")
            piece_deadline = min(
                time.monotonic() + PIECE_TIMEOUT,
                deadline,
            )
            got_any_response = False
            non_ltep_seen = 0
            ltep_other_seen = 0
            while time.monotonic() < piece_deadline and buffers[target] is None:
                raw = _read_peer_message(
                    sock,
                    piece_deadline,
                    max_msg_len=MAX_METADATA_PEER_WIRE_MSG_LEN,
                )
                if raw is None:
                    break
                mtype, payload = raw
                if mtype == -1:
                    continue
                if mtype == MSG_CHOKE:
                    choked = True
                    _peer_detail_emit(
                        peer_detail_observer,
                        peer_ip,
                        peer_port,
                        {"peer_chokes_us": True, "phase": "ut_metadata_transfer"},
                    )
                    # If we get choked mid-transfer, pause briefly to see if the peer unchokes again.
                    continue
                if mtype == MSG_UNCHOKE:
                    choked = False
                    _peer_detail_emit(
                        peer_detail_observer,
                        peer_ip,
                        peer_port,
                        {"peer_chokes_us": False, "phase": "ut_metadata_transfer"},
                    )
                    continue
                if mtype != MSG_LTEP_HANDSHAKE:
                    # Sometimes peers send other messages while we wait; sample for debugging.
                    if non_ltep_seen < 3:
                        non_ltep_seen += 1
                        logger.debug(
                            "ut_metadata: ignoring non-LTEP message type=%d while waiting for piece=%d",
                            int(mtype),
                            int(target),
                        )
                    continue
                if payload and payload[0] != (ut_recv_id & 0xFF):
                    # Extended messages on other channels (e.g. ut_pex) can arrive.
                    if ltep_other_seen < 3:
                        ltep_other_seen += 1
                        logger.debug(
                            "ut_metadata: got LTEP ext_id=%d "
                            "(inbound ut_metadata ext_id=%d) while waiting for piece=%d",
                            int(payload[0]),
                            int(ut_recv_id),
                            int(target),
                        )
                ext = _extract_ut_metadata_piece(payload, ut_recv_id)
                if ext is None:
                    continue
                got_any_response = True
                msg_type, piece_idx, chunk = ext
                if msg_type == UT_METADATA_REJECT:
                    if piece_idx == target and progress:
                        progress(f"piece {target} rejected (attempt {attempt + 1})")
                    break
                if msg_type != UT_METADATA_DATA:
                    continue
                if piece_idx < 0 or piece_idx >= num_pieces:
                    continue
                if not isinstance(chunk, bytes):
                    continue
                if buffers[piece_idx] is not None:
                    continue
                elen = expected_piece_len(piece_idx)
                if piece_idx < num_pieces - 1:
                    if len(chunk) < METADATA_BLOCK_SIZE:
                        continue
                    if len(chunk) != METADATA_BLOCK_SIZE:
                        chunk = chunk[:METADATA_BLOCK_SIZE]
                else:
                    if len(chunk) < elen:
                        continue
                    if len(chunk) > elen:
                        chunk = chunk[:elen]
                buffers[piece_idx] = chunk
                logger.debug(
                    "ut_metadata: received piece=%d len=%d (target=%d)",
                    piece_idx,
                    len(chunk),
                    target,
                )
                now = time.monotonic()
                if progress and (now - last_progress_emit > 0.15):
                    done_ct = sum(1 for b in buffers if b is not None)
                    progress(f"metadata {done_ct}/{num_pieces} pieces")
                    last_progress_emit = now
            if buffers[target] is None and not got_any_response:
                logger.debug(
                    "ut_metadata: no responses for piece=%d within %.1fs",
                    target,
                    float(PIECE_TIMEOUT),
                )
                if choked is True and progress:
                    progress("peer is choking us; ut_metadata may not be served until UNCHOKE")
            if buffers[target] is not None:
                break
        else:
            if progress:
                progress(f"gave up on piece {target}")
            return None, f"gave up on piece {target}"

    meta = b"".join(buffers[i] for i in range(num_pieces) if buffers[i] is not None)
    if len(meta) != metadata_size:
        if progress:
            progress(f"assembled metadata length mismatch: got {len(meta)} want {metadata_size}")
        logger.warning("assembled length %s != metadata_size %s", len(meta), metadata_size)
        return None, f"assembled length {len(meta)} != metadata_size {metadata_size}"

    ih = hashlib.sha1(meta).digest()
    if ih != info_hash:
        if progress:
            progress(f"metadata SHA-1 mismatch: got {ih.hex()} want {info_hash.hex()}")
        logger.warning("metadata SHA-1 mismatch (got %s want %s)", ih.hex(), info_hash.hex())
        return None, "metadata SHA-1 mismatch"

    return meta, "ok"


def retrieve_metadata(
    ip: str,
    port: int,
    info_hash: bytes,
    timeout: float = 90.0,
    is_ipv6: bool = False,
    progress_callback: ProgressCallback = None,
    *,
    dht_port_observer: Callable[[int], None] | None = None,
    peer_status_observer: Callable[[str, int, str, str | None], None] | None = None,
    peer_detail_observer: PeerDetailObserver = None,
) -> bytes | None:
    """Fetch bencoded *info* dictionary bytes from a peer via ut_metadata."""
    if len(info_hash) != 20:
        return None

    logger.debug(
        "ut_metadata: starting peer=%s:%d is_ipv6=%s timeout=%.1fs infohash=%s",
        ip,
        port,
        is_ipv6,
        float(timeout),
        info_hash.hex(),
    )

    def prog(msg: str) -> None:
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    sock = connect_to_peer(
        ip,
        port,
        timeout=min(15.0, timeout),
        is_ipv6=is_ipv6,
        peer_status_observer=peer_status_observer,
        peer_detail_observer=peer_detail_observer,
    )
    if sock is None:
        prog(f"connect failed {ip}:{port}")
        logger.debug("ut_metadata: connect failed peer=%s:%d", ip, port)
        return None

    deadline = time.monotonic() + timeout
    try:
        prog(f"handshaking {ip}:{port}")
        pid = _client_peer_id()
        sock.sendall(create_handshake(info_hash, pid, reserved_bytes=_LTEP_RESERVED))

        hs = _read_exact(sock, 68, deadline)
        if hs is None or len(hs) != 68:
            prog("peer handshake incomplete")
            logger.debug("ut_metadata: handshake incomplete peer=%s:%d", ip, port)
            return None
        try:
            ext_ok, _res, peer_ih, _peer_pid = parse_handshake(hs)
        except ExtensionError as e:
            prog(f"bad handshake: {e}")
            logger.debug("ut_metadata: bad handshake peer=%s:%d err=%s", ip, port, e)
            return None

        if peer_ih != info_hash:
            prog("info_hash mismatch in handshake")
            logger.debug(
                "ut_metadata: peer infohash mismatch peer=%s:%d got=%s want=%s",
                ip,
                port,
                peer_ih.hex(),
                info_hash.hex(),
            )
            return None
        if not ext_ok:
            prog("peer does not advertise LTEP")
            logger.debug("ut_metadata: no LTEP peer=%s:%d", ip, port)
            return None

        _send_ltep_handshake(sock, OUR_LTEP_EXTENSIONS_TO_US)
        try:

            def _obs_port(dht_port: int) -> None:
                logger.debug(
                    "ut_metadata: peer advertised DHT port %d via BEP6 PORT (%s:%d)",
                    dht_port,
                    ip,
                    port,
                )
                if dht_port_observer is not None:
                    try:
                        dht_port_observer(dht_port)
                    except Exception:
                        pass

            peer_map, md_size = _wait_for_ltep_handshake(
                sock,
                deadline,
                prog,
                dht_port_observer=_obs_port,
            )
        except ExtensionError as e:
            prog(f"no LTEP handshake: {e}")
            logger.debug("ut_metadata: LTEP handshake timeout/failure peer=%s:%d err=%s", ip, port, e)
            return None

        logger.debug(
            "ut_metadata: LTEP handshake ok peer=%s:%d ext=%s metadata_size=%d",
            ip,
            port,
            {k.decode("latin-1", "ignore"): v for k, v in peer_map.items()},
            int(md_size),
        )
        _peer_detail_emit(
            peer_detail_observer,
            ip,
            port,
            {
                "phase": "ltep_ok",
                "ut_metadata_size": int(md_size),
                "status": "handshake_ok",
            },
        )

        ut_send_id = peer_map.get(UT_METADATA)
        if not isinstance(ut_send_id, int) or ut_send_id <= 0:
            prog("peer did not offer ut_metadata")
            logger.debug("ut_metadata: peer did not offer ut_metadata peer=%s:%d", ip, port)
            return None

        ut_recv_id = OUR_LTEP_EXTENSIONS_TO_US[UT_METADATA]

        if md_size <= 0:
            prog("peer did not send metadata_size; cannot fetch")
            logger.debug("ut_metadata: missing/invalid metadata_size peer=%s:%d md_size=%s", ip, port, md_size)
            return None

        prog(f"ut_metadata send_id={ut_send_id} recv_id={ut_recv_id}, size={md_size}")
        logger.debug(
            "ut_metadata: requesting pieces peer=%s:%d send=%d recv=%d size=%d",
            ip,
            port,
            ut_send_id,
            ut_recv_id,
            md_size,
        )

        # BEP 6 / BEP 16: we have no payload pieces yet; clears "waiting for bitfield" state on many clients.
        try:
            sock.sendall(serialize_peer_message(MSG_HAVE_NONE, b""))
            prog("sent HAVE_NONE (BEP 16)")
        except OSError as exc:
            logger.debug("could not send HAVE_NONE to %s:%s: %s", ip, port, exc)

        # Many clients only push ut_metadata after standard interested/choke churn.
        try:
            sock.sendall(serialize_peer_message(MSG_INTERESTED, b""))
            prog("sent INTERESTED (BEP 3)")
            _peer_detail_emit(
                peer_detail_observer,
                ip,
                port,
                {"we_interested": True, "phase": "sent_interested"},
            )
        except OSError as exc:
            logger.debug("could not send INTERESTED to %s: %s", ip, exc)

        # Some peers won't respond to ut_metadata requests while choking us.
        # Wait briefly for an UNCHOKE (but don't fail if it never arrives).
        # IMPORTANT: Default must NOT assume choked-if-unknown; an empty/socket-timeout read-out
        # was falsely treated as remote-choke and made us behave badly toward cooperative peers.
        remote_choking: bool | None = None
        try:
            unchoke_deadline = min(deadline, time.monotonic() + 15.0)
            while time.monotonic() < unchoke_deadline:
                msg = _read_peer_message(sock, unchoke_deadline, max_msg_len=MAX_METADATA_PEER_WIRE_MSG_LEN)
                if msg is None:
                    break
                mtype, _payload = msg
                if mtype == MSG_UNCHOKE:
                    remote_choking = False
                    break
                if mtype == MSG_CHOKE:
                    remote_choking = True
            if remote_choking is True:
                prog("peer choke state before ut_metadata: choked")
            elif remote_choking is False:
                prog("peer choke state before ut_metadata: unchoked")
            else:
                prog("peer choke state before ut_metadata: unknown (no CHOKE/UNCHOKE observed yet)")
            if remote_choking is not None:
                _peer_detail_emit(
                    peer_detail_observer,
                    ip,
                    port,
                    {"peer_chokes_us": bool(remote_choking), "phase": "pre_ut_metadata"},
                )
        except Exception:
            remote_choking = None

        meta, reason = _download_metadata(
            sock,
            info_hash,
            ut_send_id,
            ut_recv_id,
            md_size,
            deadline,
            prog,
            opener_remote_choking=remote_choking,
            peer_detail_observer=peer_detail_observer,
            peer_ip=ip,
            peer_port=int(port),
        )
        if meta is None:
            prog(
                f"ut_metadata download failed: {reason}. Trying other peers.",
            )
            logger.debug(
                "ut_metadata: failed to download/verify peer=%s:%d reason=%s",
                ip,
                port,
                reason,
            )
        else:
            _peer_detail_emit(
                peer_detail_observer,
                ip,
                port,
                {"phase": "metadata_complete", "status": "metadata_ok"},
            )
        return meta
    finally:
        try:
            sock.close()
        except OSError:
            pass


def download_torrent_metadata(
    peers: list[tuple[str, int, bool]],
    info_hash: bytes,
    timeout: float = 90.0,
    progress_callback: ProgressCallback = None,
    *,
    max_concurrent: int = METADATA_PEER_CONCURRENCY_DEFAULT,
    per_peer_timeout: float | None = None,
    dht_port_observer: Callable[[str, int, int], None] | None = None,
    peer_status_observer: Callable[[str, int, str, str | None], None] | None = None,
    peer_detail_observer: PeerDetailObserver = None,
) -> bytes | None:
    """Try peers with bounded parallelism until metadata is retrieved or deadline.

    Dispatches attempts in batches of ``max_concurrent``. When an attempt completes
    without metadata, schedules the next peer from the queue (iterative resolver).
    Each peer uses at most ``per_peer_timeout`` seconds (never longer than remaining
    wall time). The overall operation stops at ``timeout`` regardless of backlog.
    """
    if not peers:
        return None

    # Suppress loser threads' callbacks once this resolver exits (success or failure).
    resolver_done = threading.Event()

    def emit_progress(msg: str) -> None:
        if resolver_done.is_set():
            return
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    if len(info_hash) != 20:
        return None

    if per_peer_timeout is None:
        # Enough time per peer for handshake + METADATA_REQUEST_TIMEOUT-style
        # piece exchange (otherwise we often negotiate metadata_size then give up
        # mid-transfer when the iterative resolver sliced ~25s per peer).
        per_peer_timeout = float(METADATA_REQUEST_TIMEOUT)

    deadline = time.monotonic() + timeout
    max_workers = max(1, min(max_concurrent, len(peers)))
    pending: dict[concurrent.futures.Future[bytes | None], tuple[str, int, bool]] = {}
    next_idx = 0

    emit_progress(
        f"metadata resolver: {len(peers)} peer(s), up to {max_concurrent} parallel, "
        f"~{per_peer_timeout:.0f}s per attempt, {timeout:.0f}s overall",
    )

    def schedule(ex: concurrent.futures.ThreadPoolExecutor) -> None:
        nonlocal next_idx
        while len(pending) < max_concurrent and next_idx < len(peers):
            remain = deadline - time.monotonic()
            if remain <= 0:
                break
            peer_timeout = min(float(per_peer_timeout), remain)
            if peer_timeout < 1.0:
                break
            ip, port, is_ipv6 = peers[next_idx]
            logger.debug(
                "schedule ut_metadata %s:%s timeout=%.1fs (%d/%d)",
                ip,
                port,
                peer_timeout,
                next_idx + 1,
                len(peers),
            )
            emit_progress(f"Trying peer {next_idx + 1}/{len(peers)}: {ip}:{port}")

            def _attempt(
                _ip: str = ip,
                _port: int = port,
                _is_v6: bool = is_ipv6,
                _peer_timeout: float = peer_timeout,
            ) -> bytes | None:
                kwargs = {}
                if dht_port_observer is not None:
                    kwargs["dht_port_observer"] = lambda dhtp, __ip=_ip, __port=_port: dht_port_observer(
                        __ip, __port, dhtp
                    )
                if peer_status_observer is not None:
                    kwargs["peer_status_observer"] = peer_status_observer
                if peer_detail_observer is not None:
                    kwargs["peer_detail_observer"] = peer_detail_observer
                return retrieve_metadata(
                    _ip,
                    _port,
                    info_hash,
                    _peer_timeout,
                    _is_v6,
                    emit_progress,
                    **kwargs,
                )

            fut = ex.submit(_attempt)
            pending[fut] = (ip, port, is_ipv6)
            next_idx += 1

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    try:
        schedule(ex)
        while pending:
            remain = deadline - time.monotonic()
            if remain <= 0:
                emit_progress("Metadata retrieval timed out (overall deadline)")
                return None
            done, _ = concurrent.futures.wait(
                pending.keys(),
                timeout=min(remain, 30.0),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                continue
            # Handle successes before failures in this batch: otherwise a failure branch
            # may schedule extra peers while another completed future already has metadata.
            batch: list[tuple[bytes | None, str, int]] = []
            for fut in done:
                peer = pending.pop(fut)
                ip, port, _is_v6 = peer
                try:
                    raw = fut.result()
                except Exception as exc:
                    logger.debug("peer task failed %s:%s: %s", ip, port, exc)
                    raw = None
                if raw is not None and len(raw) == 0:
                    raw = None
                batch.append((raw, ip, port))

            batch.sort(key=lambda rp: not bool(rp[0]))

            for raw, ip, port in batch:
                if raw:
                    emit_progress(f"Metadata retrieved from {ip}:{port}")
                    return raw

            for _raw, ip, port in batch:
                logger.debug("no metadata from %s:%s, scheduling next peer", ip, port)
                schedule(ex)

        emit_progress(
            "Failed to retrieve metadata: no reachable metadata peer before overall timeout or exhausted peer list",
        )
        return None

    finally:
        resolver_done.set()
        ex.shutdown(wait=False, cancel_futures=True)


def download_torrent_metadata_dynamic(
    *,
    peer_queue: queue.Queue[tuple[str, int]],
    info_hash: bytes,
    timeout: float = 90.0,
    progress_callback: ProgressCallback = None,
    max_concurrent: int = METADATA_PEER_CONCURRENCY_DEFAULT,
    per_peer_timeout: float | None = None,
    initial_peers: list[tuple[str, int]] | None = None,
    queue_poll_interval: float = 0.25,
    dht_port_observer: Callable[[str, int, int], None] | None = None,
    peer_status_observer: Callable[[str, int, str, str | None], None] | None = None,
    peer_detail_observer: PeerDetailObserver = None,
) -> bytes | None:
    """Like :func:`download_torrent_metadata`, but accepts peers dynamically.

    Peers can be pushed into ``peer_queue`` from another thread while this
    resolver is running. Peer identity is deduped by ``(ip, port)``; IPv6-ness
    is derived from the IP string at connect time.
    """
    # Suppress loser threads' callbacks once this resolver exits (success or failure).
    resolver_done = threading.Event()

    def emit_progress(msg: str) -> None:
        if resolver_done.is_set():
            return
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    if len(info_hash) != 20:
        return None

    if per_peer_timeout is None:
        per_peer_timeout = float(METADATA_REQUEST_TIMEOUT)

    deadline = time.monotonic() + timeout
    max_workers = max(1, int(max_concurrent))
    pending: dict[concurrent.futures.Future[bytes | None], tuple[str, int]] = {}
    backlog_v4: queue.Queue[tuple[str, int]] = queue.Queue()
    backlog_v6: queue.Queue[tuple[str, int]] = queue.Queue()
    seen: set[tuple[str, int]] = set()
    schedule_toggle_v6 = False

    def offer(ip: str, port: int) -> None:
        key = (ip, int(port))
        if key in seen:
            return
        try:
            is_ipv6 = ipaddress.ip_address(ip).version == 6
        except ValueError:
            return
        seen.add(key)
        if is_ipv6:
            backlog_v6.put(key)
        else:
            backlog_v4.put(key)

    if initial_peers:
        for ip, port in initial_peers:
            offer(ip, port)

    emit_progress(
        f"metadata resolver (dynamic): up to {max_concurrent} parallel, "
        f"~{per_peer_timeout:.0f}s per attempt, {timeout:.0f}s overall",
    )
    logger.debug(
        "metadata resolver (dynamic): start infohash=%s timeout=%.1fs max_concurrent=%d per_peer_timeout=%.1fs",
        info_hash.hex(),
        float(timeout),
        int(max_concurrent),
        float(per_peer_timeout),
    )

    def schedule(ex: concurrent.futures.ThreadPoolExecutor) -> None:
        nonlocal schedule_toggle_v6
        while len(pending) < max_concurrent:
            remain = deadline - time.monotonic()
            if remain <= 0:
                return
            peer_timeout = min(float(per_peer_timeout), remain)
            if peer_timeout < 1.0:
                return
            # Keep IPv4 and IPv6 attempts in-flight concurrently when available.
            # If both backlogs are non-empty, alternate which family we pull from.
            ip: str
            port: int
            is_ipv6: bool
            for _ in range(2):
                want_v6 = schedule_toggle_v6
                schedule_toggle_v6 = not schedule_toggle_v6

                q = backlog_v6 if want_v6 else backlog_v4
                other = backlog_v4 if want_v6 else backlog_v6

                try:
                    ip, port = q.get_nowait()
                    is_ipv6 = want_v6
                except queue.Empty:
                    try:
                        ip, port = other.get_nowait()
                        is_ipv6 = not want_v6
                    except queue.Empty:
                        return
                break
            else:
                return

            emit_progress(f"Trying peer: {ip}:{port}")
            fut = ex.submit(
                retrieve_metadata,
                ip,
                port,
                info_hash,
                peer_timeout,
                is_ipv6,
                emit_progress,
                dht_port_observer=(
                    (lambda dhtp, _ip=ip, _port=port: dht_port_observer(_ip, _port, dhtp))
                    if dht_port_observer is not None
                    else None
                ),
                peer_status_observer=peer_status_observer,
                peer_detail_observer=peer_detail_observer,
            )
            pending[fut] = (ip, port)

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    try:
        # Main loop: keep scheduling until success/timeout.
        while True:
            # Pull any newly discovered peers from the external queue.
            while True:
                try:
                    ip, port = peer_queue.get_nowait()
                except queue.Empty:
                    break
                offer(ip, port)

            schedule(ex)

            if logger.isEnabledFor(logging.DEBUG):
                try:
                    logger.debug(
                        "metadata resolver (dynamic): seen=%d backlog~%d inflight=%d",
                        len(seen),
                        backlog_v4.qsize() + backlog_v6.qsize(),
                        len(pending),
                    )
                except Exception:
                    pass

            remain = deadline - time.monotonic()
            if remain <= 0:
                emit_progress("Metadata retrieval timed out (overall deadline)")
                return None

            if not pending:
                # No in-flight work. Block briefly waiting for new peers.
                try:
                    ip, port = peer_queue.get(timeout=min(queue_poll_interval, remain))
                except queue.Empty:
                    continue
                offer(ip, port)
                continue

            done, _ = concurrent.futures.wait(
                pending.keys(),
                timeout=min(remain, 5.0),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                continue

            batch: list[tuple[bytes | None, str, int]] = []
            for fut in done:
                ip, port = pending.pop(fut)
                try:
                    raw = fut.result()
                except Exception as exc:
                    logger.debug("peer task failed %s:%s: %s", ip, port, exc)
                    raw = None
                if raw is not None and len(raw) == 0:
                    raw = None
                batch.append((raw, ip, port))

            batch.sort(key=lambda rp: not bool(rp[0]))
            for raw, ip, port in batch:
                if raw:
                    emit_progress(f"Metadata retrieved from {ip}:{port}")
                    return raw

    finally:
        resolver_done.set()
        ex.shutdown(wait=False, cancel_futures=True)
