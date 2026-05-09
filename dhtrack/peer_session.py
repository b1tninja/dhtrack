from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Protocol

from dhtrack.peer import (
    MSG_BITFIELD,
    MSG_CHOKE,
    MSG_HAVE,
    MSG_INTERESTED,
    MSG_PIECE,
    MSG_REQUEST,
    MSG_UNCHOKE,
    ExtensionError,
    create_handshake,
    parse_handshake,
    serialize_peer_message,
)
from dhtrack.peerid import Endpoint
from dhtrack.utp import UTPSocket


class _StreamSocket(Protocol):
    def settimeout(self, value: float) -> None: ...
    def send(self, data: bytes) -> int: ...
    def sendall(self, data: bytes) -> None: ...
    def recv(self, n: int) -> bytes: ...
    def close(self) -> None: ...


class _UTPStreamAdapter:
    def __init__(self, sock: UTPSocket) -> None:
        self._s = sock

    def settimeout(self, value: float) -> None:
        self._s.settimeout(value)

    def send(self, data: bytes) -> int:
        return self._s.send(data)

    def sendall(self, data: bytes) -> None:
        # uTP send() is message-oriented but supports arbitrary lengths.
        # Keep behavior close to socket.sendall for the peer-wire framing.
        view = memoryview(data)
        total = 0
        while total < len(view):
            sent = self._s.send(view[total:].tobytes())
            if sent <= 0:
                raise OSError("utp send failed")
            total += sent

    def recv(self, n: int) -> bytes:
        return self._s.recv(n)

    def close(self) -> None:
        self._s.close()


def _client_peer_id() -> bytes:
    return b"-DH0001-" + os.urandom(12)


def _read_exact(sock: _StreamSocket, n: int, deadline: float) -> bytes | None:
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


def read_peer_message(sock: _StreamSocket, deadline: float) -> tuple[int, bytes] | None:
    lb = _read_exact(sock, 4, deadline)
    if lb is None:
        return None
    msg_len = struct.unpack("!I", lb)[0]
    if msg_len == 0:
        return (-1, b"")
    rest = _read_exact(sock, msg_len, deadline)
    if rest is None:
        return None
    return (rest[0], rest[1:])


@dataclass
class PeerSession:
    endpoint: Endpoint
    info_hash: bytes
    use_utp: bool = False
    sock: _StreamSocket | None = None
    peer_id: bytes = b""
    peer_bitfield: bytes = b""
    peer_choked: bool = True
    we_interested: bool = False

    def connect(self, timeout: float = 10.0) -> None:
        if self.use_utp:
            s = UTPSocket()
            s.settimeout(timeout)
            s.connect((self.endpoint.ip, self.endpoint.port))
            self.sock = _UTPStreamAdapter(s)
            return
        fam = socket.AF_INET6 if self.endpoint.is_ipv6 else socket.AF_INET
        s2 = socket.socket(fam, socket.SOCK_STREAM)
        s2.settimeout(timeout)
        s2.connect((self.endpoint.ip, self.endpoint.port))
        self.sock = s2

    def handshake(self, timeout: float = 30.0) -> None:
        if self.sock is None:
            raise RuntimeError("not connected")
        if len(self.info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")
        deadline = time.monotonic() + timeout
        my_pid = _client_peer_id()
        self.sock.sendall(create_handshake(self.info_hash, my_pid))
        hs = _read_exact(self.sock, 68, deadline)
        if hs is None:
            raise ExtensionError("peer handshake timeout")
        ext_ok, _res, ih, pid = parse_handshake(hs)
        if ih != self.info_hash:
            raise ExtensionError("infohash mismatch")
        self.peer_id = pid
        # we don't require LTEP for payload download; but it may be used for metadata/pex
        _ = ext_ok

    def send_interested(self) -> None:
        if self.sock is None:
            raise RuntimeError("not connected")
        self.sock.sendall(serialize_peer_message(MSG_INTERESTED, b""))
        self.we_interested = True

    def recv_until_unchoked(self, timeout: float = 30.0) -> None:
        if self.sock is None:
            raise RuntimeError("not connected")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = read_peer_message(self.sock, deadline)
            if msg is None:
                continue
            mtype, payload = msg
            if mtype == MSG_UNCHOKE:
                self.peer_choked = False
                return
            if mtype == MSG_CHOKE:
                self.peer_choked = True
            if mtype == MSG_BITFIELD:
                self.peer_bitfield = payload
            if mtype == MSG_HAVE:
                # ignore for now
                pass
        raise TimeoutError("timed out waiting for unchoke")

    def request_block(self, index: int, begin: int, length: int) -> None:
        if self.sock is None:
            raise RuntimeError("not connected")
        payload = struct.pack("!III", int(index), int(begin), int(length))
        self.sock.sendall(serialize_peer_message(MSG_REQUEST, payload))

    def recv_piece_block(
        self,
        *,
        expect_index: int,
        expect_begin: int,
        timeout: float,
    ) -> bytes | None:
        if self.sock is None:
            raise RuntimeError("not connected")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = read_peer_message(self.sock, deadline)
            if msg is None:
                continue
            mtype, payload = msg
            if mtype == -1:
                continue
            if mtype == MSG_CHOKE:
                self.peer_choked = True
                return None
            if mtype == MSG_UNCHOKE:
                self.peer_choked = False
                continue
            if mtype != MSG_PIECE:
                # ignore other messages (keepalive, have, ltep, etc.)
                continue
            if len(payload) < 8:
                continue
            idx, begin = struct.unpack("!II", payload[:8])
            if idx != expect_index or begin != expect_begin:
                continue
            return payload[8:]
        return None

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
