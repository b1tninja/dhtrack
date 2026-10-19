"""Thread-safe buffer that batches DHT GUI events off the I/O thread.

The asyncio datagram callback must not touch Qt widgets. It appends here.
The window drains the buffer on a QTimer (100–250 ms) and applies the batch
on the GUI thread.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any


class GuiEventCoalescer:
    """Bounded queues of inbound, outbound, parsed, and wire events."""

    def __init__(self, *, maxlen: int = 2000, wire_maxlen: int = 200) -> None:
        self._lock = threading.Lock()
        self._incoming: deque[tuple] = deque(maxlen=maxlen)
        self._outgoing: deque[tuple] = deque(maxlen=maxlen)
        self._parsed: deque[tuple] = deque(maxlen=maxlen)
        self._wire: deque[tuple] = deque(maxlen=wire_maxlen)
        self._bootstrap: dict[str, Any] | None = None
        self._query_delta = 0
        self._response_delta = 0

    def on_outgoing_message(self, msg_type: str, dst_ip: str, dst_port: int, is_ipv6: bool, size: int) -> None:
        with self._lock:
            self._outgoing.append((msg_type, dst_ip, int(dst_port), bool(is_ipv6), int(size)))
            self._query_delta += 1

    def on_incoming_message(
        self,
        msg_type: str,
        src_ip: str,
        src_port: int,
        is_ipv6: bool,
        size: int,
        *,
        txid: str = "",
        status: str = "",
    ) -> None:
        with self._lock:
            self._incoming.append(
                (msg_type, src_ip, int(src_port), bool(is_ipv6), int(size), str(txid), str(status)),
            )
            self._response_delta += 1

    def on_message_parsed(self, ip: str, port: int, is_ipv6: bool, size: int, msg_info: dict) -> None:
        with self._lock:
            self._parsed.append((str(ip), int(port), bool(is_ipv6), int(size), dict(msg_info)))

    def on_wire_message(
        self,
        *,
        direction: str,
        addr: tuple,
        size: int,
        hex_str: str,
        decode_status: str,
        decode_repr: str,
        txid_hex: str,
        method: str,
        note: str,
    ) -> None:
        with self._lock:
            self._wire.append(
                (
                    direction,
                    addr,
                    int(size),
                    hex_str,
                    decode_status,
                    decode_repr,
                    txid_hex,
                    method,
                    note,
                ),
            )

    def on_bootstrap_progress(self, **kwargs: Any) -> None:
        with self._lock:
            self._bootstrap = dict(kwargs)

    def drain(self) -> dict[str, Any]:
        """Take the current batch. Safe to call from the GUI thread only for the result."""
        with self._lock:
            incoming = list(self._incoming)
            outgoing = list(self._outgoing)
            parsed = list(self._parsed)
            wire = list(self._wire)
            bootstrap = self._bootstrap
            queries = self._query_delta
            responses = self._response_delta
            self._incoming.clear()
            self._outgoing.clear()
            self._parsed.clear()
            self._wire.clear()
            self._bootstrap = None
            self._query_delta = 0
            self._response_delta = 0
        return {
            "incoming": incoming,
            "outgoing": outgoing,
            "parsed": parsed,
            "wire": wire,
            "bootstrap": bootstrap,
            "query_delta": queries,
            "response_delta": responses,
        }


__all__ = ["GuiEventCoalescer"]
