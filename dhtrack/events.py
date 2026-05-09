"""
Event sink interfaces for wiring dhtrack into GUIs/CLIs.
"""

from __future__ import annotations

from typing import Protocol


class ProtocolEventSink(Protocol):
    def on_outgoing_message(
        self,
        msg_type: str,
        dst_ip: str,
        dst_port: int,
        is_ipv6: bool,
        size: int,
    ) -> None: ...

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
    ) -> None: ...

    def on_status_update(
        self,
        *,
        total_peers: int,
        buckets_v4: int,
        nodes_v4: int,
        buckets_v6: int,
        nodes_v6: int,
    ) -> None: ...

    def on_message_parsed(self, ip: str, port: int, is_ipv6: bool, size: int, msg_info: dict) -> None: ...

    def on_bootstrap_progress(
        self,
        *,
        phase: str,
        depth: int,
        nodes_queried: int,
        nodes_discovered: int,
        min_xor_distance: int,
        total_nodes: int,
        elapsed: float,
    ) -> None: ...

    def on_observed_external_ip(self, *, family: str, ip: str, port: int) -> None:
        """BEP 42 ``ip`` quorum: ``family`` is ``ipv4`` or ``ipv6``."""
        ...

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
    ) -> None: ...


class NullEventSink:
    def on_outgoing_message(self, msg_type: str, dst_ip: str, dst_port: int, is_ipv6: bool, size: int) -> None:
        return

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
        return

    def on_status_update(
        self,
        *,
        total_peers: int,
        buckets_v4: int,
        nodes_v4: int,
        buckets_v6: int,
        nodes_v6: int,
    ) -> None:
        return

    def on_message_parsed(self, ip: str, port: int, is_ipv6: bool, size: int, msg_info: dict) -> None:
        return

    def on_bootstrap_progress(
        self,
        *,
        phase: str,
        depth: int,
        nodes_queried: int,
        nodes_discovered: int,
        min_xor_distance: int,
        total_nodes: int,
        elapsed: float,
    ) -> None:
        return

    def on_observed_external_ip(self, *, family: str, ip: str, port: int) -> None:
        return

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
        return


__all__ = ["ProtocolEventSink", "NullEventSink"]
