"""Outbound DHT KRPC helpers shared by kRPC Console and Peer Scope."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dhtrack.dht import DHTNode


@dataclass(frozen=True)
class KrpcActionResult:
    ok: bool
    detail: str


def _ensure_peer(
    node: DHTNode,
    ip: str,
    port: int,
    is_ipv6: bool,
    *,
    create_if_missing: bool,
) -> tuple[Any | None, str | None]:
    """Return (peer, error). ``error`` None means OK."""
    peer_key = (ip, port)
    if peer_key in node.peers:
        return node.peers[peer_key], None
    if not create_if_missing:
        return None, "peer not in local table — use Ping first or enable auto-add"
    peer = node.add_peer(None, ip, port, is_ipv6=is_ipv6)
    if peer is None:
        return None, f"failed to add/locate peer {ip}:{port}"
    return peer, None


def send_ping(node: DHTNode, ip: str, port: int, *, is_ipv6: bool, create_if_missing: bool = True) -> KrpcActionResult:
    existed = (ip, port) in node.peers
    peer, err = _ensure_peer(node, ip, port, is_ipv6, create_if_missing=create_if_missing or not existed)
    if peer is None or err:
        return KrpcActionResult(False, err or "no peer")
    peer.ping()
    if existed:
        return KrpcActionResult(True, "ping sent")
    return KrpcActionResult(True, "ping sent (new peer entry)")


def send_find_node(
    node: DHTNode,
    ip: str,
    port: int,
    *,
    target_id: bytes,
    is_ipv6: bool,
    create_if_missing: bool = True,
) -> KrpcActionResult:
    if len(target_id) != 20:
        return KrpcActionResult(False, "target_id must be 20 bytes")
    existed = (ip, port) in node.peers
    peer, err = _ensure_peer(node, ip, port, is_ipv6, create_if_missing=create_if_missing)
    if peer is None or err:
        return KrpcActionResult(False, err or "no peer")
    peer.find_node(target_id)
    if existed:
        return KrpcActionResult(True, "find_node sent")
    return KrpcActionResult(True, "find_node sent (new peer entry)")


def send_get_peers(
    node: DHTNode,
    ip: str,
    port: int,
    *,
    info_hash: bytes,
    is_ipv6: bool,
    create_if_missing: bool = True,
) -> KrpcActionResult:
    if len(info_hash) != 20:
        return KrpcActionResult(False, "info_hash must be 20 bytes")
    existed = (ip, port) in node.peers
    peer, err = _ensure_peer(node, ip, port, is_ipv6, create_if_missing=create_if_missing)
    if peer is None or err:
        return KrpcActionResult(False, err or "no peer")
    peer.query("get_peers", {"info_hash": info_hash})
    if existed:
        return KrpcActionResult(True, "get_peers sent")
    return KrpcActionResult(True, "get_peers sent (new peer entry)")


def send_announce_peer(
    node: DHTNode,
    ip: str,
    port: int,
    *,
    info_hash: bytes,
    implied_port: bool = False,
    is_ipv6: bool,
    create_if_missing: bool = True,
) -> KrpcActionResult:
    if len(info_hash) != 20:
        return KrpcActionResult(False, "info_hash must be 20 bytes")
    existed = (ip, port) in node.peers
    peer, err = _ensure_peer(node, ip, port, is_ipv6, create_if_missing=create_if_missing)
    if peer is None or err:
        return KrpcActionResult(False, err or "no peer")
    args = {
        "info_hash": info_hash,
        "port": port,
        "implied_port": 1 if implied_port else 0,
    }
    peer.query("announce_peer", args)
    if existed:
        return KrpcActionResult(True, "announce_peer sent")
    return KrpcActionResult(True, "announce_peer sent (new peer entry)")
