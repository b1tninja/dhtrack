"""Qt-free helpers for Swarm Inspector peer rows (filter + merge)."""

from __future__ import annotations

import binascii
import textwrap
import time
from collections.abc import Mapping
from typing import Any


def merge_peer_detail_fields(peer: dict[str, Any], updates: Mapping[str, Any]) -> None:
    """Merge GUI/runtime fields into an existing swarm peer dict (in-place)."""
    for k, v in updates.items():
        if v is None and k not in peer:
            continue
        peer[k] = v


def peer_row_detail_lines(peer: Mapping[str, Any]) -> list[str]:
    """Human-readable dump of peer dict keys for the detail pane."""
    lines: list[str] = []
    for k in sorted(peer.keys()):
        lines.append(f"{k}: {peer[k]!r}")
    return lines


def _coerce_peer_bitfield_bytes(raw: Any) -> bytes | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, bytearray):
        return bytes(raw)
    if isinstance(raw, memoryview):
        return raw.tobytes()
    if isinstance(raw, str):
        s = raw.strip().lower().replace(" ", "")
        if not s:
            return b""
        if len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
            try:
                return bytes.fromhex(s)
            except ValueError:
                return raw.encode("utf-8", errors="replace")
        return raw.encode("utf-8", errors="replace")
    try:
        if isinstance(raw, (list, tuple)) and raw and isinstance(raw[0], int):
            return bytes(raw)  # type: ignore[arg-type]
    except Exception:
        pass
    return None


def _bit_counts(data: bytes) -> tuple[int, int]:
    total = len(data) * 8
    if not data:
        return 0, 0
    set_bits = sum(x.bit_count() for x in data)
    return set_bits, total


def _bitmap_strip(data: bytes, *, max_bits: int = 256) -> str:
    """Tiny █/░ strip for visual scan (truncated)."""
    out: list[str] = []
    bit_n = 0
    for byte in data:
        for shift in range(7, -1, -1):
            if bit_n >= max_bits:
                out.append("…")
                return "".join(out)
            out.append("█" if (byte >> shift) & 1 else "░")
            bit_n += 1
    return "".join(out)


def peer_bitfield_expert_lines(peer: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    bf_keys = ("have_bitfield", "peer_bitfield", "bitfield")
    seen_any = False
    for key in bf_keys:
        raw_bf = peer.get(key)
        b = _coerce_peer_bitfield_bytes(raw_bf)
        if b is None:
            continue
        seen_any = True
        set_bits, total_bits = _bit_counts(b)
        pct = (100.0 * set_bits / total_bits) if total_bits else 0.0
        preview_n = min(48, len(b))
        hex_prev = binascii.hexlify(b[:preview_n]).decode("ascii")
        if len(b) > preview_n:
            hex_prev += "…"
        lines.append(f"{key}: {len(b)} byte(s); bits set ≈ {set_bits}/{total_bits} ({pct:.2f}%)")
        lines.append(textwrap.fill(f"hex[{preview_n}]: {hex_prev}", width=100))
        strip = _bitmap_strip(b)
        if strip.endswith("…"):
            lines.append(f"bitmap (first bits): {strip}")
        else:
            lines.append(f"bitmap: {strip}")
    if not seen_any:
        lines.append("(no have_bitfield / peer_bitfield / bitfield raw bytes)")
    return lines


def format_peer_expert_detail(peer: Mapping[str, Any]) -> str:
    """Sorted key/value dump plus bitfield hex, population, and ASCII bitmap preview."""
    parts: list[str] = []
    parts.append("--- Peer record ---")
    parts.extend(peer_row_detail_lines(peer))
    parts.append("")
    parts.append("--- Bitfield ---")
    parts.extend(peer_bitfield_expert_lines(peer))
    return "\n".join(parts)


def is_active_swarm_peer_row(peer: Mapping[str, Any]) -> bool:
    """Heuristic ''good / active'' row for ''Show only active peers'' filter.

    Excludes peers with fatal errors or clearly failed connection status.
    Includes known-good wire/DHT states and fresh DHT-discovered rows.
    """
    err = peer.get("last_error")
    if err:
        return False

    status_raw = peer.get("status")
    status = str(status_raw).lower() if status_raw is not None else ""

    bad_statuses = frozenset(
        {
            "connect_failed",
            "bad",
            "failed",
            "disconnect",
            "disconnected",
            "error",
        }
    )
    if status in bad_statuses:
        return False

    good_statuses = frozenset(
        {
            "connected",
            "unchoked",
            "choked",
            "metadata_ok",
            "handshake_ok",
            "good",
            "fresh",
            "recent",
        }
    )
    if status in good_statuses:
        return True

    # DHT / unknown label: use age heuristic (same spirit as SwarmPeerModel)
    if not status or status == "unknown":
        last = peer.get("last_seen", 0) or peer.get("last_contacted", 0)
        if not last:
            # Known address from DHT with no timestamps — keep visible as active-ish
            return peer.get("source") == "swarm"
        try:
            ago = time.time() - float(last)
        except Exception:
            return False
        if ago < 5 * 60:
            return True
        return False

    # ''stale'' from age heuristic counts as inactive
    if status == "stale":
        return False

    return False
