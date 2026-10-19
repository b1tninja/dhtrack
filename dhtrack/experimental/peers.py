"""JSON peer-table format shared by the experimental CLIs.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

A peer table is a JSON list of objects::

    {
      "ip": "203.0.113.10",
      "port": 6881,
      "peer_id_hex": "<40 hex chars, optional>",
      "node_id_hex": "<40 hex chars, optional>",
      "is_seeder": true
    }

``peer_id_hex``, ``node_id_hex``, and ``is_seeder`` may be omitted.
Address strings are not required to parse; the analytics report classifies
unparseable values instead of refusing the file.
"""

from __future__ import annotations

from dataclasses import dataclass

from dhtrack.experimental.persist import expect_endpoint, expect_str


@dataclass(frozen=True)
class PeerTableRow:
    """One peer row from an operator-supplied table."""

    ip: str
    port: int
    peer_id: bytes | None = None
    node_id: bytes | None = None
    is_seeder: bool | None = None


def parse_peer_table(payload: object) -> list[PeerTableRow]:
    """Parse a JSON peer table.

    Parameters
    ----------
    payload :
        The object returned by :func:`json.loads`. Must be a list.

    Returns
    -------
    list[PeerTableRow]
        Rows in input order.

    Raises
    ------
    ValueError
        If the document is not a list or a row is malformed. The message
        includes the row index.
    """
    if not isinstance(payload, list):
        raise ValueError("peer table must be a JSON list")
    rows: list[PeerTableRow] = []
    for index, item in enumerate(payload):
        rows.append(_parse_row(index, item))
    return rows


def _parse_row(index: int, item: object) -> PeerTableRow:
    label = f"peer[{index}]"
    if not isinstance(item, dict):
        raise ValueError(f"{label} must be an object")
    ip, port = expect_endpoint(item.get("ip"), item.get("port"), label, allow_port_zero=True)
    return PeerTableRow(
        ip=ip,
        port=port,
        peer_id=_optional_hex(item.get("peer_id_hex"), f"{label}.peer_id_hex"),
        node_id=_optional_hex(item.get("node_id_hex"), f"{label}.node_id_hex"),
        is_seeder=_optional_bool(item.get("is_seeder"), f"{label}.is_seeder"),
    )


def _optional_hex(value: object, label: str) -> bytes | None:
    if value is None:
        return None
    text = expect_str(value, label)
    if text == "":
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{label} is not hex") from exc
    if len(raw) != 20:
        raise ValueError(f"{label} must be 20 bytes")
    return raw


def _optional_bool(value: object, label: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value
