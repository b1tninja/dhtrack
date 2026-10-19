"""JSON helpers for the experimental prototypes.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path


def _replace_text(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically.

    The bytes go to a temporary file in the same directory, which then
    replaces ``path``. A crash mid-write leaves the old file intact rather
    than a truncated one that every later run fails to parse.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def dump_json(path: Path, payload: object) -> None:
    """Write ``payload`` as pretty, key-sorted JSON."""
    _replace_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_json(path: Path) -> object:
    """Read a JSON document."""
    return json.loads(path.read_text(encoding="utf-8"))


def append_jsonl(path: Path, row: Mapping[str, object]) -> None:
    """Append one compact JSON object as a line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(row), sort_keys=True, separators=(",", ":"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def write_snapshot_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    """Replace ``path`` with one JSON object per row.

    This is a snapshot of current aggregates, not an append-only event log.
    """
    lines = [json.dumps(dict(row), sort_keys=True, separators=(",", ":")) for row in rows]
    _replace_text(path, "".join(line + "\n" for line in lines))


def write_csv(path: Path, rows: Sequence[Mapping[str, object]], fieldnames: Sequence[str]) -> int:
    """Write ``rows`` as CSV. Returns the number of data rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "" if row.get(key) is None else row.get(key) for key in fieldnames})
    return len(rows)


def expect_int(value: object, label: str) -> int:
    """Return ``value`` when it is an ``int`` and not a ``bool``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def expect_str(value: object, label: str) -> str:
    """Return ``value`` when it is a ``str``."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def expect_number(value: object, label: str) -> float:
    """Return ``value`` as a float when it is an int or float, but not a bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    return float(value)


def expect_endpoint(ip: object, port: object, label: str, *, allow_port_zero: bool = False) -> tuple[str, int]:
    """Validate an ``(ip, port)`` pair from JSON input.

    ``ip`` must be a non-empty string and ``port`` an int in ``1..65535``.
    Peer tables pass ``allow_port_zero`` so analytics can flag the bad port
    instead of rejecting the whole table.
    """
    text = expect_str(ip, f"{label}.ip")
    if not text:
        raise ValueError(f"{label}.ip must not be empty")
    number = expect_int(port, f"{label}.port")
    if number < (0 if allow_port_zero else 1) or number > 65535:
        raise ValueError(f"{label}.port out of range")
    return text, number
