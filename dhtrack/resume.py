from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class ResumeState:
    """Persisted resume state for a torrent download.

    This is intentionally minimal and forward-compatible.
    """

    infohash_hex: str
    piece_length: int
    total_length: int
    num_pieces: int
    completed: str = ""  # hex bitfield (MSB-first)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def mark_updated(self) -> None:
        self.updated_at = time.time()

    @staticmethod
    def load(path: Path) -> ResumeState | None:
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            return ResumeState(**data)
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def save(self, path: Path) -> None:
        self.mark_updated()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
