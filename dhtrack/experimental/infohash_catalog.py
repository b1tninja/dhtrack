"""BEP 51 infohash discovery catalog and sample schedule.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
See ``docs/proposals/infohash-catalog.md``.

``DHTNode.sample_infohashes`` sends a BEP 51 query and returns an empty list.
Responses are parsed in ``DHTPeer._process_sample_infohashes_response``, which
logs the infohashes and records the peer's ``interval``, then discards the
hashes. There is no poll loop.

This module is the missing store and scheduler. It does not open sockets.
A caller (or a later hook inside the response handler) feeds it sample
payloads. :func:`run_sample_round` decides which endpoints are due, asks a
transport for each reply, and updates the catalog.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from dhtrack.experimental.persist import dump_json, expect_int, expect_number, expect_str, load_json

CATALOG_KIND = "dhtrack.experimental.infohash_catalog"
CATALOG_VERSION = 1
SOURCE_BEP51 = "bep51"


def parse_bep51_samples(samples: bytes) -> list[bytes]:
    """Split a BEP 51 ``samples`` blob into 20-byte infohashes.

    A trailing partial hash is dropped, matching
    ``DHTPeer._process_sample_infohashes_response``.

    Raises
    ------
    TypeError
        If ``samples`` is not ``bytes``.
    """
    if not isinstance(samples, bytes):
        raise TypeError("BEP 51 samples must be bytes")
    count = len(samples) // 20
    return [samples[i * 20 : (i + 1) * 20] for i in range(count)]


@dataclass(frozen=True)
class SampleReply:
    """One BEP 51 ``sample_infohashes`` response body."""

    samples: bytes
    num: int | None = None
    interval: int | None = None


@dataclass(frozen=True)
class InfohashObservation:
    """A single sighting of an infohash."""

    info_hash: bytes
    observed_at: float
    source: str
    via: str = ""
    num: int | None = None
    interval: int | None = None

    def __post_init__(self) -> None:
        if len(self.info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")
        if not self.source:
            raise ValueError("source must be non-empty")


@dataclass
class CatalogRecord:
    """Aggregate row for one infohash."""

    info_hash_hex: str
    first_seen: float
    last_seen: float
    hit_count: int
    sources: dict[str, int]
    vias: list[str]
    last_num: int | None = None
    last_interval: int | None = None

    def to_dict(self) -> dict[str, object]:
        """JSON-ready copy of this row."""
        return {
            "info_hash_hex": self.info_hash_hex,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_count": self.hit_count,
            "sources": dict(self.sources),
            "vias": list(self.vias),
            "last_num": self.last_num,
            "last_interval": self.last_interval,
        }

    @classmethod
    def from_dict(cls, raw: object) -> CatalogRecord:
        """Rebuild a row from :meth:`to_dict` output."""
        if not isinstance(raw, dict):
            raise ValueError("catalog record must be an object")
        info_hash_hex = expect_str(raw.get("info_hash_hex"), "info_hash_hex").lower()
        try:
            decoded = bytes.fromhex(info_hash_hex)
        except ValueError as exc:
            raise ValueError("info_hash_hex is not hex") from exc
        if len(decoded) != 20:
            raise ValueError("info_hash_hex must be 20 bytes")
        sources_raw = raw.get("sources", {})
        if not isinstance(sources_raw, dict):
            raise ValueError("sources must be an object")
        sources: dict[str, int] = {}
        for key, count in sources_raw.items():
            name = expect_str(key, "sources key")
            sources[name] = expect_int(count, f"sources[{name}]")
        vias_raw = raw.get("vias", [])
        if not isinstance(vias_raw, list) or not all(isinstance(item, str) for item in vias_raw):
            raise ValueError("vias must be a list of strings")
        num = raw.get("last_num")
        interval = raw.get("last_interval")
        return cls(
            info_hash_hex=info_hash_hex,
            first_seen=expect_number(raw.get("first_seen"), "first_seen"),
            last_seen=expect_number(raw.get("last_seen"), "last_seen"),
            hit_count=expect_int(raw.get("hit_count"), "hit_count"),
            sources=sources,
            vias=list(vias_raw),
            last_num=None if num is None else expect_int(num, "last_num"),
            last_interval=None if interval is None else expect_int(interval, "last_interval"),
        )


class InfohashCatalog:
    """In-memory aggregate of infohashes seen by a sampler or passive hints."""

    def __init__(self, *, max_vias: int = 16) -> None:
        if max_vias < 1:
            raise ValueError("max_vias must be at least 1")
        self.max_vias = max_vias
        self._rows: dict[str, CatalogRecord] = {}

    def __len__(self) -> int:
        return len(self._rows)

    def get(self, info_hash_hex: str) -> CatalogRecord | None:
        """Return the aggregate for ``info_hash_hex``, if present."""
        return self._rows.get(info_hash_hex.lower())

    def records(self) -> list[CatalogRecord]:
        """Rows most-recently seen first, then by infohash."""
        return sorted(self._rows.values(), key=lambda row: (-row.last_seen, row.info_hash_hex))

    def ingest(self, observation: InfohashObservation) -> CatalogRecord:
        """Fold one sighting into the aggregate. Returns the live row."""
        key = observation.info_hash.hex()
        row = self._rows.get(key)
        if row is None:
            row = CatalogRecord(
                info_hash_hex=key,
                first_seen=observation.observed_at,
                last_seen=observation.observed_at,
                hit_count=0,
                sources={},
                vias=[],
            )
            self._rows[key] = row
        row.hit_count += 1
        row.sources[observation.source] = row.sources.get(observation.source, 0) + 1
        if observation.via and observation.via not in row.vias and len(row.vias) < self.max_vias:
            row.vias.append(observation.via)
        if observation.observed_at < row.first_seen:
            row.first_seen = observation.observed_at
        if observation.observed_at >= row.last_seen:
            row.last_seen = observation.observed_at
            if observation.num is not None:
                row.last_num = observation.num
            if observation.interval is not None:
                row.last_interval = observation.interval
        return row

    def ingest_bep51(
        self,
        samples: bytes,
        *,
        via: str,
        observed_at: float,
        num: int | None = None,
        interval: int | None = None,
    ) -> list[CatalogRecord]:
        """Ingest every full infohash in a BEP 51 ``samples`` blob."""
        touched: list[CatalogRecord] = []
        for info_hash in parse_bep51_samples(samples):
            touched.append(
                self.ingest(
                    InfohashObservation(
                        info_hash=info_hash,
                        observed_at=observed_at,
                        source=SOURCE_BEP51,
                        via=via,
                        num=num,
                        interval=interval,
                    )
                )
            )
        return touched


def sample_reply_from_krpc(response: Mapping[bytes, object]) -> SampleReply:
    """Read ``samples``, ``num``, and ``interval`` from a KRPC response dict.

    Bytes keys match the bencode decoder used by :mod:`dhtrack.dht`. A missing
    ``interval``, a non-positive ``interval``, or a non-int ``num`` becomes
    ``None``. ``bool`` is not treated as an int.
    """
    body = response.get(b"r", {})
    if not isinstance(body, dict):
        raise ValueError("BEP 51 response r must be a dict")
    samples = body.get(b"samples", b"")
    if not isinstance(samples, bytes):
        raise TypeError("BEP 51 samples must be bytes")
    num = body.get(b"num")
    interval = body.get(b"interval")
    return SampleReply(
        samples=samples,
        num=num if _positive_or_zero_int(num) else None,
        interval=interval if isinstance(interval, int) and not isinstance(interval, bool) and interval > 0 else None,
    )


def _positive_or_zero_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass
class SampleSchedule:
    """Which endpoints are due for ``sample_infohashes``.

    The schedule stores the next allowed time per ``(ip, port)``. It does not
    send queries. The default interval matches the fallback in
    ``DHTPeer._process_sample_infohashes_response`` (3600 seconds) when a peer
    omits ``interval`` or advertises a non-positive one.
    """

    default_interval: float = 3600.0
    _next_at: dict[tuple[str, int], float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.default_interval <= 0:
            raise ValueError("default_interval must be positive")

    def due(self, now: float, endpoints: Sequence[tuple[str, int]]) -> list[tuple[str, int]]:
        """Return endpoints whose next-allowed time is at or before ``now``.

        Duplicate endpoints are collapsed, preserving first-seen order.
        """
        ready: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        for endpoint in endpoints:
            if endpoint in seen:
                continue
            seen.add(endpoint)
            if now >= self._next_at.get(endpoint, 0.0):
                ready.append(endpoint)
        return ready

    def record(self, endpoint: tuple[str, int], *, now: float, interval: float | None) -> None:
        """Push ``endpoint`` out by ``interval`` seconds, or the default."""
        gap = self.default_interval if interval is None or interval <= 0 else float(interval)
        self._next_at[endpoint] = now + gap

    def next_at(self, endpoint: tuple[str, int]) -> float | None:
        """Return the stored next-allowed time, if any."""
        return self._next_at.get(endpoint)

    def to_dict(self) -> dict[str, object]:
        """JSON-ready schedule. Entries are sorted by address then port."""
        entries = [
            {"ip": ip, "port": port, "at": at}
            for (ip, port), at in sorted(self._next_at.items(), key=lambda item: (item[0][0], item[0][1]))
        ]
        return {"default_interval": self.default_interval, "next_at": entries}

    @classmethod
    def from_dict(cls, raw: object) -> SampleSchedule:
        """Rebuild a schedule from :meth:`to_dict` output."""
        if not isinstance(raw, dict):
            raise ValueError("schedule must be an object")
        schedule = cls(default_interval=expect_number(raw.get("default_interval", 3600.0), "default_interval"))
        entries = raw.get("next_at", [])
        if not isinstance(entries, list):
            raise ValueError("schedule.next_at must be a list")
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("schedule entry must be an object")
            ip = expect_str(item.get("ip"), "schedule.ip")
            port = expect_int(item.get("port"), "schedule.port")
            schedule._next_at[(ip, port)] = expect_number(item.get("at"), "schedule.at")
        return schedule


class SampleTransport:
    """Interface implemented by anything that can ask one DHT node for a sample.

    The experimental CLI ships :class:`MapTransport`, which replays a JSON
    file. A future adapter can call ``DHTPeer.sample_infohashes`` and return
    the decoded reply once the node exposes it.
    """

    def sample(self, ip: str, port: int) -> SampleReply | None:
        """Return a reply, or ``None`` when the node did not answer."""
        raise NotImplementedError


@dataclass
class MapTransport(SampleTransport):
    """Replay replies from a ``(ip, port)`` map. Missing keys are misses."""

    replies: dict[tuple[str, int], SampleReply]

    def sample(self, ip: str, port: int) -> SampleReply | None:
        return self.replies.get((ip, port))


@dataclass(frozen=True)
class SampleRoundResult:
    """What one scheduler pass did."""

    queried: int
    answered: int
    missed: int
    observations: int
    unique_in_round: int


def run_sample_round(
    catalog: InfohashCatalog,
    schedule: SampleSchedule,
    endpoints: Sequence[tuple[str, int]],
    transport: SampleTransport,
    *,
    now: float,
) -> SampleRoundResult:
    """Query due endpoints, ingest replies, and push the schedule forward.

    A miss still records the default interval so a dead endpoint is not
    retried on every pass. Times are compared only with each other; use one
    clock for the lifetime of a schedule file.
    """
    due = schedule.due(now, endpoints)
    answered = 0
    missed = 0
    observations = 0
    seen: set[bytes] = set()
    for ip, port in due:
        reply = transport.sample(ip, port)
        if reply is None:
            schedule.record((ip, port), now=now, interval=None)
            missed += 1
            continue
        answered += 1
        interval = reply.interval if reply.interval is not None and reply.interval > 0 else None
        num = reply.num if reply.num is not None and reply.num >= 0 else None
        via = f"{ip}|{port}"
        for info_hash in parse_bep51_samples(reply.samples):
            seen.add(info_hash)
            catalog.ingest(
                InfohashObservation(
                    info_hash=info_hash,
                    observed_at=now,
                    source=SOURCE_BEP51,
                    via=via,
                    num=num,
                    interval=interval,
                )
            )
            observations += 1
        schedule.record((ip, port), now=now, interval=float(interval) if interval is not None else None)
    return SampleRoundResult(
        queried=len(due),
        answered=answered,
        missed=missed,
        observations=observations,
        unique_in_round=len(seen),
    )


@dataclass
class CatalogState:
    """Catalog plus schedule, which is what a headless sampler persists."""

    catalog: InfohashCatalog = field(default_factory=InfohashCatalog)
    schedule: SampleSchedule = field(default_factory=SampleSchedule)

    def to_dict(self) -> dict[str, object]:
        """JSON-ready state. Records are sorted by infohash for stable diffs."""
        rows = sorted(self.catalog.records(), key=lambda row: row.info_hash_hex)
        return {
            "version": CATALOG_VERSION,
            "kind": CATALOG_KIND,
            "max_vias": self.catalog.max_vias,
            "records": [row.to_dict() for row in rows],
            "schedule": self.schedule.to_dict(),
        }

    def save(self, path: Path) -> None:
        """Write this state to ``path``."""
        dump_json(path, self.to_dict())

    @classmethod
    def load(cls, path: Path) -> CatalogState:
        """Load state, or return an empty state when ``path`` does not exist."""
        if not path.exists():
            return cls()
        return cls.from_dict(load_json(path))

    @classmethod
    def from_dict(cls, raw: object) -> CatalogState:
        """Rebuild state from :meth:`to_dict` output."""
        if not isinstance(raw, dict):
            raise ValueError("catalog state must be an object")
        version = raw.get("version")
        if version != CATALOG_VERSION:
            raise ValueError(f"unsupported catalog state version: {version!r}")
        if raw.get("kind") != CATALOG_KIND:
            raise ValueError("catalog state kind mismatch")
        max_vias = expect_int(raw.get("max_vias", 16), "max_vias")
        catalog = InfohashCatalog(max_vias=max_vias)
        records = raw.get("records", [])
        if not isinstance(records, list):
            raise ValueError("records must be a list")
        for item in records:
            row = CatalogRecord.from_dict(item)
            if len(row.vias) > catalog.max_vias:
                row.vias = row.vias[: catalog.max_vias]
            catalog._rows[row.info_hash_hex] = row
        schedule = SampleSchedule.from_dict(raw.get("schedule", {}))
        return cls(catalog=catalog, schedule=schedule)


def endpoint_key(ip: str, port: int) -> str:
    """Stable ``ip|port`` key. The pipe avoids ambiguity with IPv6 colons."""
    return f"{ip}|{port}"


def loads_reply_map(payload: object) -> dict[tuple[str, int], SampleReply]:
    """Parse a JSON object of ``ip|port`` keys into sample replies.

    Each value is ``{"samples_hex": "...", "num": 1, "interval": 60}``.
    ``num`` and ``interval`` are optional.
    """
    if not isinstance(payload, dict):
        raise ValueError("replies must be a JSON object")
    parsed: dict[tuple[str, int], SampleReply] = {}
    for key, value in payload.items():
        ip, port = _split_endpoint_key(expect_str(key, "reply key"))
        if not isinstance(value, dict):
            raise ValueError(f"reply {key} must be an object")
        samples_hex = value.get("samples_hex", "")
        if not isinstance(samples_hex, str):
            raise ValueError(f"reply {key} samples_hex must be a string")
        try:
            samples = bytes.fromhex(samples_hex) if samples_hex else b""
        except ValueError as exc:
            raise ValueError(f"reply {key} samples_hex is not hex") from exc
        num = value.get("num")
        interval = value.get("interval")
        parsed[(ip, port)] = SampleReply(
            samples=samples,
            num=None if num is None else expect_int(num, f"reply {key} num"),
            interval=None if interval is None else expect_int(interval, f"reply {key} interval"),
        )
    return parsed


def _split_endpoint_key(key: str) -> tuple[str, int]:
    if "|" not in key:
        raise ValueError(f"reply key {key!r} must be ip|port")
    ip, _, port_text = key.rpartition("|")
    if not ip:
        raise ValueError(f"reply key {key!r} is missing an address")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"reply key {key!r} has a non-integer port") from exc
    if port < 0 or port > 65535:
        raise ValueError(f"reply key {key!r} port out of range")
    return ip, port


def snapshot_records(catalog: InfohashCatalog) -> str:
    """Serialize the catalog as JSONL text, one aggregate row per line."""
    rows = [json.dumps(row.to_dict(), sort_keys=True, separators=(",", ":")) for row in catalog.records()]
    if not rows:
        return ""
    return "\n".join(rows) + "\n"
