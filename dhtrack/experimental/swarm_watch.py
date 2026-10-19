"""Swarm health snapshots and threshold alerts.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
See ``docs/proposals/swarm-watch.md``.

Operators watching a known infohash (a release, a mirror, a measurement
corpus) want a periodic answer to "is this swarm still healthy?": how many
peers, how spread out they are, and whether tracker seeders collapsed.
``Swarm`` already stores the latest peer list for the GUI. This module does
not collect peers. It scores a peer list plus an optional tracker scrape and
emits alerts a headless job can write to a file or hand to a callback.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dhtrack.experimental.peer_analytics import address_prefix
from dhtrack.experimental.persist import dump_json, expect_int, expect_number, expect_str, load_json
from dhtrack.swarm import Swarm
from dhtrack.tracker import ScrapeInfo

WATCH_KIND = "dhtrack.experimental.swarm_watch"
WATCH_VERSION = 1
_HISTORY_LIMIT = 256
_ALERT_LIMIT = 1000
# One-shot comparisons against the previous snapshot. These fire on every
# crossing; every other kind fires only when it starts, not while it lasts.
_EDGE_ALERTS = frozenset({"peer_spike"})


@dataclass(frozen=True)
class PeerSighting:
    """One peer observed for a watched infohash."""

    ip: str
    port: int
    peer_id: bytes | None = None
    node_id: bytes | None = None
    is_seeder: bool | None = None


@dataclass(frozen=True)
class TrackerSnapshot:
    """Seed/leech counters from a tracker scrape or announce."""

    complete: int
    incomplete: int
    downloaded: int | None = None
    tracker: str = ""


@dataclass(frozen=True)
class SwarmObservation:
    """Everything the watcher knows about one infohash at one instant."""

    info_hash: bytes
    observed_at: float
    peers: tuple[PeerSighting, ...] = ()
    tracker: TrackerSnapshot | None = None
    display_name: str | None = None

    def __post_init__(self) -> None:
        if len(self.info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes")


@dataclass(frozen=True)
class WatchThresholds:
    """Alert thresholds. See the design note for how each one fires."""

    min_peers: int = 1
    min_diversity: float = 0.25
    min_peers_for_diversity: int = 8
    max_prefix_share: float = 0.8
    min_seeders: int | None = None
    spike_ratio: float = 5.0
    spike_min_previous: int = 4

    def __post_init__(self) -> None:
        if self.min_peers < 0:
            raise ValueError("min_peers must be >= 0")
        if not 0 <= self.min_diversity <= 1:
            raise ValueError("min_diversity must be between 0 and 1")
        if self.min_peers_for_diversity < 1:
            raise ValueError("min_peers_for_diversity must be >= 1")
        if not 0 < self.max_prefix_share <= 1:
            raise ValueError("max_prefix_share must be in (0, 1]")
        if self.min_seeders is not None and self.min_seeders < 0:
            raise ValueError("min_seeders must be >= 0")
        if self.spike_ratio <= 1:
            raise ValueError("spike_ratio must be > 1")
        if self.spike_min_previous < 1:
            raise ValueError("spike_min_previous must be >= 1")


@dataclass(frozen=True)
class HealthSnapshot:
    """Derived health of one observation."""

    info_hash_hex: str
    observed_at: float
    display_name: str | None
    peer_count: int
    unique_ips: int
    unique_prefixes: int
    prefix_top_share: float
    seeder_count: int | None
    tracker_complete: int | None
    tracker_incomplete: int | None
    tracker_downloaded: int | None
    diversity: float

    def to_dict(self) -> dict[str, object]:
        """JSON-ready copy."""
        return {
            "info_hash_hex": self.info_hash_hex,
            "observed_at": self.observed_at,
            "display_name": self.display_name,
            "peer_count": self.peer_count,
            "unique_ips": self.unique_ips,
            "unique_prefixes": self.unique_prefixes,
            "prefix_top_share": self.prefix_top_share,
            "seeder_count": self.seeder_count,
            "tracker_complete": self.tracker_complete,
            "tracker_incomplete": self.tracker_incomplete,
            "tracker_downloaded": self.tracker_downloaded,
            "diversity": self.diversity,
        }

    @classmethod
    def from_dict(cls, raw: object) -> HealthSnapshot:
        """Rebuild a snapshot from :meth:`to_dict` output."""
        if not isinstance(raw, dict):
            raise ValueError("health snapshot must be an object")
        info_hash_hex = expect_str(raw.get("info_hash_hex"), "info_hash_hex")
        name = raw.get("display_name")
        if name is not None and not isinstance(name, str):
            raise ValueError("display_name must be a string or null")
        return cls(
            info_hash_hex=info_hash_hex,
            observed_at=expect_number(raw.get("observed_at"), "observed_at"),
            display_name=name,
            peer_count=expect_int(raw.get("peer_count"), "peer_count"),
            unique_ips=expect_int(raw.get("unique_ips"), "unique_ips"),
            unique_prefixes=expect_int(raw.get("unique_prefixes"), "unique_prefixes"),
            prefix_top_share=expect_number(raw.get("prefix_top_share"), "prefix_top_share"),
            seeder_count=_optional_int(raw.get("seeder_count"), "seeder_count"),
            tracker_complete=_optional_int(raw.get("tracker_complete"), "tracker_complete"),
            tracker_incomplete=_optional_int(raw.get("tracker_incomplete"), "tracker_incomplete"),
            tracker_downloaded=_optional_int(raw.get("tracker_downloaded"), "tracker_downloaded"),
            diversity=expect_number(raw.get("diversity"), "diversity"),
        )


@dataclass(frozen=True)
class Alert:
    """One threshold crossing."""

    info_hash_hex: str
    observed_at: float
    kind: str
    severity: str
    message: str
    value: float
    threshold: float

    def to_dict(self) -> dict[str, object]:
        """JSON-ready copy."""
        return {
            "info_hash_hex": self.info_hash_hex,
            "observed_at": self.observed_at,
            "kind": self.kind,
            "severity": self.severity,
            "message": self.message,
            "value": self.value,
            "threshold": self.threshold,
        }


class AlertSink:
    """Where alerts go. The default watcher keeps them in memory too."""

    def emit(self, alert: Alert) -> None:
        """Accept one alert."""
        raise NotImplementedError


@dataclass
class CallableAlertSink(AlertSink):
    """Forward each alert to a callable (log line, webhook, queue)."""

    callback: Callable[[Alert], None]

    def emit(self, alert: Alert) -> None:
        self.callback(alert)


def tracker_snapshot_from_scrape(info: ScrapeInfo, *, tracker: str = "") -> TrackerSnapshot:
    """Copy BEP 48 :class:`~dhtrack.tracker.ScrapeInfo` counters."""
    return TrackerSnapshot(
        complete=int(info.complete),
        incomplete=int(info.incomplete),
        downloaded=int(info.downloaded),
        tracker=tracker,
    )


def observation_from_swarm(
    swarm: Swarm,
    *,
    observed_at: float,
    tracker: TrackerSnapshot | None = None,
) -> SwarmObservation:
    """Build an observation from a :class:`~dhtrack.swarm.Swarm` peer list.

    Peer dicts may carry optional ``peer_id`` / ``node_id`` bytes and an
    ``is_seeder`` bool, which the GUI peer rows do not always have. Missing
    keys are left unset.
    """
    peers: list[PeerSighting] = []
    for raw in swarm.swarm_peers:
        peers.append(_sighting_from_mapping(raw))
    return SwarmObservation(
        info_hash=bytes(swarm.info_hash),
        observed_at=observed_at,
        peers=tuple(peers),
        tracker=tracker,
        display_name=swarm.display_name,
    )


def _sighting_from_mapping(raw: Mapping[str, object]) -> PeerSighting:
    ip = raw.get("ip", "")
    port = raw.get("port", 0)
    peer_id = raw.get("peer_id")
    node_id = raw.get("node_id")
    seeder = raw.get("is_seeder")
    return PeerSighting(
        ip=ip if isinstance(ip, str) else str(ip),
        port=int(port) if isinstance(port, int) and not isinstance(port, bool) else 0,
        peer_id=peer_id if isinstance(peer_id, bytes) else None,
        node_id=node_id if isinstance(node_id, bytes) else None,
        is_seeder=seeder if isinstance(seeder, bool) else None,
    )


@dataclass
class SwarmWatch:
    """Score observations and remember the previous snapshot for spike detection.

    A threshold alert is emitted when it starts firing and stays quiet while
    the condition persists, so a cron job does not repeat it every run. The
    set of firing kinds per infohash is saved with the state file.

    Not thread-safe. History and alerts are capped so a long-running process
    does not grow without bound; the JSONL files written by the CLI are the
    durable log.
    """

    thresholds: WatchThresholds = field(default_factory=WatchThresholds)
    sinks: tuple[AlertSink, ...] = ()
    _latest: dict[str, HealthSnapshot] = field(default_factory=dict)
    _history: dict[str, list[HealthSnapshot]] = field(default_factory=dict)
    _alerts: list[Alert] = field(default_factory=list)
    _active: dict[str, set[str]] = field(default_factory=dict)

    def observe(self, observation: SwarmObservation) -> tuple[HealthSnapshot, list[Alert]]:
        """Score ``observation``. Returns the snapshot and the newly started alerts."""
        snapshot = score_observation(observation)
        key = snapshot.info_hash_hex
        firing = self._alerts_for(snapshot, observation)
        previously = self._active.get(key, set())
        alerts = [a for a in firing if a.kind in _EDGE_ALERTS or a.kind not in previously]
        self._active[key] = {a.kind for a in firing if a.kind not in _EDGE_ALERTS}
        self._latest[key] = snapshot
        history = self._history.setdefault(key, [])
        history.append(snapshot)
        if len(history) > _HISTORY_LIMIT:
            del history[: len(history) - _HISTORY_LIMIT]
        self._alerts.extend(alerts)
        if len(self._alerts) > _ALERT_LIMIT:
            del self._alerts[: len(self._alerts) - _ALERT_LIMIT]
        for sink in self.sinks:
            for alert in alerts:
                sink.emit(alert)
        return snapshot, alerts

    def latest(self, info_hash_hex: str) -> HealthSnapshot | None:
        """Most recent snapshot for an infohash."""
        return self._latest.get(info_hash_hex.lower())

    def history(self, info_hash_hex: str) -> list[HealthSnapshot]:
        """Retained snapshots, oldest first."""
        return list(self._history.get(info_hash_hex.lower(), []))

    def alerts(self) -> list[Alert]:
        """Alerts retained in this process, oldest first."""
        return list(self._alerts)

    def _alerts_for(self, snapshot: HealthSnapshot, observation: SwarmObservation) -> list[Alert]:
        alerts: list[Alert] = []
        key = snapshot.info_hash_hex
        tracker_population = 0
        if observation.tracker is not None:
            tracker_population = observation.tracker.complete + observation.tracker.incomplete

        if snapshot.peer_count == 0 and tracker_population == 0:
            alerts.append(
                _alert(
                    snapshot,
                    kind="swarm_empty",
                    severity="critical",
                    message="no peers and no tracker swarm",
                    value=0,
                    threshold=1,
                )
            )
        elif snapshot.peer_count == 0 and tracker_population > 0:
            alerts.append(
                _alert(
                    snapshot,
                    kind="no_dht_peers",
                    severity="info",
                    message="DHT peer list is empty while the tracker reports a swarm",
                    value=0,
                    threshold=float(tracker_population),
                )
            )
        elif snapshot.peer_count < self.thresholds.min_peers:
            alerts.append(
                _alert(
                    snapshot,
                    kind="peers_below",
                    severity="warning",
                    message=f"peer count {snapshot.peer_count} is below {self.thresholds.min_peers}",
                    value=float(snapshot.peer_count),
                    threshold=float(self.thresholds.min_peers),
                )
            )

        seeder_signal = _seeder_signal(snapshot, observation)
        if self.thresholds.min_seeders is not None and seeder_signal is not None:
            if seeder_signal < self.thresholds.min_seeders:
                alerts.append(
                    _alert(
                        snapshot,
                        kind="seeders_below",
                        severity="warning",
                        message=f"seeder count {seeder_signal} is below {self.thresholds.min_seeders}",
                        value=float(seeder_signal),
                        threshold=float(self.thresholds.min_seeders),
                    )
                )

        diverse_enough_sample = snapshot.peer_count >= self.thresholds.min_peers_for_diversity
        prefix_alert = False
        if diverse_enough_sample and snapshot.prefix_top_share >= self.thresholds.max_prefix_share:
            prefix_alert = True
            alerts.append(
                _alert(
                    snapshot,
                    kind="prefix_concentration",
                    severity="warning",
                    message=f"largest address prefix holds {snapshot.prefix_top_share:.0%} of peers",
                    value=snapshot.prefix_top_share,
                    threshold=self.thresholds.max_prefix_share,
                )
            )
        if diverse_enough_sample and not prefix_alert and snapshot.diversity < self.thresholds.min_diversity:
            alerts.append(
                _alert(
                    snapshot,
                    kind="diversity_collapse",
                    severity="warning",
                    message=(f"prefix diversity {snapshot.diversity:.3f} is below {self.thresholds.min_diversity:.3f}"),
                    value=snapshot.diversity,
                    threshold=self.thresholds.min_diversity,
                )
            )

        previous = self._latest.get(key)
        if previous is not None and previous.peer_count >= self.thresholds.spike_min_previous:
            ratio = snapshot.peer_count / previous.peer_count
            if ratio >= self.thresholds.spike_ratio:
                alerts.append(
                    _alert(
                        snapshot,
                        kind="peer_spike",
                        severity="info",
                        message=(f"peer count rose from {previous.peer_count} to {snapshot.peer_count} (x{ratio:.2f})"),
                        value=round(ratio, 4),
                        threshold=self.thresholds.spike_ratio,
                    )
                )
        return alerts

    def to_dict(self) -> dict[str, object]:
        """Persist the latest snapshot and firing alerts per infohash. History stays in JSONL."""
        latest = {key: snap.to_dict() for key, snap in sorted(self._latest.items())}
        active = {key: sorted(kinds) for key, kinds in sorted(self._active.items()) if kinds}
        return {"version": WATCH_VERSION, "kind": WATCH_KIND, "latest": latest, "active_alerts": active}

    def save(self, path: Path) -> None:
        """Write the latest-snapshot state."""
        dump_json(path, self.to_dict())

    def load_latest(self, path: Path) -> None:
        """Restore spike baselines from a state file. Missing file is a no-op."""
        if not path.exists():
            return
        raw = load_json(path)
        if not isinstance(raw, dict):
            raise ValueError("watch state must be an object")
        if raw.get("version") != WATCH_VERSION:
            raise ValueError(f"unsupported watch state version: {raw.get('version')!r}")
        if raw.get("kind") != WATCH_KIND:
            raise ValueError("watch state kind mismatch")
        latest = raw.get("latest", {})
        if not isinstance(latest, dict):
            raise ValueError("watch latest must be an object")
        restored: dict[str, HealthSnapshot] = {}
        for key, value in latest.items():
            snapshot = HealthSnapshot.from_dict(value)
            restored[expect_str(key, "infohash").lower()] = snapshot
        # Older state files have no active_alerts; every alert is then new.
        active_raw = raw.get("active_alerts", {})
        if not isinstance(active_raw, dict):
            raise ValueError("watch active_alerts must be an object")
        active: dict[str, set[str]] = {}
        for key, kinds in active_raw.items():
            if not isinstance(kinds, list):
                raise ValueError("watch active_alerts entries must be lists")
            active[expect_str(key, "infohash").lower()] = {expect_str(k, "alert kind") for k in kinds}
        self._latest = restored
        self._active = active


def score_observation(observation: SwarmObservation) -> HealthSnapshot:
    """Derive health counters from one observation. Does not emit alerts.

    Peers are counted once per ``(ip, port)``; a repeated row (for example
    from merged lookups) does not inflate the counts. A peer is a seeder if
    any of its rows says so.
    """
    unique: dict[tuple[str, int], bool | None] = {}
    for peer in observation.peers:
        endpoint = (peer.ip, peer.port)
        unique[endpoint] = _merge_seeder(unique.get(endpoint), peer.is_seeder)
    prefixes: dict[str, int] = {}
    ips: set[str] = set()
    seeder_known = False
    seeder_count = 0
    for (ip, _port), is_seeder in unique.items():
        ips.add(ip)
        prefix = address_prefix(ip)
        prefixes[prefix] = prefixes.get(prefix, 0) + 1
        if is_seeder is not None:
            seeder_known = True
            if is_seeder:
                seeder_count += 1
    peer_count = len(unique)
    top = max(prefixes.values()) if prefixes else 0
    tracker = observation.tracker
    return HealthSnapshot(
        info_hash_hex=observation.info_hash.hex(),
        observed_at=observation.observed_at,
        display_name=observation.display_name,
        peer_count=peer_count,
        unique_ips=len(ips),
        unique_prefixes=len(prefixes),
        prefix_top_share=_ratio(top, peer_count),
        seeder_count=seeder_count if seeder_known else None,
        tracker_complete=None if tracker is None else tracker.complete,
        tracker_incomplete=None if tracker is None else tracker.incomplete,
        tracker_downloaded=None if tracker is None else tracker.downloaded,
        diversity=_ratio(len(prefixes), peer_count),
    )


def _merge_seeder(a: bool | None, b: bool | None) -> bool | None:
    """Combine two seeder flags: any True wins, then any known value."""
    if a or b:
        return True
    return b if a is None else a


def _ratio(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(part / total, 6)


def _seeder_signal(snapshot: HealthSnapshot, observation: SwarmObservation) -> int | None:
    if observation.tracker is not None:
        return observation.tracker.complete
    return snapshot.seeder_count


def _alert(
    snapshot: HealthSnapshot,
    *,
    kind: str,
    severity: str,
    message: str,
    value: float,
    threshold: float,
) -> Alert:
    return Alert(
        info_hash_hex=snapshot.info_hash_hex,
        observed_at=snapshot.observed_at,
        kind=kind,
        severity=severity,
        message=message,
        value=value,
        threshold=threshold,
    )


def _optional_int(value: object, label: str) -> int | None:
    if value is None:
        return None
    return expect_int(value, label)
