"""Tests for the experimental swarm health watcher."""

from __future__ import annotations

import pytest

from dhtrack.experimental.swarm_watch import (
    CallableAlertSink,
    PeerSighting,
    SwarmObservation,
    SwarmWatch,
    TrackerSnapshot,
    WatchThresholds,
    observation_from_swarm,
    tracker_snapshot_from_scrape,
)
from dhtrack.swarm import Swarm
from dhtrack.tracker import ScrapeInfo

INFOHASH = b"\x22" * 20


def _observation(
    peers: tuple[PeerSighting, ...],
    *,
    observed_at: float = 1.0,
    tracker: TrackerSnapshot | None = None,
) -> SwarmObservation:
    return SwarmObservation(info_hash=INFOHASH, observed_at=observed_at, peers=peers, tracker=tracker)


def _spread(count: int, *, octet: int = 1) -> tuple[PeerSighting, ...]:
    return tuple(PeerSighting(ip=f"{octet}.{index}.0.1", port=1000 + index) for index in range(1, count + 1))


def test_empty_swarm_is_critical_and_tracker_only_is_info() -> None:
    watch = SwarmWatch()
    _, empty = watch.observe(_observation(()))
    assert [alert.kind for alert in empty] == ["swarm_empty"]
    assert empty[0].severity == "critical"

    _, dht_miss = watch.observe(_observation((), observed_at=2.0, tracker=TrackerSnapshot(complete=4, incomplete=1)))
    assert [alert.kind for alert in dht_miss] == ["no_dht_peers"]


def test_peer_and_seeder_floors() -> None:
    watch = SwarmWatch(thresholds=WatchThresholds(min_peers=5, min_seeders=1))
    peers = tuple(PeerSighting(ip=f"198.51.100.{index}", port=index, is_seeder=False) for index in range(1, 4))
    _, alerts = watch.observe(_observation(peers, tracker=TrackerSnapshot(complete=0, incomplete=3)))
    assert [alert.kind for alert in alerts] == ["peers_below", "seeders_below"]


def test_prefix_concentration_suppresses_duplicate_diversity_alert() -> None:
    peers = tuple(PeerSighting(ip=f"203.0.113.{index}", port=2000 + index) for index in range(1, 9))
    _, alerts = SwarmWatch().observe(_observation(peers))
    kinds = [alert.kind for alert in alerts]
    assert kinds == ["prefix_concentration"]


def test_diversity_collapse_when_prefixes_are_spread_but_few() -> None:
    peers = (
        tuple(PeerSighting(ip=f"203.0.113.{index}", port=3000 + index) for index in range(1, 7))
        + tuple(PeerSighting(ip=f"198.51.100.{index}", port=4000 + index) for index in range(1, 6))
        + tuple(PeerSighting(ip=f"192.0.2.{index}", port=5000 + index) for index in range(1, 6))
    )
    snapshot, alerts = SwarmWatch().observe(_observation(peers))
    assert snapshot.peer_count == 16
    assert snapshot.unique_prefixes == 3
    assert snapshot.diversity == 0.1875
    assert snapshot.prefix_top_share == 0.375
    assert [alert.kind for alert in alerts] == ["diversity_collapse"]


def test_healthy_sample_is_quiet() -> None:
    snapshot, alerts = SwarmWatch().observe(_observation(_spread(8)))
    assert snapshot.diversity == 1.0
    assert alerts == []


def test_spike_uses_persisted_baseline(tmp_path) -> None:
    watch = SwarmWatch()
    watch.observe(_observation(_spread(4), observed_at=1.0))
    path = tmp_path / "watch.json"
    watch.save(path)

    restored = SwarmWatch()
    restored.load_latest(path)
    _, spiked = restored.observe(_observation(_spread(20), observed_at=2.0))
    assert [alert.kind for alert in spiked] == ["peer_spike"]
    assert spiked[0].value == 5.0

    small = SwarmWatch()
    small.observe(_observation(_spread(3), observed_at=1.0))
    _, quiet = small.observe(_observation(_spread(20), observed_at=2.0))
    assert "peer_spike" not in [alert.kind for alert in quiet]


def test_callback_sink_sees_alerts() -> None:
    seen: list[str] = []
    watch = SwarmWatch(sinks=(CallableAlertSink(lambda alert: seen.append(alert.kind)),))
    watch.observe(_observation(()))
    assert seen == ["swarm_empty"]


def test_observation_from_swarm_and_scrape() -> None:
    swarm = Swarm(info_hash=INFOHASH, display_name="demo")
    swarm.update_swarm_peers(
        [{"ip": "1.1.1.1", "port": 6881, "is_seeder": True, "peer_id": b"\x00" * 20, "note": "ignored"}]
    )
    observation = observation_from_swarm(
        swarm,
        observed_at=9.0,
        tracker=tracker_snapshot_from_scrape(ScrapeInfo(complete=2, incomplete=3, downloaded=4), tracker="http://t"),
    )
    assert observation.display_name == "demo"
    assert observation.peers[0].is_seeder is True
    assert observation.peers[0].peer_id == b"\x00" * 20
    assert observation.tracker is not None
    assert observation.tracker.complete == 2
    assert observation.tracker.tracker == "http://t"
    snapshot, alerts = SwarmWatch().observe(observation)
    assert snapshot.tracker_complete == 2
    assert snapshot.seeder_count == 1
    assert alerts == []


def test_thresholds_reject_inverted_spike_ratio() -> None:
    with pytest.raises(ValueError):
        WatchThresholds(spike_ratio=1.0)


def test_duplicate_rows_count_once() -> None:
    peers = tuple(PeerSighting(ip="1.2.3.4", port=1) for _ in range(10))
    snapshot, alerts = SwarmWatch().observe(_observation(peers))
    assert snapshot.peer_count == 1
    assert "prefix_concentration" not in [alert.kind for alert in alerts]


def test_persisting_alert_fires_once_across_restarts(tmp_path) -> None:
    state = tmp_path / "watch.json"
    watch = SwarmWatch()
    _, first = watch.observe(_observation((), observed_at=1.0))
    assert [alert.kind for alert in first] == ["swarm_empty"]
    _, again = watch.observe(_observation((), observed_at=2.0))
    assert again == []
    watch.save(state)
    restored = SwarmWatch()
    restored.load_latest(state)
    _, after_restart = restored.observe(_observation((), observed_at=3.0))
    assert after_restart == []
    restored.observe(_observation(_spread(8), observed_at=4.0))
    _, relapse = restored.observe(_observation((), observed_at=5.0))
    assert [alert.kind for alert in relapse] == ["swarm_empty"]
