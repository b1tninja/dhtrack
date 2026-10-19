"""Tests for the experimental BEP 51 infohash catalog."""

from __future__ import annotations

import pytest

from dhtrack.experimental.infohash_catalog import (
    CatalogState,
    InfohashCatalog,
    InfohashObservation,
    MapTransport,
    SampleReply,
    loads_reply_map,
    parse_bep51_samples,
    run_sample_round,
    sample_reply_from_krpc,
)


def test_parse_bep51_samples_drops_partial_tail() -> None:
    blob = bytes(range(20)) + b"\x01\x02"
    assert parse_bep51_samples(blob) == [bytes(range(20))]
    assert parse_bep51_samples(b"") == []


def test_parse_bep51_samples_rejects_text() -> None:
    with pytest.raises(TypeError):
        parse_bep51_samples("abcd")  # type: ignore[arg-type]


def test_catalog_aggregates_out_of_order_sightings() -> None:
    catalog = InfohashCatalog(max_vias=1)
    info_hash = b"\x11" * 20
    catalog.ingest(InfohashObservation(info_hash, 10.0, "bep51", via="a|1", num=3, interval=60))
    catalog.ingest(InfohashObservation(info_hash, 5.0, "get_peers", via="b|2"))
    catalog.ingest(InfohashObservation(info_hash, 12.0, "bep51", via="c|3", num=9))
    row = catalog.get(info_hash.hex())
    assert row is not None
    assert row.hit_count == 3
    assert row.first_seen == 5.0
    assert row.last_seen == 12.0
    assert row.vias == ["a|1"]
    assert row.sources == {"bep51": 2, "get_peers": 1}
    assert row.last_num == 9
    assert row.last_interval == 60


def test_sample_reply_from_krpc_matches_node_rules() -> None:
    samples = b"\x00" * 20 + b"\xff"
    reply = sample_reply_from_krpc({b"r": {b"samples": samples, b"num": 4, b"interval": 0}})
    assert reply.num == 4
    assert reply.interval is None
    assert parse_bep51_samples(reply.samples) == [b"\x00" * 20]
    ignored = sample_reply_from_krpc({b"r": {b"samples": b"", b"num": True, b"interval": True}})
    assert ignored.num is None
    assert ignored.interval is None


def test_round_honors_interval_and_roundtrips(tmp_path) -> None:
    info_hash = bytes.fromhex("ab" * 20)
    replies = {("192.0.2.1", 6881): SampleReply(samples=info_hash + info_hash, num=2, interval=30)}
    state = CatalogState()
    endpoints = [("192.0.2.1", 6881), ("192.0.2.1", 6881), ("192.0.2.2", 6881)]
    result = run_sample_round(state.catalog, state.schedule, endpoints, MapTransport(replies), now=1000.0)
    assert result.queried == 2
    assert result.answered == 1
    assert result.missed == 1
    assert result.observations == 2
    assert result.unique_in_round == 1
    row = state.catalog.get(info_hash.hex())
    assert row is not None
    assert row.hit_count == 2
    assert row.vias == ["192.0.2.1|6881"]
    assert state.schedule.next_at(("192.0.2.1", 6881)) == 1030.0
    assert state.schedule.next_at(("192.0.2.2", 6881)) == 4600.0

    path = tmp_path / "state.json"
    state.save(path)
    loaded = CatalogState.load(path)
    stalled = run_sample_round(
        loaded.catalog,
        loaded.schedule,
        endpoints,
        MapTransport(replies),
        now=1010.0,
    )
    assert stalled.queried == 0
    stalled_row = loaded.catalog.get(info_hash.hex())
    assert stalled_row is not None
    assert stalled_row.hit_count == 2
    resumed = run_sample_round(
        loaded.catalog,
        loaded.schedule,
        [("192.0.2.1", 6881)],
        MapTransport(replies),
        now=1030.0,
    )
    assert resumed.answered == 1
    resumed_row = loaded.catalog.get(info_hash.hex())
    assert resumed_row is not None
    assert resumed_row.hit_count == 4


def test_missing_state_file_starts_empty(tmp_path) -> None:
    state = CatalogState.load(tmp_path / "missing.json")
    assert len(state.catalog) == 0
    assert state.schedule.due(0.0, [("192.0.2.1", 1)]) == [("192.0.2.1", 1)]


def test_reply_map_accepts_ipv6_keys() -> None:
    parsed = loads_reply_map({"2001:db8::1|6881": {"samples_hex": "", "interval": 15}})
    assert parsed[("2001:db8::1", 6881)].interval == 15


def test_corrupt_catalog_version_is_rejected(tmp_path) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"version": 99, "kind": "dhtrack.experimental.infohash_catalog"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="version"):
        CatalogState.load(path)


def test_schedule_drops_expired_endpoints() -> None:
    state = CatalogState()
    replies = {("192.0.2.1", 6881): SampleReply(samples=b"\x01" * 20, interval=60)}
    run_sample_round(state.catalog, state.schedule, [("192.0.2.1", 6881)], MapTransport(replies), now=0.0)
    assert state.schedule.next_at(("192.0.2.1", 6881)) == 60.0
    run_sample_round(state.catalog, state.schedule, [("192.0.2.2", 6881)], MapTransport({}), now=100.0)
    assert state.schedule.next_at(("192.0.2.1", 6881)) is None
    assert state.schedule.next_at(("192.0.2.2", 6881)) is not None
