# Proposal: BEP 51 infohash catalog

**Status:** experimental prototype in `dhtrack/experimental/infohash_catalog.py`.

## Use case

Researchers and index builders sample the BitTorrent DHT to learn which infohashes are being announced, how that set changes, and which nodes are willing to return samples. BEP 51 `sample_infohashes` is the purpose-built query. dhtrack can send it. It does not keep the answer, and it does not decide when to ask again.

Callers today have to invoke `DHTNode.sample_infohashes` themselves. That method returns `[]` because the hashes arrive later on the socket and are only logged inside `DHTPeer._process_sample_infohashes_response`. The same method does record the peer's `interval` on `DHTNode._sample_next_at`, but nothing walks that table.

## What the prototype does

- `parse_bep51_samples` / `sample_reply_from_krpc` split a `samples` blob the same way the node does: 20-byte chunks, trailing partial hash dropped, non-positive `interval` ignored.
- `InfohashCatalog` aggregates sightings by infohash: `first_seen`, `last_seen`, `hit_count`, per-source counts, a capped via list, and the newest population estimate (`num`) and interval.
- `SampleSchedule` is the missing poll loop's memory. An endpoint is due when `now` has passed its next-allowed time. A miss is pushed out by the default 3600s, matching the node's fallback, so a dead peer is not retried every pass. Entries whose time has passed are pruned at the start of each round, so the state file only holds endpoints still in their back-off.
- `run_sample_round` asks a `SampleTransport` for each due endpoint and ingests the replies. `MapTransport` replays a JSON file. A live adapter would call `DHTPeer.sample_infohashes` and return the decoded body once the node exposes it.
- `CatalogState` persists the catalog and the schedule as one JSON document. `catalog-round` is the headless entry point.

```bash
python -m dhtrack.experimental catalog-round \
  --endpoints endpoints.json \
  --replies replies.json \
  --state catalog_state.json \
  --snapshot catalog.jsonl \
  --now 1000
```

`endpoints.json` is a list of `{"ip", "port"}`. `replies.json` is a map of `ip|port` (pipe, so IPv6 is unambiguous) to `{samples_hex, num, interval}`. Omit `--replies` and every due endpoint is recorded as a miss.

Passive hints fit the same catalog: `InfohashObservation(..., source="get_peers")` or `"announce_peer"`. `EndpointSwarmIndex` remains the per-endpoint view; this catalog is the per-infohash view.

## Fit

No change to `dht.py`. The intended hook, once a review is ready to touch the node, is one call at the end of `_process_sample_infohashes_response`:

```python
reply = sample_reply_from_krpc(response)
catalog.ingest_bep51(
    reply.samples,
    via=f"{self.endpoint.ip}|{self.endpoint.port}",
    observed_at=time.time(),
    num=reply.num,
    interval=reply.interval,
)
```

The scheduler replaces a hand-rolled `while True: sample_infohashes()` that would ignore BEP 51 intervals.

## Limitations

- The transport in this branch does not open a socket. Wiring it to `DHTNode` is the follow-up, and it has to be thread-safe: the node reads datagrams off a background loop, and the catalog is not locked.
- The snapshot JSONL is the current aggregate, rewritten each round, not an append-only event log. A long crawl wants an event log plus periodic compaction.
- `num` is whatever the remote node claimed. It is not a measurement of the swarm.
- Sampled infohashes are not resolved to metadata. That stays on the existing `resolve` path, on purpose.
- Via lists keep the first `max_vias` distinct endpoints (default 16), not the most recent ones.
