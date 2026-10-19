# Proposal: swarm health watch and alerts

**Status:** experimental prototype in `dhtrack/experimental/swarm_watch.py`.

## Use case

Someone responsible for a release, a public-domain mirror, or a measurement corpus already knows the infohashes they care about. They want a periodic, boring answer: is the swarm still there, are there seeders, and did the peers all show up inside one prefix? The GUI swarm tracker shows the latest peer list for a person sitting in front of it. It does not page anyone when the list goes empty at 03:00.

## What the prototype does

`SwarmWatch.observe` takes a `SwarmObservation`: the 20-byte infohash, a timestamp, the peers seen for it, and an optional tracker scrape (`complete` / `incomplete` / `downloaded`). It returns a `HealthSnapshot` and zero or more `Alert`s.

| Alert | When it fires |
| --- | --- |
| `swarm_empty` (critical) | No DHT peers and the tracker, if any, also reports an empty swarm. |
| `no_dht_peers` (info) | The DHT peer list is empty while the tracker still reports seeders or leechers. |
| `peers_below` (warning) | `0 < peers < min_peers` (default `min_peers` is 1, so this stays quiet unless raised). |
| `seeders_below` (warning) | Tracker `complete`, or else the count of peers flagged `is_seeder`, is under `min_seeders`. Off unless `min_seeders` is set. |
| `prefix_concentration` (warning) | At least 8 peers, and the largest IPv4 /24 or IPv6 /64 holds at least 80% of them. |
| `diversity_collapse` (warning) | At least 8 peers, unique-prefixes / peers is under 0.25, and the prefix alert did not already fire. |
| `peer_spike` (info) | Peer count grew by at least 5× from a previous snapshot that had at least 4 peers. |

`observation_from_swarm` reads a `dhtrack.swarm.Swarm` peer list, including optional `peer_id`, `node_id`, and `is_seeder` keys when a caller has them. `tracker_snapshot_from_scrape` copies a `ScrapeInfo` from the existing BEP 48 client.

Alerts also go to any `AlertSink`. `CallableAlertSink` is the webhook seam: the operator's function can POST the alert. This prototype does not open an HTTP client.

The CLI keeps the previous snapshot so a later cron invocation can still detect a spike:

```bash
python -m dhtrack.experimental watch-observe \
  --infohash <40 hex> \
  --peers peers.json \
  --tracker-complete 12 --tracker-incomplete 3 \
  --min-seeders 1 \
  --state watch_state.json \
  --health health.jsonl \
  --alerts alerts.jsonl \
  --analyze population.json
```

`--analyze` writes the peer-analytics report for the same table. See [peer-analytics.md](peer-analytics.md).

## Fit

`SwarmManager` stays the in-memory registry for the inspector. The watcher does not register swarms, download pieces, or scrape trackers. A GUI timer or a headless loop that already calls `async_get_peers` and `TrackerClient.scrape` would hand those results in. Prefixes come from the same helper the analytics report uses, so "one /24" means the same thing in both places.

State saved by the CLI is the latest snapshot per infohash plus the alert kinds currently firing. A threshold alert is emitted when it starts and stays quiet while the condition lasts, so a cron job does not repeat it every run; `peer_spike` is a one-shot comparison and fires on each crossing. Peers are counted once per `(ip, port)`. Health and alerts append to JSONL, which is the log a dashboard would tail. In-process history is capped at 256 snapshots and 1000 alerts.

## Limitations

- Peer lists are an input. There is no DHT lookup loop here, so "no DHT peers" means "the caller passed an empty list," which is also what a failed lookup looks like. The alert cannot tell those apart.
- Diversity is prefix cardinality, not entropy, AS diversity, or RTT.
- Thresholds are CLI flags on each invocation. The state file does not remember them. A config file is the obvious next step if more than one operator runs this.
- `peer_spike` has no matching collapse alert. Going from many peers to zero is already `swarm_empty` or `peers_below`.
- The watcher is not thread-safe.
