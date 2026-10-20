# Experimental proposals

These notes describe headless workflows dhtrack is close to supporting, and the prototypes on this branch. The prototypes are suggestions. They are not part of the stable API, and they are intentionally separate from the correctness-review changes.

The code lives in [`dhtrack/experimental/`](../../dhtrack/experimental/). The catalog, swarm-watch, and peer-analytics modules do not join the DHT, contact a tracker, or change the GUI. The draft MCP server can bind a UDP port only after `confirm=true`, and it does not dial bootstrap routers unless that call listed them. Run the offline prototypes with:

```bash
python -m dhtrack.experimental --help
```

## Who would use a tool like this

dhtrack already speaks Mainline DHT, tracker scrape/announce, peer wire, and metadata retrieval, and it can show the result in a PyQt6 inspector. The people who outgrow the inspector tend to want the same facts on a schedule:

| Audience | Job they are trying to automate |
| --- | --- |
| Measurement researchers | Sample the DHT over time, keep the infohashes, and describe peer populations without clicking through the GUI. |
| Operators of a release or mirror | Watch a known infohash and hear when seeders disappear or the peer set collapses onto one network. |
| Index / corpus builders | Turn BEP 51 samples and passive `get_peers` / `announce_peer` hints into a durable infohash catalog. Metadata fetch stays a separate, explicit step. |
| Abuse and network-health reviewers | See client mix, address class, prefix/port concentration, and BEP 42 node-ID mismatches for a peer list they already collected. |
| Downstream pipelines | Export JSONL, JSON, and CSV that another process can graph, alert on, or archive. |

## What was prototyped

1. **Infohash discovery catalog** — [`infohash-catalog.md`](infohash-catalog.md). BEP 51 sample scheduling and a durable aggregate of infohashes. `DHTNode.sample_infohashes` sends the query and returns `[]`; the response handler logs the hashes and drops them. This is the store and the poll schedule that handler does not have.
2. **Swarm health watch and alerts** — [`swarm-watch.md`](swarm-watch.md). Score a peer list plus an optional tracker scrape. Emit threshold alerts (empty swarm, seeder floor, prefix concentration, diversity collapse, peer spike) to a callback or a JSONL file.
3. **Peer population analytics** — [`peer-analytics.md`](peer-analytics.md). Address class, BEP 20 client mix, optional caller-supplied geo labels, and a conservative suspicion score from prefix/port concentration and BEP 42 mismatches.
4. **MCP server (draft)** — [`mcp.md`](mcp.md). A hardly-shaped stdio server and matching CLI verbs over the three prototypes above. `guide_`, `session_`, `catalog_`, `swarm_`, and `peer_` read or score local data. `send_` and `node start` return a plan unless `confirm=true`. `write_` refuses to overwrite a file unless `overwrite=true`.

`watch-observe --analyze` runs (2) and (3) on the same peer table so a cron job can archive health, alerts, and a population report together.

## Considered and left for later

- **Live crawler / RTT / churn measurement.** Needs the running node and overlaps the protocol-correctness work. The catalog's `SampleTransport` is the seam where that crawler would plug in.
- **Automatic metadata download of every sampled infohash.** High traffic and a legal question the sampler should not answer by default. The catalog stores 20-byte hashes, not torrent names.
- **GeoIP database in-tree.** No MaxMind (or other) database is shipped. Pass a callable, or a JSON `{"ip": "label"}` file, if you already have a lookup.
- **Webhook, email, or Mongo delivery.** Alerts go to a callable or JSONL. `pymongo` remains an optional extra of the main package and is not coupled here.
- **BEP 36 RSS polling.** The parser exists. A feed watcher does not use the DHT inspector's distinctive capability, so it lost out to the three above.
- **GUI panels for these reports.** The inspector can keep rendering `Swarm` rows. These prototypes consume those rows; they do not add widgets.
