# Proposal: peer population analytics

**Status:** experimental prototype in `dhtrack/experimental/peer_analytics.py`.

## Use case

A swarm inspector collects peers and then a person squints at the table. The questions that come up repeatedly are mechanical:

- Are these global addresses, or RFC 1918 / CGNAT / documentation ranges?
- Which BitTorrent clients (BEP 20 peer IDs) are in the swarm?
- Did one /24 or one port account for most of the sample?
- Do DHT node IDs match the address under BEP 42, which exists specifically to make bulk Sybil IDs harder?
- If the operator already has an ASN or country database, how does the sample bucket?

That is a report, not an enforcement action. Blocking or disconnecting peers is out of scope.

## What the prototype does

`analyze_peers` takes `PeerRecord` rows (`ip`, `port`, optional `peer_id`, optional `node_id`) and returns a `PopulationReport`:

- Address class, computed from explicit ranges so the label does not change when Python's `ipaddress.IPv4Address.is_private` does. Classes: `public`, `private` (RFC 1918 and IPv6 ULA), `shared` (100.64.0.0/10), `loopback`, `link_local`, `multicast`, `documentation` (TEST-NET and 2001:db8::/32), `reserved`, `unspecified`, `invalid`. IPv4-mapped IPv6 is classified as the embedded IPv4 address.
- Prefix is IPv4 /24 or IPv6 /64, with mapped addresses unwrapped so `::ffff:203.0.113.5` and `203.0.113.5` share a prefix.
- Client name and code via the existing `PeerIdParser`.
- BEP 42: `is_valid_node_id` only for addresses the library does not already exempt. Exempt and missing node IDs are "not checked," not "valid." A bad length is `node_id_length`, not a mismatch.
- Descriptive flags `shared_prefix` and `shared_port` when a bucket holds at least 30% of a sample of 6 or more peers, and at least 3 peers.
- Optional `geo(ip) -> label`. Exceptions are counted in `notes` and do not fail the report. The CLI `--geo` flag is a JSON object of labels, for offline enrichment. No GeoIP database is bundled.
- A suspicion score in `[0, 1]`, rounded to 4 decimals.

The score is 0 when there are fewer than 8 peers. Otherwise, independently:

- prefix share above 50% contributes up to 0.45
- port share above 50% contributes up to 0.25
- BEP 42 mismatch rate, if at least 4 node IDs were checked, contributes up to 0.30

A 50/50 prefix split is flagged `shared_prefix` but does not move the score. Flags describe the sample; the score stays quiet until a majority bucket or a real mismatch rate shows up.

```bash
python -m dhtrack.experimental analyze-peers \
  --peers peers.json \
  --geo geo.json \
  --out report.json \
  --csv findings.csv
```

## Fit

The report reuses `dhtrack.bep42` and `dhtrack.peerid` instead of a second node-ID or client table. It does not modify routing, the peer store, or the GUI peer model. `Swarm.swarm_peers` dicts can be mapped into `PeerRecord` the same way `observation_from_swarm` maps them into sightings. `watch-observe --analyze` does that mapping for the JSON peer table.

## Limitations

- This is not a Sybil detector. One household NAT, a university /24, or a VPN exit will light up prefix concentration. The note list says which term fired so a reviewer can throw the score out.
- BEP 42 exemption follows `is_address_exempt_from_bep42` (loopback, link-local, RFC 1918, ULA). Public IPv6 is checked, and IPv4-mapped addresses are checked against the IPv4 rule. CGNAT and documentation ranges are checked, because the library checks them. A full bogon list is not included.
- No RTT, clock skew, infohash-distance, or routing-table anomaly features. Those need the live node.
- Client labels are only as good as `PeerIdParser`, and peer IDs are optional on a DHT peer list (they show up on the wire handshake, not in compact peer lists).
- Geo labels are only as good as the callable the operator passes in.
