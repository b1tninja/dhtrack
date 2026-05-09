# BEP Compliance Reference

Engineering matrix mapping official BitTorrent Enhancement Proposals to dhtrack's
implementation status. This is a developer reference, not a formal conformance
certificate. Status reflects code present at time of writing; interoperability with
third-party clients has not been systematically verified unless noted.

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ Complete | Feature fully implemented per the spec; all normative "MUST/SHALL" clauses are represented in code. |
| 🟡 Partial | Code exists and covers the core behaviour, but edge cases, optional fields, or end-to-end interop are untested or incomplete. |
| ❌ Missing | No implementation; the spec requirement is absent from the codebase. |
| N/A | The BEP is a process or administrative document with no runnable protocol; not applicable to dhtrack. |

---

## Section A — Final and Active Process BEPs

These BEPs constitute the "Final and Active Process" section of
[bep_0000.rst](https://www.bittorrent.org/beps/bep_0000.html). BEPs 0–2 and 1000
are administrative and have no runtime protocol.

| # | Title | HTML | dhtrack status | Modules | Notes / Gaps |
|---|-------|------|----------------|---------|--------------|
| 0 | Index of BitTorrent Enhancement Proposals | [bep_0000](https://www.bittorrent.org/beps/bep_0000.html) | N/A | — | Admin doc; no runtime protocol. |
| 1 | The BEP Process | [bep_0001](https://www.bittorrent.org/beps/bep_0001.html) | N/A | — | Process doc. |
| 2 | Sample reStructuredText BEP Template | [bep_0002](https://www.bittorrent.org/beps/bep_0002.html) | N/A | — | Template only. |
| 3 | The BitTorrent Protocol Specification | [bep_0003](https://www.bittorrent.org/beps/bep_0003.html) | 🟡 Partial | [`peer.py`](dhtrack/peer.py), [`bep4.py`](dhtrack/bep4.py), [`tracker.py`](dhtrack/tracker.py) | Core peer wire handshake and messages (choke/unchoke/have/bitfield/request/piece/cancel) implemented; HTTP tracker announce now present via `TrackerClient.announce` (compact peers). **Gap:** no piece-pipeline/endgame logic; full upload/download state machine is library-level. |
| 4 | Known Number Allocations | [bep_0004](https://www.bittorrent.org/beps/bep_0004.html) | ✅ Complete | [`bep4.py`](dhtrack/bep4.py) | All assigned reserved-bit positions, core message IDs, Fast Extension IDs, and LTEP flag are centralised here. |
| 20 | Peer ID Conventions | [bep_0020](https://www.bittorrent.org/beps/bep_0020.html) | 🟡 Partial | [`peerid.py`](dhtrack/peerid.py) | Peer ID parser supports many deployed formats; unit tests updated to match parser behavior. **Gap:** some formats still have coarse version parsing and may not match every historical edge-case encoding. |
| 1000 | Pending Standards Track Documents | [bep_1000](https://www.bittorrent.org/beps/bep_1000.html) | N/A | — | Meta-BEP listing future candidates; no protocol. |

---

## Section B — Accepted BEPs

These BEPs are in the "Accepted" section of
[bep_0000.rst](https://www.bittorrent.org/beps/bep_0000.html). Accepted means
the specification is stable and adopted by the community, though the BDFL sign-off
that would make them formally "Final" is still pending.

| # | Title | HTML | dhtrack status | Modules | Notes / Gaps |
|---|-------|------|----------------|---------|--------------|
| 5 | DHT Protocol | [bep_0005](https://www.bittorrent.org/beps/bep_0005.html) | 🟡 Partial | [`dht.py`](dhtrack/dht.py), [`dht_manager.py`](dhtrack/dht_manager.py) | Full KRPC engine: `ping`, `find_node`, `get_peers`, `announce_peer`; K-bucket routing table; iterative lookup; bootstrap with dual-stack (`bootstrap_all`). **Gap:** conformance at edge cases (malformed messages, bucket refresh timers, token expiry) is tested in parts but not exhaustively. |
| 6 | Fast Extension | [bep_0006](https://www.bittorrent.org/beps/bep_0006.html) | 🟡 Partial | [`bep4.py`](dhtrack/bep4.py), [`peer.py`](dhtrack/peer.py) | Message IDs (`HaveAll`, `HaveNone`, `Suggest`, `RejectRequest`, `AllowedFast`) and reserved-bit flag are defined. **Gap:** whether all Fast messages are negotiated and handled end-to-end with real clients is not verified. |
| 9 | Extension for Peers to Send Metadata Files | [bep_0009](https://www.bittorrent.org/beps/bep_0009.html) | 🟡 Partial | [`peer.py`](dhtrack/peer.py), [`extension.py`](dhtrack/extension.py) | `ut_metadata` extension name and block-based metadata exchange are implemented. **Gap:** interoperability matrix testing against mainline/qBittorrent is TBD. |
| 10 | Extension Protocol (LTEP) | [bep_0010](https://www.bittorrent.org/beps/bep_0010.html) | 🟡 Partial | [`peer.py`](dhtrack/peer.py), [`extension.py`](dhtrack/extension.py) | LTEP handshake (`{m: {...}}`) and reserved-bit flag (bit 4 of reserved[5]) are present. Extensions `ut_metadata`, `ut_pex`, `lt_donthave`, and `ut_holepunch` are all registered through this mechanism. **Gap:** full negotiation round-trip with non-dhtrack peers is untested. |
| 11 | Peer Exchange (PEX) | [bep_0011](https://www.bittorrent.org/beps/bep_0011.html) | 🟡 Partial | [`peer.py`](dhtrack/peer.py), [`extension.py`](dhtrack/extension.py) | **`ut_pex` payloads follow BEP 11** compact `added`, `added6`, `dropped`, `dropped6` (+ optional `PEX_SEMANTICS_BEP11` parse flag); inbound **legacy** dict `peers` / `peers.s` layouts are still decoded. **`PEXExtension`** applies both adds (`add_peer`) and drops (`remove_peer`). **Gap:** optional `*.f` flag octets not emitted outbound; outbound pacing (≤ 1 update/min per BEP), under-populated-swarm “recent handshake” heuristic, rate-limit disconnects vs abusive peers — not implemented; interop QA vs mainline TBD. |
| 12 | Multitracker Metadata Extension | [bep_0012](https://www.bittorrent.org/beps/bep_0012.html) | ✅ Complete | [`torrent.py`](dhtrack/torrent.py) | `announce-list`, tier shuffling, and tier promotion on success/failure are fully implemented and tested. |
| 14 | Local Service Discovery (LSD) | [bep_0014](https://www.bittorrent.org/beps/bep_0014.html) | 🟡 Partial | [`lsd.py`](dhtrack/lsd.py) | Dedicated module sends and receives multicast LSD announcements. **Gap:** IPv6 multicast group (`ff15::efc0:988f`) coverage and interaction with BEP 27 private-torrent suppression should be tested. |
| 15 | UDP Tracker Protocol | [bep_0015](https://www.bittorrent.org/beps/bep_0015.html) | 🟡 Partial | [`udp_tracker.py`](dhtrack/udp_tracker.py) | Full UDP announce/scrape client with connect/announce/scrape actions, connection ID caching, and retry logic. Tests in [`tests/test_udp_tracker.py`](tests/test_udp_tracker.py). **Gap:** live-tracker integration test absent; IPv6 UDP endpoint support not confirmed. |
| 19 | HTTP/FTP Seeding (GetRight-style) | [bep_0019](https://www.bittorrent.org/beps/bep_0019.html) | 🟡 Partial | [`webseed.py`](dhtrack/webseed.py) | HTTP/FTP range downloads with SHA-1 piece verification; URL discard on hash mismatch. Multi-URL fallback behavior is unit-tested; live mirror load-balancing/health scoring is still minimal. |
| 23 | Tracker Returns Compact Peer Lists | [bep_0023](https://www.bittorrent.org/beps/bep_0023.html) | 🟡 Partial | [`tracker.py`](dhtrack/tracker.py) | `TrackerClient.announce` sends `GET /announce?compact=1&…` and decodes compact IPv4 (`peers`), compact IPv6 (`peers6`), and legacy dict-list peer formats. Compact decoders are unit-tested in `tests/test_tracker.py`. **Gap:** no live-tracker integration test. |
| 27 | Private Torrents | [bep_0027](https://www.bittorrent.org/beps/bep_0027.html) | 🟡 Partial | [`dht.py`](dhtrack/dht.py), [`lsd.py`](dhtrack/lsd.py), [`peer.py`](dhtrack/peer.py) | DHT private-mode suppression supported; LSD refuses to announce/accept private infohashes; peer connections can suppress `ut_pex` negotiation via `PeerConnection(is_private=True)`. **Gap:** a single high-level “torrent context” still must reliably plumb the private flag into all subsystems in production usage. |
| 29 | uTorrent Transport Protocol (uTP) | [bep_0029](https://www.bittorrent.org/beps/bep_0029.html) | 🟡 Partial | [`utp.py`](dhtrack/utp.py) | Implementation module present with state machine and packet handling. **Gap:** completeness against the full BEP 29 specification (congestion control, selective ACK, edge cases) has not been independently reviewed. |
| 55 | Holepunch Extension | [bep_0055](https://www.bittorrent.org/beps/bep_0055.html) | 🟡 Partial | [`peer.py`](dhtrack/peer.py) | `ut_holepunch` extension name registered; rendezvous and connect messages are handled. **Gap:** end-to-end hole-punch success with NATed peers in production has not been validated. |

---

## Appendix — Draft / Deferred BEPs with Partial Code

The following BEPs are **not** in the Accepted or Final sections of
[bep_0000.rst](https://www.bittorrent.org/beps/bep_0000.html) but have dedicated
code in dhtrack. They are listed here for completeness; their specs are still
subject to change.

| # | Title | HTML | Status in spec | dhtrack status | Modules | Notes |
|---|-------|------|----------------|----------------|---------|-------|
| 31 | Failure Retry Extension | [bep_0031](https://www.bittorrent.org/beps/bep_0031.html) | Draft | ✅ Complete | [`bep31.py`](dhtrack/bep31.py) | `parse_failure_response` handles `retry in` (integer minutes) and `"never"` semantics. |
| 32 | IPv6 Extension for DHT | [bep_0032](https://www.bittorrent.org/beps/bep_0032.html) | Draft | 🟡 Partial | [`bep32.py`](dhtrack/bep32.py), [`dht.py`](dhtrack/dht.py) | `want` parameter parsing, `nodes6` compact encoding, dual-stack bootstrap. **Gap:** cross-DHT routing-table leaking and IPv6-only node coverage need more testing. |
| 33 | DHT Scrape | [bep_0033](https://www.bittorrent.org/beps/bep_0033.html) | Draft | 🟡 Partial | [`dht.py`](dhtrack/dht.py), [`bloom_filter.py`](dhtrack/bloom_filter.py) | `scrape=1` / `noseed=1` flags in `get_peers`; bloom-filter responses (`BFsd`, `BFpe`) for seeds and peers via `announce_peer seed=1`. |
| 42 | DHT Security Extension | [bep_0042](https://www.bittorrent.org/beps/bep_0042.html) | Draft | 🟡 Partial | [`bep42.py`](dhtrack/bep42.py), [`dht.py`](dhtrack/dht.py) | Pure-Python CRC32C implementation; `is_valid_node_id` validated against spec vectors. **Transitional adoption:** inbound node-ID enforcement is **opt-in** via `DHTNode.enforce_bep42` (default `False`). Top-level `ip` echo is included in outgoing responses to help peers infer their external endpoint. **Gap:** outbound node ID is still random (no external-IP driven node ID generation / restart loop). `quic.py` is a separate community prototype, not part of BEP 42. |
| 47 | Padding Files and Extended File Attributes | [bep_0047](https://www.bittorrent.org/beps/bep_0047.html) | Draft | ✅ Complete | [`bep47.py`](dhtrack/bep47.py) | Attribute parsing (`l`, `x`, `h`, `p`), SHA-1 deduplication hints, symlink metadata, and padding-length calculation are all implemented. |
| 48 | Tracker Protocol Extension: Scrape | [bep_0048](https://www.bittorrent.org/beps/bep_0048.html) | Draft | 🟡 Partial | [`tracker.py`](dhtrack/tracker.py) | HTTP scrape URL derivation (`/announce` → `/scrape`), multi-hash scrape requests, response parsing, and HTTP announce support live in the same module. **Gap:** no live-tracker integration tests for scrape/announce. |
| 51 | DHT Infohash Indexing | [bep_0051](https://www.bittorrent.org/beps/bep_0051.html) | Draft | 🟡 Partial | [`dht.py`](dhtrack/dht.py) | `sample_infohashes` query, response handler, and interval scheduler implemented. `DHTNode._sample_next_at` tracks the next permissible re-query time per peer endpoint; `sample_infohashes()` skips queries that arrive before the interval expires. **Gap:** no background periodic scheduling loop — callers must invoke `sample_infohashes()` themselves. |
| 53 | Magnet URI Extension — Select File Indices | [bep_0053](https://www.bittorrent.org/beps/bep_0053.html) | Draft | ✅ Complete | [`bep53.py`](dhtrack/bep53.py) | `so=` parameter parsing (ranges and individual indices), magnet URI construction and decoding. |
| 54 | The lt_donthave Extension | [bep_0054](https://www.bittorrent.org/beps/bep_0054.html) | Draft | ✅ Complete | [`bep54.py`](dhtrack/bep54.py) | `lt_donthave` message encode/decode/create; wire format matches BEP 54 spec. |

---

## Testing and Known Gaps

### Failing / Drifted Tests

- None currently tracked in this document (keep in sync with CI).

### Priority Gaps

1. **HTTP announce client (BEP 3 / BEP 23):** Implemented in `TrackerClient.announce` with compact IPv4 (`peers`) and IPv6 (`peers6`) decoding (`_decode_compact_peers6`). **Remaining gap:** live-tracker integration fixture / wider response-shape fuzzing.
2. **BEP 42 node-ID constraint:** Validation of inbound node IDs is now enforced in `_parse_nodes` / `_parse_ipv6_nodes`. Remaining gap: generate our own outbound node ID from our external IP (requires knowing the external IP at startup).
3. **BEP 51 re-query scheduling:** `sample_infohashes` now records and respects the `interval` field per peer endpoint. Remaining gap: no autonomous periodic scheduling loop (caller must trigger queries).
4. **BEP 27 + BEP 14 cross-enforcement:** Private-torrent flag should suppress LSD and PEX in addition to DHT.

### Suggested Next Validation Steps

- Run an interop harness against a real qBittorrent or Transmission peer to validate BEP 6, 9, 10, 11 end-to-end messaging.
- Add a live-tracker integration test fixture for BEP 15 (UDP announce) and BEP 48 (HTTP scrape).
- Audit `utp.py` against the full BEP 29 state machine, particularly congestion-window and selective-ACK handling.

---

## Maintenance

Update this document when:

- A new module implementing a BEP is added (add a row to the appendix or main table as appropriate).
- A major change is made to [`peer.py`](dhtrack/peer.py), [`dht.py`](dhtrack/dht.py), or [`extension.py`](dhtrack/extension.py).
- A "Missing" item is implemented — promote its status row accordingly.
- A Draft BEP from the appendix is formally Accepted upstream — move it to the main table.

> **Note on local BEP sources:** If the [bittorrent.org](https://github.com/bittorrent/bittorrent.org)
> repository is checked out as a sibling of this repo (i.e. `../bittorrent.org/`), each
> BEP's source RST is available at `../bittorrent.org/beps/bep_XXXX.rst` for offline
> reference.
