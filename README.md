<p align="center">
  <img src="dhtrack/gui/resources/app_icon.png" width="160" height="160" alt="dhtrack logo" />
</p>

# dhtrack

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/dhtrack.svg)](https://pypi.org/project/dhtrack/)

A modern **DHT swarm inspector** and **BitTorrent client library**. Run a Kademlia DHT node, discover peers, resolve magnet links and metadata, scrape trackers, and explore swarms—from a CLI or from the **PyQt6 expert GUI** (branding assets live under [`dhtrack/gui/resources/`](dhtrack/gui/resources/): [`app_icon.svg`](dhtrack/gui/resources/app_icon.svg), PNG, and ICO). The core package uses the **Python standard library only**; GUI and other tooling are **optional extras**—see [Installation](#installation) below.

## Features

- **DHT node** — KRPC (`ping`, `find_node`, `get_peers`, `announce_peer`, `sample_infohashes`; BEP 51 sampling obeys per-peer intervals but **has no autonomous poll loop—callers invoke** `sample_infohashes`), IPv4/v6 routing tables, dual-stack bootstrap, optional [BEP 42](https://bittorrent.org/beps/bep_0042.html) inbound node-ID validation (`DHTNode.enforce_bep42`, default off), [BEP 33](https://bittorrent.org/beps/bep_0033.html) scrape flags / bloom scaffolding
- **Peer discovery & metadata** — Iterative `get_peers` lookups, metadata over [`ut_metadata`](https://www.bittorrent.org/beps/bep_0009.html), magnet hints including `xt=` plus address bootstrapping via `pe=` ([`dhtrack/bep53.py`](dhtrack/bep53.py); consumed by CLI `resolve`)
- **Swarm & torrent library** — `SwarmManager` / `TorrentManager` registries, on-disk torrent library + piece resume helpers (see [`dhtrack/MANAGERS.md`](dhtrack/MANAGERS.md))
- **Trackers** — HTTP scrape (`TrackerClient.scrape`, [BEP 48](https://bittorrent.org/beps/bep_0048.html)), HTTP announce with compact IPv4 and `peers6` blobs ([BEP 23](https://bittorrent.org/beps/bep_0023.html)), UDP tracker client ([BEP 15](https://bittorrent.org/beps/bep_0015.html))
- **Wire & extensions** — Peer wire messaging, LTEP / `ut_metadata` / PEX / `ut_holepunch`, Fast Extension message IDs and reserved-bit negotiation, [`lt_donthave`](https://www.bittorrent.org/beps/bep_0054.html), multitracker lists ([BEP 12](https://bittorrent.org/beps/bep_0012.html))
- **Transfers & discovery** — Piece download/storage (`downloader.py`, `storage.py`, `piece_selector.py` for gap-oriented webseed selection), LAN Service Discovery (`lsd.py`, `LSDManager`), HTTP/FTP web seeds ([BEP 19](https://bittorrent.org/beps/bep_0019.html)), uTP skeleton ([BEP 29](https://bittorrent.org/beps/bep_0029.html)—**partial**, not audited for production congestion/interop)
- **RSS feeds** — [BEP 36](https://www.bittorrent.org/beps/bep_0036.html) Torrent RSS [`bep_0036.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0036.rst): parsing helpers ([`rss_feed.py`](dhtrack/rss_feed.py))
- **QUIC-framed DHT (experimental)** — Optional QUIC packet framing / listener path ([`quic.py`](dhtrack/quic.py)); community-facing experiment, distinct from polished UDP DHT (`protocol.md` calls this out separately from core BEP 42 conformance)
- **GUI & CLI** — Sidebar workspace: **Overview** (Metrics + BEP monitor sub-tabs), Routing table, Peer store, kRPC console, Peer scope, Traffic monitor, Swarm tracker, Torrent manager, Swarm inspector ([`gui/main.py`](dhtrack/gui/main.py)); **Preferences** dialog tabs — DHT, Routing, Peer Store, Bootstrap, Metadata, Peer Wire, Trackers, LSD/WebSeed, Persistence, Advanced, Logging

## Implementation status & BEP specs

For clause-level gaps and maintenance notes, see [`protocol.md`](protocol.md). Each numbered proposal’s **source RST** is [`beps/bep_XXXX.rst`](https://github.com/bittorrent/bittorrent.org/tree/master/beps) in the upstream [BitTorrent enhancement proposals repo](https://github.com/bittorrent/bittorrent.org) (rendered HTML: `https://www.bittorrent.org/beps/bep_XXXX.html`). With a sibling checkout, read `../bittorrent.org/beps/bep_XXXX.rst` locally.

Legend (same symbols as **`protocol.md`**): ✅ complete · 🟡 partial · ❌ missing · — process-only / no runtime protocol.

### Implementation status by proposal

Each RST link opens the authoritative proposal text (`master` branch on GitHub). **Modules** paths are rooted at [`dhtrack/`](dhtrack/).

| BEP | Subject | RST source | Status | Modules / notes |
|-----|---------|------------|--------|----------------|
| [**3**](https://www.bittorrent.org/beps/bep_0003.html) | BitTorrent wire protocol (.torrent meta + wire) | [`bep_0003.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0003.rst) | 🟡 | [`bencode.py`](dhtrack/bencode.py), [`peer.py`](dhtrack/peer.py), [`bep4.py`](dhtrack/bep4.py), [`tracker.py`](dhtrack/tracker.py) · no full pipeline / endgame / seeding SM |
| [**4**](https://www.bittorrent.org/beps/bep_0004.html) | Known number allocations | [`bep_0004.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0004.rst) | ✅ | [`bep4.py`](dhtrack/bep4.py) · reserved bits / message IDs / LTEP handshake flag |
| [**5**](https://www.bittorrent.org/beps/bep_0005.html) | DHT (KRPC) | [`bep_0005.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0005.rst) | 🟡 | [`dht.py`](dhtrack/dht.py), [`krpc.py`](dhtrack/krpc.py), [`routing.py`](dhtrack/routing.py), [`node.py`](dhtrack/node.py), [`dht_manager.py`](dhtrack/dht_manager.py) · edge-case / timer coverage see `protocol.md` |
| [**6**](https://www.bittorrent.org/beps/bep_0006.html) | Fast Extension | [`bep_0006.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0006.rst) | 🟡 | [`bep4.py`](dhtrack/bep4.py), [`peer.py`](dhtrack/peer.py) |
| [**9**](https://www.bittorrent.org/beps/bep_0009.html) | Peer metadata (`ut_metadata`) | [`bep_0009.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0009.rst) | 🟡 | [`peer.py`](dhtrack/peer.py), [`extension.py`](dhtrack/extension.py), [`metadata_retriever.py`](dhtrack/metadata_retriever.py) |
| [**10**](https://www.bittorrent.org/beps/bep_0010.html) | LTEP | [`bep_0010.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0010.rst) | 🟡 | [`peer.py`](dhtrack/peer.py), [`extension.py`](dhtrack/extension.py) |
| [**11**](https://www.bittorrent.org/beps/bep_0011.html) | PEX | [`bep_0011.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0011.rst) | 🟡 | [`peer.py`](dhtrack/peer.py) |
| [**12**](https://www.bittorrent.org/beps/bep_0012.html) | Multitracker | [`bep_0012.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0012.rst) | ✅ | [`torrent.py`](dhtrack/torrent.py) |
| [**14**](https://www.bittorrent.org/beps/bep_0014.html) | LSD | [`bep_0014.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0014.rst) | 🟡 | [`lsd.py`](dhtrack/lsd.py) · IPv6 / private interplay in `protocol.md` |
| [**15**](https://www.bittorrent.org/beps/bep_0015.html) | UDP tracker | [`bep_0015.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0015.rst) | 🟡 | [`udp_tracker.py`](dhtrack/udp_tracker.py) |
| [**19**](https://www.bittorrent.org/beps/bep_0019.html) | HTTP/FTP seeds (web seeds) | [`bep_0019.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0019.rst) | 🟡 | [`webseed.py`](dhtrack/webseed.py), [`piece_selector.py`](dhtrack/piece_selector.py) |
| [**20**](https://www.bittorrent.org/beps/bep_0020.html) | Peer ID conventions | [`bep_0020.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0020.rst) | 🟡 | [`peerid.py`](dhtrack/peerid.py) |
| [**23**](https://www.bittorrent.org/beps/bep_0023.html) | Tracker compact peers / `peers6` | [`bep_0023.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0023.rst) | 🟡 | [`tracker.py`](dhtrack/tracker.py) |
| [**27**](https://www.bittorrent.org/beps/bep_0027.html) | Private torrents | [`bep_0027.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0027.rst) | 🟡 | [`dht.py`](dhtrack/dht.py), [`lsd.py`](dhtrack/lsd.py), [`peer.py`](dhtrack/peer.py) |
| [**29**](https://www.bittorrent.org/beps/bep_0029.html) | uTP | [`bep_0029.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0029.rst) | 🟡 | [`utp.py`](dhtrack/utp.py) · research-grade; audit before production |
| [**31**](https://www.bittorrent.org/beps/bep_0031.html) | Failure Retry (Draft) | [`bep_0031.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0031.rst) | ✅ | [`bep31.py`](dhtrack/bep31.py) |
| [**32**](https://www.bittorrent.org/beps/bep_0032.html) | DHT IPv6 (Draft) | [`bep_0032.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0032.rst) | 🟡 | [`bep32.py`](dhtrack/bep32.py), [`dht.py`](dhtrack/dht.py), [`dht_address.py`](dhtrack/dht_address.py) |
| [**33**](https://www.bittorrent.org/beps/bep_0033.html) | DHT scrape (Draft) | [`bep_0033.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0033.rst) | 🟡 | [`dht.py`](dhtrack/dht.py), [`bloom_filter.py`](dhtrack/bloom_filter.py) |
| [**36**](https://www.bittorrent.org/beps/bep_0036.html) | Torrent RSS (Draft) | [`bep_0036.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0036.rst) | 🟡 | [`rss_feed.py`](dhtrack/rss_feed.py) · not yet mirrored as a row in `protocol.md` |
| [**42**](https://www.bittorrent.org/beps/bep_0042.html) | DHT security (Draft) | [`bep_0042.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0042.rst) | 🟡 | [`bep42.py`](dhtrack/bep42.py), [`dht.py`](dhtrack/dht.py) · inbound ID check opt-in; outbound ID still random |
| [**47**](https://www.bittorrent.org/beps/bep_0047.html) | Padding files (Draft) | [`bep_0047.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0047.rst) | ✅ | [`bep47.py`](dhtrack/bep47.py) |
| [**48**](https://www.bittorrent.org/beps/bep_0048.html) | HTTP scrape (Draft) | [`bep_0048.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0048.rst) | 🟡 | [`tracker.py`](dhtrack/tracker.py) |
| [**51**](https://www.bittorrent.org/beps/bep_0051.html) | DHT `sample_infohashes` (Draft) | [`bep_0051.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0051.rst) | 🟡 | [`dht.py`](dhtrack/dht.py), [`krpc.py`](dhtrack/krpc.py) · interval respected; **no** autonomous poll loop |
| [**53**](https://www.bittorrent.org/beps/bep_0053.html) | Magnet extension (Draft) | [`bep_0053.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0053.rst) | ✅ | [`bep53.py`](dhtrack/bep53.py), consumed by [`cli.py`](dhtrack/cli.py) (`resolve`) |
| [**54**](https://www.bittorrent.org/beps/bep_0054.html) | `lt_donthave` (Draft) | [`bep_0054.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0054.rst) | ✅ | [`bep54.py`](dhtrack/bep54.py), wired via LTEP / [`peer.py`](dhtrack/peer.py) |
| [**55**](https://www.bittorrent.org/beps/bep_0055.html) | Holepunch | [`bep_0055.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0055.rst) | 🟡 | [`peer.py`](dhtrack/peer.py) (`ut_holepunch`) |

**Process-only (no runtime protocol in this codebase):** [**0**](https://www.bittorrent.org/beps/bep_0000.html) [`bep_0000.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0000.rst), [**1**](https://www.bittorrent.org/beps/bep_0001.html) [`bep_0001.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0001.rst), [**2**](https://www.bittorrent.org/beps/bep_0002.html) [`bep_0002.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0002.rst), [**1000**](https://www.bittorrent.org/beps/bep_1000.html) [`bep_1000.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_1000.rst).

**Experimental (not mapped to table rows above):** QUIC-framed DHT path — [`quic.py`](dhtrack/quic.py) (see **`protocol.md`** for scope vs UDP DHT).

### Operational maturity (by concern)

Cross-cutting readiness (orthogonal to numbering); details stay in **`protocol.md`**.

| Area | Maturity |
|------|----------|
| DHT routing, iterative lookup, persisted peers, GUI inspection | Stable in-tree; edge-case / interop fuzzing ongoing |
| Magnet / metadata ([`dht_manager.py`](dhtrack/dht_manager.py), [`metadata_retriever.py`](dhtrack/metadata_retriever.py), CLI `resolve`) | Used by CLI/GUI swarms; [BEP 9](https://www.bittorrent.org/beps/bep_0009.html) interop vs every mainstream client not matrix-tested |
| HTTP + UDP trackers, compact `peers` / `peers6` on announce | Implemented; automation focuses on parsers—**live** public-tracker harness still a gap |
| Peer wire LTEP extensions (metadata, PEX, hole punch, dont‑have) | Message-level paths complete; NAT hole punch and negotiation not production-validated |
| BitTorrent upload / seeding state machine / endgame | **Not** a full client—inspector + download-focused paths |
| uTP ([`utp.py`](dhtrack/utp.py)) | Partial—treat as research until independently reviewed |
| QUIC DHT framing ([`quic.py`](dhtrack/quic.py)) | Experimental ancillary path |

## Installation

### Prerequisites

- **Python 3.10+** (see [`pyproject.toml`](pyproject.toml) `requires-python`).
- A **virtual environment** is recommended so GUI and test stacks stay isolated from your system interpreter:

  ```bash
  python -m venv .venv
  # Linux / macOS:
  source .venv/bin/activate
  # Windows (cmd):  .venv\Scripts\activate.bat
  # Windows (PowerShell):  .venv\Scripts\Activate.ps1
  ```

### From PyPI

The published wheel declares **no mandatory third-party dependencies**; everything else is an **optional extra** from [`pyproject.toml`](pyproject.toml).

| Extra | Purpose | Pulls in (summary) |
|-------|---------|----------------------|
| `gui` | PyQt6 **DHT expert inspector** | `PyQt6>=6.6` |
| `test` | Running the test suite | `pytest`, `pytest-cov` |
| `mongo` | Optional persistence integration | `pymongo` |
| `dev` | Linting, formatting, pre-commit, **regenerating GUI icons** from SVG | `ruff`, `black`, `isort`, `pre-commit`, `pillow`, `resvg-py` |

Typical installs:

```bash
pip install -U pip
pip install dhtrack              # library + CLI only (stdlib)
pip install "dhtrack[gui]"       # add the GUI
pip install "dhtrack[test]"      # add pytest + pytest-cov
pip install "dhtrack[mongo]"     # optional Mongo helpers
pip install "dhtrack[dev]"       # contributors: linters + icon tooling
```

Combine extras in one command when you need several at once:

```bash
pip install "dhtrack[gui,test]"
```

[`requirements.txt`](requirements.txt) mirrors common pins (PyQt6, pytest, linters) for quick copy-paste **without** extras syntax.

### From source (editable)

```bash
git clone https://github.com/dhtrack/dhtrack.git
cd dhtrack
python -m venv .venv
source .venv/bin/activate            # or Windows: .venv\Scripts\Activate.ps1
pip install -U pip
pip install -e ".[gui,dev,test]"   # GUI + tests + dev tooling (adjust extras as needed)
```

Minimal editable install (library/CLI only):

```bash
pip install -e .
```

To refresh **PNG** and **ICO** raster exports after editing [`app_icon.svg`](dhtrack/gui/resources/app_icon.svg), install the `dev` extra and run:

```bash
python tools/render_gui_icons.py
```

### Testing

Default pytest options are set in [`pyproject.toml`](pyproject.toml) (`-ra -v`). With the `test` extra (or `pip install pytest pytest-cov`):

```bash
python -m pytest
python -m pytest tests/test_dht.py
python -m pytest -m "not slow"
pytest --cov=dhtrack --cov-report=html
```

### Runtime notes

- **GUI:** requires the `gui` extra (or an environment where `PyQt6` is installed). Entry points are listed under [GUI](#gui) below.
- **Tests:** require `pytest` (and optionally `pytest-cov` for coverage reports).

## Quick start

Console entrypoint (see `[project.scripts]` in `pyproject.toml`):

```bash
dhtrack --help
```

Or via the module:

```bash
python -m dhtrack dht
python -m dhtrack -v dht              # debug logging
python -m dhtrack --debug dht          # same as -v

# Resolve by 40-char hex *or* magnet:?… URI (BEP 53 pe= hints respected)
python -m dhtrack resolve "magnet:?xt=urn:btih:<hex>&dn=Example" --timeout 120

python -m dhtrack scrape https://tracker.example.com/announce <infohash_hex>
```

### Subcommands

| Command | Description |
|---------|-------------|
| `dht` | Run a DHT node (default when no subcommand is given) |
| `resolve` | Discover peers and fetch torrent metadata for an infohash or magnet URI |
| `scrape` | Query a tracker scrape URL for swarm counters ([BEP 48](https://bittorrent.org/beps/bep_0048.html)) |

### GUI

Install the **`gui`** extra (`pip install "dhtrack[gui]"` or include `gui` in your editable install). Then launch with any of:

```bash
python -m dhtrack.gui
dhtrack-gui        # console entry point — terminal stays attached (debugging)
dhtrack-inspector  # GUI entry point — no extra console window on Windows
```

`dhtrack-gui` is declared under `[project.scripts]` and `dhtrack-inspector` under `[project.gui-scripts]` in `pyproject.toml`. On Windows, `pip` installs `dhtrack-gui.exe` and `dhtrack-inspector.exe` into your environment’s **Scripts** directory; **`dhtrack-inspector`** is the better choice for taskbar or Start-menu shortcuts.

Starts the **dhtrack — DHT expert inspector** window with sidebar pages: Overview, Routing table, Peer store, kRPC console, Peer scope, Traffic monitor, Swarm tracker, Torrent manager, and Swarm inspector.

## Usage

### CLI examples

```bash
python -m dhtrack dht \
    --peers-file /tmp/dht_peers.dat \
    --save-interval 60 \
    --run-time 300 \
    --bind-port 51413

python -m dhtrack dht \
    --bootstrap router.bittorrent.com 6881 \
    --bootstrap dht.transmissionbt.com 6881

python -m dhtrack resolve \
    ba0ffca471a3475ebc5467aa95a7d2ff7242732f \
    --max-peers 10 --timeout 120

python -m dhtrack scrape \
    https://tracker.example.com/announce \
    ba0ffca471a3475ebc5467aa95a7d2ff7242732f \
    ca0ffca471a3475ebc5467aa95a7d2ff7242732a \
    --timeout 15
```

### As a library

```python
from dhtrack.dht_manager import DHTManager
from dhtrack.torrent import Torrent
from dhtrack.tracker import TrackerClient
from dhtrack.bencode import encode, decode

value = decode(b"i42e")
encoded = encode({"info": b"data"})

manager = DHTManager(peers_file="peers.dat")
manager.start()

metadata = manager.retrieve_metadata(
    info_hash=bytes.fromhex("ba0ffca471a3475ebc5467aa95a7d2ff7242732f"),
    timeout=120,
    max_peers=10,
)

torrent = manager.create_torrent(metadata)
print(torrent.name, torrent.info_hash.hex(), len(torrent.files))

client = TrackerClient(timeout=10, user_agent="dhtrack")
response = client.scrape(
    info_hashes=[bytes.fromhex("ba0ffca471a3475ebc5467aa95a7d2ff7242732f")],
    announce_url="https://tracker.example.com/announce",
)

manager.stop()
```

High-level responsibilities of `*Manager` types (DHT vs swarm vs torrent library) are summarized in [`dhtrack/MANAGERS.md`](dhtrack/MANAGERS.md).

## Project layout (high level)

```
dhtrack/
├── __main__.py            # CLI entry when using python -m dhtrack
├── cli.py                 # argparse: dht, resolve, scrape
├── dht.py                 # DHTNode, routing, SocketManager, KRPC I/O
├── dht_manager.py         # asyncio façade: metadata, orchestration helpers
├── dht_address.py         # IPv4/IPv6 normalization helpers for DHT
├── krpc.py , routing.py , node.py
├── swarm.py , torrent_track.py    # swarm registry + torrent library / queue
├── peer.py , peer_session.py      # peer wire sessions + PEX bookkeeping
├── peerid.py              # Peer ID conventions (BEP 20-ish parsing)
├── tracker.py , udp_tracker.py
├── downloader.py , storage.py , resume.py , io.py
├── torrent.py , metadata_retriever.py , webseed.py , lsd.py , utp.py
├── piece_selector.py      # BEP 19 gap-based piece selection helpers
├── bloom_filter.py , endpoint_swarm_index.py , events.py , rss_feed.py
├── bep4.py , bep31.py , bep32.py , bep42.py , bep47.py , bep53.py , bep54.py , extension.py
├── quic.py                # experimental QUIC-framed DHT (non-core)
├── gui/                   # PyQt6 workspace shell, widgets, models, inspector session
├── gui/resources/         # Branding: app_icon.svg (master), app_icon.png, app_icon.ico
tests/                     # mirrored coverage of the above
pyproject.toml
requirements.txt           # PyQt6, pytest, linters (local convenience list)
protocol.md                # detailed BEP status matrix
```

## Architecture overview

### BEncode (`bencode.py`)

Typed encode/decode for the bencoding used by [.torrent meta-info (`BEP 3`)](https://bittorrent.org/beps/bep_0003.html) and raw DHT payloads.

### DHT (`dht.py`, `dht_manager.py`)

Kademlia-style node with K-buckets, token rotation, iterative queries, and integration points for bloom / scrape-related fields. **`DHTManager`** runs the asyncio loop off the CLI/GUI callers and exposes metadata retrieval helpers.

### Trackers (`tracker.py`, `udp_tracker.py`)

HTTP scrape and announce helpers; UDP connect / announce / scrape with connection-ID handling.

### Torrents & swarms (`torrent.py`, `swarm.py`, `torrent_track.py`)

`.torrent` parsing, info-hash computation, multitracker lists, and inspector-oriented registries (`SwarmManager`, `TorrentManager`) used by the GUI.

For wire-level extensions, see **`peer.py`**, **`extension.py`**, and the numbered `bep*.py` modules. **RST sources** (`beps/bep_*.rst`) and **clause-level checklist**: **[`protocol.md`](protocol.md)** · **Overview matrix**: **[Implementation status by proposal](#implementation-status-by-proposal)** above.

## BEP compliance

Use the **[Implementation status by proposal](#implementation-status-by-proposal)** table for BEP ↔ RST ↔ [`dhtrack/`](dhtrack/) mapping. **`protocol.md`** expands each 🟡 row with MUST/SHALL gaps ([BEP 51](https://www.bittorrent.org/beps/bep_0051.html) caller-driven polling, live tracker harnesses, outbound [BEP 42](https://www.bittorrent.org/beps/bep_0042.html) IDs, …). **`protocol.md`** does not yet list [BEP 36](https://www.bittorrent.org/beps/bep_0036.html) / [`bep_0036.rst`](https://github.com/bittorrent/bittorrent.org/blob/master/beps/bep_0036.rst)—add an appendix row there when auditing [`rss_feed.py`](dhtrack/rss_feed.py) against the draft.

## Development

```bash
pip install -e ".[dev,test]"          # add [gui] if you work on the inspector
ruff check dhtrack/ tests/
ruff format dhtrack/ tests/
black dhtrack/ tests/
isort dhtrack/ tests/
pytest
```

The **`dev`** extra includes **`pillow`** and **`resvg-py`** so you can regenerate [`tools/render_gui_icons.py`](tools/render_gui_icons.py) outputs after changing the SVG logo.

Optional: `mypy dhtrack/` if you install `mypy` separately (listed in [`requirements.txt`](requirements.txt), not bundled in `dhtrack[dev]`).

```bash
pre-commit install
pre-commit run --all-files
```

## License

MIT License. See [LICENSE](LICENSE).

## Contributing

1. Fork the repository  
2. Create a feature branch  
3. Implement changes with tests  
4. Run **`pytest`** and linters  
5. Open a pull request  
