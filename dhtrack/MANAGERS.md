# dhtrack “Manager” overview

Different `*Manager` types play different architectural roles:

| Component | Responsibility |
|-----------|----------------|
| **`SwarmManager`** | Inspector session registry: one row per tracked info-hash with peer lists and cached magnet metadata (`Swarm.cached_metadata_bytes`). |
| **`TorrentManager`** | Library registry + FIFO for concurrent payload jobs; persists `.torrent` files under `torrent_library_directory` (`resume/` for piece state). |
| **`DHTManager`** | Thin façade around `DHTNode`: iterative queries, scrape, asyncio loop thread, torrent download orchestration helpers. |
| **`SocketManager`** | UDP mux used inside `dht.track` I/O—not a swarm/torrent registry. |
| **`ExtensionManager`**, **`PEXManager`** | Peer wire extension bookkeeping. |
| **`WebSeedManager`**, **`LSDManager`** | BEP 19 HTTP/FTP retrieval and LAN announce respectively. |

**GUI bundle:** [`InspectorSession`](gui/inspector_session.py) groups `SwarmManager` + `TorrentManager` for Swarm Tracker, Torrent Manager, and Swarm Inspector tabs.
