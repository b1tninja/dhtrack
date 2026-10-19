# Proposal: experimental MCP server

**Status:** draft. The stdio server and the matching CLI verbs live under `dhtrack/experimental/mcp/`. They are not part of the stable dhtrack API. This note is for discussion against current upstream `master` (the merge of the experimental prototypes and the correctness review).

## Why it looks like hardly

[hardly](https://github.com/b1tninja/hardly) is an MCP server whose tool names tell you the effect before you call them. dhtrack's draft copies that authoring rule and not the HAR domain:

| hardly | dhtrack draft | Gate |
| --- | --- | --- |
| `hardly_guide_*`, `hardly_session_*` | `dhtrack_guide_*`, `dhtrack_session_*` | read or in-memory session state |
| (no marker) | `dhtrack_catalog_*`, `dhtrack_swarm_*`, `dhtrack_peer_*` | read or score data already in hand |
| `hardly_send_*` returns a plan unless `confirm=true` | `dhtrack_send_*` and `dhtrack_node_start` | no socket, no datagram, until `confirm=true` |
| `hardly_write_*` refuses to replace a file | `dhtrack_write_*` | existing file is kept unless `overwrite=true` |

`dhtrack_server_status` advertises `name`, `version`, `features`, `tools`, `modes`, `node_running`, and a `next` hint, the same shape as hardly's `capabilities()`. The feature tuple is `api_surface_v0`. Bump it when the tool list changes so an agent can tell a stale server from a current one. v0 stops at 23 tools. It does not grow toward hardly's catalog of HAR, browser, and replay tools.

The CLI uses the same words. `python -m dhtrack.experimental session overview --path session.sqlite` and the tool `dhtrack_session_overview` call one handler. A CLI process exits, so it reopens the sqlite file on every invocation. An MCP client calls `dhtrack_session_open` once and then passes `session_id`.

## Modes

| Mode | When | What it does not do |
| --- | --- | --- |
| **archive** | A session sqlite, catalog snapshot, or saved peer table is already on disk | Open a socket |
| **observe** | You want one live `get_peers` or `sample_infohashes` | Bootstrap the public DHT unless you passed routers, and never loop |
| **analyze** | A peer list is already collected | Open a socket |

`dhtrack_guide_mode` lists them. `dhtrack_guide_task_plan(goal, path, infohash)` picks one and returns ordered example calls. The default pick is archive.

## Tools

Guide and server: `dhtrack_server_status`, `dhtrack_guide_help`, `dhtrack_guide_mode`, `dhtrack_guide_task_plan`.

Session: `dhtrack_session_open`, `dhtrack_session_close`, `dhtrack_session_list`, `dhtrack_session_overview`, `dhtrack_session_report`.

Catalog: `dhtrack_catalog_list`, `dhtrack_catalog_get`, `dhtrack_write_catalog_snapshot`, `dhtrack_send_catalog_sample_round`.

Swarm and peers: `dhtrack_swarm_observe`, `dhtrack_write_swarm_alerts`, `dhtrack_swarm_analyze`, `dhtrack_peer_report`, `dhtrack_write_peer_report`.

Node: `dhtrack_node_status`, `dhtrack_node_start`, `dhtrack_node_stop`, `dhtrack_send_get_peers`, `dhtrack_send_sample_infohashes`.

Deferred on purpose: metadata retrieve, `announce_peer`, download, and GUI coalesce hooks.

## What is wrapped

The handlers call the prototypes that already landed on master. They do not reimplement them.

- Catalog rows, the BEP 51 schedule, and `run_sample_round` come from `dhtrack.experimental.infohash_catalog`. A confirmed sample round uses `SampleTransport`. Tests pass a fake. A `replies` object is replayed with `MapTransport` and does not open a socket. If neither is present the confirmed call returns `transport_required` instead of dialing the DHT.
- Health scores and threshold alerts come from `SwarmWatch.observe`. Repeated alerts stay quiet while the condition holds, because the session reloads `active_alerts` through `SwarmWatch.load_latest`.
- Address class, client mix, and the suspicion score come from `analyze_peers`.

`DHTNode.sample_infohashes` still returns `[]` and logs replies asynchronously. `dhtrack_send_sample_infohashes` reports that honestly. Folding those replies into the catalog is `dhtrack_send_catalog_sample_round` with a captured `replies` map, not a new parser.

## Confirm and write gates

`dhtrack_node_start` without `confirm=true` returns the bind plan: host, port, and the bootstrap list you passed. `default_bootstrap` is false. Omitting `bootstrap` means the confirmed start binds a UDP port and does not call `DHTNode.bootstrap`, so the public router list in `DEFAULT_BOOTSTRAP_NODES` is not contacted. Passing `bootstrap` is the only way that call dials out.

`dhtrack_send_get_peers` and `dhtrack_send_sample_infohashes` without `confirm=true` return a plan and do not touch the node. With `confirm=true` they require a node that is already running; they do not start one. Each call is a single lookup. There is no follow-up loop. The node still enforces the BEP 51 interval inside `sample_infohashes`.

`dhtrack_write_catalog_snapshot`, `dhtrack_write_swarm_alerts`, and `dhtrack_write_peer_report` leave an existing file untouched unless `overwrite=true`. The error code is `output_exists`.

Tool results page peer lists and findings (default 50, cap 200). Peer ids and node ids in those results are an 8-hex prefix. The session sqlite and a `write_` file keep the full values.

## Run it

The core package stays stdlib-only. The SDK is the optional extra `mcp` (`mcp>=2,<3`, where `FastMCP` is `MCPServer`):

```bash
pip install 'dhtrack[mcp]'
python -m dhtrack.experimental.mcp --help
python -m dhtrack.experimental.mcp
dhtrack serve
```

`--help` does not import the SDK. Serving exits with an install hint when the extra is missing.

Cursor or Claude Desktop:

```json
{
  "mcpServers": {
    "dhtrack": {
      "command": "python",
      "args": ["-m", "dhtrack.experimental.mcp"]
    }
  }
}
```

Offline CLI, same vocabulary, no server process:

```bash
python -m dhtrack.experimental session open --path session.sqlite
python -m dhtrack.experimental swarm observe --path session.sqlite --infohash <40 hex> --peers peers.json
python -m dhtrack.experimental peer report --peers peers.json
python -m dhtrack.experimental node start --port 0
python -m dhtrack.experimental send catalog-sample-round --path session.sqlite --endpoints endpoints.json --replies replies.json --confirm
```

The last command replays `replies.json`. `--confirm` runs the round; it still does not open a socket. `node start` without `--confirm` prints the plan and does not bind.

## Tests

`tests/test_experimental_mcp.py` stays offline. Confirm-gated tools are called with a fake node runtime and a fake `SampleTransport`. A blocked factory raises if a test reaches the real `DHTNode` without meaning to. Live DHT remains behind `DHTRACK_RUN_INTERNET_TESTS`, and these tests do not set it.

## Out of scope

This draft does not change DHT correctness, the eval harness, the GUI, GeoIP, or Mongo. It does not announce or seed. Shipping it as a stable entry point should wait until the tool list and the confirm rules have been reviewed.
