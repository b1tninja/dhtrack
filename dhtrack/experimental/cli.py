"""Headless CLI for the experimental proposals.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
Run ``python -m dhtrack.experimental --help``.

``catalog-round``, ``watch-observe``, and ``analyze-peers`` read and write
files. They do not join the DHT or contact a tracker.

The MCP-shaped verbs (``session``, ``catalog``, ``swarm``, ``peer``,
``send``, ``node``, ``serve``) call the same handlers as the experimental
MCP server. ``send`` and ``node start`` return a plan unless ``--confirm``
is passed. Only a confirmed node start binds a socket, and it dials bootstrap
routers only when ``--bootstrap`` is present.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from dhtrack.experimental.infohash_catalog import (
    CatalogState,
    MapTransport,
    loads_reply_map,
    run_sample_round,
)
from dhtrack.experimental.mcp.cli import MCP_COMMANDS, add_mcp_subparsers, run_mcp_command
from dhtrack.experimental.peer_analytics import FINDING_FIELDS, GeoLookup, PeerRecord, analyze_peers
from dhtrack.experimental.peers import PeerTableRow, parse_peer_table
from dhtrack.experimental.persist import (
    append_jsonl,
    dump_json,
    expect_endpoint,
    load_json,
    write_csv,
    write_snapshot_jsonl,
)
from dhtrack.experimental.swarm_watch import (
    PeerSighting,
    SwarmObservation,
    SwarmWatch,
    TrackerSnapshot,
    WatchThresholds,
)


def main(argv: list[str] | None = None) -> int:
    """Run an experimental subcommand.

    Parameters
    ----------
    argv :
        Argument vector, excluding the program name. ``None`` uses ``sys.argv``.

    Returns
    -------
    int
        ``0`` on success, ``1`` on input or data errors, ``2`` when arguments
        are missing.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    command = getattr(args, "command", None)
    if command is None:
        parser.print_help()
        return 2
    try:
        if command in MCP_COMMANDS:
            return run_mcp_command(args)
        if command == "catalog-round":
            return _catalog_round(args)
        if command == "watch-observe":
            return _watch_observe(args)
        if command == "analyze-peers":
            return _analyze_peers(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    """Build the experimental argument parser."""
    parser = argparse.ArgumentParser(
        prog="dhtrack.experimental",
        description=(
            "EXPERIMENTAL proposals for headless DHT measurement. "
            "Not a stable interface. catalog-round, watch-observe, and analyze-peers "
            "do not open the network. send and node start do nothing until --confirm."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    add_mcp_subparsers(subparsers)

    catalog = subparsers.add_parser(
        "catalog-round",
        help="Ingest one BEP 51 sample round into an infohash catalog",
    )
    catalog.add_argument("--endpoints", required=True, type=Path, help="JSON list of {ip, port}")
    catalog.add_argument("--state", required=True, type=Path, help="Catalog state JSON (created if missing)")
    catalog.add_argument("--replies", type=Path, help="JSON object of ip|port -> {samples_hex, num, interval}")
    catalog.add_argument("--snapshot", type=Path, help="Overwrite this JSONL with the current catalog")
    catalog.add_argument("--now", type=float, default=None, help="Clock value (default: time.time())")

    watch = subparsers.add_parser(
        "watch-observe",
        help="Score one swarm observation and append health/alerts",
    )
    watch.add_argument("--infohash", required=True, type=_infohash, help="40 hex characters")
    watch.add_argument("--peers", type=Path, help="JSON peer table (default: no DHT peers)")
    watch.add_argument("--name", default=None, help="Display name stored on the snapshot")
    watch.add_argument(
        "--tracker",
        default="",
        help="Tracker label stored with the scrape counters (needs --tracker-complete and --tracker-incomplete)",
    )
    watch.add_argument("--tracker-complete", type=int, default=None)
    watch.add_argument("--tracker-incomplete", type=int, default=None)
    watch.add_argument("--tracker-downloaded", type=int, default=None)
    watch.add_argument("--state", required=True, type=Path, help="Watch state JSON (created if missing)")
    watch.add_argument("--health", type=Path, help="Append the health snapshot as JSONL")
    watch.add_argument("--alerts", type=Path, help="Append new alerts as JSONL")
    watch.add_argument("--analyze", type=Path, help="Also write a population report JSON for these peers")
    watch.add_argument("--now", type=float, default=None)
    watch.add_argument("--min-peers", type=int, default=1)
    watch.add_argument("--min-diversity", type=float, default=0.25)
    watch.add_argument("--min-peers-for-diversity", type=int, default=8)
    watch.add_argument("--max-prefix-share", type=float, default=0.8)
    watch.add_argument("--min-seeders", type=int, default=None)
    watch.add_argument("--spike-ratio", type=float, default=5.0)

    analyze = subparsers.add_parser(
        "analyze-peers",
        help="Write a population and sybil-heuristic report for a peer table",
    )
    analyze.add_argument("--peers", required=True, type=Path, help="JSON peer table")
    analyze.add_argument("--out", required=True, type=Path, help="Report JSON")
    analyze.add_argument("--csv", type=Path, help="Optional per-peer CSV")
    analyze.add_argument("--geo", type=Path, help='Optional JSON object {"ip": "label"}')
    return parser


def _catalog_round(args: argparse.Namespace) -> int:
    now = time.time() if args.now is None else float(args.now)
    endpoints = load_json_endpoints(load_json(args.endpoints))
    replies = {} if args.replies is None else loads_reply_map(load_json(args.replies))
    state = CatalogState.load(args.state)
    result = run_sample_round(
        state.catalog,
        state.schedule,
        endpoints,
        MapTransport(replies),
        now=now,
    )
    state.save(args.state)
    if args.snapshot is not None:
        write_snapshot_jsonl(args.snapshot, [row.to_dict() for row in state.catalog.records()])
    print(
        f"queried={result.queried} answered={result.answered} missed={result.missed} "
        f"observations={result.observations} catalog_size={len(state.catalog)}"
    )
    return 0


def _watch_observe(args: argparse.Namespace) -> int:
    now = time.time() if args.now is None else float(args.now)
    rows = [] if args.peers is None else parse_peer_table(load_json(args.peers))
    tracker = _tracker_from_args(args)
    observation = SwarmObservation(
        info_hash=args.infohash,
        observed_at=now,
        peers=tuple(_sighting(row) for row in rows),
        tracker=tracker,
        display_name=args.name,
    )
    watch = SwarmWatch(thresholds=_thresholds_from_args(args))
    watch.load_latest(args.state)
    snapshot, alerts = watch.observe(observation)
    watch.save(args.state)
    if args.health is not None:
        append_jsonl(args.health, snapshot.to_dict())
    if args.alerts is not None:
        for alert in alerts:
            append_jsonl(args.alerts, alert.to_dict())
    if args.analyze is not None:
        report = analyze_peers([_record(row) for row in rows])
        dump_json(args.analyze, report.to_dict())
    kinds = ",".join(alert.kind for alert in alerts) or "-"
    print(f"infohash={snapshot.info_hash_hex} peers={snapshot.peer_count} alerts={len(alerts)} kinds={kinds}")
    return 0


def _analyze_peers(args: argparse.Namespace) -> int:
    rows = parse_peer_table(load_json(args.peers))
    geo = None if args.geo is None else _geo_from_file(load_json(args.geo))
    report = analyze_peers([_record(row) for row in rows], geo=geo)
    dump_json(args.out, report.to_dict())
    if args.csv is not None:
        write_csv(args.csv, report.finding_rows(), FINDING_FIELDS)
    print(f"peers={report.peer_count} suspicion={report.suspicion:.4f} bep42_mismatch={report.bep42_mismatch}")
    return 0


def load_json_endpoints(payload: object) -> list[tuple[str, int]]:
    """Parse a JSON list of ``{"ip": "...", "port": 6881}`` objects."""
    if not isinstance(payload, list):
        raise ValueError("endpoints must be a JSON list")
    endpoints: list[tuple[str, int]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"endpoint[{index}] must be an object")
        endpoints.append(expect_endpoint(item.get("ip"), item.get("port"), f"endpoint[{index}]"))
    return endpoints


def _infohash(text: str) -> bytes:
    try:
        raw = bytes.fromhex(text.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("infohash must be hex") from exc
    if len(raw) != 20:
        raise argparse.ArgumentTypeError("infohash must be 40 hex characters")
    return raw


def _tracker_from_args(args: argparse.Namespace) -> TrackerSnapshot | None:
    complete = args.tracker_complete
    incomplete = args.tracker_incomplete
    downloaded = args.tracker_downloaded
    if complete is None and incomplete is None and downloaded is None and not args.tracker:
        return None
    if complete is None or incomplete is None:
        raise ValueError("tracker-complete and tracker-incomplete are both required when scrape data is set")
    if complete < 0 or incomplete < 0 or (downloaded is not None and downloaded < 0):
        raise ValueError("tracker counters must be >= 0")
    return TrackerSnapshot(
        complete=complete,
        incomplete=incomplete,
        downloaded=downloaded,
        tracker=args.tracker or "",
    )


def _thresholds_from_args(args: argparse.Namespace) -> WatchThresholds:
    return WatchThresholds(
        min_peers=args.min_peers,
        min_diversity=args.min_diversity,
        min_peers_for_diversity=args.min_peers_for_diversity,
        max_prefix_share=args.max_prefix_share,
        min_seeders=args.min_seeders,
        spike_ratio=args.spike_ratio,
    )


def _sighting(row: PeerTableRow) -> PeerSighting:
    return PeerSighting(
        ip=row.ip,
        port=row.port,
        peer_id=row.peer_id,
        node_id=row.node_id,
        is_seeder=row.is_seeder,
    )


def _record(row: PeerTableRow) -> PeerRecord:
    return PeerRecord(ip=row.ip, port=row.port, peer_id=row.peer_id, node_id=row.node_id)


def _geo_from_file(payload: object) -> GeoLookup:
    if not isinstance(payload, dict):
        raise ValueError("geo file must be a JSON object")
    labels: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("geo entries must be strings")
        labels[key] = value

    def lookup(ip: str) -> str | None:
        return labels.get(ip)

    return lookup
