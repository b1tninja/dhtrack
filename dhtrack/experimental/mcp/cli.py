"""CLI verbs that share the MCP tool vocabulary.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

``dhtrack session overview --path session.sqlite`` and
``dhtrack_session_overview`` call the same handler. Each CLI invocation is
its own process, so pass ``--path`` to resume a sqlite session. The MCP
server keeps that session open and uses ``session_id``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dhtrack.experimental.mcp.errors import ToolError
from dhtrack.experimental.mcp.service import call_tool
from dhtrack.experimental.persist import load_json

MCP_COMMANDS = frozenset({"serve", "server", "guide", "session", "catalog", "write", "send", "swarm", "peer", "node"})


def add_mcp_subparsers(subparsers: argparse._SubParsersAction) -> None:
    """Register MCP-shaped verbs on the experimental parser."""
    serve = subparsers.add_parser("serve", help="Run the experimental MCP stdio server")
    serve.add_argument("--transport", choices=("stdio",), default="stdio")

    server = subparsers.add_parser("server", help="Server version, features, and tool names")
    server_nouns = server.add_subparsers(dest="noun", required=True)
    status = server_nouns.add_parser("status", help="dhtrack_server_status")
    status.add_argument("--section", action="append", dest="sections", help="capabilities or node")

    guide = subparsers.add_parser("guide", help="Modes, task plans, and the tool catalog")
    guide_nouns = guide.add_subparsers(dest="noun", required=True)
    mode = guide_nouns.add_parser("mode", help="dhtrack_guide_mode")
    mode.add_argument("--mode", default=None)
    mode.add_argument("--goal", default=None)
    mode.add_argument("--path", default=None)
    mode.add_argument("--infohash", default=None)
    plan = guide_nouns.add_parser("task-plan", help="dhtrack_guide_task_plan")
    plan.add_argument("--goal", default=None)
    plan.add_argument("--path", default=None)
    plan.add_argument("--infohash", default=None)
    help_parser = guide_nouns.add_parser("help", help="dhtrack_guide_help")
    help_parser.add_argument("--topic", default=None)

    session = subparsers.add_parser("session", help="Open or query an observation session")
    session_nouns = session.add_subparsers(dest="noun", required=True)
    opened = session_nouns.add_parser("open", help="dhtrack_session_open")
    _add_session_paths(opened)
    closed = session_nouns.add_parser("close", help="dhtrack_session_close")
    _add_session_path(closed)
    session_nouns.add_parser("list", help="dhtrack_session_list")
    overview = session_nouns.add_parser("overview", help="dhtrack_session_overview")
    _add_session_path(overview)
    report = session_nouns.add_parser("report", help="dhtrack_session_report")
    _add_session_path(report)
    _add_page(report)

    catalog = subparsers.add_parser("catalog", help="Read the infohash catalog")
    catalog_nouns = catalog.add_subparsers(dest="noun", required=True)
    listed = catalog_nouns.add_parser("list", help="dhtrack_catalog_list")
    _add_session_path(listed)
    _add_page(listed)
    got = catalog_nouns.add_parser("get", help="dhtrack_catalog_get")
    _add_session_path(got)
    got.add_argument("--infohash", required=True)

    write = subparsers.add_parser("write", help="Write JSON or JSONL. Refuses to overwrite unless --overwrite")
    write_nouns = write.add_subparsers(dest="noun", required=True)
    snapshot = write_nouns.add_parser("catalog-snapshot", help="dhtrack_write_catalog_snapshot")
    _add_write_common(snapshot)
    alerts = write_nouns.add_parser("swarm-alerts", help="dhtrack_write_swarm_alerts")
    _add_write_common(alerts)
    peer_report = write_nouns.add_parser("peer-report", help="dhtrack_write_peer_report")
    _add_write_common(peer_report)
    peer_report.add_argument("--peers", type=Path)
    peer_report.add_argument("--infohash", default=None)
    peer_report.add_argument("--geo", type=Path)

    send = subparsers.add_parser("send", help="Confirm-gated network or sample-round actions")
    send_nouns = send.add_subparsers(dest="noun", required=True)
    sample = send_nouns.add_parser("catalog-sample-round", help="dhtrack_send_catalog_sample_round")
    _add_session_path(sample)
    sample.add_argument("--endpoints", required=True, type=Path)
    sample.add_argument("--replies", type=Path)
    sample.add_argument("--confirm", action="store_true")
    sample.add_argument("--now", type=float, default=None)
    get_peers = send_nouns.add_parser("get-peers", help="dhtrack_send_get_peers")
    _add_session_path(get_peers)
    get_peers.add_argument("--infohash", required=True)
    get_peers.add_argument("--confirm", action="store_true")
    _add_page(get_peers)
    sample_hashes = send_nouns.add_parser("sample-infohashes", help="dhtrack_send_sample_infohashes")
    _add_session_path(sample_hashes)
    sample_hashes.add_argument("--confirm", action="store_true")

    swarm = subparsers.add_parser("swarm", help="Score a swarm or analyze its peer table")
    swarm_nouns = swarm.add_subparsers(dest="noun", required=True)
    observe = swarm_nouns.add_parser("observe", help="dhtrack_swarm_observe")
    _add_session_path(observe)
    _add_observe_args(observe)
    analyze = swarm_nouns.add_parser("analyze", help="dhtrack_swarm_analyze")
    _add_session_path(analyze)
    analyze.add_argument("--infohash", default=None)
    analyze.add_argument("--peers", type=Path)
    analyze.add_argument("--geo", type=Path)
    _add_page(analyze)

    peer = subparsers.add_parser("peer", help="Peer population report")
    peer_nouns = peer.add_subparsers(dest="noun", required=True)
    reported = peer_nouns.add_parser("report", help="dhtrack_peer_report")
    reported.add_argument("--peers", required=True, type=Path)
    reported.add_argument("--geo", type=Path)
    _add_page(reported)

    node = subparsers.add_parser("node", help="Local DHT node. start is confirm-gated")
    node_nouns = node.add_subparsers(dest="noun", required=True)
    node_nouns.add_parser("status", help="dhtrack_node_status")
    start = node_nouns.add_parser("start", help="dhtrack_node_start")
    start.add_argument("--port", type=int, default=0)
    start.add_argument(
        "--bind-host", default="127.0.0.1", help="Default is loopback; 0.0.0.0 accepts inbound DHT traffic"
    )
    start.add_argument("--bootstrap", nargs=2, action="append", metavar=("HOST", "PORT"))
    start.add_argument("--confirm", action="store_true")
    node_nouns.add_parser("stop", help="dhtrack_node_stop")


def run_mcp_command(args: argparse.Namespace) -> int:
    """Dispatch one MCP-shaped CLI command. Prints JSON. Returns 0, or 1 on a tool error."""
    if args.command == "serve":
        from dhtrack.experimental.mcp.__main__ import main as serve_main

        return serve_main(["--transport", args.transport])
    try:
        result = _dispatch(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        result = {"error": str(exc), "code": "invalid_argument"}
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if "error" in result:
        sys.stderr.write(text)
        return 1
    sys.stdout.write(text)
    return 0


def _dispatch(args: argparse.Namespace) -> dict[str, Any]:
    command, noun = args.command, args.noun
    if command == "server" and noun == "status":
        return call_tool("dhtrack_server_status", {"sections": args.sections})
    if command == "guide" and noun == "mode":
        return call_tool(
            "dhtrack_guide_mode",
            {"mode": args.mode, "goal": args.goal, "path": args.path, "infohash": args.infohash},
        )
    if command == "guide" and noun == "task-plan":
        return call_tool(
            "dhtrack_guide_task_plan",
            {"goal": args.goal, "path": args.path, "infohash": args.infohash},
        )
    if command == "guide" and noun == "help":
        return call_tool("dhtrack_guide_help", {"topic": args.topic})
    if command == "session" and noun == "list":
        return call_tool("dhtrack_session_list")
    if command == "node" and noun == "status":
        return call_tool("dhtrack_node_status")
    if command == "node" and noun == "stop":
        return call_tool("dhtrack_node_stop")
    if command == "node" and noun == "start":
        bootstrap = None
        if args.bootstrap:
            bootstrap = [{"host": host, "port": int(port)} for host, port in args.bootstrap]
        return call_tool(
            "dhtrack_node_start",
            {
                "bootstrap": bootstrap,
                "port": args.port,
                "bind_host": args.bind_host,
                "confirm": args.confirm,
            },
        )
    if command == "peer" and noun == "report":
        return call_tool(
            "dhtrack_peer_report",
            {
                "peers": load_json(args.peers),
                "geo_labels": None if args.geo is None else load_json(args.geo),
                "limit": args.limit,
                "offset": args.offset,
            },
        )

    if command == "session" and noun == "open":
        return _opening(args, call_tool, keep_open=True)
    return _with_session(args, _tool_call(args))


def _tool_call(args: argparse.Namespace):
    """Build the tool call that runs after the CLI session is open."""

    def invoke(session_id: str | None) -> dict[str, Any]:
        command, noun = args.command, args.noun
        if command == "session" and noun == "close":
            return call_tool("dhtrack_session_close", {"session_id": session_id})
        if command == "session" and noun == "overview":
            return call_tool("dhtrack_session_overview", {"session_id": session_id})
        if command == "session" and noun == "report":
            return call_tool(
                "dhtrack_session_report",
                {"session_id": session_id, "limit": args.limit, "offset": args.offset},
            )
        if command == "catalog" and noun == "list":
            return call_tool(
                "dhtrack_catalog_list",
                {"session_id": session_id, "limit": args.limit, "offset": args.offset},
            )
        if command == "catalog" and noun == "get":
            return call_tool("dhtrack_catalog_get", {"session_id": session_id, "infohash": args.infohash})
        if command == "write" and noun == "catalog-snapshot":
            return call_tool(
                "dhtrack_write_catalog_snapshot",
                {"session_id": session_id, "output_path": args.output, "overwrite": args.overwrite},
            )
        if command == "write" and noun == "swarm-alerts":
            return call_tool(
                "dhtrack_write_swarm_alerts",
                {"session_id": session_id, "output_path": args.output, "overwrite": args.overwrite},
            )
        if command == "write" and noun == "peer-report":
            peers = None if args.peers is None else load_json(args.peers)
            return call_tool(
                "dhtrack_write_peer_report",
                {
                    "session_id": session_id,
                    "output_path": args.output,
                    "peers": peers,
                    "infohash": args.infohash,
                    "geo_labels": None if args.geo is None else load_json(args.geo),
                    "overwrite": args.overwrite,
                },
            )
        if command == "send" and noun == "catalog-sample-round":
            return call_tool(
                "dhtrack_send_catalog_sample_round",
                {
                    "session_id": session_id,
                    "endpoints": load_json(args.endpoints),
                    "replies": None if args.replies is None else load_json(args.replies),
                    "confirm": args.confirm,
                    "now": args.now,
                },
            )
        if command == "send" and noun == "get-peers":
            return call_tool(
                "dhtrack_send_get_peers",
                {
                    "session_id": session_id,
                    "infohash": args.infohash,
                    "confirm": args.confirm,
                    "limit": args.limit,
                    "offset": args.offset,
                },
            )
        if command == "send" and noun == "sample-infohashes":
            return call_tool(
                "dhtrack_send_sample_infohashes",
                {"session_id": session_id, "confirm": args.confirm},
            )
        if command == "swarm" and noun == "observe":
            return call_tool("dhtrack_swarm_observe", _observe_arguments(args, session_id))
        if command == "swarm" and noun == "analyze":
            peers = None if args.peers is None else load_json(args.peers)
            return call_tool(
                "dhtrack_swarm_analyze",
                {
                    "session_id": session_id,
                    "infohash": args.infohash,
                    "peers": peers,
                    "geo_labels": None if args.geo is None else load_json(args.geo),
                    "limit": args.limit,
                    "offset": args.offset,
                },
            )
        raise ToolError(f"unknown command {command} {noun}", code="unknown_tool")

    return invoke


def _opening(args: argparse.Namespace, caller, *, keep_open: bool) -> dict[str, Any]:
    """``session open`` then close the connection so the sqlite file is not left locked."""
    del keep_open
    result = caller(
        "dhtrack_session_open",
        {"path": args.path, "output_path": args.output},
    )
    if "error" not in result:
        call_tool("dhtrack_session_close", {"session_id": result["session_id"]})
    return result


def _with_session(args: argparse.Namespace, invoke) -> dict[str, Any]:
    path = getattr(args, "path", None)
    opened: dict[str, Any] | None = None
    if path:
        opened = call_tool("dhtrack_session_open", {"path": path})
        if "error" in opened:
            return opened
    try:
        session_id = None if opened is None else opened["session_id"]
        return invoke(session_id)
    finally:
        if opened is not None and "session_id" in opened:
            call_tool("dhtrack_session_close", {"session_id": opened["session_id"]})


def _observe_arguments(args: argparse.Namespace, session_id: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": session_id,
        "infohash": args.infohash,
        "peers": None if args.peers is None else load_json(args.peers),
        "name": args.name,
        "tracker": args.tracker,
        "tracker_complete": args.tracker_complete,
        "tracker_incomplete": args.tracker_incomplete,
        "tracker_downloaded": args.tracker_downloaded,
        "now": args.now,
        "min_peers": args.min_peers,
        "min_diversity": args.min_diversity,
        "min_peers_for_diversity": args.min_peers_for_diversity,
        "max_prefix_share": args.max_prefix_share,
        "min_seeders": args.min_seeders,
        "spike_ratio": args.spike_ratio,
        "include_peers": args.include_peers,
        "limit": args.limit,
        "offset": args.offset,
    }
    return payload


def _add_session_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", help="Sqlite session file. Required for a one-shot CLI call that reads state.")


def _add_session_paths(parser: argparse.ArgumentParser) -> None:
    _add_session_path(parser)
    parser.add_argument("--output", help="Sqlite file to create or resume")


def _add_page(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--offset", type=int, default=None)


def _add_write_common(parser: argparse.ArgumentParser) -> None:
    _add_session_path(parser)
    parser.add_argument("--output", required=True, help="File to write")
    parser.add_argument("--overwrite", action="store_true")


def _add_observe_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--infohash", required=True)
    parser.add_argument("--peers", type=Path)
    parser.add_argument("--name", default=None)
    parser.add_argument("--tracker", default=None)
    parser.add_argument("--tracker-complete", type=int, default=None)
    parser.add_argument("--tracker-incomplete", type=int, default=None)
    parser.add_argument("--tracker-downloaded", type=int, default=None)
    parser.add_argument("--now", type=float, default=None)
    parser.add_argument("--min-peers", type=int, default=None)
    parser.add_argument("--min-diversity", type=float, default=None)
    parser.add_argument("--min-peers-for-diversity", type=int, default=None)
    parser.add_argument("--max-prefix-share", type=float, default=None)
    parser.add_argument("--min-seeders", type=int, default=None)
    parser.add_argument("--spike-ratio", type=float, default=None)
    parser.add_argument("--include-peers", action="store_true")
    _add_page(parser)
