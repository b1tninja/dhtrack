"""Tool handlers shared by the experimental CLI and the MCP server.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

Handlers call the existing catalog, swarm-watch, and peer-analytics modules.
They do not reimplement scoring. ``send_`` and ``node_start`` return a plan
unless ``confirm`` is true. ``write_`` refuses to replace a file unless
``overwrite`` is true.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from dhtrack.experimental.infohash_catalog import MapTransport, SampleTransport, loads_reply_map, run_sample_round
from dhtrack.experimental.mcp.capabilities import TOOLS
from dhtrack.experimental.mcp.errors import ToolError
from dhtrack.experimental.mcp.gates import dry_run, prepare_write
from dhtrack.experimental.mcp.helptext import tool_help
from dhtrack.experimental.mcp.modes import list_modes, mode_playbook, pick_mode
from dhtrack.experimental.mcp.node import controller, node_running
from dhtrack.experimental.mcp.paging import page, public_peer, redact_id
from dhtrack.experimental.mcp.session import Session, open_session, registry
from dhtrack.experimental.peer_analytics import PeerRecord, PopulationReport, analyze_peers
from dhtrack.experimental.peers import PeerTableRow, parse_peer_table
from dhtrack.experimental.persist import dump_json, expect_endpoint, write_snapshot_jsonl
from dhtrack.experimental.swarm_watch import (
    PeerSighting,
    SwarmObservation,
    TrackerSnapshot,
    WatchThresholds,
)

HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {}

_sample_transport: SampleTransport | None = None


def _handler(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    HANDLERS[fn.__name__] = fn
    return fn


def install_sample_transport(transport: SampleTransport | None) -> None:
    """Replay or fake a BEP 51 round. ``None`` clears the override. Tests use this."""
    global _sample_transport
    _sample_transport = transport


def reset_state() -> None:
    """Drop sessions, stop a node, and clear the sample-transport override."""
    global _sample_transport
    _sample_transport = None
    registry.reset()
    controller.reset()


def call_tool(name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Run one tool and return a JSON-ready dict. Errors become ``error`` / ``code``."""
    try:
        handler = HANDLERS[name]
    except KeyError as exc:
        raise ToolError(f"unknown tool {name}", code="unknown_tool") from exc
    try:
        result = handler(**dict(arguments or {}))
    except ToolError as exc:
        return exc.to_dict()
    except (OSError, ValueError, KeyError) as exc:
        return {"error": str(exc), "code": "invalid_argument"}
    if not isinstance(result, dict):
        raise TypeError(f"{name} returned {type(result).__name__}, expected dict")
    return result


@_handler
def dhtrack_server_status(sections: list[str] | None = None) -> dict[str, Any]:
    """Version, feature flags, tool names, and node state. sections: capabilities (default), node.

    Example: dhtrack_server_status(sections=['node']).
    """
    chosen = _sections(sections, ("capabilities", "node"), ("capabilities",))
    payload: dict[str, Any] = {"sections": chosen}
    if "capabilities" in chosen:
        from dhtrack.experimental.mcp.capabilities import capabilities

        payload["capabilities"] = capabilities()
    if "node" in chosen:
        payload["node"] = controller.status()
    return payload


@_handler
def dhtrack_guide_help(topic: str | None = None) -> dict[str, Any]:
    """Tool catalog. Pass topic=modes|session|catalog|swarm|peer|node|send|write, or a tool name.

    Example: dhtrack_guide_help(topic='send').
    """
    found = tool_help(topic)
    if "error" in found:
        raise ToolError(str(found["error"]), code="unknown_topic", hint=str(found.get("hint") or ""))
    return found


@_handler
def dhtrack_guide_mode(
    mode: str | None = None,
    goal: str | None = None,
    path: str | None = None,
    infohash: str | None = None,
) -> dict[str, Any]:
    """List archive / observe / analyze, return one playbook, or pick a mode from goal.

    Example: dhtrack_guide_mode(goal='score this peer list for prefix concentration').
    """
    if (mode or "").strip():
        playbook = mode_playbook(mode or "", path=path or "", infohash=infohash or "", goal=goal or "")
        if "error" in playbook:
            raise ToolError(str(playbook["error"]), code="unknown_mode", hint="Modes: archive, observe, analyze.")
        return playbook
    if not any((goal, path, infohash)):
        return list_modes()
    picked = pick_mode(goal=goal or "", path=path or "", infohash=infohash or "")
    if "error" in picked:
        raise ToolError(str(picked["error"]), code="unknown_mode", hint="Modes: archive, observe, analyze.")
    return picked


@_handler
def dhtrack_guide_task_plan(
    goal: str | None = None,
    path: str | None = None,
    infohash: str | None = None,
) -> dict[str, Any]:
    """Ordered tool calls for a goal, plus whether a session or node is already up.

    Example: dhtrack_guide_task_plan(goal='sample the DHT once', infohash='ab'*20).
    """
    picked = pick_mode(goal=goal or "", path=path or "", infohash=infohash or "")
    playbook = picked["playbook"]
    steps = list(playbook["steps"])
    return {
        "goal": goal or "",
        "mode": picked["mode"],
        "reason": picked["reason"],
        "steps": steps,
        "calls": list(playbook["calls"]),
        "environment": {
            "open_sessions": len(registry.values()),
            "node_running": node_running(),
            "network": "offline until a send_ tool or node_start is repeated with confirm=true",
        },
        "next": steps[0] if steps else "",
    }


@_handler
def dhtrack_session_open(path: str | None = None, output_path: str | None = None) -> dict[str, Any]:
    """Open a sqlite session. Omit both paths for an in-memory session on this server.

    output_path persists a copy. An existing different output_path is refused.
    Example: dhtrack_session_open(path='session.sqlite').
    """
    session = open_session(path=path, output_path=output_path)
    payload = session.overview()
    payload["created"] = session.created
    return payload


@_handler
def dhtrack_session_close(session_id: str | None = None) -> dict[str, Any]:
    """Flush and drop a session. Exported files stay on disk.

    Example: dhtrack_session_close(session_id='s1').
    """
    session = _session(session_id)
    registry.pop(session.id)
    path = session.path
    session.close()
    return {"closed": True, "session_id": session.id, "path": path}


@_handler
def dhtrack_session_list() -> dict[str, Any]:
    """List sessions open in this process. Example: dhtrack_session_list()."""
    rows = []
    for session in registry.values():
        overview = session.overview()
        rows.append(
            {
                "session_id": session.id,
                "path": session.path,
                "durable": session.durable,
                "infohashes": overview["infohashes"],
                "alerts": overview["alerts"],
            }
        )
    return {"count": len(rows), "sessions": rows}


@_handler
def dhtrack_session_overview(session_id: str | None = None) -> dict[str, Any]:
    """Counts: infohashes, peers, alerts, last sample time, last observe time.

    Example: dhtrack_session_overview(session_id='s1').
    """
    return _session(session_id).overview()


@_handler
def dhtrack_session_report(
    session_id: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """Threshold alerts stored for the session, newest first.

    Example: dhtrack_session_report(session_id='s1', limit=20).
    """
    session = _session(session_id)
    window = page(session.alert_rows(), limit, offset)
    watch_state = session.watch.to_dict()
    active = watch_state.get("active_alerts", {})
    return {
        "session_id": session.id,
        "severity": session.alert_severity_counts(),
        "active_alerts": active if isinstance(active, dict) else {},
        "total": window["total"],
        "limit": window["limit"],
        "offset": window["offset"],
        "truncated": window["truncated"],
        "alerts": window["items"],
    }


@_handler
def dhtrack_catalog_list(
    session_id: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """Page catalog infohashes, newest first. Example: dhtrack_catalog_list(limit=50)."""
    session = _session(session_id)
    records = [row.to_dict() for row in session.catalog.catalog.records()]
    window = page(records, limit, offset)
    return {
        "session_id": session.id,
        "total": window["total"],
        "limit": window["limit"],
        "offset": window["offset"],
        "truncated": window["truncated"],
        "infohashes": window["items"],
    }


@_handler
def dhtrack_catalog_get(infohash: str, session_id: str | None = None) -> dict[str, Any]:
    """One catalog row. Example: dhtrack_catalog_get(infohash='ab'*20)."""
    session = _session(session_id)
    key = _infohash(infohash).hex()
    row = session.catalog.catalog.get(key)
    if row is None:
        raise ToolError("unknown infohash", code="not_found", hint="dhtrack_catalog_list pages the session catalog.")
    return {"session_id": session.id, "record": row.to_dict()}


@_handler
def dhtrack_write_catalog_snapshot(
    output_path: str,
    session_id: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Write the catalog as JSONL. Refuses an existing file unless overwrite=true.

    Example: dhtrack_write_catalog_snapshot(output_path='catalog.jsonl').
    """
    session = _session(session_id)
    path = prepare_write(output_path, overwrite)
    rows = [row.to_dict() for row in session.catalog.catalog.records()]
    write_snapshot_jsonl(path, rows)
    return {"path": str(path), "rows": len(rows), "bytes": path.stat().st_size}


@_handler
def dhtrack_send_catalog_sample_round(
    endpoints: list[dict[str, Any]],
    session_id: str | None = None,
    replies: dict[str, Any] | None = None,
    confirm: bool = False,
    now: float | None = None,
) -> dict[str, Any]:
    """One BEP 51 round through SampleTransport. Without confirm=true, returns a plan and does not query.

    Pass replies to replay offline (MapTransport, no socket). A missing transport is refused
    rather than opening a DHT socket.
    Example: dhtrack_send_catalog_sample_round(endpoints=[...], replies={...}, confirm=true).
    """
    session = _session(session_id)
    targets = _endpoints(endpoints)
    when = _clock(now)
    due = session.catalog.schedule.due(when, targets)
    if _sample_transport is not None:
        transport_name = "injected"
    elif replies is not None:
        transport_name = "map"
    else:
        transport_name = "missing"
    plan = {
        "action": "catalog_sample_round",
        "endpoints": [{"ip": ip, "port": port} for ip, port in targets],
        "due": [{"ip": ip, "port": port} for ip, port in due],
        "transport": transport_name,
        "opens_sockets": False,
        "note": (
            "replies are replayed by MapTransport and do not open a socket. "
            "Without replies the confirmed call is refused; this tool does not dial the DHT."
        ),
    }
    if not confirm:
        return dry_run(plan)
    transport = _sample_transport
    if transport is None and replies is not None:
        try:
            transport = MapTransport(loads_reply_map(replies))
        except (TypeError, ValueError) as exc:
            raise ToolError(str(exc), code="invalid_argument") from exc
    if transport is None:
        raise ToolError(
            "no sample transport",
            code="transport_required",
            hint="Pass replies to replay a BEP 51 round offline. This tool does not open a DHT socket.",
        )
    result = run_sample_round(
        session.catalog.catalog,
        session.catalog.schedule,
        targets,
        transport,
        now=when,
    )
    session.mark_sample(when)
    session.flush()
    return {
        "confirmed": True,
        "sent": False,
        "executed": True,
        "opens_sockets": False,
        "queried": result.queried,
        "answered": result.answered,
        "missed": result.missed,
        "observations": result.observations,
        "unique_in_round": result.unique_in_round,
        "catalog_size": len(session.catalog.catalog),
    }


@_handler
def dhtrack_swarm_observe(
    infohash: str,
    peers: list[dict[str, Any]] | None = None,
    session_id: str | None = None,
    name: str | None = None,
    tracker: str | None = None,
    tracker_complete: int | None = None,
    tracker_incomplete: int | None = None,
    tracker_downloaded: int | None = None,
    now: float | None = None,
    min_peers: int | None = None,
    min_diversity: float | None = None,
    min_peers_for_diversity: int | None = None,
    max_prefix_share: float | None = None,
    min_seeders: int | None = None,
    spike_ratio: float | None = None,
    include_peers: bool = False,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """Score one peer list offline and store new threshold alerts. Does not open a socket.

    Example: dhtrack_swarm_observe(infohash='ab'*20, peers=[{'ip':'203.0.113.10','port':6881}]).
    """
    session = _session(session_id)
    raw_hash = _infohash(infohash)
    rows = [] if peers is None else _peer_rows(peers)
    when = _clock(now)
    _apply_thresholds(
        session.watch.thresholds,
        session,
        min_peers=min_peers,
        min_diversity=min_diversity,
        min_peers_for_diversity=min_peers_for_diversity,
        max_prefix_share=max_prefix_share,
        min_seeders=min_seeders,
        spike_ratio=spike_ratio,
    )
    observation = SwarmObservation(
        info_hash=raw_hash,
        observed_at=when,
        peers=tuple(_sighting(row) for row in rows),
        tracker=_tracker(tracker, tracker_complete, tracker_incomplete, tracker_downloaded),
        display_name=name,
    )
    snapshot, alerts = session.watch.observe(observation)
    session.add_alerts(alerts)
    stored = session.put_peers(raw_hash.hex(), [_row_dict(row) for row in rows], observed_at=when)
    session.mark_observe(when)
    session.flush()
    payload: dict[str, Any] = {
        "session_id": session.id,
        "snapshot": snapshot.to_dict(),
        "alerts": [alert.to_dict() for alert in alerts],
        "alert_count": len(alerts),
        "peer_table": stored,
    }
    if include_peers:
        payload["peers"] = page([_echo_peer(_row_dict(row)) for row in rows], limit, offset)
    return payload


@_handler
def dhtrack_write_swarm_alerts(
    output_path: str,
    session_id: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Write stored alerts as JSONL. Refuses an existing file unless overwrite=true.

    Example: dhtrack_write_swarm_alerts(output_path='alerts.jsonl').
    """
    session = _session(session_id)
    path = prepare_write(output_path, overwrite)
    rows = list(reversed(session.alert_rows()))
    write_snapshot_jsonl(path, rows)
    return {"path": str(path), "rows": len(rows), "bytes": path.stat().st_size}


@_handler
def dhtrack_swarm_analyze(
    infohash: str | None = None,
    peers: list[dict[str, Any]] | None = None,
    session_id: str | None = None,
    geo_labels: dict[str, str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """Population report for an inline peer list or the peers last stored for infohash. Offline.

    Example: dhtrack_swarm_analyze(infohash='ab'*20).
    """
    rows, note = _analyze_rows(infohash=infohash, peers=peers, session_id=session_id)
    payload = _population(rows, geo_labels, limit, offset)
    if note:
        payload["notes"] = list(payload["notes"]) + [note]
    if infohash:
        payload["infohash"] = _infohash(infohash).hex()
    return payload


@_handler
def dhtrack_peer_report(
    peers: list[dict[str, Any]],
    geo_labels: dict[str, str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """Address class, prefix, client mix, and suspicion for peers you already have. Offline.

    Findings are paged. Example: dhtrack_peer_report(peers=[{'ip':'1.1.1.1','port':6881}]).
    """
    return _population(_peer_rows(peers), geo_labels, limit, offset)


@_handler
def dhtrack_write_peer_report(
    output_path: str,
    peers: list[dict[str, Any]] | None = None,
    infohash: str | None = None,
    session_id: str | None = None,
    geo_labels: dict[str, str] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Write the full population report JSON. Refuses an existing file unless overwrite=true.

    Example: dhtrack_write_peer_report(output_path='report.json', peers=[...]).
    """
    path = prepare_write(output_path, overwrite)
    rows, _note = _analyze_rows(infohash=infohash, peers=peers, session_id=session_id)
    report = analyze_peers(_records(rows), geo=_geo(geo_labels))
    dump_json(path, report.to_dict())
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "peer_count": report.peer_count,
        "suspicion": report.suspicion,
    }


@_handler
def dhtrack_node_status() -> dict[str, Any]:
    """Whether a local node is bound. Does not start one. Example: dhtrack_node_status()."""
    return controller.status()


@_handler
def dhtrack_node_start(
    bootstrap: list[dict[str, Any]] | None = None,
    port: int = 0,
    bind_host: str = "0.0.0.0",
    confirm: bool = False,
) -> dict[str, Any]:
    """Plan a UDP bind. confirm=true binds. Routers are contacted only when bootstrap is passed.

    The public DHT bootstrap list is not used implicitly.
    Example: dhtrack_node_start(port=0, confirm=false).
    """
    routers = _bootstrap(bootstrap)
    if isinstance(port, bool) or not isinstance(port, int) or port < 0 or port > 65535:
        raise ToolError("port must be an integer from 0 to 65535", code="invalid_argument")
    if not isinstance(bind_host, str) or not bind_host.strip():
        raise ToolError("bind_host must be a string", code="invalid_argument")
    plan = {
        "action": "node_start",
        "bind_host": bind_host,
        "port": port,
        "bootstrap": [{"ip": ip, "port": item_port} for ip, item_port in routers],
        "outbound": bool(routers),
        "binds_udp": True,
        "default_bootstrap": False,
        "note": "No bootstrap list means the bind does not dial DHT routers.",
    }
    if not confirm:
        payload = dry_run(plan)
        payload["started"] = False
        return payload
    status = controller.start(port=port, bootstrap=routers, bind_host=bind_host)
    return {"confirmed": True, "sent": bool(status.get("outbound")), "started": True, "node": status}


@_handler
def dhtrack_node_stop() -> dict[str, Any]:
    """Stop the local node. Example: dhtrack_node_stop()."""
    was_running = controller.running()
    status = controller.stop()
    return {"stopped": was_running, "node": status}


@_handler
def dhtrack_send_get_peers(
    infohash: str,
    confirm: bool = False,
    session_id: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """One iterative get_peers. Without confirm=true, returns a plan and does not send.

    Requires a running node. Peer ids in the result are truncated.
    Example: dhtrack_send_get_peers(infohash='ab'*20, confirm=true).
    """
    raw_hash = _infohash(infohash)
    plan = {
        "action": "get_peers",
        "infohash": raw_hash.hex(),
        "node_running": node_running(),
        "outbound": True,
        "calls": 1,
        "note": "One iterative get_peers. The node is not started for you. Nothing is sent until confirm=true.",
    }
    if not confirm:
        return dry_run(plan)
    rows = controller.get_peers(raw_hash)
    _store_runtime_peers(session_id, raw_hash.hex(), rows)
    window = page([_echo_peer(row) for row in rows], limit, offset)
    return {
        "confirmed": True,
        "sent": True,
        "infohash": raw_hash.hex(),
        "total": window["total"],
        "limit": window["limit"],
        "offset": window["offset"],
        "count": window["count"],
        "truncated": window["truncated"],
        "peers": window["items"],
    }


@_handler
def dhtrack_send_sample_infohashes(confirm: bool = False, session_id: str | None = None) -> dict[str, Any]:
    """One BEP 51 sample_infohashes. Without confirm=true, returns a plan and does not send.

    One call, no follow-up loop. The node enforces the peer interval.
    Example: dhtrack_send_sample_infohashes(confirm=true).
    """
    plan = {
        "action": "sample_infohashes",
        "node_running": node_running(),
        "calls": 1,
        "respects_interval": True,
        "autonomous_loop": False,
        "outbound": True,
        "note": (
            "One DHTNode.sample_infohashes call. The node may skip the send when the interval "
            "has not elapsed. Nothing is sent until confirm=true."
        ),
    }
    if not confirm:
        return dry_run(plan)
    result = controller.sample_infohashes()
    if _wants_session(session_id):
        session = _session(session_id)
        session.mark_sample(time.time())
        session.flush()
    return {"confirmed": True, "sent": True, **result}


def _session(session_id: str | None) -> Session:
    if session_id:
        found = registry.get(session_id)
        if found is None:
            raise ToolError(
                "unknown session_id",
                code="unknown_session",
                hint="dhtrack_session_list shows open ids. Otherwise dhtrack_session_open.",
            )
        return found
    open_sessions = registry.values()
    if len(open_sessions) == 1:
        return open_sessions[0]
    if not open_sessions:
        raise ToolError(
            "no session is open",
            code="unknown_session",
            hint="Call dhtrack_session_open first. The CLI passes --path each invocation.",
        )
    raise ToolError(
        "session_id is required",
        code="ambiguous_session",
        hint="More than one session is open. Pass session_id.",
    )


def _wants_session(session_id: str | None) -> bool:
    return session_id is not None or len(registry.values()) == 1


def _infohash(text: str) -> bytes:
    if not isinstance(text, str) or not text.strip():
        raise ToolError("infohash must be a 40-character hex string", code="invalid_argument")
    try:
        raw = bytes.fromhex(text.strip())
    except ValueError as exc:
        raise ToolError("infohash must be hex", code="invalid_argument") from exc
    if len(raw) != 20:
        raise ToolError("infohash must be 40 hex characters", code="invalid_argument")
    return raw


def _clock(value: float | None) -> float:
    if value is None:
        return time.time()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ToolError("now must be a number", code="invalid_argument")
    return float(value)


def _sections(sections: list[str] | str | None, valid: tuple[str, ...], default: tuple[str, ...]) -> list[str]:
    if sections is None:
        return list(default)
    wanted = [sections] if isinstance(sections, str) else sections
    if not isinstance(wanted, list) or not all(isinstance(item, str) for item in wanted):
        raise ToolError("sections must be a list of strings", code="invalid_argument")
    if not wanted:
        return list(default)
    bad = [item for item in wanted if item not in valid]
    if bad:
        raise ToolError(
            "unknown section(s): " + ", ".join(bad),
            code="unknown_section",
            hint="Valid sections: " + ", ".join(valid) + ".",
        )
    return list(dict.fromkeys(wanted))


def _endpoints(payload: object) -> list[tuple[str, int]]:
    if not isinstance(payload, list) or not payload:
        raise ToolError("endpoints must be a non-empty list of {ip, port}", code="invalid_argument")
    found: list[tuple[str, int]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ToolError(f"endpoint[{index}] must be an object", code="invalid_argument")
        try:
            found.append(expect_endpoint(item.get("ip"), item.get("port"), f"endpoint[{index}]"))
        except ValueError as exc:
            raise ToolError(str(exc), code="invalid_argument") from exc
    return found


def _bootstrap(items: object) -> list[tuple[str, int]]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ToolError("bootstrap must be a list of {host, port}", code="invalid_argument")
    found: list[tuple[str, int]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ToolError(f"bootstrap[{index}] must be an object", code="invalid_argument")
        host = item.get("host", item.get("ip"))
        try:
            found.append(expect_endpoint(host, item.get("port"), f"bootstrap[{index}]"))
        except ValueError as exc:
            raise ToolError(str(exc), code="invalid_argument") from exc
    return found


def _peer_rows(payload: object) -> list[PeerTableRow]:
    try:
        return parse_peer_table(payload)
    except ValueError as exc:
        raise ToolError(str(exc), code="invalid_argument") from exc


def _records(rows: list[PeerTableRow]) -> list[PeerRecord]:
    return [PeerRecord(ip=row.ip, port=row.port, peer_id=row.peer_id, node_id=row.node_id) for row in rows]


def _sighting(row: PeerTableRow) -> PeerSighting:
    return PeerSighting(ip=row.ip, port=row.port, peer_id=row.peer_id, node_id=row.node_id, is_seeder=row.is_seeder)


def _row_dict(row: PeerTableRow) -> dict[str, Any]:
    item: dict[str, Any] = {"ip": row.ip, "port": row.port}
    if row.peer_id is not None:
        item["peer_id_hex"] = row.peer_id.hex()
    if row.node_id is not None:
        item["node_id_hex"] = row.node_id.hex()
    if row.is_seeder is not None:
        item["is_seeder"] = row.is_seeder
    return item


def _echo_peer(row: dict[str, Any]) -> dict[str, object]:
    if isinstance(row.get("peer_id"), bytes) or isinstance(row.get("node_id"), bytes):
        return public_peer(row)
    payload: dict[str, object] = {"ip": row.get("ip"), "port": row.get("port"), "is_seeder": row.get("is_seeder")}
    payload.update(redact_id("peer_id", _hex_bytes(row.get("peer_id_hex"))))
    payload.update(redact_id("node_id", _hex_bytes(row.get("node_id_hex"))))
    return payload


def _hex_bytes(value: object) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _tracker(
    tracker: str | None,
    complete: int | None,
    incomplete: int | None,
    downloaded: int | None,
) -> TrackerSnapshot | None:
    label = tracker or ""
    if complete is None and incomplete is None and downloaded is None and not label:
        return None
    if complete is None or incomplete is None:
        raise ToolError(
            "tracker_complete and tracker_incomplete are both required when scrape data is set",
            code="invalid_argument",
        )
    if complete < 0 or incomplete < 0 or (downloaded is not None and downloaded < 0):
        raise ToolError("tracker counters must be >= 0", code="invalid_argument")
    return TrackerSnapshot(complete=complete, incomplete=incomplete, downloaded=downloaded, tracker=label)


def _apply_thresholds(current: WatchThresholds, session: Session, **overrides: Any) -> None:
    if all(value is None for value in overrides.values()):
        return
    session.watch.thresholds = WatchThresholds(
        min_peers=current.min_peers if overrides["min_peers"] is None else overrides["min_peers"],
        min_diversity=current.min_diversity if overrides["min_diversity"] is None else overrides["min_diversity"],
        min_peers_for_diversity=(
            current.min_peers_for_diversity
            if overrides["min_peers_for_diversity"] is None
            else overrides["min_peers_for_diversity"]
        ),
        max_prefix_share=(
            current.max_prefix_share if overrides["max_prefix_share"] is None else overrides["max_prefix_share"]
        ),
        min_seeders=current.min_seeders if overrides["min_seeders"] is None else overrides["min_seeders"],
        spike_ratio=current.spike_ratio if overrides["spike_ratio"] is None else overrides["spike_ratio"],
        spike_min_previous=current.spike_min_previous,
    )


def _geo(labels: dict[str, str] | None) -> Any:
    if labels is None:
        return None
    if not isinstance(labels, dict):
        raise ToolError("geo_labels must be an object of ip -> label", code="invalid_argument")
    cleaned: dict[str, str] = {}
    for key, value in labels.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ToolError("geo_labels entries must be strings", code="invalid_argument")
        cleaned[key] = value

    def lookup(ip: str) -> str | None:
        return cleaned.get(ip)

    return lookup


def _population(
    rows: list[PeerTableRow],
    geo_labels: dict[str, str] | None,
    limit: int | None,
    offset: int | None,
) -> dict[str, Any]:
    report: PopulationReport = analyze_peers(_records(rows), geo=_geo(geo_labels))
    body = report.to_dict()
    findings = body.pop("findings")
    if not isinstance(findings, list):
        raise ToolError("population report findings were not a list", code="invalid_argument")
    window = page(findings, limit, offset)
    body["findings"] = window["items"]
    body["findings_total"] = window["total"]
    body["findings_truncated"] = window["truncated"]
    body["limit"] = window["limit"]
    body["offset"] = window["offset"]
    return body


def _analyze_rows(
    *,
    infohash: str | None,
    peers: list[dict[str, Any]] | None,
    session_id: str | None,
) -> tuple[list[PeerTableRow], str | None]:
    if peers is not None:
        return _peer_rows(peers), None
    if not infohash:
        raise ToolError(
            "peers or infohash is required",
            code="missing_argument",
            hint="Pass peers=[...] or infohash of a table stored by dhtrack_swarm_observe.",
        )
    session = _session(session_id)
    key = _infohash(infohash).hex()
    stored = session.get_peers(key)
    if stored is None:
        raise ToolError(
            "no peer table stored for that infohash",
            code="not_found",
            hint="Call dhtrack_swarm_observe first, or pass peers=[...].",
        )
    note = None
    if stored["truncated"]:
        note = f"session kept {stored['stored']} of {stored['peer_count']} peers"
    return _peer_rows(stored["peers"]), note


def _store_runtime_peers(session_id: str | None, info_hash_hex: str, rows: list[dict[str, Any]]) -> None:
    if not _wants_session(session_id):
        return
    session = _session(session_id)
    normalized = []
    for row in rows:
        item: dict[str, Any] = {"ip": row.get("ip"), "port": row.get("port")}
        node_id = row.get("node_id")
        peer_id = row.get("peer_id")
        if isinstance(node_id, bytes):
            item["node_id_hex"] = node_id.hex()
        if isinstance(peer_id, bytes):
            item["peer_id_hex"] = peer_id.hex()
        if isinstance(row.get("is_seeder"), bool):
            item["is_seeder"] = row["is_seeder"]
        normalized.append(item)
    session.put_peers(info_hash_hex, normalized, observed_at=time.time())
    session.flush()


_missing = [name for name in TOOLS if name not in HANDLERS]
_extra = [name for name in HANDLERS if name not in TOOLS]
if _missing or _extra:
    raise RuntimeError(f"MCP tool handlers drifted from capabilities. missing={_missing} extra={_extra}")
