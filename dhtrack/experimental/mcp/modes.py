"""Three operating modes: archive, observe, analyze.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.

The split follows hardly's archive / headless / interactive idea, mapped onto
DHT inspect work instead of HAR capture. Observe is the only mode whose
playbook contains confirm-gated network calls.
"""

from __future__ import annotations

from typing import Any

MODE_ARCHIVE = "archive"
MODE_OBSERVE = "observe"
MODE_ANALYZE = "analyze"

MODES: tuple[dict[str, Any], ...] = (
    {
        "id": MODE_ARCHIVE,
        "title": "Archive (catalog, alerts, and peer tables already on disk)",
        "when": (
            "A session sqlite, catalog snapshot, or saved peer table is already available. No DHT socket is required."
        ),
        "needs_network": False,
        "entry_tools": [
            "dhtrack_session_open",
            "dhtrack_session_overview",
            "dhtrack_catalog_list",
            "dhtrack_session_report",
        ],
        "tools": [
            "dhtrack_session_open",
            "dhtrack_session_overview",
            "dhtrack_session_report",
            "dhtrack_catalog_list",
            "dhtrack_catalog_get",
            "dhtrack_swarm_observe",
            "dhtrack_write_catalog_snapshot",
            "dhtrack_write_swarm_alerts",
        ],
        "steps": [
            "dhtrack_session_open(path) loads a sqlite session, or omit path for an in-memory one",
            "dhtrack_session_overview for infohash, peer, and alert counts",
            "dhtrack_catalog_list / dhtrack_catalog_get to page the infohash catalog",
            "dhtrack_session_report for threshold findings already stored",
            "dhtrack_write_catalog_snapshot or dhtrack_write_swarm_alerts to export JSONL",
        ],
    },
    {
        "id": MODE_OBSERVE,
        "title": "Observe (one confirm-gated DHT sample or lookup)",
        "when": (
            "You need a live sample_infohashes or get_peers. The node binds a "
            "UDP port only after confirm=true, and it does not dial bootstrap "
            "routers unless bootstrap endpoints were passed in that same call."
        ),
        "needs_network": True,
        "entry_tools": [
            "dhtrack_node_status",
            "dhtrack_node_start",
            "dhtrack_send_sample_infohashes",
            "dhtrack_send_get_peers",
        ],
        "tools": [
            "dhtrack_node_status",
            "dhtrack_node_start",
            "dhtrack_node_stop",
            "dhtrack_send_sample_infohashes",
            "dhtrack_send_get_peers",
            "dhtrack_send_catalog_sample_round",
            "dhtrack_session_open",
            "dhtrack_catalog_list",
        ],
        "steps": [
            "dhtrack_node_start without confirm returns the bind plan and sends nothing",
            "Repeat dhtrack_node_start(confirm=true) to bind. Pass bootstrap only if routers should be contacted",
            "dhtrack_send_sample_infohashes(confirm=true) or dhtrack_send_get_peers(infohash, confirm=true) once",
            "Ingest a captured BEP 51 reply with dhtrack_send_catalog_sample_round(replies, confirm=true)",
            "dhtrack_node_stop, then continue in archive mode",
        ],
    },
    {
        "id": MODE_ANALYZE,
        "title": "Analyze (peer table already collected)",
        "when": "A peer list is already in hand. Scoring it does not open a socket.",
        "needs_network": False,
        "entry_tools": [
            "dhtrack_peer_report",
            "dhtrack_swarm_analyze",
            "dhtrack_swarm_observe",
        ],
        "tools": [
            "dhtrack_peer_report",
            "dhtrack_swarm_analyze",
            "dhtrack_swarm_observe",
            "dhtrack_write_peer_report",
            "dhtrack_write_swarm_alerts",
            "dhtrack_session_report",
        ],
        "steps": [
            "dhtrack_peer_report(peers) for address class, prefix, BEP 20 mix, and suspicion",
            "dhtrack_swarm_observe(infohash, peers) to score health and threshold alerts",
            "dhtrack_swarm_analyze(infohash) reuses the peers stored by the last observe",
            "dhtrack_write_peer_report(output_path) for the full JSON report",
        ],
    },
)


def list_modes() -> dict[str, Any]:
    """Short catalog of operating modes."""
    return {
        "modes": [
            {
                "id": mode["id"],
                "title": mode["title"],
                "when": mode["when"],
                "needs_network": mode["needs_network"],
                "entry_tools": list(mode["entry_tools"]),
            }
            for mode in MODES
        ],
        "summary": [
            "archive — open a session sqlite or memory index and query it; no socket",
            "observe — dhtrack_node_start / send_get_peers / send_sample_infohashes; confirm=true to act",
            "analyze — dhtrack_peer_report or dhtrack_swarm_analyze on a peer table; no socket",
        ],
        "pick": "Call dhtrack_guide_mode(mode) for a playbook, or dhtrack_guide_mode(goal=...) to pick.",
        "rule": (
            "Saved catalog or peer table -> archive or analyze. "
            "Need a live DHT lookup -> observe, and read the plan before confirm=true."
        ),
    }


def get_mode(mode_id: str) -> dict[str, Any] | None:
    """Return one mode, honoring a few aliases."""
    key = (mode_id or "").strip().lower()
    aliases = {
        "file": MODE_ARCHIVE,
        "sqlite": MODE_ARCHIVE,
        "offline": MODE_ARCHIVE,
        "catalog": MODE_ARCHIVE,
        "live": MODE_OBSERVE,
        "dht": MODE_OBSERVE,
        "sample": MODE_OBSERVE,
        "node": MODE_OBSERVE,
        "peers": MODE_ANALYZE,
        "sybil": MODE_ANALYZE,
        "population": MODE_ANALYZE,
        "report": MODE_ANALYZE,
    }
    key = aliases.get(key, key)
    for mode in MODES:
        if mode["id"] == key:
            return dict(mode)
    return None


def pick_mode(*, goal: str = "", path: str = "", infohash: str = "", prefer: str = "") -> dict[str, Any]:
    """Choose a mode from a goal string. ``prefer`` wins when it names a mode."""
    if prefer:
        chosen = get_mode(prefer)
        if chosen is None:
            return {
                "error": f"unknown mode {prefer!r}",
                "code": "unknown_mode",
                "modes": [mode["id"] for mode in MODES],
            }
        return {
            "mode": chosen["id"],
            "reason": f"explicit mode {prefer!r}",
            "playbook": mode_playbook(chosen["id"], path=path, infohash=infohash, goal=goal),
        }

    text = (goal or "").strip().lower()
    observe_kw = ("observe", "live", "dht", "sample", "bootstrap", "crawl", "get_peers", "node")
    analyze_kw = ("analyze", "sybil", "suspicion", "population", "peer report", "bep 42", "bep42")
    archive_kw = ("archive", "catalog", "sqlite", "snapshot", "session", "jsonl")

    if any(word in text for word in observe_kw):
        mode_id = MODE_OBSERVE
        reason = "goal asks for a live DHT sample or lookup"
    elif any(word in text for word in analyze_kw):
        mode_id = MODE_ANALYZE
        reason = "goal asks to score a peer population"
    elif path or any(word in text for word in archive_kw):
        mode_id = MODE_ARCHIVE
        reason = "a saved session or catalog is the input" if path else "goal reads saved DHT observations"
    elif infohash and "peer" in text:
        mode_id = MODE_ANALYZE
        reason = "an infohash plus peers is an offline score"
    else:
        mode_id = MODE_ARCHIVE
        reason = "default is archive: open a session and query it before any socket"
    return {
        "mode": mode_id,
        "reason": reason,
        "playbook": mode_playbook(mode_id, path=path, infohash=infohash, goal=goal),
    }


def mode_playbook(
    mode_id: str,
    *,
    path: str = "",
    infohash: str = "",
    goal: str = "",
) -> dict[str, Any]:
    """Concrete steps and example tool calls for one mode."""
    mode = get_mode(mode_id)
    if mode is None:
        return {"error": f"unknown mode {mode_id!r}", "code": "unknown_mode", "modes": [item["id"] for item in MODES]}

    calls: list[dict[str, Any]] = []
    saved = (path or "").strip()
    target = (infohash or "").strip() or "<40 hex chars>"
    if mode["id"] == MODE_ARCHIVE:
        calls.append(
            {
                "tool": "dhtrack_session_open",
                "args": {"path": saved or "<session.sqlite>"} if saved else {},
                "note": "omit path for an in-memory session on the MCP server",
            }
        )
        calls.append({"tool": "dhtrack_session_overview", "args": {"session_id": "<from open>"}})
        calls.append({"tool": "dhtrack_catalog_list", "args": {"session_id": "<from open>", "limit": 50}})
    elif mode["id"] == MODE_OBSERVE:
        calls.append({"tool": "dhtrack_node_status", "args": {}})
        calls.append(
            {
                "tool": "dhtrack_node_start",
                "args": {"port": 0, "confirm": False},
                "note": "read the plan; repeat with confirm=true to bind. bootstrap is opt-in",
            }
        )
        calls.append(
            {
                "tool": "dhtrack_send_get_peers",
                "args": {"infohash": target, "confirm": False},
                "note": "plan only until confirm=true, and only if the node is already running",
            }
        )
    else:
        calls.append(
            {
                "tool": "dhtrack_peer_report",
                "args": {"peers": [{"ip": "203.0.113.10", "port": 6881}]},
                "note": "offline; pages findings and truncates ids",
            }
        )
        calls.append(
            {
                "tool": "dhtrack_swarm_observe",
                "args": {"infohash": target, "peers": [{"ip": "203.0.113.10", "port": 6881}]},
            }
        )

    payload: dict[str, Any] = {
        "mode": mode["id"],
        "title": mode["title"],
        "when": mode["when"],
        "needs_network": mode["needs_network"],
        "steps": list(mode["steps"]),
        "calls": calls,
        "entry_tools": list(mode["entry_tools"]),
        "tools": list(mode["tools"]),
    }
    if goal:
        payload["goal"] = goal
    if saved:
        payload["path"] = saved
    if infohash:
        payload["infohash"] = infohash
    return payload
