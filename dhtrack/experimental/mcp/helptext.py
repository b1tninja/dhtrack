"""Short catalog so an agent can pick a tool without reading the source.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
"""

from __future__ import annotations

from typing import Any

from dhtrack.experimental.mcp.capabilities import TOOLS

TOOL_BLURBS: dict[str, str] = {
    "dhtrack_server_status": "Version, feature flags, tool names, and whether a node is running.",
    "dhtrack_guide_help": "Categorized tool list. Pass topic to filter, or a tool name for one blurb.",
    "dhtrack_guide_mode": "List archive, observe, and analyze, or return one mode's playbook.",
    "dhtrack_guide_task_plan": "Ordered plan of tool calls for a goal, plus whether a node is running.",
    "dhtrack_session_open": "Open a sqlite session, or an in-memory one when path is omitted.",
    "dhtrack_session_close": "Flush and drop a session. Files already written stay on disk.",
    "dhtrack_session_list": "List sessions open in this process.",
    "dhtrack_session_overview": "Counts: infohashes, peers, alerts, last sample time, last observe time.",
    "dhtrack_session_report": "Threshold alerts stored for the session, newest first, paged.",
    "dhtrack_catalog_list": "Page infohashes in the session catalog, newest first.",
    "dhtrack_catalog_get": "One catalog row for a 40-hex infohash.",
    "dhtrack_write_catalog_snapshot": "Write the catalog as JSONL. Refuses to overwrite unless overwrite=true.",
    "dhtrack_send_catalog_sample_round": (
        "One BEP 51 round through a SampleTransport. confirm=true required; replies replay offline."
    ),
    "dhtrack_swarm_observe": "Score a peer list and optional tracker scrape. Offline. Stores alerts on the session.",
    "dhtrack_write_swarm_alerts": "Write stored alerts as JSONL. Refuses to overwrite unless overwrite=true.",
    "dhtrack_swarm_analyze": "Population report for peers last observed on an infohash, or for an inline peer list.",
    "dhtrack_peer_report": "Address class, prefix, BEP 20 mix, and suspicion for a peer list. Offline.",
    "dhtrack_write_peer_report": "Write the full population report JSON. Refuses to overwrite unless overwrite=true.",
    "dhtrack_node_status": "Whether a local DHT node is bound, and on which address. Does not start one.",
    "dhtrack_node_start": (
        "Plan a UDP bind. confirm=true binds. Bootstrap routers are contacted only if you passed them."
    ),
    "dhtrack_node_stop": "Stop the local node and drop the socket. Not confirm-gated.",
    "dhtrack_send_get_peers": "Plan or run one iterative get_peers on the running node. confirm=true sends.",
    "dhtrack_send_sample_infohashes": (
        "Plan or send one BEP 51 sample_infohashes. confirm=true sends. No follow-up loop."
    ),
}

_CATEGORIES: tuple[dict[str, Any], ...] = (
    {
        "id": "modes",
        "title": "Operating modes",
        "when": "Choose archive, observe, or analyze before other tools",
        "tools": [
            "dhtrack_guide_task_plan",
            "dhtrack_guide_mode",
            "dhtrack_guide_help",
            "dhtrack_server_status",
        ],
    },
    {
        "id": "session",
        "title": "Session",
        "when": "Open a sqlite or in-memory index of observations",
        "tools": [
            "dhtrack_session_open",
            "dhtrack_session_close",
            "dhtrack_session_list",
            "dhtrack_session_overview",
            "dhtrack_session_report",
        ],
    },
    {
        "id": "catalog",
        "title": "Infohash catalog",
        "when": "Read BEP 51 aggregates, or replay one sample round",
        "tools": [
            "dhtrack_catalog_list",
            "dhtrack_catalog_get",
            "dhtrack_write_catalog_snapshot",
            "dhtrack_send_catalog_sample_round",
        ],
    },
    {
        "id": "swarm",
        "title": "Swarm watch",
        "when": "Score a peer list and read threshold alerts",
        "tools": [
            "dhtrack_swarm_observe",
            "dhtrack_swarm_analyze",
            "dhtrack_write_swarm_alerts",
        ],
    },
    {
        "id": "peer",
        "title": "Peer analytics",
        "when": "Population and suspicion report for peers you already have",
        "tools": [
            "dhtrack_peer_report",
            "dhtrack_write_peer_report",
        ],
    },
    {
        "id": "node",
        "title": "Local node (observe)",
        "when": "Bind or stop a DHT node. Start is confirm-gated and does not bootstrap unless asked",
        "tools": [
            "dhtrack_node_status",
            "dhtrack_node_start",
            "dhtrack_node_stop",
        ],
    },
    {
        "id": "send",
        "title": "Outbound DHT (confirm-gated)",
        "when": "Without confirm=true these return a plan and send nothing",
        "tools": [
            "dhtrack_send_get_peers",
            "dhtrack_send_sample_infohashes",
            "dhtrack_send_catalog_sample_round",
        ],
    },
    {
        "id": "write",
        "title": "Files (overwrite-gated)",
        "when": "Refuse to replace an existing file unless overwrite=true",
        "tools": [
            "dhtrack_write_catalog_snapshot",
            "dhtrack_write_swarm_alerts",
            "dhtrack_write_peer_report",
        ],
    },
)


def tool_help(topic: str | None = None) -> dict[str, Any]:
    """Return the catalog, one category, or one tool blurb."""
    key = (topic or "").strip().lower()
    if not key:
        return {
            "topic": None,
            "categories": [
                {
                    "id": category["id"],
                    "title": category["title"],
                    "when": category["when"],
                    "tools": [{"name": name, "summary": TOOL_BLURBS[name]} for name in category["tools"]],
                }
                for category in _CATEGORIES
            ],
            "tool_count": len(TOOLS),
        }
    for category in _CATEGORIES:
        if key == category["id"]:
            return {
                "topic": category["id"],
                "title": category["title"],
                "when": category["when"],
                "tools": [{"name": name, "summary": TOOL_BLURBS[name]} for name in category["tools"]],
            }
    for name, summary in TOOL_BLURBS.items():
        if key == name or key == name.removeprefix("dhtrack_"):
            return {"topic": name, "summary": summary}
    known = [category["id"] for category in _CATEGORIES]
    return {
        "error": f"unknown help topic {topic!r}",
        "code": "unknown_topic",
        "hint": "Topics: " + ", ".join(known) + ", or a tool name.",
        "topics": known,
    }


if set(TOOL_BLURBS) != set(TOOLS):
    raise RuntimeError("help blurbs drifted from the advertised tool list")
