"""Experimental proposals for headless dhtrack workflows.

These modules are suggestions for discussion. They are not part of the stable
dhtrack API, and importing them does not change DHT, tracker, or GUI behavior.

See ``docs/proposals/`` for the use case, the fit with the existing
architecture, and the limitations of each prototype. The draft MCP server
is ``python -m dhtrack.experimental.mcp``; it is documented in
``docs/proposals/mcp.md`` and is not imported from this package.
"""

from __future__ import annotations

from dhtrack.experimental.infohash_catalog import (
    CatalogState,
    InfohashCatalog,
    InfohashObservation,
    SampleReply,
    SampleRoundResult,
    SampleSchedule,
    parse_bep51_samples,
    run_sample_round,
    sample_reply_from_krpc,
)
from dhtrack.experimental.peer_analytics import (
    PopulationReport,
    address_class,
    analyze_peers,
)
from dhtrack.experimental.swarm_watch import (
    Alert,
    HealthSnapshot,
    SwarmWatch,
    WatchThresholds,
)

__all__ = [
    "Alert",
    "CatalogState",
    "HealthSnapshot",
    "InfohashCatalog",
    "InfohashObservation",
    "PopulationReport",
    "SampleReply",
    "SampleRoundResult",
    "SampleSchedule",
    "SwarmWatch",
    "WatchThresholds",
    "address_class",
    "analyze_peers",
    "parse_bep51_samples",
    "run_sample_round",
    "sample_reply_from_krpc",
]
