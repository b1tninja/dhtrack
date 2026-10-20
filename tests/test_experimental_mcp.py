"""Offline tests for the experimental MCP surface.

No live DHT. A blocked node factory fails the test if a confirm path constructs
the real runtime without a fake installed over it.
"""

from __future__ import annotations

import json
import socket
from typing import Any

import pytest

from dhtrack.cli import main as dhtrack_main
from dhtrack.experimental.cli import main as experimental_main
from dhtrack.experimental.infohash_catalog import SampleReply, SampleTransport
from dhtrack.experimental.mcp import __main__ as mcp_main
from dhtrack.experimental.mcp.capabilities import FEATURES, TOOLS, capabilities
from dhtrack.experimental.mcp.modes import MODES
from dhtrack.experimental.mcp.node import LiveNodeRuntime, controller, install_node_runtime
from dhtrack.experimental.mcp.service import call_tool, install_sample_transport, reset_state

INFOHASH = "ab" * 20


class CountingTransport(SampleTransport):
    def __init__(self, replies: dict[tuple[str, int], SampleReply] | None = None) -> None:
        self.calls = 0
        self.replies = replies or {}

    def sample(self, ip: str, port: int) -> SampleReply | None:
        self.calls += 1
        return self.replies.get((ip, port))


class FakeRuntime:
    def __init__(self) -> None:
        self.starts = 0
        self.gets = 0
        self.samples = 0
        self.stopped = 0
        self.bootstrap: list[tuple[str, int]] = []
        self.running = False
        self.peers = [
            {"ip": f"198.51.100.{(index % 200) + 1}", "port": 6881, "node_id": bytes([index % 256]) * 20}
            for index in range(250)
        ]

    def start(self, *, port: int, bootstrap: list[tuple[str, int]], bind_host: str) -> dict[str, Any]:
        self.starts += 1
        self.running = True
        self.bootstrap = list(bootstrap)
        return {
            "running": True,
            "bind_host": bind_host,
            "port": port,
            "bootstrap": [{"ip": ip, "port": item_port} for ip, item_port in bootstrap],
            "outbound": bool(bootstrap),
            "node_id_hex": "11" * 20,
            "live": False,
        }

    def stop(self) -> dict[str, Any]:
        self.stopped += 1
        self.running = False
        return {
            "running": False,
            "bind_host": None,
            "port": None,
            "bootstrap": [],
            "outbound": False,
            "node_id_hex": None,
            "live": False,
        }

    def status(self) -> dict[str, Any]:
        if not self.running:
            return {
                "running": False,
                "bind_host": None,
                "port": None,
                "bootstrap": [],
                "outbound": False,
                "node_id_hex": None,
                "live": False,
            }
        return {
            "running": True,
            "bind_host": "127.0.0.1",
            "port": 0,
            "bootstrap": [{"ip": ip, "port": item_port} for ip, item_port in self.bootstrap],
            "outbound": bool(self.bootstrap),
            "node_id_hex": "11" * 20,
            "live": False,
        }

    def get_peers(self, info_hash: bytes) -> list[dict[str, Any]]:
        self.gets += 1
        assert len(info_hash) == 20
        return list(self.peers)

    def sample_infohashes(self) -> dict[str, Any]:
        self.samples += 1
        return {
            "calls": 1,
            "returned_infohashes": 0,
            "respects_interval": True,
            "autonomous_loop": False,
            "note": "fake",
        }


def _block_live() -> Any:
    raise AssertionError("live DHT runtime is blocked in unit tests")


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    reset_state()
    controller.set_factory(_block_live)
    yield
    reset_state()


def _peers(count: int = 8) -> list[dict[str, Any]]:
    return [{"ip": f"203.0.113.{index}", "port": 6880 + index, "is_seeder": False} for index in range(1, count + 1)]


def test_capabilities_advertise_the_v0_surface() -> None:
    caps = capabilities()
    assert caps["name"] == "dhtrack"
    assert caps["version"]
    assert caps["tool_count"] == len(TOOLS) == 23
    assert caps["tools"] == list(TOOLS)
    assert caps["node_running"] is False
    assert len(caps["modes"]) == 3
    assert {mode["id"] for mode in caps["modes"]} == {"archive", "observe", "analyze"}
    for feature in ("confirm_gate", "write_overwrite_guard", "pagination", "peer_id_truncation", "api_surface_v0"):
        assert feature in caps["features"]
    assert list(FEATURES) == caps["features"]
    assert "dhtrack_send_get_peers" in caps["tools"]
    status = call_tool("dhtrack_server_status")
    assert status["capabilities"]["tools"] == list(TOOLS)
    for mode in MODES:
        for name in mode["tools"] + mode["entry_tools"]:
            assert name in TOOLS


def test_guide_picks_archive_by_default_and_observe_for_a_live_goal() -> None:
    listed = call_tool("dhtrack_guide_mode")
    assert [mode["id"] for mode in listed["modes"]] == ["archive", "observe", "analyze"]
    plan = call_tool("dhtrack_guide_task_plan", {"goal": "read the catalog sqlite", "path": "session.sqlite"})
    assert plan["mode"] == "archive"
    assert plan["environment"]["node_running"] is False
    assert plan["calls"][0]["tool"] == "dhtrack_session_open"
    live = call_tool("dhtrack_guide_mode", {"goal": "sample the live DHT once"})
    assert live["mode"] == "observe"
    assert live["playbook"]["needs_network"] is True
    analyze = call_tool("dhtrack_guide_task_plan", {"goal": "suspicion score for this peer population"})
    assert analyze["mode"] == "analyze"
    unknown = call_tool("dhtrack_guide_mode", {"mode": "headless"})
    assert unknown["code"] == "unknown_mode"
    help_payload = call_tool("dhtrack_guide_help", {"topic": "send"})
    assert any(tool["name"] == "dhtrack_send_get_peers" for tool in help_payload["tools"])
    missing = call_tool("dhtrack_guide_help", {"topic": "hardly_browser_start"})
    assert missing["code"] == "unknown_topic"


def test_session_round_trip_keeps_edge_triggered_alerts_quiet(tmp_path) -> None:
    path = tmp_path / "session.sqlite"
    opened = call_tool("dhtrack_session_open", {"path": str(path)})
    assert opened["session_id"] == "s1"
    assert opened["created"] is True
    peers = _peers()
    first = call_tool(
        "dhtrack_swarm_observe",
        {"session_id": "s1", "infohash": INFOHASH, "peers": peers, "now": 10, "name": "lab"},
    )
    assert first["snapshot"]["peer_count"] == 8
    assert "prefix_concentration" in {alert["kind"] for alert in first["alerts"]}
    overview = call_tool("dhtrack_session_overview", {"session_id": "s1"})
    assert overview["infohashes"] == 0
    assert overview["peers"] == 8
    assert overview["alerts"] == 1
    assert overview["last_observe_at"] == 10
    call_tool("dhtrack_session_close", {"session_id": "s1"})

    reopened = call_tool("dhtrack_session_open", {"path": str(path)})
    assert reopened["alerts"] == 1
    second = call_tool(
        "dhtrack_swarm_observe",
        {"infohash": INFOHASH, "peers": peers, "now": 20},
    )
    assert second["alert_count"] == 0
    report = call_tool("dhtrack_session_report")
    assert report["severity"]["warning"] == 1
    assert report["alerts"][0]["kind"] == "prefix_concentration"
    assert "prefix_concentration" in report["active_alerts"][INFOHASH]


def test_catalog_sample_round_is_confirm_gated_and_respects_the_schedule() -> None:
    call_tool("dhtrack_session_open")
    info_hash = bytes(range(20))
    endpoints = [{"ip": "192.0.2.8", "port": 6881}, {"ip": "2001:db8::1", "port": 1}]
    transport = CountingTransport({("192.0.2.8", 6881): SampleReply(samples=info_hash, num=1, interval=10)})
    install_sample_transport(transport)
    plan = call_tool(
        "dhtrack_send_catalog_sample_round",
        {"endpoints": endpoints, "confirm": False, "now": 50},
    )
    assert plan["confirmed"] is False
    assert plan["sent"] is False
    assert plan["plan"]["opens_sockets"] is False
    assert transport.calls == 0

    done = call_tool(
        "dhtrack_send_catalog_sample_round",
        {"endpoints": endpoints, "confirm": True, "now": 50},
    )
    assert done["executed"] is True
    assert done["sent"] is False
    assert done["queried"] == 2
    assert done["answered"] == 1
    assert done["observations"] == 1
    assert transport.calls == 2
    listed = call_tool("dhtrack_catalog_list")
    assert listed["infohashes"][0]["info_hash_hex"] == info_hash.hex()
    got = call_tool("dhtrack_catalog_get", {"infohash": info_hash.hex()})
    assert got["record"]["hit_count"] == 1

    early = call_tool(
        "dhtrack_send_catalog_sample_round",
        {"endpoints": endpoints, "confirm": True, "now": 55},
    )
    assert early["queried"] == 0
    assert transport.calls == 2

    refused = call_tool(
        "dhtrack_send_catalog_sample_round",
        {"endpoints": [{"ip": "192.0.2.9", "port": 1}], "confirm": True, "now": 10},
    )
    install_sample_transport(None)
    # The override is still installed above; clear it and refuse a bare confirm.
    install_sample_transport(None)
    missing = call_tool(
        "dhtrack_send_catalog_sample_round",
        {"endpoints": [{"ip": "192.0.2.9", "port": 1}], "confirm": True, "now": 10},
    )
    assert missing["code"] == "transport_required"
    assert refused["executed"] is True


def test_catalog_round_replays_replies_without_a_socket(monkeypatch) -> None:
    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("socket created")

    monkeypatch.setattr(socket, "socket", _boom)
    call_tool("dhtrack_session_open")
    info_hash = bytes(range(20))
    result = call_tool(
        "dhtrack_send_catalog_sample_round",
        {
            "endpoints": [{"ip": "192.0.2.8", "port": 6881}],
            "replies": {"192.0.2.8|6881": {"samples_hex": info_hash.hex(), "num": 1, "interval": 30}},
            "confirm": True,
            "now": 5,
        },
    )
    assert result["answered"] == 1
    assert result["opens_sockets"] is False
    dry = call_tool(
        "dhtrack_node_start",
        {"confirm": False, "port": 0},
    )
    assert dry["started"] is False
    assert dry["plan"]["bootstrap"] == []
    assert dry["plan"]["default_bootstrap"] is False
    assert "router.bittorrent.com" not in json.dumps(dry)
    peers = call_tool("dhtrack_send_get_peers", {"infohash": INFOHASH, "confirm": False})
    assert peers["sent"] is False
    sample = call_tool("dhtrack_send_sample_infohashes", {"confirm": False})
    assert sample["sent"] is False
    assert sample["plan"]["autonomous_loop"] is False


def test_write_tools_refuse_to_overwrite(tmp_path) -> None:
    call_tool("dhtrack_session_open")
    call_tool(
        "dhtrack_swarm_observe",
        {"infohash": INFOHASH, "peers": _peers(), "now": 1},
    )
    snapshot = tmp_path / "catalog.jsonl"
    alerts = tmp_path / "alerts.jsonl"
    report = tmp_path / "report.json"
    snapshot.write_text("keep\n", encoding="utf-8")
    refused = call_tool("dhtrack_write_catalog_snapshot", {"output_path": str(snapshot)})
    assert refused["code"] == "output_exists"
    assert snapshot.read_text(encoding="utf-8") == "keep\n"
    written = call_tool(
        "dhtrack_write_catalog_snapshot",
        {"output_path": str(snapshot), "overwrite": True},
    )
    assert written["rows"] == 0
    alerts.write_text("keep\n", encoding="utf-8")
    assert call_tool("dhtrack_write_swarm_alerts", {"output_path": str(alerts)})["code"] == "output_exists"
    saved = call_tool("dhtrack_write_swarm_alerts", {"output_path": str(alerts), "overwrite": True})
    assert saved["rows"] == 1
    assert "prefix_concentration" in alerts.read_text(encoding="utf-8")
    report.write_text("{}\n", encoding="utf-8")
    assert (
        call_tool(
            "dhtrack_write_peer_report",
            {"output_path": str(report), "infohash": INFOHASH},
        )["code"]
        == "output_exists"
    )
    full = call_tool(
        "dhtrack_write_peer_report",
        {"output_path": str(report), "infohash": INFOHASH, "overwrite": True},
    )
    assert full["suspicion"] == 0.45
    body = json.loads(report.read_text(encoding="utf-8"))
    assert body["peer_count"] == 8
    assert len(body["findings"]) == 8


def test_peer_report_pages_findings_and_truncates_ids() -> None:
    peers = []
    for index in range(120):
        peers.append(
            {
                "ip": f"203.0.113.{(index % 250) + 1}",
                "port": 1000 + index,
                "peer_id_hex": bytes([index % 256]).hex() * 20,
                "node_id_hex": "ff" * 20,
            }
        )
    call_tool("dhtrack_session_open")
    observed = call_tool(
        "dhtrack_swarm_observe",
        {"infohash": INFOHASH, "peers": peers, "include_peers": True, "now": 3},
    )
    window = observed["peers"]
    assert window["total"] == 120
    assert window["count"] == 50
    assert window["truncated"] is True
    encoded = json.dumps(window)
    assert "ff" * 20 not in encoded
    assert window["items"][0]["peer_id_truncated"] is True
    assert len(window["items"][0]["peer_id_prefix"]) == 8
    report = call_tool("dhtrack_peer_report", {"peers": peers[:2], "geo_labels": {"203.0.113.1": "lab"}})
    assert report["peer_count"] == 2
    assert report["geo_labels"] == {"lab": 1}
    assert report["suspicion"] == 0.0
    assert report["findings_total"] == 2
    paged = call_tool("dhtrack_swarm_analyze", {"infohash": INFOHASH, "limit": 10, "offset": 100})
    assert paged["findings_total"] == 120
    assert paged["limit"] == 10
    assert len(paged["findings"]) == 10
    assert paged["bep42_checked"] == 120
    assert paged["suspicion"] > 0
    listed = call_tool("dhtrack_catalog_list", {"limit": 1})
    assert listed["total"] == 0


def test_two_sessions_require_an_id() -> None:
    call_tool("dhtrack_session_open")
    call_tool("dhtrack_session_open")
    listed = call_tool("dhtrack_session_list")
    assert listed["count"] == 2
    missing = call_tool("dhtrack_session_overview")
    assert missing["code"] == "ambiguous_session"
    bad = call_tool("dhtrack_catalog_get", {"infohash": "zz", "session_id": "s1"})
    assert bad["code"] == "invalid_argument"
    absent = call_tool("dhtrack_catalog_get", {"infohash": INFOHASH, "session_id": "missing"})
    assert absent["code"] == "unknown_session"


def test_confirmed_node_tools_use_the_fake_runtime_once() -> None:
    fake = FakeRuntime()
    install_node_runtime(fake)
    plan = call_tool("dhtrack_node_start", {"confirm": False, "bootstrap": [{"host": "router.example", "port": 6881}]})
    assert plan["started"] is False
    assert fake.starts == 0
    started = call_tool(
        "dhtrack_node_start",
        {"confirm": True, "bind_host": "127.0.0.1", "port": 0, "bootstrap": [{"host": "192.0.2.1", "port": 6881}]},
    )
    assert started["started"] is True
    assert started["sent"] is True
    assert started["node"]["outbound"] is True
    assert fake.starts == 1
    assert fake.bootstrap == [("192.0.2.1", 6881)]
    dry_peers = call_tool("dhtrack_send_get_peers", {"infohash": INFOHASH, "confirm": False})
    assert dry_peers["sent"] is False
    assert fake.gets == 0
    peers = call_tool("dhtrack_send_get_peers", {"infohash": INFOHASH, "confirm": True, "limit": 25})
    assert peers["sent"] is True
    assert peers["total"] == 250
    assert peers["count"] == 25
    assert peers["truncated"] is True
    assert fake.gets == 1
    assert "00" * 20 not in json.dumps(peers["peers"])
    dry_sample = call_tool("dhtrack_send_sample_infohashes", {"confirm": False})
    assert dry_sample["sent"] is False
    assert fake.samples == 0
    sampled = call_tool("dhtrack_send_sample_infohashes", {"confirm": True})
    assert sampled["sent"] is True
    assert sampled["calls"] == 1
    assert sampled["autonomous_loop"] is False
    assert fake.samples == 1
    idle = call_tool("dhtrack_send_get_peers", {"infohash": INFOHASH, "confirm": True})
    # still running, so this is the second real call
    assert idle["sent"] is True
    stopped = call_tool("dhtrack_node_stop")
    assert stopped["stopped"] is True
    assert fake.stopped >= 1
    refused = call_tool("dhtrack_send_get_peers", {"infohash": INFOHASH, "confirm": True})
    assert refused["code"] == "node_not_running"
    assert fake.gets == 2


def test_node_start_without_bootstrap_does_not_mark_outbound() -> None:
    fake = FakeRuntime()
    install_node_runtime(fake)
    started = call_tool("dhtrack_node_start", {"confirm": True, "port": 0})
    assert started["sent"] is False
    assert started["node"]["outbound"] is False
    assert started["node"]["bootstrap"] == []
    assert fake.bootstrap == []
    status = call_tool("dhtrack_node_status")
    assert status["running"] is True
    assert capabilities()["node_running"] is True


def test_live_runtime_does_not_bootstrap_unless_asked(monkeypatch) -> None:
    created: dict[str, Any] = {}

    class FakeNode:
        def __init__(self, **kwargs: Any) -> None:
            created["kwargs"] = kwargs
            self.node_id = b"\x22" * 20
            self.sock = None
            self.bootstraps: list[Any] = []

        async def start(self) -> None:
            created["started"] = True

        async def close_async(self) -> None:
            created["closed"] = True

        def bootstrap(self, nodes: Any = None) -> int:
            self.bootstraps.append(list(nodes or []))
            created["bootstrap"] = self.bootstraps
            return len(nodes or [])

        def sample_infohashes(self, target: Any = None) -> list[bytes]:
            created["sampled"] = True
            return []

        def iterative_get_peers(self, info_hash: bytes, **kwargs: Any) -> list[Any]:
            created["get"] = info_hash
            return []

    monkeypatch.setattr("dhtrack.dht.DHTNode", FakeNode)
    runtime = LiveNodeRuntime()
    try:
        status = runtime.start(port=0, bootstrap=[], bind_host="127.0.0.1")
        assert status["running"] is True
        assert status["outbound"] is False
        assert created["started"] is True
        assert "bootstrap" not in created
        assert created["kwargs"]["persist_node_identity"] is False
        sampled = runtime.sample_infohashes()
        assert sampled["calls"] == 1
        assert created["sampled"] is True
        assert runtime.get_peers(b"\x01" * 20) == []
    finally:
        runtime.stop()
    assert created["closed"] is True

    runtime = LiveNodeRuntime()
    try:
        status = runtime.start(port=0, bootstrap=[("192.0.2.10", 6881)], bind_host="127.0.0.1")
        assert status["outbound"] is True
        assert status["bootstrap_contacted"] == 1
    finally:
        runtime.stop()


def test_cli_verbs_match_the_tools(tmp_path, capsys) -> None:
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps(_peers()), encoding="utf-8")
    session = tmp_path / "session.sqlite"
    assert experimental_main(["peer", "report", "--peers", str(peers)]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["suspicion"] == 0.45
    assert experimental_main(["node", "start", "--port", "0"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["confirmed"] is False
    assert plan["plan"]["default_bootstrap"] is False
    assert (
        experimental_main(
            [
                "swarm",
                "observe",
                "--path",
                str(session),
                "--infohash",
                INFOHASH,
                "--peers",
                str(peers),
                "--now",
                "10",
            ]
        )
        == 0
    )
    observed = json.loads(capsys.readouterr().out)
    assert observed["snapshot"]["peer_count"] == 8
    assert experimental_main(["session", "overview", "--path", str(session)]) == 0
    overview = json.loads(capsys.readouterr().out)
    assert overview["peers"] == 8
    target = tmp_path / "alerts.jsonl"
    target.write_text("x", encoding="utf-8")
    assert experimental_main(["write", "swarm-alerts", "--path", str(session), "--output", str(target)]) == 1
    error = json.loads(capsys.readouterr().err)
    assert error["code"] == "output_exists"
    assert target.read_text(encoding="utf-8") == "x"


def test_mcp_server_registers_the_same_tools() -> None:
    pytest.importorskip("mcp.server.mcpserver")
    import anyio

    from dhtrack.experimental.mcp.server import build_server

    server = build_server()
    tools = anyio.run(server.list_tools)
    assert [tool.name for tool in tools] == list(TOOLS)
    start = next(tool for tool in tools if tool.name == "dhtrack_node_start")
    assert "confirm" in start.input_schema["properties"]
    assert start.input_schema["properties"]["confirm"].get("default") is False
    sample = next(tool for tool in tools if tool.name == "dhtrack_send_catalog_sample_round")
    assert "replies" in sample.input_schema["properties"]
    assert "confirm" in sample.input_schema["properties"]


def test_help_entries_do_not_start_a_server() -> None:
    with pytest.raises(SystemExit) as caught:
        experimental_main(["serve", "--help"])
    assert caught.value.code == 0
    with pytest.raises(SystemExit) as caught:
        mcp_main.main(["--help"])
    assert caught.value.code == 0
    with pytest.raises(SystemExit) as caught:
        dhtrack_main(["serve", "--help"])
    assert caught.value.code == 0


def test_output_path_refuses_an_existing_different_file(tmp_path) -> None:
    source = tmp_path / "source.sqlite"
    sink = tmp_path / "sink.sqlite"
    call_tool("dhtrack_session_open", {"path": str(source)})
    call_tool("dhtrack_session_close", {"session_id": "s1"})
    sink.write_text("not empty", encoding="utf-8")
    refused = call_tool("dhtrack_session_open", {"path": str(source), "output_path": str(sink)})
    assert refused["code"] == "output_exists"
    copied = tmp_path / "copy.sqlite"
    opened = call_tool("dhtrack_session_open", {"path": str(source), "output_path": str(copied)})
    assert opened["durable"] is True
    assert copied.exists()


# --- review follow-ups --------------------------------------------------------


@pytest.fixture
def write_root(tmp_path) -> Any:
    from dhtrack.experimental.mcp.gates import set_write_root

    root = set_write_root(tmp_path)
    yield root
    set_write_root(None)


def test_writes_are_confined_to_the_root(write_root) -> None:
    outside = write_root.parent / "escape.json"
    for target in (str(outside), "../escape.json"):
        refused = call_tool("dhtrack_write_peer_report", {"output_path": target, "peers": _peers()})
        assert refused["code"] == "path_outside_root"
    assert not outside.exists()
    done = call_tool("dhtrack_write_peer_report", {"output_path": "sub/report.json", "peers": _peers()})
    assert done["path"] == str(write_root / "sub" / "report.json")
    refused = call_tool("dhtrack_session_open", {"path": str(outside.with_suffix(".sqlite"))})
    assert refused["code"] == "path_outside_root"


def test_session_open_refuses_empty_files_duplicates_and_stray_sources(tmp_path) -> None:
    empty = tmp_path / "placeholder.lock"
    empty.write_bytes(b"")
    assert call_tool("dhtrack_session_open", {"path": str(empty)})["code"] == "invalid_session_file"
    assert empty.read_bytes() == b""
    missing = tmp_path / "new" / "a.sqlite"
    copy = tmp_path / "b.sqlite"
    refused = call_tool("dhtrack_session_open", {"path": str(missing), "output_path": str(copy)})
    assert refused["code"] == "invalid_session_file"
    assert not missing.exists() and not missing.parent.exists() and not copy.exists()
    first = call_tool("dhtrack_session_open", {"path": str(tmp_path / "s.sqlite")})
    again = call_tool("dhtrack_session_open", {"path": str(tmp_path / "s.sqlite")})
    assert again["code"] == "session_already_open"
    assert first["session_id"] in again["hint"]


def test_session_survives_tool_calls_on_different_threads(tmp_path) -> None:
    import threading

    from dhtrack.experimental.mcp.server import _wrap
    from dhtrack.experimental.mcp.service import HANDLERS

    opened = json.loads(_wrap(HANDLERS["dhtrack_session_open"])(path=str(tmp_path / "t.sqlite")))
    result: dict[str, Any] = {}

    def observe() -> None:
        result["out"] = json.loads(
            _wrap(HANDLERS["dhtrack_swarm_observe"])(infohash=INFOHASH, peers=_peers(), session_id=opened["session_id"])
        )

    worker = threading.Thread(target=observe)
    worker.start()
    worker.join()
    assert "error" not in result["out"], result["out"]
    assert result["out"]["session_id"] == opened["session_id"]


def test_concurrent_starts_bind_once() -> None:
    import threading

    gate = threading.Event()
    starts: list[int] = []

    class SlowRuntime(FakeRuntime):
        def start(self, **kwargs: Any) -> dict[str, Any]:
            starts.append(1)
            gate.wait(timeout=5)
            return super().start(**kwargs)

    install_node_runtime(SlowRuntime())
    results: list[dict[str, Any]] = []
    first = threading.Thread(target=lambda: results.append(call_tool("dhtrack_node_start", {"confirm": True})))
    first.start()
    while not starts:
        pass
    second = call_tool("dhtrack_node_start", {"confirm": True})
    gate.set()
    first.join()
    assert second["code"] == "node_already_running"
    assert results[0]["started"] is True
    assert len(starts) == 1


def test_node_start_defaults_to_loopback_and_flags_inbound() -> None:
    plan = call_tool("dhtrack_node_start", {})
    assert plan["plan"]["bind_host"] == "127.0.0.1"
    assert plan["plan"]["accepts_inbound"] is False
    public = call_tool("dhtrack_node_start", {"bind_host": "0.0.0.0"})
    assert public["plan"]["accepts_inbound"] is True
    assert "answer" in public["plan"]["note"]


def test_live_runtime_reports_skipped_sends_and_seeders(monkeypatch) -> None:
    class StoredPeer:
        ip = "198.51.100.9"
        port = 6881
        node_id = None
        is_seed = True

    class Table:
        buckets: list[Any] = []

    class FakeNode:
        def __init__(self, **kwargs: Any) -> None:
            self.node_id = b"\x22" * 20
            self.sock = None
            self.routing_table = type("RT", (), {"v4": Table(), "v6": Table()})()

        async def start(self) -> None:
            return None

        async def close_async(self) -> None:
            return None

        def sample_infohashes(self, target: Any = None) -> bool:
            return False

        def iterative_get_peers(self, info_hash: bytes, **kwargs: Any) -> list[Any]:
            return [StoredPeer()]

    monkeypatch.setattr("dhtrack.dht.DHTNode", FakeNode)
    runtime = LiveNodeRuntime()
    install_node_runtime(runtime)
    try:
        call_tool("dhtrack_node_start", {"confirm": True})
        sampled = call_tool("dhtrack_send_sample_infohashes", {"confirm": True})
        assert sampled["sent"] is False
        peers = call_tool("dhtrack_send_get_peers", {"infohash": INFOHASH, "confirm": True})
        assert peers["sent"] is False
        assert peers["peers"][0]["is_seeder"] is True
    finally:
        call_tool("dhtrack_node_stop")


def test_oversized_agent_input_is_refused() -> None:
    from dhtrack.experimental.mcp.service import MAX_INPUT_ITEMS

    huge = [{"ip": "203.0.113.1", "port": 1}] * (MAX_INPUT_ITEMS + 1)
    assert call_tool("dhtrack_peer_report", {"peers": huge})["code"] == "input_too_large"
