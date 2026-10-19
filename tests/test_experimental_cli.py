"""CLI tests for the experimental headless proposals."""

from __future__ import annotations

import json

import pytest

from dhtrack.experimental.cli import main


def test_help_without_a_command() -> None:
    assert main([]) == 2


def test_catalog_round_replays_replies_and_skips_early_retries(tmp_path, capsys) -> None:
    info_hash = bytes(range(20))
    endpoints = tmp_path / "endpoints.json"
    replies = tmp_path / "replies.json"
    state = tmp_path / "state.json"
    snapshot = tmp_path / "catalog.jsonl"
    endpoints.write_text(
        json.dumps(
            [
                {"ip": "192.0.2.8", "port": 6881},
                {"ip": "2001:db8::1", "port": 1},
            ]
        ),
        encoding="utf-8",
    )
    replies.write_text(
        json.dumps({"192.0.2.8|6881": {"samples_hex": info_hash.hex(), "num": 1, "interval": 10}}),
        encoding="utf-8",
    )
    args = [
        "catalog-round",
        "--endpoints",
        str(endpoints),
        "--replies",
        str(replies),
        "--state",
        str(state),
        "--snapshot",
        str(snapshot),
        "--now",
        "50",
    ]
    assert main(args) == 0
    assert "queried=2 answered=1 missed=1" in capsys.readouterr().out
    assert info_hash.hex() in snapshot.read_text(encoding="utf-8")

    assert main(args[:-1] + ["55"]) == 0
    assert "queried=0" in capsys.readouterr().out

    assert main(args[:-1] + ["60"]) == 0
    summary = capsys.readouterr().out
    assert "queried=1 answered=1" in summary
    assert "catalog_size=1" in summary
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["records"][0]["hit_count"] == 2


def test_watch_observe_writes_health_alerts_and_report(tmp_path, capsys) -> None:
    peers = [{"ip": f"203.0.113.{index}", "port": 6880 + index, "is_seeder": False} for index in range(1, 9)]
    peer_path = tmp_path / "peers.json"
    peer_path.write_text(json.dumps(peers), encoding="utf-8")
    state = tmp_path / "watch.json"
    health = tmp_path / "health.jsonl"
    alerts = tmp_path / "alerts.jsonl"
    report = tmp_path / "report.json"
    code = main(
        [
            "watch-observe",
            "--infohash",
            "ab" * 20,
            "--peers",
            str(peer_path),
            "--name",
            "lab",
            "--state",
            str(state),
            "--health",
            str(health),
            "--alerts",
            str(alerts),
            "--analyze",
            str(report),
            "--now",
            "10",
            "--min-seeders",
            "1",
        ]
    )
    assert code == 0
    assert "prefix_concentration" in capsys.readouterr().out
    health_row = json.loads(health.read_text(encoding="utf-8"))
    assert health_row["display_name"] == "lab"
    assert health_row["peer_count"] == 8
    alert_text = alerts.read_text(encoding="utf-8")
    assert "prefix_concentration" in alert_text
    assert "seeders_below" in alert_text
    body = json.loads(report.read_text(encoding="utf-8"))
    assert body["suspicion"] == 0.45
    assert body["address_classes"]["documentation"] == 8


def test_analyze_peers_geo_and_csv(tmp_path, capsys) -> None:
    peers = [{"ip": "1.1.1.1", "port": 6881}, {"ip": "8.8.8.8", "port": 6882}]
    peer_path = tmp_path / "peers.json"
    geo = tmp_path / "geo.json"
    out = tmp_path / "out.json"
    csv_path = tmp_path / "out.csv"
    peer_path.write_text(json.dumps(peers), encoding="utf-8")
    geo.write_text(json.dumps({"1.1.1.1": "AS13335"}), encoding="utf-8")
    assert (
        main(
            [
                "analyze-peers",
                "--peers",
                str(peer_path),
                "--out",
                str(out),
                "--csv",
                str(csv_path),
                "--geo",
                str(geo),
            ]
        )
        == 0
    )
    assert "suspicion=0.0000" in capsys.readouterr().out
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["geo_labels"] == {"AS13335": 1}
    csv_text = csv_path.read_text(encoding="utf-8")
    assert "1.1.1.1" in csv_text
    assert "public" in csv_text


def test_bad_inputs_return_one(tmp_path, capsys) -> None:
    peers = tmp_path / "peers.json"
    peers.write_text('[{"ip": "1.1.1.1", "port": 1, "peer_id_hex": "zz"}]', encoding="utf-8")
    assert main(["analyze-peers", "--peers", str(peers), "--out", str(tmp_path / "out.json")]) == 1
    assert "error:" in capsys.readouterr().err

    with pytest.raises(SystemExit) as caught:
        main(["watch-observe", "--infohash", "zz", "--state", str(tmp_path / "w.json")])
    assert caught.value.code == 2


def test_dump_json_replaces_atomically(tmp_path) -> None:
    from dhtrack.experimental.persist import dump_json, load_json

    target = tmp_path / "state.json"
    dump_json(target, {"a": 1})
    dump_json(target, {"a": 2})
    assert load_json(target) == {"a": 2}
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]
