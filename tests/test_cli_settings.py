"""Shared settings: verbose logging, bootstrap forwarding, peers path."""

from __future__ import annotations

import logging

from dhtrack.cli import main, setup_logging
from dhtrack.dht import TIMEOUT, DHTNode
from dhtrack.settings import GuiSettings, default_peers_file


def test_verbose_enables_dhtrack_debug(caplog) -> None:
    root = logging.getLogger()
    pkg = logging.getLogger("dhtrack")
    saved = (root.level, pkg.level, list(root.handlers), list(pkg.handlers), pkg.propagate)
    try:
        setup_logging(True)
        log = logging.getLogger("dhtrack.dht")
        assert log.isEnabledFor(logging.DEBUG)
        with caplog.at_level(logging.DEBUG, logger="dhtrack.dht"):
            log.debug("hello-debug-marker")
        assert "hello-debug-marker" in caplog.text
    finally:
        root.setLevel(saved[0])
        pkg.setLevel(saved[1])
        root.handlers[:] = saved[2]
        pkg.handlers[:] = saved[3]
        pkg.propagate = saved[4]


def test_nonverbose_is_info() -> None:
    root = logging.getLogger()
    pkg = logging.getLogger("dhtrack")
    saved = (root.level, pkg.level, list(pkg.handlers), pkg.propagate)
    try:
        pkg.setLevel(logging.WARNING)
        setup_logging(False)
        log = logging.getLogger("dhtrack.dht")
        assert log.isEnabledFor(logging.INFO)
        assert not log.isEnabledFor(logging.DEBUG)
    finally:
        root.setLevel(saved[0])
        pkg.setLevel(saved[1])
        pkg.handlers[:] = saved[2]
        pkg.propagate = saved[3]


def test_bootstrap_reaches_manager_start(monkeypatch, tmp_path) -> None:
    calls: dict[str, object] = {}

    class FakeNode:
        def __init__(self, **kwargs: object) -> None:
            calls["node_kw"] = kwargs
            self.node_id = b"\x00" * 20
            self.peers: dict = {}
            self.bootstrap_nodes = None

        def apply_runtime_settings(self, settings: object) -> None:
            calls["applied"] = settings

        def close(self) -> None:
            return None

    class FakeManager:
        def __init__(self, node: object = None, peers_file: str | None = None) -> None:
            self.node = node
            calls["peers_file"] = peers_file

        def start(self, *, bootstrap_nodes: object = None) -> None:
            calls["bootstrap"] = bootstrap_nodes

        def stop(self) -> None:
            calls["stopped"] = True

    monkeypatch.setattr("dhtrack.cli.DHTNode", FakeNode)
    monkeypatch.setattr("dhtrack.cli.DHTManager", FakeManager)

    def _stop_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("dhtrack.cli.time.sleep", _stop_sleep)
    peers = str(tmp_path / "peers.dat")
    rc = main(["dht", "--bootstrap", "router.example", "7000", "--peers-file", peers])
    assert rc == 0
    assert calls["bootstrap"] == [("router.example", 7000)]
    assert calls["peers_file"] == peers
    assert calls.get("stopped") is True


def test_apply_runtime_settings_does_not_mutate_module_timeout(tmp_path) -> None:
    import dhtrack.dht as dht_module

    before = dht_module.TIMEOUT
    node = DHTNode(
        bind_addr=("127.0.0.1", 0),
        peers_file=str(tmp_path / "peers.dat"),
        persist_node_identity=False,
    )
    try:
        node.apply_runtime_settings(GuiSettings(dht_timeout=1.5))
        assert node.krpc_timeout == 1.5
        assert dht_module.TIMEOUT == before == TIMEOUT
    finally:
        node.close()


def test_default_peers_file_is_beside_config() -> None:
    path = default_peers_file()
    assert path.endswith("peers.dat")
    assert "dhtrack" in path


def test_legacy_relative_peers_file_moves_to_config_dir() -> None:
    from dhtrack.settings import resolved_peers_file

    assert resolved_peers_file(GuiSettings(peers_file="peers.dat")) == default_peers_file()
    assert resolved_peers_file(GuiSettings(peers_file="/srv/dht/peers.dat")) == "/srv/dht/peers.dat"


def test_token_timing_settings_still_apply(monkeypatch) -> None:
    import dhtrack.dht as dht_module
    from dhtrack.settings import apply_to_runtime

    monkeypatch.setattr(dht_module, "TOKEN_MAX_AGE", dht_module.TOKEN_MAX_AGE)
    monkeypatch.setattr(dht_module, "SECRET_ROTATION_INTERVAL", dht_module.SECRET_ROTATION_INTERVAL)
    apply_to_runtime(GuiSettings(dht_token_max_age=1234, dht_secret_rotation_interval=77))
    assert dht_module.TOKEN_MAX_AGE == 1234
    assert dht_module.SECRET_ROTATION_INTERVAL == 77


def test_save_peers_creates_config_dir(tmp_path) -> None:
    target = tmp_path / "missing" / "dir" / "peers.dat"
    node = DHTNode(
        node_id=b"\x01" * 20, bind_addr=("127.0.0.1", 0), peers_file=str(target), persist_node_identity=False
    )
    try:
        node.add_peer(b"\x22" * 20, "192.0.2.80", 6881)
        node.save_peers()
        assert target.exists()
    finally:
        node.close()


def test_send_does_not_count_as_heard_from() -> None:
    node = DHTNode(node_id=b"\x01" * 20, bind_addr=("127.0.0.1", 0), persist_node_identity=False)
    try:
        node.send_datagram = lambda _endpoint, _payload: None  # type: ignore[method-assign]
        peer = node.add_peer(None, "192.0.2.81", 6881)
        assert peer is not None
        peer.last_seen = 5.0
        peer.write(b"d1:y1:qe")
        assert peer.last_seen == 5.0
    finally:
        node.close()
