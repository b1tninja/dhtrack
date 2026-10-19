"""GUI event buffer batches datagram callbacks off the I/O thread. No Qt."""

from dhtrack.gui.coalesce import GuiEventCoalescer


def test_drain_batches_and_clears() -> None:
    buf = GuiEventCoalescer()
    buf.on_outgoing_message("ping", "192.0.2.1", 1, False, 20)
    buf.on_outgoing_message("find_node", "192.0.2.2", 2, False, 30)
    buf.on_incoming_message("ping", "192.0.2.3", 3, False, 40, txid="aa", status="query")
    buf.on_message_parsed("192.0.2.3", 3, False, 40, {"q": "ping"})
    buf.on_wire_message(
        direction="IN",
        addr=("192.0.2.3", 3),
        size=40,
        hex_str="ab",
        decode_status="OK",
        decode_repr="{}",
        txid_hex="aa",
        method="ping",
        note="",
    )
    buf.on_bootstrap_progress(phase="find", depth=1, nodes_queried=2)

    first = buf.drain()
    assert len(first["outgoing"]) == 2
    assert first["query_delta"] == 2
    assert first["response_delta"] == 1
    assert first["parsed"][0][0] == "192.0.2.3"
    assert len(first["wire"]) == 1
    assert first["bootstrap"]["phase"] == "find"

    second = buf.drain()
    assert second["outgoing"] == []
    assert second["incoming"] == []
    assert second["parsed"] == []
    assert second["wire"] == []
    assert second["bootstrap"] is None
    assert second["query_delta"] == 0
    assert second["response_delta"] == 0
