from dhtrack.endpoint_swarm_index import (
    EVIDENCE_INBOUND_GET_PEERS,
    EndpointSwarmIndex,
)


def test_merge_evidence_same_hash() -> None:
    ix = EndpointSwarmIndex(max_hashes_per_endpoint=10)
    h = "a" * 40
    ix.record_hint(
        ip="192.0.2.10",
        port=6881,
        is_ipv6=False,
        info_hash_hex=h.upper(),
        evidence=EVIDENCE_INBOUND_GET_PEERS,
        now=1.0,
    )
    ix.record_hint(
        ip="192.0.2.10",
        port=6881,
        is_ipv6=False,
        info_hash_hex=h.lower(),
        evidence=EVIDENCE_INBOUND_GET_PEERS,
        now=2.0,
    )
    snap = ix.snapshot(ip="192.0.2.10", port=6881, is_ipv6=False)
    assert len(snap) == 1
    assert snap[0].hit_count == 2
    assert snap[0].last_seen == 2.0
