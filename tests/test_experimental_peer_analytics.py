"""Tests for the experimental peer population report."""

from __future__ import annotations

from dhtrack.bep42 import generate_node_id
from dhtrack.experimental.peer_analytics import (
    FINDING_FIELDS,
    PeerRecord,
    address_class,
    address_prefix,
    analyze_peers,
)

PUBLIC = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "208.67.222.222",
    "77.88.8.8",
    "64.6.64.6",
    "76.76.2.5",
    "185.228.168.9",
]
MAINLINE = b"M4-3-6--" + b"\x00" * 12


def test_address_classes_are_stable_across_interpreters() -> None:
    assert address_class("127.0.0.1") == "loopback"
    assert address_class("0.0.0.0") == "unspecified"
    assert address_class("169.254.1.1") == "link_local"
    assert address_class("224.0.0.1") == "multicast"
    assert address_class("10.1.2.3") == "private"
    assert address_class("100.64.1.1") == "shared"
    assert address_class("192.0.2.1") == "documentation"
    assert address_class("198.51.100.5") == "documentation"
    assert address_class("203.0.113.9") == "documentation"
    assert address_class("240.0.0.1") == "reserved"
    assert address_class("198.18.0.1") == "reserved"
    assert address_class("1.1.1.1") == "public"
    assert address_class("not-an-ip") == "invalid"
    assert address_class("::1") == "loopback"
    assert address_class("fe80::1") == "link_local"
    assert address_class("ff02::1") == "multicast"
    assert address_class("fc00::1") == "private"
    assert address_class("2001:db8::1") == "documentation"
    assert address_class("::ffff:192.0.2.10") == "documentation"
    assert address_prefix("::ffff:192.0.2.10") == "192.0.2.0/24"
    assert address_prefix("2001:db8::1") == "2001:db8::/64"
    assert address_prefix("nope") == "invalid"


def test_prefix_concentration_scores_without_treating_a_tie_as_sybil() -> None:
    concentrated = analyze_peers([PeerRecord(ip=f"203.0.113.{index}", port=1000 + index) for index in range(1, 9)])
    assert concentrated.suspicion == 0.45
    assert concentrated.bep42_checked == 0
    assert "shared_prefix" in concentrated.findings[0].flags
    assert any("prefix concentration" in note for note in concentrated.notes)

    split = analyze_peers(
        [PeerRecord(ip=f"203.0.113.{index}", port=1000 + index) for index in range(1, 5)]
        + [PeerRecord(ip=f"198.51.100.{index}", port=2000 + index) for index in range(1, 5)]
    )
    assert split.suspicion == 0.0
    assert "shared_prefix" in split.findings[0].flags
    assert any("no prefix" in note for note in split.notes)


def test_port_concentration_and_client_mix() -> None:
    report = analyze_peers([PeerRecord(ip=PUBLIC[index], port=6881, peer_id=MAINLINE) for index in range(8)])
    assert report.suspicion == 0.25
    assert report.clients == {"Mainline": 8}
    assert report.findings[0].client_code == "M"
    assert "shared_port" in report.findings[0].flags
    assert "shared_prefix" not in report.findings[0].flags


def test_bep42_mismatch_needs_a_large_enough_sample() -> None:
    stolen = generate_node_id("203.0.113.50")
    small = analyze_peers([PeerRecord(ip=PUBLIC[index], port=1000 + index, node_id=stolen) for index in range(4)])
    assert small.bep42_mismatch == 4
    assert small.suspicion == 0.0
    assert any("sample too small" in note for note in small.notes)

    mixed = analyze_peers(
        [PeerRecord(ip=PUBLIC[index], port=1000 + index, node_id=stolen) for index in range(4)]
        + [PeerRecord(ip=PUBLIC[index], port=2000 + index) for index in range(4, 8)]
    )
    assert mixed.bep42_checked == 4
    assert mixed.bep42_mismatch == 4
    assert mixed.suspicion == 0.3
    assert "bep42_mismatch" in mixed.findings[0].flags


def test_valid_node_id_and_private_exemption() -> None:
    ip = "1.1.1.1"
    valid = analyze_peers([PeerRecord(ip=ip, port=6881, node_id=generate_node_id(ip))])
    assert valid.findings[0].bep42_ok is True
    assert "bep42_mismatch" not in valid.findings[0].flags

    private = analyze_peers([PeerRecord(ip="10.0.0.8", port=6881, node_id=b"\x00" * 20)])
    assert private.bep42_checked == 0
    assert private.findings[0].bep42_ok is None
    assert "bep42_exempt" in private.findings[0].flags
    assert private.findings[0].address_class == "private"


def test_geo_lookup_counts_labels_and_survives_errors() -> None:
    peers = [PeerRecord(ip=PUBLIC[index], port=1000 + index) for index in range(8)]

    def lookup(ip: str) -> str | None:
        if ip == PUBLIC[0]:
            raise RuntimeError("db")
        if ip == PUBLIC[1]:
            return "AS13335"
        return None

    report = analyze_peers(peers, geo=lookup)
    assert report.geo_labels == {"AS13335": 1}
    assert any("geo lookup failed for 1" in note for note in report.notes)
    assert FINDING_FIELDS[0] == "ip"
    assert report.finding_rows()[1]["bep42_ok"] == ""
