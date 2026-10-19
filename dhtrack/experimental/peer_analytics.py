"""Peer-population analytics and a conservative sybil heuristic.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
See ``docs/proposals/peer-analytics.md``.

Given the peers already collected for a swarm, this report summarizes address
class, prefix and port concentration, BitTorrent client mix (BEP 20), and
whether DHT node IDs satisfy BEP 42 for their address. The suspicion score is
a review aid. It does not block peers or decide that an address is abusive.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from dhtrack.bep42 import is_address_exempt_from_bep42, is_valid_node_id
from dhtrack.peerid import PeerIdParser

GeoLookup = Callable[[str], str | None]

_DOC_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_DOC_V6 = (ipaddress.ip_network("2001:db8::/32"),)
_PRIVATE_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_PRIVATE_V6 = (ipaddress.ip_network("fc00::/7"),)
_SHARED_V4 = (ipaddress.ip_network("100.64.0.0/10"),)
_RESERVED_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("240.0.0.0/4"),
)

_MIN_SUSPICION_PEERS = 8
_PREFIX_SCORE_WEIGHT = 0.45
_PORT_SCORE_WEIGHT = 0.25
_BEP42_SCORE_WEIGHT = 0.30
_CONCENTRATION_FLOOR = 0.5
_SHARED_MIN_PEERS = 6


@dataclass(frozen=True)
class PeerRecord:
    """One peer to include in a population report."""

    ip: str
    port: int
    peer_id: bytes | None = None
    node_id: bytes | None = None


@dataclass(frozen=True)
class PeerFinding:
    """Per-peer classification."""

    ip: str
    port: int
    address_class: str
    prefix: str
    client_name: str | None
    client_code: str | None
    bep42_ok: bool | None
    flags: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """JSON-ready copy. ``bep42_ok`` is ``None`` when it was not checked."""
        return {
            "ip": self.ip,
            "port": self.port,
            "address_class": self.address_class,
            "prefix": self.prefix,
            "client_name": self.client_name,
            "client_code": self.client_code,
            "bep42_ok": self.bep42_ok,
            "flags": list(self.flags),
        }


@dataclass(frozen=True)
class PopulationReport:
    """Aggregate view of one peer list."""

    peer_count: int
    unique_ips: int
    address_classes: dict[str, int]
    clients: dict[str, int]
    top_prefixes: list[tuple[str, int]]
    top_ports: list[tuple[int, int]]
    bep42_checked: int
    bep42_mismatch: int
    suspicion: float
    geo_labels: dict[str, int]
    findings: list[PeerFinding]
    notes: list[str]

    def to_dict(self) -> dict[str, object]:
        """JSON-ready copy."""
        return {
            "peer_count": self.peer_count,
            "unique_ips": self.unique_ips,
            "address_classes": dict(self.address_classes),
            "clients": dict(self.clients),
            "top_prefixes": [{"prefix": prefix, "count": count} for prefix, count in self.top_prefixes],
            "top_ports": [{"port": port, "count": count} for port, count in self.top_ports],
            "bep42_checked": self.bep42_checked,
            "bep42_mismatch": self.bep42_mismatch,
            "suspicion": self.suspicion,
            "geo_labels": dict(self.geo_labels),
            "findings": [finding.to_dict() for finding in self.findings],
            "notes": list(self.notes),
        }

    def finding_rows(self) -> list[dict[str, object]]:
        """CSV-oriented rows. Flags are joined with ``|``."""
        rows: list[dict[str, object]] = []
        for finding in self.findings:
            bep42 = "" if finding.bep42_ok is None else ("yes" if finding.bep42_ok else "no")
            rows.append(
                {
                    "ip": finding.ip,
                    "port": finding.port,
                    "address_class": finding.address_class,
                    "prefix": finding.prefix,
                    "client_name": finding.client_name or "",
                    "client_code": finding.client_code or "",
                    "bep42_ok": bep42,
                    "flags": "|".join(finding.flags),
                }
            )
        return rows


FINDING_FIELDS = (
    "ip",
    "port",
    "address_class",
    "prefix",
    "client_name",
    "client_code",
    "bep42_ok",
    "flags",
)


def address_class(ip: str) -> str:
    """Classify an address without depending on ``ipaddress`` special-range churn.

    ``IPv4Address.is_private`` / ``is_global`` changed meaning across the
    Python versions dhtrack supports, so documentation, private, shared, and
    reserved ranges are matched explicitly. IPv4-mapped IPv6 is classified as
    the embedded IPv4 address. This is not a bogon feed.
    """
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_link_local:
        return "link_local"
    if isinstance(parsed, ipaddress.IPv4Address):
        return _class_v4(parsed)
    return _class_v6(parsed)


def address_prefix(ip: str) -> str:
    """Return the IPv4 /24 or IPv6 /64 containing ``ip``.

    Unparseable addresses share the label ``invalid``. IPv4-mapped IPv6 uses
    the embedded IPv4 /24 so the two spellings count as one prefix.
    """
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if isinstance(parsed, ipaddress.IPv4Address):
        network = ipaddress.ip_network(f"{parsed}/24", strict=False)
    else:
        network = ipaddress.ip_network(f"{parsed}/64", strict=False)
    return str(network)


def analyze_peers(
    peers: Sequence[PeerRecord],
    *,
    geo: GeoLookup | None = None,
) -> PopulationReport:
    """Build a population report.

    Parameters
    ----------
    peers :
        Peers already discovered by DHT, a tracker, or an imported table.
    geo :
        Optional ``ip -> label`` callable (country, ASN, or any bucket the
        operator cares about). Exceptions are counted in ``notes`` and do not
        fail the report. Returning ``None`` or ``""`` skips that peer.
    """
    prefix_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    class_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    preliminary: list[tuple[PeerRecord, str, str, str | None, str | None, bool | None, list[str]]] = []
    bep42_checked = 0
    bep42_mismatch = 0

    for peer in peers:
        addr_class = address_class(peer.ip)
        prefix = address_prefix(peer.ip)
        class_counts[addr_class] += 1
        prefix_counts[prefix] += 1
        port_counts[peer.port] += 1
        client_name, client_code = _client(peer.peer_id)
        if client_name is not None:
            client_counts[client_name] += 1
        bep42_ok, flags = _bep42(peer)
        if bep42_ok is not None:
            bep42_checked += 1
            if not bep42_ok:
                bep42_mismatch += 1
        preliminary.append((peer, addr_class, prefix, client_name, client_code, bep42_ok, flags))

    total = len(peers)
    shared_prefixes = {prefix for prefix, count in prefix_counts.items() if _is_shared(count, total)}
    shared_ports = {port for port, count in port_counts.items() if _is_shared(count, total)}
    findings: list[PeerFinding] = []
    for peer, addr_class, prefix, client_name, client_code, bep42_ok, flags in preliminary:
        if prefix in shared_prefixes:
            flags.append("shared_prefix")
        if peer.port in shared_ports:
            flags.append("shared_port")
        findings.append(
            PeerFinding(
                ip=peer.ip,
                port=peer.port,
                address_class=addr_class,
                prefix=prefix,
                client_name=client_name,
                client_code=client_code,
                bep42_ok=bep42_ok,
                flags=tuple(flags),
            )
        )

    max_prefix_share = (max(prefix_counts.values()) / total) if total and prefix_counts else 0.0
    max_port_share = (max(port_counts.values()) / total) if total and port_counts else 0.0
    mismatch_rate = (bep42_mismatch / bep42_checked) if bep42_checked else 0.0
    suspicion, notes = _suspicion(
        peer_count=total,
        max_prefix_share=max_prefix_share,
        max_port_share=max_port_share,
        mismatch_rate=mismatch_rate,
        bep42_checked=bep42_checked,
    )
    geo_labels, geo_errors = _geo_counts(peers, geo)
    if geo_errors:
        notes.append(f"geo lookup failed for {geo_errors} peer(s)")

    return PopulationReport(
        peer_count=total,
        unique_ips=len({peer.ip for peer in peers}),
        address_classes=_ranked(class_counts),
        clients=_ranked(client_counts),
        top_prefixes=prefix_counts.most_common(10),
        top_ports=port_counts.most_common(10),
        bep42_checked=bep42_checked,
        bep42_mismatch=bep42_mismatch,
        suspicion=suspicion,
        geo_labels=_ranked(geo_labels),
        findings=findings,
        notes=notes,
    )


def _class_v4(addr: ipaddress.IPv4Address) -> str:
    if any(addr in network for network in _DOC_V4):
        return "documentation"
    if any(addr in network for network in _PRIVATE_V4):
        return "private"
    if any(addr in network for network in _SHARED_V4):
        return "shared"
    if any(addr in network for network in _RESERVED_V4):
        return "reserved"
    return "public"


def _class_v6(addr: ipaddress.IPv6Address) -> str:
    if any(addr in network for network in _DOC_V6):
        return "documentation"
    if any(addr in network for network in _PRIVATE_V6):
        return "private"
    return "public"


def _client(peer_id: bytes | None) -> tuple[str | None, str | None]:
    if not peer_id:
        return None, None
    info = PeerIdParser.parse(peer_id)
    return info.client_name, info.client_code or None


def _bep42(peer: PeerRecord) -> tuple[bool | None, list[str]]:
    flags: list[str] = []
    if peer.port < 1 or peer.port > 65535:
        flags.append("port_out_of_range")
    if peer.node_id is None:
        return None, flags
    if len(peer.node_id) != 20:
        flags.append("node_id_length")
        return None, flags
    if is_address_exempt_from_bep42(peer.ip):
        flags.append("bep42_exempt")
        return None, flags
    ok = is_valid_node_id(peer.node_id, peer.ip)
    if not ok:
        flags.append("bep42_mismatch")
    return ok, flags


def _is_shared(count: int, total: int) -> bool:
    if total < _SHARED_MIN_PEERS:
        return False
    return count >= max(3, _ceil_div(total * 3, 10))


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def _suspicion(
    *,
    peer_count: int,
    max_prefix_share: float,
    max_port_share: float,
    mismatch_rate: float,
    bep42_checked: int,
) -> tuple[float, list[str]]:
    """Score in ``[0, 1]``.

    Below 8 peers the score is 0: a handful of peers from one NAT is normal.
    Prefix and port contribute only above a 50% share. BEP 42 contributes
    only when at least 4 non-exempt node IDs were checked. Weights sum to 1.
    """
    if peer_count < _MIN_SUSPICION_PEERS:
        return 0.0, ["sample too small for a suspicion score (need at least 8 peers)"]
    score = 0.0
    notes: list[str] = []
    if max_prefix_share > _CONCENTRATION_FLOOR:
        score += _PREFIX_SCORE_WEIGHT * ((max_prefix_share - _CONCENTRATION_FLOOR) / _CONCENTRATION_FLOOR)
        notes.append("prefix concentration contributes to the score")
    if max_port_share > _CONCENTRATION_FLOOR:
        score += _PORT_SCORE_WEIGHT * ((max_port_share - _CONCENTRATION_FLOOR) / _CONCENTRATION_FLOOR)
        notes.append("port concentration contributes to the score")
    if bep42_checked >= 4 and mismatch_rate > 0:
        score += _BEP42_SCORE_WEIGHT * mismatch_rate
        notes.append("BEP 42 mismatches contribute to the score")
    if not notes:
        notes.append("no prefix, port, or BEP 42 signal above the scoring thresholds")
    return round(min(1.0, score), 4), notes


def _geo_counts(peers: Sequence[PeerRecord], geo: GeoLookup | None) -> tuple[Counter[str], int]:
    labels: Counter[str] = Counter()
    errors = 0
    if geo is None:
        return labels, errors
    for peer in peers:
        try:
            label = geo(peer.ip)
        except Exception:
            errors += 1
            continue
        if label:
            labels[label] += 1
    return labels, errors


def _ranked(counts: Counter[str]) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
