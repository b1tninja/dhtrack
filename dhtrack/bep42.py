"""BEP 42 — DHT Security Extension: IP-derived node ID constraint.

Implements the CRC32C-based node-ID validation and generation algorithm
described in BEP 42.  Nodes that enforce this extension accept only peers
whose node IDs satisfy the prefix constraint derived from their external IP
address, making Sybil attacks against a specific infohash significantly
harder.

Algorithm summary
-----------------
For an IPv4 address ``ip`` (4 bytes, big-endian) and a random octet ``rand``:

    mask  = [0x03, 0x0f, 0x3f, 0xff]
    r     = rand & 0x7
    masked_ip[0] = (ip[0] & mask[0]) | (r << 5)
    masked_ip[i] = ip[i] & mask[i]   (for i > 0)
    crc   = crc32c(masked_ip)   # 32-bit CRC32C (Castagnoli)

The first 21 bits of the resulting ``node_id`` must equal the first 21 bits
of ``crc``, and ``node_id[19]`` must equal ``rand``.

For IPv6 the first 8 bytes are used with mask
``[0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff]``.

References
----------
- BEP 42: https://www.bittorrent.org/beps/bep_0042.html
"""

from __future__ import annotations

import os
import socket

# ---------------------------------------------------------------------------
# CRC32C (Castagnoli) — pure-Python table implementation
# ---------------------------------------------------------------------------

# Bit-reversed Castagnoli polynomial
_CRC32C_POLY = 0x82F63B78

_CRC32C_TABLE: list[int] = []
for _i in range(256):
    _crc = _i
    for _ in range(8):
        if _crc & 1:
            _crc = (_crc >> 1) ^ _CRC32C_POLY
        else:
            _crc >>= 1
    _CRC32C_TABLE.append(_crc)


def _crc32c(data: bytes) -> int:
    """Compute CRC32C (Castagnoli) of ``data``.

    Returns a 32-bit unsigned integer.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# BEP 42 masks
# ---------------------------------------------------------------------------

_V4_MASK = bytes([0x03, 0x0F, 0x3F, 0xFF])
_V6_MASK = bytes([0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF])


def _masked_ip(ip_bytes: bytes, mask: bytes, r: int) -> bytes:
    """Apply BEP 42 IP mask and embed the random nibble ``r`` in the MSB."""
    out = bytearray(len(mask))
    for i in range(len(mask)):
        out[i] = ip_bytes[i] & mask[i]
    out[0] |= (r & 0x7) << 5
    return bytes(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_node_id(ip: str) -> bytes:
    """Generate a BEP 42 compliant 20-byte node ID for the given external IP.

    Parameters
    ----------
    ip : str
        External IP address (IPv4 or IPv6 string).

    Returns
    -------
    bytes
        A 20-byte node ID satisfying the BEP 42 prefix constraint.
    """
    rand = ord(os.urandom(1))
    r = rand & 0x7

    try:
        packed = socket.inet_pton(socket.AF_INET6, ip)
        # IPv6: use first 8 bytes
        ip_bytes = packed[:8]
        mask = _V6_MASK
    except OSError:
        packed = socket.inet_aton(ip)
        ip_bytes = packed
        mask = _V4_MASK

    masked = _masked_ip(ip_bytes, mask, r)
    crc = _crc32c(masked)

    node_id = bytearray(20)
    node_id[0] = (crc >> 24) & 0xFF
    node_id[1] = (crc >> 16) & 0xFF
    # Only the top 5 bits of the 3rd byte come from the CRC; low 3 bits are random
    node_id[2] = ((crc >> 8) & 0xF8) | (ord(os.urandom(1)) & 0x07)
    for i in range(3, 19):
        node_id[i] = ord(os.urandom(1))
    node_id[19] = rand

    return bytes(node_id)


def is_valid_node_id(node_id: bytes, ip: str) -> bool:
    """Check whether ``node_id`` satisfies the BEP 42 constraint for ``ip``.

    The first 21 bits of the node ID must match those derived from the IP and
    the random value encoded in ``node_id[19]``.  Any node ID whose IP
    resolves to a private / reserved range is exempt (constraint not enforced).

    Parameters
    ----------
    node_id : bytes
        20-byte DHT node ID to validate.
    ip : str
        Remote node's external IP address.

    Returns
    -------
    bool
        True if the node ID is valid (or if validation is not applicable).
    """
    if len(node_id) != 20:
        return False

    # Do not enforce constraint for private / loopback / link-local addresses
    if _is_exempt_ip(ip):
        return True

    rand = node_id[19]
    r = rand & 0x7

    try:
        packed = socket.inet_pton(socket.AF_INET6, ip)
        ip_bytes = packed[:8]
        mask = _V6_MASK
    except OSError:
        try:
            packed = socket.inet_aton(ip)
        except OSError:
            return True  # unparseable address → exempt
        ip_bytes = packed
        mask = _V4_MASK

    masked = _masked_ip(ip_bytes, mask, r)
    crc = _crc32c(masked)

    # Compare first 21 bits: crc bits 31..11 vs node_id[0..2] bits 7..3
    expected_b0 = (crc >> 24) & 0xFF
    expected_b1 = (crc >> 16) & 0xFF
    expected_b2_top5 = (crc >> 8) & 0xF8  # top 5 bits of byte 2

    if node_id[0] != expected_b0:
        return False
    if node_id[1] != expected_b1:
        return False
    if (node_id[2] & 0xF8) != expected_b2_top5:
        return False

    return True


def is_address_exempt_from_bep42(ip: str) -> bool:
    """Return True if ``ip`` is exempt from BEP 42 ID constraints (private, loopback, etc.)."""
    return _is_exempt_ip(ip)


def _is_exempt_ip(ip: str) -> bool:
    """Return True for IPs that are exempt from BEP 42 enforcement.

    Exempt ranges: loopback, link-local, private (RFC 1918 / RFC 4193),
    and the unspecified address.
    """
    try:
        packed4 = socket.inet_aton(ip)
        a = packed4[0]
        b = packed4[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
        return False
    except OSError:
        pass

    try:
        packed6 = socket.inet_pton(socket.AF_INET6, ip)
        # Loopback ::1
        if packed6 == b"\x00" * 15 + b"\x01":
            return True
        # Unspecified ::
        if packed6 == b"\x00" * 16:
            return True
        # ULA fc00::/7
        if packed6[0] & 0xFE == 0xFC:
            return True
        # Link-local fe80::/10
        if packed6[0] == 0xFE and (packed6[1] & 0xC0) == 0x80:
            return True
    except OSError:
        pass

    return True  # unparseable → exempt


# ---------------------------------------------------------------------------
# Test vectors from the BEP (for verification)
# ---------------------------------------------------------------------------

_TEST_VECTORS: list[tuple[str, int, str]] = [
    ("124.31.75.21", 1, "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"),
    ("21.75.31.124", 86, "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"),
    ("65.23.51.170", 22, "a5d43220bc8f112a3d426c84764f8c2a1150e616"),
    ("84.124.73.14", 65, "1b0321dd1bb1fe518101ceef99462b947a01ff41"),
    ("43.213.53.83", 90, "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"),
]


def verify_test_vectors() -> bool:
    """Return True if all BEP 42 test vectors pass.

    Useful as a self-test to confirm the CRC32C implementation is correct.
    """
    for ip, rand, expected_hex in _TEST_VECTORS:
        expected = bytes.fromhex(expected_hex)
        r = rand & 0x7

        packed = socket.inet_aton(ip)
        masked = _masked_ip(packed, _V4_MASK, r)
        crc = _crc32c(masked)

        b0 = (crc >> 24) & 0xFF
        b1 = (crc >> 16) & 0xFF
        b2_top5 = (crc >> 8) & 0xF8

        if expected[0] != b0:
            return False
        if expected[1] != b1:
            return False
        if (expected[2] & 0xF8) != b2_top5:
            return False
        if expected[19] != rand:
            return False

    return True
