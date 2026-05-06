"""
Distributed Counting Bloom Filter for BEP 33 (DHT Scrapes).

Implements a Bloom Filter with the following parameters per BEP 33:
- k = 2 hash functions
- m = 256 * 8 = 2048 bits (256 bytes)

The filter supports:
- Inserting IPv4/IPv6 addresses
- Estimating cardinality (population count)
- Union operations (bitwise OR)
- Serialization to/from 256-byte representations

References
----------
BEP 33: https://www.bittorrent.org/beps/bep_0033.html
"""

from __future__ import annotations

import hashlib
import math
import socket
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of bits per hash (m = 256 * 8 = 2048 bits)
BLOOM_BIT_LENGTH = 256 * 8  # 2048

# Number of hash functions (k = 2)
BLOOM_K = 2

# Filter size in bytes
BLOOM_BYTE_LENGTH = 256


# ---------------------------------------------------------------------------
# Bloom Filter
# ---------------------------------------------------------------------------


class BloomFilter:
    """A Bloom Filter for distributed cardinality estimation (BEP 33).

    The filter uses SHA1 hashing with two 16-bit index selections from the
    160-bit SHA1 digest.  Each hash function truncates its index to the
    filter bit-length (m = 2048 bits, requiring 11 bits).

    Parameters
    ----------
    data : bytes, optional
        Initial 256-byte filter state. If provided, the internal bit array
        is populated from these bytes.
    """

    __slots__ = ("_bloom",)

    def __init__(self, data: Optional[bytes] = None) -> None:
        # 2048 bits = 256 bytes
        self._bloom: bytearray = bytearray(BLOOM_BYTE_LENGTH)
        if data is not None:
            if len(data) != BLOOM_BYTE_LENGTH:
                raise ValueError(
                    f"Bloom filter data must be {BLOOM_BYTE_LENGTH} bytes, "
                    f"got {len(data)}"
                )
            self._bloom = bytearray(data)

    # ------------------------------------------------------------------
    # Hashing / Insertion
    # ------------------------------------------------------------------

    def insert_ip(self, ip: str) -> None:
        """Insert an IPv4 or IPv6 address into the bloom filter.

        Per BEP 33, only IP addresses (v4 or v6) may be inserted.
        Port numbers or host names are NOT allowed.

        The algorithm:
        1. Compute SHA1(ip) -> 20 bytes (160 bits)
        2. Extract two 16-bit indices from bytes 0-1 and 2-3
        3. Truncate each index to 11 bits (modulo 2048)
        4. Set the two corresponding bits in the filter

        Parameters
        ----------
        ip : str
            An IPv4 or IPv6 address string.

        Raises
        ------
        ValueError
            If the IP address is invalid.
        """
        # Determine address family and get packed bytes
        if ":" in ip:
            # IPv6
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
        else:
            # IPv4
            ip_bytes = socket.inet_pton(socket.AF_INET, ip)

        # Compute SHA1 hash
        h = hashlib.sha1(ip_bytes).digest()  # 20 bytes

        # Extract two 16-bit indices (little-endian from the hash)
        index1 = h[0] | (h[1] << 8)
        index2 = h[2] | (h[3] << 8)

        # Truncate index to m bits (11 bits for 2048)
        index1 = index1 % BLOOM_BIT_LENGTH
        index2 = index2 % BLOOM_BIT_LENGTH

        # Set bits at index1 and index2
        self._set_bit(index1)
        self._set_bit(index2)

    # ------------------------------------------------------------------
    # Bit manipulation
    # ------------------------------------------------------------------

    def _set_bit(self, index: int) -> None:
        """Set a single bit in the bloom filter."""
        byte_index = index // 8
        bit_index = index % 8
        self._bloom[byte_index] |= 0x01 << bit_index

    def _get_bit(self, index: int) -> bool:
        """Get the value of a single bit."""
        byte_index = index // 8
        bit_index = index % 8
        return bool(self._bloom[byte_index] & (0x01 << bit_index))

    # ------------------------------------------------------------------
    # Cardinality estimation
    # ------------------------------------------------------------------

    def estimate_count(self) -> float:
        """Estimate the number of items in the bloom filter.

        Uses the formula from [#Bloom]_:

        .. math::

            c = \\min(m-1, \\text{countZeroBits}(bloom))

            size = \\frac{\\log(c / m)}{k \\cdot \\log(1 - 1/m)}

        where:
        - m = 2048 (filter bit length)
        - k = 2 (number of hash functions)
        - c = number of zero bits (capped at m-1)

        Returns
        -------
        float
            The estimated cardinality. Returns 0.0 if the filter is full
            (all bits set) or if the estimation would be undefined.
        """
        m = BLOOM_BIT_LENGTH
        k = BLOOM_K

        # Count zero bits
        zero_bits = 0
        for byte in self._bloom:
            zero_bits += bin(~byte & 0xFF).count("1")

        # Cap at m - 1
        c = min(m - 1, zero_bits)

        # If all bits are set (c == 0) or no zero bits, estimation breaks down
        if c <= 0:
            return 0.0

        numerator = math.log(c / m)
        denominator = k * math.log(1.0 - 1.0 / m)

        if denominator == 0:
            return 0.0

        return numerator / denominator

    # ------------------------------------------------------------------
    # Union operation
    # ------------------------------------------------------------------

    def union(self, other: "BloomFilter") -> "BloomFilter":
        """Perform a bitwise OR union with another bloom filter.

        Per BEP 33, performing unions on bloom filters is trivial - simply
        OR the bits of each filter together.

        Parameters
        ----------
        other : BloomFilter
            Another bloom filter to union with.

        Returns
        -------
        BloomFilter
            A new BloomFilter representing the union.

        Raises
        ------
        ValueError
            If the filters have different sizes.
        """
        if len(self._bloom) != len(other._bloom):
            raise ValueError(
                "Cannot union bloom filters of different sizes"
            )

        result = BloomFilter()
        for self_byte, other_byte in zip(self._bloom, other._bloom):
            result._bloom.append(self_byte | other_byte)

        return result

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize the bloom filter to 256 bytes.

        Returns
        -------
        bytes
            Exactly 256 bytes representing the filter state.
        """
        return bytes(self._bloom)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BloomFilter":
        """Create a BloomFilter from 256 bytes.

        Parameters
        ----------
        data : bytes
            Exactly 256 bytes of filter data.

        Returns
        -------
        BloomFilter
            A new BloomFilter instance.

        Raises
        ------
        ValueError
            If the data is not exactly 256 bytes.
        """
        return cls(data)

    # ------------------------------------------------------------------
    # Comparison / inspection
    # ------------------------------------------------------------------

    def count_zero_bits(self) -> int:
        """Count the number of zero bits in the filter."""
        count = 0
        for byte in self._bloom:
            count += bin(~byte & 0xFF).count("1")
        return count

    def count_set_bits(self) -> int:
        """Count the number of set (1) bits in the filter."""
        count = 0
        for byte in self._bloom:
            count += bin(byte).count("1")
        return count

    def is_full(self) -> bool:
        """Check if all bits are set."""
        return all(b == 0xFF for b in self._bloom)

    def __repr__(self) -> str:
        zero_bits = self.count_zero_bits()
        set_bits = self.count_set_bits()
        return (
            f"BloomFilter(zero_bits={zero_bits}, "
            f"set_bits={set_bits}, "
            f"estimate={self.estimate_count():.2f})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BloomFilter):
            return NotImplemented
        return bytes(self._bloom) == bytes(other._bloom)

    def __bytes__(self) -> bytes:
        return bytes(self._bloom)


# ---------------------------------------------------------------------------
# Test vector validation
# ---------------------------------------------------------------------------

def generate_test_vector_bloom() -> BloomFilter:
    """Generate a bloom filter from the BEP 33 test vector.

    Inserts:
    - IPv4: 192.0.2.0 through 192.0.2.255 (inclusive, 256 addresses)
    - IPv6: 2001:DB8:: through 2001:DB8::3E7 (inclusive, 1000 addresses)

    Expected result:
    - Total inserted: 1256 values
    - Expected estimate: 1224.9308
    - Expected hash (hex):
      F6C3F5EA A07FFD91 BDE89F77 7F26FB2B FF37BDB8 FB2BBAA2 FD3DDDE7 BACFFF75
      EE7CCBAE FE5EEDB1 FBFAFF67 F6ABFF5E 43DDBCA3 FD9B9FFD F4FFD3E9 DFF12D1B
      DF59DB53 DBE9FA5B 7FF3B8FD FCDE1AFB 8BEDD7BE 2F3EE71E BBBFE93B CDEEFE14
      8246C2BC 5DBFF7E7 EFDCF24F D8DC7ADF FD8FFFDF DDFFF7A4 BBEEDF5C B95CE81F
      C7FCFF1F F4FFFFDF E5F7FDCB B7FD79B3 FA1FC77B FE07FFF9 05B7B7FF C7FEFEFF
      E0B8370B B0CD3F5B 7F2BD93F EB4386CF DD6F7FD5 BFAF2E9E BFFFFEEC D67ADBF7
      C67F17EF D5D75EBA 6FFEBA7F FF47A91E B1BFBB53 E8ABFB57 62ABE8FF 237279BF
      EFBFEEF5 FFC5FEBF DFE5ADFF ADFEE1FB 737FFFFB FD9F6AEF FEEE76B6 FD8F72EF
    """
    bf = BloomFilter()

    # IPv4 range: 192.0.2.0 - 192.0.2.255
    for i in range(256):
        bf.insert_ip(f"192.0.2.{i}")

    # IPv6 range: 2001:DB8:: - 2001:DB8::3E7
    # 0x3E7 = 1000 in decimal
    for i in range(1001):  # inclusive, so 0 to 1000
        # 2001:0db8::N where N is the suffix
        ipv6 = f"2001:db8::{i}"
        bf.insert_ip(ipv6)

    return bf


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def create_bloom_filter(ips: list[str]) -> BloomFilter:
    """Create a BloomFilter from a list of IP address strings.

    Parameters
    ----------
    ips : list[str]
        List of IPv4 or IPv6 addresses.

    Returns
    -------
    BloomFilter
        A bloom filter with all IPs inserted.
    """
    bf = BloomFilter()
    for ip in ips:
        bf.insert_ip(ip)
    return bf


def union_bloom_filters(filters: list["BloomFilter"]) -> "BloomFilter":
    """Compute the union of multiple bloom filters.

    Parameters
    ----------
    filters : list[BloomFilter]
        List of bloom filters to union.

    Returns
    -------
    BloomFilter
        A single bloom filter representing the union.

    Raises
    ------
    ValueError
        If the list is empty or filters have different sizes.
    """
    if not filters:
        raise ValueError("Cannot union empty list of bloom filters")

    result = filters[0].copy()
    for f in filters[1:]:
        result = result.union(f)

    return result


# Add a copy method to BloomFilter
def _bloom_filter_copy(self: BloomFilter) -> BloomFilter:
    """Shallow copy of the bloom filter."""
    return BloomFilter(bytes(self._bloom))


# Attach the copy method
BloomFilter.copy = _bloom_filter_copy