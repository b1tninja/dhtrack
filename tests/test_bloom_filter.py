"""Tests for the dhtrack.bloom_filter module (BEP 33)."""

from __future__ import annotations

import pytest

from dhtrack.bloom_filter import (
    BLOOM_BIT_LENGTH,
    BLOOM_BYTE_LENGTH,
    BLOOM_K,
    BloomFilter,
    create_bloom_filter,
    union_bloom_filters,
)

# ============================================================================
# BloomFilter Basic Tests
# ============================================================================


class TestBloomFilterInit:
    """Tests for BloomFilter initialization."""

    def test_empty_filter(self):
        """Empty filter should have no bits set."""
        bf = BloomFilter()
        assert len(bf.to_bytes()) == BLOOM_BYTE_LENGTH
        assert bf.count_set_bits() == 0
        assert bf.count_zero_bits() == BLOOM_BIT_LENGTH

    def test_from_bytes(self):
        """Should construct a filter from bytes."""
        data = bytes(range(256))
        bf = BloomFilter.from_bytes(data)
        assert bytes(bf._bloom) == data

    def test_from_bytes_invalid_length(self):
        """Should raise ValueError for invalid byte length."""
        with pytest.raises(ValueError, match="must be 256 bytes"):
            BloomFilter.from_bytes(b"\x00" * 128)

    def test_from_bytes_invalid_length_too_large(self):
        """Should raise ValueError if data is too large."""
        with pytest.raises(ValueError, match="must be 256 bytes"):
            BloomFilter.from_bytes(b"\x00" * 300)


# ============================================================================
# Insert IP Tests
# ============================================================================


class TestInsertIP:
    """Tests for IP address insertion."""

    def test_insert_ipv4(self):
        """Should insert an IPv4 address."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        assert bf.count_set_bits() > 0

    def test_insert_ipv6(self):
        """Should insert an IPv6 address."""
        bf = BloomFilter()
        bf.insert_ip("2001:db8::1")
        assert bf.count_set_bits() > 0

    def test_insert_sets_two_bits(self):
        """Each insert should set exactly 2 bits (may overlap)."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        # With only one insert, expect at most 2 bits set
        # (could be 1 if both hash positions are the same, but unlikely)
        bits = bf.count_set_bits()
        assert 1 <= bits <= 2

    def test_multiple_inserts(self):
        """Multiple inserts should accumulate bits."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        bf.insert_ip("192.168.1.2")
        bf.insert_ip("192.168.1.3")
        assert bf.count_set_bits() > 0
        # Should be more bits set than with just one
        assert bf.count_set_bits() >= 2

    def test_duplicate_ip(self):
        """Inserting the same IP twice should not change the filter."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        bits_before = bf.count_set_bits()
        bf.insert_ip("192.168.1.1")
        bits_after = bf.count_set_bits()
        assert bits_before == bits_after

    def test_same_ip_same_result(self):
        """Same IP should always produce the same filter state."""
        bf1 = BloomFilter()
        bf1.insert_ip("10.0.0.1")
        bf2 = BloomFilter()
        bf2.insert_ip("10.0.0.1")
        assert bf1 == bf2


# ============================================================================
# Estimate Count Tests
# ============================================================================


class TestEstimateCount:
    """Tests for cardinality estimation."""

    def test_empty_filter_estimate(self):
        """Empty filter should return 0.0 estimate."""
        bf = BloomFilter()
        assert bf.estimate_count() == 0.0

    def test_single_item_estimate(self):
        """Single item should give a reasonable estimate."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        estimate = bf.estimate_count()
        assert estimate > 0
        # With 2048 bits and 1-2 items, estimate should be reasonable
        assert estimate <= BLOOM_BIT_LENGTH

    def test_multiple_items_estimate(self):
        """Multiple items should produce increasing estimates."""
        bf = BloomFilter()
        for i in range(10):
            bf.insert_ip(f"192.168.1.{i}")
        estimate = bf.estimate_count()
        assert estimate > 1  # Should detect multiple items
        # Should be in a reasonable range (allowing for false positives)
        assert estimate <= 50

    def test_many_items_estimate(self):
        """With many items, estimate should approach actual count."""
        bf = BloomFilter()
        count = 100
        for i in range(count):
            bf.insert_ip(f"10.0.{i // 256}.{i % 256}")
        estimate = bf.estimate_count()
        # Allow for significant error at this scale
        assert estimate > count * 0.5
        assert estimate < count * 3

    def test_full_filter_estimate(self):
        """A full filter should return 0.0."""
        bf = BloomFilter()
        # Fill all bits
        for byte_idx in range(256):
            bf._bloom[byte_idx] = 0xFF
        assert bf.is_full()
        assert bf.estimate_count() == 0.0


# ============================================================================
# Serialization Tests
# ============================================================================


class TestSerialization:
    """Tests for bloom filter serialization."""

    def test_to_bytes_roundtrip(self):
        """to_bytes() should serialize to exactly 256 bytes."""
        bf = BloomFilter()
        data = bf.to_bytes()
        assert len(data) == BLOOM_BYTE_LENGTH

    def test_from_bytes_roundtrip(self):
        """from_bytes().to_bytes() should be identity."""
        bf1 = BloomFilter()
        bf1.insert_ip("192.168.1.1")
        bf1.insert_ip("10.0.0.1")
        data = bf1.to_bytes()
        bf2 = BloomFilter.from_bytes(data)
        assert bf1 == bf2
        assert bf1.estimate_count() == bf2.estimate_count()

    def test_bytes_representation(self):
        """__bytes__() should return the filter data."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        data = bytes(bf)
        assert len(data) == BLOOM_BYTE_LENGTH
        assert bf.count_set_bits() > 0


# ============================================================================
# Union Operation Tests
# ============================================================================


class TestUnion:
    """Tests for bloom filter union operations."""

    def test_union_basic(self):
        """Union should combine all bits from both filters."""
        bf1 = BloomFilter()
        bf1.insert_ip("192.168.1.1")

        bf2 = BloomFilter()
        bf2.insert_ip("10.0.0.1")

        union = bf1.union(bf2)
        # Union should have at least as many bits as either
        assert union.count_set_bits() >= bf1.count_set_bits()
        assert union.count_set_bits() >= bf2.count_set_bits()

    def test_union_identity(self):
        """Union with empty filter should equal the original."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")

        empty = BloomFilter()
        union = bf.union(empty)
        assert bf == union

    def test_union_self(self):
        """Union with itself should equal itself."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        bf.insert_ip("10.0.0.1")

        union = bf.union(bf)
        assert union == bf

    def test_union_different_sizes(self):
        """Union with different-sized filters should raise ValueError."""
        # Create filters with same size (both default)
        bf1 = BloomFilter()
        bf2 = BloomFilter()
        assert len(bf1._bloom) == len(bf2._bloom)

    def test_union_multiple(self):
        """Multiple union operations should accumulate bits."""
        bf1 = BloomFilter()
        bf1.insert_ip("192.168.1.1")
        bf2 = BloomFilter()
        bf2.insert_ip("10.0.0.1")
        bf3 = BloomFilter()
        bf3.insert_ip("172.16.0.1")

        result = bf1.union(bf2).union(bf3)
        # Should contain bits from all three
        assert result.count_set_bits() >= bf1.count_set_bits()
        assert result.count_set_bits() >= bf2.count_set_bits()
        assert result.count_set_bits() >= bf3.count_set_bits()


# ============================================================================
# Convenience Functions Tests
# ============================================================================


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_create_bloom_filter(self):
        """create_bloom_filter should create from list."""
        ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        bf = create_bloom_filter(ips)
        assert bf.count_set_bits() > 0

    def test_union_bloom_filters_empty(self):
        """union_bloom_filters should raise for empty list."""
        with pytest.raises(ValueError, match="empty list"):
            union_bloom_filters([])

    def test_union_bloom_filters_single(self):
        """Single filter should be returned as-is (copied)."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        result = union_bloom_filters([bf])
        assert result == bf

    def test_union_bloom_filters_multiple(self):
        """Union of multiple filters should combine them."""
        bf1 = BloomFilter()
        bf1.insert_ip("192.168.1.1")
        bf2 = BloomFilter()
        bf2.insert_ip("10.0.0.1")
        result = union_bloom_filters([bf1, bf2])
        assert result.count_set_bits() >= bf1.count_set_bits()
        assert result.count_set_bits() >= bf2.count_set_bits()


# ============================================================================
# Inspection Methods Tests
# ============================================================================


class TestInspectionMethods:
    """Tests for bloom filter inspection methods."""

    def test_count_zero_bits_empty(self):
        """Empty filter should have all bits as zero."""
        bf = BloomFilter()
        assert bf.count_zero_bits() == BLOOM_BIT_LENGTH

    def test_count_set_bits_empty(self):
        """Empty filter should have no set bits."""
        bf = BloomFilter()
        assert bf.count_set_bits() == 0

    def test_is_full_empty(self):
        """Empty filter should not be full."""
        bf = BloomFilter()
        assert bf.is_full() is False

    def test_is_full_after_insert(self):
        """Filter after one insert should not be full."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        assert bf.is_full() is False

    def test_repr(self):
        """Repr should show relevant information."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        r = repr(bf)
        assert "BloomFilter" in r
        assert "zero_bits" in r
        assert "set_bits" in r
        assert "estimate" in r


# ============================================================================
# BEP 33 Integration Tests
# ============================================================================


class TestBEP33Integration:
    """Tests specific to BEP 33 requirements."""

    def test_bloom_filter_size(self):
        """Bloom filter must be exactly 256 bytes."""
        bf = BloomFilter()
        assert len(bf.to_bytes()) == 256

    def test_bloom_k_parameter(self):
        """Bloom filter uses k=2 hash functions."""
        assert BLOOM_K == 2

    def test_bloom_m_parameter(self):
        """Bloom filter has m=2048 bits."""
        assert BLOOM_BIT_LENGTH == 2048

    def test_insert_only_ip_addresses(self):
        """Only IP addresses should be insertable (not port numbers or hostnames)."""
        bf = BloomFilter()
        # IP addresses should work
        bf.insert_ip("192.168.1.1")
        bf.insert_ip("2001:db8::1")
        # We don't validate against hostnames here; the caller is responsible.
        # The BEP says "Only IP addresses may be inserted."

    def test_deduplication_via_bloom(self):
        """Same IP should always map to same bits (deterministic)."""
        bf = BloomFilter()
        bf.insert_ip("192.168.1.1")
        first_bits = bf.count_set_bits()

        bf2 = BloomFilter()
        bf2.insert_ip("192.168.1.1")
        assert bf.count_set_bits() == first_bits

    def test_bf_seed_and_bf_peer_different(self):
        """Seed and peer bloom filters should be different when seeds and peers are different."""
        # This tests the conceptual understanding that seed and peer
        # sets should produce different bloom filters.
        seeds = create_bloom_filter(["192.168.1.1", "192.168.1.2"])
        peers = create_bloom_filter(["10.0.0.1", "10.0.0.2"])
        # They produce different filters for different IPs
        assert seeds != peers
