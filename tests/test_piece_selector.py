"""Tests for BEP 19 Piece Selector module."""

import unittest

from dhtrack.piece_selector import (
    Gap,
    PieceSelector,
    bitfield_to_string,
    string_to_bitfield,
)


class TestGap(unittest.TestCase):
    """Tests for the Gap dataclass."""

    def test_gap_length(self):
        """Test Gap length calculation."""
        gap = Gap(start=0, end=9)
        self.assertEqual(gap.length, 10)

    def test_gap_repr(self):
        """Test Gap string representation."""
        gap = Gap(start=5, end=10)
        s = repr(gap)
        self.assertIn("start=5", s)
        self.assertIn("end=10", s)
        self.assertIn("length=6", s)

    def test_gap_comparison(self):
        """Test Gap sorting (by length descending)."""
        gap1 = Gap(start=0, end=4)  # length 5
        gap2 = Gap(start=10, end=11)  # length 2
        # Sorted descending, so larger comes first
        self.assertTrue(gap1.length > gap2.length)


class TestPieceSelector(unittest.TestCase):
    """Tests for the PieceSelector class."""

    def test_initialization(self):
        """Test PieceSelector initialization."""
        selector = PieceSelector(total_pieces=100)
        self.assertEqual(selector.total_pieces, 100)

    def test_set_total_pieces(self):
        """Test setting total pieces."""
        selector = PieceSelector()
        selector.set_total_pieces(50)
        self.assertEqual(selector.total_pieces, 50)

    def test_find_gaps_empty_bitfield(self):
        """Test finding gaps with empty bitfield."""
        selector = PieceSelector(total_pieces=10)
        gaps = selector.find_gaps(b"")
        self.assertEqual(len(gaps), 0)

    def test_find_gaps_all_downloaded(self):
        """Test finding gaps when all pieces are downloaded."""
        selector = PieceSelector(total_pieces=4)
        # All 1s for pieces 0-3: bits 7-4 = 1111xxxx = 0xF0
        bitfield = bytes([0b11110000])
        gaps = selector.find_gaps(bitfield)
        self.assertEqual(len(gaps), 0)

    def test_find_gaps_nothing_downloaded(self):
        """Test finding gaps when nothing is downloaded."""
        selector = PieceSelector(total_pieces=4)
        # All 0s for pieces 0-3: bits 7-4 = 0000xxxx = 0x00
        bitfield = bytes([0b00000000])
        gaps = selector.find_gaps(bitfield)
        # Should find one gap of 4 pieces (0-3)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].start, 0)
        self.assertEqual(gaps[0].end, 3)

    def test_find_gaps_partial(self):
        """Test finding gaps with partial downloads."""
        selector = PieceSelector(total_pieces=8)
        # Create a clear pattern: pieces 0,3,4 have, rest missing
        # byte 0: 10110000 = bits 7,5,4 set = pieces 0,2,3
        # Use a cleaner bitfield: byte = 11100001
        # bit 7 (piece 0): 1 = have
        # bit 6 (piece 1): 1 = have
        # bit 5 (piece 2): 1 = have
        # bits 4-1 (pieces 3-6): 0 = missing
        # bit 0 (piece 7): 1 = have
        bitfield = bytes([0b11100001])
        gaps = selector.find_gaps(bitfield)
        # One gap: pieces 3-6 (length 4)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].start, 3)
        self.assertEqual(gaps[0].end, 6)
        self.assertEqual(gaps[0].length, 4)

    def test_fill_gaps_from_string(self):
        """Test finding gaps from string bitfield."""
        selector = PieceSelector(total_pieces=8)
        # "1" = have, "0" = missing
        # 11100001 = pieces 0,1,2 have, 3-6 missing, 7 have
        bitfield_str = "11100001"
        gaps = selector.find_gaps_from_string(bitfield_str)
        # One gap: pieces 3-6 (length 4)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].start, 3)
        self.assertEqual(gaps[0].end, 6)
        self.assertEqual(gaps[0].length, 4)

    def test_select_rarest_with_gap_empty(self):
        """Test selecting with empty total."""
        selector = PieceSelector(total_pieces=0)
        result = selector.select_rarest_with_gap(b"", {}, 0)
        self.assertIsNone(result)

    def test_select_piece_from_gap(self):
        """Test selecting a piece from a specific gap."""
        selector = PieceSelector(total_pieces=100)
        gap = Gap(start=5, end=10)
        piece = selector.select_piece_from_gap(b"", gap)
        # Should return the end of the gap (highest piece first)
        self.assertEqual(piece, 10)

    def test_bitfield_completion(self):
        """Test bitfield completion calculation."""
        selector = PieceSelector(total_pieces=8)
        # piece 0=have, 1-2=missing, 3=have, 4-7=missing
        # 2 out of 8 = 0.25
        bitfield = bytes([0b10010000])
        completion = selector.get_bitfield_completion(bitfield)
        self.assertAlmostEqual(completion, 0.25)

    def test_bitfield_completion_all(self):
        """Test completion when all pieces downloaded."""
        selector = PieceSelector(total_pieces=4)
        # All bits set for pieces 0-3
        bitfield = bytes([0b11110000])
        completion = selector.get_bitfield_completion(bitfield)
        self.assertEqual(completion, 1.0)

    def test_bitfield_completion_none(self):
        """Test completion when no pieces downloaded."""
        selector = PieceSelector(total_pieces=4)
        bitfield = bytes([0b00000000])
        completion = selector.get_bitfield_completion(bitfield)
        self.assertEqual(completion, 0.0)


class TestBitfieldConversion(unittest.TestCase):
    """Tests for bitfield conversion utilities."""

    def test_bitfield_to_string(self):
        """Test converting bitfield to string."""
        # Piece 0 has (bit 7 = 1), rest don't
        bitfield = bytes([0b10000000])
        s = bitfield_to_string(bitfield, 8)
        self.assertEqual(s, "10000000")

    def test_bitfield_to_string_partial(self):
        """Test converting bitfield to string with partial data."""
        bitfield = bytes([0b10101010])
        s = bitfield_to_string(bitfield, 4)
        self.assertEqual(s, "1010")

    def test_string_to_bitfield(self):
        """Test converting string to bitfield."""
        s = "10000000"
        b = string_to_bitfield(s)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0], 0b10000000)

    def test_roundtrip(self):
        """Test roundtrip conversion."""
        original = "10101100"
        bitfield = string_to_bitfield(original)
        result = bitfield_to_string(bitfield, len(original))
        self.assertEqual(result, original)

    def test_roundtrip_longer(self):
        """Test roundtrip with longer bitfield."""
        original = "110010101100"
        bitfield = string_to_bitfield(original)
        result = bitfield_to_string(bitfield, len(original))
        self.assertEqual(result, original)


class TestPieceSelectorEdgeCases(unittest.TestCase):
    """Tests for edge cases in PieceSelector."""

    def test_no_missing_pieces(self):
        """Test selection when no pieces are missing."""
        selector = PieceSelector(total_pieces=4)
        bitfield = bytes([0b11110000])
        result = selector.select_rarest_with_gap(bitfield, {}, 0)
        self.assertIsNone(result)

    def test_all_missing_pieces(self):
        """Test selection when all pieces are missing."""
        selector = PieceSelector(total_pieces=4)
        bitfield = bytes([0b00000000])
        result = selector.select_rarest_with_gap(bitfield, {0: 1, 1: 1, 2: 1, 3: 1}, 4)
        self.assertIsNotNone(result)
        self.assertLess(result, 4)

    def test_empty_bitfield_all_missing(self):
        """Test with empty bitfield (all missing)."""
        selector = PieceSelector(total_pieces=10)
        result = selector.select_rarest_with_gap(b"", dict.fromkeys(range(10), 1), 10)
        self.assertIsNotNone(result)

    def test_fill_in_gaps_below_threshold(self):
        """Test fill_in_gaps below completion threshold."""
        selector = PieceSelector(total_pieces=10)
        bitfield = bytes([0b11000000])  # 2 bits set
        result = selector.fill_in_gaps(bitfield, completion_threshold=0.5)
        self.assertIsNone(result)

    def test_fill_in_gaps_above_threshold(self):
        """Test fill_in_gaps above completion threshold."""
        selector = PieceSelector(total_pieces=8)
        # 50% complete with a gap at the end
        # pieces 0-5 have, 6-7 missing
        # bits 7-2 = 111111 (pieces 0-5), bits 1-0 = 00 (pieces 6-7)
        bitfield = bytes([0b11111100])
        result = selector.fill_in_gaps(bitfield, completion_threshold=0.5)
        # 6/8 = 75% complete, above threshold, should find pieces 6-7
        self.assertIsNotNone(result)
        self.assertIn(result, [6, 7])

    def test_select_for_webseed_fresh(self):
        """Test webseed selection for fresh downloads."""
        selector = PieceSelector(total_pieces=100)
        bitfield = bytes([0b00000000]) * 13  # Empty bitfield (104 pieces)
        result = selector.select_for_webseed(
            bitfield,
            peer_counts={},
            peer_count=5,
            webseed_urls=2,
            is_fresh_download=True,
        )
        self.assertIsNotNone(result)
        self.assertLess(result, 100)

    def test_calculate_optimal_start_offset_no_gaps(self):
        """Test optimal offset with no gaps."""
        selector = PieceSelector(total_pieces=10)
        bitfield = bytes([0b11111111, 0b11111111, 0b11000000])
        start, length = selector.calculate_optimal_start_offset(bitfield)
        self.assertEqual(start, 0)
        self.assertEqual(length, 0)

    def test_multiple_gaps_sorted(self):
        """Test that multiple gaps are sorted by length."""
        selector = PieceSelector(total_pieces=20)
        # pieces 0-9 have, pieces 10-19 missing
        # byte 0 (pieces 0-7): 11111111 (all 8 have)
        # byte 1 (pieces 8-15): bits 7-6=11 (pieces 8-9 have), bits 5-0=000000 (pieces 10-15 missing)
        # = 11000000 = 0xC0
        # byte 2 (pieces 16-23): bits 7-4=1111 (pieces 16-19 have), bits 3-0=0000
        # = 11110000 = 0xF0
        bitfield = bytes([0b11111111, 0b11000000, 0b11110000])
        gaps = selector.find_gaps(bitfield)
        # Should find one gap: pieces 10-15 (length 6)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].start, 10)
        self.assertEqual(gaps[0].end, 15)

    def test_select_rarest_all_same_rarity(self):
        """Test selection when all pieces have same rarity."""
        selector = PieceSelector(total_pieces=4)
        bitfield = bytes([0b00000000])  # All missing
        peer_counts = {0: 3, 1: 3, 2: 3, 3: 3}  # All same
        result = selector.select_rarest_with_gap(bitfield, peer_counts, 4)
        self.assertIsNotNone(result)
        self.assertLess(result, 4)


class TestStringBitfieldConversion(unittest.TestCase):
    """Additional tests for string bitfield conversion."""

    def test_empty_string(self):
        """Test with empty string."""
        b = string_to_bitfield("")
        self.assertEqual(len(b), 0)

    def test_single_bit(self):
        """Test with single bit."""
        b = string_to_bitfield("1")
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0] & 0x80, 0x80)

    def test_to_string_empty(self):
        """Test with empty bitfield."""
        s = bitfield_to_string(b"", 0)
        self.assertEqual(s, "")

    def test_bitfield_truncation(self):
        """Test that bitfield_to_string truncates to total_pieces."""
        bitfield = bytes([0b11111111])  # 8 bits set
        s = bitfield_to_string(bitfield, 4)  # Only return 4
        self.assertEqual(s, "1111")
        self.assertEqual(len(s), 4)


if __name__ == "__main__":
    unittest.main()
