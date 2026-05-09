"""Piece selection algorithm for BEP 19 WebSeed optimization.

This module implements the piece selection algorithms described in BEP 19
to optimize HTTP/FTP webseed downloading. The key insight is that HTTP/FTP
connections work best when they can download contiguous ranges of pieces,
so the algorithm prioritizes filling "gaps" in the downloaded bitfield.

Key algorithms:
- Gap identification: finds contiguous ranges of missing pieces
- "Pretty rare with biggest gap" piece selection (BEP 19 formula)
- "Fill in gaps" for files >50% complete
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Gap Dataclass
# ---------------------------------------------------------------------------


@dataclass
class Gap:
    """Represents a contiguous range of missing pieces.

    Attributes
    ----------
    start : int
        The starting piece index (inclusive).
    end : int
        The ending piece index (inclusive).
    length : int
        The number of pieces in this gap (end - start + 1).
    """

    start: int
    end: int

    @property
    def length(self) -> int:
        """Get the number of pieces in this gap.

        Returns
        -------
        int
            The gap length.
        """
        return self.end - self.start + 1

    def __repr__(self) -> str:
        return f"Gap(start={self.start}, end={self.end}, length={self.length})"

    def __lt__(self, other: Gap) -> bool:
        return self.length > other.length  # Sort by length descending


# ---------------------------------------------------------------------------
# Piece Selector
# ---------------------------------------------------------------------------


class PieceSelector:
    """Implements BEP 19 piece selection algorithms.

    The selector optimizes piece selection to maximize contiguous ranges
    for HTTP/FTP webseed downloading.

    Attributes
    ----------
    total_pieces : int
        Total number of pieces in the torrent.
    x_multiplier : float
        Multiplier for the "rare-X" formula. Defaults to sqrt(peers) - 1
        where peers is the number of connected peers.
    """

    def __init__(self, total_pieces: int = 0) -> None:
        """Initialize the piece selector.

        Parameters
        ----------
        total_pieces : int
            Total number of pieces in the torrent.
        """
        self.total_pieces = total_pieces
        self.x_multiplier = 1.0  # Will be computed based on peer count

    def set_total_pieces(self, total: int) -> None:
        """Set the total number of pieces.

        Parameters
        ----------
        total : int
            Total number of pieces.
        """
        self.total_pieces = total

    def find_gaps(self, bitfield: bytes) -> list[Gap]:
        """Find all contiguous gaps of missing pieces in the bitfield.

        Parameters
        ----------
        bitfield : bytes
            The BitTorrent bitfield where bit 1 = have piece, bit 0 = missing.

        Returns
        -------
        list of Gap
            All gaps of missing pieces, sorted by length descending.

        Notes
        -----
        Given bitfield YYnnnnYnnY where Y=have, n=missing:
        - There are two gaps: one of 4 pieces, one of 2 pieces
        """
        if not bitfield or self.total_pieces == 0:
            return []

        gaps: list[Gap] = []
        gap_start: int | None = None

        for i in range(self.total_pieces):
            # Check if we have this piece
            byte_index = i // 8
            bit_index = 7 - (i % 8)

            if byte_index < len(bitfield):
                has_piece = bool(bitfield[byte_index] & (1 << bit_index))
            else:
                has_piece = False

            if not has_piece:
                if gap_start is None:
                    gap_start = i
            else:
                if gap_start is not None:
                    gaps.append(Gap(start=gap_start, end=i - 1))
                    gap_start = None

        # Handle gap extending to end
        if gap_start is not None:
            gaps.append(Gap(start=gap_start, end=self.total_pieces - 1))

        # Sort by length descending
        gaps.sort(reverse=True)
        return gaps

    def find_gaps_from_string(self, bitfield: str) -> list[Gap]:
        """Find all gaps from a string bitfield.

        Parameters
        ----------
        bitfield : str
            String of '0' and '1' characters representing piece availability.

        Returns
        -------
        list of Gap
            All gaps of missing pieces (where '0' = missing).
        """
        gaps: list[Gap] = []
        gap_start: int | None = None

        for i, has_piece in enumerate(bitfield):
            if i >= self.total_pieces:
                break

            if has_piece == "0":  # Missing piece
                if gap_start is None:
                    gap_start = i
            else:
                if gap_start is not None:
                    gaps.append(Gap(start=gap_start, end=i - 1))
                    gap_start = None

        if gap_start is not None:
            gaps.append(Gap(start=gap_start, end=self.total_pieces - 1))

        gaps.sort(reverse=True)
        return gaps

    def select_rarest_with_gap(
        self,
        bitfield: bytes,
        peer_counts: dict[int, int],
        peer_count: int = 0,
    ) -> int | None:
        """Select the next piece using "pretty rare with biggest gap" algorithm.

        Per BEP 19, when scanning for the rarest piece, if the distance from
        another completed piece is less than for the current rarest piece,
        it must be "rare-X". If the gap is bigger, it can be picked as
        rare+X.

        Formula: X = sqrt(peers) - 1

        Parameters
        ----------
        bitfield : bytes
            The bitfield of pieces.
        peer_counts : dict
            Mapping of piece_index to number of peers that have it.
        peer_count : int
            Number of active peers (used for X calculation).

        Returns
        -------
        int or None
            The selected piece index, or None if all pieces are downloaded.
        """
        if self.total_pieces == 0:
            return None

        # Calculate X = sqrt(peers) - 1
        x = math.sqrt(max(peer_count, 1)) - 1

        cur_rarest: int | None = None
        cur_gap = 0
        cur_rarest_count = float("inf")
        next_piece: int | None = None

        gap = 0
        for i in range(self.total_pieces):
            # Check if we have this piece
            byte_index = i // 8
            bit_index = 7 - (i % 8)

            if byte_index < len(bitfield):
                has_piece = bool(bitfield[byte_index] & (1 << bit_index))
            else:
                has_piece = False

            if not has_piece:
                gap += 1
                count = peer_counts.get(i, peer_count)

                if cur_rarest is None:
                    # First missing piece found
                    cur_rarest = i
                    cur_rarest_count = count
                    cur_gap = gap
                    next_piece = i
                elif count < cur_rarest_count - x or (count <= cur_rarest_count + x and gap > cur_gap):
                    # This piece is rarer or has a bigger gap
                    cur_rarest = i
                    cur_rarest_count = count
                    cur_gap = gap
                    next_piece = i
            else:
                gap = 0

        return next_piece

    def fill_in_gaps(
        self,
        bitfield: bytes,
        peer_counts: dict[int, int] | None = None,
        completion_threshold: float = 0.5,
    ) -> int | None:
        """Select piece with smallest gap from a completed piece.

        When a file is more than 50% complete (or the configured threshold),
        this method randomly selects pieces from the smallest gaps to help
        fill in small holes.

        Parameters
        ----------
        bitfield : bytes
            The bitfield of pieces.
        peer_counts : dict, optional
            Piece peer counts (ignored in this method, kept for API consistency).
        completion_threshold : float
            Completion threshold (0.0-1.0) to enable gap filling.

        Returns
        -------
        int or None
            The selected piece index, or None if no gaps or not enough complete.
        """
        if self.total_pieces == 0:
            return None

        # Calculate completion percentage
        completed_pieces = 0
        for i in range(self.total_pieces):
            byte_index = i // 8
            bit_index = 7 - (i % 8)
            if byte_index < len(bitfield):
                if bitfield[byte_index] & (1 << bit_index):
                    completed_pieces += 1

        completion = completed_pieces / self.total_pieces if self.total_pieces > 0 else 0

        if completion < completion_threshold:
            return None

        # Find the gap that ends with the highest missing piece
        # This selects the piece just before a completed piece
        gaps = self.find_gaps(bitfield)
        if not gaps:
            return None

        # Pick from the smallest gap
        # Sort by length ascending (smallest first)
        sorted_gaps = sorted(gaps, key=lambda g: g.length)

        if sorted_gaps:
            smallest_gap = sorted_gaps[0]
            # Return the highest piece index in the smallest gap
            # (closest to the completed piece after it)
            return smallest_gap.end

        return None

    def select_for_webseed(
        self,
        bitfield: bytes,
        peer_counts: dict[int, int] = None,
        peer_count: int = 0,
        webseed_urls: int = 0,
        is_fresh_download: bool = True,
        random_start_range: int = 0,
    ) -> int | None:
        """Select the optimal piece for downloading.

        Combines standard rarest-first with WebSeed gap-aware selection.

        Parameters
        ----------
        bitfield : bytes
            The bitfield of pieces.
        peer_counts : dict, optional
            Mapping of piece_index to peer count.
        peer_count : int
            Number of active peers.
        webseed_urls : int
            Number of available webseed URLs.
        is_fresh_download : bool
            If True and webseed_urls > 0, start at a random position
            for fresh downloads (BEP 19 recommendation).
        random_start_range : int
            Range for random start position in fresh downloads.

        Returns
        -------
        int or None
            The selected piece index, or None if no missing pieces.
        """
        if peer_counts is None:
            peer_counts = {}

        if self.total_pieces == 0:
            return None

        # For fresh downloads with webseed, start at a random position
        # Per BEP 19: "it is better to start the HTTP/FTP download somewhere
        # randomly in the file"
        if is_fresh_download and webseed_urls > 0:
            missing_pieces = []
            for i in range(self.total_pieces):
                byte_index = i // 8
                bit_index = 7 - (i % 8)
                if byte_index >= len(bitfield) or not (bitfield[byte_index] & (1 << bit_index)):
                    missing_pieces.append(i)

            if missing_pieces:
                # Pick a random piece, but biased toward later pieces for webseed
                import random

                if len(missing_pieces) > 100:
                    # Pick from the last 20% of the file
                    start_idx = int(len(missing_pieces) * 0.8)
                    return random.choice(missing_pieces[start_idx:])
                else:
                    return random.choice(missing_pieces)

        # Normal rarest-first with gap awareness
        return self.select_rarest_with_gap(bitfield, peer_counts, peer_count)

    def select_piece_from_gap(
        self,
        bitfield: bytes,
        target_gap: Gap,
    ) -> int:
        """Select the piece at the end of a specific gap.

        Per BEP 19: "In any gap, it is best to fill in from the end
        (ie, the highest piece number first)."

        Parameters
        ----------
        bitfield : bytes
            The bitfield.
        target_gap : Gap
            The gap to select from.

        Returns
        -------
        int
            The highest missing piece index in the gap.
        """
        return target_gap.end

    def calculate_optimal_start_offset(
        self,
        bitfield: bytes,
    ) -> tuple[int, int]:
        """Calculate the optimal start offset and length for webseed download.

        For a new download or when continuing from gaps, determine which
        range of bytes to request from the HTTP server.

        Per BEP 19: "If a BitTorrent download is already progressing when
        starting a HTTP/FTP connection, the HTTP/FTP should start at the
        beginning of the biggest gap."

        Parameters
        ----------
        bitfield : bytes
            The bitfield of pieces.

        Returns
        -------
        tuple[int, int]
            A tuple of (start_offset, length) for the HTTP request.
        """
        gaps = self.find_gaps(bitfield)

        if not gaps:
            return (0, 0)

        # Use the largest gap
        largest_gap = gaps[0]

        start_offset = largest_gap.start * self.total_pieces if self.total_pieces > 0 else 0
        # Assume piece length is 1 for this calculation
        # The actual byte offset should be calculated with piece_length
        length = largest_gap.length

        return (start_offset, length)

    def get_bitfield_completion(self, bitfield: bytes) -> float:
        """Get the completion percentage of a bitfield.

        Parameters
        ----------
        bitfield : bytes
            The bitfield.

        Returns
        -------
        float
            Completion percentage (0.0 to 1.0).
        """
        if not self.total_pieces:
            return 0.0

        completed = 0
        for i in range(self.total_pieces):
            byte_index = i // 8
            bit_index = 7 - (i % 8)
            if byte_index < len(bitfield):
                if bitfield[byte_index] & (1 << bit_index):
                    completed += 1

        return completed / self.total_pieces


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------


def bitfield_to_string(bitfield: bytes, total_pieces: int) -> str:
    """Convert a bitfield bytes to a string representation.

    Parameters
    ----------
    bitfield : bytes
        The bitfield bytes.
    total_pieces : int
        Total number of pieces.

    Returns
    -------
    str
        String of '1' (have) and '0' (missing) characters.
    """
    result = []
    for i in range(total_pieces):
        byte_index = i // 8
        bit_index = 7 - (i % 8)
        if byte_index < len(bitfield):
            has_piece = bool(bitfield[byte_index] & (1 << bit_index))
        else:
            has_piece = False
        result.append("1" if has_piece else "0")
    return "".join(result[:total_pieces])


def string_to_bitfield(bitfield_str: str) -> bytes:
    """Convert a string bitfield to bytes.

    Parameters
    ----------
    bitfield_str : str
        String of '0' and '1' characters.

    Returns
    -------
    bytes
        The bitfield bytes.
    """
    length = len(bitfield_str)
    num_bytes = (length + 7) // 8
    result = bytearray(num_bytes)

    for i, ch in enumerate(bitfield_str):
        if i < length:
            bit_index = 7 - (i % 8)
            byte_index = i // 8
            if byte_index < num_bytes:
                if ch == "1":
                    result[byte_index] |= 1 << bit_index

    return bytes(result)
