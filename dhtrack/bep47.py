"""BEP-47: Padding files and extended file attributes.

This module provides utilities for handling extended file attributes,
SHA1 hashes, symlinks, and padding files as specified in BEP-47.

Features
--------
- File attribute parsing and formatting (l, x, h, p)
- SHA1 hash computation for file deduplication hints
- Symlink metadata handling
- Padding file length calculation

Examples
--------
>>> from dhtrack.bep47 import parse_attr, format_attr, create_padding_length
>>> parse_attr("hx")
{'h': True, 'x': True}
>>> format_attr({'x', 'h'})
'hx'
>>> create_padding_length(16384, 10000)
6384
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File Attribute Constants
# ---------------------------------------------------------------------------


class FileAttribute:
    """File attribute flags as defined in BEP-47.

    Attributes
    ----------
    SYMLINK : str
        File is a symbolic link (l).
    EXECUTABLE : str
        File has executable permission (x).
    HIDDEN : str
        File is hidden (h).
    PADDING : str
        File is a padding file (p).
    """

    SYMLINK = "l"
    EXECUTABLE = "x"
    HIDDEN = "h"
    PADDING = "p"

    # All recognized attribute characters
    ALL_ATTRIBUTES = frozenset([SYMLINK, EXECUTABLE, HIDDEN, PADDING])


# ---------------------------------------------------------------------------
# Attribute Parsing and Formatting
# ---------------------------------------------------------------------------


def parse_attr(attr_str: str) -> dict[str, bool]:
    """Parse an attribute string into a dictionary of flags.

    Each character in the string represents a file attribute.
    Unknown characters are ignored.

    Parameters
    ----------
    attr_str : str
        The attribute string (e.g., "hx", "lp", "xlh").

    Returns
    -------
    dict[str, bool]
        Dictionary mapping each attribute character to True if present.
        Only includes recognized attributes.

    Examples
    --------
    >>> parse_attr("hx")
    {'h': True, 'x': True}
    >>> parse_attr("l")
    {'l': True}
    >>> parse_attr("")
    {}
    """
    result: dict[str, bool] = {}
    for ch in attr_str:
        if ch in FileAttribute.ALL_ATTRIBUTES:
            result[ch] = True
    return result


def format_attr(attributes: set[str]) -> str:
    """Format a set of attribute flags into a string.

    Unknown characters are ignored. The output characters
    appear in no particular order (sorted for consistency).

    Parameters
    ----------
    attributes : set[str]
        Set of attribute characters (e.g., {'x', 'h'}).

    Returns
    -------
    str
        The formatted attribute string.

    Examples
    --------
    >>> sorted(format_attr({'x', 'h'}))
    ['h', 'x']
    >>> format_attr(set())
    ''
    """
    known = set(attributes) & FileAttribute.ALL_ATTRIBUTES
    return "".join(sorted(known))


def has_attribute(attr_str: str | None, attr: str) -> bool:
    """Check if a specific attribute flag is set.

    Parameters
    ----------
    attr_str : str or None
        The attribute string.
    attr : str
        The attribute character to check.

    Returns
    -------
    bool
        True if the attribute is set.

    Examples
    --------
    >>> has_attribute("hx", "x")
    True
    >>> has_attribute("hx", "l")
    False
    >>> has_attribute(None, "x")
    False
    """
    if not attr_str:
        return False
    return attr in attr_str


# ---------------------------------------------------------------------------
# SHA1 Hash Utilities
# ---------------------------------------------------------------------------


def compute_sha1(data: bytes) -> bytes:
    """Compute the SHA-1 hash of the given data.

    Parameters
    ----------
    data : bytes
        The data to hash.

    Returns
    -------
    bytes
        The 20-byte SHA-1 digest.

    Examples
    --------
    >>> import hashlib
    >>> result = compute_sha1(b"hello")
    >>> len(result) == 20
    True
    >>> result == hashlib.sha1(b"hello").digest()
    True
    """
    return hashlib.sha1(data).digest()


def validate_sha1(sha1_bytes: bytes) -> bool:
    """Validate that a SHA-1 digest is the correct length.

    Parameters
    ----------
    sha1_bytes : bytes
        The bytes to validate.

    Returns
    -------
    bool
        True if the length is exactly 20 bytes.
    """
    return isinstance(sha1_bytes, bytes) and len(sha1_bytes) == 20


# ---------------------------------------------------------------------------
# Padding File Utilities
# ---------------------------------------------------------------------------


def create_padding_length(piece_length: int, file_length: int) -> int:
    """Calculate the padding length needed to align a file to a piece boundary.

    The padding length is the remainder needed to fill the current piece
    so the next file starts at the next piece boundary.

    Parameters
    ----------
    piece_length : int
        The piece length of the torrent.
    file_length : int
        The length of the file that needs padding.

    Returns
    -------
    int
        The number of padding bytes needed. Zero if the file is already
        aligned to a piece boundary.

    Examples
    --------
    >>> create_padding_length(16384, 10000)
    6384
    >>> create_padding_length(16384, 16384)
    0
    >>> create_padding_length(16384, 32768)
    0
    >>> create_padding_length(16384, 0)
    0
    """
    if piece_length <= 0 or file_length <= 0:
        return 0
    remainder = file_length % piece_length
    if remainder == 0:
        return 0
    return piece_length - remainder


def create_padding_file_entry(
    piece_length: int,
    previous_cumulative_length: int,
    torrent_name: str = "unnamed",
) -> dict[bytes, Any] | None:
    """Create a padding file metadata entry for a torrent.

    This creates a synthetic file entry that, when inserted into the file
    list, aligns the following file to a piece boundary.

    Parameters
    ----------
    piece_length : int
        The piece length of the torrent.
    previous_cumulative_length : int
        The cumulative length of all files before this padding file.
        For multi-file torrents, this is the sum of all preceding file lengths.
    torrent_name : str, optional
        The torrent name, used for the padding directory name.
        Defaults to "unnamed".

    Returns
    -------
    dict
        A file entry dictionary compatible with BEP-3 torrent metadata,
        including the BEP-47 extended attributes.

    Examples
    --------
    >>> entry = create_padding_file_entry(16384, 10000, "my_torrent")
    >>> entry["path"]
    ['.pad', '6384']
    >>> entry["length"]
    6384
    >>> entry["attr"]
    'p'
    """
    padding_length = create_padding_length(piece_length, previous_cumulative_length)
    if padding_length == 0:
        return None  # type: ignore[return-value]

    padding_path = [b".pad", str(padding_length).encode("ascii")]

    entry: dict[bytes, Any] = {
        b"path": padding_path,
        b"length": padding_length,
        b"attr": FileAttribute.PADDING.encode("ascii"),
    }

    return entry


def is_padding_file(file_entry: dict[bytes, Any]) -> bool:
    """Check if a file entry is a padding file.

    Checks both the ``attr`` field and the path structure for
    padding file identification.

    Parameters
    ----------
    file_entry : dict
        A file entry from the torrent's ``files`` list.

    Returns
    -------
    bool
        True if the entry is a padding file.

    Examples
    --------
    >>> is_padding_file({"path": [".pad", "6384"], "length": 6384, "attr": "p"})
    True
    >>> is_padding_file({"path": ["file.txt"], "length": 100})
    False
    """
    # Bytes-only bencode invariant
    attr = file_entry.get(b"attr")
    if attr and isinstance(attr, bytes) and FileAttribute.PADDING.encode("ascii") in attr:
        return True

    # Check path structure as fallback
    path = file_entry.get(b"path")
    if isinstance(path, list) and len(path) >= 1:
        first_component = path[0]
        if isinstance(first_component, bytes) and first_component == b".pad":
            return True

    return False


# ---------------------------------------------------------------------------
# Symlink Utilities
# ---------------------------------------------------------------------------


def is_symlink(file_entry: dict[bytes, Any]) -> bool:
    """Check if a file entry is a symlink.

    Checks both the ``attr`` field and presence of ``symlink path``
    for symlink identification.

    Parameters
    ----------
    file_entry : dict
        A file entry from the torrent's ``files`` list.

    Returns
    -------
    bool
        True if the entry is a symlink.

    Examples
    --------
    >>> is_symlink({"path": ["link"], "length": 0, "attr": "l", "symlink path": ["target"]})
    True
    >>> is_symlink({"path": ["regular"], "length": 100})
    False
    """
    # Bytes-only bencode invariant
    attr = file_entry.get(b"attr")
    if attr and isinstance(attr, bytes) and FileAttribute.SYMLINK.encode("ascii") in attr:
        return True

    # Check for symlink path field
    symlink_path = file_entry.get(b"symlink path")
    if symlink_path is not None:
        return True

    return False


def get_symlink_path(file_entry: dict[bytes, Any]) -> list[bytes] | None:
    """Get the symlink target path from a file entry.

    Parameters
    ----------
    file_entry : dict
        A file entry from the torrent's ``files`` list.

    Returns
    -------
    list[str] or None
        The symlink target path components, or None if not a symlink.

    Examples
    --------
    >>> get_symlink_path({"symlink path": ["dir", "target.txt"]})
    ['dir', 'target.txt']
    >>> get_symlink_path({"path": ["regular"]})

    """
    symlink_path = file_entry.get(b"symlink path")
    if symlink_path is None:
        return None

    if not isinstance(symlink_path, list):
        return None

    return [c for c in symlink_path if isinstance(c, bytes)]


def create_symlink_file_entry(
    path: list[str],
    target_path: list[str],
    length: int = 0,
) -> dict[bytes, Any]:
    """Create a symlink file metadata entry.

    Parameters
    ----------
    path : list[str]
        The location of the symlink within the torrent.
    target_path : list[str]
        The target path that the symlink points to, relative to torrent root.
    length : int, optional
        Always 0 for symlinks. Defaults to 0.

    Returns
    -------
    dict
        A file entry dictionary with symlink metadata.

    Examples
    --------
    >>> entry = create_symlink_file_entry(
    ...     path=["link_file"],
    ...     target_path=["data", "target.txt"]
    ... )
    >>> entry["path"]
    ['link_file']
    >>> entry["symlink path"]
    ['data', 'target.txt']
    >>> entry["attr"]
    'l'
    """
    entry: dict[bytes, Any] = {
        b"path": [p.encode("utf-8") for p in path],
        b"length": length,
        b"attr": FileAttribute.SYMLINK.encode("ascii"),
        b"symlink path": [p.encode("utf-8") for p in target_path],
    }

    return entry


# ---------------------------------------------------------------------------
# File Entry Helper Functions
# ---------------------------------------------------------------------------


def get_file_sha1(file_entry: dict[bytes, Any]) -> bytes | None:
    """Get the SHA1 hash from a file entry.

    Parameters
    ----------
    file_entry : dict
        A file entry from the torrent's ``files`` list.

    Returns
    -------
    bytes or None
        The 20-byte SHA1 digest, or None if not present.

    Examples
    --------
    >>> import hashlib
    >>> sha = hashlib.sha1(b"test").digest()
    >>> get_file_sha1({"sha1": sha}) is not None
    True
    >>> get_file_sha1({"path": ["file.txt"]})

    """
    sha1 = file_entry.get(b"sha1")
    if sha1 is None:
        logger.debug("No SHA1 hash found in file entry")
        return None
    logger.debug("Got SHA1 hash from bytes key: %s", bytes(sha1).hex())
    return bytes(sha1)


def set_file_sha1(file_entry: dict[bytes, Any], sha1: bytes) -> None:
    """Set the SHA1 hash on a file entry.

    Parameters
    ----------
    file_entry : dict
        The file entry to modify.
    sha1 : bytes
        The 20-byte SHA1 digest.

    Examples
    --------
    >>> import hashlib
    >>> entry: dict[str, Any] = {"path": ["file.txt"]}
    >>> set_file_sha1(entry, hashlib.sha1(b"test").digest())
    >>> get_file_sha1(entry) is not None
    True
    """
    if not isinstance(sha1, bytes) or len(sha1) != 20:
        raise ValueError("SHA1 must be exactly 20 bytes")
    file_entry[b"sha1"] = sha1


def normalize_file_entry(file_entry: dict[bytes, Any]) -> dict[bytes, Any]:
    """Normalize a file entry to bytes-key form.

    This preserves the bytes-only bencode invariant for metainfo structures.
    """
    normalized: dict[bytes, Any] = {k: v for k, v in file_entry.items() if isinstance(k, bytes)}

    normalized.setdefault(b"path", [])
    normalized.setdefault(b"length", 0)
    normalized.setdefault(b"attr", b"")

    return normalized


def build_file_entry(
    path: list[str],
    length: int,
    attr: str | None = None,
    sha1: bytes | None = None,
    symlink_path: list[str] | None = None,
) -> dict[bytes, Any]:
    """Build a complete file entry dictionary.

    Parameters
    ----------
    path : list[str]
        The file path components relative to torrent root.
    length : int
        The file length in bytes.
    attr : str, optional
        Attribute string (e.g., "hx" for hidden+executable).
    sha1 : bytes, optional
        20-byte SHA1 digest.
    symlink_path : list[str], optional
        Symlink target path.

    Returns
    -------
    dict
        A complete file entry dictionary.

    Examples
    --------
    >>> entry = build_file_entry(["dir", "file.txt"], 1024, attr="hx")
    >>> entry["path"]
    ['dir', 'file.txt']
    >>> entry["length"]
    1024
    >>> entry["attr"]
    'hx'
    """
    entry: dict[bytes, Any] = {
        b"path": [p.encode("utf-8") for p in path],
        b"length": length,
    }

    if attr is not None:
        entry[b"attr"] = attr.encode("ascii")
    if sha1 is not None:
        entry[b"sha1"] = sha1
    if symlink_path is not None:
        entry[b"symlink path"] = [p.encode("utf-8") for p in symlink_path]

    return entry
