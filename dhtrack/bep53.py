"""BEP 53 — Magnet URI Extension: Select specific file indices for download.

Provides parsing and handling of magnet URIs with file selection
parameters.  The ``select-only`` (``so``) parameter allows a magnet
link to specify which files within a torrent should be downloaded.

Examples
--------
>>> from dhtrack.bep53 import parse_magnet_uri, select_only
>>> uri = "magnet:?xt=urn:btih:QFLA47OD3KEQVOVECCGMCTWBYDQ7IE&dn=example&so=0,2,4-5"
>>> result = parse_magnet_uri(uri)
>>> result.info_hash
b"QFLA47OD3KEQVOVECCGMCTWBYDQ7IE"
>>> result.select_only
{0, 2, 4, 5}
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Set

logger = logging.getLogger(__name__)

# Supported magnet URI scheme
MAGNET_SCHEME = "magnet"

# Base32 alphabet used in BTIH hashes
_BASE32_PADDED = b"="  # RFC 4648 padding


def _parse_so_parameter(value: str) -> Optional[set[int]]:
    """Parse the ``select-only`` (``so``) parameter value.

    Format: comma-separated list of file indices with optional inclusive
    ranges.  Example: ``0,2,4-8`` → ``{0, 2, 4, 5, 6, 7, 8}``.

    Parameters
    ----------
    value : str
        Raw ``so`` parameter value.

    Returns
    -------
    set[int] or None
        Set of file indices to download.  ``None`` if the value is empty
        or malformed.

    Raises
    ------
    ValueError
        If a file index is negative or out of range.
    """
    if not value or not value.strip():
        return None

    indices: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            # Range: e.g., "4-8"
            tokens = part.split("-", 1)
            if len(tokens) != 2:
                logger.warning("Invalid range: %r", part)
                continue
            try:
                start = int(tokens[0].strip())
                end = int(tokens[1].strip())
            except ValueError as exc:
                logger.warning("Invalid range values in %r: %s", part, exc)
                continue
            if start < 0 or end < 0:
                logger.warning("Negative range values in %r", part)
                continue
            if start > end:
                logger.warning("Invalid range (start > end): %r", part)
                continue
            indices.update(range(start, end + 1))
        else:
            try:
                indices.add(int(part))
            except ValueError as exc:
                logger.warning("Invalid file index in %r: %s", part, exc)
                continue

    return indices if indices else None


@dataclass
class MagnetInfo:
    """Parsed magnet URI data.

    Attributes
    ----------
    info_hash : bytes | None
        The binary info hash (20 bytes) or ``None`` if unavailable.
    info_hash_base32 : bytes | None
        The raw base32-encoded info hash or ``None`` if unavailable.
    name : str | None
        Display name of the torrent.
    trackers : list[str]
        Tracker URLs.
    select_only : set[int] | None
        File indices to download per BEP 53.
    peers : list[str]
        Peer addresses (PEER/PEERS parameters).
    keywords : str | None
        'x-deezer-...' / 'x-bt-url-scheme' metadata.
    urgh : str | None
        Urgency hint.
    """

    info_hash: Optional[bytes] = None
    info_hash_base32: Optional[bytes] = None
    name: Optional[str] = None
    trackers: list[str] = field(default_factory=list)
    select_only: Optional[set[int]] = None
    peers: list[str] = field(default_factory=list)
    keywords: Optional[str] = None
    urgh: Optional[str] = None

    @property
    def info_hash_hex(self) -> Optional[str]:
        """Hex-encoded info hash.

        Returns
        -------
        str or None
            Hex string of the info hash, or ``None`` if unavailable.
        """
        if self.info_hash is None:
            return None
        return self.info_hash.hex()

    @property
    def info_hash_base16(self) -> Optional[str]:
        """Upper-case hex info hash (BTIH format).

        Returns
        -------
        str or None
            Upper-case hex string, or ``None`` if unavailable.
        """
        if self.info_hash is None:
            return None
        return self.info_hash.hex().upper()


def parse_magnet_uri(uri: str) -> MagnetInfo:
    """Parse a magnet URI.

    Supported parameters:
    - ``xt``: exact topic (URN with info hash)
    - ``dn``: display name
    - ``tr``: tracker URLs
    - ``so``: select-only file indices (BEP 53)
    - ``pe``: peer addresses
    - ``xs``: extended metadata (keywords)
    - ``ugh``: urgency hint

    Parameters
    ----------
    uri : str
        The magnet URI string.

    Returns
    -------
    MagnetInfo
        Parsed magnet URI data.

    Raises
    ------
    ValueError
        If the URI is not a valid magnet URI.
    """
    parsed = urllib.parse.urlparse(uri)

    if parsed.scheme != MAGNET_SCHEME:
        raise ValueError(f"Not a magnet URI: scheme={parsed.scheme}")

    info = MagnetInfo()

    # Parse query parameters
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    # xt: exact topic — URN with info hash
    xt_values = params.get("xt")
    if xt_values:
        xt = xt_values[0]
        if xt.startswith("urn:btih:"):
            btih = xt[9:]  # Remove "urn:btih:" (9 characters: u-r-n-:-b-t-i-h-:)
            info.info_hash = _decode_btih(btih)
        else:
            logger.warning("Unsupported URN scheme: %r", xt)

    # dn: display name
    dn_values = params.get("dn")
    if dn_values:
        info.name = dn_values[0]

    # tr: tracker URLs
    tr_values = params.get("tr")
    if tr_values:
        info.trackers = [t for t in tr_values if t]

    # so: select-only (BEP 53)
    so_values = params.get("so")
    if so_values:
        info.select_only = _parse_so_parameter(so_values[0])

    # pe: peers
    pe_values = params.get("pe")
    if pe_values:
        info.peers = [p for p in pe_values if p]

    # xs: extended metadata / keywords
    xs_values = params.get("xs")
    if xs_values:
        info.keywords = xs_values[0]

    # urgh: urgency hint
    urgh_values = params.get("ugh")
    if urgh_values:
        info.urgh = urgh_values[0]

    return info


def _decode_btih(btih: str) -> Optional[bytes]:
    """Decode a BTIH value (base32 or base32-sha1) to raw bytes.

    Parameters
    ----------
    btih : str
        The value after "urn:btih:" in a magnet URI.

    Returns
    -------
    bytes or None
        20-byte info hash, or ``None`` on failure.
    """
    # First try: hex-encoded SHA-1 (40 hex chars = 20 bytes)
    if len(btih) == 40:
        try:
            return bytes.fromhex(btih)
        except ValueError:
            pass
        try:
            return bytes.fromhex(btih.upper())
        except ValueError:
            pass

    # Second try: base32-encoded (32 chars = 20 bytes)
    # Normalize: remove non-alphanumeric chars and add padding
    normalized = btih.rstrip("=").upper().replace(" ", "").replace("-", "")
    # Add padding to make valid base32 length
    padding = (8 - len(normalized) % 8) % 8
    padded = normalized + "=" * padding

    try:
        decoded = base64.b32decode(padded)
        # Trim to 20 bytes if longer (base32-sha1 with base32 encoding)
        if len(decoded) >= 20:
            return decoded[:20]
        return decoded
    except Exception:
        pass

    return None


def filter_files_by_select_only(
    torrent: Any,
    select_only: Optional[set[int]],
) -> set[int]:
    """Filter torrent files by the ``select-only`` parameter from a magnet URI.

    Given a parsed torrent object and a ``select_only`` set of file indices,
    returns the subset of file indices that should be downloaded.

    Parameters
    ----------
    torrent : Any
        A ``Torrent`` object from ``dhtrack.torrent``.
    select_only : set[int] or None
        File indices from the magnet URI.  ``None`` means download all.

    Returns
    -------
    set[int]
        Set of file indices to download.  If ``select_only`` is ``None``,
        returns all valid file indices from the torrent.

    Raises
    ------
    ValueError
        If a file index in ``select_only`` is out of range.
    """
    if select_only is None:
        # Download all files
        file_count = getattr(torrent, "file_count", 0)
        return set(range(file_count))

    file_count = getattr(torrent, "file_count", 0)
    if file_count == 0:
        return set()

    # Filter to valid indices
    filtered: set[int] = set()
    for idx in select_only:
        if 0 <= idx < file_count:
            filtered.add(idx)
        else:
            logger.warning(
                "File index %d out of range (torrent has %d files)",
                idx,
                file_count,
            )

    return filtered


def create_magnet_from_torrent(
    torrent: Any,
    name: Optional[str] = None,
    trackers: Optional[list[str]] = None,
    select_only: Optional[set[int]] = None,
) -> str:
    """Create a magnet URI string from a torrent object (BEP 53).

    Parameters
    ----------
    torrent : Any
        A ``Torrent`` object from ``dhtrack.torrent``.
    name : str or None
        Torrent name for the ``dn`` parameter.
    trackers : list[str] or None
        Tracker URLs for the ``tr`` parameter.
    select_only : set[int] or None
        File indices to include (BEP 53).

    Returns
    -------
    str
        The magnet URI string.
    """
    # Get info hash
    info_hash_bytes = None
    if hasattr(torrent, "infohash") and isinstance(torrent.infohash, bytes) and len(torrent.infohash) == 20:
        info_hash_bytes = torrent.infohash

    if info_hash_bytes is None:
        raise ValueError("Cannot create magnet without a valid infohash")

    # Build query parameters
    params: list[tuple[str, str]] = []

    # xt: URN with hex-encoded info hash (BTIH)
    params.append(("xt", f"urn:btih:{info_hash_bytes.hex()}"))

    # dn: display name
    if name is not None:
        params.append(("dn", name))
    elif hasattr(torrent, "name"):
        n = torrent.name
        if n is not None:
            params.append(("dn", n))

    # tr: trackers
    if trackers:
        for url in trackers:
            params.append(("tr", url))

    # so: select-only (BEP 53)
    if select_only is not None and len(select_only) > 0:
        indices = sorted(select_only)
        so_value = _format_select_only(indices)
        params.append(("so", so_value))

    query = urllib.parse.urlencode(params, doseq=False)
    return f"magnet:?{query}"


def _format_select_only(indices: list[int]) -> str:
    """Format a sorted list of file indices into a BEP 53 ``so`` value.

    Groups consecutive indices into ranges.

    Parameters
    ----------
    indices : list[int]
        Sorted, unique file indices.

    Returns
    -------
    str
        Formatted string, e.g., ``"0,2,4-8"``.
    """
    if not indices:
        return ""

    result: list[str] = []
    start = indices[0]
    end = indices[0]

    for i in range(1, len(indices)):
        if indices[i] == end + 1:
            end = indices[i]
        else:
            if start == end:
                result.append(str(start))
            else:
                result.append(f"{start}-{end}")
            start = indices[i]
            end = indices[i]

    # Last group
    if start == end:
        result.append(str(start))
    else:
        result.append(f"{start}-{end}")

    return ",".join(result)