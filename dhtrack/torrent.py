"""
Torrent file parsing and infohash computation.

Provides utilities for parsing .torrent files and computing
infohashes used in BitTorrent and DHT protocols.
"""

from __future__ import annotations

import hashlib
import random
from contextlib import closing
from pathlib import Path
from typing import Any, Optional

from dhtrack import bencode as bencode_module
from dhtrack.bencode import BEncodeValue
from dhtrack import bep47


try:
    import pymongo
    from pymongo import MongoClient
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False
    MongoClient = None  # type: ignore[misc,assignment]


class TorrentError(Exception):
    """Base exception for torrent parsing errors."""


class TorrentParseError(TorrentError):
    """Raised when a torrent file cannot be parsed."""


class MongoNotAvailableError(TorrentError):
    """Raised when MongoDB operations are used without pymongo installed."""


class Torrent:
    """Represents a parsed BitTorrent file.

    The Torrent class handles parsing of .torrent files and provides
    access to metadata such as infohash, file list, and tracker URLs.

    Parameters
    ----------
    data : BEncodeValue
        The parsed BEncode data from a torrent file.

    Attributes
    ----------
    dict : dict
        The raw parsed BEncode dictionary.
    infohash : bytes
        The SHA-1 hash of the info dictionary.
    """

    # MongoDB integration (optional)
    _mongo_client: Any = None
    _db: Any = None
    _torrents: Any = None

    def __init__(self, data: BEncodeValue) -> None:
        """Initialize a Torrent from parsed BEncode data.

        Parameters
        ----------
        data : BEncodeValue
            The parsed BEncode dictionary representing a torrent file.

        Raises
        ------
        TorrentParseError
            If the data is not a valid torrent structure.
        """
        if not isinstance(data, dict):
            raise TorrentParseError("Torrent data must be a dictionary")

        # Get info - handle both byte and string keys
        info_value = None
        for key in data:
            if isinstance(key, bytes) and key.lower() == b'info' or (isinstance(key, str) and key.lower() == 'info'):
                info_value = data[key]
                break

        if info_value is None:
            raise TorrentParseError("Torrent data missing 'info' field")

        # Store raw dict (preserve original key types)
        self.dict: dict[Any, Any] = data

        # Normalize to string keys for convenience (but keep raw dict too)
        self._normalized_dict: dict[str, Any] = {}
        if isinstance(self.dict, dict):
            for k, v in self.dict.items():
                str_key = k.decode('utf-8') if isinstance(k, bytes) else k
                self._normalized_dict[str_key] = v

        # Compute infohash: SHA-1 of the bencoded info dictionary (BEP 3)
        self.infohash: bytes = hashlib.sha1(bencode_module.encode(info_value)).digest()

    @property
    def name(self) -> Optional[str]:
        """Get the torrent name, if available.

        Returns
        -------
        str or None
            The torrent name from the info dictionary.
        """
        info = self._normalized_dict.get('info')
        if isinstance(info, dict):
            name = info.get('name')
            if name is None:
                name = info.get(b'name')
            if isinstance(name, bytes):
                return name.decode('utf-8', errors='replace')
            return str(name) if name else None
        return None

    def _get_key(self, data: dict[Any, Any], str_key: str, byte_key: bytes) -> Any:
        """Get a value from a dict, trying string key first then byte key.

        Parameters
        ----------
        data : dict
            The dictionary to look up.
        str_key : str
            The string key to try first.
        byte_key : bytes
            The byte key to try if string key is not found.

        Returns
        -------
        Any
            The value associated with the key, or None if not found.
        """
        if str_key in data:
            return data[str_key]
        if byte_key in data:
            return data[byte_key]
        return None

    @property
    def info(self) -> Optional[BEncodeValue]:
        """Get the raw info dictionary."""
        return self._get_key(self._normalized_dict, 'info', b'info')

    @property
    def trackers(self) -> list[str]:
        """Get the list of tracker URLs.

        Per BEP-12, when ``announce-list`` is present, the ``announce`` key
        MUST be ignored.  Only the URLs from ``announce-list`` are returned.
        If no ``announce-list`` exists, the single ``announce`` URL is returned.

        Returns
        -------
        list[str]
            Tracker URLs from ``announce-list`` (if present) or the single
            ``announce`` URL.

        Notes
        -----
        See BEP-12: https://www.bittorrent.org/beps/bep_0012.html
        """
        trackers: list[str] = []

        # Per BEP-12: if announce-list exists, ignore the announce key
        announce_list = self._get_key(self._normalized_dict, 'announce-list', b'announce-list')
        if announce_list is None:
            # Fallback to legacy key name
            announce_list = self._get_key(self._normalized_dict, 'announcelist', b'announcelist')

        if isinstance(announce_list, list):
            # Multi-tracker mode (BEP 12)
            for tier in announce_list:
                if isinstance(tier, list):
                    for tracker in tier:
                        if isinstance(tracker, bytes):
                            trackers.append(tracker.decode('utf-8', errors='replace'))
                        elif isinstance(tracker, str):
                            trackers.append(tracker)
        else:
            # Legacy single-tracker mode: fall back to announce key
            announce = self._get_key(self._normalized_dict, 'announce', b'announce')
            if announce is not None:
                if isinstance(announce, bytes):
                    trackers.append(announce.decode('utf-8', errors='replace'))
                elif isinstance(announce, str):
                    trackers.append(announce)

        return trackers

    # ---- BEP 12: Multitracker Metadata Extension ----

    def get_raw_announce_list(self) -> Any:
        """Get the raw announce-list value from the torrent metadata.

        Returns
        -------
        Any
            The raw value of the 'announce-list' key, or None if not present.
        """
        return self._get_key(self._normalized_dict, 'announce-list', b'announce-list')

    def has_announce_list(self) -> bool:
        """Check if the torrent uses the multitracker format (BEP 12).

        Returns
        -------
        bool
            True if 'announce-list' is present in the torrent metadata.
            Per BEP 12, when present, the 'announce' key should be ignored.

        Notes
        -----
        This checks for 'announce-list' (the standard BEP 12 key) as well
        as 'announcelist' (legacy non-standard key).
        """
        if self.get_raw_announce_list() is not None:
            return True
        return self._get_key(self._normalized_dict, 'announcelist', b'announcelist') is not None

    def set_announce_list(self, tiers: list[list[str]]) -> None:
        """Set the announce-list for the torrent metadata.

        This replaces or creates the 'announce-list' key in the torrent's
        top-level metadata dictionary. After calling this method, the
        torrent will use multitracker format per BEP 12.

        Parameters
        ----------
        tiers : list[list[str]]
            A list of tiers, where each tier is a list of tracker URL strings.
        """
        # Convert to bytes for BEncode compatibility
        encoded_tiers: list[list[bytes]] = []
        for tier in tiers:
            encoded_tier: list[bytes] = []
            for url in tier:
                if isinstance(url, str):
                    encoded_tier.append(url.encode('utf-8'))
                elif isinstance(url, bytes):
                    encoded_tier.append(url)
            encoded_tiers.append(encoded_tier)

        # Set on the raw dictionary (using string key for compatibility)
        self._normalized_dict['announce-list'] = encoded_tiers

        # Also set on the raw dict - try both key types
        raw_dict = self.dict
        raw_dict['announce-list'] = encoded_tiers

    def shuffle_tier(self, tier_index: int) -> list[str]:
        """Shuffle a specific tier and return the shuffled tracker URLs.

        Per BEP 12, URLs within each tier are shuffled when first read,
        and the shuffled order is maintained for subsequent announces.

        Parameters
        ----------
        tier_index : int
            The 0-based index of the tier to shuffle.

        Returns
        -------
        list[str]
            The shuffled tracker URLs for the specified tier.

        Raises
        ------
        ValueError
            If the tier_index is out of range.
        """
        announce_list = self.get_raw_announce_list()
        if not isinstance(announce_list, list):
            raise ValueError("No announce-list found in torrent metadata")

        if tier_index < 0 or tier_index >= len(announce_list):
            raise ValueError(
                f"Tier index {tier_index} out of range (0-{len(announce_list) - 1})"
            )

        tier = announce_list[tier_index]
        if isinstance(tier, list):
            # Extract string URLs
            urls: list[str] = []
            for tracker in tier:
                if isinstance(tracker, bytes):
                    urls.append(tracker.decode('utf-8', errors='replace'))
                elif isinstance(tracker, str):
                    urls.append(tracker)

            # Shuffle in place (BEP 12: shuffle once on first read)
            random.shuffle(urls)

            # Update the tier in the announce-list
            for i, url in enumerate(urls):
                tier[i] = url.encode('utf-8') if isinstance(tier[i], bytes) else url

            return urls

        return []

    def record_announce_success(self, tier_index: int, tracker_url: str) -> None:
        """Record that a tracker successfully responded and move it to the front.

        Per BEP 12, if a connection with a tracker is successful, the tracker
        is moved to the front of its tier for future announces.

        Parameters
        ----------
        tier_index : int
            The 0-based index of the tier containing the tracker.
        tracker_url : str
            The URL of the tracker that successfully responded.

        Raises
        ------
        ValueError
            If the tier is not found or the tracker is not in the tier.
        """
        announce_list = self.get_raw_announce_list()
        if not isinstance(announce_list, list):
            raise ValueError("No announce-list found in torrent metadata")

        if tier_index < 0 or tier_index >= len(announce_list):
            raise ValueError(
                f"Tier index {tier_index} out of range (0-{len(announce_list) - 1})"
            )

        tier = announce_list[tier_index]
        if not isinstance(tier, list):
            raise ValueError(f"Tier {tier_index} is not a list")

        # Find the tracker URL and move to front
        target_url = tracker_url.encode('utf-8') if isinstance(tracker_url, str) else tracker_url
        found_index = None
        for i, tracker in enumerate(tier):
            tracker_str = tracker.decode('utf-8', errors='replace') if isinstance(tracker, bytes) else tracker
            if tracker_str == tracker_url or tracker == target_url:
                found_index = i
                break

        if found_index is None:
            raise ValueError(
                f"Tracker '{tracker_url}' not found in tier {tier_index}"
            )

        # Move to front
        if found_index != 0:
            tier.insert(0, tier.pop(found_index))

    def shuffle_all_tiers(self) -> list[list[str]]:
        """Shuffle all tiers in the announce-list.

        Per BEP 12, each tier is shuffled independently when first read.
        This method shuffles all tiers and returns the shuffled results.

        Returns
        -------
        list[list[str]]
            All tiers with URLs shuffled within each tier.

        Raises
        ------
        ValueError
            If no announce-list is found in torrent metadata.

        Notes
        -----
        See BEP-12: https://www.bittorrent.org/beps/bep_0012.html
        """
        announce_list = self.get_raw_announce_list()
        if not isinstance(announce_list, list):
            raise ValueError("No announce-list found in torrent metadata")

        all_shuffled: list[list[str]] = []
        for tier in announce_list:
            if not isinstance(tier, list):
                continue
            urls: list[str] = []
            for tracker in tier:
                if isinstance(tracker, bytes):
                    urls.append(tracker.decode('utf-8', errors='replace'))
                elif isinstance(tracker, str):
                    urls.append(tracker)
            random.shuffle(urls)

            # Update the tier in place
            for i, url in enumerate(urls):
                tier[i] = url.encode('utf-8') if isinstance(tier[i], bytes) else url

            all_shuffled.append(urls)

        return all_shuffled

    # ---- BEP 12: Tier Progression Tracking ----

    # Instance-level state for tracking current tier during announce cycles.
    # This is intentionally NOT persisted with the torrent data - it is
    # runtime state only.
    _current_tier_index: int = 0

    def get_current_tier_index(self) -> int:
        """Get the current tier index for announce operations.

        Per BEP 12, tiers are processed sequentially. This method tracks
        which tier is currently active for announce operations. When a
        tracker in the current tier fails, the client should advance to
        the next tier.

        Returns
        -------
        int
            The 0-based index of the current tier.

        Notes
        -----
        See BEP-12: https://www.bittorrent.org/beps/bep_0012.html
        """
        return self._current_tier_index

    def advance_tier_on_failure(self) -> int:
        """Advance to the next tier when the current tier's trackers fail.

        Per BEP 12, if all trackers in the current tier fail to respond,
        the client should proceed to the next tier. This method increments
        the current tier index and returns it, clamping to the last tier
        if already at the end.

        Returns
        -------
        int
            The new current tier index (0-based).

        Notes
        -----
        This method is intended for use by the tracker iteration logic.
        After calling this method, the tracker layer should attempt to
        connect to the first URL in the new current tier.

        See BEP-12: https://www.bittorrent.org/beps/bep_0012.html
        """
        announce_list = self.get_raw_announce_list()
        if isinstance(announce_list, list) and len(announce_list) > 0:
            max_tier = len(announce_list) - 1
            if self._current_tier_index < max_tier:
                self._current_tier_index += 1
            # Clamp to last tier - no further progression needed
        return self._current_tier_index

    def reset_tier_index(self) -> None:
        """Reset the current tier index to 0.

        Per BEP 12, the client should start from the first tier on each
        full announce cycle (e.g., after a successful connection to any
        tier, the next announce should start from tier 0 again).

        Notes
        -----
        See BEP-12: https://www.bittorrent.org/beps/bep_0012.html
        """
        self._current_tier_index = 0

    def get_current_tier_urls(self) -> list[str]:
        """Get the tracker URLs for the current tier.

        Returns the URLs of the currently active tier for announce
        operations. The URLs should be shuffled before use (BEP 12).

        Returns
        -------
        list[str]
            Tracker URLs for the current tier.

        Raises
        ------
        ValueError
            If no announce-list is found or the tier index is invalid.

        Notes
        -----
        See BEP-12: https://www.bittorrent.org/beps/bep_0012.html
        """
        announce_list = self.get_raw_announce_list()
        if not isinstance(announce_list, list):
            raise ValueError("No announce-list found in torrent metadata")

        tier_index = self.get_current_tier_index()
        if tier_index < 0 or tier_index >= len(announce_list):
            raise ValueError(
                f"Invalid tier index {tier_index} (valid range: 0-{len(announce_list) - 1})"
            )

        tier = announce_list[tier_index]
        if not isinstance(tier, list):
            raise ValueError(f"Tier {tier_index} is not a list")

        urls: list[str] = []
        for tracker in tier:
            if isinstance(tracker, bytes):
                urls.append(tracker.decode('utf-8', errors='replace'))
            elif isinstance(tracker, str):
                urls.append(tracker)

        return urls

    # ---- BEP 19: WebSeed - HTTP/FTP Seeding ----

    @property
    def webseeding_urls(self) -> list[str]:
        """Get the list of webseed URLs from the torrent metadata.

        Reads the top-level "url-list" key from the torrent (BEP 19).
        This key is NOT inside the "info" section - it's at the top level.

        Returns
        -------
        list[str]
            List of HTTP/FTP URLs for webseeding.

        Notes
        -----
        Per BEP 19, if a URL ends with "/", the client should append
        the "name" from the torrent and the "path" from multi-file torrents
        to construct the full URL.
        """
        urls: list[str] = []

        # Try both string and bytes keys at top level
        url_list = self._normalized_dict.get('url-list')
        if url_list is None:
            # Try the raw dict with bytes key
            url_list = self.dict.get(b'url-list')
        if url_list is None:
            # Try string key on raw dict
            url_list = self.dict.get('url-list')

        if url_list is None:
            return urls

        # Handle both single URL string and list of URLs
        if isinstance(url_list, bytes):
            urls.append(url_list.decode('utf-8', errors='replace'))
        elif isinstance(url_list, str):
            urls.append(url_list)
        elif isinstance(url_list, list):
            for url in url_list:
                if isinstance(url, bytes):
                    urls.append(url.decode('utf-8', errors='replace'))
                elif isinstance(url, str):
                    urls.append(url)

        return urls

    @webseeding_urls.setter
    def webseeding_urls(self, urls: list[str]) -> None:
        """Set the webseed URLs in the torrent metadata.

        Parameters
        ----------
        urls : list[str]
            List of HTTP/FTP URLs for webseeding.
        """
        # Convert to bytes for BEncode compatibility
        encoded_urls: list[bytes] = []
        for url in urls:
            if isinstance(url, str):
                encoded_urls.append(url.encode('utf-8'))
            elif isinstance(url, bytes):
                encoded_urls.append(url)

        # Set on both normalized and raw dict
        self._normalized_dict['url-list'] = encoded_urls
        self.dict['url-list'] = encoded_urls

    def get_webseeding_url_for_file(self, file_index: int = 0) -> Optional[str]:
        """Get the full webseed URL for a specific file in multi-file torrents.

        Constructs the full URL by appending the torrent name and file path
        to the base webseed URL (BEP 19).

        Parameters
        ----------
        file_index : int
            The index of the file within the torrent (0 for single-file, index for multi-file).

        Returns
        -------
        str or None
            The complete URL for downloading the file from a webseed server, or None
            if no webseed URLs are available.

        Notes
        -----
        Per BEP 19, if the url-list URL ends with "/", the client appends:
        - Single-file: the "name" from the torrent info
        - Multi-file: the "name" + "path" elements from the file entries
        """
        urls = self.webseeding_urls
        if not urls:
            return None

        # Use the first URL as the base
        base_url = urls[0]

        # Check if URL ends with "/" - if so, we need to append name/path
        if base_url.endswith('/'):
            # Get the torrent name
            name = self.name
            if not name:
                return base_url

            # Check if this is a multi-file torrent
            if self.file_count > 1 and file_index < self.file_count:
                # Multi-file torrent - get the file path
                file_path = self.get_file_path(file_index)
                if file_path:
                    return f"{base_url}{name}/{file_path}"

            # Single-file torrent or default
            return f"{base_url}{name}"

        return base_url if urls else None

    def get_file_path(self, file_index: int) -> Optional[str]:
        """Get the path of a file in a multi-file torrent.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        str or None
            The file path relative to the torrent's root, or None for single-file torrents.
        """
        info = self.info
        if info is None:
            return None

        if not isinstance(info, dict):
            return None

        files = self._get_key(info, 'files', b'files')
        if files is None or not isinstance(files, list):
            return None  # Single-file torrent

        if file_index < 0 or file_index >= len(files):
            return None

        file_entry = files[file_index]
        if not isinstance(file_entry, dict):
            return None

        # Get the path list
        path = self._get_key(file_entry, 'path', b'path')
        if path is None:
            return None

        if isinstance(path, bytes):
            return path.decode('utf-8', errors='replace')
        elif isinstance(path, list):
            # Path can be a list of path components (BEP 32)
            parts: list[str] = []
            for component in path:
                if isinstance(component, bytes):
                    parts.append(component.decode('utf-8', errors='replace'))
                elif isinstance(component, str):
                    parts.append(component)
            return '/'.join(parts)

        return None

    @property
    def tracker_tiers(self) -> list[list[str]]:
        """Get the tracker URLs organized by tiers.

        Returns
        -------
        list[list[str]]
            A list of tiers, where each tier is a list of tracker URLs.
            If no announce-list is present, returns a single tier with
            the announce URL (if any).

        Notes
        -----
        Per BEP 12, tiers are processed sequentially. URLs within each
        tier are shuffled on first read and successful trackers move
        to the front of their tier.
        """
        announce_list = self._get_key(self._normalized_dict, 'announce-list', b'announce-list')
        if announce_list is None:
            # Fallback to legacy key name
            announce_list = self._get_key(self._normalized_dict, 'announcelist', b'announcelist')

        if isinstance(announce_list, list):
            tiers: list[list[str]] = []
            for tier in announce_list:
                if isinstance(tier, list):
                    tier_urls: list[str] = []
                    for tracker in tier:
                        if isinstance(tracker, bytes):
                            tier_urls.append(tracker.decode('utf-8', errors='replace'))
                        elif isinstance(tracker, str):
                            tier_urls.append(tracker)
                    if tier_urls:
                        tiers.append(tier_urls)
            if tiers:
                return tiers

        # Fallback: return single announce as a single-tier list
        announce = self._get_key(self._normalized_dict, 'announce', b'announce')
        if announce is not None:
            if isinstance(announce, bytes):
                return [[announce.decode('utf-8', errors='replace')]]
            elif isinstance(announce, str):
                return [[announce]]

        return []

    @property
    def file_count(self) -> int:
        """Get the number of files in the torrent.

        Returns
        -------
        int
            Number of files, or 1 for single-file torrents.
        """
        info = self.info
        if info is None:
            return 0

        if isinstance(info, dict):
            files = self._get_key(info, 'files', b'files')
            if files is not None and isinstance(files, list):
                return len(files)
        return 1  # Single-file torrent

    # ---- BEP-47: Padding Files and Extended File Attributes ----

    def _get_files_list(self) -> Optional[list[dict[str, Any]]]:
        """Get the files list from the info dictionary.

        Returns
        -------
        list of dict or None
            The files list for multi-file torrents, or None for single-file torrents.
        """
        info = self.info
        if not isinstance(info, dict):
            return None

        files = self._get_key(info, 'files', b'files')
        if not isinstance(files, list):
            return None

        return files  # type: ignore[return-value]

    def _get_normalized_file_entry(self, file_index: int) -> Optional[dict[str, Any]]:
        """Get a normalized file entry at the given index.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        dict or None
            Normalized file entry, or None if not found.
        """
        files = self._get_files_list()
        if files is None or file_index < 0 or file_index >= len(files):
            return None

        return bep47.normalize_file_entry(files[file_index])

    def get_file_attribute(self, file_index: int) -> str:
        """Get the attribute string for a file.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        str
            The attribute string (e.g., "hx" for hidden+executable),
            or empty string if no attributes are set.
        """
        entry = self._get_normalized_file_entry(file_index)
        if entry is None:
            return ""
        return entry.get("attr", "")

    def has_file_attribute(self, file_index: int, attr: str) -> bool:
        """Check if a file has a specific attribute.

        Parameters
        ----------
        file_index : int
            The index of the file.
        attr : str
            The attribute character to check ('l', 'x', 'h', 'p').

        Returns
        -------
        bool
            True if the file has the specified attribute.
        """
        attr_str = self.get_file_attribute(file_index)
        return bep47.has_attribute(attr_str, attr)

    def set_file_attribute(self, file_index: int, attr: str, set_value: bool = True) -> None:
        """Set or unset an attribute on a file entry.

        Parameters
        ----------
        file_index : int
            The index of the file.
        attr : str
            The attribute character to set ('l', 'x', 'h', 'p').
        set_value : bool, optional
            True to set the attribute, False to unset it. Defaults to True.
        """
        files = self._get_files_list()
        if files is None or file_index < 0 or file_index >= len(files):
            return

        entry = files[file_index]
        if not isinstance(entry, dict):
            return

        # Normalize attr field
        current_attr = entry.get("attr", "") or entry.get(b"attr", "")
        if isinstance(current_attr, bytes):
            current_attr = current_attr.decode("utf-8", errors="replace")

        current_attr = str(current_attr)

        if set_value:
            new_attr = current_attr + attr if attr not in current_attr else current_attr
        else:
            new_attr = "".join(c for c in current_attr if c != attr)

        entry["attr"] = new_attr

    def get_file_sha1(self, file_index: int) -> Optional[bytes]:
        """Get the SHA1 hash for a file.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        bytes or None
            The 20-byte SHA1 digest, or None if not set.
        """
        entry = self._get_normalized_file_entry(file_index)
        if entry is None:
            return None
        return bep47.get_file_sha1(entry)

    def set_file_sha1(self, file_index: int, sha1: bytes) -> None:
        """Set the SHA1 hash for a file.

        Parameters
        ----------
        file_index : int
            The index of the file.
        sha1 : bytes
            The 20-byte SHA1 digest.

        Raises
        ------
        ValueError
            If sha1 is not exactly 20 bytes.
        """
        files = self._get_files_list()
        if files is None or file_index < 0 or file_index >= len(files):
            return

        entry = files[file_index]
        if not isinstance(entry, dict):
            return

        bep47.set_file_sha1(entry, sha1)

    def compute_file_sha1(self, file_index: int, data: bytes) -> bytes:
        """Compute and store the SHA1 hash for a file.

        Parameters
        ----------
        file_index : int
            The index of the file.
        data : bytes
            The file data to hash.

        Returns
        -------
        bytes
            The computed 20-byte SHA1 digest.
        """
        sha1 = bep47.compute_sha1(data)
        self.set_file_sha1(file_index, sha1)
        return sha1

    def get_symlink_path(self, file_index: int) -> Optional[list[str]]:
        """Get the symlink target path for a file.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        list[str] or None
            The symlink target path components, or None if not a symlink.
        """
        entry = self._get_normalized_file_entry(file_index)
        if entry is None:
            return None
        return bep47.get_symlink_path(entry)

    def is_symlink(self, file_index: int) -> bool:
        """Check if a file is a symlink.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        bool
            True if the file is a symlink.
        """
        entry = self._get_normalized_file_entry(file_index)
        if entry is None:
            return False
        return bep47.is_symlink(entry)

    def is_padding_file(self, file_index: int) -> bool:
        """Check if a file is a padding file.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        bool
            True if the file is a padding file.
        """
        entry = self._get_normalized_file_entry(file_index)
        if entry is None:
            return False
        return bep47.is_padding_file(entry)

    def get_padding_length(self, file_index: int) -> int:
        """Get the padding length for a padding file.

        Parameters
        ----------
        file_index : int
            The index of the file.

        Returns
        -------
        int
            The padding length in bytes, or 0 if not a padding file.
        """
        entry = self._get_normalized_file_entry(file_index)
        if entry is None:
            return 0
        if self.is_padding_file(file_index):
            return entry.get("length", 0)
        return 0

    # ---- BEP-27: Private Torrents ----

    @property
    def is_private(self) -> bool:
        """Check if this is a private torrent (BEP-27).

        A torrent is private when the ``info`` dict contains the key-value
        pair ``private=1``.  Per BEP-27, private torrents MUST NOT use
        DHT, PEX, or LSD for peer discovery.

        Returns
        -------
        bool
            True if the torrent is private, False otherwise.

        Notes
        -----
        The ``private`` key is stored inside the ``info`` dictionary (not
        at the top level of the metainfo file).

        See BEP-27 for details:
        https://www.bittorrent.org/beps/bep_0027.html
        """
        if isinstance(self.info, dict):
            for key in (b"private", "private"):
                if key in self.info:
                    value = self.info[key]
                    if isinstance(value, (bytes, str)):
                        return value in (b"1", "1", b"true", "true")
                    elif isinstance(value, int) and not isinstance(value, bool):
                        return value == 1
        return False

    @is_private.setter
    def is_private(self, value: bool) -> None:
        """Set or remove the private flag in the torrent's info dict.

        When ``value`` is True, adds (or updates) the ``"private"`` key
        inside the ``info`` dictionary to ``"1"``.  When ``False``, removes
        the key if present.

        Parameters
        ----------
        value : bool
            True to mark the torrent as private, False to remove the flag.
        """
        if not isinstance(self.info, dict):
            return

        if value:
            # Check if key exists as bytes or string and update accordingly
            if b"private" in self.info:
                self.info[b"private"] = b"1"
            elif "private" in self.info:
                self.info["private"] = "1"
            else:
                # Default to bytes key for BEncode compatibility
                self.info[b"private"] = b"1"
        else:
            # Remove the private key
            self.info.pop(b"private", None)
            self.info.pop("private", None)

    def get_piece_length(self) -> int:
        """Get the piece length from the torrent.

        Returns
        -------
        int
            The piece length, or 0 if not available.
        """
        info = self.info
        if isinstance(info, dict):
            piece_length = self._get_key(info, 'piece length', b'piece length')
            if isinstance(piece_length, int) and piece_length > 0:
                return piece_length
        return 0

    def add_padding_file(self, file_index: int) -> Optional[dict[str, Any]]:
        """Add a padding file before the specified file to align it to a piece boundary.

        Parameters
        ----------
        file_index : int
            The index of the file to align with padding.

        Returns
        -------
        dict or None
            The padding file entry, or None if no padding is needed.
        """
        files = self._get_files_list()
        if files is None:
            return None

        if file_index < 0 or file_index >= len(files):
            return None

        piece_length = self.get_piece_length()
        if piece_length <= 0:
            return None

        cumulative_length = 0
        for i in range(file_index):
            entry = files[i]
            if isinstance(entry, dict):
                length = entry.get("length", entry.get(b"length", 0))
                if isinstance(length, int):
                    cumulative_length += length

        padding_entry = bep47.create_padding_file_entry(
            piece_length, cumulative_length
        )

        if padding_entry is None:
            return None

        files.insert(file_index, padding_entry)

        return padding_entry

    def generate_padding_files(
        self,
        exclude_existing_padding: bool = True,
    ) -> list[dict[str, Any]]:
        """Generate padding files for all files that need them.

        Parameters
        ----------
        exclude_existing_padding : bool
            If True, skip padding for files that already have padding
            attributes or are already aligned. Defaults to True.

        Returns
        -------
        list of dict
            The list of generated padding file entries.
        """
        files = self._get_files_list()
        if files is None:
            return []

        piece_length = self.get_piece_length()
        if piece_length <= 0:
            return []

        padding_entries: list[dict[str, Any]] = []
        cumulative_length = 0
        insert_positions: list[tuple[int, dict[str, Any]]] = []

        for i, entry in enumerate(files):
            if not isinstance(entry, dict):
                cumulative_length += entry.get("length", entry.get(b"length", 0))
                continue

            if exclude_existing_padding and self.is_padding_file(i):
                cumulative_length += entry.get("length", 0)
                continue

            padding_len = bep47.create_padding_length(piece_length, cumulative_length)
            if padding_len > 0:
                padding_entry = bep47.create_padding_file_entry(
                    piece_length, cumulative_length
                )
                if padding_entry is not None:
                    insert_positions.insert(0, (i, padding_entry))

            entry_length = entry.get("length", entry.get(b"length", 0))
            if isinstance(entry_length, int):
                cumulative_length += entry_length

        for position, padding_entry in sorted(insert_positions, key=lambda x: x[0], reverse=True):
            files.insert(position, padding_entry)
            padding_entries.append(padding_entry)

        return padding_entries

    def has_extended_attributes(self) -> bool:
        """Check if any file in the torrent has extended attributes.

        Returns
        -------
        bool
            True if any file has extended attributes (attr, sha1, symlink path).
        """
        files = self._get_files_list()
        if files is None:
            return False

        for entry in files:
            if not isinstance(entry, dict):
                continue
            attr = entry.get("attr") or entry.get(b"attr")
            sha1 = entry.get("sha1") or entry.get(b"sha1")
            symlink = entry.get("symlink path") or entry.get(b"symlink path")
            if attr or sha1 or symlink:
                return True

        return False

    def get_file_count_by_attr(self, attr: str) -> int:
        """Get the count of files with a specific attribute.

        Parameters
        ----------
        attr : str
            The attribute character to count ('l', 'x', 'h', 'p').

        Returns
        -------
        int
            Number of files with the specified attribute.
        """
        count = 0
        files = self._get_files_list()
        if files is None:
            return 0

        for entry in files:
            if not isinstance(entry, dict):
                continue
            file_attr = entry.get("attr") or entry.get(b"attr")
            if file_attr and isinstance(file_attr, str) and attr in file_attr:
                count += 1

        return count

    @property
    def symlink_count(self) -> int:
        """Get the number of symlink files in the torrent.

        Returns
        -------
        int
            Number of symlinks.
        """
        return self.get_file_count_by_attr(bep47.FileAttribute.SYMLINK)

    @property
    def executable_count(self) -> int:
        """Get the number of executable files in the torrent.

        Returns
        -------
        int
            Number of executable files.
        """
        return self.get_file_count_by_attr(bep47.FileAttribute.EXECUTABLE)

    @property
    def hidden_count(self) -> int:
        """Get the number of hidden files in the torrent.

        Returns
        -------
        int
            Number of hidden files.
        """
        return self.get_file_count_by_attr(bep47.FileAttribute.HIDDEN)

    @property
    def padding_file_count(self) -> int:
        """Get the number of padding files in the torrent.

        Returns
        -------
        int
            Number of padding files.
        """
        return self.get_file_count_by_attr(bep47.FileAttribute.PADDING)

    @property
    def total_padding_bytes(self) -> int:
        """Get the total number of bytes used by padding files.

        Returns
        -------
        int
            Total bytes used by all padding files.
        """
        total = 0
        for i in range(self.file_count):
            if self.is_padding_file(i):
                entry = self._get_normalized_file_entry(i)
                if entry:
                    total += entry.get("length", 0)
        return total

    @classmethod
    def parse(cls, buffer: bytes) -> Torrent:
        """Parse a torrent from raw bytes.

        Parameters
        ----------
        buffer : bytes
            The raw torrent file content.

        Returns
        -------
        Torrent
            The parsed Torrent object.
        """
        data = bencode_module.decode(buffer)
        return cls(data)

    @classmethod
    def parse_file(cls, path: str | Path) -> Torrent:
        """Parse a torrent from a file on disk.

        Parameters
        ----------
        path : str | Path
            The path to the .torrent file.

        Returns
        -------
        Torrent
            The parsed Torrent object.
        """
        with closing(open(path, 'rb')) as fd:
            return cls.parse(fd.read())

    @staticmethod
    def compute_infohash(info: BEncodeValue) -> bytes:
        """Compute the infohash for a given info dictionary.

        The infohash is SHA-1 hash of the BEncoded info dictionary.

        Parameters
        ----------
        info : BEncodeValue
            The info dictionary from a torrent file.

        Returns
        -------
        bytes
            The 20-byte infohash.
        """
        return hashlib.sha1(bencode_module.encode(info)).digest()

    def __repr__(self) -> str:
        name = self.name or 'unknown'
        return f"Torrent(name={name!r}, infohash={self.infohash.hex()!r})"

    def __str__(self) -> str:
        name = self.name or 'unknown'
        return f"Torrent: {name} ({self.infohash.hex()})"

    # ---- MongoDB integration (optional) ----

    @classmethod
    def _ensure_mongo(cls) -> bool:
        """Ensure MongoDB client is available.

        Returns
        -------
        bool
            True if MongoDB is available, False otherwise.
        """
        if not MONGO_AVAILABLE:
            return False

        if cls._mongo_client is None:
            try:
                cls._mongo_client = pymongo.MongoClient(serverSelectionTimeoutMS=1000)
                cls._db = cls._mongo_client.dht
                cls._torrents = cls._db.torrents
                cls._torrents.create_index('infohash', unique=True)
            except Exception:
                cls._mongo_client = None
                return False

        return cls._mongo_client is not None

    @classmethod
    def store(cls, torrent: Torrent) -> None:
        """Store a torrent in MongoDB.

        Parameters
        ----------
        torrent : Torrent
            The torrent to store.

        Raises
        ------
        MongoNotAvailableError
            If MongoDB is not available.
        """
        if not cls._ensure_mongo():
            raise MongoNotAvailableError("MongoDB is not available")

        info = torrent.info
        if isinstance(info, dict):
            # Convert byte keys to string keys for storage
            info = {
                k.decode('utf-8') if isinstance(k, bytes) else k: v
                for k, v in info.items()
            }

        doc = {
            'infohash': torrent.infohash.hex(),
            'name': torrent.name,
            'info': info,
            'trackers': torrent.trackers,
        }

        cls._torrents.replace_one(
            {'infohash': torrent.infohash.hex()},
            doc,
            upsert=True,
        )

    @classmethod
    def find_by_infohash(cls, infohash: bytes | str) -> Optional[dict]:
        """Find a torrent by its infohash.

        Parameters
        ----------
        infohash : bytes | str
            The infohash to search for.

        Returns
        -------
        dict | None
            The stored torrent document, or None if not found.
        """
        if not cls._ensure_mongo():
            return None

        if isinstance(infohash, bytes):
            infohash = infohash.hex()

        return cls._torrents.find_one({'infohash': infohash})

    @classmethod
    def search(cls, query: str) -> list[dict]:
        """Search stored torrents by name.

        Parameters
        ----------
        query : str
            The search string.

        Returns
        -------
        list[dict]
            Matching torrent documents.
        """
        if not cls._ensure_mongo():
            return []

        return list(cls._torrents.find(
            {'name': {'$regex': query, '$options': 'i'}}
        ))