"""
Torrent file parsing and infohash computation.

Provides utilities for parsing .torrent files and computing
infohashes used in BitTorrent and DHT protocols.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
from contextlib import closing
from pathlib import Path
from typing import Any, ClassVar, Optional

from dhtrack import bencode as bencode_module
from dhtrack.bencode import BEncodeValue


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

        # Get info — handle both byte and string keys
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

        Returns
        -------
        list[str]
            All tracker URLs from both single 'announce' and 'announce-list' tiers.
        """
        trackers: list[str] = []

        # Single tracker
        announce = self._get_key(self._normalized_dict, 'announce', b'announce')
        if announce is not None:
            if isinstance(announce, bytes):
                trackers.append(announce.decode('utf-8', errors='replace'))
            elif isinstance(announce, str):
                trackers.append(announce)

        # Tracker tiers (BEP 12) — 'announce-list' takes priority
        announce_list = self._get_key(self._normalized_dict, 'announce-list', b'announce-list')
        if announce_list is None:
            # Fallback to legacy key name
            announce_list = self._get_key(self._normalized_dict, 'announcelist', b'announcelist')

        if isinstance(announce_list, list):
            for tier in announce_list:
                if isinstance(tier, list):
                    for tracker in tier:
                        if isinstance(tracker, bytes):
                            trackers.append(tracker.decode('utf-8', errors='replace'))
                        elif isinstance(tracker, str):
                            trackers.append(tracker)

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

        Examples
        --------
        Single tier with multiple trackers::

            torrent.set_announce_list([
                ["http://tracker1.com/announce", "http://tracker2.com/announce"]
            ])

        Multiple tiers with fallback::

            torrent.set_announce_list([
                ["http://primary1.com/announce", "http://primary2.com/announce"],
                ["http://backup1.com/announce"],
            ])
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

        Examples
        --------
        >>> torrent.shuffle_tier(0)  # Shuffle the first tier
        ['http://tracker2.com/announce', 'http://tracker1.com/announce']
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