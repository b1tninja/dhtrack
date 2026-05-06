"""
Torrent file parsing and infohash computation.

Provides utilities for parsing .torrent files and computing
infohashes used in BitTorrent and DHT protocols.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
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