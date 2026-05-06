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

from dhtrack.bencode import BEncode, BEncodeValue


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

        if b'info' not in data:
            raise TorrentParseError("Torrent data missing 'info' field")

        self.dict: dict[str, Any] = data if isinstance(data, dict) else {}
        if isinstance(self.dict, dict):
            # Convert byte keys to string keys for consistency
            self.dict = {
                k.decode('utf-8') if isinstance(k, bytes) else k: v
                for k, v in self.dict.items()
            }

        # Compute infohash
        self.infohash: bytes = hashlib.sha1(BEncode.encode([b'info'])).digest()

    @property
    def name(self) -> Optional[str]:
        """Get the torrent name, if available."""
        info = self.dict.get(b'info' if isinstance(b'info' in self.dict, bool) else 'info', {})
        if isinstance(info, dict):
            name = info.get(b'name' if isinstance(info, dict) else 'name',
                           info.get('name'))
            if isinstance(name, bytes):
                return name.decode('utf-8', errors='replace')
            return str(name) if name else None
        return None

    @property
    def info(self) -> Optional[BEncodeValue]:
        """Get the raw info dictionary."""
        return self.dict.get('info')

    @property
    def trackers(self) -> list[str]:
        """Get the list of tracker URLs."""
        trackers: list[str] = []

        # Single tracker tier
        announce = self.dict.get(b'announce' if isinstance(b'announce' in self.dict, bool) else 'announce', '')
        if isinstance(announce, bytes):
            trackers.append(announce.decode('utf-8', errors='replace'))
        elif isinstance(announce, str):
            trackers.append(announce)

        # Tracker tiers (announcelist)
        announcelist = self.dict.get(b'announcelist' if isinstance(b'announcelist' in self.dict, bool) else 'announcelist',
                                     self.dict.get(b'announce-list' if isinstance(b'announce-list' in self.dict, bool) else 'announce-list', []))
        if isinstance(announcelist, list):
            for tier in announcelist:
                if isinstance(tier, list):
                    for tracker in tier:
                        if isinstance(tracker, bytes):
                            trackers.append(tracker.decode('utf-8', errors='replace'))
                        elif isinstance(tracker, str):
                            trackers.append(tracker)

        return trackers

    @property
    def file_count(self) -> int:
        """Get the number of files in the torrent."""
        info = self.info
        if info is None:
            return 0

        if isinstance(info, dict):
            if b'files' in info or 'files' in info:
                return len(info.get(b'files' if isinstance(b'files' in info, bool) else 'files', []))
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
        data = BEncode.parse(buffer)
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
        return hashlib.sha1(BEncode.encode(info)).digest()

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