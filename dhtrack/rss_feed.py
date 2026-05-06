"""BEP 0036 — Torrent RSS feeds.

Provides parsing and generation of RSS 2.0 feeds for torrent content.
Supports the various formats documented in BEP 0036 for identifying
torrents in RSS feed items, including:

- ``<enclosure>`` tag (recommended standard)
- ``<media:content>`` tag (Media RSS)
- ``<media:hash>`` tag (info hash)
- ``<link>`` tag (torrent URL)
- ``<torrent>`` tag (extended torrent metadata from eztv namespace)
- ``<guid>`` tag (unique identifier or torrent URL)

Examples
--------
>>> from dhtrack import rss_feed
>>> rss_xml = open("feed.xml").read()
>>> feed = rss_feed.parse_rss_feed(rss_xml)
>>> feed.title
"My Torrent Feed"
>>> len(feed.items)
2
>>> feed.items[0].title
"Example Torrent"
"""

from __future__ import annotations

import base64
import html
import logging
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# XML namespace constants
# ---------------------------------------------------------------------------

# Media RSS namespace (http://search.yahoo.com/mrss/)
MEDIA_NS = "http://search.yahoo.com/mrss/"

# Eztv / ltrss namespace for extended torrent metadata
# (http://xmlns.ezrss.it/0.1/)
EZRSS_NS = "http://xmlns.ezrss.it/0.1/"

# Generic torrent namespace
GENERIC_TORRENT_NS = "urn:bittorrent:rss"

# RSS 2.0 namespace (not explicitly declared in feeds, but convention)
RSS_VERSION = "2.0"

# Enclosure type for torrent files
TORRENT_ENCLOSURE_TYPE = "application/x-bittorrent"

# Regex patterns for identifying torrent URLs
# Matches .torrent URLs (HTTP(S))
_TORRENT_URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+\.torrent(?:\?[^\s<>\"']*)?",
    re.IGNORECASE,
)

# Matches magnet URIs
_MAGNET_PATTERN = re.compile(r"magnet:\?", re.IGNORECASE)

# Info hash pattern (40 hex chars for SHA-1)
_INFOHASH_PATTERN = re.compile(r"[0-9a-fA-F]{40}")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TorrentFeedItem:
    """Represents a single torrent entry from an RSS feed.

    Attributes
    ----------
    title : str or None
        Torrent name from the ``<title>`` element.
    description : str or None
        Description from the ``<description>`` element.
    torrent_url : str or None
        Direct URL to the ``.torrent`` file or magnet link.
    info_hash : str or None
        Hex-encoded 40-character SHA-1 info hash.
    guid : str or None
        Unique identifier for the item.
    enclosure_length : int or None
        Size of the ``.torrent`` file in bytes (from ``<enclosure length>``).
    content_size : int or None
        Size of the torrent's content in bytes (from ``<media:content fileSize>``).
    filename : str or None
        Display name of the torrent file (from ``<torrent filename>``).
    content_length : int or None
        Total content size in bytes (from ``<torrent contentlength>``).
    magnet_uri : str or None
        Full magnet URI (from ``<torrent magneturi>``).
    trackers : list[str] or None
        List of tracker URLs extracted from the ``<trackers>`` element.
    link : str or None
        The ``<link>`` element body (alternative torrent URL).
    media_hash_algo : str or None
        Hash algorithm identifier (typically "sha1" from ``<media:hash>``).
    pub_date : str or None
        Publication date from ``<pubDate>`` element.
    """

    title: Optional[str] = None
    description: Optional[str] = None
    torrent_url: Optional[str] = None
    info_hash: Optional[str] = None
    guid: Optional[str] = None
    enclosure_length: Optional[int] = None
    content_size: Optional[int] = None
    filename: Optional[str] = None
    content_length: Optional[int] = None
    magnet_uri: Optional[str] = None
    trackers: Optional[list[str]] = None
    link: Optional[str] = None
    media_hash_algo: Optional[str] = None
    pub_date: Optional[str] = None

    @property
    def info_hash_hex(self) -> Optional[str]:
        """Return lower-case hex-encoded info hash.

        Returns
        -------
        str or None
            Lower-case hex string, or ``None`` if unavailable.
        """
        if self.info_hash is None:
            return None
        return self.info_hash.lower()

    @property
    def info_hash_upper(self) -> Optional[str]:
        """Return upper-case hex-encoded info hash (BTIH format).

        Returns
        -------
        str or None
            Upper-case hex string, or ``None`` if unavailable.
        """
        if self.info_hash is None:
            return None
        return self.info_hash.upper()

    def get_torrent_link(self) -> Optional[str]:
        """Get the primary torrent link.

        Returns the ``torrent_url`` if available, otherwise falls back to
        ``link``, ``magnet_uri``, or ``guid``.

        Returns
        -------
        str or None
            The primary torrent URL, magnet link, or ``None``.
        """
        if self.torrent_url:
            return self.torrent_url
        if self.magnet_uri:
            return self.magnet_uri
        if self.link:
            return self.link
        if self.guid and _TORRENT_URL_PATTERN.search(self.guid):
            return self.guid
        return None

    def is_magnet(self) -> bool:
        """Check if the torrent link is a magnet URI.

        Returns
        -------
        bool
            ``True`` if the primary link is a magnet URI.
        """
        link = self.get_torrent_link()
        if link is None:
            return False
        return _MAGNET_PATTERN.search(link) is not None

    def is_valid(self) -> bool:
        """Check if this item has at least one identifying torrent field.

        Returns
        -------
        bool
            ``True`` if any of ``torrent_url``, ``info_hash``,
            ``magnet_uri``, ``guid``, ``link`` is set.
        """
        return any([
            self.torrent_url,
            self.info_hash,
            self.magnet_uri,
            self.guid,
            self.link,
        ])


@dataclass
class RSSFeed:
    """Represents a parsed RSS 2.0 torrent feed.

    Attributes
    ----------
    title : str
        Feed title from ``<channel><title>``.
    link : str
        Feed link from ``<channel><link>``.
    description : str
        Feed description from ``<channel><description>``.
    ttl : int
        Time-to-live in seconds.  Clients should refresh the feed
        after this interval.
    language : str or None
        Language from ``<language>`` element.
    copyright : str or None
        Copyright notice from ``<copyright>`` element.
    manager : str or None
        Webmaster from ``<webMaster>`` element.
    author : str or None
        Author from ``<managingEditor>`` element.
    items : list[TorrentFeedItem]
        List of parsed torrent items.
    """

    title: str = ""
    link: str = ""
    description: str = ""
    ttl: int = 3600
    language: Optional[str] = None
    copyright: Optional[str] = None
    manager: Optional[str] = None
    author: Optional[str] = None
    items: list[TorrentFeedItem] = field(default_factory=list)


class RSSFeedError(Exception):
    """Base exception for RSS feed parsing errors."""


class RSSParseError(RSSFeedError):
    """Raised when an RSS feed cannot be parsed."""


class RSSValidationError(RSSFeedError):
    """Raised when an RSS feed fails validation."""


# ---------------------------------------------------------------------------
# XML namespace helpers
# ---------------------------------------------------------------------------


def _ns(tag: str, prefix: str = "") -> str:
    """Wrap a tag name in XML namespace braces.

    Parameters
    ----------
    tag : str
        The local tag name.
    prefix : str
        Optional prefix (without colon).

    Returns
    -------
    str
        Namespaced tag string, e.g. ``"{http://search.yahoo.com/mrss/}content"``.
    """
    ns_map: dict[str, str] = {
        "media": MEDIA_NS,
        "torrent": EZRSS_NS,
    }
    ns = ns_map.get(prefix, prefix)
    return f"{{{ns}}}{tag}"


def _find_text(
    element: ET.Element,
    path: str,
    namespaces: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Get the text content of a child element.

    Parameters
    ----------
    element : Element
        The parent element.
    path : str
        Child tag or XPath.
    namespaces : dict or None
        Namespace mapping for XPath queries.

    Returns
    -------
    str or None
        Text content, or ``None`` if the element is not found.
    """
    child = element.find(path, namespaces)
    if child is None:
        return None
    text = child.text
    if text is None:
        return None
    return text.strip() if text.strip() else None


# ---------------------------------------------------------------------------
# Torrent item extraction
# ---------------------------------------------------------------------------


def _extract_enclosure(item_el: ET.Element) -> dict:
    """Extract enclosure attributes from an RSS item."""
    enclosure = item_el.find("enclosure")
    if enclosure is None:
        return {}

    attrs: dict = dict(enclosure.attrib)
    content_type = attrs.get("type", "")

    # Only return if this looks like a torrent enclosure
    if content_type == TORRENT_ENCLOSURE_TYPE or "torrent" in content_type.lower():
        return attrs
    return {}


def _extract_media_content(item_el: ET.Element) -> dict:
    """Extract media:content attributes from an RSS item."""
    # Try with namespace
    content = item_el.find(_ns("content", "media"))
    if content is None:
        # Try without namespace (some feeds omit the namespace declaration)
        content = item_el.find("*.content")
    if content is None:
        return {}
    return dict(content.attrib)


def _extract_media_hash(item_el: ET.Element) -> Optional[str]:
    """Extract the media:hash value from an RSS item."""
    hash_el = item_el.find(_ns("hash", "media"))
    if hash_el is None:
        return None
    text = hash_el.text
    if text is None:
        return None
    return text.strip()


def _extract_torrent_tag(item_el: ET.Element) -> dict:
    """Extract the extended ``<torrent>`` tag from an RSS item.

    Supports both the eztv namespace and generic torrent namespace.
    """
    # Try eztv namespace first
    torrent_el = item_el.find(_ns("torrent", "torrent"))
    if torrent_el is None:
        # Try generic namespace
        torrent_el = item_el.find(f"{{{GENERIC_TORRENT_NS}}}torrent")
    if torrent_el is None:
        # Try without namespace (some feeds use bare <torrent> tag)
        for el in item_el:
            if el.tag == "torrent" or el.tag.endswith("}torrent"):
                torrent_el = el
                break

    if torrent_el is None:
        return {}

    result: dict = {}

    for child in torrent_el:
        tag = child.tag
        # Strip namespace
        if "}" in tag:
            tag = tag.split("}", 1)[1]

        text = child.text
        if tag in ("infohash", "contentlength", "filename", "magneturi"):
            result[tag] = text.strip() if text else None
        elif tag == "trackers":
            # Parse tracker groups
            for group in child:
                group_order = group.attrib.get("order", "random")
                for tracker in group:
                    tracker_url = tracker.text.strip() if tracker.text else ""
                    if tracker_url:
                        result.setdefault("_trackers_ordered", []).append({
                            "url": tracker_url,
                            "order": group_order,
                            "seeds": tracker.attrib.get("seeds", "0"),
                            "peers": tracker.attrib.get("peers", "0"),
                        })
            if "_trackers_ordered" in result:
                # Sort by order preference
                ordered = result.pop("_trackers_ordered")
                result["trackers"] = [
                    t["url"] for t in sorted(
                        ordered,
                        key=lambda x: (0 if x["order"] == "ordered" else 1, x["url"]),
                    )
                ]
            else:
                result["trackers"] = []

    return result


def _parse_torrent_url(url: Optional[str]) -> Optional[str]:
    """Validate and clean a torrent URL.

    Parameters
    ----------
    url : str or None
        Raw URL to validate.

    Returns
    -------
    str or None
        Cleaned URL, or ``None`` if invalid.
    """
    if url is None:
        return None
    url = url.strip()
    if not url:
        return None
    # Verify it looks like a torrent URL or magnet
    if url.startswith("magnet:"):
        return url
    if url.startswith("http://") or url.startswith("https://"):
        if ".torrent" in url or "magnet" in url.lower():
            return url
        # Some feeds use regular HTTP URLs for torrents
        return url
    return None


def _parse_info_hash(raw_hash: Optional[str]) -> Optional[str]:
    """Validate and normalize an info hash string.

    Parameters
    ----------
    raw_hash : str or None
        Raw hex-encoded hash.

    Returns
    -------
    str or None
        Lower-case 40-character hex string, or ``None``.
    """
    if raw_hash is None:
        return None
    raw_hash = raw_hash.strip()
    if not raw_hash:
        return None

    # Remove non-hex characters
    cleaned = re.sub(r'[^0-9a-fA-F]', '', raw_hash)

    if len(cleaned) == 40:
        return cleaned.lower()

    logger.warning("Invalid info hash length: %d chars", len(cleaned))
    return None


# ---------------------------------------------------------------------------
# Main parsing
# ---------------------------------------------------------------------------


def parse_item(item_el: ET.Element) -> TorrentFeedItem:
    """Parse a single RSS ``<item>`` element into a :class:`TorrentFeedItem`.

    The parser extracts torrent information using the following priority
    order for identifying the torrent link:

    1. ``<enclosure type="application/x-bittorrent">`` (recommended)
    2. ``<media:content>`` with torrent URL
    3. ``<torrent>`` extended metadata tag
    4. ``<link>`` element containing a torrent URL
    5. ``<guid>`` containing a torrent URL

    Parameters
    ----------
    item_el : Element
        An ``<item>`` element from an RSS feed.

    Returns
    -------
    TorrentFeedItem
        Parsed torrent feed item.
    """
    item = TorrentFeedItem()

    # Title
    title = _find_text(item_el, "title")
    if title:
        item.title = title

    # Description
    description = _find_text(item_el, "description")
    if description:
        item.description = description

    # Publication date
    pub_date = _find_text(item_el, "pubDate")
    if pub_date:
        item.pub_date = pub_date

    # GUID
    guid = _find_text(item_el, "guid")
    if guid:
        item.guid = guid

    # Link
    link = _find_text(item_el, "link")
    if link:
        item.link = link

    # --- Extract torrent data ---

    # 1. Enclosure (preferred method)
    enclosure = _extract_enclosure(item_el)
    if enclosure:
        url = _parse_torrent_url(enclosure.get("url"))
        if url:
            item.torrent_url = url
            try:
                item.enclosure_length = int(enclosure.get("length", "0") or "0")
            except ValueError:
                item.enclosure_length = None

    # 2. media:content
    media = _extract_media_content(item_el)
    if media:
        media_url = media.get("url")
        if media_url:
            parsed_url = _parse_torrent_url(media_url)
            if parsed_url and not item.torrent_url:
                item.torrent_url = parsed_url
            try:
                item.content_size = int(media.get("fileSize", "0") or "0")
            except ValueError:
                item.content_size = None

    # 3. media:hash
    raw_hash = _extract_media_hash(item_el)
    if raw_hash:
        item.info_hash = _parse_info_hash(raw_hash)
        # Check for algo attribute
        hash_el = item_el.find(_ns("hash", "media"))
        if hash_el is not None:
            algo = hash_el.attrib.get("algo", "")
            if algo:
                item.media_hash_algo = algo

    # 4. Extended torrent tag
    torrent_data = _extract_torrent_tag(item_el)
    if torrent_data:
        if not item.torrent_url:
            magnet_uri = torrent_data.get("magneturi")
            if magnet_uri:
                item.magnet_uri = magnet_uri
                item.torrent_url = magnet_uri

        infohash = torrent_data.get("infohash")
        if infohash:
            if item.info_hash is None:
                item.info_hash = _parse_info_hash(infohash)

        filename = torrent_data.get("filename")
        if filename:
            item.filename = filename

        content_length = torrent_data.get("contentlength")
        if content_length:
            try:
                item.content_length = int(content_length)
            except ValueError:
                pass

        trackers = torrent_data.get("trackers")
        if trackers:
            item.trackers = trackers

    # 5. Fallback: link containing torrent URL
    if not item.torrent_url and link:
        parsed_link = _parse_torrent_url(link)
        if parsed_link:
            item.torrent_url = parsed_link

    # 6. Fallback: guid containing torrent URL
    if not item.torrent_url and guid:
        parsed_guid = _parse_torrent_url(guid)
        if parsed_guid:
            item.torrent_url = parsed_guid

    # Log items with only info_hash but no URL
    if not item.torrent_url and item.info_hash:
        logger.debug(
            "Item %r has info_hash but no torrent URL",
            item.title or item.guid,
        )

    return item


def parse_rss_feed(xml_content: str) -> RSSFeed:
    """Parse an RSS 2.0 feed XML document.

    Parameters
    ----------
    xml_content : str
        Raw RSS XML content as a string.

    Returns
    -------
    RSSFeed
        Parsed feed object with channel metadata and items.

    Raises
    ------
    RSSParseError
        If the XML is malformed or not a valid RSS feed.
    """
    if not xml_content or not xml_content.strip():
        raise RSSParseError("Empty RSS feed content")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        raise RSSParseError(f"Invalid XML: {exc}") from exc

    # Verify RSS root element
    if root.tag != "rss" and root.tag != "rdf":
        # Some feeds use Atom format
        if root.tag == "feed" and "atom" in str(root.tag):
            logger.warning("Atom feed detected; BEP 0036 focuses on RSS 2.0")
        elif root.tag != "rss":
            raise RSSParseError(
                f"Expected <rss> root element, got <{root.tag}>"
            )

    # Find channel element
    channel = root.find("channel")
    if channel is None:
        raise RSSParseError("RSS feed missing <channel> element")

    feed = RSSFeed()

    # Channel metadata
    title = _find_text(channel, "title")
    if title:
        feed.title = title

    link = _find_text(channel, "link")
    if link:
        feed.link = link

    description = _find_text(channel, "description")
    if description:
        feed.description = description

    ttl = _find_text(channel, "ttl")
    if ttl:
        try:
            feed.ttl = int(ttl)
        except ValueError:
            logger.warning("Invalid ttl value: %r", ttl)
            feed.ttl = 3600

    language = _find_text(channel, "language")
    if language:
        feed.language = language

    copyright = _find_text(channel, "copyright")
    if copyright:
        feed.copyright = copyright

    manager = _find_text(channel, "webMaster")
    if manager:
        feed.manager = manager

    author = _find_text(channel, "managingEditor")
    if author:
        feed.author = author

    # Parse items
    for item_el in channel.findall("item"):
        try:
            item = parse_item(item_el)
            if item.is_valid():
                feed.items.append(item)
        except Exception:
            logger.warning("Failed to parse RSS item", exc_info=True)

    return feed


# ---------------------------------------------------------------------------
# RSS Feed Generation
# ---------------------------------------------------------------------------


def _escape_xml(text: str) -> str:
    """Escape XML special characters.

    Parameters
    ----------
    text : str
        Raw text.

    Returns
    -------
    str
        Text with XML special characters escaped.
    """
    return html.escape(text, quote=True)


def create_rss_feed(
    title: str,
    link: str,
    description: str,
    items: list[TorrentFeedItem],
    ttl: int = 3600,
    language: Optional[str] = None,
) -> str:
    """Create an RSS 2.0 feed XML string from torrent items.

    Generates a feed using the recommended ``<enclosure>`` format with
    ``type="application/x-bittorrent"``.

    Parameters
    ----------
    title : str
        Feed title.
    link : str
        Feed link URL.
    description : str
        Feed description.
    items : list[TorrentFeedItem]
        Torrent items to include.
    ttl : int, optional
        Time-to-live in seconds.  Defaults to 3600.
    language : str or None
        Feed language code.

    Returns
    -------
    str
        Complete RSS 2.0 XML document as a string.
    """
    lines: list[str] = []
    lines.append('<?xml version="1.0" encoding="utf-8"?>')
    lines.append('<rss version="2.0">')
    lines.append('  <channel>')

    lines.append(f'    <title>{_escape_xml(title)}</title>')
    lines.append(f'    <link>{_escape_xml(link)}</link>')
    lines.append(f'    <description>{_escape_xml(description)}</description>')
    lines.append(f'    <ttl>{ttl}</ttl>')

    if language:
        lines.append(f'    <language>{_escape_xml(language)}</language>')

    lines.append('  </channel>')
    lines.append('</rss>')

    return '\n'.join(lines)


def create_torrent_item_rss(
    title: str,
    torrent_url: str,
    content_size: Optional[int] = None,
    info_hash: Optional[str] = None,
    description: Optional[str] = None,
    guid: Optional[str] = None,
) -> str:
    """Create a single RSS ``<item>`` element for a torrent.

    Uses the recommended ``<enclosure>`` format with
    ``type="application/x-bittorrent"``.

    Parameters
    ----------
    title : str
        Torrent display name.
    torrent_url : str
        URL to the ``.torrent`` file or magnet link.
    content_size : int or None
        Size of the torrent content in bytes.
    info_hash : str or None
        Hex-encoded info hash (for ``<guid>``).
    description : str or None
        Torrent description.
    guid : str or None
        Unique identifier.  Defaults to the info hash.

    Returns
    -------
    str
        An RSS ``<item>`` XML element string.
    """
    lines: list[str] = []
    lines.append('    <item>')
    lines.append(f'      <title>{_escape_xml(title)}</title>')

    if description:
        lines.append(f'      <description>{_escape_xml(description)}</description>')

    # GUID - prefer explicit info hash or a URL that acts as GUID
    if guid:
        lines.append(f'      <guid>{_escape_xml(guid)}</guid>')
    elif info_hash:
        lines.append(f'      <guid>{_escape_xml(info_hash)}</guid>')
    else:
        lines.append(f'      <guid>{_escape_xml(torrent_url)}</guid>')

    # Enclosure (recommended)
    enclosure_attrs: list[str] = [
        f'type="{TORRENT_ENCLOSURE_TYPE}"',
        f'url="{_escape_xml(torrent_url)}"',
    ]
    if content_size is not None:
        enclosure_attrs.append(f'length="{content_size}"')

    lines.append(
        f'      <enclosure {" ".join(enclosure_attrs)}/>'
    )

    # media:content (optional, for compatibility)
    media_attrs: list[str] = [
        f'url="{_escape_xml(torrent_url)}"',
    ]
    if content_size is not None:
        media_attrs.append(f'fileSize="{content_size}"')

    lines.append(
        f'      <media:content {" ".join(media_attrs)}/>'
    )

    # media:hash (optional)
    if info_hash:
        lines.append(
            f'      <media:hash algo="sha1">{_escape_xml(info_hash)}</media:hash>'
        )

    lines.append('    </item>')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def detect_torrent_url(text: str) -> Optional[str]:
    """Detect a torrent URL within arbitrary text.

    Parameters
    ----------
    text : str
        Text to search for torrent URLs.

    Returns
    -------
    str or None
        First detected torrent URL, or ``None``.
    """
    match = _TORRENT_URL_PATTERN.search(text)
    if match:
        return match.group(0)
    return None


def detect_magnet_uri(text: str) -> Optional[str]:
    """Detect a magnet URI within arbitrary text.

    Parameters
    ----------
    text : str
        Text to search for magnet URIs.

    Returns
    -------
    str or None
        First detected magnet URI, or ``None``.
    """
    match = _MAGNET_PATTERN.search(text)
    if match:
        start = match.start()
        end = start
        for i in range(start, len(text)):
            if text[i] in (' ', '\t', '\n', '\r', '"', "'", '>', '<'):
                end = i
                break
        else:
            end = len(text)
        return text[start:end]
    return None


def extract_info_hash_from_magnet(magnet_uri: str) -> Optional[str]:
    """Extract the info hash from a magnet URI.

    Parameters
    ----------
    magnet_uri : str
        A magnet URI string.

    Returns
    -------
    str or None
        Hex-encoded info hash, or ``None`` if not found.
    """
    if not magnet_uri or not magnet_uri.startswith("magnet:"):
        return None

    try:
        parsed = urllib.parse.urlparse(magnet_uri)
        params = urllib.parse.parse_qs(parsed.query)
        xt = params.get("xt", [])[0] if "xt" in params else ""
        if xt.startswith("urn:btih:"):
            btih = xt[9:]
            # Try hex first
            if len(btih) == 40:
                try:
                    bytes.fromhex(btih)
                    return btih.lower()
                except ValueError:
                    pass
            # Try base32
            cleaned = re.sub(r'[^A-Za-z0-9]', '', btih).upper()
            padding = (8 - len(cleaned) % 8) % 8
            padded = cleaned + "=" * padding
            try:
                decoded = base64.b32decode(padded)
                if len(decoded) >= 20:
                    return decoded[:20].hex()
            except Exception:
                pass
        return None
    except Exception:
        logger.warning("Failed to extract info hash from magnet: %r", magnet_uri)
        return None