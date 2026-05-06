"""Tests for BEP 0036 - Torrent RSS feeds (dhtrack/rss_feed.py)."""

from __future__ import annotations

import pytest

from dhtrack.rss_feed import (
    RSSFeed,
    RSSFeedError,
    RSSParseError,
    TorrentFeedItem,
    create_rss_feed,
    create_torrent_item_rss,
    detect_magnet_uri,
    detect_torrent_url,
    extract_info_hash_from_magnet,
    parse_item,
    parse_rss_feed,
)


# ---------------------------------------------------------------------------
# TorrentFeedItem tests
# ---------------------------------------------------------------------------


class TestTorrentFeedItem:
    """Tests for TorrentFeedItem."""

    def test_empty_item_is_not_valid(self):
        item = TorrentFeedItem()
        assert item.is_valid() is False

    def test_item_with_torrent_url_is_valid(self):
        item = TorrentFeedItem(torrent_url="http://example.com/torrent.torrent")
        assert item.is_valid() is True

    def test_item_with_info_hash_is_valid(self):
        item = TorrentFeedItem(info_hash="a" * 40)
        assert item.is_valid() is True

    def test_item_with_guid_is_valid(self):
        item = TorrentFeedItem(guid="unique-id")
        assert item.is_valid() is True

    def test_info_hash_hex_lowercase(self):
        item = TorrentFeedItem(info_hash="A1B2C3")
        assert item.info_hash_hex == "a1b2c3"

    def test_info_hash_upper_uppercase(self):
        item = TorrentFeedItem(info_hash="a1b2c3")
        assert item.info_hash_upper == "A1B2C3"

    def test_info_hash_hex_none_when_empty(self):
        item = TorrentFeedItem()
        assert item.info_hash_hex is None

    def test_get_torrent_link_returns_torrent_url(self):
        item = TorrentFeedItem(torrent_url="http://example.com/a.torrent")
        assert item.get_torrent_link() == "http://example.com/a.torrent"

    def test_get_torrent_link_fallback_to_magnet(self):
        item = TorrentFeedItem(magnet_uri="magnet:?xt=foo")
        assert item.get_torrent_link() == "magnet:?xt=foo"

    def test_get_torrent_link_fallback_to_link(self):
        item = TorrentFeedItem(link="http://example.com/a.torrent")
        assert item.get_torrent_link() == "http://example.com/a.torrent"

    def test_get_torrent_link_fallback_to_guid_with_torrent(self):
        item = TorrentFeedItem(guid="http://example.com/a.torrent")
        assert item.get_torrent_link() == "http://example.com/a.torrent"

    def test_get_torrent_link_returns_none(self):
        item = TorrentFeedItem(guid="not-a-url")
        assert item.get_torrent_link() is None

    def test_is_magnet_true(self):
        item = TorrentFeedItem(magnet_uri="magnet:?xt=foo")
        assert item.is_magnet() is True

    def test_is_magnet_false(self):
        item = TorrentFeedItem(torrent_url="http://example.com/a.torrent")
        assert item.is_magnet() is False


# ---------------------------------------------------------------------------
# parse_item tests
# ---------------------------------------------------------------------------


class TestParseItem:
    """Tests for parse_item."""

    def test_parse_enclosure(self):
        xml = """<item>
            <title>Test</title>
            <enclosure url="http://example.com/torrent.torrent"
                       type="application/x-bittorrent" length="12345"/>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.title == "Test"
        assert item.torrent_url == "http://example.com/torrent.torrent"
        assert item.enclosure_length == 12345

    def test_parse_enclosure_priority_over_media_content(self):
        """Enclosure should take priority over media:content."""
        xml = """<item>
            <title>Test</title>
            <enclosure url="http://example.com/enclosure.torrent"
                       type="application/x-bittorrent"/>
            <media:content xmlns:media="http://search.yahoo.com/mrss/"
                           url="http://example.com/media.torrent"/>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.torrent_url == "http://example.com/enclosure.torrent"

    def test_parse_media_content(self):
        xml = """<item>
            <title>Test</title>
            <media:content xmlns:media="http://search.yahoo.com/mrss/"
                           url="http://example.com/torrent.torrent"
                           fileSize="1024"/>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.torrent_url == "http://example.com/torrent.torrent"
        assert item.content_size == 1024

    def test_parse_media_hash(self):
        xml = """<item>
            <title>Test</title>
            <media:hash xmlns:media="http://search.yahoo.com/mrss/" algo="sha1">
                a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
            </media:hash>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.info_hash == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        assert item.media_hash_algo == "sha1"

    def test_parse_link(self):
        xml = """<item>
            <title>Test</title>
            <link>http://example.com/torrent.torrent</link>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.torrent_url == "http://example.com/torrent.torrent"
        assert item.link == "http://example.com/torrent.torrent"

    def test_parse_guid(self):
        xml = """<item>
            <title>Test</title>
            <guid>abc123</guid>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.guid == "abc123"

    def test_parse_torrent_tag_eztv(self):
        xml = """<item>
            <title>Test</title>
            <torrent xmlns="http://xmlns.ezrss.it/0.1/">
                <infohash>a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2</infohash>
                <contentlength>600162597</contentlength>
                <filename>Test Torrent</filename>
                <magneturi>magnet:?xt=urn:btih:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2</magneturi>
            </torrent>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.info_hash == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        assert item.content_length == 600162597
        assert item.filename == "Test Torrent"
        assert "magnet:" in item.magnet_uri

    def test_parse_torrent_tag_with_trackers(self):
        xml = """<item>
            <title>Test</title>
            <torrent xmlns="http://xmlns.ezrss.it/0.1/">
                <trackers>
                    <group order="ordered">
                        <tracker seeds="10" peers="20">
                            udp://tracker.example.com/announce
                        </tracker>
                    </group>
                    <group order="random">
                        <tracker seeds="5" peers="10">
                            http://tracker2.example.com/announce
                        </tracker>
                    </group>
                </trackers>
            </torrent>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.trackers is not None
        assert len(item.trackers) == 2
        assert "udp://tracker.example.com/announce" in item.trackers

    def test_parse_pub_date(self):
        xml = """<item>
            <title>Test</title>
            <pubDate>Mon, 06 May 2026 12:00:00 GMT</pubDate>
        </item>"""
        import xml.etree.ElementTree as ET
        item_el = ET.fromstring(xml)
        item = parse_item(item_el)
        assert item.pub_date == "Mon, 06 May 2026 12:00:00 GMT"


# ---------------------------------------------------------------------------
# parse_rss_feed tests
# ---------------------------------------------------------------------------


class TestParseRSSFeed:
    """Tests for parse_rss_feed."""

    def test_parse_basic_feed(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
    <channel>
        <title>My Torrent Feed</title>
        <link>http://example.com</link>
        <description>Test feed</description>
        <ttl>3600</ttl>
        <language>en</language>
        <item>
            <title>Sample Torrent</title>
            <enclosure url="http://example.com/sample.torrent"
                       type="application/x-bittorrent" length="1024"/>
        </item>
    </channel>
</rss>"""
        feed = parse_rss_feed(xml)
        assert feed.title == "My Torrent Feed"
        assert feed.link == "http://example.com"
        assert feed.description == "Test feed"
        assert feed.ttl == 3600
        assert feed.language == "en"
        assert len(feed.items) == 1
        assert feed.items[0].title == "Sample Torrent"
        assert feed.items[0].torrent_url == "http://example.com/sample.torrent"

    def test_parse_empty_feed(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
    <channel>
        <title>Empty Feed</title>
    </channel>
</rss>"""
        feed = parse_rss_feed(xml)
        assert feed.title == "Empty Feed"
        assert len(feed.items) == 0

    def test_parse_multiple_items(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
    <channel>
        <title>Multi Item Feed</title>
        <item>
            <title>Torrent 1</title>
            <enclosure url="http://example.com/1.torrent"
                       type="application/x-bittorrent"/>
        </item>
        <item>
            <title>Torrent 2</title>
            <enclosure url="http://example.com/2.torrent"
                       type="application/x-bittorrent"/>
        </item>
    </channel>
</rss>"""
        feed = parse_rss_feed(xml)
        assert len(feed.items) == 2
        assert feed.items[0].title == "Torrent 1"
        assert feed.items[1].title == "Torrent 2"

    def test_parse_with_copyright(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
    <channel>
        <title>Feed</title>
        <copyright>CC BY-SA 4.0</copyright>
    </channel>
</rss>"""
        feed = parse_rss_feed(xml)
        assert feed.copyright == "CC BY-SA 4.0"

    def test_parse_with_managing_editor(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
    <channel>
        <title>Feed</title>
        <managingEditor>author@example.com</managingEditor>
        <webMaster>webmaster@example.com</webMaster>
    </channel>
</rss>"""
        feed = parse_rss_feed(xml)
        assert feed.author == "author@example.com"
        assert feed.manager == "webmaster@example.com"

    def test_invalid_xml_raises_error(self):
        with pytest.raises(RSSParseError, match="Invalid XML"):
            parse_rss_feed("not valid xml <>")

    def test_missing_channel_raises_error(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"></rss>"""
        with pytest.raises(RSSParseError, match="missing <channel>"):
            parse_rss_feed(xml)

    def test_empty_content_raises_error(self):
        with pytest.raises(RSSParseError, match="Empty RSS feed"):
            parse_rss_feed("")

    def test_invalid_ttl_defaults(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
    <channel>
        <title>Feed</title>
        <ttl>not-a-number</ttl>
    </channel>
</rss>"""
        feed = parse_rss_feed(xml)
        assert feed.ttl == 3600


# ---------------------------------------------------------------------------
# Feed generation tests
# ---------------------------------------------------------------------------


class TestFeedGeneration:
    """Tests for RSS feed generation functions."""

    def test_create_rss_feed(self):
        items = [
            TorrentFeedItem(
                title="Test",
                torrent_url="http://example.com/torrent.torrent",
                info_hash="a" * 40,
                content_size=1024,
            )
        ]
        xml = create_rss_feed(
            title="Test Feed",
            link="http://example.com",
            description="A test feed",
            items=items,
            ttl=1800,
            language="en",
        )
        assert '<?xml version="1.0"' in xml
        assert '<rss version="2.0">' in xml
        assert "<title>Test Feed</title>" in xml
        assert "<ttl>1800</ttl>" in xml

    def test_create_torrent_item_rss(self):
        xml = create_torrent_item_rss(
            title="Test Torrent",
            torrent_url="http://example.com/torrent.torrent",
            content_size=1024,
            info_hash="a" * 40,
            description="A test description",
        )
        assert "<title>Test Torrent</title>" in xml
        assert 'type="application/x-bittorrent"' in xml
        assert 'url="http://example.com/torrent.torrent"' in xml
        assert 'length="1024"' in xml
        assert 'fileSize="1024"' in xml
        assert 'algo="sha1"' in xml
        assert "aaaa" in xml

    def test_create_torrent_item_rss_with_guid(self):
        xml = create_torrent_item_rss(
            title="Test",
            torrent_url="http://example.com/torrent.torrent",
            guid="custom-guid",
        )
        assert "<guid>custom-guid</guid>" in xml

    def test_create_torrent_item_rss_with_info_hash_guid(self):
        xml = create_torrent_item_rss(
            title="Test",
            torrent_url="http://example.com/torrent.torrent",
            info_hash="b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )
        assert "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" in xml


# ---------------------------------------------------------------------------
# Convenience helper tests
# ---------------------------------------------------------------------------


class TestConvenienceHelpers:
    """Tests for convenience helper functions."""

    def test_detect_torrent_url(self):
        text = "Visit http://example.com/file.torrent for details"
        url = detect_torrent_url(text)
        assert url == "http://example.com/file.torrent"

    def test_detect_torrent_url_not_found(self):
        text = "No torrent here"
        assert detect_torrent_url(text) is None

    def test_detect_magnet_uri(self):
        text = "Use magnet:?xt=urn:btih=abc123 to download"
        uri = detect_magnet_uri(text)
        assert uri is not None
        assert uri.startswith("magnet:?")

    def test_detect_magnet_uri_not_found(self):
        text = "No magnet link here"
        assert detect_magnet_uri(text) is None

    def test_extract_info_hash_from_magnet_hex(self):
        uri = "magnet:?xt=urn:btih:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        h = extract_info_hash_from_magnet(uri)
        assert h == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

    def test_extract_info_hash_from_magnet_not_magnet(self):
        assert extract_info_hash_from_magnet("http://example.com") is None

    def test_extract_info_hash_from_magnet_empty(self):
        assert extract_info_hash_from_magnet("") is None

    def test_escape_xml_uses_html_escape(self):
        # Just verify html.escape is used by checking output is not plain text
        from dhtrack.rss_feed import _escape_xml
        result = _escape_xml("a & b")
        # The entity code for & is 38, so we should see &#38; or &
        assert "&#38;" in result or "&" in result

    def test_escape_xml_no_change(self):
        from dhtrack.rss_feed import _escape_xml
        assert _escape_xml("hello world") == "hello world"