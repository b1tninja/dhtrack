"""Tests for the dhtrack.bep47 module."""

from __future__ import annotations

import hashlib

import pytest

from dhtrack import bep47
from dhtrack.torrent import Torrent

# ============================================================================
# Test FileAttribute Constants
# ============================================================================


class TestFileAttributeConstants:
    """Tests for FileAttribute constants."""

    def test_symlink_attribute(self):
        """Should have 'l' for symlink."""
        assert bep47.FileAttribute.SYMLINK == "l"

    def test_executable_attribute(self):
        """Should have 'x' for executable."""
        assert bep47.FileAttribute.EXECUTABLE == "x"

    def test_hidden_attribute(self):
        """Should have 'h' for hidden."""
        assert bep47.FileAttribute.HIDDEN == "h"

    def test_padding_attribute(self):
        """Should have 'p' for padding file."""
        assert bep47.FileAttribute.PADDING == "p"

    def test_all_attributes(self):
        """Should contain all four attribute characters."""
        assert "l" in bep47.FileAttribute.ALL_ATTRIBUTES
        assert "x" in bep47.FileAttribute.ALL_ATTRIBUTES
        assert "h" in bep47.FileAttribute.ALL_ATTRIBUTES
        assert "p" in bep47.FileAttribute.ALL_ATTRIBUTES
        assert len(bep47.FileAttribute.ALL_ATTRIBUTES) == 4


# ============================================================================
# Test Attribute Parsing
# ============================================================================


class TestAttributeParsing:
    """Tests for parse_attr function."""

    def test_parse_single_attr(self):
        """Should parse a single attribute character."""
        result = bep47.parse_attr("l")
        assert result == {"l": True}

    def test_parse_multiple_attrs(self):
        """Should parse multiple attribute characters."""
        result = bep47.parse_attr("hx")
        assert result == {"h": True, "x": True}

    def test_parse_all_attrs(self):
        """Should parse all attribute characters."""
        result = bep47.parse_attr("lxhp")
        assert result == {"l": True, "x": True, "h": True, "p": True}

    def test_parse_empty_string(self):
        """Should return empty dict for empty string."""
        result = bep47.parse_attr("")
        assert result == {}

    def test_ignore_unknown_chars(self):
        """Should ignore unknown characters."""
        result = bep47.parse_attr("xyunknownz")
        # Only 'x' is a known attribute character, so only that should appear
        assert result == {"x": True}

    def test_parse_duplicate_chars(self):
        """Should handle duplicate characters."""
        result = bep47.parse_attr("xx")
        assert result == {"x": True}


# ============================================================================
# Test Attribute Formatting
# ============================================================================


class TestAttributeFormatting:
    """Tests for format_attr function."""

    def test_format_empty(self):
        """Should format empty set."""
        result = bep47.format_attr(set())
        assert result == ""

    def test_format_single(self):
        """Should format single attribute."""
        result = bep47.format_attr({"x"})
        assert result == "x"

    def test_format_multiple(self):
        """Should format multiple attributes sorted."""
        result = bep47.format_attr({"x", "h"})
        assert result == "hx"

    def test_format_all(self):
        """Should format all attributes sorted."""
        result = bep47.format_attr({"l", "x", "h", "p"})
        assert result == "hlpx"

    def test_filter_unknown(self):
        """Should filter out unknown attributes."""
        result = bep47.format_attr({"x", "z", "unknown"})
        assert result == "x"


# ============================================================================
# Test Has Attribute
# ============================================================================


class TestHasAttribute:
    """Tests for has_attribute function."""

    def test_present(self):
        """Should return True when attribute is present."""
        assert bep47.has_attribute("hx", "x") is True

    def test_not_present(self):
        """Should return False when attribute is not present."""
        assert bep47.has_attribute("hx", "l") is False

    def test_none_string(self):
        """Should return False for None string."""
        assert bep47.has_attribute(None, "x") is False

    def test_empty_string(self):
        """Should return False for empty string."""
        assert bep47.has_attribute("", "x") is False


# ============================================================================
# Test SHA1 Hash Utilities
# ============================================================================


class TestSHA1Hash:
    """Tests for SHA1 hash utilities."""

    def test_compute_sha1(self):
        """Should compute SHA1 hash correctly."""
        data = b"hello world"
        result = bep47.compute_sha1(data)
        assert len(result) == 20
        assert result == hashlib.sha1(data).digest()

    def test_compute_sha1_empty(self):
        """Should handle empty data."""
        result = bep47.compute_sha1(b"")
        assert len(result) == 20

    def test_compute_sha1_different(self):
        """Should produce different hashes for different data."""
        result1 = bep47.compute_sha1(b"abc")
        result2 = bep47.compute_sha1(b"def")
        assert result1 != result2

    def test_validate_sha1_valid(self):
        """Should validate correct SHA1 length."""
        sha1 = bep47.compute_sha1(b"test")
        assert bep47.validate_sha1(sha1) is True

    def test_validate_sha1_wrong_length(self):
        """Should reject wrong length."""
        assert bep47.validate_sha1(b"too short") is False

    def test_validate_sha1_not_bytes(self):
        """Should reject non-bytes."""
        assert bep47.validate_sha1("not bytes") is False


# ============================================================================
# Test Padding File Utilities
# ============================================================================


class TestPaddingFileUtilities:
    """Tests for padding file utilities."""

    def test_create_padding_length(self):
        """Should calculate correct padding length."""
        assert bep47.create_padding_length(16384, 10000) == 6384

    def test_padding_length_zero(self):
        """Should return 0 if already aligned."""
        assert bep47.create_padding_length(16384, 16384) == 0

    def test_padding_length_multiple(self):
        """Should return 0 if exact multiple of piece length."""
        assert bep47.create_padding_length(16384, 32768) == 0

    def test_padding_length_small_file(self):
        """Should handle small file."""
        assert bep47.create_padding_length(16384, 100) == 16284

    def test_padding_length_zero_file(self):
        """Should return 0 for zero-length file."""
        assert bep47.create_padding_length(16384, 0) == 0

    def test_padding_length_zero_piece(self):
        """Should return 0 for zero piece length."""
        assert bep47.create_padding_length(0, 100) == 0

    def test_padding_length_larger_than_piece(self):
        """Should handle file larger than piece length."""
        # 20000 % 16384 = 3616, padding = 16384 - 3616 = 12768
        assert bep47.create_padding_length(16384, 20000) == 12768

    def test_create_padding_file_entry(self):
        """Should create padding file entry."""
        entry = bep47.create_padding_file_entry(16384, 10000)
        assert entry is not None
        assert entry[b"path"] == [b".pad", b"6384"]
        assert entry[b"length"] == 6384
        assert entry[b"attr"] == b"p"

    def test_create_padding_file_entry_no_padding_needed(self):
        """Should return None when no padding needed."""
        entry = bep47.create_padding_file_entry(16384, 0)
        assert entry is None

    def test_create_padding_file_entry_aligned(self):
        """Should return None when already aligned."""
        entry = bep47.create_padding_file_entry(16384, 16384)
        assert entry is None


# ============================================================================
# Test Padding File Detection
# ============================================================================


class TestPaddingFileDetection:
    """Tests for padding file detection."""

    def test_is_padding_file_by_attr(self):
        """Should detect padding file by attr."""
        entry = {b"path": [b".pad", b"6384"], b"length": 6384, b"attr": b"p"}
        assert bep47.is_padding_file(entry) is True

    def test_is_padding_file_by_path(self):
        """Should detect padding file by path."""
        entry = {b"path": [b".pad", b"6384"], b"length": 6384}
        assert bep47.is_padding_file(entry) is True

    def test_is_not_padding_file(self):
        """Should return False for regular file."""
        entry = {b"path": [b"file.txt"], b"length": 100}
        assert bep47.is_padding_file(entry) is False

    def test_is_padding_file_empty_entry(self):
        """Should return False for empty entry."""
        assert bep47.is_padding_file({}) is False


# ============================================================================
# Test Symlink Detection
# ============================================================================


class TestSymlinkDetection:
    """Tests for symlink detection."""

    def test_is_symlink_by_attr(self):
        """Should detect symlink by attr."""
        entry = {b"path": [b"link"], b"length": 0, b"attr": b"l"}
        assert bep47.is_symlink(entry) is True

    def test_is_symlink_by_path(self):
        """Should detect symlink by symlink path."""
        entry = {b"path": [b"link"], b"length": 0, b"symlink path": [b"target"]}
        assert bep47.is_symlink(entry) is True

    def test_is_not_symlink(self):
        """Should return False for regular file."""
        entry = {"path": ["file.txt"], "length": 100}
        assert bep47.is_symlink(entry) is False

    def test_is_not_symlink_empty(self):
        """Should return False for empty entry."""
        assert bep47.is_symlink({}) is False


# ============================================================================
# Test Symlink Path Retrieval
# ============================================================================


class TestSymlinkPathRetrieval:
    """Tests for symlink path retrieval."""

    def test_get_symlink_path(self):
        """Should return symlink target path."""
        entry = {b"symlink path": [b"dir", b"target.txt"]}
        result = bep47.get_symlink_path(entry)
        assert result == [b"dir", b"target.txt"]

    def test_get_symlink_path_bytes(self):
        """Should handle byte string components."""
        entry = {b"symlink path": [b"dir", b"target.txt"]}
        result = bep47.get_symlink_path(entry)
        assert result == [b"dir", b"target.txt"]

    def test_get_symlink_path_none(self):
        """Should return None for non-symlink."""
        entry = {b"path": [b"file.txt"]}
        result = bep47.get_symlink_path(entry)
        assert result is None

    def test_get_symlink_path_empty(self):
        """Should return None for empty entry."""
        result = bep47.get_symlink_path({})
        assert result is None


# ============================================================================
# Test Symlink File Entry Creation
# ============================================================================


class TestSymlinkEntryCreation:
    """Tests for creating symlink file entries."""

    def test_create_symlink_entry(self):
        """Should create complete symlink entry."""
        entry = bep47.create_symlink_file_entry(path=["link_file"], target_path=["data", "target.txt"])
        assert entry[b"path"] == [b"link_file"]
        assert entry[b"length"] == 0
        assert entry[b"attr"] == b"l"
        assert entry[b"symlink path"] == [b"data", b"target.txt"]

    def test_create_symlink_entry_custom_length(self):
        """Should allow custom length (though always 0 for symlinks)."""
        entry = bep47.create_symlink_file_entry(path=["link"], target_path=["target"], length=0)
        assert entry[b"length"] == 0


# ============================================================================
# Test SHA1 File Entry Utilities
# ============================================================================


class TestSHA1FileEntry:
    """Tests for SHA1 file entry utilities."""

    def test_get_file_sha1(self):
        """Should retrieve SHA1 from entry."""
        sha1 = hashlib.sha1(b"test").digest()
        entry = {b"sha1": sha1}
        result = bep47.get_file_sha1(entry)
        assert result == sha1

    def test_get_file_sha1_missing(self):
        """Should return None when SHA1 missing."""
        entry = {b"path": [b"file.txt"]}
        result = bep47.get_file_sha1(entry)
        assert result is None

    def test_set_file_sha1(self):
        """Should set SHA1 on entry."""
        entry = {b"path": [b"file.txt"]}
        sha1 = hashlib.sha1(b"test").digest()
        bep47.set_file_sha1(entry, sha1)
        assert entry[b"sha1"] == sha1

    def test_set_file_sha1_invalid_length(self):
        """Should raise ValueError for wrong length."""
        entry: dict = {b"path": [b"file.txt"]}
        with pytest.raises(ValueError):
            bep47.set_file_sha1(entry, b"too short")


# ============================================================================
# Test File Entry Normalization
# ============================================================================


class TestFileEntryNormalization:
    """Tests for file entry normalization."""

    def test_normalize_byte_keys(self):
        """Should preserve bytes-key form."""
        entry = {b"path": [b"file.txt"], b"length": 100}
        result = bep47.normalize_file_entry(entry)
        assert isinstance(result, dict)
        assert b"path" in result
        assert b"length" in result

    def test_normalize_missing_fields(self):
        """Should add missing required fields."""
        entry: dict = {b"path": [b"file.txt"]}
        result = bep47.normalize_file_entry(entry)
        assert b"attr" in result
        assert result[b"attr"] == b""
        assert b"length" in result

    def test_normalize_all_fields(self):
        """Should preserve all fields."""
        entry = {
            b"path": [b"dir", b"file.txt"],
            b"length": 1024,
            b"attr": b"hx",
            b"sha1": hashlib.sha1(b"test").digest(),
        }
        result = bep47.normalize_file_entry(entry)
        assert result[b"path"] == [b"dir", b"file.txt"]
        assert result[b"length"] == 1024
        assert result[b"attr"] == b"hx"


# ============================================================================
# Test Build File Entry
# ============================================================================


class TestBuildFileEntry:
    """Tests for building file entries."""

    def test_build_minimal(self):
        """Should build minimal entry."""
        entry = bep47.build_file_entry(["file.txt"], 100)
        assert entry[b"path"] == [b"file.txt"]
        assert entry[b"length"] == 100

    def test_build_with_attr(self):
        """Should include attribute."""
        entry = bep47.build_file_entry(["file.txt"], 100, attr="hx")
        assert entry[b"attr"] == b"hx"

    def test_build_with_sha1(self):
        """Should include SHA1."""
        sha1 = hashlib.sha1(b"test").digest()
        entry = bep47.build_file_entry(["file.txt"], 100, sha1=sha1)
        assert entry[b"sha1"] == sha1

    def test_build_with_symlink(self):
        """Should include symlink path."""
        entry = bep47.build_file_entry(["link"], 0, symlink_path=["target"])
        assert entry[b"symlink path"] == [b"target"]


# ============================================================================
# Torrent Integration Tests
# ============================================================================


class TestTorrentExtendedAttributes:
    """Tests for BEP-47 integration with Torrent class."""

    def create_multifile_torrent(self) -> Torrent:
        """Create a torrent with extended attributes."""
        files = [
            {
                b"path": [b"executable"],
                b"length": 1024,
                b"attr": b"x",
            },
            {
                b"path": [b"hidden_file.txt"],
                b"length": 512,
                b"attr": b"h",
            },
            {
                b"path": [b"regular.txt"],
                b"length": 256,
            },
        ]
        data = {
            b"announce": b"http://tracker.example.com/announce",
            b"info": {
                b"name": b"test_torrent",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        return Torrent(data)

    def test_get_file_attribute(self):
        """Should get file attribute."""
        torrent = self.create_multifile_torrent()
        assert torrent.get_file_attribute(0) == b"x"
        assert torrent.get_file_attribute(1) == b"h"
        assert torrent.get_file_attribute(2) == b""

    def test_has_file_attribute(self):
        """Should check file attribute."""
        torrent = self.create_multifile_torrent()
        assert torrent.has_file_attribute(0, "x") is True
        assert torrent.has_file_attribute(0, "h") is False
        assert torrent.has_file_attribute(2, "x") is False

    def test_set_file_attribute(self):
        """Should set file attribute."""
        torrent = self.create_multifile_torrent()
        torrent.set_file_attribute(2, "x")
        assert torrent.has_file_attribute(2, "x") is True

    def test_set_file_attribute_unset(self):
        """Should unset file attribute."""
        torrent = self.create_multifile_torrent()
        torrent.set_file_attribute(0, "x", False)
        assert torrent.has_file_attribute(0, "x") is False

    def test_set_file_attribute_add_both(self):
        """Should add multiple attributes."""
        torrent = self.create_multifile_torrent()
        torrent.set_file_attribute(2, "x")
        torrent.set_file_attribute(2, "h")
        assert torrent.get_file_attribute(2) in (b"xh", b"hx")

    def test_symlink_count(self):
        """Should count symlinks."""
        torrent = self.create_multifile_torrent()
        assert torrent.symlink_count == 0

    def test_executable_count(self):
        """Should count executable files."""
        torrent = self.create_multifile_torrent()
        assert torrent.executable_count == 1

    def test_hidden_count(self):
        """Should count hidden files."""
        torrent = self.create_multifile_torrent()
        assert torrent.hidden_count == 1

    def test_padding_file_count(self):
        """Should count padding files."""
        torrent = self.create_multifile_torrent()
        assert torrent.padding_file_count == 0

    def test_has_extended_attributes(self):
        """Should detect extended attributes."""
        torrent = self.create_multifile_torrent()
        assert torrent.has_extended_attributes() is True

    def test_no_extended_attributes(self):
        """Should return False when no extended attributes."""
        data = {
            b"announce": b"http://tracker.example.com/announce",
            b"info": {
                b"name": b"simple",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
            },
        }
        torrent = Torrent(data)
        assert torrent.has_extended_attributes() is False


class TestTorrentPaddingFiles:
    """Tests for padding file handling."""

    def test_get_piece_length(self):
        """Should get piece length."""
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
            },
        }
        torrent = Torrent(data)
        assert torrent.get_piece_length() == 16384

    def test_get_piece_length_missing(self):
        """Should return 0 when piece length missing."""
        data = {
            b"info": {
                b"name": b"test",
                b"pieces": b"\x00" * 20,
            },
        }
        torrent = Torrent(data)
        assert torrent.get_piece_length() == 0

    def test_add_padding_file(self):
        """Should add padding file before target."""
        files = [
            {b"path": [b"file1.txt"], b"length": 10000},
            {b"path": [b"file2.txt"], b"length": 2048},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        # file2.txt starts at offset 10000
        # 10000 % 16384 = 10000
        # Padding needed: 16384 - 10000 = 6384
        result = torrent.add_padding_file(1)
        assert result is not None
        assert result[b"length"] == 6384
        assert torrent.file_count == 3

    def test_add_padding_file_no_padding_needed(self):
        """Should return None when no padding needed."""
        files = [
            {b"path": [b"file1.txt"], b"length": 16384},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        result = torrent.add_padding_file(1)
        assert result is None

    def test_total_padding_bytes(self):
        """Should calculate total padding bytes."""
        files = [
            {b"path": [b".pad", b"6384"], b"length": 6384, b"attr": b"p"},
            {b"path": [b"file1.txt"], b"length": 100},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        assert torrent.total_padding_bytes == 6384

    def test_is_padding_file(self):
        """Should identify padding files."""
        files = [
            {b"path": [b".pad", b"6384"], b"length": 6384, b"attr": b"p"},
            {b"path": [b"file.txt"], b"length": 100},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        assert torrent.is_padding_file(0) is True
        assert torrent.is_padding_file(1) is False

    def test_get_padding_length(self):
        """Should get padding file length."""
        files = [
            {b"path": [b".pad", b"6384"], b"length": 6384, b"attr": b"p"},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        assert torrent.get_padding_length(0) == 6384


class TestTorrentSymlinks:
    """Tests for symlink handling in Torrent."""

    def test_is_symlink(self):
        """Should identify symlink files."""
        files = [
            {
                b"path": [b"link"],
                b"length": 0,
                b"attr": b"l",
                b"symlink path": [b"target.txt"],
            },
            {b"path": [b"file.txt"], b"length": 100},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        assert torrent.is_symlink(0) is True
        assert torrent.is_symlink(1) is False

    def test_get_symlink_path(self):
        """Should get symlink path."""
        files = [
            {
                b"path": [b"link"],
                b"length": 0,
                b"attr": b"l",
                b"symlink path": [b"dir", b"target.txt"],
            },
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        path = torrent.get_symlink_path(0)
        assert path == [b"dir", b"target.txt"]

    def test_symlink_count(self):
        """Should count symlinks."""
        files = [
            {
                b"path": [b"link1"],
                b"length": 0,
                b"attr": b"l",
                b"symlink path": [b"target1"],
            },
            {b"path": [b"file.txt"], b"length": 100},
            {
                b"path": [b"link2"],
                b"length": 0,
                b"attr": b"l",
                b"symlink path": [b"target2"],
            },
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        assert torrent.symlink_count == 2


class TestTorrentSHA1:
    """Tests for SHA1 handling in Torrent."""

    def test_set_file_sha1(self):
        """Should set SHA1 on file."""
        files = [
            {b"path": [b"file.txt"], b"length": 100},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        sha1 = hashlib.sha1(b"file content").digest()
        torrent.set_file_sha1(0, sha1)
        result = torrent.get_file_sha1(0)
        assert result == sha1

    def test_compute_file_sha1(self):
        """Should compute and store SHA1."""
        files = [
            {b"path": [b"file.txt"], b"length": 100},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        data_content = b"file content"
        sha1 = torrent.compute_file_sha1(0, data_content)
        assert sha1 == hashlib.sha1(data_content).digest()
        assert torrent.get_file_sha1(0) == sha1

    def test_get_file_sha1_missing(self):
        """Should return None when SHA1 not set."""
        files = [
            {b"path": [b"file.txt"], b"length": 100},
        ]
        data = {
            b"info": {
                b"name": b"test",
                b"piece length": 16384,
                b"pieces": b"\x00" * 20,
                b"files": files,
            },
        }
        torrent = Torrent(data)
        assert torrent.get_file_sha1(0) is None
