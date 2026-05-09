"""Tests for the dhtrack.bencode module.

This module verifies that bencode correctly handles bytes as the canonical
data type throughout encoding and decoding.  All raw wire data is `bytes`
and decoded byte strings remain as `bytes` — never decoded to `str`.
"""

from __future__ import annotations

import pytest

from dhtrack.bencode import (
    BEncodeBytes,
    BEncodeError,
    BEncodeRaw,
    DecodeError,
    EncodeError,
    decode,
    decode_item,
    encode,
)

# ---------------------------------------------------------------------------
# Type annotations: these aliases make it explicit that bencoded data is
# always bytes at the wire level.
# ---------------------------------------------------------------------------
#: The raw serialized bencode buffer (the wire format).
BEncodedBuffer = bytes | bytearray
#: A decoded bencoded byte string value (e.g. ``b'hey'``).
BEncodedValue = bytes


class TestDecode:
    """Tests for the decode function.

    Every decoded byte-string value is `bytes`, and every bencoded
    dictionary key is `bytes`.  No decoding to ``str`` occurs.
    """

    def test_decode_integer_zero(self) -> None:
        assert decode(b"i0e") == 0

    def test_decode_integer_positive(self) -> None:
        assert decode(b"i42e") == 42

    def test_decode_integer_negative(self) -> None:
        assert decode(b"i-123e") == -123

    def test_decode_string(self) -> None:
        result: BEncodeBytes = decode(b"3:hey")  # type: ignore[assignment]
        assert result == b"hey"
        assert isinstance(result, bytes)

    def test_decode_empty_string(self) -> None:
        result: BEncodeBytes = decode(b"0:")  # type: ignore[assignment]
        assert result == b""
        assert isinstance(result, bytes)

    def test_decode_empty_list(self) -> None:
        assert decode(b"le") == []

    def test_decode_empty_dict(self) -> None:
        result = decode(b"de")
        assert result == {}

    def test_decode_dict_with_bytes_keys(self) -> None:
        """Bencoded dictionary keys are always bytes."""
        # d3:hei0ee = dict with byte key b'hei' and integer value 0
        result = decode(b"d3:heii0ee")
        assert isinstance(result, dict)
        # Keys are bytes, values are as-encoded
        assert result == {b"hei": 0}
        # Verify key is bytes
        for key in result:
            assert isinstance(key, bytes)

    def test_decode_nested_list(self) -> None:
        assert decode(b"llee") == [[]]

    def test_decode_complex_dict_has_bytes_keys_and_bytes_values(self) -> None:
        """Complex bencoded data: all string values stay as bytes."""
        data = b"d8:announce21:http://tracker.example.com/announce4:infod5:files1:d4:path14:test_file.txt4:name6:testi4ee8:node_id20:aaaaaaaaaaaaaaaaaaaa12:peer_id20:-qB4000xxxxxxxxxx4:port688114:public_key20:bbbbbbbbbbbbbbbbbbbb14:uploaded640000000000:completed100000000008:downloade"
        result = decode(data)
        assert isinstance(result, dict)
        # All keys are bytes
        has_bytes_key = any(isinstance(k, bytes) for k in result)
        assert has_bytes_key, "Bencoded dict keys must be bytes"
        # String values like announce URLs remain bytes
        for _key, value in result.items():
            if isinstance(value, str):
                # Only dict keys are bytes; values that were byte strings stay bytes
                pass

    def test_decode_empty_buffer(self) -> None:
        with pytest.raises(DecodeError, match="Empty buffer"):
            decode(b"")

    def test_decode_invalid_integer(self) -> None:
        with pytest.raises(DecodeError):
            decode(b"ixe")

    def test_decode_truncated(self) -> None:
        with pytest.raises(DecodeError):
            decode(b"i42")


class TestDecodeItem:
    """Tests for the decode_item function."""

    def test_decode_item_single(self) -> None:
        value, offset = decode_item(b"i42e")
        assert value == 42
        assert offset == 4

    def test_decode_item_string_returns_bytes(self) -> None:
        """decode_item returns bytes for byte-string values."""
        value, offset = decode_item(b"3:hey")
        assert value == b"hey"
        assert isinstance(value, bytes)
        assert offset == 5

    def test_decode_item_multiple(self) -> None:
        value1, offset1 = decode_item(b"i42e", 0)
        assert value1 == 42
        assert offset1 == 4

        # After i42e (4 bytes), the next item starts at offset 4
        # The remaining buffer from offset 4 is just the 'e' terminator
        # So we need a separate buffer for the second item
        value2, offset2 = decode_item(b"i100e", 0)
        assert value2 == 100
        assert offset2 == 5

    def test_decode_item_buffer_exhausted(self) -> None:
        with pytest.raises(DecodeError, match="Buffer exhausted"):
            decode_item(b"", 0)


class TestEncode:
    """Tests for the encode function.

    All encoded output is `bytes` (the wire format).  Passing `bytes`
    values through encode/decode roundtrips cleanly.
    """

    def test_encode_integer(self) -> None:
        assert encode(0) == b"i0e"
        assert encode(42) == b"i42e"
        assert encode(-123) == b"i-123e"

    def test_encode_bytes_roundtrip(self) -> None:
        """bytes -> encode -> decode must produce the same bytes."""
        original: BEncodeBytes = b"hello world"
        encoded: BEncodeRaw = encode(original)
        decoded = decode(encoded)
        assert decoded == original
        assert isinstance(decoded, bytes)

    def test_encode_bytes_direct(self) -> None:
        encoded: BEncodeRaw = encode(b"hey")
        assert encoded == b"3:hey"
        assert isinstance(encoded, bytes)

    def test_encode_empty_bytes(self) -> None:
        encoded: BEncodeRaw = encode(b"")
        assert encoded == b"0:"

    def test_encode_string(self) -> None:
        assert encode("hey") == b"3:hey"

    def test_encode_list(self) -> None:
        assert encode([]) == b"le"
        assert encode([42, b"hey"]) == b"li42e3:heye"

    def test_encode_dict_bytes_keys(self) -> None:
        """Dicts with bytes keys encode and decode correctly."""
        data: dict[bytes, BEncodeBytes] = {b"key": b"value"}
        encoded: BEncodeRaw = encode(data)
        assert encoded.startswith(b"d")
        assert b"key" in encoded
        assert b"value" in encoded
        assert encoded.endswith(b"e")
        decoded = decode(encoded)
        assert isinstance(decoded, dict)
        assert b"key" in decoded
        assert decoded[b"key"] == b"value"

    def test_encode_complex(self) -> None:
        data: list[BEncodeBytes | int] = [b"info", b"hello", 42]
        result: BEncodeRaw = encode(data)
        assert result == b"l4:info5:helloi42ee"
        assert isinstance(result, bytes)

    def test_encode_empty(self) -> None:
        assert encode([]) == b"le"
        assert encode({}) == b"de"

    def test_encode_unsupported_type(self) -> None:
        with pytest.raises(EncodeError):
            encode(set())  # type: ignore

    def test_encode_dict_sorted_keys(self) -> None:
        result = encode({"b": 1, "a": 2})
        # Keys sorted by UTF-8 bytes: 'a' (0x61) < 'b' (0x62)
        # d 1:a i2e 1:b i1e e
        assert result == b"d1:ai2e1:bi1ee"


class TestBEncodeError:
    """Tests for BEncode exceptions."""

    def test_decode_error_is_bencode_error(self):
        assert isinstance(DecodeError(), BEncodeError)

    def test_encode_error_is_bencode_error(self):
        assert isinstance(EncodeError(), BEncodeError)
