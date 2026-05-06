"""Tests for the dhtrack.bencode module."""

from __future__ import annotations

import pytest

from dhtrack.bencode import (
    BEncodeError,
    DecodeError,
    EncodeError,
    decode,
    decode_item,
    encode,
)


class TestDecode:
    """Tests for the decode function."""

    def test_decode_integer_zero(self):
        assert decode(b'i0e') == 0

    def test_decode_integer_positive(self):
        assert decode(b'i42e') == 42

    def test_decode_integer_negative(self):
        assert decode(b'i-123e') == -123

    def test_decode_string(self):
        assert decode(b'3:hey') == b'hey'

    def test_decode_empty_string(self):
        assert decode(b'0:') == b''

    def test_decode_empty_list(self):
        assert decode(b'le') == []

    def test_decode_empty_dict(self):
        assert decode(b'de') == {}

    def test_decode_dict_with_value(self):
        result = decode(b'd3:hei0e')
        assert result == {'hei': 0}

    def test_decode_nested_list(self):
        assert decode(b'llee') == [[]]

    def test_decode_complex(self):
        data = b'd8:announce21:http://tracker.example.com/announce4:infod5:files1:d4:path14:test_file.txt4:name6:testi4ee8:node_id20:aaaaaaaaaaaaaaaaaaaa12:peer_id20:-qB4000xxxxxxxxxx4:port688114:public_key20:bbbbbbbbbbbbbbbbbbbb14:uploaded640000000000:completed100000000008:downloade'
        result = decode(data)
        assert isinstance(result, dict)
        assert b'announce' in result or 'announce' in result

    def test_decode_empty_buffer(self):
        with pytest.raises(DecodeError, match='Empty buffer'):
            decode(b'')

    def test_decode_invalid_integer(self):
        with pytest.raises(DecodeError):
            decode(b'ixe')

    def test_decode_truncated(self):
        with pytest.raises(DecodeError):
            decode(b'i42')


class TestDecodeItem:
    """Tests for the decode_item function."""

    def test_decode_item_single(self):
        value, offset = decode_item(b'i42e')
        assert value == 42
        assert offset == 4

    def test_decode_item_multiple(self):
        value1, offset1 = decode_item(b'i42e', 0)
        assert value1 == 42
        assert offset1 == 4

        value2, offset2 = decode_item(b'i100e', offset1)
        assert value2 == 100
        assert offset2 == 8

    def test_decode_item_buffer_exhausted(self):
        with pytest.raises(DecodeError, match='Buffer exhausted'):
            decode_item(b'', 0)


class TestEncode:
    """Tests for the encode function."""

    def test_encode_integer(self):
        assert encode(0) == b'i0e'
        assert encode(42) == b'i42e'
        assert encode(-123) == b'i-123e'

    def test_encode_bytes(self):
        assert encode(b'hey') == b'3:hey'
        assert encode(b'') == b'0:'

    def test_encode_string(self):
        assert encode('hey') == b'3:hey'

    def test_encode_list(self):
        assert encode([]) == b'le'
        assert encode([42, b'hey']) == b'lli42e3:heye'

    def test_encode_dict(self):
        result = encode({'key': 'value'})
        assert result.startswith(b'd')
        assert b'key' in result
        assert b'value' in result
        assert result.endswith(b'e')

    def test_encode_complex(self):
        data = [b'info', b'hello', 42]
        result = encode(data)
        assert result == b'lle3:hei5:helloi42ee'

    def test_encode_empty(self):
        assert encode([]) == b'le'
        assert encode({}) == b'de'

    def test_encode_unsupported_type(self):
        with pytest.raises(EncodeError):
            encode(set())  # type: ignore

    def test_encode_dict_sorted_keys(self):
        result = encode({'b': 1, 'a': 2})
        # Keys should be sorted by UTF-8 bytes
        b_pos = result.index(b'1:')
        a_pos = result.index(b'2:')
        assert b_pos < a_pos


class TestBEncodeError:
    """Tests for BEncode exceptions."""

    def test_decode_error_is_bencode_error(self):
        assert isinstance(DecodeError(), BEncodeError)

    def test_encode_error_is_bencode_error(self):
        assert isinstance(EncodeError(), BEncodeError)