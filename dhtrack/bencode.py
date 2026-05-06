"""
BEncode encoding and decoding for BitTorrent protocol data.

BEncode is the data serialization format used by BitTorrent and the DHT protocol.
It supports four types: integers, byte strings, lists, and dictionaries.

Examples
--------
>>> encode([b'info', b'hello', 42])
b'lle3:hei5:helloi42ee'
>>> decode(b'i42ee')
[42]
"""

from __future__ import annotations

import struct
from typing import Any


class BEncodeError(Exception):
    """Base exception for BEncode errors."""


class DecodeError(BEncodeError):
    """Raised when BEncode data cannot be decoded."""


class EncodeError(BEncodeError):
    """Raised when an object cannot be encoded."""


# Type aliases for BEncoded data
BEncodeInt = int
BEncodeBytes = bytes
BEncodeString = str
BEncodeList = list[Any]
BEncodeDict = dict[str, Any]
BEncodeValue = BEncodeInt | BEncodeBytes | BEncodeString | BEncodeList | BEncodeDict
BEncodeItem = tuple[str, BEncodeValue]


def decode(buffer: bytes | bytearray) -> BEncodeValue:
    """Parse a BEncode-encoded buffer and return the decoded value.

    Parameters
    ----------
    buffer : bytes | bytearray
        The raw BEncode buffer to decode.

    Returns
    -------
    BEncodeValue
        The decoded Python object.

    Raises
    ------
    DecodeError
        If the buffer is malformed or contains unsupported types.
    """
    if not buffer:
        raise DecodeError("Empty buffer")

    parsed, _ = _decode_item(buffer, 0)
    return parsed


def decode_item(buffer: bytes | bytearray, offset: int = 0) -> tuple[BEncodeValue, int]:
    """Parse a single BEncode item from the buffer at the given offset.

    Parameters
    ----------
    buffer : bytes | bytearray
        The raw BEncode buffer.
    offset : int
        The byte offset to start parsing from. Defaults to 0.

    Returns
    -------
    tuple[BEncodeValue, int]
        A tuple of (decoded_value, new_offset).
    """
    if offset >= len(buffer):
        raise DecodeError(f"Buffer exhausted at offset {offset}")

    parsed, new_offset = _decode_item(buffer, offset)
    return parsed, new_offset


def encode(value: BEncodeValue) -> bytes:
    """Encode a Python value into BEncode bytes.

    Parameters
    ----------
    value : BEncodeValue
        The Python object to encode. Must be one of: int, bytes, str, list, or dict.

    Returns
    -------
    bytes
        The BEncode-encoded byte string.

    Raises
    ------
    EncodeError
        If the value cannot be encoded.
    """
    try:
        return _encode_item(value)
    except (TypeError, ValueError, KeyError) as exc:
        raise EncodeError(f"Cannot encode value: {type(value).__name__}") from exc


def _decode_item(buffer: bytes | bytearray, offset: int) -> tuple[BEncodeValue, int]:
    """Internal: decode a single BEncode item from buffer at offset.

    Parameters
    ----------
    buffer : bytes | bytearray
        The raw BEncode buffer.
    offset : int
        The byte offset to start parsing from.

    Returns
    -------
    tuple[BEncodeValue, int]
        (decoded_value, new_offset)
    """
    if offset >= len(buffer):
        raise DecodeError("Buffer exhausted")

    byte = buffer[offset]

    # Integer: i<digits>e
    if byte == ord(b'i'):
        return _decode_integer(buffer, offset)

    # Byte string: <length>:<data>
    if ord(b'0') <= byte <= ord(b'9'):
        return _decode_string(buffer, offset)

    # Dictionary: d<items>e
    if byte == ord(b'd'):
        return _decode_dict(buffer, offset)

    # List: l<items>e
    if byte == ord(b'l'):
        return _decode_list(buffer, offset)

    raise DecodeError(f"Unexpected byte 0x{byte:02x} at offset {offset}")


def _decode_integer(buffer: bytes | bytearray, offset: int) -> tuple[BEncodeInt, int]:
    """Decode an integer from BEncode format.

    Format: i<digits>e
    """
    start = offset + 1  # skip 'i'
    end = buffer.index(ord(b'e'), start)

    try:
        value = int(buffer[start:end])
    except ValueError:
        raise DecodeError(f"Invalid integer at offset {offset}")

    return value, end + 1


def _decode_string(buffer: bytes | bytearray, offset: int) -> tuple[BEncodeBytes, int]:
    """Decode a byte string from BEncode format.

    Format: <length>:<data>
    """
    colon = buffer.index(ord(b':'), offset)

    try:
        length = int(buffer[offset:colon])
    except ValueError:
        raise DecodeError(f"Invalid string length at offset {offset}")

    if length < 0:
        raise DecodeError(f"Negative string length at offset {offset}")

    start = colon + 1
    end = start + length

    if end > len(buffer):
        raise DecodeError(f"String extends beyond buffer (need {end}, have {len(buffer)})")

    return buffer[start:end], end


def _decode_dict(buffer: bytes | bytearray, offset: int) -> tuple[BEncodeDict, int]:
    """Decode a dictionary from BEncode format.

    Format: d<key><value><key><value>...e
    Keys are always byte strings.
    """
    start = offset + 1  # skip 'd'
    result: dict[str, Any] = {}

    while True:
        if start >= len(buffer):
            raise DecodeError("Dictionary not terminated")

        # Check for termination
        if buffer[start] == ord(b'e'):
            return result, start + 1

        # Decode key
        key, start = _decode_string(buffer, start)
        key_str = key.decode('latin-1')  # BEncode keys are raw bytes, use latin-1 for compatibility

        # Decode value
        value, start = _decode_item(buffer, start)
        result[key_str] = value

    raise DecodeError("Unreachable")


def _decode_list(buffer: bytes | bytearray, offset: int) -> tuple[BEncodeList, int]:
    """Decode a list from BEncode format.

    Format: l<items>e
    """
    start = offset + 1  # skip 'l'
    result: list[Any] = []

    while True:
        if start >= len(buffer):
            raise DecodeError("List not terminated")

        if buffer[start] == ord(b'e'):
            return result, start + 1

        value, start = _decode_item(buffer, start)
        result.append(value)

    raise DecodeError("Unreachable")


def _encode_item(value: BEncodeValue) -> bytes:
    """Internal: encode a single BEncode value item.

    Parameters
    ----------
    value : BEncodeValue
        The value to encode.

    Returns
    -------
    bytes
        The BEncode-encoded bytes.
    """
    if isinstance(value, bytes):
        return _encode_bytes(value)

    if isinstance(value, int):
        return _encode_int(value)

    if isinstance(value, str):
        return _encode_str(value)

    if isinstance(value, list):
        return _encode_list(value)

    if isinstance(value, dict):
        return _encode_dict(value)

    raise EncodeError(f"Unsupported type: {type(value).__name__}")


def _encode_bytes(value: bytes) -> bytes:
    """Encode a bytes object as a BEncode byte string.

    Format: <length>:<data>
    """
    return f"{len(value)}:".encode('ascii') + value


def _encode_int(value: int) -> bytes:
    """Encode an integer as BEncode format.

    Format: i<digits>e
    """
    return f"i{value}e".encode('ascii')


def _encode_str(value: str) -> bytes:
    """Encode a string as a BEncode byte string (UTF-8 encoded)."""
    encoded = value.encode('utf-8')
    return f"{len(encoded)}:".encode('ascii') + encoded


def _encode_list(value: list) -> bytes:
    """Encode a list as BEncode format.

    Format: l<items>e
    """
    result = bytearray(b'l')
    for item in value:
        result.extend(_encode_item(item))
    result.extend(b'e')
    return bytes(result)


def _encode_dict(value: dict) -> bytes:
    """Encode a dictionary as BEncode format.

    Format: d<key><value><key><value>...e

    Keys are sorted by their UTF-8 byte representation, as required
    by the BitTorrent specification.
    """
    result = bytearray(b'd')

    # Sort keys by their byte representation
    for key in sorted(value.keys(), key=lambda k: k.encode('utf-8')):
        result.extend(_encode_bytes(key.encode('utf-8')))
        result.extend(_encode_item(value[key]))

    result.extend(b'e')
    return bytes(result)