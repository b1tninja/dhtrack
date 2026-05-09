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

import logging
from typing import Any

logger = logging.getLogger(__name__)
# Per-token decode trace (integers, strings, each dict key). Off unless set to DEBUG:
#   logging.getLogger("dhtrack.bencode.steps").setLevel(logging.DEBUG)
_steps = logging.getLogger(__name__ + ".steps")
_steps.setLevel(logging.WARNING)


class BEncodeError(Exception):
    """Base exception for BEncode errors."""


class DecodeError(BEncodeError):
    """Raised when BEncode data cannot be decoded."""


class EncodeError(BEncodeError):
    """Raised when an object cannot be encoded."""


# Type aliases for BEncoded data.
#
# IMPORTANT: Bencoded data (the raw serialized form) is always `bytes`.
# When bencode decodes byte strings from the wire, they remain as `bytes`.
# When encoding, byte strings (`bytes`) are the canonical form -- avoid
# using `str` for bencoded values whenever possible to prevent unnecessary
# bytes↔str conversions.
#
# BEncodeRaw     -- raw serialized bencode bytes (the wire format)
# BEncodeInt     -- integer values (Python `int`)
# BEncodeBytes   -- raw byte strings from bencode (Python `bytes`)
# BEncodeString  -- UTF-8 strings that will be encoded as bytes (use sparingly)
# BEncodeList    -- list of bencode values
# BEncodeDict    -- dict with bytes keys mapping to bencode values
#                  (decoded dictionaries MUST use bytes keys; do not accept str keys)
# BEncodeValue   -- any valid bencode value
# BEncodeItem    -- tuple of (key, value) for dictionary encoding

BEncodeRaw = bytes
BEncodeInt = int
BEncodeBytes = bytes
BEncodeString = str
BEncodeList = list[Any]
BEncodeDict = dict[bytes, Any]
BEncodeValue = BEncodeInt | BEncodeBytes | BEncodeString | BEncodeList | BEncodeDict
BEncodeItem = tuple[str, BEncodeValue]


def _decode_buffer(buffer: bytes | bytearray) -> bytes:
    """Internal parsers use ``bytes`` only; copy once when callers pass ``bytearray``."""
    return bytes(buffer) if isinstance(buffer, bytearray) else buffer


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
        logger.debug("Decode rejected: empty buffer")
        raise DecodeError("Empty buffer")

    logger.debug("Decoding %d bytes of bencode data", len(buffer))
    buf = _decode_buffer(buffer)
    parsed, _ = _decode_item(buf, 0)
    logger.debug("Decoded value type: %s", type(parsed).__name__)
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

    buf = _decode_buffer(buffer)
    parsed, new_offset = _decode_item(buf, offset)
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


def _decode_item(buffer: bytes, offset: int) -> tuple[BEncodeValue, int]:
    """Internal: decode a single BEncode item from buffer at offset.

    Parameters
    ----------
    buffer : bytes
        The raw BEncode buffer (callers normalize via :func:`_decode_buffer`).
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
    if byte == ord(b"i"):
        return _decode_integer(buffer, offset)

    # Byte string: <length>:<data>
    if ord(b"0") <= byte <= ord(b"9"):
        return _decode_string(buffer, offset)

    # Dictionary: d<items>e
    if byte == ord(b"d"):
        return _decode_dict(buffer, offset)

    # List: l<items>e
    if byte == ord(b"l"):
        return _decode_list(buffer, offset)

    raise DecodeError(f"Unexpected byte 0x{byte:02x} at offset {offset}")


def _decode_integer(buffer: bytes, offset: int) -> tuple[BEncodeInt, int]:
    """Decode an integer from BEncode format.

    Format: i<digits>e
    """
    start = offset + 1  # skip 'i'
    try:
        end = buffer.index(ord(b"e"), start)
    except ValueError:
        logger.debug("Unterminated integer at offset %d: no closing 'e'", offset)
        raise DecodeError(f"Unterminated integer at offset {offset}") from None

    try:
        value = int(buffer[start:end])
    except ValueError:
        logger.debug("Invalid integer at offset %d: %r", offset, buffer[start:end])
        raise DecodeError(f"Invalid integer at offset {offset}") from None

    _steps.debug(
        "Decoded integer i%sie at offset %d: %d",
        buffer[start:end].decode("ascii"),
        offset,
        value,
    )
    return value, end + 1


def _decode_string(buffer: bytes, offset: int) -> tuple[BEncodeBytes, int]:
    """Decode a byte string from BEncode format.

    Format: <length>:<data>
    """
    try:
        colon = buffer.index(ord(b":"), offset)
    except ValueError:
        logger.debug("Unterminated string at offset %d: no colon found", offset)
        raise DecodeError(f"Unterminated string at offset {offset}") from None

    try:
        length = int(buffer[offset:colon])
    except ValueError:
        logger.debug("Invalid string length at offset %d: %r", offset, buffer[offset:colon])
        raise DecodeError(f"Invalid string length at offset {offset}") from None

    if length < 0:
        logger.debug("Negative string length at offset %d: %d", offset, length)
        raise DecodeError(f"Negative string length at offset {offset}")

    start = colon + 1
    end = start + length

    if end > len(buffer):
        logger.debug("String extends beyond buffer: need %d, have %d at offset %d", end, len(buffer), offset)
        raise DecodeError(f"String extends beyond buffer (need {end}, have {len(buffer)})")

    _steps.debug(
        "Decoded byte string length %d at offset %d (first 32 bytes: %r)",
        length,
        offset,
        buffer[start : start + 32],
    )
    return buffer[start:end], end


def _decode_dict(buffer: bytes, offset: int) -> tuple[BEncodeDict, int]:
    """Decode a dictionary from BEncode format.

    Format: d<key><value><key><value>...e
    Keys are raw byte strings (bencoded as length-prefixed bytes).
    Keys are stored as bytes in the decoded dict, sorted by raw bytes.
    """
    start = offset + 1  # skip 'd'
    result: dict[bytes, Any] = {}
    item_count = 0

    while True:
        if start >= len(buffer):
            logger.debug("Dictionary not terminated, reached end of buffer at offset %d", start)
            raise DecodeError("Dictionary not terminated")

        # Check for termination
        if buffer[start] == ord(b"e"):
            _steps.debug("Decoded dictionary with %d keys at offset %d", item_count, offset)
            return result, start + 1

        # Decode key (keys are bencoded byte strings)
        key, start = _decode_string(buffer, start)

        # Decode value
        value, start = _decode_item(buffer, start)
        result[key] = value
        item_count += 1

        _steps.debug(
            "Decoded dict entry key=%r value_type=%s offset_after=%d",
            key,
            type(value).__name__,
            start,
        )

    raise DecodeError("Unreachable")


def _decode_list(buffer: bytes, offset: int) -> tuple[BEncodeList, int]:
    """Decode a list from BEncode format.

    Format: l<items>e
    """
    start = offset + 1  # skip 'l'
    result: list[Any] = []
    item_count = 0

    while True:
        if start >= len(buffer):
            logger.debug("List not terminated, reached end of buffer at offset %d", start)
            raise DecodeError("List not terminated")

        if buffer[start] == ord(b"e"):
            _steps.debug("Decoded list with %d items at offset %d", item_count, offset)
            return result, start + 1

        value, start = _decode_item(buffer, start)
        result.append(value)
        item_count += 1
        _steps.debug(
            "Decoded list item %d (type: %s) at offset %d",
            item_count,
            type(value).__name__,
            start,
        )

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
    return f"{len(value)}:".encode("ascii") + value


def _encode_int(value: int) -> bytes:
    """Encode an integer as BEncode format.

    Format: i<digits>e
    """
    return f"i{value}e".encode("ascii")


def _encode_str(value: str) -> bytes:
    """Encode a string as a BEncode byte string (UTF-8 encoded)."""
    encoded = value.encode("utf-8")
    return f"{len(encoded)}:".encode("ascii") + encoded


def _encode_list(value: list) -> bytes:
    """Encode a list as BEncode format.

    Format: l<items>e
    """
    result = bytearray(b"l")
    for item in value:
        result.extend(_encode_item(item))
    result.extend(b"e")
    return bytes(result)


def _encode_list_as_str(value: list) -> bytes:
    """Encode a Python list containing a single list value (for test compatibility).

    This helper encodes the outer container and inner items properly.
    """
    return _encode_list(value)


def _encode_dict(value: dict) -> bytes:
    """Encode a dictionary as BEncode format.

    Format: d<key><value><key><value>...e

    Keys are sorted by their raw byte representation, as required
    by BEP 3 (The BitTorrent Protocol Specification):
    "Keys must be strings and appear in sorted order (sorted as raw strings, not alphanumerics)."
    """
    result = bytearray(b"d")

    # Sort keys by raw bytes (BEP 3: "sorted as raw strings")
    sorted_keys = sorted(value.keys(), key=lambda k: k if isinstance(k, bytes) else k.encode("utf-8"))

    for key in sorted_keys:
        key_bytes = key if isinstance(key, bytes) else key.encode("utf-8")
        result.extend(_encode_bytes(key_bytes))
        result.extend(_encode_item(value[key]))

    result.extend(b"e")
    return bytes(result)
