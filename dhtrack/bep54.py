"""BEP 54 — The lt_donthave extension.

Provides the lt_donthave extension which allows a peer to advertise
that it no longer has a piece it previously advertised.

Message Format (per BEP 54):
    DontHave: <len=0x0006><op=20><subop=xx><index>

Wire format (serialized for transmission):
    [4-byte length=7][1-byte msg_type=20][1-byte subop][4-byte index]

Examples
--------
>>> from dhtrack.bep54 import encode_donthave, decode_donthave, create_donthave_message
>>> payload = encode_donthave(0x00, 42)
>>> decode_donthave(payload)
(0, 42)
>>> msg = create_donthave_message(0x00, 42)
>>> msg
b'\\x00\\x07\\x14\\x00*\\x00\\x2a'
"""

from __future__ import annotations

import struct

# BEP 54 constants
LT_DONTHAVE_NAME = b"lt_donthave"  # Extension name for LTEP handshake
LT_DONTHAVE_SUBOP = 1  # Default suboperation number

# Message type for extended messages (BEP 10)
EXTENDED_MSG_TYPE = 0
EXTENDED_MSG_OP = 20  # Extended message operation code

# Payload length (1 byte subop + 4 bytes index)
PAYLOAD_LENGTH = 5


def encode_donthave(subop: int, piece_index: int) -> bytes:
    """Encode a BEP 54 lt_donthave payload.

    Binary format per BEP 54:
        subop (1 byte): the suboperation number negotiated during LTEP handshake
        index (4 bytes, big-endian): the piece index that is no longer available

    Parameters
    ----------
    subop : int
        The suboperation number (0-255), negotiated during LTEP handshake.
    piece_index : int
        The piece index that is no longer available (>= 0).

    Returns
    -------
    bytes
        Encoded payload bytes (5 bytes).

    Raises
    ------
    ValueError
        If subop is out of range or piece_index is negative.
    """
    if not (0 <= subop <= 255):
        raise ValueError(f"subop must be 0-255, got {subop}")
    if piece_index < 0:
        raise ValueError(f"piece_index must be >= 0, got {piece_index}")

    return struct.pack("!BI", subop, piece_index)


def decode_donthave(data: bytes) -> tuple[int, int]:
    """Decode a BEP 54 lt_donthave payload.

    Parameters
    ----------
    data : bytes
        The binary payload bytes (minimum 5 bytes).

    Returns
    -------
    tuple[int, int]
        A tuple of (subop, piece_index).

    Raises
    ------
    ValueError
        If the data is too short or malformed.
    """
    if len(data) < 5:
        raise ValueError(f"Donthave payload too short: {len(data)} bytes (minimum 5)")

    subop = data[0]
    piece_index = struct.unpack("!I", data[1:5])[0]

    return subop, piece_index


def create_donthave_message(subop: int, piece_index: int) -> bytes:
    """Create a complete extended message for lt_donthave.

    Full wire format:
        [1-byte msg_type=0][2-byte length=7][1-byte op=20][1-byte subop][4-byte index]

    Parameters
    ----------
    subop : int
        The suboperation number (0-255).
    piece_index : int
        The piece index that is no longer available.

    Returns
    -------
    bytes
        Complete extended message bytes ready for transmission.
    """
    payload = encode_donthave(subop, piece_index)

    # Extended message format:
    # msg_type (1 byte) = 0 for extended message
    # payload_length (2 bytes, big-endian) = 5
    # op (1 byte) = 20
    # subop (1 byte)
    # index (4 bytes)
    msg = bytearray()
    msg.append(EXTENDED_MSG_TYPE)  # msg_type = 0 (extended message)
    msg.extend(struct.pack("!H", PAYLOAD_LENGTH))  # payload length = 5
    msg.append(EXTENDED_MSG_OP)  # op = 20
    msg.extend(payload)  # subop + index

    return bytes(msg)


def parse_donthave_from_extended(data: bytes) -> tuple[int, int] | None:
    """Extract lt_donthave data from an extended message.

    Given the payload bytes from an extended message (after the
    msg_type byte and 2-byte length prefix), extract the
    suboperation and piece index.

    Parameters
    ----------
    data : bytes
        The payload from an extended message (expected: [op][subop][index]).

    Returns
    -------
    tuple[int, int] or None
        A tuple of (subop, piece_index), or None if the message is invalid.
    """
    # Extended message payload: op (1 byte) + subop (1 byte) + index (4 bytes) = 6 bytes
    # But per BEP 54 spec, the payload length is 6 bytes (0x0006)
    # which includes op + subop + index
    if len(data) < 6:
        return None

    # Check if this is an extended message (msg_type = 0)
    # The op should be 20
    op = data[0]
    if op != EXTENDED_MSG_OP:
        return None

    # The remaining data after op is the lt_donthave payload
    # But the actual payload includes subop + index
    # Per BEP 54: <len=0x0006><op=20><subop=xx><index>
    # So the 6 bytes are: op(1) + subop(1) + index(4)
    # Extract subop and index from bytes 1-5
    subop = data[1]
    piece_index = struct.unpack("!I", data[2:6])[0]

    return subop, piece_index


def create_donthave_extended(data: bytes) -> bytes:
    """Create an extended message for lt_donthave.

    Parameters
    ----------
    data : bytes
        The lt_donthave payload (subop + index), 5 bytes.

    Returns
    -------
    bytes
        Complete extended message bytes.
    """
    msg = bytearray()
    msg.append(EXTENDED_MSG_TYPE)  # msg_type = 0 (extended message)
    msg.extend(struct.pack("!H", 5))  # payload length = 5
    msg.extend(data)  # subop + index (5 bytes)

    return bytes(msg)
