"""
QUIC variable-length integer encoding/decoding.

Per RFC 9000 Section 16, QUIC uses a 2-bit length prefix (in the two
most significant bits of the first byte) to encode integers in 1, 2, 4
or 8 bytes:

    0b00 -> 1 byte  -> 6 usable bits   (0..63)
    0b01 -> 2 bytes -> 14 usable bits  (0..16383)
    0b10 -> 4 bytes -> 30 usable bits  (0..1073741823)
    0b11 -> 8 bytes -> 62 usable bits  (0..4611686018427387903)
"""

from __future__ import annotations

from dataclasses import dataclass


class VarIntError(ValueError):
    """Raised when a buffer does not contain a valid/complete varint."""


@dataclass(frozen=True)
class VarIntResult:
    value: int
    length: int  # number of bytes consumed


_LENGTH_FOR_PREFIX = {0b00: 1, 0b01: 2, 0b10: 4, 0b11: 8}


def decode_varint(data: bytes, offset: int = 0) -> VarIntResult:
    """Decode a single QUIC varint starting at ``offset``.

    Raises VarIntError if there are not enough bytes available.
    """
    if offset >= len(data):
        raise VarIntError("no data available to decode varint")

    first_byte = data[offset]
    prefix = (first_byte & 0xC0) >> 6
    length = _LENGTH_FOR_PREFIX[prefix]

    if offset + length > len(data):
        raise VarIntError(
            f"truncated varint: need {length} bytes, have {len(data) - offset}"
        )

    value = first_byte & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[offset + i]

    return VarIntResult(value=value, length=length)


def encode_varint(value: int) -> bytes:
    """Encode ``value`` as a QUIC varint, choosing the smallest form."""
    if value < 0:
        raise VarIntError("varint cannot be negative")
    if value <= 0x3F:
        return bytes([value])
    if value <= 0x3FFF:
        return (0x4000 | value).to_bytes(2, "big")
    if value <= 0x3FFFFFFF:
        return (0x80000000 | value).to_bytes(4, "big")
    if value <= 0x3FFFFFFFFFFFFFFF:
        return (0xC000000000000000 | value).to_bytes(8, "big")
    raise VarIntError("value too large for QUIC varint (max 62 bits)")


def varint_length_for_prefix(first_byte: int) -> int:
    """Return the total encoded length implied by a varint's first byte."""
    return _LENGTH_FOR_PREFIX[(first_byte & 0xC0) >> 6]
