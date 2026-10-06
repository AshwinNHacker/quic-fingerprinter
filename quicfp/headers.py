"""
QUIC packet header parsing.

Implements the cleartext portions of QUIC packet headers as defined in
RFC 9000 Section 17 ("Packet Formats"). Only fields that are visible to
a passive on-path observer are exposed here: the header-protection bits
that get unmasked later live in :mod:`quicfp.initial_crypto`.

Long Header (RFC 9000 §17.2)::

    +-+-+-+-+-+-+-+-+
    |1|1|T T|X X X X|
    +-+-+-+-+-+-+-+-+
    |         Version (32)         |
    +-+-+-+-+-+-+-+-+
    | DCID Len (8)  |
    +-+-+-+-+-+-+-+-+
    |   Dest Conn ID (0..160)    ...
    +-+-+-+-+-+-+-+-+
    | SCID Len (8)  |
    +-+-+-+-+-+-+-+-+
    |   Source Conn ID (0..160)  ...
    +-+-+-+-+-+-+-+-+

Short Header (RFC 9000 §17.3)::

    +-+-+-+-+-+-+-+-+
    |0|1|S|X X X X X|
    +-+-+-+-+-+-+-+-+
    |  Dest Conn ID (0..160)     ...
    +-+-+-+-+-+-+-+-+
    |  Packet Number (8/16/24/32) ...
    +-+-+-+-+-+-+-+-+
    |    Protected Payload (*)   ...
    +-+-+-+-+-+-+-+-+
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from quicfp.varint import VarIntError, decode_varint

# --------------------------------------------------------------------------
# Known / registered QUIC versions (IANA "QUIC Version Numbers" registry)
# --------------------------------------------------------------------------

QUIC_VERSION_NEGOTIATION = 0x00000000
QUIC_VERSION_1 = 0x00000001          # RFC 9000
QUIC_VERSION_2 = 0x6B3343CF          # RFC 9369
QUIC_VERSION_DRAFT27_34_PREFIX = 0xFF00_0000  # draft-ietf-quic-transport-XX

KNOWN_VERSION_NAMES = {
    0x00000000: "Version Negotiation",
    0x00000001: "QUIC v1 (RFC 9000)",
    0x6B3343CF: "QUIC v2 (RFC 9369)",
    0x51303433: "Google QUIC Q043",
    0x51303436: "Google QUIC Q046",
    0x51303530: "Google QUIC Q050",
    0xFAFAFAFA: "GREASE (example)",
}


def describe_version(version: int) -> str:
    if version in KNOWN_VERSION_NAMES:
        return KNOWN_VERSION_NAMES[version]
    if (version & 0x0F0F0F0F) == 0x0A0A0A0A:
        return "GREASE version (RFC 9287)"
    if 0xFF000000 <= version <= 0xFF000022:
        draft = version & 0xFF
        return f"QUIC draft-{draft:02d}"
    return f"Unknown (0x{version:08x})"


class LongPacketType(enum.IntEnum):
    """RFC 9000 §17.2 long header packet types (QUIC v1 encoding)."""

    INITIAL = 0x00
    ZERO_RTT = 0x01
    HANDSHAKE = 0x02
    RETRY = 0x03


LONG_PACKET_TYPE_NAMES = {
    LongPacketType.INITIAL: "Initial",
    LongPacketType.ZERO_RTT: "0-RTT",
    LongPacketType.HANDSHAKE: "Handshake",
    LongPacketType.RETRY: "Retry",
}

# QUIC v2 renumbers long-header packet types (RFC 9369 §3.2)
QUIC_V2_TYPE_MAP = {
    0b01: LongPacketType.INITIAL,
    0b10: LongPacketType.ZERO_RTT,
    0b11: LongPacketType.HANDSHAKE,
    0b00: LongPacketType.RETRY,
}


class HeaderParseError(ValueError):
    pass


@dataclass
class LongHeaderPacket:
    is_long_header: bool = True
    version: int = 0
    packet_type: LongPacketType | None = None
    dcid: bytes = b""
    scid: bytes = b""
    token: bytes | None = None
    length_field: int | None = None  # declared payload length (Initial/HS/0RTT)
    header_len: int = 0  # bytes consumed by the *unprotected* header portion
    first_byte: int = 0
    raw: bytes = field(default=b"", repr=False)

    @property
    def type_name(self) -> str:
        if self.version == QUIC_VERSION_NEGOTIATION:
            return "Version Negotiation"
        if self.packet_type is None:
            return "Unknown"
        return LONG_PACKET_TYPE_NAMES.get(self.packet_type, "Unknown")


@dataclass
class ShortHeaderPacket:
    is_long_header: bool = False
    dcid: bytes = b""
    spin_bit: int = 0
    key_phase_bit_masked: bool = True  # protected until header protection removed
    first_byte: int = 0
    header_len: int = 0
    raw: bytes = field(default=b"", repr=False)


@dataclass
class VersionNegotiationPacket:
    is_long_header: bool = True
    is_version_negotiation: bool = True
    dcid: bytes = b""
    scid: bytes = b""
    supported_versions: list = field(default_factory=list)
    raw: bytes = field(default=b"", repr=False)


def parse_quic_header(data: bytes, dcid_len_hint: int = 8):
    """Parse the cleartext portion of a single QUIC packet.

    ``dcid_len_hint`` is used only for *short*-header packets, since
    RFC 9000 does not encode the DCID length there — an observer must
    already know it (typically from having seen the connection's
    Initial exchange, or from a fixed deployment convention). It
    defaults to 8, the common length used by major QUIC stacks.

    Returns a LongHeaderPacket, ShortHeaderPacket or
    VersionNegotiationPacket. Raises HeaderParseError on malformed or
    too-short input.
    """
    if len(data) < 1:
        raise HeaderParseError("empty packet")

    first_byte = data[0]
    is_long = bool(first_byte & 0x80)

    if is_long:
        return _parse_long_header(data, first_byte)
    return _parse_short_header(data, first_byte, dcid_len_hint)


def _read_cid(data: bytes, offset: int):
    if offset >= len(data):
        raise HeaderParseError("truncated packet: expected CID length byte")
    cid_len = data[offset]
    offset += 1
    if cid_len > 20:
        raise HeaderParseError(f"invalid connection ID length {cid_len} (max 20)")
    if offset + cid_len > len(data):
        raise HeaderParseError("truncated packet: CID exceeds available bytes")
    cid = data[offset : offset + cid_len]
    return cid, offset + cid_len


def _parse_long_header(data: bytes, first_byte: int) -> LongHeaderPacket:
    if len(data) < 5:
        raise HeaderParseError("long header packet shorter than minimum (5 bytes)")

    version = int.from_bytes(data[1:5], "big")
    offset = 5

    dcid, offset = _read_cid(data, offset)

    if version == QUIC_VERSION_NEGOTIATION:
        scid, offset = _read_cid(data, offset)
        versions = []
        while offset + 4 <= len(data):
            versions.append(int.from_bytes(data[offset : offset + 4], "big"))
            offset += 4
        return VersionNegotiationPacket(
            dcid=dcid, scid=scid, supported_versions=versions, raw=data
        )

    scid, offset = _read_cid(data, offset)

    type_bits = (first_byte & 0x30) >> 4
    if version == QUIC_VERSION_2:
        packet_type = QUIC_V2_TYPE_MAP.get(type_bits)
    else:
        try:
            packet_type = LongPacketType(type_bits)
        except ValueError:
            packet_type = None

    token = None
    if packet_type == LongPacketType.INITIAL:
        try:
            tok_len_res = decode_varint(data, offset)
        except VarIntError as exc:
            raise HeaderParseError(f"bad token length varint: {exc}") from exc
        offset += tok_len_res.length
        if offset + tok_len_res.value > len(data):
            raise HeaderParseError("truncated packet: token exceeds available bytes")
        token = data[offset : offset + tok_len_res.value]
        offset += tok_len_res.value

    length_field = None
    if packet_type in (
        LongPacketType.INITIAL,
        LongPacketType.ZERO_RTT,
        LongPacketType.HANDSHAKE,
    ):
        try:
            len_res = decode_varint(data, offset)
        except VarIntError as exc:
            raise HeaderParseError(f"bad length varint: {exc}") from exc
        length_field = len_res.value
        offset += len_res.length

    return LongHeaderPacket(
        version=version,
        packet_type=packet_type,
        dcid=dcid,
        scid=scid,
        token=token,
        length_field=length_field,
        header_len=offset,
        first_byte=first_byte,
        raw=data,
    )


def _parse_short_header(
    data: bytes, first_byte: int, dcid_len_hint: int
) -> ShortHeaderPacket:
    offset = 1
    dcid = data[offset : offset + dcid_len_hint]
    if len(dcid) < dcid_len_hint:
        # Not fatal -- short-header packets carry no explicit CID length,
        # so we may be guessing wrong; return what we have.
        pass
    offset += len(dcid)
    spin_bit = (first_byte & 0x20) >> 5
    return ShortHeaderPacket(
        dcid=dcid,
        spin_bit=spin_bit,
        first_byte=first_byte,
        header_len=offset,
        raw=data,
    )
