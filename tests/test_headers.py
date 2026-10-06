import pytest

from quicfp.headers import (
    QUIC_VERSION_2,
    HeaderParseError,
    LongHeaderPacket,
    LongPacketType,
    ShortHeaderPacket,
    describe_version,
    parse_quic_header,
)
from tests.vectors import (
    RFC9369_CLIENT_INITIAL_DCID_HEX,
    RFC9369_CLIENT_INITIAL_PACKET_HEX,
)


def test_parse_long_header_initial_from_rfc_vector():
    raw = bytes.fromhex(RFC9369_CLIENT_INITIAL_PACKET_HEX)
    pkt = parse_quic_header(raw)

    assert isinstance(pkt, LongHeaderPacket)
    assert pkt.version == QUIC_VERSION_2
    assert pkt.packet_type == LongPacketType.INITIAL
    assert pkt.dcid.hex() == RFC9369_CLIENT_INITIAL_DCID_HEX
    assert pkt.scid == b""
    assert pkt.token == b""
    # header_len should point exactly to where the packet number starts
    assert pkt.header_len == 18


def test_describe_version_known():
    assert "RFC 9000" in describe_version(0x00000001)
    assert "RFC 9369" in describe_version(QUIC_VERSION_2)
    assert describe_version(0x00000000) == "Version Negotiation"


def test_describe_version_grease():
    assert "GREASE" in describe_version(0x1A2A3A4A)


def test_describe_version_unknown():
    desc = describe_version(0x12345678)
    assert "Unknown" in desc


def test_parse_short_header():
    # First byte: 0b01000001 -> short header, fixed bit set, spin=0
    raw = bytes([0b01000001]) + bytes(8) + b"\x00\x00\x00\x00"
    pkt = parse_quic_header(raw, dcid_len_hint=8)
    assert isinstance(pkt, ShortHeaderPacket)
    assert len(pkt.dcid) == 8


def test_parse_empty_raises():
    with pytest.raises(HeaderParseError):
        parse_quic_header(b"")


def test_parse_truncated_long_header_raises():
    with pytest.raises(HeaderParseError):
        parse_quic_header(bytes([0xC0, 0x00, 0x00, 0x00]))  # only 4 bytes, needs 5+


def test_parse_version_negotiation():
    # VN packet: first byte long-header bit set + arbitrary bits (unused),
    # version = 0, then DCID/SCID, then a list of supported versions.
    dcid = bytes([0xAA, 0xBB])
    scid = bytes([0xCC])
    raw = (
        bytes([0x80])
        + b"\x00\x00\x00\x00"
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + (0x00000001).to_bytes(4, "big")
        + QUIC_VERSION_2.to_bytes(4, "big")
    )
    pkt = parse_quic_header(raw)
    assert pkt.is_version_negotiation
    assert pkt.dcid == dcid
    assert pkt.scid == scid
    assert pkt.supported_versions == [0x00000001, QUIC_VERSION_2]
