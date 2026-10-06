import pytest

from quicfp.varint import VarIntError, decode_varint, encode_varint

# RFC 9000 Appendix A.1 examples.
RFC9000_VARINT_CASES = [
    (bytes.fromhex("c2197c5eff14e88c"), 151288809941952652),
    (bytes.fromhex("9d7f3e7d"), 494878333),
    (bytes.fromhex("7bbd"), 15293),
    (bytes.fromhex("25"), 37),
    (bytes.fromhex("40 25".replace(" ", "")), 37),
]


@pytest.mark.parametrize("data,expected", RFC9000_VARINT_CASES)
def test_decode_varint_rfc9000_examples(data, expected):
    result = decode_varint(data)
    assert result.value == expected
    assert result.length == len(data)


@pytest.mark.parametrize("value", [0, 1, 37, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903])
def test_encode_decode_round_trip(value):
    encoded = encode_varint(value)
    decoded = decode_varint(encoded)
    assert decoded.value == value
    assert decoded.length == len(encoded)


def test_varint_smallest_encoding_chosen():
    assert len(encode_varint(0)) == 1
    assert len(encode_varint(63)) == 1
    assert len(encode_varint(64)) == 2
    assert len(encode_varint(16383)) == 2
    assert len(encode_varint(16384)) == 4
    assert len(encode_varint(1073741823)) == 4
    assert len(encode_varint(1073741824)) == 8


def test_decode_varint_truncated_raises():
    with pytest.raises(VarIntError):
        decode_varint(bytes([0xC0]))  # claims 8-byte length, only 1 byte given


def test_decode_varint_empty_raises():
    with pytest.raises(VarIntError):
        decode_varint(b"")


def test_encode_varint_negative_raises():
    with pytest.raises(VarIntError):
        encode_varint(-1)


def test_encode_varint_too_large_raises():
    with pytest.raises(VarIntError):
        encode_varint(2**62)
