from quicfp.headers import QUIC_VERSION_2, parse_quic_header
from quicfp.initial_crypto import (
    INITIAL_SALT_V2,
    derive_initial_keys,
    find_crypto_frame_data,
    hkdf_extract,
    remove_initial_protection,
)
from tests.vectors import (
    RFC9369_CLIENT_HP_HEX,
    RFC9369_CLIENT_INITIAL_DCID_HEX,
    RFC9369_CLIENT_INITIAL_EXPECTED_HEADER_HEX,
    RFC9369_CLIENT_INITIAL_EXPECTED_PN,
    RFC9369_CLIENT_INITIAL_PACKET_HEX,
    RFC9369_CLIENT_IV_HEX,
    RFC9369_CLIENT_KEY_HEX,
    RFC9369_CLIENTHELLO_PREFIX_HEX,
    RFC9369_INITIAL_SALT_HEX,
    RFC9369_INITIAL_SECRET_HEX,
)


def test_initial_salt_matches_published_rfc_value():
    assert INITIAL_SALT_V2.hex() == RFC9369_INITIAL_SALT_HEX


def test_hkdf_extract_matches_rfc_initial_secret():
    dcid = bytes.fromhex(RFC9369_CLIENT_INITIAL_DCID_HEX)
    secret = hkdf_extract(INITIAL_SALT_V2, dcid)
    assert secret.hex() == RFC9369_INITIAL_SECRET_HEX


def test_derive_initial_keys_matches_rfc_appendix_a1():
    dcid = bytes.fromhex(RFC9369_CLIENT_INITIAL_DCID_HEX)
    keys = derive_initial_keys(dcid, version=QUIC_VERSION_2)

    assert keys.client.key.hex() == RFC9369_CLIENT_KEY_HEX
    assert keys.client.iv.hex() == RFC9369_CLIENT_IV_HEX
    assert keys.client.hp.hex() == RFC9369_CLIENT_HP_HEX


def test_full_round_trip_decrypt_matches_rfc_appendix_a2():
    """End-to-end: parse the wire header, remove header protection,
    AEAD-decrypt, and confirm both the recovered packet number and the
    recovered header bytes exactly match the RFC's worked example.
    """
    raw = bytes.fromhex(RFC9369_CLIENT_INITIAL_PACKET_HEX)
    header_pkt = parse_quic_header(raw)

    result = remove_initial_protection(
        raw, header_pkt.header_len, header_pkt.dcid, header_pkt.version, is_from_client=True
    )

    assert result.packet_number == RFC9369_CLIENT_INITIAL_EXPECTED_PN
    assert result.header.hex() == RFC9369_CLIENT_INITIAL_EXPECTED_HEADER_HEX


def test_recovered_crypto_frame_contains_expected_clienthello_prefix():
    raw = bytes.fromhex(RFC9369_CLIENT_INITIAL_PACKET_HEX)
    header_pkt = parse_quic_header(raw)
    result = remove_initial_protection(
        raw, header_pkt.header_len, header_pkt.dcid, header_pkt.version, is_from_client=True
    )
    crypto_data = find_crypto_frame_data(result.payload)

    expected_prefix = bytes.fromhex(RFC9369_CLIENTHELLO_PREFIX_HEX)
    assert crypto_data[: len(expected_prefix)] == expected_prefix
    # TLS handshake type 0x01 == ClientHello (RFC 8446 §4)
    assert crypto_data[0] == 0x01
