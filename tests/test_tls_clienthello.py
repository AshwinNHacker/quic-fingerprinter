import pytest

from quicfp.headers import parse_quic_header
from quicfp.initial_crypto import find_crypto_frame_data, remove_initial_protection
from quicfp.tls_clienthello import ClientHelloParseError, parse_client_hello
from tests.vectors import RFC9369_CLIENT_INITIAL_PACKET_HEX


@pytest.fixture
def parsed_clienthello():
    raw = bytes.fromhex(RFC9369_CLIENT_INITIAL_PACKET_HEX)
    header_pkt = parse_quic_header(raw)
    result = remove_initial_protection(
        raw, header_pkt.header_len, header_pkt.dcid, header_pkt.version, is_from_client=True
    )
    crypto_data = find_crypto_frame_data(result.payload)
    return parse_client_hello(crypto_data)


def test_sni_extracted(parsed_clienthello):
    assert parsed_clienthello.sni == "example.com"


def test_alpn_extracted(parsed_clienthello):
    # The RFC's own worked example uses the literal placeholder
    # protocol string "alpn" rather than a real ALPN token like "h3".
    assert parsed_clienthello.alpn == ["alpn"]


def test_tls13_supported_version_present(parsed_clienthello):
    assert 0x0304 in parsed_clienthello.supported_versions


def test_cipher_suites_extracted(parsed_clienthello):
    assert 0x1301 in parsed_clienthello.cipher_suites  # TLS_AES_128_GCM_SHA256
    assert 0x1302 in parsed_clienthello.cipher_suites  # TLS_AES_256_GCM_SHA384


def test_quic_transport_parameters_extension_present(parsed_clienthello):
    assert parsed_clienthello.quic_transport_parameters is not None
    assert len(parsed_clienthello.quic_transport_parameters) > 0


def test_extension_order_is_nonempty_and_matches_count(parsed_clienthello):
    assert len(parsed_clienthello.extension_order) == len(parsed_clienthello.extensions)
    assert 0 in parsed_clienthello.extension_order  # server_name
    assert 57 in parsed_clienthello.extension_order  # quic_transport_parameters


def test_rejects_non_clienthello_message():
    fake_server_hello = bytes([0x02, 0x00, 0x00, 0x02, 0xAA, 0xBB])
    with pytest.raises(ClientHelloParseError):
        parse_client_hello(fake_server_hello)


def test_rejects_too_short_input():
    with pytest.raises(ClientHelloParseError):
        parse_client_hello(b"\x01\x00")
