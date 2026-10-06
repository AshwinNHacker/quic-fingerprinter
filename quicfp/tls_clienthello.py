"""
Minimal TLS 1.3 ClientHello parser.

Parses the handshake message recovered from a QUIC Initial packet's
CRYPTO frame (see :mod:`quicfp.initial_crypto`). Only the fields useful
for fingerprinting and passive visibility are extracted: this is not a
general-purpose TLS library and does not validate the handshake.

Structure reference: RFC 8446 §4.1.2 (ClientHello).
"""

from __future__ import annotations

from dataclasses import dataclass, field

HANDSHAKE_TYPE_CLIENT_HELLO = 0x01

# A representative subset of the IANA TLS ExtensionType registry --
# enough to label the extensions that matter for fingerprinting without
# vendoring the entire registry.
EXTENSION_NAMES = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    14: "use_srtp",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    21: "padding",
    23: "extended_master_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "certificate_authorities",
    50: "signature_algorithms_cert",
    51: "key_share",
    57: "quic_transport_parameters",
    65037: "encrypted_client_hello",
    65281: "renegotiation_info",
}

# Cipher suites relevant to TLS 1.3 / QUIC (RFC 8446 Appendix B.4).
TLS13_CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}


class ClientHelloParseError(ValueError):
    pass


@dataclass
class ClientHello:
    legacy_version: int = 0
    random: bytes = b""
    session_id: bytes = b""
    cipher_suites: list[int] = field(default_factory=list)
    compression_methods: bytes = b""
    extension_order: list[int] = field(default_factory=list)
    extensions: dict[int, bytes] = field(default_factory=dict)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    key_share_groups: list[int] = field(default_factory=list)
    quic_transport_parameters: bytes | None = None
    is_grease_present: bool = False

    @property
    def cipher_suite_names(self) -> list[str]:
        return [TLS13_CIPHER_SUITES.get(c, f"0x{c:04x}") for c in self.cipher_suites]


def _is_grease(value: int) -> bool:
    """RFC 8701: GREASE values are 0x?A?A where both nibbles match 'A'."""
    return (value & 0x0F0F) == 0x0A0A


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse a (decrypted) TLS handshake message, expected to be a
    ClientHello, as recovered from a QUIC CRYPTO frame.
    """
    if len(data) < 4:
        raise ClientHelloParseError("too short to contain a handshake header")

    msg_type = data[0]
    if msg_type != HANDSHAKE_TYPE_CLIENT_HELLO:
        raise ClientHelloParseError(
            f"expected ClientHello (type 1), got handshake type {msg_type}"
        )

    length = int.from_bytes(data[1:4], "big")
    body = data[4 : 4 + length]
    if len(body) < length:
        raise ClientHelloParseError(
            "ClientHello declared length exceeds available data "
            "(likely spans multiple QUIC packets/CRYPTO frames -- "
            "reassemble the flow's CRYPTO stream before parsing)"
        )

    offset = 0
    ch = ClientHello()

    ch.legacy_version = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2

    ch.random = body[offset : offset + 32]
    offset += 32

    session_id_len = body[offset]
    offset += 1
    ch.session_id = body[offset : offset + session_id_len]
    offset += session_id_len

    cs_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    cs_bytes = body[offset : offset + cs_len]
    offset += cs_len
    for i in range(0, len(cs_bytes), 2):
        suite = int.from_bytes(cs_bytes[i : i + 2], "big")
        if _is_grease(suite):
            ch.is_grease_present = True
            continue
        ch.cipher_suites.append(suite)

    comp_len = body[offset]
    offset += 1
    ch.compression_methods = body[offset : offset + comp_len]
    offset += comp_len

    if offset + 2 > len(body):
        # No extensions block present (unusual for a real client, but
        # not fatal to what we've already extracted).
        return ch

    ext_total_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    ext_end = offset + ext_total_len

    while offset + 4 <= ext_end and offset + 4 <= len(body):
        ext_type = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        ext_len = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        ext_data = body[offset : offset + ext_len]
        offset += ext_len

        if _is_grease(ext_type):
            ch.is_grease_present = True
            continue

        ch.extension_order.append(ext_type)
        ch.extensions[ext_type] = ext_data

        try:
            _handle_extension(ch, ext_type, ext_data)
        except (IndexError, ValueError):
            # Malformed/truncated extension body -- keep what we have
            # rather than aborting the whole parse.
            continue

    return ch


def _handle_extension(ch: ClientHello, ext_type: int, ext_data: bytes) -> None:
    if ext_type == 0:  # server_name
        ch.sni = _parse_sni(ext_data)
    elif ext_type == 16:  # ALPN
        ch.alpn = _parse_alpn(ext_data)
    elif ext_type == 10:  # supported_groups
        ch.supported_groups = _parse_group_list(ext_data)
    elif ext_type == 43:  # supported_versions
        ch.supported_versions = _parse_u16_list(ext_data[1:], count=ext_data[0] // 2)
    elif ext_type == 13:  # signature_algorithms
        ch.signature_algorithms = _parse_group_list(ext_data)
    elif ext_type == 51:  # key_share
        ch.key_share_groups = _parse_key_share_groups(ext_data)
    elif ext_type == 57:  # quic_transport_parameters
        ch.quic_transport_parameters = ext_data


def _parse_sni(ext_data: bytes) -> str | None:
    if len(ext_data) < 5:
        return None
    # server_name_list length (2) + name_type (1) + host_name length (2)
    name_len = int.from_bytes(ext_data[3:5], "big")
    host = ext_data[5 : 5 + name_len]
    try:
        return host.decode("idna")
    except Exception:
        try:
            return host.decode("ascii", errors="replace")
        except Exception:
            return None


def _parse_alpn(ext_data: bytes) -> list[str]:
    protocols = []
    if len(ext_data) < 2:
        return protocols
    offset = 2  # skip ALPN protocol list length
    while offset < len(ext_data):
        plen = ext_data[offset]
        offset += 1
        proto = ext_data[offset : offset + plen]
        offset += plen
        try:
            protocols.append(proto.decode("ascii"))
        except Exception:
            protocols.append(proto.hex())
    return protocols


def _parse_group_list(ext_data: bytes) -> list[int]:
    if len(ext_data) < 2:
        return []
    list_len = int.from_bytes(ext_data[0:2], "big")
    raw = ext_data[2 : 2 + list_len]
    groups = []
    for i in range(0, len(raw) - 1, 2):
        v = int.from_bytes(raw[i : i + 2], "big")
        if not _is_grease(v):
            groups.append(v)
    return groups


def _parse_u16_list(data: bytes, count: int) -> list[int]:
    values = []
    for i in range(count):
        chunk = data[i * 2 : i * 2 + 2]
        if len(chunk) < 2:
            break
        v = int.from_bytes(chunk, "big")
        if not _is_grease(v):
            values.append(v)
    return values


def _parse_key_share_groups(ext_data: bytes) -> list[int]:
    if len(ext_data) < 2:
        return []
    list_len = int.from_bytes(ext_data[0:2], "big")
    raw = ext_data[2 : 2 + list_len]
    groups = []
    offset = 0
    while offset + 4 <= len(raw):
        group = int.from_bytes(raw[offset : offset + 2], "big")
        key_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        offset += 4 + key_len
        if not _is_grease(group):
            groups.append(group)
    return groups
