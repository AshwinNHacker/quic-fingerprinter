"""
RFC 9001 Initial packet cryptography: header de-obfuscation + AEAD.

IMPORTANT CONTEXT FOR REVIEWERS
--------------------------------
This module does *not* break QUIC's real encryption. QUIC's actual
end-to-end confidentiality comes from the TLS 1.3 handshake secrets,
which are derived from an ephemeral (EC)DHE key exchange and are never
recoverable by a passive observer. What this module implements is the
Initial-packet key derivation defined in RFC 9001 Section 5.2: the very
first flight of every QUIC connection (which carries the TLS
ClientHello) is only "protected" with a key derived from a fixed,
public salt and the packet's own cleartext Destination Connection ID.

The QUIC working group made this deliberate design choice (see RFC
9001 Section 7, "Security of Initial Messages" and RFC 9369's
discussion of why each new QUIC version defines a new salt) precisely
*so that* network intermediaries, firewalls, and NIDS engines can
continue to see the ClientHello/ServerHello -- the same visibility
they historically had into TLS-over-TCP. Every serious QUIC-aware
traffic inspector (Zeek's quic analyzer, Suricata's quic keyword,
Wireshark's built-in QUIC dissector) performs exactly this
computation. There is no secret material or private key anywhere in
this process: the salt is published in the RFC text and the DCID is
sent in cleartext in every Initial packet.

References:
    RFC 9001 §5.1  Packet Protection Keys (HKDF-Expand-Label usage)
    RFC 9001 §5.2  Initial Secrets        (salt + HKDF-Extract)
    RFC 9001 §5.3  AEAD Usage             (nonce = IV XOR packet number)
    RFC 9001 §5.4  Header Protection      (AES-ECB mask over a ciphertext sample)
    RFC 9369 §3.3  QUIC v2 salt + "quicv2 *" labels
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from quicfp.headers import QUIC_VERSION_1, QUIC_VERSION_2
from quicfp.varint import decode_varint

# RFC 9001 §5.2 -- the public QUIC v1 Initial salt.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

# RFC 9369 §3.3.1 -- the public QUIC v2 Initial salt (first 20 bytes of
# SHA-256("QUICv2 salt")). Note: pre-RFC drafts of quic-v2 (draft-00
# through draft-04) used a different provisional salt
# (0xa707c203a59b47184a1d62ca570406ea7ae3e5d3); the value below is the
# one that shipped in the final, published RFC 9369 text.
INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

_LABEL_PREFIX = b"tls13 "


class InitialCryptoError(ValueError):
    pass


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract, i.e. HMAC-SHA256(salt, IKM)."""
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def hkdf_expand_label(secret: bytes, label: str, length: int, context: bytes = b"") -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1), as reused verbatim by
    QUIC-TLS (RFC 9001 §5.1) with a zero-length Context.
    """
    full_label = _LABEL_PREFIX + label.encode("ascii")
    if len(full_label) > 255:
        raise InitialCryptoError("label too long")

    hkdf_label = (
        length.to_bytes(2, "big")
        + len(full_label).to_bytes(1, "big")
        + full_label
        + len(context).to_bytes(1, "big")
        + context
    )
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label).derive(secret)


@dataclass(frozen=True)
class DirectionalKeys:
    key: bytes  # AEAD_AES_128_GCM key (16 bytes)
    iv: bytes  # AEAD nonce base (12 bytes)
    hp: bytes  # header-protection key (16 bytes)


@dataclass(frozen=True)
class InitialKeySet:
    client: DirectionalKeys
    server: DirectionalKeys


def _salt_and_labels(version: int):
    if version == QUIC_VERSION_2:
        return INITIAL_SALT_V2, "quicv2 key", "quicv2 iv", "quicv2 hp"
    # Default to v1 labels/salt for QUIC v1 and for any unrecognized /
    # draft version, since nearly all draft versions reused the v1 salt
    # (only the wire version number changed during standardization).
    return INITIAL_SALT_V1, "quic key", "quic iv", "quic hp"


def derive_initial_keys(dcid: bytes, version: int = QUIC_VERSION_1) -> InitialKeySet:
    """Derive the client/server Initial AEAD + header-protection keys
    for a given Destination Connection ID, per RFC 9001 §5.2.
    """
    salt, key_label, iv_label, hp_label = _salt_and_labels(version)
    initial_secret = hkdf_extract(salt, dcid)

    client_secret = hkdf_expand_label(initial_secret, "client in", 32)
    server_secret = hkdf_expand_label(initial_secret, "server in", 32)

    def _derive(secret: bytes) -> DirectionalKeys:
        return DirectionalKeys(
            key=hkdf_expand_label(secret, key_label, 16),
            iv=hkdf_expand_label(secret, iv_label, 12),
            hp=hkdf_expand_label(secret, hp_label, 16),
        )

    return InitialKeySet(client=_derive(client_secret), server=_derive(server_secret))


def _aes_ecb_mask(hp_key: bytes, sample: bytes) -> bytes:
    """RFC 9001 §5.4.3: AES-ECB(hp_key, sample) -> 5-byte usable mask."""
    if len(sample) != 16:
        raise InitialCryptoError("header protection sample must be 16 bytes")
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return encryptor.update(sample) + encryptor.finalize()


@dataclass
class UnprotectedInitial:
    packet_number: int
    packet_number_len: int
    header: bytes  # full unprotected header (first byte + pn now in the clear)
    payload: bytes  # decrypted, authenticated payload (frames)


def remove_initial_protection(
    raw: bytes,
    header_len_before_pn: int,
    dcid: bytes,
    version: int,
    is_from_client: bool = True,
) -> UnprotectedInitial:
    """Remove header protection and AEAD-decrypt an Initial packet.

    ``header_len_before_pn`` is the number of bytes from the start of the
    packet up to (but not including) the Packet Number field -- i.e. what
    :func:`quicfp.headers.parse_quic_header` reports as ``header_len`` for
    a LongHeaderPacket of type Initial.

    Raises InitialCryptoError if the packet is malformed, too short, or
    fails AEAD authentication (e.g. it's not actually a QUIC Initial
    packet, or was truncated/corrupted in capture).
    """
    keys = derive_initial_keys(dcid, version)
    directional = keys.client if is_from_client else keys.server

    # RFC 9001 §5.4.2: sample starts 4 bytes after the (assumed 4-byte)
    # start of the packet number field.
    sample_offset = header_len_before_pn + 4
    sample = raw[sample_offset : sample_offset + 16]
    if len(sample) < 16:
        raise InitialCryptoError(
            "packet too short to contain a header-protection sample "
            "(truncated capture snaplen?)"
        )

    mask = _aes_ecb_mask(directional.hp, sample)

    packet = bytearray(raw)
    # Long header: 4 low bits of the first byte are protected.
    packet[0] ^= mask[0] & 0x0F

    pn_length = (packet[0] & 0x03) + 1
    pn_offset = header_len_before_pn
    for i in range(pn_length):
        packet[pn_offset + i] ^= mask[1 + i]

    packet_number = int.from_bytes(packet[pn_offset : pn_offset + pn_length], "big")

    header = bytes(packet[: pn_offset + pn_length])
    ciphertext_and_tag = bytes(packet[pn_offset + pn_length :])

    if len(ciphertext_and_tag) < 16:
        raise InitialCryptoError("payload shorter than AEAD authentication tag")

    # RFC 9001 §5.3: nonce = left-padded packet number XOR IV.
    iv = bytearray(directional.iv)
    pn_bytes = packet_number.to_bytes(len(iv), "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn_bytes, strict=True))

    aesgcm = AESGCM(directional.key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, header)
    except Exception as exc:  # cryptography raises InvalidTag
        raise InitialCryptoError(
            "AEAD authentication failed -- not a well-formed QUIC Initial "
            "packet, wrong DCID/version pairing, or corrupted capture"
        ) from exc

    return UnprotectedInitial(
        packet_number=packet_number,
        packet_number_len=pn_length,
        header=header,
        payload=plaintext,
    )


def find_crypto_frame_data(payload: bytes) -> bytes:
    """Walk the decrypted Initial payload's frames and concatenate the
    contents of all CRYPTO frames (RFC 9000 §19.6), in the order found.

    A ClientHello that spans multiple CRYPTO frames within one packet
    (rare, but legal) is reassembled by offset; frames from *separate*
    packets are the caller's responsibility to reassemble (see
    :mod:`quicfp.flow`).
    """
    offset = 0
    chunks: dict[int, bytes] = {}
    while offset < len(payload):
        frame_type = payload[offset]
        if frame_type == 0x00:  # PADDING
            offset += 1
            continue
        if frame_type == 0x01:  # PING
            offset += 1
            continue
        if frame_type == 0x02 or frame_type == 0x03:  # ACK (with/without ECN)
            offset += 1
            offset = _skip_ack_frame(payload, offset, has_ecn=frame_type == 0x03)
            continue
        if frame_type == 0x06:  # CRYPTO
            offset += 1
            off_res = decode_varint(payload, offset)
            crypto_offset = off_res.value
            offset += off_res.length
            len_res = decode_varint(payload, offset)
            crypto_len = len_res.value
            offset += len_res.length
            data = payload[offset : offset + crypto_len]
            chunks[crypto_offset] = data
            offset += crypto_len
            continue
        if frame_type == 0x1C or frame_type == 0x1D:  # CONNECTION_CLOSE
            break
        # Unknown/unsupported frame type in this context (unexpected for
        # Initial packets, which should only carry PADDING/PING/ACK/CRYPTO/
        # CONNECTION_CLOSE) -- stop parsing rather than risk misreading.
        break

    if not chunks:
        return b""
    ordered = sorted(chunks.items())
    return b"".join(data for _, data in ordered)


def _skip_ack_frame(payload: bytes, offset: int, has_ecn: bool) -> int:
    largest = decode_varint(payload, offset)
    offset += largest.length
    delay = decode_varint(payload, offset)
    offset += delay.length
    range_count = decode_varint(payload, offset)
    offset += range_count.length
    first_range = decode_varint(payload, offset)
    offset += first_range.length
    for _ in range(range_count.value):
        gap = decode_varint(payload, offset)
        offset += gap.length
        ack_range_len = decode_varint(payload, offset)
        offset += ack_range_len.length
    if has_ecn:
        for _ in range(3):
            v = decode_varint(payload, offset)
            offset += v.length
    return offset
