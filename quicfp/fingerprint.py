"""
Deterministic ClientHello fingerprinting for QUIC, in the spirit of
JA3 (Salesforce, 2017) and its JA4/JA4+ successors (FoxIO, 2023),
adapted to QUIC's Initial-packet ClientHello and QUIC transport
parameters.

Design notes
------------
JA3 hashed a comma-joined string of (TLSVersion, Ciphers, Extensions,
EllipticCurves, EllipticCurvePointFormats) taken in the *order
presented on the wire*. That wire order is a genuine client-library
signature: different TLS stacks (BoringSSL/Chrome, NSS/Firefox,
rustls, quiche, msquic, s2n-quic, ...) order and select extensions
differently, and GREASE-shuffling clients still leave a fairly stable
non-GREASE skeleton. JA4 improved robustness by sorting extensions
before hashing (removing sensitivity to non-semantic reordering some
stacks introduce) while keeping raw wire order in a separate part of
the fingerprint, and by using SHA-256 truncated segments instead of
raw MD5.

This module produces two complementary fingerprints:

* ``raw_order_fingerprint`` -- SHA-256 over cipher suites and
  extensions exactly as they appeared on the wire. Maximally specific;
  changes if a client's extension order changes between versions.
* ``sorted_fingerprint`` (the JA4-style one) -- SHA-256 over the
  *sorted* cipher-suite and extension sets, GREASE removed. More
  stable across minor client library point releases, and is what
  :mod:`quicfp.fingerprint_db` matches against.

Both are computed purely from information already extracted by
:mod:`quicfp.tls_clienthello` -- nothing here requires breaking any
real encryption.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from quicfp.tls_clienthello import ClientHello


@dataclass(frozen=True)
class QuicFingerprint:
    raw_order_fingerprint: str
    sorted_fingerprint: str
    protocol: str  # "quic" or "quicv2" -- some client stacks differ by version
    tls_version: str
    cipher_count: int
    extension_count: int
    alpn_first: str
    sni_present: bool
    quic_transport_params_len: int
    grease_present: bool

    def short(self) -> str:
        """A JA4-style compact tag, e.g. 'q13d0709_alpn=h3'."""
        return f"q{self.tls_version}{self.cipher_count:02d}{self.extension_count:02d}_{self.alpn_first or 'none'}"


def _hash_hex(parts: list[str]) -> str:
    joined = ",".join(parts).encode("ascii", errors="replace")
    return hashlib.sha256(joined).hexdigest()


def compute_fingerprint(ch: ClientHello, quic_version_is_v2: bool = False) -> QuicFingerprint:
    tls_ver = "13" if 0x0304 in ch.supported_versions else f"{ch.legacy_version:04x}"

    raw_ciphers = [f"{c:04x}" for c in ch.cipher_suites]
    raw_exts = [f"{e:04x}" for e in ch.extension_order]

    raw_fp = _hash_hex(["quicv2" if quic_version_is_v2 else "quic", tls_ver] + raw_ciphers + ["|"] + raw_exts)

    sorted_ciphers = sorted(raw_ciphers)
    sorted_exts = sorted(raw_exts)
    sorted_fp = _hash_hex(
        ["quicv2" if quic_version_is_v2 else "quic", tls_ver] + sorted_ciphers + ["|"] + sorted_exts
    )

    return QuicFingerprint(
        raw_order_fingerprint=raw_fp,
        sorted_fingerprint=sorted_fp,
        protocol="quicv2" if quic_version_is_v2 else "quic",
        tls_version=tls_ver,
        cipher_count=len(ch.cipher_suites),
        extension_count=len(ch.extension_order),
        alpn_first=ch.alpn[0] if ch.alpn else "",
        sni_present=ch.sni is not None,
        quic_transport_params_len=len(ch.quic_transport_parameters or b""),
        grease_present=ch.is_grease_present,
    )
