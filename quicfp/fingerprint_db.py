"""
Fingerprint database: match observed QUIC ClientHello fingerprints
against known client families.

Honesty note
------------
Exact JA3/JA4-style hash values are specific to the *precise* set and
order of cipher suites/extensions a given TLS library version sends,
which drifts across browser/library releases and build flags. Rather
than hard-coding a handful of hashes that were accurate on some
version of Chrome on some date (and shipping a false sense of
precision), this module ships two things:

1. A small, structural *heuristic* matcher (cipher-suite set, ALPN,
   presence/absence of specific extensions like QUIC transport
   parameters or ECH) that gives a best-effort, human-readable guess
   of client family -- explicitly labeled as a heuristic, not a
   cryptographic identification.
2. A persistent on-disk JSON store (``fingerprint_db.json``) that
   *you* populate from your own labeled captures (see
   ``quicfp learn --label "Chrome 126" capture.pcap``). Exact-hash
   matching against entries you've personally verified is far more
   trustworthy for a production deployment than a hard-coded list of
   hashes that may already be stale by the time you read this.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from quicfp.fingerprint import QuicFingerprint
from quicfp.tls_clienthello import ClientHello

DEFAULT_DB_PATH = Path.home() / ".quicfp" / "fingerprint_db.json"


@dataclass
class MatchResult:
    label: str
    confidence: str  # "exact" | "heuristic" | "unknown"
    detail: str = ""


@dataclass
class FingerprintStore:
    path: Path = field(default_factory=lambda: DEFAULT_DB_PATH)
    entries: dict[str, str] = field(default_factory=dict)  # sorted_fp -> label

    @classmethod
    def load(cls, path: Path | None = None) -> FingerprintStore:
        p = path or DEFAULT_DB_PATH
        store = cls(path=p)
        if p.exists():
            try:
                store.entries = json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                store.entries = {}
        return store

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.entries, indent=2, sort_keys=True))

    def learn(self, fp: QuicFingerprint, label: str) -> None:
        self.entries[fp.sorted_fingerprint] = label

    def lookup(self, fp: QuicFingerprint) -> MatchResult | None:
        label = self.entries.get(fp.sorted_fingerprint)
        if label:
            return MatchResult(label=label, confidence="exact", detail=fp.sorted_fingerprint)
        return None


# ---------------------------------------------------------------------
# Structural heuristics (approximate, explicitly labeled as such)
# ---------------------------------------------------------------------

_BORINGSSL_LIKE_ALPN = {"h3", "h3-29", "h3-32"}


def heuristic_guess(ch: ClientHello) -> MatchResult:
    """A best-effort, transparently-labeled structural guess. This is
    NOT cryptographic identification -- treat it as a hint for triage,
    not a security control.
    """
    ext_set = set(ch.extension_order)
    has_ech = 65037 in ext_set
    has_qtp = 57 in ext_set
    alpn = set(ch.alpn)

    if not has_qtp:
        return MatchResult(
            label="non-standard-or-truncated",
            confidence="heuristic",
            detail="missing quic_transport_parameters extension (RFC 9001 §8.2 "
            "requires it) -- either a non-browser QUIC stack, a partial "
            "capture, or a deliberately minimal/obfuscated client",
        )

    if ch.is_grease_present and has_ech and alpn & _BORINGSSL_LIKE_ALPN:
        return MatchResult(
            label="Chromium-family (Chrome/Edge/Brave/Opera -- BoringSSL)",
            confidence="heuristic",
            detail="GREASE + ECH + h3 ALPN is characteristic of recent "
            "BoringSSL-based Chromium browsers",
        )

    if ch.is_grease_present and not has_ech and alpn & _BORINGSSL_LIKE_ALPN:
        return MatchResult(
            label="Chromium-family (older) or curl --http3 (quiche/BoringSSL)",
            confidence="heuristic",
            detail="GREASE present without ECH and with h3 ALPN",
        )

    if not ch.is_grease_present and "h3" in alpn:
        return MatchResult(
            label="Firefox (NSS) or non-GREASE QUIC library",
            confidence="heuristic",
            detail="h3 ALPN without GREASE extension values; Firefox's NSS "
            "stack and several minimal QUIC libraries (e.g. some Go/Rust "
            "stacks) do not send GREASE",
        )

    if "doq" in alpn:
        return MatchResult(
            label="DNS-over-QUIC client (RFC 9250)",
            confidence="heuristic",
            detail="ALPN negotiated 'doq'",
        )

    return MatchResult(
        label="unknown QUIC client",
        confidence="heuristic",
        detail=f"alpn={sorted(alpn) or 'none'}, grease={ch.is_grease_present}",
    )
