# quicfp — QUIC/HTTP3 Traffic Fingerprinter

**Detection tooling for the growing QUIC blind spot.**

As QUIC and HTTP/3 adoption grows, more traffic moves off TCP+TLS onto
UDP, where traditional TCP/TLS-centric visibility tools (JA3, SNI
sniffing, TCP fingerprinting) go dark. `quicfp` is a passive,
standards-based traffic fingerprinter that restores equivalent
visibility for QUIC: it decrypts and fingerprints the TLS ClientHello
carried in every QUIC connection's Initial packet (a mechanism the
IETF QUIC working group deliberately designed to remain observable —
see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)), and falls back to
flow-level statistical fingerprinting for the genuinely encrypted
1-RTT traffic that follows.

```
$ quicfp analyze capture.pcap

quicfp analysis: capture.pcap
  total flows (any protocol on UDP): 4
  QUIC flows identified:             3
========================================================================

[1] [['10.0.0.5', 51234], ['93.184.216.34', 443]]
    version: 0x00000001 (QUIC v1 (RFC 9000))
    packets: 1   duration: 0.00s
    SNI:  example.com
    ALPN: ['h3']
    ciphers: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384']
    fingerprint (sorted):    2db9dd58836720ba1fd6851696f2ba2df9d9170bc5beb6d240bc0ef70f061836
    client match: Chromium-family (Chrome/Edge/Brave/Opera -- BoringSSL)  [heuristic]
```

## Why this is legitimate, not a "break" of QUIC

QUIC's real end-to-end encryption comes from an ephemeral TLS 1.3
(EC)DHE handshake and is never recoverable by a passive observer.
What this tool decrypts is specifically the **Initial packet**, whose
protection RFC 9001 §5.2 deliberately derives from a **public,
RFC-published salt** and the packet's own **cleartext connection ID**
— by design, so that network intermediaries retain the same
ClientHello/SNI visibility they historically had into TLS-over-TCP.
Every serious QUIC-aware inspector (Zeek, Suricata, Wireshark) performs
this exact computation. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the full explanation, and [`docs/LEGAL_AND_ETHICAL_USE.md`](docs/LEGAL_AND_ETHICAL_USE.md)
for usage guidelines.

## Correctness

The cryptographic core (`quicfp/initial_crypto.py`) is validated
**byte-for-byte against the IETF's own published test vectors** in
[RFC 9369 Appendix A](https://www.rfc-editor.org/rfc/rfc9369.html#appendix-A)
— including a full round-trip decrypt of the sample Initial packet
that recovers the exact TLS ClientHello bytes given in the RFC text.
70 tests cover the varint codec (RFC 9000 App. A.1), header parsing,
Initial key derivation, AEAD decryption, ClientHello parsing,
fingerprinting, flow tracking, statistical features, the fingerprint
database, and the CLI — run them yourself:

```bash
pytest -q
# 70 passed
```

## Features

- **QUIC packet parsing**: long/short header parsing for QUIC v1
  (RFC 9000) and v2 (RFC 9369), with GREASE-version tolerance
  (RFC 9287) and Version Negotiation packet support.
- **Initial packet decryption**: RFC 9001 §5.2/§5.4 compliant
  Initial-secret derivation and AES-GCM/header-protection removal,
  for both QUIC v1 and v2 salts/labels.
- **TLS 1.3 ClientHello parsing**: SNI, ALPN, cipher suites, supported
  groups, key-share groups, QUIC transport parameters, and full
  extension order, with GREASE (RFC 8701) detection.
- **JA4-style fingerprinting**: deterministic SHA-256 fingerprints in
  both raw wire-order and order-independent forms.
- **Learnable fingerprint database**: label your own captures
  (`quicfp learn`) rather than trusting a hardcoded, inevitably-stale
  hash list.
- **Statistical flow classification**: for the genuinely encrypted
  1-RTT majority of every connection's traffic, a documented,
  auditable RandomForest classifier over packet size/timing/direction
  features — trainable on your own labeled data (`quicfp train`).
- **CLI + library**: `quicfp analyze|learn|train|live`, or use the
  `quicfp` package directly (see `examples/`).
- **Offline pcap and live capture** via `dpkt` and `scapy`.

## Installation

```bash
git clone https://github.com/AshwinNHacker/quic-fingerprinter.git
cd quic-fingerprinter
pip install -e .
```

Requires Python 3.10+. See `requirements.txt` / `pyproject.toml` for
dependencies (`cryptography`, `dpkt`, `scapy`, `numpy`,
`scikit-learn`, `joblib`).

## Quick start

```bash
# Analyze a pcap file
quicfp analyze capture.pcap

# Machine-readable output
quicfp analyze capture.pcap --json

# Verbose: also show statistical features per flow
quicfp analyze capture.pcap --verbose

# Teach quicfp what a specific client's fingerprint looks like
quicfp learn known_chrome_capture.pcap --label "Chrome 126 / Windows 11"

# Live capture (needs root/Administrator + npcap on Windows)
sudo quicfp live eth0 --duration 30

# Train a statistical classifier on your own labeled captures
quicfp train labeled_captures/ --output my_model.joblib
```

See [`examples/`](examples/) for library-usage scripts
(`analyze_pcap_basic.py`, `train_classifier.py`).

## How it works (short version)

1. **Parse** every UDP datagram's QUIC long/short header
   (`quicfp/headers.py`).
2. For a client's first **Initial** packet, **derive** the
   RFC 9001 §5.2 Initial secrets from the packet's own cleartext DCID
   and the public IETF salt, **remove header protection**, and
   **AEAD-decrypt** the payload (`quicfp/initial_crypto.py`).
3. **Reassemble and parse** the recovered CRYPTO frame as a TLS 1.3
   ClientHello (`quicfp/tls_clienthello.py`).
4. **Fingerprint** the ClientHello's cipher suites and extensions into
   a deterministic hash (`quicfp/fingerprint.py`), and optionally match
   it against a learned database (`quicfp/fingerprint_db.py`).
5. For everything **after** the handshake — the genuinely,
   strongly-encrypted 1-RTT majority of the connection — extract
   **flow-level statistical features** (packet size/timing/direction;
   `quicfp/features.py`) and optionally classify them with a trained
   RandomForest (`quicfp/ml/classifier.py`).

Full detail, including *why* step 2 is not a security break, is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Project layout

```
quicfp/
  varint.py            RFC 9000 §16 variable-length integers
  headers.py           RFC 9000 §17 packet header parsing
  initial_crypto.py    RFC 9001 §5.2/5.4 Initial secrets + AEAD
  tls_clienthello.py   TLS 1.3 ClientHello parsing
  fingerprint.py        JA4-style fingerprint hashing
  fingerprint_db.py    Learnable fingerprint store + heuristics
  flow.py              Flow tracking / CRYPTO reassembly
  features.py          Statistical flow features
  capture.py           Offline pcap + live capture
  cli.py               Command-line interface
  ml/classifier.py     RandomForest statistical classifier
tests/                 70 tests, including RFC 9369 known-answer vectors
examples/               Library-usage example scripts
docs/                  Architecture, methodology, legal/ethical notes
```

## Limitations

- Multi-Initial-packet ClientHello reassembly (rare in practice) is a
  known follow-up — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Encrypted Client Hello (ECH) hides the *inner* SNI; `quicfp` reports
  only what's genuinely visible and does not claim otherwise.
- The statistical classifier ships untrained — there is no universal
  "QUIC application classifier," and shipping one pretrained on an
  arbitrary dataset would misrepresent its accuracy on your network.

Full list in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#known-limitations).

## License

MIT — see [`LICENSE`](LICENSE).

## Legal & ethical use

Read [`docs/LEGAL_AND_ETHICAL_USE.md`](docs/LEGAL_AND_ETHICAL_USE.md)
before deploying this on any network you don't own or have explicit
authorization to monitor.

## Author

Ashwin N ([g.dev/Ashwin-N-CyberSecurity-Google](https://g.dev/Ashwin-N-CyberSecurity-Google)) —
offensive security professional, TryHackMe global #1, creator of
[SOC-X](https://github.com/AshwinNHacker).
