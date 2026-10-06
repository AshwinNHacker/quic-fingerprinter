# Contributing to quicfp

Contributions are welcome. This project intentionally favors
correctness verified against IETF RFC test vectors over feature
breadth -- when in doubt, add a test that cites the RFC section it
verifies.

## Development setup

```bash
git clone https://github.com/AshwinNHacker/quic-fingerprinter.git
cd quic-fingerprinter
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest                          # full suite
pytest --cov=quicfp             # with coverage
ruff check quicfp tests         # lint
```

The test suite includes known-answer tests transcribed directly from
RFC 9369 Appendix A ("Sample Packet Protection") -- if you touch
`quicfp/initial_crypto.py`, `quicfp/headers.py`, or `quicfp/varint.py`,
make sure `tests/test_initial_crypto.py` and `tests/test_headers.py`
still pass; these are the ground-truth checks that the cryptographic
core is correct, not just internally consistent.

## Good first issues

- **Multi-packet ClientHello reassembly**: `quicfp/flow.py`'s
  `_try_decrypt_initial` currently treats each Initial packet's CRYPTO
  contribution as starting at stream offset 0. A ClientHello that
  spans multiple Initial packets (large cert chains, many extensions)
  needs offset-aware reassembly across packets, not just within one
  packet's frames.
- **QUIC v1 additional test vectors**: `tests/vectors.py` currently
  only includes RFC 9369 (v2) vectors. Adding the RFC 9001 Appendix A
  v1 vectors alongside them would extend known-answer coverage.
- **JA4QUIC comparison / interop**: if you have real-world labeled
  captures, a script comparing `quicfp`'s fingerprint output against
  published third-party QUIC fingerprinting tools would help validate
  the fingerprint design choices in `quicfp/fingerprint.py`.
- **ChaCha20-Poly1305 Initial support**: `initial_crypto.py` currently
  assumes AEAD_AES_128_GCM for Initial packets (correct per RFC 9001
  §5 -- Initial packets always use AES-128-GCM), but header protection
  helper functions could be extended to also support ChaCha20 for
  completeness with `quicfp/tls_clienthello.py`'s handshake parsing of
  1-RTT ChaCha20 traffic, should that be added later.

## Code style

- Type hints throughout; `mypy` is configured but not yet strictly
  enforced in CI.
- Every non-trivial cryptographic or protocol-parsing function should
  cite the RFC section it implements in a docstring or comment.
- Prefer raising a project-specific exception (`HeaderParseError`,
  `InitialCryptoError`, `ClientHelloParseError`) over letting a raw
  `IndexError`/`struct.error` propagate from malformed input --
  capture parsing must never crash on garbage bytes.

## Reporting security issues

If you find a vulnerability in this tool itself (not in QUIC/TLS),
please open a GitHub issue marked `security` or contact the maintainer
directly rather than filing a public exploit walkthrough.
