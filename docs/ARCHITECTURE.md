# Architecture & Methodology

## The problem: the QUIC blind spot

For two decades, network defenders have relied on TCP+TLS metadata for
visibility: TCP handshake fingerprinting (p0f), TLS ClientHello
fingerprinting (JA3/JA3S/JA4), and plain-text SNI in the TLS
handshake. As HTTP/3 and QUIC adoption grows, an increasing share of
traffic moves onto UDP/443 with a transport (QUIC) that was
deliberately designed to resist exactly this kind of passive,
on-path visibility for everything *after* the handshake:

- QUIC packet headers are far more minimal than TCP's, carrying almost
  no cleartext metadata once a connection is past its Initial phase.
- 1-RTT (short-header) packets -- which make up the overwhelming
  majority of a connection's packets by both count and byte volume --
  have their packet numbers and payload strongly encrypted with keys
  from a genuine, ephemeral (EC)DHE handshake. There is no
  cryptographic trick available to a passive observer here, by design.
- Because QUIC multiplexes streams inside a single encrypted
  connection, even the coarse "how many things is this connection
  doing" signal that TCP connection-count gave you is gone.

This is "the QUIC blind spot": existing TLS/TCP-centric NIDS,
firewalls, and traffic-shaping tools frequently fall back to "treat
all UDP/443 as opaque," which is both a visibility loss for defenders
and, ironically, a *privacy* win users didn't necessarily ask their
network operator to give up awareness of (e.g. malware C2 traffic
increasingly rides on QUIC specifically because it's under-inspected).

## What this project does about it

`quicfp` targets the two halves of a QUIC connection separately,
because they have fundamentally different visibility properties:

### 1. The Initial packet (genuinely visible, by design)

RFC 9001 §5.2 deliberately protects a connection's very first packet
(the one carrying the TLS ClientHello) with a key derived only from a
**public, RFC-published salt** and the packet's own **cleartext
Destination Connection ID**. This is not a vulnerability or a trick --
quoting RFC 9369's discussion of why each new QUIC version defines a
new salt: it exists specifically so that "observers [can] inspect
[Initial packets'] contents, which includes the TLS ClientHello or
ServerHello messages," preserving the same operational visibility
network operators historically had into TLS-over-TCP's ClientHello.

`quicfp` implements this derivation faithfully (`quicfp/initial_crypto.py`),
validated byte-for-byte against the IETF's own published test vectors
in RFC 9369 Appendix A, and uses it to:

1. Remove header protection and AEAD-decrypt the Initial packet.
2. Reassemble and parse the TLS 1.3 ClientHello it carries
   (`quicfp/tls_clienthello.py`).
3. Extract SNI, ALPN, cipher suites, extensions, and QUIC transport
   parameters.
4. Compute a JA4-style deterministic fingerprint hash
   (`quicfp/fingerprint.py`) usable for allow/deny-listing and client
   family identification.

This gives you, for the *start* of every QUIC connection, equivalent
visibility to what JA3/SNI-sniffing gave you for TLS-over-TCP.

### 2. Everything after the handshake (genuinely opaque, by design)

Once a connection moves to 1-RTT packets, there is no equivalent
trick -- and there shouldn't be, because this is QUIC's actual
end-to-end security boundary doing its job. For this traffic,
`quicfp` falls back to the well-established academic technique of
**flow-level statistical fingerprinting** (`quicfp/features.py`):
packet size distributions, inter-arrival timing, directionality
ratios, and Shannon entropy of the size distribution. Encryption
protects packet *content*; it does not and cannot hide packet
*timing and size*, which is why this class of side-channel survives
even a textbook-perfect TLS 1.3/QUIC deployment. A `RandomForestClassifier`
(`quicfp/ml/classifier.py`) is provided to turn these features into
coarse application/client-family classification -- but **only when
trained on your own labeled traffic**; there is no universally
correct pretrained model for this and this project doesn't pretend
otherwise.

## Why a random forest, not a neural network?

Flow statistical features are low-dimensional (15 features) and
tabular. Tree ensembles are a strong, well-understood, and -- crucially
for a defensive security tool -- *auditable* baseline: every
classification comes with per-feature importances explaining *why*
the model reached its conclusion, which matters when the output might
inform a blocking decision. A deep model might squeeze out a few
points of accuracy on a specific dataset at the cost of
interpretability quicfp intentionally does not trade away.

## Module map

```
quicfp/
  varint.py            RFC 9000 §16 variable-length integers
  headers.py           RFC 9000 §17 long/short header parsing
  initial_crypto.py    RFC 9001 §5.2/5.4 Initial secret derivation + AEAD
  tls_clienthello.py   TLS 1.3 ClientHello parsing (RFC 8446 §4.1.2)
  fingerprint.py        JA4-style deterministic fingerprint hashing
  fingerprint_db.py    Learnable fingerprint store + heuristic matcher
  flow.py              5-tuple/CID flow tracking, CRYPTO reassembly
  features.py          Flow-level statistical feature extraction
  capture.py           Offline pcap + live interface capture
  cli.py               `quicfp` command-line tool
  ml/
    classifier.py      RandomForest wrapper for statistical classification
```

## Known limitations

- **ECH (Encrypted Client Hello)**: when the TLS ClientHello itself is
  wrapped in ECH, the *outer* ClientHello is still visible (and still
  fingerprintable), but the real SNI is hidden inside the encrypted
  inner ClientHello. `quicfp` correctly reports what it can see (outer
  extensions, ALPN if present outside ECH) and does not claim to
  recover the inner SNI.
- **Multi-packet ClientHellos**: a ClientHello that spans more than one
  Initial packet (rare -- typically only with very large certificate
  chains or many extensions) requires CRYPTO-stream reassembly across
  packets by *offset*, not just by packet arrival order. The current
  flow tracker reassembles same-packet CRYPTO fragments but treats
  each packet's contribution as a fresh reassembly; genuinely
  multi-packet-spanning ClientHellos are a known follow-up (tracked as
  a "good first issue" -- see CONTRIBUTING).
- **0-RTT / resumed connections**: a resumed connection's 0-RTT data is
  still protected with negotiated (not Initial-salt-derived) keys and
  is correctly treated as opaque by this tool.
- **Statistical classification accuracy** depends entirely on the
  quality and representativeness of the labeled training data you
  provide; no pretrained model ships with this project.
