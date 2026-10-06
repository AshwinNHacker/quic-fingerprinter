"""
quicfp — QUIC / HTTP3 Traffic Fingerprinter
=============================================

Passive, standards-based detection and fingerprinting tooling for QUIC
(RFC 9000/9001/9369) and HTTP/3 traffic. Built to shine a light into the
"QUIC blind spot": as more traffic moves off TCP+TLS onto QUIC-over-UDP,
traditional TCP/TLS-centric visibility tools (JA3, SNI-sniffing on TLS
ClientHello, TCP fingerprinting) stop seeing anything useful. This
project brings equivalent visibility to UDP/443 QUIC flows.

Capabilities:
    - QUIC long/short header parsing (versions 1 and 2, plus draft/GREASE
      version tolerance) straight off the wire, no active probing.
    - RFC 9001 §5.2 Initial-secret derivation to unprotect Initial
      packets (this uses the *public* QUIC initial salt -- the same
      mechanism every QUIC-aware NIDS such as Zeek/Suricata relies on;
      it is header *de-obfuscation*, not a break of QUIC's real
      end-to-end TLS 1.3 encryption of application data).
    - Parses the recovered CRYPTO frame as a TLS 1.3 ClientHello and
      extracts SNI, ALPN, supported groups/versions and extension order.
    - Computes a JA4QUIC-style deterministic fingerprint hash from that
      ClientHello, for allow-list/deny-list and client-family matching.
    - Falls back to passive flow-statistical fingerprinting (packet size
      / timing / direction distributions) for 1-RTT / short-header
      traffic where no ClientHello is observable, feeding a scikit-learn
      classifier.
    - CLI and library APIs for offline pcap analysis and live capture.

This is a defensive/observability tool. It does not decrypt QUIC
application data, does not perform key exfiltration, and requires no
endpoint access — everything is derived from information any on-path
observer already has (public salts + cleartext long-header fields).
"""

from quicfp.version import __version__

__all__ = ["__version__"]
