"""
Regenerates tests/data/rfc9369_client_initial.pcap.

This wraps the exact RFC 9369 Appendix A.2 "Client Initial" sample
packet (see tests/vectors.py) in a synthetic Ethernet/IPv4/UDP frame
so that quicfp's pcap-reading code path can be exercised against
known-good QUIC bytes, rather than only against hand-built Python
objects. The pcap is committed to the repo so tests don't depend on
scapy at test-collection time, but you can regenerate it with:

    python3 tests/data/generate_vectors.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.vectors import RFC9369_CLIENT_INITIAL_PACKET_HEX  # noqa: E402


def main() -> None:
    from scapy.all import IP, UDP, Ether, Raw, wrpcap

    quic_payload = bytes.fromhex(RFC9369_CLIENT_INITIAL_PACKET_HEX)
    pkt = (
        Ether()
        / IP(src="10.0.0.5", dst="93.184.216.34")
        / UDP(sport=51234, dport=443)
        / Raw(load=quic_payload)
    )
    out_path = Path(__file__).parent / "rfc9369_client_initial.pcap"
    wrpcap(str(out_path), [pkt])
    print(f"wrote {out_path} ({len(quic_payload)}-byte QUIC payload)")


if __name__ == "__main__":
    main()
