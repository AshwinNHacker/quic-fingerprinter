#!/usr/bin/env python3
"""
Example: use quicfp as a library (rather than the CLI) to analyze a
pcap file and print a summary of every QUIC ClientHello found.

Usage:
    python3 examples/analyze_pcap_basic.py path/to/capture.pcap
"""

import sys

from quicfp.capture import analyze_pcap
from quicfp.fingerprint import compute_fingerprint
from quicfp.fingerprint_db import heuristic_guess
from quicfp.headers import QUIC_VERSION_2, describe_version


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <pcap-file>", file=sys.stderr)
        return 1

    pcap_path = sys.argv[1]
    print(f"Analyzing {pcap_path}...")

    table = analyze_pcap(pcap_path)
    flows = table.flows()
    quic_flows = [f for f in flows if f.version is not None]

    print(f"Found {len(flows)} total UDP flows, {len(quic_flows)} of which are QUIC.\n")

    for flow in quic_flows:
        print(f"Flow: {flow.flow_key}")
        print(f"  Version: {describe_version(flow.version)}")
        print(f"  Packets: {flow.packet_count}, duration: {flow.duration:.2f}s")

        if flow.client_hello_parsed and flow.client_hello:
            ch = flow.client_hello
            fp = compute_fingerprint(ch, quic_version_is_v2=(flow.version == QUIC_VERSION_2))
            guess = heuristic_guess(ch)

            print(f"  SNI: {ch.sni}")
            print(f"  ALPN: {ch.alpn}")
            print(f"  Fingerprint: {fp.sorted_fingerprint[:16]}...")
            print(f"  Likely client: {guess.label} ({guess.confidence})")
        else:
            print(f"  No ClientHello visible ({flow.parse_error or '1-RTT only'})")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
