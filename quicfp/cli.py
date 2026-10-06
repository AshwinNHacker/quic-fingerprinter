"""
Command-line interface for quicfp.

Subcommands:
    analyze   Analyze a pcap file offline: parse QUIC packets, decrypt
              Initial ClientHellos, compute fingerprints, and report.
    live      Capture live traffic from an interface and report in
              real time (requires elevated privileges).
    learn     Add a labeled fingerprint to the local fingerprint
              database from a pcap known to contain traffic from a
              specific client.
    train     Train a statistical flow classifier from a directory of
              labeled pcaps (one subdirectory per label).
    version   Print the installed quicfp version.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from quicfp.version import __version__


def _cmd_analyze(args: argparse.Namespace) -> int:
    from quicfp.capture import analyze_pcap
    from quicfp.features import extract_features
    from quicfp.fingerprint import compute_fingerprint
    from quicfp.fingerprint_db import FingerprintStore, heuristic_guess
    from quicfp.headers import QUIC_VERSION_2, describe_version

    if not Path(args.pcap).exists():
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return 1

    store = FingerprintStore.load(Path(args.db) if args.db else None)

    def _progress(n: int) -> None:
        if args.verbose:
            print(f"\r  ...{n} UDP datagrams processed", end="", file=sys.stderr)

    try:
        table = analyze_pcap(args.pcap, progress_cb=_progress if args.verbose else None)
    except Exception as exc:
        print(f"error: failed to read pcap: {exc}", file=sys.stderr)
        return 1
    if args.verbose:
        print(file=sys.stderr)

    flows = table.flows()
    quic_flows = [f for f in flows if f.version is not None or any(p.is_long_header for p in f.packets)]

    report = {
        "pcap": args.pcap,
        "total_flows_seen": len(flows),
        "quic_flows": len(quic_flows),
        "flows": [],
    }

    for flow in quic_flows:
        entry = {
            "flow_key": [list(x) for x in flow.flow_key],
            "version": f"0x{flow.version:08x}" if flow.version else None,
            "version_name": describe_version(flow.version) if flow.version else None,
            "packet_count": flow.packet_count,
            "duration_s": round(flow.duration, 3),
        }

        if flow.client_hello_parsed and flow.client_hello:
            ch = flow.client_hello
            fp = compute_fingerprint(ch, quic_version_is_v2=(flow.version == QUIC_VERSION_2))
            match = store.lookup(fp) or heuristic_guess(ch)
            entry["client_hello"] = {
                "sni": ch.sni,
                "alpn": ch.alpn,
                "cipher_suites": ch.cipher_suite_names,
                "supported_groups": ch.supported_groups,
                "extension_order": ch.extension_order,
                "grease_present": ch.is_grease_present,
            }
            entry["fingerprint"] = {
                "sorted": fp.sorted_fingerprint,
                "raw_order": fp.raw_order_fingerprint,
                "short": fp.short(),
            }
            entry["client_match"] = {"label": match.label, "confidence": match.confidence, "detail": match.detail}
        elif flow.parse_error:
            entry["parse_error"] = flow.parse_error
        else:
            entry["note"] = "no visible ClientHello (1-RTT only, ECH, or non-Initial capture)"

        features = extract_features(flow)
        if features:
            entry["statistical_features"] = dict(zip(features.feature_names(), features.as_vector(), strict=True))

        report["flows"].append(entry)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_human_report(report, args.verbose)

    return 0


def _print_human_report(report: dict, verbose: bool) -> None:
    print(f"\nquicfp analysis: {report['pcap']}")
    print(f"  total flows (any protocol on UDP): {report['total_flows_seen']}")
    print(f"  QUIC flows identified:             {report['quic_flows']}")
    print("=" * 72)

    for i, flow in enumerate(report["flows"], 1):
        print(f"\n[{i}] {flow['flow_key']}")
        print(f"    version: {flow.get('version')} ({flow.get('version_name')})")
        print(f"    packets: {flow['packet_count']}   duration: {flow['duration_s']}s")

        if "client_hello" in flow:
            ch = flow["client_hello"]
            fp = flow["fingerprint"]
            match = flow["client_match"]
            print(f"    SNI:  {ch['sni']}")
            print(f"    ALPN: {ch['alpn']}")
            print(f"    ciphers: {ch['cipher_suites']}")
            print(f"    fingerprint (sorted):    {fp['sorted']}")
            print(f"    fingerprint (raw order): {fp['raw_order']}")
            print(f"    client match: {match['label']}  [{match['confidence']}]")
            if verbose:
                print(f"      -> {match['detail']}")
        elif "parse_error" in flow:
            print(f"    (Initial packet seen but not decrypted: {flow['parse_error']})")
        elif "note" in flow:
            print(f"    ({flow['note']})")

        if verbose and "statistical_features" in flow:
            print("    statistical features:")
            for k, v in flow["statistical_features"].items():
                print(f"      {k}: {v:.4f}" if isinstance(v, float) else f"      {k}: {v}")

    print()


def _cmd_learn(args: argparse.Namespace) -> int:
    from quicfp.capture import analyze_pcap
    from quicfp.fingerprint import compute_fingerprint
    from quicfp.fingerprint_db import FingerprintStore
    from quicfp.headers import QUIC_VERSION_2

    if not Path(args.pcap).exists():
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return 1

    store = FingerprintStore.load(Path(args.db) if args.db else None)
    table = analyze_pcap(args.pcap)
    learned = 0
    for flow in table.flows():
        if flow.client_hello_parsed and flow.client_hello:
            fp = compute_fingerprint(flow.client_hello, quic_version_is_v2=(flow.version == QUIC_VERSION_2))
            store.learn(fp, args.label)
            learned += 1
    store.save()
    print(f"Learned {learned} fingerprint(s) as '{args.label}' -> {store.path}")
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    from quicfp.capture import analyze_pcap
    from quicfp.features import extract_features
    from quicfp.ml.classifier import FlowClassifier

    root = Path(args.labeled_dir)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    all_features = []
    all_labels = []
    for label_dir in sorted(root.iterdir()):
        if not label_dir.is_dir():
            continue
        label = label_dir.name
        for pcap_path in sorted(label_dir.glob("*.pcap*")):
            table = analyze_pcap(str(pcap_path))
            for flow in table.flows():
                feats = extract_features(flow)
                if feats:
                    all_features.append(feats)
                    all_labels.append(label)

    if not all_features:
        print("error: no usable flows found under the labeled directory", file=sys.stderr)
        return 1

    print(f"Training on {len(all_features)} flows across {len(set(all_labels))} labels...")
    clf = FlowClassifier()
    clf.fit(all_features, all_labels)
    clf.save(args.output)
    print(f"Saved trained classifier to {args.output}")
    print("Feature importances:")
    for name, importance in sorted(clf.export_feature_importances().items(), key=lambda t: -t[1]):
        print(f"  {name:24s} {importance:.4f}")
    return 0


def _cmd_live(args: argparse.Namespace) -> int:
    from quicfp.capture import live_capture
    from quicfp.features import extract_features
    from quicfp.fingerprint import compute_fingerprint
    from quicfp.fingerprint_db import FingerprintStore, heuristic_guess
    from quicfp.headers import QUIC_VERSION_2

    print(f"Capturing on {args.interface} (filter: udp)... Ctrl+C to stop.")
    store = FingerprintStore.load(Path(args.db) if args.db else None)
    try:
        table = live_capture(args.interface, duration_s=args.duration, packet_limit=args.count)
    except PermissionError:
        print(
            "error: live capture requires elevated privileges "
            "(run with sudo on Linux/macOS, or as Administrator with "
            "Npcap installed on Windows)",
            file=sys.stderr,
        )
        return 1

    for flow in table.flows():
        if flow.client_hello_parsed and flow.client_hello:
            fp = compute_fingerprint(flow.client_hello, quic_version_is_v2=(flow.version == QUIC_VERSION_2))
            match = store.lookup(fp) or heuristic_guess(flow.client_hello)
            print(f"{flow.flow_key} SNI={flow.client_hello.sni} ALPN={flow.client_hello.alpn} "
                  f"match={match.label} [{match.confidence}]")
        else:
            feats = extract_features(flow)
            note = "1-RTT only / no ClientHello observed"
            if feats:
                note += f" (mean_size={feats.mean_packet_size:.0f}B, pps={feats.packets_per_second:.1f})"
            print(f"{flow.flow_key} {note}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quicfp",
        description="QUIC/HTTP3 traffic fingerprinter -- detection tooling for the QUIC blind spot",
    )
    parser.add_argument("--version", action="version", version=f"quicfp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze a pcap/pcapng file offline")
    p_analyze.add_argument("pcap", help="Path to a .pcap or .pcapng file")
    p_analyze.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_analyze.add_argument("--verbose", "-v", action="store_true", help="Show statistical features and progress")
    p_analyze.add_argument("--db", help="Path to a fingerprint database JSON file")
    p_analyze.set_defaults(func=_cmd_analyze)

    p_learn = sub.add_parser("learn", help="Add labeled fingerprints from a pcap to the local database")
    p_learn.add_argument("pcap", help="Path to a pcap containing traffic from a known client")
    p_learn.add_argument("--label", required=True, help="Human-readable label, e.g. 'Chrome 126 / Windows 11'")
    p_learn.add_argument("--db", help="Path to a fingerprint database JSON file")
    p_learn.set_defaults(func=_cmd_learn)

    p_train = sub.add_parser("train", help="Train a statistical flow classifier from labeled pcaps")
    p_train.add_argument("labeled_dir", help="Directory with one subdirectory of pcaps per label")
    p_train.add_argument("--output", default="quicfp_classifier.joblib", help="Where to save the trained model")
    p_train.set_defaults(func=_cmd_train)

    p_live = sub.add_parser("live", help="Capture and report on live QUIC traffic")
    p_live.add_argument("interface", help="Network interface name (e.g. eth0, en0)")
    p_live.add_argument("--duration", type=float, default=None, help="Stop after N seconds")
    p_live.add_argument("--count", type=int, default=0, help="Stop after N packets")
    p_live.add_argument("--db", help="Path to a fingerprint database JSON file")
    p_live.set_defaults(func=_cmd_live)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
