#!/usr/bin/env python3
"""
Example: train a statistical flow classifier on your own labeled
captures, then use it to classify a new, unlabeled capture.

Expected directory layout for training data:

    labeled_captures/
        youtube/
            session1.pcap
            session2.pcap
        zoom/
            call1.pcap
        web_browsing/
            chrome_session.pcap

Usage:
    python3 examples/train_classifier.py labeled_captures/ my_model.joblib
    python3 examples/train_classifier.py --predict my_model.joblib unknown.pcap
"""

import sys
from pathlib import Path

from quicfp.capture import analyze_pcap
from quicfp.features import extract_features
from quicfp.ml.classifier import FlowClassifier


def train(labeled_dir: str, output_path: str) -> None:
    root = Path(labeled_dir)
    features, labels = [], []

    for label_dir in sorted(root.iterdir()):
        if not label_dir.is_dir():
            continue
        label = label_dir.name
        for pcap_path in sorted(label_dir.glob("*.pcap*")):
            print(f"  reading {pcap_path} (label={label})...")
            table = analyze_pcap(str(pcap_path))
            for flow in table.flows():
                feats = extract_features(flow)
                if feats:
                    features.append(feats)
                    labels.append(label)

    print(f"\nTraining on {len(features)} flows across labels: {sorted(set(labels))}")
    clf = FlowClassifier()
    clf.fit(features, labels)
    clf.save(output_path)
    print(f"Saved model to {output_path}")

    print("\nTop predictive features:")
    for name, importance in sorted(clf.export_feature_importances().items(), key=lambda t: -t[1])[:5]:
        print(f"  {name}: {importance:.4f}")


def predict(model_path: str, pcap_path: str) -> None:
    clf = FlowClassifier.load(model_path)
    table = analyze_pcap(pcap_path)

    for flow in table.flows():
        feats = extract_features(flow)
        if not feats:
            print(f"{flow.flow_key}: too few packets to classify")
            continue
        result = clf.predict(feats)
        print(f"{flow.flow_key}: {result.label} (confidence {result.confidence:.2f})")
        print(f"  all probabilities: {result.all_probabilities}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    if sys.argv[1] == "--predict":
        if len(sys.argv) != 4:
            print("usage: train_classifier.py --predict <model.joblib> <capture.pcap>")
            return 1
        predict(sys.argv[2], sys.argv[3])
        return 0

    if len(sys.argv) != 3:
        print("usage: train_classifier.py <labeled_dir> <output_model.joblib>")
        return 1

    train(sys.argv[1], sys.argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
