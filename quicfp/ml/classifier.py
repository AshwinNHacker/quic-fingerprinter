"""
Statistical flow classifier for QUIC traffic that offers no visible
ClientHello (1-RTT-only captures, ECH-protected handshakes, resumed
0-RTT connections, etc.).

This is a thin, well-documented wrapper around scikit-learn's
RandomForestClassifier trained on the features in
:mod:`quicfp.features`. It is intentionally simple: the point of this
project is transparent, auditable detection logic, not a black-box
model. A random forest was chosen over a neural approach because (a)
flow statistical features are low-dimensional and tabular, where tree
ensembles are a strong, well-understood baseline, and (b) per-tree
feature importances give an interpretable explanation for any
classification, which matters for a defensive tool whose output may
inform blocking decisions.

You must train this on YOUR OWN labeled traffic before it is useful
--- there is no universal "QUIC application classifier" that
generalizes across networks, and shipping one pretrained on an
arbitrary dataset would give a false sense of accuracy. See
``examples/train_classifier.py`` and the README's "Training your own
classifier" section.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from quicfp.features import FlowFeatures


@dataclass
class ClassificationResult:
    label: str
    confidence: float
    all_probabilities: dict[str, float]
    top_features: list[tuple[str, float]]


class FlowClassifier:
    def __init__(self, n_estimators: int = 200, max_depth: int | None = 12, random_state: int = 42):
        from sklearn.ensemble import RandomForestClassifier

        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            class_weight="balanced",
        )
        self.classes_: list[str] = []
        self.is_trained = False

    def fit(self, features: list[FlowFeatures], labels: list[str]) -> None:
        if len(features) != len(labels):
            raise ValueError("features and labels must be the same length")
        if len(features) < 10:
            raise ValueError(
                f"only {len(features)} training examples provided; "
                "a meaningful classifier needs at least a few dozen "
                "labeled flows per class"
            )
        X = np.array([f.as_vector() for f in features])
        self.model.fit(X, labels)
        self.classes_ = list(self.model.classes_)
        self.is_trained = True

    def predict(self, features: FlowFeatures) -> ClassificationResult:
        if not self.is_trained:
            raise RuntimeError("classifier has not been trained or loaded yet")
        X = np.array([features.as_vector()])
        proba = self.model.predict_proba(X)[0]
        label_idx = int(np.argmax(proba))
        label = self.classes_[label_idx]
        confidence = float(proba[label_idx])
        all_probs = {cls: float(p) for cls, p in zip(self.classes_, proba, strict=True)}

        importances = self.model.feature_importances_
        names = FlowFeatures.feature_names()
        top = sorted(zip(names, importances, strict=True), key=lambda t: -t[1])[:5]

        return ClassificationResult(
            label=label,
            confidence=confidence,
            all_probabilities=all_probs,
            top_features=[(n, float(v)) for n, v in top],
        )

    def save(self, path: str | Path) -> None:
        path = Path(path)
        joblib.dump({"model": self.model, "classes": self.classes_}, path)

    @classmethod
    def load(cls, path: str | Path) -> FlowClassifier:
        path = Path(path)
        payload = joblib.load(path)
        clf = cls.__new__(cls)
        clf.model = payload["model"]
        clf.classes_ = payload["classes"]
        clf.is_trained = True
        return clf

    def export_feature_importances(self) -> dict[str, float]:
        if not self.is_trained:
            raise RuntimeError("classifier has not been trained yet")
        names = FlowFeatures.feature_names()
        return dict(zip(names, (float(v) for v in self.model.feature_importances_), strict=True))
