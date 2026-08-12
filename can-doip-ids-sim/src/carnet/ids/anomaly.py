"""
ML-based intrusion detection, for direct comparison against the rule-based
detector - several of the papers in this project''s literature review use
ML/statistical approaches (CNN, Gaussian Naive Bayes, GAN-based) rather than
hand-tuned thresholds, so the evaluation should be able to say something
quantitative about that choice rather than just asserting it.

Uses one scikit-learn IsolationForest per known arbitration ID, trained on
baseline (attack-free) traffic features: inter-arrival time and the first
two payload bytes. IsolationForest is an unsupervised outlier detector - it
never sees attack traffic during training, matching the realistic
constraint that labelled attack data is scarce, which is exactly why
several of the reviewed papers pick anomaly-detection framings over
supervised classifiers.

Same two-phase lifecycle as the rule-based IDS''s baseline/attack split:
messages observed before `fit()` is called become training data; every
message after that is scored against the fitted models.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

import can
from sklearn.ensemble import IsolationForest

from carnet.config import KNOWN_IDS
from carnet.ids.alert import IDSAlert

MIN_TRAINING_SAMPLES = 20
CONTAMINATION = 0.02


class AnomalyIDS(can.Listener):
    def __init__(self, start_time: float | None = None):
        self.start_time = start_time if start_time is not None else time.monotonic()
        self._lock = threading.Lock()
        self.alerts: list[IDSAlert] = []
        self._training_features: dict[int, list[list[float]]] = defaultdict(list)
        self._last_seen: dict[int, float] = {}
        self._models: dict[int, IsolationForest] = {}
        self._trained = False

    def now(self) -> float:
        return time.monotonic() - self.start_time

    def _raise(self, now: float, arb_id: int, rule: str, detail: str) -> None:
        self.alerts.append(IDSAlert(timestamp=now, arbitration_id=arb_id, rule=rule, detail=detail))

    def _features(self, arb_id: int, data: bytes, now: float) -> list[float]:
        last = self._last_seen.get(arb_id)
        inter_arrival_ms = (now - last) * 1000 if last is not None else 0.0
        self._last_seen[arb_id] = now
        byte0 = data[0] if len(data) > 0 else 0
        byte1 = data[1] if len(data) > 1 else 0
        return [inter_arrival_ms, float(byte0), float(byte1)]

    def on_message_received(self, msg: can.Message) -> None:
        now = self.now()
        arb_id = msg.arbitration_id
        data = bytes(msg.data)
        with self._lock:
            if self._trained:
                self._detect(now, arb_id, data)
            else:
                feats = self._features(arb_id, data, now)
                self._training_features[arb_id].append(feats)

    def fit(self) -> None:
        """Call once, at the baseline/attack boundary, to train on everything
        observed so far and switch into detection mode."""
        with self._lock:
            for arb_id, feats in self._training_features.items():
                if len(feats) < MIN_TRAINING_SAMPLES:
                    continue
                model = IsolationForest(n_estimators=100, contamination=CONTAMINATION, random_state=42)
                model.fit(feats)
                self._models[arb_id] = model
            # Deliberately not clearing _last_seen here: the last training-phase
            # timestamp is still valid history, and discarding it would make the
            # first post-training message for each ID look like a fake 0ms
            # inter-arrival - an artificial edge effect, not a real anomaly.
            self._trained = True

    def _detect(self, now: float, arb_id: int, data: bytes) -> None:
        if arb_id not in KNOWN_IDS:
            self._raise(now, arb_id, "ml_unknown_id", f"arbitration ID 0x{arb_id:X} never seen in training")
            return
        model = self._models.get(arb_id)
        feats = self._features(arb_id, data, now)
        if model is None:
            return  # not enough baseline samples to train a model for this ID
        prediction = model.predict([feats])[0]
        if prediction == -1:
            self._raise(
                now,
                arb_id,
                "ml_anomaly",
                f"IsolationForest outlier: inter_arrival={feats[0]:.1f}ms, byte0={int(feats[1])}, byte1={int(feats[2])}",
            )

    def alert_count(self) -> int:
        with self._lock:
            return len(self.alerts)