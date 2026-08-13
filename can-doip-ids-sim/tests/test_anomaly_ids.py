# Author: Rayan Hamour (22103817)
"""Unit tests for the ML-based (IsolationForest) anomaly detector."""

from __future__ import annotations

import random

import can

from carnet.ids.anomaly import AnomalyIDS, MIN_TRAINING_SAMPLES


def _feed_normal_traffic(ids: AnomalyIDS, arb_id: int, count: int) -> None:
    rng = random.Random(1)
    for _ in range(count):
        ids.on_message_received(
            can.Message(arbitration_id=arb_id, data=bytes([rng.randint(100, 110), 0, 0, 0]), is_extended_id=False)
        )


def test_no_model_before_fit_collects_training_data():
    ids = AnomalyIDS()
    _feed_normal_traffic(ids, 0x100, MIN_TRAINING_SAMPLES + 5)
    assert ids.alert_count() == 0  # still in training mode, never scores anything
    assert 0x100 in ids._training_features


def test_grossly_out_of_range_value_flagged_after_training():
    ids = AnomalyIDS()
    _feed_normal_traffic(ids, 0x100, MIN_TRAINING_SAMPLES + 10)
    ids.fit()
    # baseline byte0 was always ~100-110; an extreme outlier should stand out
    for _ in range(5):
        ids.on_message_received(can.Message(arbitration_id=0x100, data=bytes([255, 0, 0, 0]), is_extended_id=False))
    assert ids.alert_count() > 0


def test_unknown_id_after_training_is_flagged():
    ids = AnomalyIDS()
    _feed_normal_traffic(ids, 0x100, MIN_TRAINING_SAMPLES + 5)
    ids.fit()
    ids.on_message_received(can.Message(arbitration_id=0x999, data=bytes(4), is_extended_id=False))
    rules = {a.rule for a in ids.alerts}
    assert "ml_unknown_id" in rules


def test_insufficient_training_data_skips_model_without_crashing():
    ids = AnomalyIDS()
    _feed_normal_traffic(ids, 0x100, 3)  # well under MIN_TRAINING_SAMPLES
    ids.fit()
    ids.on_message_received(can.Message(arbitration_id=0x100, data=bytes(4), is_extended_id=False))
    assert 0x100 not in ids._models
