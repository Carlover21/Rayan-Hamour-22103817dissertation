# Author: Rayan Hamour (22103817)
"""Unit tests for the LSTM sequence-based anomaly detector."""

from __future__ import annotations

import random

import can

from carnet.ids.sequence_dl import MIN_TRAINING_WINDOWS, WINDOW, SequenceIDS


def _feed_normal_traffic(ids: SequenceIDS, arb_id: int, count: int) -> None:
    rng = random.Random(1)
    for _ in range(count):
        ids.on_message_received(
            can.Message(arbitration_id=arb_id, data=bytes([rng.randint(100, 110), 0, 0, 0]), is_extended_id=False)
        )


def test_no_model_before_fit_collects_training_windows():
    ids = SequenceIDS()
    _feed_normal_traffic(ids, 0x100, WINDOW + MIN_TRAINING_WINDOWS + 5)
    assert ids.alert_count() == 0
    assert len(ids._training_windows[0x100]) >= MIN_TRAINING_WINDOWS


def test_insufficient_training_data_skips_model_without_crashing():
    ids = SequenceIDS()
    _feed_normal_traffic(ids, 0x100, WINDOW + 2)  # not enough windows
    ids.fit()
    ids.on_message_received(can.Message(arbitration_id=0x100, data=bytes(4), is_extended_id=False))
    assert 0x100 not in ids._models


def test_unknown_id_after_training_is_flagged():
    ids = SequenceIDS()
    _feed_normal_traffic(ids, 0x100, WINDOW + MIN_TRAINING_WINDOWS + 5)
    ids.fit()
    ids.on_message_received(can.Message(arbitration_id=0x999, data=bytes(4), is_extended_id=False))
    rules = {a.rule for a in ids.alerts}
    assert "seq_unknown_id" in rules


def test_grossly_abnormal_sequence_flagged_after_training():
    ids = SequenceIDS()
    _feed_normal_traffic(ids, 0x100, WINDOW + MIN_TRAINING_WINDOWS + 10)
    ids.fit()
    assert 0x100 in ids._models  # sanity: model actually trained

    # a whole window of extreme, wildly different values from the tight
    # 100-110 baseline the model was trained on
    for _ in range(WINDOW + 2):
        ids.on_message_received(can.Message(arbitration_id=0x100, data=bytes([0, 255, 0, 0]), is_extended_id=False))
    assert ids.alert_count() > 0
