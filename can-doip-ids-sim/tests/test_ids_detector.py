"""Unit tests for the rule-based IDS, using synthetic can.Message objects
directly (no real bus/timing involved) so they run fast and deterministically.
"""

from __future__ import annotations

import time

import can

from carnet.ids.detector import RuleBasedIDS


def make_msg(arb_id: int, data: bytes = b"\x00" * 8) -> can.Message:
    return can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)


def test_unknown_id_triggers_alert():
    ids = RuleBasedIDS()
    ids.on_message_received(make_msg(0xABC))  # not in KNOWN_IDS
    rules = {a.rule for a in ids.alerts}
    assert "unknown_id" in rules


def test_known_id_normal_rate_no_alert():
    ids = RuleBasedIDS()
    # 0x400 (Body_Control) nominal period 100ms; a handful of on-time
    # messages should not trip rate or timing rules.
    t0 = time.monotonic()
    ids.start_time = t0
    for _ in range(5):
        ids.on_message_received(make_msg(0x400))
        time.sleep(0.1)
    assert ids.alert_count() == 0


def test_flood_triggers_rate_alert():
    ids = RuleBasedIDS()
    for _ in range(300):  # far above the configured limit for 0x100
        ids.on_message_received(make_msg(0x100))
    rules = {a.rule for a in ids.alerts}
    assert "rate_threshold" in rules


def test_rapid_repeat_triggers_timing_deviation():
    ids = RuleBasedIDS()
    ids.on_message_received(make_msg(0x200))  # nominal period 20ms
    ids.on_message_received(make_msg(0x200))  # sent ~instantly after -> far too fast
    rules = {a.rule for a in ids.alerts}
    assert "timing_deviation" in rules
