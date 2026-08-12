"""Unit tests for the bus-off attack and the IDS silence rule."""

from __future__ import annotations

import time

from carnet.attacks.busoff import run_busoff_attack
from carnet.can.bus import create_bus
from carnet.config import BUS_OFF_TEC_INCREMENT, BUS_OFF_TEC_THRESHOLD
from carnet.ids.detector import RuleBasedIDS


def test_busoff_attack_silences_victim_id():
    bus = create_bus()
    try:
        silenced: set[int] = set()
        result = run_busoff_attack(bus, target_id=0x200, duration_s=1.0, rate_hz=100, silenced_ids=silenced)
        assert result["bus_off_achieved"] is True
        assert 0x200 in silenced
        expected_frames = BUS_OFF_TEC_THRESHOLD / BUS_OFF_TEC_INCREMENT
        assert result["time_to_bus_off_s"] is not None
        assert result["sent"] >= expected_frames
    finally:
        bus.shutdown()


def test_busoff_attack_does_not_silence_other_ids():
    bus = create_bus()
    try:
        silenced: set[int] = set()
        run_busoff_attack(bus, target_id=0x200, duration_s=1.0, rate_hz=100, silenced_ids=silenced)
        assert 0x100 not in silenced
    finally:
        bus.shutdown()


def test_silence_rule_fires_after_id_goes_quiet():
    ids = RuleBasedIDS()
    try:
        import can

        ids.on_message_received(can.Message(arbitration_id=0x200, data=bytes(4), is_extended_id=False))
        time.sleep(0.25)  # 0x200's nominal period is 20ms; 250ms is well past the silence threshold
        ids.check_silence()
        rules = {a.rule for a in ids.alerts}
        assert "silence" in rules
    finally:
        ids.stop()


def test_silence_rule_does_not_fire_while_traffic_continues():
    ids = RuleBasedIDS()
    try:
        import can

        for _ in range(5):
            ids.on_message_received(can.Message(arbitration_id=0x200, data=bytes(4), is_extended_id=False))
            time.sleep(0.02)
        ids.check_silence()
        rules = {a.rule for a in ids.alerts}
        assert "silence" not in rules
    finally:
        ids.stop()
