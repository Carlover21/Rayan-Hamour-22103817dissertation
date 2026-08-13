# Author: Rayan Hamour (22103817)
"""Unit tests for the gray-box adversarial ML-evasion attack."""

from __future__ import annotations

import time

from carnet.attacks.adversarial_ml import (
    inject_with_stats,
    observe_signal_stats,
    run_adversarial_ml_evasion_attack,
)
from carnet.attacks.flood import run_flood_attack
from carnet.can.bus import create_bus, create_notifier
from carnet.can.traffic import TrafficGenerator
from carnet.ids.anomaly import AnomalyIDS

TARGET_ID = 0x100  # Engine_RPM_Speed, fastest period so plenty of observation samples fast


def test_insufficient_observation_time_reports_no_learned_stats():
    bus = create_bus()
    traffic = TrafficGenerator(bus)
    try:
        traffic.start()
        result = run_adversarial_ml_evasion_attack(
            bus, target_id=TARGET_ID, duration_s=0.1, observation_s=0.0, injected_payload_marker=b"\xde\xad"
        )
    finally:
        traffic.stop()
        bus.shutdown()
    assert result["learned_stats"] is False
    assert result["sent"] == 0


def test_evasion_attack_learns_stats_and_injects():
    bus = create_bus()
    traffic = TrafficGenerator(bus)
    try:
        traffic.start()
        result = run_adversarial_ml_evasion_attack(
            bus, target_id=TARGET_ID, duration_s=1.0, observation_s=0.5, injected_payload_marker=b"\xde\xad"
        )
    finally:
        traffic.stop()
        bus.shutdown()
    assert result["learned_stats"] is True
    assert result["observed_samples"] >= 10
    assert result["sent"] > 0


def _run_against_ml(send_fn) -> tuple[AnomalyIDS, int]:
    """Trains the ML detector on baseline traffic, then calls `send_fn(bus)`
    with the legitimate ECU stopped, so every message that reaches
    TARGET_ID during the measured window comes from `send_fn` alone. That
    keeps the per-message alert rate well-defined: without this, a
    high-volume injection also disrupts the legitimate ECU's own
    inter-arrival pattern through pure interleaving, inflating the alert
    count with detections that aren't really about the injected messages.
    Returns (ids, sent_count).
    """
    t0 = time.monotonic()
    main_bus = create_bus()
    tap_bus = create_bus()
    ml_ids = AnomalyIDS(start_time=t0)
    notifier = create_notifier(tap_bus, [ml_ids])
    traffic = TrafficGenerator(main_bus)
    sent = 0
    try:
        traffic.start()
        time.sleep(1.0)
        ml_ids.fit()
        traffic.stop()
        sent = send_fn(main_bus)
        time.sleep(0.2)
    finally:
        traffic.stop()
        notifier.stop()
        main_bus.shutdown()
        tap_bus.shutdown()
    return ml_ids, sent


def test_evasion_attack_evades_ml_detector_better_than_naive_injection():
    # Compare per-message detection rate, not raw alert counts: the
    # evasion attack deliberately mimics the target ID's own (fast, ~10ms)
    # cadence to blend in, so it necessarily sends far more messages than a
    # sparse naive flood over the same duration. Comparing raw counts would
    # unfairly penalise it for volume rather than for how detectable each
    # individual injected message is, which is the actual claim being
    # tested: gray-box statistical mimicry evades on a per-message basis.
    #
    # The evasion attack still needs to observe *some* live traffic to learn
    # its stats from, so that phase runs against a second, independent
    # traffic generator on its own bus rather than the one being measured.
    stats_bus = create_bus()
    stats_traffic = TrafficGenerator(stats_bus)
    stats_traffic.start()
    time.sleep(1.0)
    stats = observe_signal_stats(stats_bus, TARGET_ID, observation_s=0.5)
    stats_traffic.stop()
    stats_bus.shutdown()
    assert stats is not None

    def naive(bus):
        return run_flood_attack(bus, target_id=TARGET_ID, duration_s=1.5, rate_hz=10)

    def evasive(bus):
        return inject_with_stats(bus, TARGET_ID, duration_s=1.5, stats=stats, injected_payload_marker=b"\xde\xad")

    naive_ids, naive_sent = _run_against_ml(naive)
    evasive_ids, evasive_sent = _run_against_ml(evasive)

    assert naive_sent > 0
    assert evasive_sent > 0

    naive_alerts = sum(1 for a in naive_ids.alerts if a.rule == "ml_anomaly" and a.arbitration_id == TARGET_ID)
    evasive_alerts = sum(1 for a in evasive_ids.alerts if a.rule == "ml_anomaly" and a.arbitration_id == TARGET_ID)

    naive_rate = naive_alerts / naive_sent
    evasive_rate = evasive_alerts / evasive_sent

    assert evasive_rate < naive_rate
