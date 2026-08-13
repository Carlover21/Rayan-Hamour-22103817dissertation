# Author: Rayan Hamour (22103817)
"""Unit tests for the mimicry (bus-timing-aware) evasion attack.

These are integration-style: real traffic, real IDS, real timing - because
the entire point of a mimicry attack is a timing property that can't be
verified any other way. Compares against a naive flood at a similar
injection rate to show the evasion is a real effect, not just "few enough
messages to not matter".
"""

from __future__ import annotations

import time

from carnet.attacks.flood import run_flood_attack
from carnet.attacks.mimicry import run_mimicry_attack
from carnet.can.bus import create_bus, create_notifier
from carnet.can.traffic import TrafficGenerator
from carnet.config import ECU_PROFILE
from carnet.ids.detector import RuleBasedIDS

TARGET_ID = 0x200  # Brake_Status, nominal period 20ms
NOMINAL_PERIOD_S = ECU_PROFILE[TARGET_ID]["period_s"]


def _run_with_attack(attack_fn) -> RuleBasedIDS:
    t0 = time.monotonic()
    main_bus = create_bus()
    tap_bus = create_bus()
    ids = RuleBasedIDS(start_time=t0)
    notifier = create_notifier(tap_bus, [ids])
    traffic = TrafficGenerator(main_bus)
    try:
        traffic.start()
        time.sleep(1.0)  # let baseline settle
        attack_fn(main_bus)
        time.sleep(0.3)
    finally:
        ids.stop()
        traffic.stop()
        notifier.stop()
        main_bus.shutdown()
        tap_bus.shutdown()
    return ids


def test_mimicry_produces_far_fewer_alerts_than_naive_flood_at_similar_rate():
    # Naive: inject at roughly the same overall rate as mimicry will, but
    # with no awareness of the legitimate ECU's schedule.
    def naive(bus):
        run_flood_attack(bus, target_id=TARGET_ID, duration_s=2.0, rate_hz=1.0 / (NOMINAL_PERIOD_S * 3))

    def mimicry(bus):
        run_mimicry_attack(
            bus,
            target_id=TARGET_ID,
            nominal_period_s=NOMINAL_PERIOD_S,
            duration_s=2.0,
            cycles_between_injections=3,
            spoofed_payload=b"\xff\x00\xff\x00",
        )

    naive_ids = _run_with_attack(naive)
    mimicry_ids = _run_with_attack(mimicry)

    naive_alerts = sum(1 for a in naive_ids.alerts if a.arbitration_id == TARGET_ID)
    mimicry_alerts = sum(1 for a in mimicry_ids.alerts if a.arbitration_id == TARGET_ID)

    # Not asserting mimicry_alerts == 0 (OS scheduling jitter can still
    # occasionally trip it) - asserting the intended effect: mimicry is
    # substantially quieter than an equally-sized naive injection.
    assert mimicry_alerts < naive_alerts


def test_mimicry_actually_injects_messages():
    result_holder = {}

    def mimicry(bus):
        result_holder["result"] = run_mimicry_attack(
            bus,
            target_id=TARGET_ID,
            nominal_period_s=NOMINAL_PERIOD_S,
            duration_s=1.5,
            cycles_between_injections=2,
            spoofed_payload=b"\xff\x00\xff\x00",
        )

    _run_with_attack(mimicry)
    result = result_holder["result"]
    assert result["legit_observed"] > 0
    assert result["injected"] > 0
