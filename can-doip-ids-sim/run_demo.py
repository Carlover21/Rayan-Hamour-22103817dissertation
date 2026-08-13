# Author: Rayan Hamour (22103817)
"""
Single-scenario demo: runs a short baseline period of normal in-vehicle
traffic, launches one attack (flood on the engine ID by default), and
prints what the IDS saw plus a traffic-timeline plot.

Usage:
    python run_demo.py [flood|spoof|doip]
"""

from __future__ import annotations

import sys

from carnet.attacks.scenario import AttackScenario
from carnet.config import DOIP_ROUTE_TARGET_CAN_ID
from carnet.eval.harness import run_trial
from carnet.eval.plots import plot_traffic_timeline

SCENARIOS = {
    "flood": AttackScenario(
        name="demo_flood",
        kind="flood",
        params={"target_id": 0x100, "duration_s": 5.0, "rate_hz": 500},
        target_can_id=0x100,
    ),
    "spoof": AttackScenario(
        name="demo_spoof",
        kind="spoof",
        params={
            "target_id": 0x200,
            "duration_s": 5.0,
            "rate_hz": 200,
            "spoofed_payload": b"\xff\x00\xff\x00",
        },
        target_can_id=0x200,
    ),
    "doip": AttackScenario(
        name="demo_doip_injection",
        kind="doip_injection",
        params={
            "attacker_address": 0x0EEE,
            "duration_s": 5.0,
            "rate_hz": 50,
            "payload": b"\x22\xf1\x90",
            "skip_routing_activation": True,
        },
        target_can_id=None,
    ),
}


def main() -> None:
    choice = sys.argv[1] if len(sys.argv) > 1 else "flood"
    if choice not in SCENARIOS:
        print(f"Unknown scenario '{choice}'. Choose from: {list(SCENARIOS)}")
        sys.exit(1)

    scenario = SCENARIOS[choice]
    print(f"Running demo scenario: {scenario.name} ({scenario.kind})")
    print("Baseline: 3.0s normal traffic, then attack for its configured duration, then 1.0s cooldown.\n")

    result, logger, ids = run_trial(
        scenario,
        baseline_duration_s=3.0,
        attack_duration_s=scenario.params.get("duration_s", 5.0),
        csv_log_path=f"logs/{scenario.name}_can_log.csv",
    )

    print(f"Total CAN frames logged:        {len(logger.records)}")
    print(f"Total IDS alerts:               {result.total_alert_count}")
    print(f"False positives during baseline:{result.baseline_false_positive_count:>4}")
    print(f"Attack window:                  {result.attack_start_s:.2f}s - {result.attack_end_s:.2f}s")
    print(f"Relevant alerts during attack:  {result.relevant_alert_count}")
    print(f"Attack detected:                {result.detected}")
    if result.time_to_detect_s is not None:
        print(f"Time to first relevant alert:   {result.time_to_detect_s:.3f}s after attack start")
    if result.doip_rejected_count:
        print(f"DoIP gateway rejected attempts: {result.doip_rejected_count} (unauthorized)")
    print(f"Attack-side outcome:             {result.attack_outcome}")

    print("\nFirst 10 IDS alerts:")
    for alert in ids.alerts[:10]:
        print(f"  {alert}")

    plot_path = plot_traffic_timeline(
        logger, ids, result.attack_start_s, result.attack_end_s, f"{scenario.name}_timeline.png"
    )
    print(f"\nSaved traffic timeline plot to: {plot_path}")


if __name__ == "__main__":
    main()
