# Author: Rayan Hamour (22103817)
"""
Parameter sweeps: runs the same attack at several intensities (and repeats
each intensity a few times), so the evaluation can report how detection
rate and false positives change under varying attack intensity - the
proposal's stated evaluation methodology - rather than a single pass/fail
data point.
"""

from __future__ import annotations

import os

import pandas as pd

from carnet.attacks.scenario import AttackScenario
from carnet.config import DOIP_ROUTE_TARGET_CAN_ID, RESULTS_DIR
from carnet.eval.harness import run_trial


def sweep_flood(rates_hz: list[float], target_id: int = 0x100, repeats: int = 3) -> pd.DataFrame:
    rows = []
    for rate in rates_hz:
        for rep in range(repeats):
            scenario = AttackScenario(
                name=f"flood_{rate}hz",
                kind="flood",
                params={"target_id": target_id, "duration_s": 3.0, "rate_hz": rate},
                target_can_id=target_id,
            )
            result, _, _ = run_trial(scenario, baseline_duration_s=2.0, attack_duration_s=3.0)
            rows.append(
                {
                    "attack": "flood",
                    "intensity": rate,
                    "repeat": rep,
                    "detected": result.detected,
                    "relevant_alerts": result.relevant_alert_count,
                    "baseline_false_positives": result.baseline_false_positive_count,
                    "time_to_detect_s": result.time_to_detect_s,
                }
            )
    return pd.DataFrame(rows)


def sweep_spoof(rates_hz: list[float], target_id: int = 0x200, repeats: int = 3) -> pd.DataFrame:
    rows = []
    for rate in rates_hz:
        for rep in range(repeats):
            scenario = AttackScenario(
                name=f"spoof_{rate}hz",
                kind="spoof",
                params={
                    "target_id": target_id,
                    "duration_s": 3.0,
                    "rate_hz": rate,
                    "spoofed_payload": b"\xff\x00\xff\x00",
                },
                target_can_id=target_id,
            )
            result, _, _ = run_trial(scenario, baseline_duration_s=2.0, attack_duration_s=3.0)
            rows.append(
                {
                    "attack": "spoof",
                    "intensity": rate,
                    "repeat": rep,
                    "detected": result.detected,
                    "relevant_alerts": result.relevant_alert_count,
                    "baseline_false_positives": result.baseline_false_positive_count,
                    "time_to_detect_s": result.time_to_detect_s,
                }
            )
    return pd.DataFrame(rows)


def sweep_doip_injection(
    rates_hz: list[float], skip_routing_activation: bool = True, repeats: int = 3
) -> pd.DataFrame:
    rows = []
    for rate in rates_hz:
        for rep in range(repeats):
            scenario = AttackScenario(
                name=f"doip_injection_{rate}hz_skip{skip_routing_activation}",
                kind="doip_injection",
                params={
                    "attacker_address": 0x0EEE,
                    "duration_s": 3.0,
                    "rate_hz": rate,
                    "payload": b"\x22\xf1\x90",
                    "skip_routing_activation": skip_routing_activation,
                },
                target_can_id=None if skip_routing_activation else DOIP_ROUTE_TARGET_CAN_ID,
            )
            result, _, _ = run_trial(scenario, baseline_duration_s=2.0, attack_duration_s=3.0)
            rows.append(
                {
                    "attack": f"doip_injection_skip{skip_routing_activation}",
                    "intensity": rate,
                    "repeat": rep,
                    "detected": result.detected,
                    "relevant_alerts": result.relevant_alert_count,
                    "baseline_false_positives": result.baseline_false_positive_count,
                    "time_to_detect_s": result.time_to_detect_s,
                    "doip_rejected": result.doip_rejected_count,
                }
            )
    return pd.DataFrame(rows)


def sweep_busoff(rates_hz: list[float], target_id: int = 0x200, repeats: int = 3) -> pd.DataFrame:
    rows = []
    for rate in rates_hz:
        for rep in range(repeats):
            scenario = AttackScenario(
                name=f"busoff_{rate}hz",
                kind="busoff",
                params={"target_id": target_id, "duration_s": 3.0, "rate_hz": rate},
                target_can_id=target_id,
            )
            result, _, _ = run_trial(scenario, baseline_duration_s=2.0, attack_duration_s=3.0)
            rows.append(
                {
                    "attack": "busoff",
                    "intensity": rate,
                    "repeat": rep,
                    "detected": result.detected,
                    "relevant_alerts": result.relevant_alert_count,
                    "baseline_false_positives": result.baseline_false_positive_count,
                    "time_to_detect_s": result.time_to_detect_s,
                    "bus_off_achieved": result.attack_outcome.get("bus_off_achieved"),
                    "time_to_bus_off_s": result.attack_outcome.get("time_to_bus_off_s"),
                }
            )
    return pd.DataFrame(rows)


def sweep_infotainment_pivot(rates_hz: list[float], target_id: int = 0x300, repeats: int = 3) -> pd.DataFrame:
    rows = []
    for rate in rates_hz:
        for rep in range(repeats):
            scenario = AttackScenario(
                name=f"infotainment_pivot_{rate}hz",
                kind="infotainment_pivot",
                params={"target_id": target_id, "duration_s": 3.0, "rate_hz": rate},
                target_can_id=target_id,
            )
            result, _, _ = run_trial(scenario, baseline_duration_s=2.0, attack_duration_s=3.0)
            rows.append(
                {
                    "attack": "infotainment_pivot",
                    "intensity": rate,
                    "repeat": rep,
                    "detected": result.detected,
                    "relevant_alerts": result.relevant_alert_count,
                    "baseline_false_positives": result.baseline_false_positive_count,
                    "time_to_detect_s": result.time_to_detect_s,
                }
            )
    return pd.DataFrame(rows)


def sweep_key_fob_relay(repeats: int = 10, target_id: int = 0x400) -> pd.DataFrame:
    rows = []
    for rep in range(repeats):
        scenario = AttackScenario(
            name="key_fob_relay",
            kind="key_fob_relay",
            params={"target_id": target_id, "num_events": 1, "spacing_s": 0.2},
            target_can_id=target_id,
        )
        result, _, _ = run_trial(scenario, baseline_duration_s=2.0, attack_duration_s=1.0)
        rows.append(
            {
                "attack": "key_fob_relay",
                "intensity": 1,  # single event - not a rate-based attack
                "repeat": rep,
                "detected": result.detected,
                "relevant_alerts": result.relevant_alert_count,
                "baseline_false_positives": result.baseline_false_positive_count,
                "time_to_detect_s": result.time_to_detect_s,
            }
        )
    return pd.DataFrame(rows)


def sweep_secoc_comparison(rates_hz: list[float], repeats: int = 3) -> pd.DataFrame:
    """The authorized-DoIP-abuse case that scored 0% detection in the original
    (pre-SecOC) evaluation: an attacker completes routing activation like a
    legitimate tester, then floods diagnostic messages. Runs it with and
    without SecOC authentication enabled to quantify what authentication buys."""
    rows = []
    for secoc_enabled in (False, True):
        for rate in rates_hz:
            for rep in range(repeats):
                scenario = AttackScenario(
                    name=f"doip_authorized_abuse_{rate}hz_secoc{secoc_enabled}",
                    kind="doip_injection",
                    params={
                        "attacker_address": 0x0EEE,
                        "duration_s": 3.0,
                        "rate_hz": rate,
                        "payload": b"\x22\xf1\x90",
                        "skip_routing_activation": False,
                    },
                    target_can_id=DOIP_ROUTE_TARGET_CAN_ID,
                )
                result, _, _ = run_trial(
                    scenario, baseline_duration_s=2.0, attack_duration_s=3.0, secoc_enabled=secoc_enabled
                )
                rows.append(
                    {
                        "attack": f"doip_authorized_abuse_secoc{secoc_enabled}",
                        "secoc_enabled": secoc_enabled,
                        "intensity": rate,
                        "repeat": rep,
                        "detected": result.detected,
                        "relevant_alerts": result.relevant_alert_count,
                        "baseline_false_positives": result.baseline_false_positive_count,
                        "time_to_detect_s": result.time_to_detect_s,
                    }
                )
    return pd.DataFrame(rows)


def sweep_ml_vs_rule_comparison(repeats: int = 5) -> pd.DataFrame:
    """Runs a curated set of scenarios - including the ones known to be hard
    for the rule-based detector - through both detectors in the same trial,
    for a direct, paired rule-based-vs-ML comparison."""
    scenario_builders = {
        "flood": lambda: AttackScenario(
            name="flood_cmp", kind="flood", params={"target_id": 0x100, "duration_s": 3.0, "rate_hz": 50},
            target_can_id=0x100,
        ),
        "spoof": lambda: AttackScenario(
            name="spoof_cmp", kind="spoof",
            params={"target_id": 0x200, "duration_s": 3.0, "rate_hz": 30, "spoofed_payload": b"\xff\x00\xff\x00"},
            target_can_id=0x200,
        ),
        "key_fob_relay": lambda: AttackScenario(
            name="key_fob_relay_cmp", kind="key_fob_relay",
            params={"target_id": 0x400, "num_events": 1, "spacing_s": 0.2}, target_can_id=0x400,
        ),
        "busoff": lambda: AttackScenario(
            name="busoff_cmp", kind="busoff", params={"target_id": 0x200, "duration_s": 3.0, "rate_hz": 50},
            target_can_id=0x200,
        ),
    }
    rows = []
    for attack_name, build in scenario_builders.items():
        for rep in range(repeats):
            scenario = build()
            attack_duration = 1.0 if attack_name == "key_fob_relay" else 3.0
            result, _, _ = run_trial(
                scenario, baseline_duration_s=5.0, attack_duration_s=attack_duration, with_ml=True
            )
            rows.append(
                {
                    "attack": attack_name,
                    "repeat": rep,
                    "rule_detected": result.detected,
                    "ml_detected": result.ml_detected,
                    "rule_baseline_fp": result.baseline_false_positive_count,
                    "ml_baseline_fp": result.ml_baseline_false_positive_count,
                }
            )
    return pd.DataFrame(rows)


def save_results(df: pd.DataFrame, filename: str) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, filename)
    df.to_csv(path, index=False)
    return path
