"""Unit tests for the evaluation harness (eval.harness.run_trial).

These exercise the real threaded pipeline (bus, traffic, IDS, notifier)
end-to-end rather than mocking it, since that pipeline is what produces
every detection-rate number in the evaluation - a bug here would silently
corrupt results without ever showing up as a test failure elsewhere.
Durations are kept short to keep the suite fast; they're long enough to
be statistically meaningful for a 10-20ms period ID.
"""

from __future__ import annotations

from carnet.attacks.scenario import AttackScenario
from carnet.eval.harness import run_trial


def test_baseline_only_trial_has_no_false_positives():
    result, logger, ids = run_trial(None, baseline_duration_s=0.5, attack_duration_s=0.5, cooldown_s=0.1)
    assert result.scenario_kind == "none"
    assert result.detected is False
    assert result.baseline_false_positive_count == 0
    assert result.total_alert_count == 0
    assert len(logger.records) > 0  # traffic actually flowed


def test_flood_scenario_is_detected():
    scenario = AttackScenario(
        name="flood_test", kind="flood",
        params={"target_id": 0x100, "duration_s": 0.5, "rate_hz": 200},
        target_can_id=0x100,
    )
    result, _, _ = run_trial(scenario, baseline_duration_s=0.5, attack_duration_s=0.5, cooldown_s=0.1)
    assert result.detected is True
    assert result.relevant_alert_count > 0
    assert result.time_to_detect_s is not None


def test_unauthorized_doip_scenario_scores_via_gateway_rejection():
    scenario = AttackScenario(
        name="doip_test", kind="doip_injection",
        params={
            "attacker_address": 0x0EEE, "duration_s": 0.5, "rate_hz": 20,
            "payload": b"\x22\xf1\x90", "skip_routing_activation": True,
        },
        target_can_id=None,
    )
    result, _, _ = run_trial(scenario, baseline_duration_s=0.3, attack_duration_s=0.5, cooldown_s=0.1)
    assert result.detected is True
    assert result.doip_rejected_count > 0


def test_secoc_flag_is_recorded_on_result():
    result_off, _, _ = run_trial(None, baseline_duration_s=0.2, attack_duration_s=0.2, cooldown_s=0.1, secoc_enabled=False)
    result_on, _, _ = run_trial(None, baseline_duration_s=0.2, attack_duration_s=0.2, cooldown_s=0.1, secoc_enabled=True)
    assert result_off.secoc_enabled is False
    assert result_on.secoc_enabled is True


def test_with_ml_populates_ml_result_fields():
    scenario = AttackScenario(
        name="flood_ml_test", kind="flood",
        params={"target_id": 0x100, "duration_s": 0.5, "rate_hz": 200},
        target_can_id=0x100,
    )
    result, _, _ = run_trial(scenario, baseline_duration_s=1.0, attack_duration_s=0.5, cooldown_s=0.1, with_ml=True)
    assert result.ml_detected is not None
    assert result.ml_relevant_alert_count is not None
    assert result.ml_baseline_false_positive_count is not None
    assert result.ml_total_alert_count is not None


def test_without_ml_leaves_ml_fields_none():
    result, _, _ = run_trial(None, baseline_duration_s=0.2, attack_duration_s=0.2, cooldown_s=0.1, with_ml=False)
    assert result.ml_detected is None
    assert result.ml_relevant_alert_count is None
