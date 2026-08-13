# Author: Rayan Hamour (22103817)
"""
Evaluation harness: runs a scenario (normal baseline traffic, optionally
followed by an attack window), then scores what the IDS did against ground
truth (was there actually an attack, and on which CAN ID). This is what
produces the detection-rate / false-positive numbers for the dissertation's
evaluation chapter.

Optionally runs the ML-based AnomalyIDS in parallel with the rule-based
RuleBasedIDS, against the exact same traffic and attack in the same trial,
for a fair paired comparison rather than two separate runs that could differ
by chance timing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from carnet.attacks.scenario import AttackScenario, run_scenario
from carnet.can.bus import create_bus, create_notifier
from carnet.can.logger import CANLogger
from carnet.can.traffic import TrafficGenerator
from carnet.config import SECOC_MASTER_KEY
from carnet.doip.gateway import DoIPGateway
from carnet.ids.alert import IDSAlert
from carnet.ids.anomaly import AnomalyIDS
from carnet.ids.detector import RuleBasedIDS
from carnet.security.secoc import SecOCContext


@dataclass
class TrialResult:
    scenario_name: str
    scenario_kind: str
    params: dict[str, Any]
    target_can_id: int | None
    baseline_duration_s: float
    attack_duration_s: float
    attack_start_s: float
    attack_end_s: float
    detected: bool
    relevant_alert_count: int
    time_to_detect_s: float | None
    baseline_false_positive_count: int
    total_alert_count: int
    attack_outcome: dict[str, Any]
    doip_rejected_count: int
    secoc_enabled: bool = False
    ml_detected: bool | None = None
    ml_relevant_alert_count: int | None = None
    ml_baseline_false_positive_count: int | None = None
    ml_total_alert_count: int | None = None


def _score(alerts: list[IDSAlert], attack_start: float, attack_end: float, target_id: int | None, has_scenario: bool):
    if target_id is not None:
        relevant = [a for a in alerts if attack_start <= a.timestamp <= attack_end and a.arbitration_id == target_id]
    elif has_scenario:
        relevant = [a for a in alerts if attack_start <= a.timestamp <= attack_end]
    else:
        relevant = []
    return relevant


def run_trial(
    scenario: AttackScenario | None,
    baseline_duration_s: float = 3.0,
    attack_duration_s: float = 5.0,
    cooldown_s: float = 1.0,
    csv_log_path: str | None = None,
    secoc_enabled: bool = False,
    with_ml: bool = False,
) -> tuple[TrialResult, CANLogger, RuleBasedIDS]:
    """Run one baseline+attack trial (attack may be None for a pure-baseline/control run)."""
    t0 = time.monotonic()
    main_bus = create_bus()
    tap_bus = create_bus()
    ml_tap_bus = create_bus() if with_ml else None

    secoc = SecOCContext(SECOC_MASTER_KEY) if secoc_enabled else None
    silenced_ids: set[int] = set()

    logger = CANLogger(csv_path=csv_log_path, start_time=t0)
    ids = RuleBasedIDS(start_time=t0, secoc=secoc)
    notifier = create_notifier(tap_bus, [logger, ids])

    # AnomalyIDS gets its own bus handle and Notifier thread: sklearn
    # inference is slow enough per-message to back up a shared dispatch
    # queue, which would otherwise distort the rule-based IDS's own timing
    # measurements (delayed delivery looks like delayed inter-arrival).
    ml_ids = AnomalyIDS(start_time=t0) if with_ml else None
    ml_notifier = create_notifier(ml_tap_bus, [ml_ids]) if with_ml else None

    gateway = DoIPGateway(bus=main_bus, start_time=t0)
    traffic = TrafficGenerator(main_bus, secoc=secoc, silenced_ids=silenced_ids)

    if scenario is not None and scenario.kind == "busoff":
        scenario.params.setdefault("silenced_ids", silenced_ids)

    try:
        traffic.start()
        time.sleep(baseline_duration_s)
        baseline_fp = ids.alert_count()
        if ml_ids:
            ml_ids.fit()
            ml_baseline_fp = ml_ids.alert_count()

        attack_start = time.monotonic() - t0
        attack_outcome: dict[str, Any] = {}
        if scenario is not None:
            attack_outcome = run_scenario(scenario, bus=main_bus, gateway=gateway)
        else:
            time.sleep(attack_duration_s)
        attack_end = time.monotonic() - t0

        time.sleep(cooldown_s)
    finally:
        # Stop the silence monitor before traffic stops, not after - otherwise
        # it correctly notices the deliberate post-measurement quiet during
        # teardown and misreports it as a silence/bus-off finding.
        ids.stop()
        traffic.stop()
        notifier.stop()
        if ml_notifier:
            ml_notifier.stop()
        main_bus.shutdown()
        tap_bus.shutdown()
        if ml_tap_bus:
            ml_tap_bus.shutdown()
        logger.close()

    target_id = scenario.target_can_id if scenario else None
    relevant = _score(ids.alerts, attack_start, attack_end, target_id, scenario is not None)
    doip_rejected = attack_outcome.get("rejected", 0) if attack_outcome else 0
    detected = bool(relevant) or doip_rejected > 0

    ml_detected = ml_relevant_count = None
    if ml_ids:
        ml_relevant = _score(ml_ids.alerts, attack_start, attack_end, target_id, scenario is not None)
        ml_relevant_count = len(ml_relevant)
        ml_detected = bool(ml_relevant) or doip_rejected > 0

    result = TrialResult(
        scenario_name=scenario.name if scenario else "baseline_only",
        scenario_kind=scenario.kind if scenario else "none",
        params={k: v for k, v in (scenario.params if scenario else {}).items() if k != "silenced_ids"},
        target_can_id=target_id,
        baseline_duration_s=baseline_duration_s,
        attack_duration_s=attack_duration_s,
        attack_start_s=attack_start,
        attack_end_s=attack_end,
        detected=detected,
        relevant_alert_count=len(relevant),
        time_to_detect_s=(relevant[0].timestamp - attack_start) if relevant else None,
        baseline_false_positive_count=baseline_fp,
        total_alert_count=ids.alert_count(),
        attack_outcome=attack_outcome,
        doip_rejected_count=doip_rejected,
        secoc_enabled=secoc_enabled,
        ml_detected=ml_detected,
        ml_relevant_alert_count=ml_relevant_count,
        ml_baseline_false_positive_count=ml_baseline_fp if ml_ids else None,
        ml_total_alert_count=ml_ids.alert_count() if ml_ids else None,
    )
    return result, logger, ids
