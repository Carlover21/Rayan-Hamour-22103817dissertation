"""
Attack scenario registry: a uniform way for the evaluation harness to launch
any attack by name with a dict of parameters, and to know which CAN IDs (if
any) it targets so ground truth can be labelled for scoring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import can

from carnet.attacks.busoff import run_busoff_attack
from carnet.attacks.doip_injection import run_doip_injection_attack
from carnet.attacks.flood import run_flood_attack
from carnet.attacks.infotainment_pivot import run_infotainment_pivot_attack
from carnet.attacks.key_fob_relay import run_key_fob_relay_attack
from carnet.attacks.spoof import run_spoofing_attack
from carnet.doip.gateway import DoIPGateway


@dataclass
class AttackScenario:
    name: str
    kind: str  # "flood" | "spoof" | "doip_injection" | "busoff" | "infotainment_pivot" | "key_fob_relay"
    params: dict[str, Any] = field(default_factory=dict)
    target_can_id: int | None = None  # CAN ID this attack manifests on, for scoring


def run_scenario(scenario: AttackScenario, bus: can.Bus, gateway: DoIPGateway) -> dict:
    if scenario.kind == "flood":
        sent = run_flood_attack(bus=bus, **scenario.params)
        return {"sent": sent}
    if scenario.kind == "spoof":
        sent = run_spoofing_attack(bus=bus, **scenario.params)
        return {"sent": sent}
    if scenario.kind == "doip_injection":
        return run_doip_injection_attack(gateway=gateway, **scenario.params)
    if scenario.kind == "busoff":
        return run_busoff_attack(bus=bus, **scenario.params)
    if scenario.kind == "infotainment_pivot":
        sent = run_infotainment_pivot_attack(bus=bus, **scenario.params)
        return {"sent": sent}
    if scenario.kind == "key_fob_relay":
        sent = run_key_fob_relay_attack(bus=bus, **scenario.params)
        return {"sent": sent}
    raise ValueError(f"Unknown attack kind: {scenario.kind}")
