# Author: Rayan Hamour (22103817)
"""
Normal traffic generator: spins up one VirtualECU per entry in ECU_PROFILE
that has a periodic schedule, giving a repeatable "baseline" of legitimate
in-vehicle traffic for the IDS to learn/compare against.
"""

from __future__ import annotations

import can

from carnet.can.ecu import VirtualECU
from carnet.config import ECU_PROFILE
from carnet.security.secoc import SecOCContext


class TrafficGenerator:
    def __init__(
        self,
        bus: can.Bus,
        secoc: SecOCContext | None = None,
        silenced_ids: set[int] | None = None,
    ):
        self.bus = bus
        self.ecus: list[VirtualECU] = []
        for arb_id, profile in ECU_PROFILE.items():
            if profile["period_s"] is None:
                continue  # diagnostic-only IDs are not spontaneous traffic
            self.ecus.append(
                VirtualECU(
                    bus=bus,
                    name=profile["name"],
                    arbitration_id=arb_id,
                    period_s=profile["period_s"],
                    jitter_s=profile["jitter_s"],
                    dlc=profile["dlc"],
                    is_fd=profile.get("is_fd", False),
                    secoc=secoc,
                    silenced_ids=silenced_ids,
                )
            )

    def start(self) -> None:
        for ecu in self.ecus:
            ecu.start()

    def stop(self) -> None:
        for ecu in self.ecus:
            ecu.stop()

    def total_sent(self) -> int:
        return sum(ecu.sent_count for ecu in self.ecus)