"""
Dashboard DoIP gateway: same conceptual model as carnet.doip.gateway
(routing activation required before diagnostic messages are forwarded onto
the CAN bus), but lets the demo attacker choose *which* CAN ID and payload
to inject, so the dashboard can show the full story: a remote/IP attacker
reaches the gateway, and - if authorized - can push arbitrary signals (e.g.
a spoofed steering command) straight onto the bus.
"""

from __future__ import annotations

from carnet.config import DOIP_GATEWAY_LOGICAL_ADDRESS


class DashboardDoIPGateway:
    def __init__(self, require_routing_activation: bool = True):
        self.require_routing_activation = require_routing_activation
        self._activated_testers: set[int] = set()
        self.events: list[dict] = []
        self._next_seq = 1

    def _log(self, now: float, kind: str, **fields) -> dict:
        event = {"seq": self._next_seq, "timestamp": round(now, 3), "kind": kind, **fields}
        self.events.append(event)
        self._next_seq += 1
        return event

    def routing_activation(self, now: float, attacker_address: int) -> dict:
        self._activated_testers.add(attacker_address)
        return self._log(now, "routing_activation", source=attacker_address)

    def send_diagnostic(
        self, now: float, attacker_address: int, target_can_id: int, data: bytes
    ) -> tuple[bool, dict]:
        authorized = (
            not self.require_routing_activation or attacker_address in self._activated_testers
        )
        if not authorized:
            event = self._log(now, "unauthorized_diagnostic_attempt", source=attacker_address)
            return False, event
        event = self._log(
            now, "forwarded_to_can", source=attacker_address, can_id=target_can_id, data=data.hex()
        )
        return True, event

    def reset(self) -> None:
        self._activated_testers.clear()
        self.events.clear()
        self._next_seq = 1
