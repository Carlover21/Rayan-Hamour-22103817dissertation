"""
Mocked DoIP gateway: the modelled entry point where an IP-connected tester
(or attacker) reaches the vehicle and, once "routing activation" succeeds,
can have diagnostic payloads forwarded onto the CAN bus. This is the
IP-originated -> CAN attack path called out in the dissertation proposal.

No real network sockets are used (per project scope: DoIP is modelled
conceptually, not as a full ISO 13400 stack) - messages are handed to
`receive()` as in-process DoIPMessage objects.
"""

from __future__ import annotations

import logging
import time

import can

from carnet.config import DOIP_GATEWAY_LOGICAL_ADDRESS, DOIP_ROUTE_TARGET_CAN_ID
from carnet.doip.message import DoIPMessage, DoIPPayloadType

logger = logging.getLogger("carnet.doip.gateway")


class DoIPGateway:
    def __init__(
        self,
        bus: can.Bus,
        require_routing_activation: bool = True,
        start_time: float | None = None,
    ):
        self.bus = bus
        self.require_routing_activation = require_routing_activation
        self.start_time = start_time if start_time is not None else time.monotonic()
        self._activated_testers: set[int] = set()
        self.events: list[dict] = []  # audit trail for the evaluation harness

    def _log_event(self, kind: str, **fields) -> None:
        self.events.append({"timestamp": time.monotonic() - self.start_time, "kind": kind, **fields})

    def receive(self, message: DoIPMessage) -> DoIPMessage | None:
        if message.target_address != DOIP_GATEWAY_LOGICAL_ADDRESS:
            self._log_event("misdirected", source=message.source_address)
            return None

        if message.payload_type is DoIPPayloadType.ROUTING_ACTIVATION_REQUEST:
            return self._handle_routing_activation(message)

        if message.payload_type is DoIPPayloadType.DIAGNOSTIC_MESSAGE:
            return self._handle_diagnostic_message(message)

        self._log_event("unhandled_payload_type", source=message.source_address)
        return None

    def _handle_routing_activation(self, message: DoIPMessage) -> DoIPMessage:
        self._activated_testers.add(message.source_address)
        self._log_event("routing_activation", source=message.source_address)
        return DoIPMessage(
            payload_type=DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE,
            source_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
            target_address=message.source_address,
            payload=b"\x10",  # success code
        )

    def _handle_diagnostic_message(self, message: DoIPMessage) -> DoIPMessage | None:
        authorized = (
            not self.require_routing_activation
            or message.source_address in self._activated_testers
        )
        if not authorized:
            self._log_event("unauthorized_diagnostic_attempt", source=message.source_address)
            return DoIPMessage(
                payload_type=DoIPPayloadType.DIAGNOSTIC_MESSAGE_REJECTED,
                source_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
                target_address=message.source_address,
            )

        can_data = message.payload[:8].ljust(8, b"\x00")
        can_msg = can.Message(
            arbitration_id=DOIP_ROUTE_TARGET_CAN_ID, data=can_data, is_extended_id=False
        )
        try:
            self.bus.send(can_msg)
            self._log_event(
                "forwarded_to_can", source=message.source_address, can_id=DOIP_ROUTE_TARGET_CAN_ID
            )
        except can.CanError:
            self._log_event("forward_failed", source=message.source_address)
        return DoIPMessage(
            payload_type=DoIPPayloadType.ROUTING_ACTIVATION_RESPONSE,
            source_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
            target_address=message.source_address,
            payload=b"\x00",  # ack
        )