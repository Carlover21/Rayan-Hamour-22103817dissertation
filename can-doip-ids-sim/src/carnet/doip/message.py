"""
Mocked DoIP message model.

This is a conceptual approximation of ISO 13400 (Diagnostics over IP), not a
wire-accurate implementation: no real sockets are opened and the header
fields below are simplified to the ones needed to demonstrate the IP-to-CAN
attack surface described in the dissertation proposal (routing activation
followed by diagnostic message forwarding onto the CAN bus).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DoIPPayloadType(Enum):
    ROUTING_ACTIVATION_REQUEST = "routing_activation_request"
    ROUTING_ACTIVATION_RESPONSE = "routing_activation_response"
    DIAGNOSTIC_MESSAGE = "diagnostic_message"
    DIAGNOSTIC_MESSAGE_REJECTED = "diagnostic_message_rejected"


@dataclass
class DoIPMessage:
    payload_type: DoIPPayloadType
    source_address: int  # logical address of the sender (tester/attacker)
    target_address: int  # logical address of the intended recipient (gateway/ECU)
    payload: bytes = b""

    def __repr__(self) -> str:
        return (
            f"DoIPMessage({self.payload_type.value}, "
            f"src=0x{self.source_address:04X}, dst=0x{self.target_address:04X}, "
            f"payload={self.payload.hex()})"
        )