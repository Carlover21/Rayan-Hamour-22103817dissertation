# Author: Rayan Hamour (22103817)
"""
Unauthorized CAN injection via DoIP: models a remote, IP-connected attacker
that reaches the DoIP gateway and attempts to inject diagnostic payloads
that get forwarded onto the CAN bus - the IP-to-CAN attack path from the
dissertation proposal. Two variants:

- skip_routing_activation=True: attacker sends diagnostic messages directly,
  without ever performing routing activation (tests the gateway's own
  authorization check).
- skip_routing_activation=False: attacker performs routing activation first
  (like a legitimate tester would) then abuses the resulting access by
  flooding diagnostic messages, which should surface on the CAN side as
  injected/duplicated 0x7E0 traffic for the IDS to catch.
"""

from __future__ import annotations

import time

from carnet.config import DOIP_GATEWAY_LOGICAL_ADDRESS
from carnet.doip.gateway import DoIPGateway
from carnet.doip.message import DoIPMessage, DoIPPayloadType


def run_doip_injection_attack(
    gateway: DoIPGateway,
    attacker_address: int,
    duration_s: float,
    rate_hz: float,
    payload: bytes,
    skip_routing_activation: bool = True,
) -> dict:
    if not skip_routing_activation:
        gateway.receive(
            DoIPMessage(
                payload_type=DoIPPayloadType.ROUTING_ACTIVATION_REQUEST,
                source_address=attacker_address,
                target_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
            )
        )

    interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
    end_time = time.monotonic() + duration_s
    attempts = 0
    while time.monotonic() < end_time:
        response = gateway.receive(
            DoIPMessage(
                payload_type=DoIPPayloadType.DIAGNOSTIC_MESSAGE,
                source_address=attacker_address,
                target_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
                payload=payload,
            )
        )
        attempts += 1
        if interval > 0:
            time.sleep(interval)

    rejected = sum(
        1
        for e in gateway.events
        if e["kind"] == "unauthorized_diagnostic_attempt" and e["source"] == attacker_address
    )
    forwarded = sum(
        1
        for e in gateway.events
        if e["kind"] == "forwarded_to_can" and e["source"] == attacker_address
    )
    return {"attempts": attempts, "forwarded": forwarded, "rejected": rejected}
