"""Unit tests for the mocked DoIP gateway's authorization logic."""

from __future__ import annotations

import can

from carnet.can.bus import create_bus
from carnet.config import DOIP_GATEWAY_LOGICAL_ADDRESS, DOIP_ROUTE_TARGET_CAN_ID
from carnet.doip.gateway import DoIPGateway
from carnet.doip.message import DoIPMessage, DoIPPayloadType


def test_diagnostic_without_activation_is_rejected():
    bus = create_bus()
    try:
        gw = DoIPGateway(bus=bus)
        response = gw.receive(
            DoIPMessage(
                payload_type=DoIPPayloadType.DIAGNOSTIC_MESSAGE,
                source_address=0x0EEE,
                target_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
                payload=b"\x22\xf1\x90",
            )
        )
        assert response.payload_type is DoIPPayloadType.DIAGNOSTIC_MESSAGE_REJECTED
        assert any(e["kind"] == "unauthorized_diagnostic_attempt" for e in gw.events)
        assert not any(e["kind"] == "forwarded_to_can" for e in gw.events)
    finally:
        bus.shutdown()


def test_diagnostic_after_activation_forwards_to_can():
    bus = create_bus()
    tap_bus = create_bus()  # separate handle on the same virtual channel, for receiving
    try:
        gw = DoIPGateway(bus=bus)
        gw.receive(
            DoIPMessage(
                payload_type=DoIPPayloadType.ROUTING_ACTIVATION_REQUEST,
                source_address=0x0E00,
                target_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
            )
        )
        gw.receive(
            DoIPMessage(
                payload_type=DoIPPayloadType.DIAGNOSTIC_MESSAGE,
                source_address=0x0E00,
                target_address=DOIP_GATEWAY_LOGICAL_ADDRESS,
                payload=b"\x22\xf1\x90",
            )
        )
        assert any(e["kind"] == "forwarded_to_can" for e in gw.events)

        received = tap_bus.recv(timeout=1.0)
        assert received is not None
        assert received.arbitration_id == DOIP_ROUTE_TARGET_CAN_ID
    finally:
        bus.shutdown()
        tap_bus.shutdown()


def test_message_to_wrong_target_is_ignored():
    bus = create_bus()
    try:
        gw = DoIPGateway(bus=bus)
        response = gw.receive(
            DoIPMessage(
                payload_type=DoIPPayloadType.ROUTING_ACTIVATION_REQUEST,
                source_address=0x0E00,
                target_address=0x9999,  # not the gateway's address
            )
        )
        assert response is None
        assert any(e["kind"] == "misdirected" for e in gw.events)
    finally:
        bus.shutdown()
