# Author: Rayan Hamour (22103817)
"""Unit tests for the real-socket DoIP gateway (doip.socket_gateway)."""

from __future__ import annotations

import socket

from carnet.attacks.socket_doip_injection import run_socket_doip_injection_attack
from carnet.can.bus import create_bus
from carnet.config import DOIP_ROUTE_TARGET_CAN_ID
from carnet.doip.socket_gateway import DoIPSocketClient, SocketDoIPGateway


def _start_gateway(bus, require_routing_activation=True) -> SocketDoIPGateway:
    gw = SocketDoIPGateway(bus=bus, require_routing_activation=require_routing_activation)
    gw.start()
    return gw


def test_unauthorized_diagnostic_over_socket_is_rejected():
    bus = create_bus()
    gw = _start_gateway(bus)
    try:
        client = DoIPSocketClient("127.0.0.1", gw.port, source_address=0x0EEE)
        ok = client.send_diagnostic(0x1000, b"\x22\xf1\x90")
        client.close()
        assert ok is False
        assert any(e["kind"] == "unauthorized_diagnostic_attempt" for e in gw.events)
    finally:
        gw.stop()
        bus.shutdown()


def test_authorized_diagnostic_over_socket_forwards_to_can():
    bus = create_bus()
    tap_bus = create_bus()
    gw = _start_gateway(bus)
    try:
        client = DoIPSocketClient("127.0.0.1", gw.port, source_address=0x0E00)
        assert client.routing_activation() is True
        ok = client.send_diagnostic(0x1000, b"\x22\xf1\x90")
        client.close()
        assert ok is True
        assert any(e["kind"] == "forwarded_to_can" for e in gw.events)

        received = tap_bus.recv(timeout=1.0)
        assert received is not None
        assert received.arbitration_id == DOIP_ROUTE_TARGET_CAN_ID
    finally:
        gw.stop()
        bus.shutdown()
        tap_bus.shutdown()


def test_reconnecting_drops_routing_activation():
    bus = create_bus()
    gw = _start_gateway(bus)
    try:
        client = DoIPSocketClient("127.0.0.1", gw.port, source_address=0x0E00)
        assert client.routing_activation() is True
        client.close()

        client2 = DoIPSocketClient("127.0.0.1", gw.port, source_address=0x0E00)
        ok = client2.send_diagnostic(0x1000, b"\x22\xf1\x90")
        client2.close()
        assert ok is False  # new connection, never activated on it
    finally:
        gw.stop()
        bus.shutdown()


def test_malformed_frame_does_not_crash_server():
    bus = create_bus()
    gw = _start_gateway(bus)
    try:
        raw = socket.create_connection(("127.0.0.1", gw.port), timeout=2.0)
        raw.sendall(b"garbage-not-a-doip-frame")
        raw.close()

        # server should still be alive and accept the next legitimate client
        client = DoIPSocketClient("127.0.0.1", gw.port, source_address=0x0E00)
        assert client.routing_activation() is True
        client.close()
    finally:
        gw.stop()
        bus.shutdown()


def test_socket_injection_attack_unauthorized_all_rejected():
    bus = create_bus()
    gw = _start_gateway(bus)
    try:
        result = run_socket_doip_injection_attack(
            "127.0.0.1", gw.port, attacker_address=0x0EEE, duration_s=1.0, rate_hz=10,
            payload=b"\x22\xf1\x90", skip_routing_activation=True,
        )
        assert result["forwarded"] == 0
        assert result["rejected"] == result["attempts"]
        assert result["attempts"] > 0
    finally:
        gw.stop()
        bus.shutdown()
